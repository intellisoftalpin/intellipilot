//! Back-channel logout (OpenID Connect Back-Channel Logout 1.0).
//!
//! Closes the one gap that would otherwise make SSO *weaker* than LDAP here:
//! IntelliPilot sessions are long-lived opaque refresh families, so without
//! this endpoint, disabling someone at the identity provider leaves them signed
//! in for the full refresh TTL.
//!
//! # Why this verifies the token by hand
//!
//! A logout token is not an ID token. It carries `events` and may omit `exp`
//! entirely — Authentik's does — so it cannot be run through the library's
//! `IdTokenClaims`, which requires that claim. The cryptography still is the
//! library's: [`JsonWebKey::verify_signature`] against the discovered JWKS
//! does the actual signature check. What is written out here is the claim
//! validation from §2.6 of the specification, which is string and time
//! comparison, plus the two prohibitions that make a logout token distinct
//! from an ID token: `nonce` must be absent, and the `events` member must be
//! present.
//!
//! # Replay
//!
//! `jti` is not remembered. Replaying a logout token can only revoke sessions
//! that this one already revoked, and revoking an already-revoked family is a
//! no-op, so a replay achieves nothing an attacker could want. Storing every
//! `jti` would buy no security and would need its own table and sweeper.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{CoreJsonWebKey, CoreJwsSigningAlgorithm};
use openidconnect::{JsonWebKey, JsonWebKeyId};
use serde::Deserialize;

use intellipilot_db::oidc_providers::OidcProvider;

use super::{OidcCache, OidcError};

/// The event URI a logout token must announce.
const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// How far out of step with our clock a logout token's `iat` may be.
const MAX_IAT_SKEW_SECS: i64 = 300;
/// How old a logout token may be before we stop honouring it.
const MAX_IAT_AGE_SECS: i64 = 600;

/// The claims we act on, once verified.
#[derive(Debug, Clone)]
pub struct LogoutSubject {
    pub issuer: String,
    /// Absent when the provider identified the session by `sid` alone, which
    /// we cannot resolve — see [`super::backchannel`] module docs.
    pub subject: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    /// A JWE has this; we refuse encrypted logout tokens rather than pretend.
    #[serde(default)]
    enc: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LogoutClaims {
    iss: String,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    aud: Audience,
    iat: i64,
    #[serde(default)]
    events: Option<serde_json::Value>,
    /// Must not be present. Its presence means this is an ID token being
    /// passed off as a logout token.
    #[serde(default)]
    nonce: Option<serde_json::Value>,
}

/// `aud` is a string or an array of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, client_id: &str) -> bool {
        match self {
            Self::One(a) => a == client_id,
            Self::Many(list) => list.iter().any(|a| a == client_id),
        }
    }
}

/// Verify a `logout_token` and report whose sessions it closes.
pub async fn verify(
    cache: &OidcCache,
    provider: &OidcProvider,
    logout_token: &str,
) -> Result<LogoutSubject, OidcError> {
    let mut parts = logout_token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(OidcError::Rejected(
            "logout token is not a compact JWS".to_owned(),
        ));
    };

    let header: JwsHeader = decode_json(header_b64, "header")?;
    if header.enc.is_some() {
        return Err(OidcError::Rejected(
            "encrypted logout tokens are not supported".to_owned(),
        ));
    }
    // `alg: none` is the classic JWT forgery: an unsigned token that a naive
    // verifier accepts because it never checks a signature at all.
    let alg: CoreJwsSigningAlgorithm =
        serde_json::from_value(serde_json::Value::String(header.alg.clone()))
            .map_err(|_| OidcError::Rejected(format!("unsupported alg {}", header.alg)))?;
    if matches!(alg, CoreJwsSigningAlgorithm::None) {
        return Err(OidcError::Rejected(
            "unsigned logout token refused".to_owned(),
        ));
    }

    // Signature, against the provider's published keys.
    let metadata = cache.metadata(provider).await?;
    let signature = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| OidcError::Rejected("logout token signature is not base64url".to_owned()))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let kid = header.kid.map(JsonWebKeyId::new);
    let verified = metadata
        .jwks()
        .keys()
        .iter()
        .filter(|key: &&CoreJsonWebKey| match (&kid, key.key_id()) {
            // With a `kid`, only that key may be used. Without one, try every
            // published key — a provider is allowed to omit it.
            (Some(want), Some(have)) => want == have,
            (Some(_), None) => false,
            (None, _) => true,
        })
        .any(|key| {
            key.verify_signature(&alg, signing_input.as_bytes(), &signature)
                .is_ok()
        });
    if !verified {
        return Err(OidcError::Rejected(
            "logout token signature did not verify".to_owned(),
        ));
    }

    // Claims.
    let claims: LogoutClaims = decode_json(payload_b64, "payload")?;
    if claims.nonce.is_some() {
        return Err(OidcError::Rejected(
            "logout token carries a nonce, which the specification prohibits".to_owned(),
        ));
    }
    if claims.iss != metadata.issuer().as_str() {
        return Err(OidcError::Rejected(
            "logout token issuer mismatch".to_owned(),
        ));
    }
    if !claims.aud.contains(&provider.client_id) {
        return Err(OidcError::Rejected(
            "logout token audience mismatch".to_owned(),
        ));
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let age = now.saturating_sub(claims.iat);
    if !(-MAX_IAT_SKEW_SECS..=MAX_IAT_AGE_SECS).contains(&age) {
        return Err(OidcError::Rejected(
            "logout token is not current".to_owned(),
        ));
    }
    if claims.sub.is_none() && claims.sid.is_none() {
        return Err(OidcError::Rejected(
            "logout token identifies no session".to_owned(),
        ));
    }
    let has_event = claims
        .events
        .as_ref()
        .and_then(|e| e.as_object())
        .is_some_and(|map| map.contains_key(LOGOUT_EVENT));
    if !has_event {
        return Err(OidcError::Rejected(
            "logout token carries no back-channel logout event".to_owned(),
        ));
    }

    Ok(LogoutSubject {
        issuer: claims.iss,
        subject: claims.sub,
    })
}

fn decode_json<T: serde::de::DeserializeOwned>(part: &str, what: &str) -> Result<T, OidcError> {
    let raw = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| OidcError::Rejected(format!("logout token {what} is not base64url")))?;
    serde_json::from_slice(&raw)
        .map_err(|e| OidcError::Rejected(format!("logout token {what} is not valid JSON: {e}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn b64(value: &serde_json::Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn audience_accepts_both_json_shapes() {
        let one: Audience = serde_json::from_value(serde_json::json!("client-a")).unwrap();
        assert!(one.contains("client-a"));
        assert!(!one.contains("client-b"));

        let many: Audience =
            serde_json::from_value(serde_json::json!(["client-a", "client-b"])).unwrap();
        assert!(many.contains("client-b"));
        assert!(!many.contains("client-c"));
    }

    #[test]
    fn header_parsing_recognises_none_and_jwe() {
        let header: JwsHeader =
            decode_json(&b64(&serde_json::json!({"alg": "none"})), "header").unwrap();
        assert_eq!(header.alg, "none");
        assert!(header.enc.is_none());

        let header: JwsHeader = decode_json(
            &b64(&serde_json::json!({"alg": "RSA-OAEP", "enc": "A256GCM"})),
            "header",
        )
        .unwrap();
        assert!(header.enc.is_some());
    }

    #[test]
    fn logout_claims_require_an_event_and_reject_a_nonce() {
        let claims: LogoutClaims = decode_json(
            &b64(&serde_json::json!({
                "iss": "https://idp.example",
                "sub": "abc",
                "aud": "client-a",
                "iat": 1_700_000_000i64,
                "events": { LOGOUT_EVENT: {} },
            })),
            "payload",
        )
        .unwrap();
        assert!(claims.nonce.is_none());
        assert!(
            claims
                .events
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key(LOGOUT_EVENT)
        );

        let claims: LogoutClaims = decode_json(
            &b64(&serde_json::json!({
                "iss": "https://idp.example",
                "sub": "abc",
                "aud": "client-a",
                "iat": 1_700_000_000i64,
                "nonce": "n",
            })),
            "payload",
        )
        .unwrap();
        assert!(claims.nonce.is_some());
    }

    #[test]
    fn malformed_tokens_are_rejected_before_any_crypto() {
        assert!(decode_json::<JwsHeader>("!!not-base64!!", "header").is_err());
        assert!(decode_json::<JwsHeader>(&URL_SAFE_NO_PAD.encode("not json"), "header").is_err());
    }
}
