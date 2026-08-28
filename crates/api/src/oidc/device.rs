//! The device authorization flow (RFC 8628), brokered by the server.
//!
//! For the desktop and mobile clients, which cannot host a redirect endpoint
//! and should not hold a provider's client secret. The API performs both
//! halves against the IdP and hands the client only an opaque poll token, so
//! nothing the client holds is a credential at the identity provider.
//!
//! The `openidconnect` crate models this flow only as a blocking loop that
//! polls until the human finishes — no use to an HTTP handler that must answer
//! one request. The two calls are therefore driven directly: they are form
//! POSTs with nothing subtle in them. The part that *is* subtle, verifying the
//! returned ID token, still goes through the library.

use openidconnect::{Nonce, TokenResponse};
use serde::Deserialize;

use intellipilot_db::oidc_providers::OidcProvider;

use super::{
    IpIdTokenClaims, IpTokenResponse, OidcCache, OidcError, client_from_metadata, http_client,
};

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Floor and ceiling on the poll interval we accept from a provider.
///
/// A provider asking for 0 would have the client hammering us; one asking for
/// an hour would make the dialog look broken.
const MIN_INTERVAL_SECS: i32 = 1;
const MAX_INTERVAL_SECS: i32 = 60;
/// Fallback lifetime when the provider does not say (RFC 8628 suggests 1800).
const DEFAULT_EXPIRES_IN: i64 = 600;

/// What the IdP returns from the device authorization endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub interval: Option<i32>,
}

impl DeviceAuthorization {
    /// Poll interval, clamped into a sane range.
    #[must_use]
    pub fn clamped_interval(&self) -> i32 {
        self.interval
            .unwrap_or(5)
            .clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS)
    }

    #[must_use]
    pub fn expires_in_secs(&self) -> i64 {
        self.expires_in
            .unwrap_or(DEFAULT_EXPIRES_IN)
            .clamp(30, 3600)
    }
}

/// An OAuth error body, which the token endpoint returns with a 4xx during
/// the normal course of a device flow (`authorization_pending` is not a fault).
#[derive(Debug, Deserialize)]
struct OauthErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Begin a device authorization.
///
/// Fails with [`OidcError::Config`] when the provider publishes no
/// `device_authorization_endpoint` — that is an operator-visible fact about
/// their IdP, surfaced by the admin "Test" button rather than discovered by a
/// user at sign-in time.
pub async fn start(
    cache: &OidcCache,
    provider: &OidcProvider,
) -> Result<DeviceAuthorization, OidcError> {
    let metadata = cache.metadata(provider).await?;
    let endpoint = metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone()
        .ok_or_else(|| {
            OidcError::Config(
                "this provider does not publish a device authorization endpoint".to_owned(),
            )
        })?;

    let http = http_client(provider)?;
    let mut form: Vec<(&str, String)> = vec![
        ("client_id", provider.client_id.clone()),
        ("scope", provider.scope_list().join(" ")),
    ];
    if !provider.client_secret.is_empty() {
        form.push(("client_secret", provider.client_secret.clone()));
    }

    let response = http
        .post(endpoint.as_str())
        .form(&form)
        .send()
        .await
        .map_err(|e| OidcError::Unavailable(format!("device authorization failed: {e}")))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| OidcError::Unavailable(format!("device authorization body: {e}")))?;

    if !status.is_success() {
        return Err(map_oauth_error(&body, status.as_u16()));
    }
    serde_json::from_str::<DeviceAuthorization>(&body).map_err(|e| {
        OidcError::Unavailable(format!("device authorization response not understood: {e}"))
    })
}

/// One poll of the token endpoint for a pending device authorization.
///
/// Returns verified claims on success, [`OidcError::Pending`] while the human
/// has not finished, and [`OidcError::SlowDown`] when the provider asks us to
/// back off. Both of those are ordinary states of this flow, not failures —
/// which is why they are variants rather than errors the caller logs.
pub async fn poll(
    cache: &OidcCache,
    provider: &OidcProvider,
    device_code: &str,
) -> Result<IpIdTokenClaims, OidcError> {
    let metadata = cache.metadata(provider).await?;
    let token_endpoint = metadata
        .token_endpoint()
        .ok_or_else(|| OidcError::Config("provider publishes no token endpoint".to_owned()))?
        .clone();

    let http = http_client(provider)?;
    let mut form: Vec<(&str, String)> = vec![
        ("grant_type", DEVICE_GRANT.to_owned()),
        ("device_code", device_code.to_owned()),
        ("client_id", provider.client_id.clone()),
    ];
    if !provider.client_secret.is_empty() {
        form.push(("client_secret", provider.client_secret.clone()));
    }

    let response = http
        .post(token_endpoint.as_str())
        .form(&form)
        .send()
        .await
        .map_err(|e| OidcError::Unavailable(format!("device token request failed: {e}")))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| OidcError::Unavailable(format!("device token body: {e}")))?;

    if !status.is_success() {
        return Err(map_oauth_error(&body, status.as_u16()));
    }

    let token_response: IpTokenResponse = serde_json::from_str(&body)
        .map_err(|e| OidcError::Rejected(format!("token response not understood: {e}")))?;
    let id_token = token_response
        .id_token()
        .ok_or_else(|| OidcError::Rejected("provider returned no ID token".to_owned()))?;

    let client = client_from_metadata(provider, metadata);
    let verifier = client.id_token_verifier();
    // RFC 8628 has no nonce: the browser half of this flow happens entirely at
    // the identity provider, so there is no value we could have planted to
    // check. Replay is instead prevented by the device code being single-use
    // at the IdP and by our own row being consumed once.
    let claims = id_token
        .claims(&verifier, |_: Option<&Nonce>| Ok(()))
        .map_err(|e| OidcError::Rejected(format!("ID token verification failed: {e}")))?;

    Ok(claims.clone())
}

/// Translate an OAuth error body into the right variant.
fn map_oauth_error(body: &str, status: u16) -> OidcError {
    let Ok(parsed) = serde_json::from_str::<OauthErrorBody>(body) else {
        return OidcError::Unavailable(format!("provider returned HTTP {status}"));
    };
    let detail = parsed
        .error_description
        .unwrap_or_else(|| parsed.error.clone());
    match parsed.error.as_str() {
        "authorization_pending" => OidcError::Pending,
        "slow_down" => OidcError::SlowDown,
        // The human said no, or took too long. Terminal for this attempt.
        "access_denied" | "expired_token" => OidcError::Rejected(detail),
        // Anything else is our configuration: a wrong client id, a secret the
        // provider does not recognise, a grant type it will not issue.
        _ => OidcError::Config(detail),
    }
}
