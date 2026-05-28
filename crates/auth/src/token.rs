//! Paseto v4 local access tokens.
//!
//! Access tokens are short-lived (default 15 min). They carry the user id as
//! `sub` and a `type=access` claim. Symmetric key comes from config.

use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::SymmetricKey;
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::{Local, local};
use thiserror::Error;
use uuid::Uuid;

pub const ACCESS_TTL_SECS: i64 = 15 * 60;
/// Ephemeral token issued after a correct password when a second factor is
/// still required. Short-lived; carries `type=mfa`.
pub const MFA_TTL_SECS: i64 = 60;
const TOKEN_TYPE_CLAIM: &str = "type";
const TOKEN_TYPE_ACCESS: &str = "access";
const TOKEN_TYPE_MFA: &str = "mfa";

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("invalid signing key")]
    InvalidKey,
    #[error("failed to build token")]
    Build,
    #[error("token invalid or expired")]
    Invalid,
}

/// The 32-byte symmetric key for Paseto v4 local.
#[derive(Clone)]
pub struct AccessKey(SymmetricKey<V4>);

impl std::fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccessKey(<redacted>)")
    }
}

impl AccessKey {
    /// Build from raw 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        SymmetricKey::<V4>::from(bytes)
            .map(Self)
            .map_err(|_| TokenError::InvalidKey)
    }
}

#[derive(Debug, Clone)]
pub struct AccessClaims {
    pub user_id: Uuid,
}

/// Issue an access token for `user_id` valid for `ttl_secs`.
pub fn issue_access_token(
    key: &AccessKey,
    user_id: Uuid,
    ttl_secs: i64,
) -> Result<String, TokenError> {
    issue_typed(key, user_id, ttl_secs, TOKEN_TYPE_ACCESS)
}

/// Issue a short-lived MFA challenge token.
pub fn issue_mfa_token(
    key: &AccessKey,
    user_id: Uuid,
    ttl_secs: i64,
) -> Result<String, TokenError> {
    issue_typed(key, user_id, ttl_secs, TOKEN_TYPE_MFA)
}

/// Verify and decode an access token.
pub fn verify_access_token(key: &AccessKey, token: &str) -> Result<AccessClaims, TokenError> {
    verify_typed(key, token, TOKEN_TYPE_ACCESS)
}

/// Verify and decode an MFA challenge token.
pub fn verify_mfa_token(key: &AccessKey, token: &str) -> Result<AccessClaims, TokenError> {
    verify_typed(key, token, TOKEN_TYPE_MFA)
}

fn issue_typed(
    key: &AccessKey,
    user_id: Uuid,
    ttl_secs: i64,
    token_type: &str,
) -> Result<String, TokenError> {
    let mut claims = Claims::new().map_err(|_| TokenError::Build)?;
    claims
        .subject(&user_id.to_string())
        .map_err(|_| TokenError::Build)?;
    claims
        .add_additional(TOKEN_TYPE_CLAIM, token_type)
        .map_err(|_| TokenError::Build)?;
    set_expiry(&mut claims, ttl_secs)?;

    local::encrypt(&key.0, &claims, None, None).map_err(|_| TokenError::Build)
}

fn verify_typed(
    key: &AccessKey,
    token: &str,
    expected_type: &str,
) -> Result<AccessClaims, TokenError> {
    // Default rules validate the standard time claims (exp/nbf/iat).
    let rules = ClaimsValidationRules::new();

    let untrusted =
        UntrustedToken::<Local, V4>::try_from(token).map_err(|_| TokenError::Invalid)?;
    let trusted =
        local::decrypt(&key.0, &untrusted, &rules, None, None).map_err(|_| TokenError::Invalid)?;

    let claims = trusted.payload_claims().ok_or(TokenError::Invalid)?;

    // Reject tokens that aren't of the expected type (prevents using e.g. an
    // mfa token as an access token).
    let token_type = claims
        .get_claim(TOKEN_TYPE_CLAIM)
        .and_then(serde_json::Value::as_str);
    if token_type != Some(expected_type) {
        return Err(TokenError::Invalid);
    }

    let sub = claims
        .get_claim("sub")
        .and_then(serde_json::Value::as_str)
        .ok_or(TokenError::Invalid)?;
    let user_id = Uuid::parse_str(sub).map_err(|_| TokenError::Invalid)?;

    Ok(AccessClaims { user_id })
}

fn set_expiry(claims: &mut Claims, ttl_secs: i64) -> Result<(), TokenError> {
    let exp = time::OffsetDateTime::now_utc()
        .checked_add(time::Duration::seconds(ttl_secs))
        .ok_or(TokenError::Build)?;
    let formatted = exp
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| TokenError::Build)?;
    claims
        .expiration(&formatted)
        .map_err(|_| TokenError::Build)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::integer_division
    )]
    use super::*;

    fn test_key() -> AccessKey {
        AccessKey::from_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn round_trip() {
        let key = test_key();
        let uid = Uuid::now_v7();
        let token = issue_access_token(&key, uid, ACCESS_TTL_SECS).unwrap();
        let claims = verify_access_token(&key, &token).unwrap();
        assert_eq!(claims.user_id, uid);
    }

    #[test]
    fn wrong_key_fails() {
        let token = issue_access_token(&test_key(), Uuid::now_v7(), ACCESS_TTL_SECS).unwrap();
        let other = AccessKey::from_bytes(&[9u8; 32]).unwrap();
        assert!(verify_access_token(&other, &token).is_err());
    }

    #[test]
    fn expired_token_fails() {
        let key = test_key();
        let token = issue_access_token(&key, Uuid::now_v7(), -1).unwrap();
        assert!(verify_access_token(&key, &token).is_err());
    }

    #[test]
    fn tampered_token_fails() {
        let key = test_key();
        let token = issue_access_token(&key, Uuid::now_v7(), ACCESS_TTL_SECS).unwrap();
        // Flip a character in the payload section.
        let mut chars: Vec<char> = token.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();
        assert!(verify_access_token(&key, &tampered).is_err());
    }

    #[test]
    fn fuzz_1k_random_mutations_never_verify() {
        use rand::Rng;
        let key = test_key();
        let token = issue_access_token(&key, Uuid::now_v7(), ACCESS_TTL_SECS).unwrap();
        let original = token.into_bytes();
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let mut bytes = original.clone();
            let pos = rng.gen_range(0..bytes.len());
            let orig = bytes[pos];
            let mut replacement = orig;
            while replacement == orig {
                replacement = rng.r#gen();
            }
            bytes[pos] = replacement;
            if let Ok(mutated) = std::str::from_utf8(&bytes) {
                assert!(
                    verify_access_token(&key, mutated).is_err(),
                    "a tampered token verified successfully: {mutated}"
                );
            }
        }
    }
}
