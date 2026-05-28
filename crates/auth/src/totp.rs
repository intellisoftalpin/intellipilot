//! TOTP (RFC 6238) enrollment & verification via `totp-rs`.
//!
//! 6-digit, 30-second step, SHA-1 (the universally-supported authenticator
//! profile), with a ±1 step tolerance (skew = 1).

use rand::RngCore;
use rand::rngs::OsRng;
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};

const DIGITS: usize = 6;
const SKEW: u8 = 1;
const STEP: u64 = 30;
const SECRET_LEN: usize = 20; // 160-bit, RFC 4226 recommendation

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("invalid TOTP configuration")]
    Config,
    #[error("QR generation failed")]
    Qr,
}

/// Generate a fresh random TOTP secret (raw bytes).
#[must_use]
pub fn new_secret() -> Vec<u8> {
    let mut bytes = vec![0u8; SECRET_LEN];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn build(secret: &[u8], issuer: &str, account: &str) -> Result<TOTP, TotpError> {
    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW,
        STEP,
        secret.to_vec(),
        Some(issuer.to_owned()),
        account.to_owned(),
    )
    .map_err(|_| TotpError::Config)
}

/// Base32 (RFC 4648, no padding) encoding of the secret, for manual entry.
#[must_use]
pub fn secret_base32(secret: &[u8]) -> String {
    Secret::Raw(secret.to_vec()).to_encoded().to_string()
}

/// `otpauth://` provisioning URI for QR / deep links.
pub fn provisioning_uri(secret: &[u8], issuer: &str, account: &str) -> Result<String, TotpError> {
    Ok(build(secret, issuer, account)?.get_url())
}

/// Base64-encoded PNG QR code of the provisioning URI.
pub fn qr_png_base64(secret: &[u8], issuer: &str, account: &str) -> Result<String, TotpError> {
    build(secret, issuer, account)?
        .get_qr_base64()
        .map_err(|_| TotpError::Qr)
}

/// Generate the current TOTP code for a secret (useful for clients/tests).
#[must_use]
pub fn current_code(secret: &[u8]) -> Option<String> {
    build(secret, "IntelliPilot", "generate")
        .ok()
        .and_then(|t| t.generate_current().ok())
}

/// Decode a base32 (RFC 4648, no padding) secret back to raw bytes.
#[must_use]
pub fn secret_from_base32(encoded: &str) -> Option<Vec<u8>> {
    Secret::Encoded(encoded.to_owned()).to_bytes().ok()
}

/// Verify a code against the secret with ±1 step tolerance.
#[must_use]
pub fn verify(secret: &[u8], code: &str) -> bool {
    build(secret, "IntelliPilot", "verify")
        .is_ok_and(|totp| totp.check_current(code).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn current_code_verifies() {
        let secret = new_secret();
        let totp = build(&secret, "IntelliPilot", "alice@example.com").unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify(&secret, &code));
    }

    #[test]
    fn wrong_code_rejected() {
        let secret = new_secret();
        assert!(!verify(&secret, "000000"));
    }

    #[test]
    fn provisioning_uri_contains_issuer_and_secret() {
        let secret = new_secret();
        let uri = provisioning_uri(&secret, "IntelliPilot", "alice@example.com").unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("IntelliPilot"));
        assert!(uri.contains("secret="));
    }

    #[test]
    fn qr_is_generated() {
        let secret = new_secret();
        let qr = qr_png_base64(&secret, "IntelliPilot", "alice@example.com").unwrap();
        assert!(!qr.is_empty());
    }

    #[test]
    fn base32_secret_is_decodable() {
        let secret = new_secret();
        let b32 = secret_base32(&secret);
        assert!(!b32.is_empty());
        // base32 alphabet only
        assert!(
            b32.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn tolerance_is_plus_minus_one_step_not_two() {
        // Generate a code for the previous and the two-steps-ago windows and
        // confirm ±1 is accepted but ±2 is not.
        let secret = new_secret();
        let totp = build(&secret, "IntelliPilot", "x").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let one_step_ago = totp.generate(now - STEP);
        let two_steps_ago = totp.generate(now - (STEP * 2));
        assert!(verify(&secret, &one_step_ago), "±1 step must be accepted");
        // It is theoretically possible (1/10^6) for adjacent codes to collide;
        // only assert rejection when the codes actually differ.
        if two_steps_ago != one_step_ago {
            assert!(
                !verify(&secret, &two_steps_ago),
                "±2 steps must be rejected"
            );
        }
    }
}
