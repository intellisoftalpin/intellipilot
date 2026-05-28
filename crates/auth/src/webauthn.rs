//! WebAuthn (passkey) ceremony helpers, thin wrappers over `webauthn-rs`.
//!
//! The HTTP layer persists the intermediate registration/authentication state
//! between `start` and `finish` (see `webauthn_states` table) and the stored
//! `Passkey` credentials.

use thiserror::Error;
use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder};

#[derive(Debug, Error)]
pub enum WebauthnError {
    #[error("invalid relying-party configuration: {0}")]
    Config(String),
}

/// Relying-Party configuration, sourced from env at startup.
#[derive(Debug, Clone)]
pub struct RpConfig {
    /// Effective domain, e.g. `example.com` (or `localhost` in dev).
    pub rp_id: String,
    /// Full origin, e.g. `https://app.example.com` (or `http://localhost`).
    pub rp_origin: String,
    /// Human-readable RP name shown by authenticators.
    pub rp_name: String,
}

impl Default for RpConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_owned(),
            rp_origin: "http://localhost".to_owned(),
            rp_name: "IntelliPilot".to_owned(),
        }
    }
}

/// Build a configured `Webauthn` instance.
pub fn build(cfg: &RpConfig) -> Result<Webauthn, WebauthnError> {
    let origin = Url::parse(&cfg.rp_origin).map_err(|e| WebauthnError::Config(e.to_string()))?;
    let builder = WebauthnBuilder::new(&cfg.rp_id, &origin)
        .map_err(|e| WebauthnError::Config(e.to_string()))?
        .rp_name(&cfg.rp_name);
    builder
        .build()
        .map_err(|e| WebauthnError::Config(e.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn builds_with_localhost_defaults() {
        let wa = build(&RpConfig::default());
        assert!(wa.is_ok());
    }

    #[test]
    fn rejects_mismatched_origin() {
        // rp_id not a registrable suffix of the origin → error.
        let cfg = RpConfig {
            rp_id: "example.com".to_owned(),
            rp_origin: "http://localhost".to_owned(),
            rp_name: "x".to_owned(),
        };
        assert!(build(&cfg).is_err());
    }
}
