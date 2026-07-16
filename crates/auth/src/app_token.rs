//! App tokens — long-lived machine credentials.
//!
//! Like refresh tokens, the raw value is 256 bits of CSPRNG output handed to
//! the client once; only its SHA-256 hex digest is stored. The raw value
//! carries the `ipat_` prefix so the auth layer can distinguish it from a
//! Paseto access token in the same `Authorization: Bearer` header.

use rand::RngCore;
use rand::rngs::OsRng;

/// Raw secret prefix. Mirrors `intellipilot_core::app_token::TOKEN_PREFIX`.
pub const PREFIX: &str = "ipat_";

/// Raw personal-token secret prefix. Mirrors
/// `intellipilot_core::app_token::PERSONAL_TOKEN_PREFIX`.
pub const PERSONAL_PREFIX: &str = "ippt_";

/// A freshly minted app token: the raw secret goes to the client once; the
/// hash + display hints are stored.
#[derive(Debug, Clone)]
pub struct NewAppToken {
    /// Full secret, e.g. `ipat_Ab12…`. Shown to the admin exactly once.
    pub raw: String,
    /// SHA-256 hex digest, for storage + lookup.
    pub hash: String,
    /// Leading display hint, e.g. `ipat_Ab12cd`.
    pub prefix: String,
    /// Last 4 chars of the secret.
    pub last4: String,
}

/// Generate a new opaque app token.
#[must_use]
pub fn generate() -> NewAppToken {
    generate_with_prefix(PREFIX)
}

/// Generate a new opaque personal app token (`ippt_…`).
#[must_use]
pub fn generate_personal() -> NewAppToken {
    generate_with_prefix(PERSONAL_PREFIX)
}

fn generate_with_prefix(secret_prefix: &str) -> NewAppToken {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let raw = format!("{secret_prefix}{}", crate::refresh::base64url(&bytes));
    let hash = hash_token(&raw);
    // `raw` is pure ASCII (prefix + base64url alphabet), so byte slicing is
    // char-safe. Display hint = the 5-char prefix + 6 leading secret chars.
    let prefix = raw.chars().take(11).collect();
    let len = raw.len();
    let last4 = raw.get(len.saturating_sub(4)..).unwrap_or("").to_owned();
    NewAppToken {
        raw,
        hash,
        prefix,
        last4,
    }
}

/// SHA-256 hex digest of a raw app token, for lookup/storage.
#[must_use]
pub fn hash_token(raw: &str) -> String {
    crate::refresh::hash_token(raw)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn personal_tokens_carry_their_own_prefix() {
        let t = generate_personal();
        assert!(t.raw.starts_with(PERSONAL_PREFIX), "prefix: {}", t.raw);
        assert!(!t.raw.starts_with(PREFIX));
        assert_eq!(t.hash, hash_token(&t.raw));
        assert!(t.raw.starts_with(&t.prefix));
        assert!(t.raw.ends_with(&t.last4));
    }

    #[test]
    fn generates_unique_prefixed_tokens() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let t = generate();
            assert!(t.raw.starts_with(PREFIX), "missing prefix: {}", t.raw);
            assert!(seen.insert(t.raw.clone()), "duplicate token");
            assert_eq!(t.hash, hash_token(&t.raw));
            assert_eq!(t.hash.len(), 64);
            assert!(t.raw.ends_with(&t.last4));
            assert!(t.raw.starts_with(&t.prefix));
        }
    }
}
