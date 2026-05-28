//! Opaque refresh tokens.
//!
//! The raw token is 256 bits of CSPRNG output, base64url-encoded, handed to
//! the client once. Only its SHA-256 hex digest is stored server-side, so a
//! database leak does not expose usable tokens.

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

pub const REFRESH_TTL_SECS: i64 = 30 * 24 * 60 * 60; // 30 days

/// A freshly minted refresh token: the raw value goes to the client, the
/// hash is stored.
#[derive(Debug, Clone)]
pub struct NewRefreshToken {
    pub raw: String,
    pub hash: String,
}

/// Generate a new opaque refresh token.
#[must_use]
pub fn generate() -> NewRefreshToken {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let raw = base64url(&bytes);
    let hash = hash_token(&raw);
    NewRefreshToken { raw, hash }
}

/// SHA-256 hex digest of a raw refresh token, for lookup/storage.
#[must_use]
pub fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    hex_encode(&digest)
}

// Hand-rolled byte encoders: bit-twiddling and fixed-table indexing are
// inherent here and provably in-bounds, so the arithmetic/indexing lints are
// noise for these two functions.
#[allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]
fn base64url(bytes: &[u8]) -> String {
    // URL-safe, no padding. Hand-rolled to avoid pulling a base64 crate into
    // the auth surface.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

#[allow(clippy::cast_lossless)]
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn generates_unique_tokens() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let t = generate();
            assert!(seen.insert(t.raw.clone()), "duplicate raw token");
            // hash is deterministic for the raw value
            assert_eq!(t.hash, hash_token(&t.raw));
            // hash is 64 hex chars (sha256)
            assert_eq!(t.hash.len(), 64);
            assert!(t.hash.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn hash_is_stable_and_distinct() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("xyz"));
    }

    #[test]
    fn raw_is_url_safe() {
        for _ in 0..100 {
            let t = generate();
            assert!(
                t.raw
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            );
        }
    }
}
