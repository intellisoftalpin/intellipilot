//! Symmetric encryption of small secrets at rest (e.g. TOTP seeds).
//!
//! ChaCha20-Poly1305 AEAD with a key derived from the server pepper via
//! HKDF-SHA256. Ciphertext layout: `nonce(12) || ciphertext+tag`.

use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;

const HKDF_INFO: &[u8] = b"intellipilot-secret-encryption-v1";
const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("no encryption key configured (server pepper required)")]
    NoKey,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
}

/// Derives the AEAD key from the pepper. `pepper` must be present; secret
/// encryption is unavailable without it.
fn cipher(pepper: Option<&[u8]>) -> Result<ChaCha20Poly1305, SecretError> {
    let pepper = pepper.ok_or(SecretError::NoKey)?;
    let hk = Hkdf::<Sha256>::new(None, pepper);
    let mut key_bytes = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|_| SecretError::Encrypt)?;
    let key = Key::from_slice(&key_bytes);
    Ok(ChaCha20Poly1305::new(key))
}

/// Encrypt `plaintext`, returning `nonce || ciphertext`.
pub fn encrypt(pepper: Option<&[u8]>, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
    let cipher = cipher(pepper)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| SecretError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN.saturating_add(ciphertext.len()));
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data produced by [`encrypt`].
pub fn decrypt(pepper: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, SecretError> {
    if data.len() < NONCE_LEN {
        return Err(SecretError::Decrypt);
    }
    let cipher = cipher(pepper)?;
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SecretError::Decrypt)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const PEPPER: &[u8] = b"a-sufficiently-long-server-pepper-value";

    #[test]
    fn round_trip() {
        let ct = encrypt(Some(PEPPER), b"super secret seed").unwrap();
        let pt = decrypt(Some(PEPPER), &ct).unwrap();
        assert_eq!(pt, b"super secret seed");
    }

    #[test]
    fn ciphertext_differs_each_time() {
        let a = encrypt(Some(PEPPER), b"same").unwrap();
        let b = encrypt(Some(PEPPER), b"same").unwrap();
        assert_ne!(a, b, "random nonce must make ciphertexts differ");
    }

    #[test]
    fn wrong_pepper_fails() {
        let ct = encrypt(Some(PEPPER), b"secret").unwrap();
        assert!(decrypt(Some(b"different-pepper-entirely-here"), &ct).is_err());
    }

    #[test]
    fn requires_key() {
        assert!(matches!(encrypt(None, b"x"), Err(SecretError::NoKey)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut ct = encrypt(Some(PEPPER), b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(decrypt(Some(PEPPER), &ct).is_err());
    }
}
