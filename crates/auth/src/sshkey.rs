//! Server-side SSH keypair generation for the per-project git credential vault.
//!
//! Keys are Ed25519. The private key is produced as an OpenSSH PEM string for
//! the caller to encrypt at rest via [`crate::secret`]; it is never persisted
//! or returned to clients in plaintext. The public key (OpenSSH one-line form)
//! and its SHA256 fingerprint are safe to display so a user can register the
//! public key as a deploy key on their git host.

use rand::rngs::OsRng;
use ssh_key::private::PrivateKey;
use ssh_key::{Algorithm, HashAlg, LineEnding};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshKeyError {
    #[error("failed to generate ssh key")]
    Generate,
    #[error("failed to encode ssh key")]
    Encode,
}

/// A freshly generated Ed25519 keypair.
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    /// OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`). A secret:
    /// encrypt before storing; never return it to clients.
    pub private_openssh: String,
    /// OpenSSH public key, one-line form (`ssh-ed25519 AAAA...`).
    pub public_openssh: String,
    /// SHA256 fingerprint (`SHA256:...`), safe to display.
    pub fingerprint: String,
    /// Algorithm label, e.g. `ed25519`.
    pub key_type: String,
}

/// Generate a new Ed25519 keypair.
pub fn generate_ed25519() -> Result<GeneratedKey, SshKeyError> {
    let private =
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|_| SshKeyError::Generate)?;
    let private_openssh = private
        .to_openssh(LineEnding::LF)
        .map_err(|_| SshKeyError::Encode)?
        .to_string();
    let public = private.public_key();
    let public_openssh = public.to_openssh().map_err(|_| SshKeyError::Encode)?;
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    Ok(GeneratedKey {
        private_openssh,
        public_openssh,
        fingerprint,
        key_type: "ed25519".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::secret;

    #[test]
    fn generates_parseable_ed25519_keypair() {
        let key = generate_ed25519().unwrap();
        assert_eq!(key.key_type, "ed25519");
        // Private key parses back as an OpenSSH key.
        let parsed = PrivateKey::from_openssh(&key.private_openssh).unwrap();
        assert_eq!(parsed.algorithm(), Algorithm::Ed25519);
        // Public key is the one-line OpenSSH form and parses.
        assert!(key.public_openssh.starts_with("ssh-ed25519 "));
        ssh_key::PublicKey::from_openssh(&key.public_openssh).unwrap();
        // Fingerprint is a SHA256 fingerprint.
        assert!(key.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn each_generation_is_unique() {
        let a = generate_ed25519().unwrap();
        let b = generate_ed25519().unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
        assert_ne!(a.public_openssh, b.public_openssh);
    }

    #[test]
    fn private_key_encrypts_at_rest_and_round_trips() {
        const PEPPER: &[u8] = b"a-sufficiently-long-server-pepper-value";
        let key = generate_ed25519().unwrap();
        let enc = secret::encrypt(Some(PEPPER), key.private_openssh.as_bytes()).unwrap();
        // Ciphertext must not contain the plaintext PEM marker.
        assert!(
            !enc.windows(11).any(|w| w == b"BEGIN OPENS"),
            "encrypted blob must not contain plaintext key material"
        );
        let dec = secret::decrypt(Some(PEPPER), &enc).unwrap();
        assert_eq!(dec, key.private_openssh.as_bytes());
    }
}
