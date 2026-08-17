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
    #[error("not a valid OpenSSH private key")]
    Parse,
    #[error("passphrase-protected keys are not supported")]
    Encrypted,
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

/// Adopt a private key the user already has, deriving its public half.
///
/// Re-encoded rather than stored verbatim, so what we persist is always
/// canonical OpenSSH regardless of what was pasted.
///
/// Passphrase-protected keys are refused: libgit2 is handed the key in memory
/// with no passphrase, so accepting one would only surface later as a
/// confusing authentication failure at push time.
///
/// # Errors
/// [`SshKeyError::Parse`] if the input is not an OpenSSH private key;
/// [`SshKeyError::Encrypted`] if it is protected by a passphrase.
pub fn import_openssh(pem: &str) -> Result<GeneratedKey, SshKeyError> {
    let key = PrivateKey::from_openssh(pem).map_err(|_| SshKeyError::Parse)?;
    if key.is_encrypted() {
        return Err(SshKeyError::Encrypted);
    }
    let private_openssh = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| SshKeyError::Encode)?
        .to_string();
    let public = key.public_key();
    Ok(GeneratedKey {
        private_openssh,
        public_openssh: public.to_openssh().map_err(|_| SshKeyError::Encode)?,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        key_type: key.algorithm().as_str().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::secret;

    #[test]
    fn imports_a_generated_key_and_derives_its_public_half() {
        let generated = generate_ed25519().unwrap();
        let imported = import_openssh(&generated.private_openssh).unwrap();
        assert_eq!(imported.public_openssh, generated.public_openssh);
        assert_eq!(imported.fingerprint, generated.fingerprint);
        assert_eq!(imported.key_type, "ssh-ed25519");
        assert!(imported.private_openssh.contains("OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn refuses_junk_and_public_keys() {
        assert!(matches!(
            import_openssh("not a key"),
            Err(SshKeyError::Parse)
        ));
        assert!(matches!(import_openssh(""), Err(SshKeyError::Parse)));
        // A *public* key is not a private key, however well-formed.
        let generated = generate_ed25519().unwrap();
        assert!(matches!(
            import_openssh(&generated.public_openssh),
            Err(SshKeyError::Parse)
        ));
    }

    /// A throwaway `ssh-keygen -t ed25519 -N …` fixture. It exists only to
    /// exercise the passphrase guard: we cannot construct an encrypted key at
    /// runtime, because that would require the `ssh-key` `encryption` feature
    /// and its cipher dependencies, which this workspace deliberately omits.
    const ENCRYPTED_FIXTURE: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAf3CdYoF
ViuTiPDLb7d6eJAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPGtsGBQM7w1B1IC
D2AZVBM/1RWMXbt0WjPBJaJDCsQvAAAAoG9m9uw5HVaj04gFCbsmLUuhHxB3cfkEGK0rp9
yiDMjNEewUH+iDtKsgf00pGztZO95FVZA0LsUQhDcal2pPp9LawD+2KnG591ZNOnvGQGSs
FFtemf8MZuZ1Or5k2tYLBlIUQU1Lc/VScklfFc+ugrTsjvYq/ONTR1qvUgfHT8bypOMz6k
fajF9svo4E4rZaal2zlbNHFHBK9fqCjfmGNOg=
-----END OPENSSH PRIVATE KEY-----
";

    /// Accepting one of these would only fail later, at push time, as an
    /// opaque authentication error: libgit2 gets the key with no passphrase.
    #[test]
    fn refuses_passphrase_protected_keys() {
        assert!(matches!(
            import_openssh(ENCRYPTED_FIXTURE),
            Err(SshKeyError::Encrypted)
        ));
    }

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
