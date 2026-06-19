//! Authentication & authorization primitives.
//!
//! Phase 1: Argon2id password hashing + policy, Paseto v4 access tokens,
//! opaque refresh tokens.
//! Phase 2: TOTP, recovery codes, secret encryption, WebAuthn ceremonies.

pub mod password;
pub mod recovery;
pub mod refresh;
pub mod secret;
pub mod sshkey;
pub mod token;
pub mod totp;
pub mod webauthn;

pub use password::{PasswordError, WeakPassword};
pub use recovery::{RECOVERY_CODE_COUNT, RecoveryCode};
pub use refresh::{NewRefreshToken, REFRESH_TTL_SECS};
pub use secret::SecretError;
pub use sshkey::{GeneratedKey, SshKeyError};
pub use token::{ACCESS_TTL_SECS, AccessClaims, AccessKey, MFA_TTL_SECS, TokenError};
pub use webauthn::{RpConfig, WebauthnError};
