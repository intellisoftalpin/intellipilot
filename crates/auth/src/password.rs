//! Argon2id password hashing + strength policy.

use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use argon2::{Algorithm, Argon2, Params, Version};
use thiserror::Error;
use zxcvbn::{Score, zxcvbn};

/// OWASP 2024 Argon2id parameters: 64 MiB memory, 3 iterations, 4 lanes.
const ARGON2_M_COST_KIB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// Minimum password length and zxcvbn strength.
pub const MIN_PASSWORD_LEN: usize = 12;
pub const MIN_ZXCVBN_SCORE: Score = Score::Three;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("hashing failed")]
    Hash,
    #[error("invalid stored hash")]
    InvalidHash,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WeakPassword {
    #[error("password must be at least {MIN_PASSWORD_LEN} characters")]
    TooShort,
    #[error("password is too weak or guessable")]
    TooGuessable,
}

fn argon2(pepper: Option<&[u8]>) -> Result<Argon2<'_>, PasswordError> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|_| PasswordError::Hash)?;
    match pepper {
        Some(secret) => {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
                .map_err(|_| PasswordError::Hash)
        }
        None => Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params)),
    }
}

/// Hash a password to a PHC string (`$argon2id$v=19$m=65536,t=3,p=4$...`).
/// `pepper` is an optional server-side secret kept separately from the DB.
pub fn hash_password(password: &str, pepper: Option<&[u8]>) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2(pepper)?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| PasswordError::Hash)?;
    Ok(hash.to_string())
}

/// Verify a password against a stored PHC hash. Returns `Ok(false)` on
/// mismatch, `Err` only when the stored hash is unparsable.
pub fn verify_password(
    password: &str,
    stored_hash: &str,
    pepper: Option<&[u8]>,
) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(stored_hash).map_err(|_| PasswordError::InvalidHash)?;
    Ok(argon2(pepper)?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Enforce password policy: minimum length + zxcvbn strength (using related
/// user inputs like email/username to penalise guessable passwords).
pub fn check_strength(password: &str, user_inputs: &[&str]) -> Result<(), WeakPassword> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(WeakPassword::TooShort);
    }
    let estimate = zxcvbn(password, user_inputs);
    if estimate.score() < MIN_ZXCVBN_SCORE {
        return Err(WeakPassword::TooGuessable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn hash_is_argon2id_and_verifies() {
        let hash = hash_password("correct horse battery staple", None).unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &hash, None).unwrap());
        assert!(!verify_password("wrong password entirely", &hash, None).unwrap());
    }

    #[test]
    fn pepper_changes_verification() {
        let pepper = b"server-side-secret";
        let hash = hash_password("correct horse battery staple", Some(pepper)).unwrap();
        // Right pepper verifies.
        assert!(verify_password("correct horse battery staple", &hash, Some(pepper)).unwrap());
        // Wrong/missing pepper fails.
        assert!(!verify_password("correct horse battery staple", &hash, None).unwrap());
    }

    #[test]
    fn rejects_short_password() {
        assert_eq!(check_strength("short", &[]), Err(WeakPassword::TooShort));
    }

    #[test]
    fn rejects_guessable_password() {
        assert_eq!(
            check_strength("password1234", &[]),
            Err(WeakPassword::TooGuessable)
        );
    }

    #[test]
    fn accepts_strong_password() {
        assert!(check_strength("7xK!pq2$mz9Wbe", &[]).is_ok());
    }

    #[test]
    fn penalises_password_containing_user_inputs() {
        // A password built from the user's own email should be rejected.
        let result = check_strength("alice@example.com1", &["alice@example.com"]);
        assert!(result.is_err());
    }
}
