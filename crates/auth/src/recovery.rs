//! Single-use recovery codes.
//!
//! Generated at 2FA enrollment, shown to the user exactly once. Stored
//! argon2id-hashed (with the same optional pepper as passwords).

use rand::RngCore;
use rand::rngs::OsRng;

use crate::password::{self, PasswordError};

/// Number of recovery codes issued per enrollment.
pub const RECOVERY_CODE_COUNT: usize = 10;
const GROUPS: usize = 3;
const GROUP_LEN: usize = 4;
// Crockford-ish base32 without ambiguous chars (no I, L, O, U).
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";

/// A generated recovery code: plaintext for one-time display, hash for storage.
#[derive(Debug, Clone)]
pub struct RecoveryCode {
    pub plaintext: String,
    pub hash: String,
}

// Fixed-table indexing with a modulo into a known-length alphabet — provably
// in-bounds, so the indexing/arithmetic lints are noise here.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn random_code() -> String {
    let mut rng = OsRng;
    let mut groups = Vec::with_capacity(GROUPS);
    for _ in 0..GROUPS {
        let mut g = String::with_capacity(GROUP_LEN);
        for _ in 0..GROUP_LEN {
            let idx = (rng.next_u32() as usize) % ALPHABET.len();
            g.push(ALPHABET[idx] as char);
        }
        groups.push(g);
    }
    groups.join("-")
}

/// Normalize a user-entered code (uppercase, strip spaces) before hashing or
/// comparison. Dashes are kept.
#[must_use]
pub fn normalize(code: &str) -> String {
    code.trim().to_uppercase().replace(' ', "")
}

/// Generate a fresh set of recovery codes, hashing each with argon2id.
pub fn generate_set(pepper: Option<&[u8]>) -> Result<Vec<RecoveryCode>, PasswordError> {
    let mut out = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let plaintext = random_code();
        let hash = password::hash_password(&normalize(&plaintext), pepper)?;
        out.push(RecoveryCode { plaintext, hash });
    }
    Ok(out)
}

/// Verify a candidate code against a stored hash.
pub fn verify(candidate: &str, stored_hash: &str, pepper: Option<&[u8]>) -> bool {
    password::verify_password(&normalize(candidate), stored_hash, pepper).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn generates_ten_unique_codes() {
        let set = generate_set(None).unwrap();
        assert_eq!(set.len(), RECOVERY_CODE_COUNT);
        let uniques: HashSet<_> = set.iter().map(|c| c.plaintext.clone()).collect();
        assert_eq!(uniques.len(), RECOVERY_CODE_COUNT, "codes must be unique");
    }

    #[test]
    fn code_verifies_against_its_hash() {
        let set = generate_set(None).unwrap();
        let first = &set[0];
        assert!(verify(&first.plaintext, &first.hash, None));
        assert!(!verify("WRONG-CODE-HERE", &first.hash, None));
    }

    #[test]
    fn verification_is_case_and_space_insensitive() {
        let set = generate_set(None).unwrap();
        let c = &set[0];
        let messy = format!("  {}  ", c.plaintext.to_lowercase());
        assert!(verify(&messy, &c.hash, None));
    }

    #[test]
    fn format_is_grouped() {
        let set = generate_set(None).unwrap();
        // e.g. ABCD-EFGH-JKMN
        let parts: Vec<&str> = set[0].plaintext.split('-').collect();
        assert_eq!(parts.len(), GROUPS);
        assert!(parts.iter().all(|p| p.len() == GROUP_LEN));
    }
}
