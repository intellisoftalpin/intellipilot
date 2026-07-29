//! Last-activity tracking and account-status enforcement (V018).
//!
//! Two requirements meet in one mechanism:
//!
//! * The admin user list shows when each account was last active.
//! * A banned account must lose access promptly. Access tokens are stateless
//!   Paseto with a 15-minute TTL, so revoking refresh families alone would
//!   leave a banned user working for up to a quarter of an hour.
//!
//! Doing either naively means a database round trip on *every* authenticated
//! request — today the access-token path touches no database at all, and
//! giving that up to stamp a timestamp would be a poor trade. Instead we cache
//! each user's status for [`CHECK_TTL`] and refresh it with a single statement
//! that stamps `last_seen_at` and returns the status together. The cost is one
//! write per active user per window; the ban lag is bounded by the same
//! window.
//!
//! In-process state, consistent with the existing per-IP rate limiter — this
//! deployment is single-node by design. On a multi-instance deployment each
//! instance keeps its own cache, which costs a little extra writing and
//! nothing in correctness: the bound on ban lag is unchanged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use intellipilot_db::users::AccountStatus;
use uuid::Uuid;

/// How long a checked status is trusted before being re-read.
///
/// Also the upper bound on how long a banned user can keep using an
/// already-issued access token, and the resolution of "last active".
pub const CHECK_TTL: Duration = Duration::from_secs(30);

/// Entries older than this are dropped wholesale, bounding memory on an
/// instance that has seen many users.
const SWEEP_AFTER: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy)]
struct Entry {
    status: AccountStatus,
    checked: Instant,
}

/// Cached account status keyed by user.
#[derive(Clone)]
pub struct Presence {
    entries: Arc<Mutex<HashMap<Uuid, Entry>>>,
    ttl: Duration,
}

impl std::fmt::Debug for Presence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Presence")
            .field("ttl", &self.ttl)
            .field(
                "tracked",
                &self.entries.lock().map(|e| e.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl Default for Presence {
    fn default() -> Self {
        Self::new(CHECK_TTL)
    }
}

impl Presence {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// The cached status, if still fresh.
    fn cached(&self, user_id: Uuid) -> Option<AccountStatus> {
        let entries = self.entries.lock().ok()?;
        entries
            .get(&user_id)
            .filter(|e| e.checked.elapsed() < self.ttl)
            .map(|e| e.status)
    }

    fn store(&self, user_id: Uuid, status: AccountStatus) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() > 1024 {
            entries.retain(|_, e| e.checked.elapsed() < SWEEP_AFTER);
        }
        entries.insert(
            user_id,
            Entry {
                status,
                checked: Instant::now(),
            },
        );
    }

    /// Drop a user's cached status so the next request re-reads it.
    ///
    /// Called when an admin bans, unbans or deactivates someone: on this node
    /// the change then takes effect on their very next request rather than
    /// after the TTL.
    pub fn invalidate(&self, user_id: Uuid) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(&user_id);
        }
    }

    /// Resolve a user's status, stamping activity when the cache is cold.
    ///
    /// `None` means the account no longer exists (or was soft-deleted) and the
    /// caller should reject the request.
    pub async fn check(
        &self,
        client: &deadpool_postgres::Client,
        user_id: Uuid,
    ) -> Option<AccountStatus> {
        if let Some(status) = self.cached(user_id) {
            return Some(status);
        }
        match intellipilot_db::users::touch_last_seen(client, user_id).await {
            Ok(Some(status)) => {
                self.store(user_id, status);
                Some(status)
            }
            Ok(None) => None,
            Err(e) => {
                // Availability over strictness: a database blip should not log
                // the whole platform out. The token was cryptographically
                // valid, and the next window re-checks.
                tracing::warn!(error = %e, "presence check failed; allowing request");
                Some(AccountStatus {
                    is_active: true,
                    is_banned: false,
                })
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn ok() -> AccountStatus {
        AccountStatus {
            is_active: true,
            is_banned: false,
        }
    }

    #[test]
    fn fresh_entries_are_served_from_cache() {
        let p = Presence::new(Duration::from_secs(30));
        let id = Uuid::now_v7();
        assert!(p.cached(id).is_none(), "cold cache must miss");

        p.store(id, ok());
        assert_eq!(p.cached(id), Some(ok()), "fresh entry should hit");
    }

    #[test]
    fn expired_entries_are_not_served() {
        // A zero TTL makes every stored entry immediately stale.
        let p = Presence::new(Duration::ZERO);
        let id = Uuid::now_v7();
        p.store(id, ok());
        assert!(p.cached(id).is_none(), "stale entry must miss");
    }

    #[test]
    fn invalidate_forces_a_recheck() {
        let p = Presence::new(Duration::from_secs(30));
        let id = Uuid::now_v7();
        p.store(id, ok());
        assert!(p.cached(id).is_some());

        p.invalidate(id);
        assert!(
            p.cached(id).is_none(),
            "a ban must not keep serving from cache"
        );
    }

    #[test]
    fn banned_status_round_trips() {
        let p = Presence::new(Duration::from_secs(30));
        let id = Uuid::now_v7();
        let banned = AccountStatus {
            is_active: true,
            is_banned: true,
        };
        p.store(id, banned);

        let got = p.cached(id).expect("entry present");
        assert!(!got.may_authenticate(), "banned must not authenticate");
    }

    #[test]
    fn inactive_status_blocks_authentication() {
        let status = AccountStatus {
            is_active: false,
            is_banned: false,
        };
        assert!(!status.may_authenticate());
    }
}
