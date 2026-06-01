//! Platform-level invitation persistence (V011).
//!
//! Mirrors `crate::invitations` for per-project invites: tokens are hashed at
//! rest, single-use, and consumed atomically by the register handler. The
//! distinction is that platform invitations have no project scope and carry a
//! `role` field (`user` or `superadmin`) controlling what `is_superadmin`
//! becomes on the new account.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

/// Role granted on acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformInviteRole {
    User,
    Superadmin,
}

impl PlatformInviteRole {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Superadmin => "superadmin",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "superadmin" => Some(Self::Superadmin),
            _ => None,
        }
    }
}

/// Listing row returned by [`list_pending`] for the admin UI.
#[derive(Debug, Clone)]
pub struct PendingInvitation {
    pub id: Uuid,
    pub email: String,
    pub role: PlatformInviteRole,
    pub invited_by: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

/// Lookup result for the consuming register handler. Includes only what's
/// needed to enforce the email-match guard and propagate the role.
#[derive(Debug, Clone)]
pub struct PendingForConsume {
    pub id: Uuid,
    pub email: String,
    pub role: PlatformInviteRole,
}

pub async fn create(
    client: &deadpool_postgres::Client,
    email: &str,
    role: PlatformInviteRole,
    token_hash: &str,
    invited_by: Option<Uuid>,
    expires_at: OffsetDateTime,
) -> Result<Uuid, DbError> {
    let role_str = role.as_str();
    let row = client
        .query_one(
            "INSERT INTO platform_invitations \
               (email, role, token_hash, invited_by, expires_at) \
             VALUES (lower($1), $2, $3, $4, $5) \
             RETURNING id",
            &[&email, &role_str, &token_hash, &invited_by, &expires_at],
        )
        .await?;
    Ok(row.get("id"))
}

/// Look up a pending invitation by token hash (not yet consumed, not
/// expired). Used by the register handler to validate an incoming token
/// before any mutation.
pub async fn find_pending(
    client: &deadpool_postgres::Client,
    token_hash: &str,
) -> Result<Option<PendingForConsume>, DbError> {
    let row = client
        .query_opt(
            "SELECT id, email, role FROM platform_invitations \
             WHERE token_hash = $1 \
               AND accepted_at IS NULL \
               AND expires_at > now()",
            &[&token_hash],
        )
        .await?;
    Ok(row.and_then(|r| {
        let role_str: String = r.get("role");
        PlatformInviteRole::parse(&role_str).map(|role| PendingForConsume {
            id: r.get("id"),
            email: r.get("email"),
            role,
        })
    }))
}

/// Distinguishes "unknown token" (404) from "expired or already consumed" (410)
/// for honest error responses.
pub async fn exists(
    client: &deadpool_postgres::Client,
    token_hash: &str,
) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM platform_invitations WHERE token_hash = $1) AS e",
            &[&token_hash],
        )
        .await?;
    Ok(row.get("e"))
}

/// Atomically mark an invitation as accepted. Returns true if it transitioned.
pub async fn mark_accepted(
    client: &deadpool_postgres::Client,
    token_hash: &str,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE platform_invitations SET accepted_at = now() \
             WHERE token_hash = $1 \
               AND accepted_at IS NULL \
               AND expires_at > now()",
            &[&token_hash],
        )
        .await?;
    Ok(n > 0)
}

pub async fn list_pending(
    client: &deadpool_postgres::Client,
) -> Result<Vec<PendingInvitation>, DbError> {
    let rows = client
        .query(
            "SELECT id, email, role, invited_by, expires_at, created_at \
             FROM platform_invitations \
             WHERE accepted_at IS NULL AND expires_at > now() \
             ORDER BY created_at DESC",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            let role_str: String = r.get("role");
            PlatformInviteRole::parse(&role_str).map(|role| PendingInvitation {
                id: r.get("id"),
                email: r.get("email"),
                role,
                invited_by: r.get("invited_by"),
                expires_at: r.get("expires_at"),
                created_at: r.get("created_at"),
            })
        })
        .collect())
}

/// Revoke a pending invitation by id. Returns true if it transitioned (was
/// pending and is now marked accepted to block reuse). We deliberately set
/// `accepted_at = now()` rather than deleting so audit / forensics keep the
/// row.
pub async fn revoke(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE platform_invitations SET accepted_at = now() \
             WHERE id = $1 AND accepted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(n > 0)
}
