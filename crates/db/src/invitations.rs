//! Invitation persistence (token hashed at rest, single-use).

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

/// Details needed to accept an invitation.
#[derive(Debug, Clone)]
pub struct AcceptedInvitation {
    pub project_id: Uuid,
    pub role_id: Uuid,
    pub email: String,
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    email: &str,
    role_id: Uuid,
    token_hash: &str,
    invited_by: Option<Uuid>,
    expires_at: OffsetDateTime,
) -> Result<Uuid, DbError> {
    let row = client
        .query_one(
            "INSERT INTO invitations (project_id, email, role_id, token_hash, invited_by, expires_at) \
             VALUES ($1, lower($2), $3, $4, $5, $6) RETURNING id",
            &[&project_id, &email, &role_id, &token_hash, &invited_by, &expires_at],
        )
        .await?;
    Ok(row.get("id"))
}

/// Look up a pending invitation by token hash (not yet consumed/expired).
pub async fn find_pending(
    client: &deadpool_postgres::Client,
    token_hash: &str,
) -> Result<Option<AcceptedInvitation>, DbError> {
    let row = client
        .query_opt(
            "SELECT project_id, role_id, email FROM invitations \
             WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()",
            &[&token_hash],
        )
        .await?;
    Ok(row.map(|r| AcceptedInvitation {
        project_id: r.get("project_id"),
        role_id: r.get("role_id"),
        email: r.get("email"),
    }))
}

/// Whether a token exists at all (used to distinguish "unknown" from
/// "already accepted/expired" → 410).
pub async fn exists(client: &deadpool_postgres::Client, token_hash: &str) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM invitations WHERE token_hash = $1) AS e",
            &[&token_hash],
        )
        .await?;
    Ok(row.get("e"))
}

/// Atomically mark an invitation accepted. Returns true if it transitioned.
pub async fn mark_accepted(
    client: &deadpool_postgres::Client,
    token_hash: &str,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE invitations SET accepted_at = now() \
             WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()",
            &[&token_hash],
        )
        .await?;
    Ok(n > 0)
}

pub async fn list_pending(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<intellipilot_core::project::Invitation>, DbError> {
    let rows = client
        .query(
            "SELECT id, project_id, email, role_id, created_at FROM invitations \
             WHERE project_id = $1 AND accepted_at IS NULL AND expires_at > now() \
             ORDER BY created_at",
            &[&project_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| intellipilot_core::project::Invitation {
            id: r.get("id"),
            project_id: r.get("project_id"),
            email: r.get("email"),
            role_id: r.get("role_id"),
            created_at: r.get("created_at"),
        })
        .collect())
}
