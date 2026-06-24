//! App token persistence (V004).
//!
//! Tokens are hashed at rest (SHA-256 hex), scoped to a set of projects via
//! `app_token_projects`, and carry a JSONB array of granted permissions. The
//! hot auth path is [`find_active_by_hash`], which returns only what the
//! request needs to authorise: the granted permissions and the project scope.

use intellipilot_core::app_token::AppToken;
use intellipilot_core::perms::Permission;
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

/// Minimal record returned by [`find_active_by_hash`] for request auth.
#[derive(Debug, Clone)]
pub struct AppTokenAuth {
    pub id: Uuid,
    pub permissions: Vec<Permission>,
    pub project_ids: Vec<Uuid>,
}

fn row_to_token(row: &Row) -> Result<AppToken, DbError> {
    let perms_json: serde_json::Value = row.get("permissions");
    let permissions: Vec<Permission> = serde_json::from_value(perms_json)?;
    Ok(AppToken {
        id: row.get("id"),
        name: row.get("name"),
        prefix: row.get("prefix"),
        last4: row.get("last4"),
        permissions,
        project_ids: row.get("project_ids"),
        created_by: row.get("created_by"),
        expires_at: row.get("expires_at"),
        revoked_at: row.get("revoked_at"),
        last_used_at: row.get("last_used_at"),
        created_at: row.get("created_at"),
    })
}

const SELECT_COLS: &str = "t.id, t.name, t.prefix, t.last4, t.permissions, t.created_by, \
     t.expires_at, t.revoked_at, t.last_used_at, t.created_at, \
     COALESCE(ARRAY(SELECT project_id FROM app_token_projects p WHERE p.token_id = t.id), \
              '{}'::uuid[]) AS project_ids";

/// Create a token + its project scope atomically. Returns the new token id.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    client: &mut deadpool_postgres::Client,
    name: &str,
    token_hash: &str,
    prefix: &str,
    last4: &str,
    permissions: &[Permission],
    created_by: Option<Uuid>,
    expires_at: Option<OffsetDateTime>,
    project_ids: &[Uuid],
) -> Result<Uuid, DbError> {
    let perms_json = serde_json::to_value(permissions)?;
    let tx = client.transaction().await?;
    let row = tx
        .query_one(
            "INSERT INTO app_tokens \
               (name, token_hash, prefix, last4, permissions, created_by, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
            &[
                &name,
                &token_hash,
                &prefix,
                &last4,
                &perms_json,
                &created_by,
                &expires_at,
            ],
        )
        .await?;
    let id: Uuid = row.get("id");
    for pid in project_ids {
        tx.execute(
            "INSERT INTO app_token_projects (token_id, project_id) \
             VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&id, pid],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(id)
}

/// List all tokens (newest first), masked — never includes the secret.
pub async fn list(client: &deadpool_postgres::Client) -> Result<Vec<AppToken>, DbError> {
    let sql = format!("SELECT {SELECT_COLS} FROM app_tokens t ORDER BY t.created_at DESC");
    let rows = client.query(&sql, &[]).await?;
    rows.iter().map(row_to_token).collect()
}

/// Fetch a single token by id.
pub async fn get(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<AppToken>, DbError> {
    let sql = format!("SELECT {SELECT_COLS} FROM app_tokens t WHERE t.id = $1");
    let row = client.query_opt(&sql, &[&id]).await?;
    row.as_ref().map(row_to_token).transpose()
}

/// Resolve an active (not revoked, not expired) token by its hash — the request
/// auth hot path.
pub async fn find_active_by_hash(
    client: &deadpool_postgres::Client,
    token_hash: &str,
) -> Result<Option<AppTokenAuth>, DbError> {
    let row = client
        .query_opt(
            "SELECT t.id, t.permissions, \
                    COALESCE(ARRAY(SELECT project_id FROM app_token_projects p \
                             WHERE p.token_id = t.id), '{}'::uuid[]) AS project_ids \
             FROM app_tokens t \
             WHERE t.token_hash = $1 AND t.revoked_at IS NULL \
               AND (t.expires_at IS NULL OR t.expires_at > now())",
            &[&token_hash],
        )
        .await?;
    match row {
        None => Ok(None),
        Some(r) => {
            let perms_json: serde_json::Value = r.get("permissions");
            let permissions: Vec<Permission> = serde_json::from_value(perms_json)?;
            Ok(Some(AppTokenAuth {
                id: r.get("id"),
                permissions,
                project_ids: r.get("project_ids"),
            }))
        }
    }
}

/// Update a token's name / permissions / project scope. Any `None` field is
/// left unchanged. Returns false if no token with `id` exists.
pub async fn update(
    client: &mut deadpool_postgres::Client,
    id: Uuid,
    name: Option<&str>,
    permissions: Option<&[Permission]>,
    project_ids: Option<&[Uuid]>,
) -> Result<bool, DbError> {
    let perms_json = match permissions {
        Some(p) => Some(serde_json::to_value(p)?),
        None => None,
    };
    let tx = client.transaction().await?;
    let n = tx
        .execute(
            "UPDATE app_tokens SET \
               name = COALESCE($2, name), \
               permissions = COALESCE($3, permissions) \
             WHERE id = $1",
            &[&id, &name, &perms_json],
        )
        .await?;
    if n == 0 {
        return Ok(false);
    }
    if let Some(pids) = project_ids {
        tx.execute("DELETE FROM app_token_projects WHERE token_id = $1", &[&id])
            .await?;
        for pid in pids {
            tx.execute(
                "INSERT INTO app_token_projects (token_id, project_id) \
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
                &[&id, pid],
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

/// Soft-revoke a token (sets `revoked_at`). Returns true if it transitioned.
pub async fn revoke(client: &deadpool_postgres::Client, id: Uuid) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE app_tokens SET revoked_at = now() \
             WHERE id = $1 AND revoked_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(n > 0)
}

/// Best-effort: stamp `last_used_at`. Errors are the caller's to ignore.
pub async fn touch_last_used(client: &deadpool_postgres::Client, id: Uuid) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE app_tokens SET last_used_at = now() WHERE id = $1",
            &[&id],
        )
        .await?;
    Ok(())
}
