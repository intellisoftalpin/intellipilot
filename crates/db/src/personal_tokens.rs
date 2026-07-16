//! Personal app token persistence (V015).
//!
//! One token per user (enforced by the `user_id` UNIQUE constraint). Tokens
//! are hashed at rest (SHA-256 hex). The hot auth path is
//! [`find_active_by_hash`], which resolves the hash to the owning user —
//! rejecting disabled tokens and inactive/deleted owners in the same query.

use intellipilot_core::app_token::PersonalAppToken;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

/// Minimal record returned by [`find_active_by_hash`] for request auth.
#[derive(Debug, Clone, Copy)]
pub struct PersonalTokenAuth {
    pub id: Uuid,
    pub user_id: Uuid,
}

const COLS: &str = "id, user_id, prefix, last4, disabled_at, last_used_at, created_at";

fn row_to_token(row: &Row) -> PersonalAppToken {
    PersonalAppToken {
        id: row.get("id"),
        user_id: row.get("user_id"),
        prefix: row.get("prefix"),
        last4: row.get("last4"),
        disabled_at: row.get("disabled_at"),
        last_used_at: row.get("last_used_at"),
        created_at: row.get("created_at"),
    }
}

/// Fetch a user's token, masked — never includes the secret.
pub async fn get_by_user(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<Option<PersonalAppToken>, DbError> {
    let sql = format!("SELECT {COLS} FROM personal_app_tokens WHERE user_id = $1");
    let row = client.query_opt(&sql, &[&user_id]).await?;
    Ok(row.as_ref().map(row_to_token))
}

/// Create the user's token. Returns `None` if one already exists (the caller
/// maps that to a 409).
pub async fn create(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    token_hash: &str,
    prefix: &str,
    last4: &str,
) -> Result<Option<PersonalAppToken>, DbError> {
    let sql = format!(
        "INSERT INTO personal_app_tokens (user_id, token_hash, prefix, last4) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (user_id) DO NOTHING \
         RETURNING {COLS}"
    );
    let row = client
        .query_opt(&sql, &[&user_id, &token_hash, &prefix, &last4])
        .await?;
    Ok(row.as_ref().map(row_to_token))
}

/// Swap the credential in place: new hash + display hints, usage cleared,
/// `created_at` restamped, and any disable lifted (a reset mints a working
/// token). Returns `None` if the user has no token.
pub async fn rotate(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    token_hash: &str,
    prefix: &str,
    last4: &str,
) -> Result<Option<PersonalAppToken>, DbError> {
    let sql = format!(
        "UPDATE personal_app_tokens SET \
           token_hash = $2, prefix = $3, last4 = $4, \
           disabled_at = NULL, last_used_at = NULL, created_at = now() \
         WHERE user_id = $1 \
         RETURNING {COLS}"
    );
    let row = client
        .query_opt(&sql, &[&user_id, &token_hash, &prefix, &last4])
        .await?;
    Ok(row.as_ref().map(row_to_token))
}

/// Disable or re-enable the user's token (idempotent; a repeat disable keeps
/// the original `disabled_at`). Returns false if no token exists.
pub async fn set_disabled(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    disabled: bool,
) -> Result<bool, DbError> {
    let n = if disabled {
        client
            .execute(
                "UPDATE personal_app_tokens \
                 SET disabled_at = COALESCE(disabled_at, now()) \
                 WHERE user_id = $1",
                &[&user_id],
            )
            .await?
    } else {
        client
            .execute(
                "UPDATE personal_app_tokens SET disabled_at = NULL WHERE user_id = $1",
                &[&user_id],
            )
            .await?
    };
    Ok(n > 0)
}

/// Delete the user's token. Returns false if none exists.
pub async fn delete(client: &deadpool_postgres::Client, user_id: Uuid) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM personal_app_tokens WHERE user_id = $1",
            &[&user_id],
        )
        .await?;
    Ok(n > 0)
}

/// Resolve an active token by its hash — the request auth hot path. Active
/// means: not disabled, and the owning user is active and not deleted.
pub async fn find_active_by_hash(
    client: &deadpool_postgres::Client,
    token_hash: &str,
) -> Result<Option<PersonalTokenAuth>, DbError> {
    let row = client
        .query_opt(
            "SELECT t.id, t.user_id \
             FROM personal_app_tokens t \
             JOIN users u ON u.id = t.user_id \
             WHERE t.token_hash = $1 AND t.disabled_at IS NULL \
               AND u.is_active AND u.deleted_at IS NULL",
            &[&token_hash],
        )
        .await?;
    Ok(row.map(|r| PersonalTokenAuth {
        id: r.get("id"),
        user_id: r.get("user_id"),
    }))
}

/// Best-effort: stamp `last_used_at`. Errors are the caller's to ignore.
pub async fn touch_last_used(client: &deadpool_postgres::Client, id: Uuid) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE personal_app_tokens SET last_used_at = now() WHERE id = $1",
            &[&id],
        )
        .await?;
    Ok(())
}
