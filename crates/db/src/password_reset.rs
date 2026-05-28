//! Password-reset tokens (hashed at rest, single-use).

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

/// Create a reset token for a user.
pub async fn create(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    token_hash: &str,
    expires_at: OffsetDateTime,
) -> Result<(), DbError> {
    client
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) \
             VALUES ($1, $2, $3)",
            &[&user_id, &token_hash, &expires_at],
        )
        .await?;
    Ok(())
}

/// Atomically consume a valid, unexpired, unused token. Returns the user id on
/// success, marking the token used. Returns `None` if invalid/expired/used.
pub async fn consume(
    client: &deadpool_postgres::Client,
    token_hash: &str,
) -> Result<Option<Uuid>, DbError> {
    let row = client
        .query_opt(
            "UPDATE password_reset_tokens SET used_at = now() \
             WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() \
             RETURNING user_id",
            &[&token_hash],
        )
        .await?;
    Ok(row.map(|r| r.get("user_id")))
}
