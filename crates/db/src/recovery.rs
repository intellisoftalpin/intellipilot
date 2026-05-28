//! Recovery-code persistence.

use uuid::Uuid;

use crate::DbError;

/// An unused recovery code row (id + hash) for verification.
#[derive(Debug, Clone)]
pub struct UnusedCode {
    pub id: Uuid,
    pub code_hash: String,
}

/// Replace a user's recovery codes with a fresh hashed set (transaction).
pub async fn replace_all(
    client: &mut deadpool_postgres::Client,
    user_id: Uuid,
    hashes: &[String],
) -> Result<(), DbError> {
    let tx = client.transaction().await?;
    tx.execute("DELETE FROM recovery_codes WHERE user_id = $1", &[&user_id])
        .await?;
    for hash in hashes {
        tx.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)",
            &[&user_id, &hash],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// List a user's currently-unused recovery codes.
pub async fn list_unused(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<Vec<UnusedCode>, DbError> {
    let rows = client
        .query(
            "SELECT id, code_hash FROM recovery_codes \
             WHERE user_id = $1 AND used_at IS NULL",
            &[&user_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| UnusedCode {
            id: r.get("id"),
            code_hash: r.get("code_hash"),
        })
        .collect())
}

/// Atomically mark a specific code used. Returns true if it transitioned
/// (false means it was already used — concurrent reuse).
pub async fn mark_used(client: &deadpool_postgres::Client, id: Uuid) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE recovery_codes SET used_at = now() \
             WHERE id = $1 AND used_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(n > 0)
}

/// Count remaining unused codes.
pub async fn count_unused(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM recovery_codes \
             WHERE user_id = $1 AND used_at IS NULL",
            &[&user_id],
        )
        .await?;
    Ok(row.get("n"))
}
