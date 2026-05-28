//! Idempotency-Key storage for safe POST replay.
#![allow(clippy::too_many_arguments)]

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

/// A previously-stored response for an idempotency key.
#[derive(Debug, Clone)]
pub struct StoredResponse {
    pub status: i32,
    pub body: Value,
}

/// Look up a stored response for (user, key, method, path), if not expired.
pub async fn lookup(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    key: &str,
    method: &str,
    path: &str,
) -> Result<Option<StoredResponse>, DbError> {
    let row = client
        .query_opt(
            "SELECT response_status, response_body FROM idempotency_keys \
             WHERE user_id=$1 AND idem_key=$2 AND method=$3 AND path=$4 AND expires_at > now()",
            &[&user_id, &key, &method, &path],
        )
        .await?;
    Ok(row.map(|r| StoredResponse {
        status: r.get("response_status"),
        body: r.get("response_body"),
    }))
}

/// Store a response for replay. Ignores conflicts (a concurrent request that
/// already stored one wins).
pub async fn store(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    key: &str,
    method: &str,
    path: &str,
    status: i32,
    body: &Value,
    expires_at: OffsetDateTime,
) -> Result<(), DbError> {
    client
        .execute(
            "INSERT INTO idempotency_keys \
               (idem_key, user_id, method, path, response_status, response_body, expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7) \
             ON CONFLICT (user_id, idem_key, method, path) DO NOTHING",
            &[&key, &user_id, &method, &path, &status, &body, &expires_at],
        )
        .await?;
    Ok(())
}
