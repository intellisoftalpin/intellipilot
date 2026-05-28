//! Passkey credential + ceremony-state persistence.

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

/// A stored passkey credential (as returned for listing/management).
#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub id: Uuid,
    pub credential_id: Vec<u8>,
    pub passkey: Value,
    pub nickname: String,
    pub sign_count: i64,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

// --- ceremony state -------------------------------------------------------

/// Persist in-progress ceremony state; returns the state id to hand to client.
pub async fn save_state(
    client: &deadpool_postgres::Client,
    user_id: Option<Uuid>,
    kind: &str,
    state: &Value,
    expires_at: OffsetDateTime,
) -> Result<Uuid, DbError> {
    let row = client
        .query_one(
            "INSERT INTO webauthn_states (user_id, kind, state, expires_at) \
             VALUES ($1, $2, $3, $4) RETURNING id",
            &[&user_id, &kind, &state, &expires_at],
        )
        .await?;
    Ok(row.get("id"))
}

/// Atomically fetch-and-delete a ceremony state (single use, unexpired).
pub async fn take_state(
    client: &deadpool_postgres::Client,
    id: Uuid,
    kind: &str,
) -> Result<Option<(Option<Uuid>, Value)>, DbError> {
    let row = client
        .query_opt(
            "DELETE FROM webauthn_states \
             WHERE id = $1 AND kind = $2 AND expires_at > now() \
             RETURNING user_id, state",
            &[&id, &kind],
        )
        .await?;
    Ok(row.map(|r| (r.get("user_id"), r.get("state"))))
}

// --- credentials ----------------------------------------------------------

pub async fn insert_credential(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    credential_id: &[u8],
    passkey: &Value,
    nickname: &str,
    sign_count: i64,
) -> Result<Uuid, DbError> {
    let row = client
        .query_one(
            "INSERT INTO webauthn_credentials \
               (user_id, credential_id, passkey, nickname, sign_count) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
            &[&user_id, &credential_id, &passkey, &nickname, &sign_count],
        )
        .await?;
    Ok(row.get("id"))
}

pub async fn list_for_user(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<Vec<StoredCredential>, DbError> {
    let rows = client
        .query(
            "SELECT id, credential_id, passkey, nickname, sign_count, created_at, last_used_at \
             FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at",
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_cred).collect())
}

pub async fn delete_credential(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2",
            &[&id, &user_id],
        )
        .await?;
    Ok(n > 0)
}

/// Update the stored passkey + signature counter after a successful auth.
pub async fn update_after_auth(
    client: &deadpool_postgres::Client,
    credential_id: &[u8],
    passkey: &Value,
    sign_count: i64,
) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE webauthn_credentials \
             SET passkey = $2, sign_count = $3, last_used_at = now() \
             WHERE credential_id = $1",
            &[&credential_id, &passkey, &sign_count],
        )
        .await?;
    Ok(())
}

fn row_to_cred(r: &tokio_postgres::Row) -> StoredCredential {
    StoredCredential {
        id: r.get("id"),
        credential_id: r.get("credential_id"),
        passkey: r.get("passkey"),
        nickname: r.get("nickname"),
        sign_count: r.get("sign_count"),
        created_at: r.get("created_at"),
        last_used_at: r.get("last_used_at"),
    }
}
