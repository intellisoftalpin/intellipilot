//! Per-(project, user) writable SSH key persistence.
//!
//! Mirrors the discipline of [`crate::ssh_keys`]: `private_key_enc` is written
//! on create and read back only by [`private_key_enc`] for a push. It is
//! deliberately excluded from [`COLS`], so no list or get response can ever
//! carry it — not even to the key's own owner.

use intellipilot_core::docs::DocUserKey;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, user_id, key_type, public_key, fingerprint, origin, created_at";

fn row_to_key(r: &Row) -> DocUserKey {
    DocUserKey {
        id: r.get("id"),
        project_id: r.get("project_id"),
        user_id: r.get("user_id"),
        key_type: r.get("key_type"),
        public_key: r.get("public_key"),
        fingerprint: r.get("fingerprint"),
        origin: r.get("origin"),
        created_at: r.get("created_at"),
    }
}

/// The caller's key for this project, if they have registered one.
pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<Option<DocUserKey>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM doc_user_keys WHERE project_id=$1 AND user_id=$2"),
            &[&project_id, &user_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_key))
}

/// Does this user hold a write key here? Cheaper than [`get`] when the answer
/// only feeds a `can_edit` flag.
pub async fn exists(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<bool, DbError> {
    let row = client
        .query_opt(
            "SELECT 1 FROM doc_user_keys WHERE project_id=$1 AND user_id=$2",
            &[&project_id, &user_id],
        )
        .await?;
    Ok(row.is_some())
}

/// Parameters for registering a key, generated or imported.
#[derive(Debug)]
pub struct NewDocUserKey<'a> {
    pub key_type: &'a str,
    pub public_key: &'a str,
    pub private_key_enc: &'a [u8],
    pub fingerprint: &'a str,
    /// `generated` or `imported`.
    pub origin: &'a str,
}

/// Register or replace the caller's key.
///
/// Replacing is an upsert rather than an error: rotating a key is the common
/// case, and the unique constraint on `(project_id, user_id)` is what makes
/// one-key-per-user the invariant.
pub async fn upsert(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
    new: &NewDocUserKey<'_>,
) -> Result<DocUserKey, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO doc_user_keys \
                   (project_id, user_id, key_type, public_key, private_key_enc, \
                    fingerprint, origin) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7) \
                 ON CONFLICT (project_id, user_id) DO UPDATE SET \
                   key_type=EXCLUDED.key_type, public_key=EXCLUDED.public_key, \
                   private_key_enc=EXCLUDED.private_key_enc, \
                   fingerprint=EXCLUDED.fingerprint, origin=EXCLUDED.origin, \
                   created_at=now() \
                 RETURNING {COLS}"
            ),
            &[
                &project_id,
                &user_id,
                &new.key_type,
                &new.public_key,
                &new.private_key_enc,
                &new.fingerprint,
                &new.origin,
            ],
        )
        .await?;
    Ok(row_to_key(&row))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM doc_user_keys WHERE project_id=$1 AND user_id=$2",
            &[&project_id, &user_id],
        )
        .await?;
    Ok(n > 0)
}

/// Fetch the encrypted private key for a push. Scoped to the project so a key
/// registered for one project can never sign a push in another.
pub async fn private_key_enc(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<Option<Vec<u8>>, DbError> {
    let row = client
        .query_opt(
            "SELECT private_key_enc FROM doc_user_keys WHERE project_id=$1 AND user_id=$2",
            &[&project_id, &user_id],
        )
        .await?;
    Ok(row.map(|r| r.get::<_, Vec<u8>>("private_key_enc")))
}
