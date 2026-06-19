//! SSH credential vault persistence (per project).
//!
//! The encrypted private key (`private_key_enc`) is written on create and read
//! back only by [`private_key_enc`] for git operations — it is deliberately
//! excluded from the public [`SshKey`] projection so it can never leak through
//! a list/get response.

use intellipilot_core::repo::SshKey;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

/// Public columns plus a live count of repositories referencing the key. The
/// encrypted private key is intentionally never part of this projection.
const COLS: &str = "ssh_keys.id, ssh_keys.project_id, ssh_keys.name, ssh_keys.read_only, \
     ssh_keys.key_type, ssh_keys.public_key, ssh_keys.fingerprint, ssh_keys.created_at, \
     (SELECT count(*) FROM repositories r WHERE r.ssh_key_id = ssh_keys.id) AS used_by_repo_count";

fn row_to_key(r: &Row) -> SshKey {
    SshKey {
        id: r.get("id"),
        project_id: r.get("project_id"),
        name: r.get("name"),
        read_only: r.get("read_only"),
        key_type: r.get("key_type"),
        public_key: r.get("public_key"),
        fingerprint: r.get("fingerprint"),
        used_by_repo_count: r.get("used_by_repo_count"),
        created_at: r.get("created_at"),
    }
}

pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<SshKey>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {COLS} FROM ssh_keys WHERE project_id=$1 ORDER BY name"),
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_key).collect())
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<SshKey>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM ssh_keys WHERE id=$1 AND project_id=$2"),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_key))
}

/// Count keys in a project (used to enforce per-project caps).
pub async fn count(client: &deadpool_postgres::Client, project_id: Uuid) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM ssh_keys WHERE project_id=$1",
            &[&project_id],
        )
        .await?;
    Ok(row.get("n"))
}

/// Parameters for inserting a freshly generated key.
#[derive(Debug)]
pub struct NewSshKey<'a> {
    pub name: &'a str,
    pub read_only: bool,
    pub key_type: &'a str,
    pub public_key: &'a str,
    pub private_key_enc: &'a [u8],
    pub fingerprint: &'a str,
    pub created_by: Uuid,
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    new: &NewSshKey<'_>,
) -> Result<SshKey, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO ssh_keys \
                   (project_id, name, read_only, key_type, public_key, private_key_enc, \
                    fingerprint, created_by) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING {COLS}"
            ),
            &[
                &project_id,
                &new.name,
                &new.read_only,
                &new.key_type,
                &new.public_key,
                &new.private_key_enc,
                &new.fingerprint,
                &new.created_by,
            ],
        )
        .await?;
    Ok(row_to_key(&row))
}

pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    name: Option<&str>,
    read_only: Option<bool>,
) -> Result<Option<SshKey>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE ssh_keys SET name=COALESCE($3,name), read_only=COALESCE($4,read_only) \
                 WHERE id=$1 AND project_id=$2 RETURNING {COLS}"
            ),
            &[&id, &project_id, &name, &read_only],
        )
        .await?;
    Ok(row.as_ref().map(row_to_key))
}

/// Delete a key. Repositories referencing it are detached (FK `ON DELETE SET
/// NULL`), so the deletion always succeeds when the key exists.
pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM ssh_keys WHERE id=$1 AND project_id=$2",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// Fetch the encrypted private key blob for a key, for git operations. Scoped
/// to the project. Returns `None` if the key does not exist.
pub async fn private_key_enc(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Vec<u8>>, DbError> {
    let row = client
        .query_opt(
            "SELECT private_key_enc FROM ssh_keys WHERE id=$1 AND project_id=$2",
            &[&id, &project_id],
        )
        .await?;
    Ok(row.map(|r| r.get::<_, Vec<u8>>("private_key_enc")))
}
