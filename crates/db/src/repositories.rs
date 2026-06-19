//! Repository persistence (per project). A repository references at most one
//! SSH key (nullable; detached when the key is deleted).

use intellipilot_core::repo::Repository;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, name, ssh_url, ssh_key_id, default_branch, \
     host_fingerprint, created_at";

fn row_to_repo(r: &Row) -> Repository {
    Repository {
        id: r.get("id"),
        project_id: r.get("project_id"),
        name: r.get("name"),
        ssh_url: r.get("ssh_url"),
        ssh_key_id: r.get("ssh_key_id"),
        default_branch: r.get("default_branch"),
        host_fingerprint: r.get("host_fingerprint"),
        created_at: r.get("created_at"),
    }
}

pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<Repository>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {COLS} FROM repositories WHERE project_id=$1 ORDER BY name"),
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_repo).collect())
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Repository>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM repositories WHERE id=$1 AND project_id=$2"),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_repo))
}

pub async fn count(client: &deadpool_postgres::Client, project_id: Uuid) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM repositories WHERE project_id=$1",
            &[&project_id],
        )
        .await?;
    Ok(row.get("n"))
}

/// Parameters for inserting a repository.
#[derive(Debug)]
pub struct NewRepository<'a> {
    pub name: &'a str,
    pub ssh_url: &'a str,
    pub ssh_key_id: Option<Uuid>,
    pub default_branch: Option<&'a str>,
    pub host_fingerprint: Option<&'a str>,
    pub created_by: Uuid,
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    new: &NewRepository<'_>,
) -> Result<Repository, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO repositories \
                   (project_id, name, ssh_url, ssh_key_id, default_branch, host_fingerprint, \
                    created_by) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING {COLS}"
            ),
            &[
                &project_id,
                &new.name,
                &new.ssh_url,
                &new.ssh_key_id,
                &new.default_branch,
                &new.host_fingerprint,
                &new.created_by,
            ],
        )
        .await?;
    Ok(row_to_repo(&row))
}

/// Partial update. Each `Option<Option<_>>` field follows the convention
/// `None` = leave unchanged, `Some(None)` = set NULL, `Some(Some(v))` = set v.
#[derive(Debug, Default)]
pub struct RepoUpdate<'a> {
    pub name: Option<&'a str>,
    pub ssh_url: Option<&'a str>,
    pub ssh_key_id: Option<Option<Uuid>>,
    pub default_branch: Option<Option<&'a str>>,
    pub host_fingerprint: Option<Option<&'a str>>,
}

pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    upd: &RepoUpdate<'_>,
) -> Result<Option<Repository>, DbError> {
    let (set_key, key_val) = upd.ssh_key_id.map_or((false, None), |v| (true, v));
    let (set_branch, branch_val) = upd.default_branch.map_or((false, None), |v| (true, v));
    let (set_fp, fp_val) = upd.host_fingerprint.map_or((false, None), |v| (true, v));
    let row = client
        .query_opt(
            &format!(
                "UPDATE repositories SET \
                   name = COALESCE($3, name), \
                   ssh_url = COALESCE($4, ssh_url), \
                   ssh_key_id = CASE WHEN $5 THEN $6 ELSE ssh_key_id END, \
                   default_branch = CASE WHEN $7 THEN $8 ELSE default_branch END, \
                   host_fingerprint = CASE WHEN $9 THEN $10 ELSE host_fingerprint END \
                 WHERE id=$1 AND project_id=$2 RETURNING {COLS}"
            ),
            &[
                &id,
                &project_id,
                &upd.name,
                &upd.ssh_url,
                &set_key,
                &key_val,
                &set_branch,
                &branch_val,
                &set_fp,
                &fp_val,
            ],
        )
        .await?;
    Ok(row.as_ref().map(row_to_repo))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM repositories WHERE id=$1 AND project_id=$2",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// Fetch the encrypted private key for a repository's linked SSH key, for git
/// operations. Returns `None` if the repo does not exist or has no key linked.
pub async fn private_key_enc(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    repo_id: Uuid,
) -> Result<Option<Vec<u8>>, DbError> {
    let row = client
        .query_opt(
            "SELECT k.private_key_enc FROM repositories r \
               JOIN ssh_keys k ON k.id = r.ssh_key_id \
             WHERE r.id=$1 AND r.project_id=$2",
            &[&repo_id, &project_id],
        )
        .await?;
    Ok(row.map(|r| r.get::<_, Vec<u8>>("private_key_enc")))
}
