//! Release (product / release line) persistence.

use intellipilot_core::release::Release;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, name, description, color, created_at";

fn row_to_release(r: &Row) -> Release {
    Release {
        id: r.get("id"),
        project_id: r.get("project_id"),
        name: r.get("name"),
        description: r.get("description"),
        color: r.get("color"),
        created_at: r.get("created_at"),
    }
}

pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<Release>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {COLS} FROM releases WHERE project_id=$1 ORDER BY name"),
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_release).collect())
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Release>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM releases WHERE id=$1 AND project_id=$2"),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_release))
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    created_by: Uuid,
    name: &str,
    description: Option<&str>,
    color: &str,
) -> Result<Release, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO releases (project_id, name, description, color, created_by) \
                 VALUES ($1,$2,$3,$4,$5) RETURNING {COLS}"
            ),
            &[&project_id, &name, &description, &color, &created_by],
        )
        .await?;
    Ok(row_to_release(&row))
}

pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    name: Option<&str>,
    description: Option<Option<&str>>,
    color: Option<&str>,
) -> Result<Option<Release>, DbError> {
    let (set_desc, desc) = description.map_or((false, None), |v| (true, v));
    let row = client
        .query_opt(
            &format!(
                "UPDATE releases SET name=COALESCE($3,name), \
                   description = CASE WHEN $4 THEN $5 ELSE description END, \
                   color=COALESCE($6,color) \
                 WHERE id=$1 AND project_id=$2 RETURNING {COLS}"
            ),
            &[&id, &project_id, &name, &set_desc, &desc, &color],
        )
        .await?;
    Ok(row.as_ref().map(row_to_release))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM releases WHERE id=$1 AND project_id=$2",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}
