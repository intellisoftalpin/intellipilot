//! Component persistence (project-level). Git repositories link to components
//! separately — see [`crate::component_repositories`].

use intellipilot_core::catalog::Component;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, name, color, created_at";

fn row_to_component(r: &Row) -> Component {
    Component {
        id: r.get("id"),
        project_id: r.get("project_id"),
        name: r.get("name"),
        color: r.get("color"),
        created_at: r.get("created_at"),
    }
}

pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<Component>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {COLS} FROM components WHERE project_id=$1 ORDER BY name"),
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_component).collect())
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    name: &str,
    color: &str,
) -> Result<Component, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO components (project_id, name, color) \
                 VALUES ($1,$2,$3) RETURNING {COLS}"
            ),
            &[&project_id, &name, &color],
        )
        .await?;
    Ok(row_to_component(&row))
}

pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    name: Option<&str>,
    color: Option<&str>,
) -> Result<Option<Component>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE components SET name=COALESCE($3,name), color=COALESCE($4,color) \
                 WHERE id=$1 AND project_id=$2 RETURNING {COLS}"
            ),
            &[&id, &project_id, &name, &color],
        )
        .await?;
    Ok(row.as_ref().map(row_to_component))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM components WHERE id=$1 AND project_id=$2",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

pub async fn all_in_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    ids: &[Uuid],
) -> Result<bool, DbError> {
    if ids.is_empty() {
        return Ok(true);
    }
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM components WHERE project_id=$1 AND id = ANY($2)",
            &[&project_id, &ids],
        )
        .await?;
    let n: i64 = row.get("n");
    let mut v = ids.to_vec();
    v.sort_unstable();
    v.dedup();
    Ok(usize::try_from(n).unwrap_or(0) == v.len())
}
