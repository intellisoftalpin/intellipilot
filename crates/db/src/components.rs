//! Component persistence (project-level, optional git repository).

use intellipilot_core::catalog::Component;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, name, color, git_repository, created_at";

fn row_to_component(r: &Row) -> Component {
    Component {
        id: r.get("id"),
        project_id: r.get("project_id"),
        name: r.get("name"),
        color: r.get("color"),
        git_repository: r.get("git_repository"),
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
    git_repository: Option<&str>,
) -> Result<Component, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO components (project_id, name, color, git_repository) \
                 VALUES ($1,$2,$3,$4) RETURNING {COLS}"
            ),
            &[&project_id, &name, &color, &git_repository],
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
    git_repository: Option<Option<&str>>,
) -> Result<Option<Component>, DbError> {
    // `git_repository`: None = unchanged, Some(None) = clear, Some(Some(v)) = set.
    let (set_git, git_val): (bool, Option<&str>) =
        git_repository.map_or((false, None), |v| (true, v));
    let row = client
        .query_opt(
            &format!(
                "UPDATE components SET name=COALESCE($3,name), color=COALESCE($4,color), \
                   git_repository = CASE WHEN $5 THEN $6 ELSE git_repository END \
                 WHERE id=$1 AND project_id=$2 RETURNING {COLS}"
            ),
            &[&id, &project_id, &name, &color, &set_git, &git_val],
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
