//! Per-user kanban board view persistence: named saved states (`board_views`)
//! and the per-user last-used board (`board_last_used`). The `config` is stored
//! verbatim as jsonb.

use intellipilot_core::board::BoardView;
use serde_json::Value;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, user_id, name, config, created_at, modified_at";

fn row_to_view(r: &Row) -> BoardView {
    BoardView {
        id: r.get("id"),
        project_id: r.get("project_id"),
        user_id: r.get("user_id"),
        name: r.get("name"),
        config: r.get("config"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

/// All saved board views owned by a user in a project (ordered by name).
pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<BoardView>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {COLS} FROM board_views \
                 WHERE project_id = $1 AND user_id = $2 ORDER BY name"
            ),
            &[&project_id, &user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_view).collect())
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
    name: &str,
    config: &Value,
) -> Result<BoardView, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO board_views (project_id, user_id, name, config) \
                 VALUES ($1, $2, $3, $4) RETURNING {COLS}"
            ),
            &[&project_id, &user_id, &name, &config],
        )
        .await?;
    Ok(row_to_view(&row))
}

pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
    id: Uuid,
    name: &str,
    config: &Value,
) -> Result<Option<BoardView>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE board_views SET name = $4, config = $5 \
                 WHERE id = $1 AND project_id = $2 AND user_id = $3 RETURNING {COLS}"
            ),
            &[&id, &project_id, &user_id, &name, &config],
        )
        .await?;
    Ok(row.as_ref().map(row_to_view))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM board_views WHERE id = $1 AND project_id = $2 AND user_id = $3",
            &[&id, &project_id, &user_id],
        )
        .await?;
    Ok(n > 0)
}

/// The user's last-used board config for a project, if remembered.
pub async fn get_last_used(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<Option<Value>, DbError> {
    let row = client
        .query_opt(
            "SELECT config FROM board_last_used WHERE project_id = $1 AND user_id = $2",
            &[&project_id, &user_id],
        )
        .await?;
    Ok(row.map(|r| r.get("config")))
}

/// Remember the user's current board config for a project (upsert).
pub async fn set_last_used(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
    config: &Value,
) -> Result<(), DbError> {
    client
        .execute(
            "INSERT INTO board_last_used (project_id, user_id, config) VALUES ($1, $2, $3) \
             ON CONFLICT (project_id, user_id) \
               DO UPDATE SET config = excluded.config, modified_at = now()",
            &[&project_id, &user_id, &config],
        )
        .await?;
    Ok(())
}
