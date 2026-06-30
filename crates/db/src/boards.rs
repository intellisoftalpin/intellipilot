//! Board persistence: first-class personal/shared kanban boards.
//!
//! Also holds the per-user "last opened board" pointer. The board-DATA queries
//! (bucketed columns/lanes with counts + capped cards) live in
//! [`crate::backlog`].

use intellipilot_core::board::{Board, BoardVisibility};
use intellipilot_core::ordering::rank_between;
use serde_json::Value;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, owner_id, visibility, name, color, config, \
     \"order\", created_at, modified_at";

fn row_to_board(r: &Row) -> Board {
    let vis: String = r.get("visibility");
    Board {
        id: r.get("id"),
        project_id: r.get("project_id"),
        owner_id: r.get("owner_id"),
        visibility: BoardVisibility::parse(&vis).unwrap_or(BoardVisibility::Personal),
        name: r.get("name"),
        color: r.get("color"),
        config: r.get("config"),
        order: r.get("order"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

/// Boards visible to a user in a project: every shared board + the user's own
/// personal boards, ordered for the nav submenu.
pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Board>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {COLS} FROM boards \
                 WHERE project_id = $1 AND (visibility = 'shared' OR owner_id = $2) \
                 ORDER BY \"order\", name"
            ),
            &[&project_id, &user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_board).collect())
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Board>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM boards WHERE id = $1 AND project_id = $2"),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_board))
}

async fn max_order(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Option<f64>, DbError> {
    let row = client
        .query_one(
            "SELECT max(\"order\") AS m FROM boards WHERE project_id = $1",
            &[&project_id],
        )
        .await?;
    Ok(row.get("m"))
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    owner_id: Option<Uuid>,
    visibility: BoardVisibility,
    name: &str,
    color: &str,
    config: &Value,
) -> Result<Board, DbError> {
    let order = rank_between(max_order(client, project_id).await?, None).unwrap_or(1.0);
    let row = client
        .query_one(
            &format!(
                "INSERT INTO boards (project_id, owner_id, visibility, name, color, config, \"order\") \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {COLS}"
            ),
            &[
                &project_id,
                &owner_id,
                &visibility.as_str(),
                &name,
                &color,
                &config,
                &order,
            ],
        )
        .await?;
    Ok(row_to_board(&row))
}

/// Update mutable fields. Visibility is fixed at creation and not changed here.
pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    name: &str,
    color: &str,
    config: &Value,
) -> Result<Option<Board>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE boards SET name = $3, color = $4, config = $5 \
                 WHERE id = $1 AND project_id = $2 RETURNING {COLS}"
            ),
            &[&id, &project_id, &name, &color, &config],
        )
        .await?;
    Ok(row.as_ref().map(row_to_board))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM boards WHERE id = $1 AND project_id = $2",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// The board id the user last had open in this project, if any.
pub async fn get_last_opened(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<Option<Uuid>, DbError> {
    let row = client
        .query_opt(
            "SELECT board_id FROM board_last_opened WHERE project_id = $1 AND user_id = $2",
            &[&project_id, &user_id],
        )
        .await?;
    Ok(row.and_then(|r| r.get("board_id")))
}

pub async fn set_last_opened(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
    board_id: Uuid,
) -> Result<(), DbError> {
    client
        .execute(
            "INSERT INTO board_last_opened (project_id, user_id, board_id) VALUES ($1, $2, $3) \
             ON CONFLICT (project_id, user_id) \
               DO UPDATE SET board_id = excluded.board_id, modified_at = now()",
            &[&project_id, &user_id, &board_id],
        )
        .await?;
    Ok(())
}
