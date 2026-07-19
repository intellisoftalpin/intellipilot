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

const COLS: &str = "id, project_id, owner_id, visibility, name, key, color, config, \
     \"order\", created_at, modified_at";

fn row_to_board(r: &Row) -> Board {
    let vis: String = r.get("visibility");
    Board {
        id: r.get("id"),
        project_id: r.get("project_id"),
        owner_id: r.get("owner_id"),
        visibility: BoardVisibility::parse(&vis).unwrap_or(BoardVisibility::Personal),
        name: r.get("name"),
        key: r.get("key"),
        color: r.get("color"),
        config: r.get("config"),
        order: r.get("order"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

/// Derive the base short key from a board name: initials for multi-word
/// names ("Sprint Board" → "sb"), the truncated word otherwise ("Board" →
/// "board"), `"b"` when nothing alphanumeric survives. Mirrors the V016
/// backfill rules.
fn key_base(name: &str) -> String {
    let lowered = name.to_lowercase();
    let words: Vec<&str> = lowered
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    match words.as_slice() {
        [] => "b".to_owned(),
        [word] => word.chars().take(6).collect(),
        many => many
            .iter()
            .take(6)
            .filter_map(|w| w.chars().next())
            .collect(),
    }
}

/// A free key for a new board: the name-derived base, suffixed `-2`, `-3`…
/// while taken within the project.
pub async fn generate_key(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    name: &str,
) -> Result<String, DbError> {
    let base = key_base(name);
    let mut cand = base.clone();
    let mut n: u32 = 1;
    loop {
        let taken: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM boards WHERE project_id = $1 AND key = $2) AS e",
                &[&project_id, &cand],
            )
            .await?
            .get("e");
        if !taken {
            return Ok(cand);
        }
        n = n.saturating_add(1);
        let suffix = format!("-{n}");
        let head: String = base
            .chars()
            .take(12_usize.saturating_sub(suffix.len()))
            .collect();
        cand = format!("{head}{suffix}");
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

#[allow(clippy::too_many_arguments)]
pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    owner_id: Option<Uuid>,
    visibility: BoardVisibility,
    name: &str,
    key: &str,
    color: &str,
    config: &Value,
) -> Result<Board, DbError> {
    let order = rank_between(max_order(client, project_id).await?, None).unwrap_or(1.0);
    let row = client
        .query_one(
            &format!(
                "INSERT INTO boards (project_id, owner_id, visibility, name, key, color, config, \"order\") \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {COLS}"
            ),
            &[
                &project_id,
                &owner_id,
                &visibility.as_str(),
                &name,
                &key,
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
    key: &str,
    color: &str,
    config: &Value,
) -> Result<Option<Board>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE boards SET name = $3, key = $4, color = $5, config = $6 \
                 WHERE id = $1 AND project_id = $2 RETURNING {COLS}"
            ),
            &[&id, &project_id, &name, &key, &color, &config],
        )
        .await?;
    Ok(row.as_ref().map(row_to_board))
}

/// Board by its short key (already lowercase-normalised by the caller).
pub async fn get_by_key(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    key: &str,
) -> Result<Option<Board>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM boards WHERE project_id = $1 AND key = $2"),
            &[&project_id, &key],
        )
        .await?;
    Ok(row.as_ref().map(row_to_board))
}

/// The board a historic (renamed-away) key pointed to, if recorded.
pub async fn find_id_by_historic_key(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    key: &str,
) -> Result<Option<Uuid>, DbError> {
    let row = client
        .query_opt(
            "SELECT board_id FROM board_key_history WHERE project_id = $1 AND key = $2",
            &[&project_id, &key],
        )
        .await?;
    Ok(row.map(|r| r.get("board_id")))
}

/// Remember a renamed-away key so old short links keep resolving. Last claim
/// of a key wins.
pub async fn record_key_history(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    board_id: Uuid,
    old_key: &str,
) -> Result<(), DbError> {
    client
        .execute(
            "INSERT INTO board_key_history (project_id, board_id, key) VALUES ($1, $2, $3) \
             ON CONFLICT (project_id, key) \
               DO UPDATE SET board_id = excluded.board_id, replaced_at = now()",
            &[&project_id, &board_id, &old_key],
        )
        .await?;
    Ok(())
}

/// One historic board-key entry, enriched for the superadmin listing.
#[derive(Debug, serde::Serialize)]
pub struct BoardKeyHistoryEntry {
    pub id: Uuid,
    pub project_id: Uuid,
    pub project_name: String,
    pub board_id: Uuid,
    pub board_name: String,
    pub key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub replaced_at: time::OffsetDateTime,
}

/// All historic board keys, newest first (superadmin maintenance view).
pub async fn list_key_history(
    client: &deadpool_postgres::Client,
) -> Result<Vec<BoardKeyHistoryEntry>, DbError> {
    let rows = client
        .query(
            "SELECT h.id, h.project_id, p.name AS project_name, h.board_id, \
                    b.name AS board_name, h.key, h.replaced_at \
             FROM board_key_history h \
             JOIN projects p ON p.id = h.project_id \
             JOIN boards b ON b.id = h.board_id \
             ORDER BY h.replaced_at DESC",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| BoardKeyHistoryEntry {
            id: r.get("id"),
            project_id: r.get("project_id"),
            project_name: r.get("project_name"),
            board_id: r.get("board_id"),
            board_name: r.get("board_name"),
            key: r.get("key"),
            replaced_at: r.get("replaced_at"),
        })
        .collect())
}

/// Delete historic board keys by id; returns how many rows went away.
pub async fn delete_key_history(
    client: &deadpool_postgres::Client,
    ids: &[Uuid],
) -> Result<u64, DbError> {
    let n = client
        .execute("DELETE FROM board_key_history WHERE id = ANY($1)", &[&ids])
        .await?;
    Ok(n)
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
