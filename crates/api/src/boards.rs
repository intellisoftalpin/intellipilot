//! Board endpoints: first-class personal/shared boards (CRUD), the per-user
//! last-opened pointer, and the performant per-column board DATA endpoint.
//!
//! Personal boards need only `project.view` (you manage your own). Shared
//! boards are gated by `board.shared.{create,modify,delete}`.
#![allow(clippy::result_large_err, clippy::implicit_hasher, clippy::ref_option)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::board::BoardVisibility;
use intellipilot_core::perms::Permission;
use intellipilot_db::backlog as bl;
use intellipilot_db::boards as bdb;
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

fn problem(status: StatusCode, code: &'static str, title: &str, rid: &str) -> Response {
    Problem::new(status, code, title, None, rid).into_response_with_status(status)
}
fn internal(rid: &str) -> Response {
    problem(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal Server Error",
        rid,
    )
}
fn not_found(rid: &str) -> Response {
    problem(StatusCode::NOT_FOUND, "not_found", "Not Found", rid)
}
fn forbidden(rid: &str) -> Response {
    problem(StatusCode::FORBIDDEN, "forbidden", "Forbidden", rid)
}

// --------------------------------------------------------------------------
// board CRUD
// --------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateBoardRequest {
    #[garde(length(min = 1, max = 120))]
    pub name: String,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: String,
    /// Defaults to a personal board; set true (with `board.shared.create`) for
    /// a board visible to the whole project.
    #[garde(skip)]
    #[serde(default)]
    pub shared: bool,
    #[garde(skip)]
    #[serde(default)]
    #[schema(value_type = Object)]
    pub config: Value,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateBoardRequest {
    #[garde(length(min = 1, max = 120))]
    pub name: String,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: String,
    #[garde(skip)]
    #[serde(default)]
    #[schema(value_type = Object)]
    pub config: Value,
}

fn board_id(params: &HashMap<String, String>) -> Option<Uuid> {
    params.get("board_id").and_then(|s| Uuid::parse_str(s).ok())
}

fn parse_create(
    body: Result<Json<CreateBoardRequest>, JsonRejection>,
    rid: &str,
) -> Result<CreateBoardRequest, Response> {
    let Ok(Json(v)) = body else {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            rid,
        ));
    };
    if v.validate().is_err() {
        return Err(problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
            rid,
        ));
    }
    Ok(v)
}

fn parse_update(
    body: Result<Json<UpdateBoardRequest>, JsonRejection>,
    rid: &str,
) -> Result<UpdateBoardRequest, Response> {
    let Ok(Json(v)) = body else {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            rid,
        ));
    };
    if v.validate().is_err() {
        return Err(problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
            rid,
        ));
    }
    Ok(v)
}

/// `GET /api/v1/projects/{project_id}/boards`
pub async fn list(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bdb::list(&client, ctx.project.id, ctx.actor_id).await {
        Ok(boards) => Json(json!({ "boards": boards })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/boards`
pub async fn create(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<CreateBoardRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let req = match parse_create(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Creating a SHARED board needs the dedicated permission; personal boards
    // are free to any project viewer.
    let visibility = if req.shared {
        if let Err(r) = ctx.require(Permission::BoardSharedCreate) {
            return r;
        }
        BoardVisibility::Shared
    } else {
        BoardVisibility::Personal
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bdb::create(
        &client,
        ctx.project.id,
        Some(ctx.actor_id),
        visibility,
        &req.name,
        &req.color,
        &req.config,
    )
    .await
    {
        Ok(board) => (StatusCode::CREATED, Json(board)).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// Load a board and authorize the caller for the given action. Returns the
/// board, or a Response to short-circuit with.
async fn load_for_write(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    id: Uuid,
    shared_perm: Permission,
) -> Result<intellipilot_core::board::Board, Response> {
    let board = match bdb::get(client, ctx.project.id, id).await {
        Ok(Some(b)) => b,
        Ok(None) => return Err(not_found(&ctx.rid)),
        Err(_) => return Err(internal(&ctx.rid)),
    };
    if board.visibility.is_shared() {
        ctx.require(shared_perm).map_err(|_| forbidden(&ctx.rid))?;
    } else if board.owner_id != Some(ctx.actor_id) {
        // Someone else's personal board is invisible / untouchable.
        return Err(not_found(&ctx.rid));
    }
    Ok(board)
}

/// `GET /api/v1/projects/{project_id}/boards/{board_id}`
pub async fn get(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(id) = board_id(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bdb::get(&client, ctx.project.id, id).await {
        Ok(Some(b)) if b.visibility.is_shared() || b.owner_id == Some(ctx.actor_id) => {
            Json(b).into_response()
        }
        Ok(_) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PUT /api/v1/projects/{project_id}/boards/{board_id}`
pub async fn update(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateBoardRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(id) = board_id(&params) else {
        return not_found(&ctx.rid);
    };
    let req = match parse_update(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if let Err(r) = load_for_write(&client, &ctx, id, Permission::BoardSharedModify).await {
        return r;
    }
    match bdb::update(
        &client,
        ctx.project.id,
        id,
        &req.name,
        &req.color,
        &req.config,
    )
    .await
    {
        Ok(Some(b)) => Json(b).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/boards/{board_id}`
pub async fn delete(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(id) = board_id(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if let Err(r) = load_for_write(&client, &ctx, id, Permission::BoardSharedDelete).await {
        return r;
    }
    match bdb::delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/boards/last-opened`
pub async fn get_last_opened(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bdb::get_last_opened(&client, ctx.project.id, ctx.actor_id).await {
        Ok(board_id) => Json(json!({ "board_id": board_id })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PUT /api/v1/projects/{project_id}/boards/{board_id}/last-opened`
pub async fn set_last_opened(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(id) = board_id(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bdb::set_last_opened(&client, ctx.project.id, ctx.actor_id, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

// --------------------------------------------------------------------------
// board DATA (per-column counts + capped cards)
// --------------------------------------------------------------------------

/// Query string for the board-data endpoint: the same filter params as the
/// issues list, plus `group`, `columns` (CSV of status ids to include), and
/// `column_limit`.
#[derive(Debug, Deserialize)]
pub struct BoardDataQuery {
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub columns: Option<String>,
    #[serde(default)]
    pub column_limit: Option<u32>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default, rename = "status")]
    pub status_id: Option<String>,
    #[serde(default, rename = "type")]
    pub type_id: Option<String>,
    #[serde(default, rename = "priority")]
    pub priority_id: Option<String>,
    #[serde(default, rename = "size")]
    pub size_id: Option<String>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub qa_assignee: Option<String>,
    #[serde(default)]
    pub epic: Option<String>,
    #[serde(default)]
    pub milestone: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub component: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub overdue: Option<bool>,
}

fn ref_filter(s: &Option<String>) -> (Option<String>, Option<Uuid>) {
    match s.as_deref() {
        None => (None, None),
        Some("none") => (Some("none".to_owned()), None),
        Some(v) => Uuid::parse_str(v).map_or((None, None), |u| (Some("is".to_owned()), Some(u))),
    }
}
fn opt_uuid(s: &Option<String>) -> Option<Uuid> {
    s.as_deref().and_then(|v| Uuid::parse_str(v).ok())
}
fn opt_nonempty(s: &Option<String>) -> Option<String> {
    s.as_ref()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// `GET /api/v1/projects/{project_id}/board`
pub async fn board_data(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Query(q): Query<BoardDataQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let (assignee_mode, assignee_id) = ref_filter(&q.assignee);
    let (qa_assignee_mode, qa_assignee_id) = ref_filter(&q.qa_assignee);
    let (epic_mode, epic_id) = ref_filter(&q.epic);
    let (milestone_mode, milestone_id) = ref_filter(&q.milestone);
    let query = bl::IssueQuery {
        search: opt_nonempty(&q.search),
        status_id: opt_uuid(&q.status_id),
        type_id: opt_uuid(&q.type_id),
        priority_id: opt_uuid(&q.priority_id),
        size_id: opt_uuid(&q.size_id),
        category: opt_nonempty(&q.category),
        assignee_mode,
        assignee_id,
        qa_assignee_mode,
        qa_assignee_id,
        epic_mode,
        epic_id,
        milestone_mode,
        milestone_id,
        label_id: opt_uuid(&q.label),
        component_id: opt_uuid(&q.component),
        overdue: q.overdue.unwrap_or(false),
    };
    let column_limit = i64::from(q.column_limit.unwrap_or(50).clamp(1, 200));
    let columns: Option<Vec<Uuid>> = q.columns.as_deref().map(|s| {
        s.split(',')
            .filter_map(|p| Uuid::parse_str(p.trim()).ok())
            .collect()
    });
    let cols_ref = columns.as_deref();

    let group = q.group.as_deref().filter(|g| *g != "none" && !g.is_empty());
    match group {
        Some(g) => {
            match bl::board_lanes(&client, ctx.project.id, &query, g, cols_ref, column_limit).await
            {
                Ok(lanes) => Json(json!({ "group": g, "lanes": lanes })).into_response(),
                Err(_) => internal(&ctx.rid),
            }
        }
        None => {
            match bl::board_columns(&client, ctx.project.id, &query, cols_ref, column_limit).await {
                Ok(columns) => {
                    Json(json!({ "group": Value::Null, "columns": columns })).into_response()
                }
                Err(_) => internal(&ctx.rid),
            }
        }
    }
}
