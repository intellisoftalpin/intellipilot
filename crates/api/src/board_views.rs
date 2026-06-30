//! Per-user kanban board configuration endpoints.
//!
//! Named saved board states plus a remembered "last-used" board, all scoped to
//! the calling user. The `config` blob (visible columns, order, filter,
//! grouping) is owned by the SPA and stored verbatim. Viewing/saving your own
//! board preferences only needs `project.view`.
#![allow(clippy::result_large_err, clippy::implicit_hasher)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::perms::Permission;
use intellipilot_db::board_views as bvdb;
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

/// Create/update payload for a named saved board view.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct BoardViewRequest {
    #[garde(length(min = 1, max = 120))]
    pub name: String,
    /// Opaque board config (visible columns, order, filter, grouping).
    #[garde(skip)]
    #[serde(default)]
    #[schema(value_type = Object)]
    pub config: Value,
}

fn parse_body(
    body: Result<Json<BoardViewRequest>, JsonRejection>,
    rid: &str,
) -> Result<BoardViewRequest, Response> {
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

fn view_id(params: &HashMap<String, String>) -> Option<Uuid> {
    params.get("view_id").and_then(|s| Uuid::parse_str(s).ok())
}

/// `GET /api/v1/projects/{project_id}/board-views`
pub async fn list(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bvdb::list(&client, ctx.project.id, ctx.actor_id).await {
        Ok(views) => Json(json!({ "views": views })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/board-views`
pub async fn create(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<BoardViewRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bvdb::create(
        &client,
        ctx.project.id,
        ctx.actor_id,
        &req.name,
        &req.config,
    )
    .await
    {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PUT /api/v1/projects/{project_id}/board-views/{view_id}`
pub async fn update(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<BoardViewRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(id) = view_id(&params) else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bvdb::update(
        &client,
        ctx.project.id,
        ctx.actor_id,
        id,
        &req.name,
        &req.config,
    )
    .await
    {
        Ok(Some(view)) => Json(view).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/board-views/{view_id}`
pub async fn delete(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(id) = view_id(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bvdb::delete(&client, ctx.project.id, ctx.actor_id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/board-views/last-used`
pub async fn get_last_used(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bvdb::get_last_used(&client, ctx.project.id, ctx.actor_id).await {
        Ok(config) => Json(json!({ "config": config })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PUT /api/v1/projects/{project_id}/board-views/last-used`
pub async fn put_last_used(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let config = match body {
        Ok(Json(v)) => v,
        Err(_) => Value::Null,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bvdb::set_last_used(&client, ctx.project.id, ctx.actor_id, &config).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal(&ctx.rid),
    }
}
