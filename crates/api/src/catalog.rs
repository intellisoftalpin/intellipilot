//! Project-level Labels and Components endpoints.
//!
//! Viewing needs `project.view`; managing needs `project.modify` (consistent
//! with taxonomy — these are project configuration, not work items).
#![allow(clippy::result_large_err, clippy::implicit_hasher)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::perms::Permission;
use intellipilot_db::{components as compdb, labels as ldb};
use serde_json::json;
use uuid::Uuid;

use crate::dto::{
    CreateComponentRequest, CreateLabelRequest, UpdateComponentRequest, UpdateLabelRequest,
};
use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

fn problem(
    status: StatusCode,
    code: &'static str,
    title: &str,
    detail: Option<String>,
    rid: &str,
) -> Response {
    Problem::new(status, code, title, detail, rid).into_response_with_status(status)
}
fn internal(rid: &str) -> Response {
    problem(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal Server Error",
        None,
        rid,
    )
}
fn not_found(rid: &str) -> Response {
    problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, rid)
}
fn conflict(rid: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        "already_exists",
        "Already Exists",
        Some("name already used".to_owned()),
        rid,
    )
}

fn parse_body<T: serde::de::DeserializeOwned + Validate<Context = ()>>(
    body: Result<Json<T>, JsonRejection>,
    rid: &str,
) -> Result<T, Response> {
    let Ok(Json(v)) = body else {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            None,
            rid,
        ));
    };
    if v.validate().is_err() {
        return Err(problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
            None,
            rid,
        ));
    }
    Ok(v)
}

fn item_id(params: &HashMap<String, String>, key: &str) -> Option<Uuid> {
    params.get(key).and_then(|s| Uuid::parse_str(s).ok())
}

// --- labels ---------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/labels`
pub async fn list_labels(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ldb::list(&client, ctx.project.id).await {
        Ok(items) => Json(json!({ "labels": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/labels`
pub async fn create_label(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<CreateLabelRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
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
    match ldb::create(&client, ctx.project.id, &req.name, &req.color).await {
        Ok(l) => (StatusCode::CREATED, Json(l)).into_response(),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/labels/{label_id}`
pub async fn update_label(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateLabelRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "label_id") else {
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
    match ldb::update(
        &client,
        ctx.project.id,
        id,
        req.name.as_deref(),
        req.color.as_deref(),
    )
    .await
    {
        Ok(Some(l)) => Json(l).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/labels/{label_id}`
pub async fn delete_label(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "label_id") else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ldb::delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// --- components -----------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/components`
pub async fn list_components(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match compdb::list(&client, ctx.project.id).await {
        Ok(items) => Json(json!({ "components": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/components`
pub async fn create_component(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<CreateComponentRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
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
    match compdb::create(&client, ctx.project.id, &req.name, &req.color).await {
        Ok(c) => (StatusCode::CREATED, Json(c)).into_response(),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/components/{component_id}`
pub async fn update_component(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateComponentRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "component_id") else {
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
    match compdb::update(
        &client,
        ctx.project.id,
        id,
        req.name.as_deref(),
        req.color.as_deref(),
    )
    .await
    {
        Ok(Some(c)) => Json(c).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/components/{component_id}`
pub async fn delete_component(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "component_id") else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match compdb::delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}
