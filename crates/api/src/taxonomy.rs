//! Generic per-project taxonomy endpoints, parameterized by `{kind}`.
//!
//! `/api/v1/projects/{project_id}/taxonomy/{kind}` covers statuses, issue
//! types, priorities, severities, and points with one handler set. Viewing
//! needs `project.view`; mutating needs `project.modify`.
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::manual_let_else
)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::perms::Permission;
use intellipilot_core::taxonomy::TaxonomyKind;
use intellipilot_db::taxonomy as taxdb;
use serde_json::json;
use uuid::Uuid;

use crate::dto::{CreateTaxonomyItemRequest, MoveTaxonomyItemRequest, UpdateTaxonomyItemRequest};
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

fn parse_kind(params: &HashMap<String, String>, rid: &str) -> Result<TaxonomyKind, Response> {
    params
        .get("kind")
        .and_then(|s| TaxonomyKind::parse(s))
        .ok_or_else(|| not_found(rid))
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

/// `GET /api/v1/projects/{project_id}/taxonomy/{kind}`
pub async fn list(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let kind = match parse_kind(&params, &ctx.rid) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match taxdb::list(&client, ctx.project.id, kind).await {
        Ok(items) => Json(json!({ "items": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/taxonomy/{kind}`
pub async fn create(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<CreateTaxonomyItemRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let kind = match parse_kind(&params, &ctx.rid) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Default is_closed for status kinds if omitted.
    let is_closed = if kind.has_closed() {
        Some(req.is_closed.unwrap_or(false))
    } else {
        None
    };
    let value = if kind.has_value() { req.value } else { None };

    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match taxdb::create(
        &client,
        ctx.project.id,
        kind,
        &req.name,
        &req.slug,
        &req.color,
        &req.emoji,
        is_closed,
        value,
    )
    .await
    {
        Ok(item) => (StatusCode::CREATED, Json(item)).into_response(),
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "already_exists",
            "Already Exists",
            Some("slug already used for this kind".to_owned()),
            &ctx.rid,
        ),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/taxonomy/{kind}/{item_id}`
pub async fn update(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateTaxonomyItemRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let kind = match parse_kind(&params, &ctx.rid) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(item_id) = params.get("item_id").and_then(|s| Uuid::parse_str(s).ok()) else {
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
    match taxdb::update(
        &client,
        ctx.project.id,
        kind,
        item_id,
        req.name.as_deref(),
        req.color.as_deref(),
        req.emoji.as_deref(),
        req.is_closed,
        req.value,
    )
    .await
    {
        Ok(Some(item)) => Json(item).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/taxonomy/{kind}/{item_id}`
///
/// Returns 409 (with the reference count) if the item is referenced by any
/// backlog entity (status/type/priority/severity).
pub async fn delete(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let kind = match parse_kind(&params, &ctx.rid) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(item_id) = params.get("item_id").and_then(|s| Uuid::parse_str(s).ok()) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };

    // In-use guard: refuse to delete a taxonomy item still referenced by work
    // items, returning the count so the client can surface it.
    match intellipilot_db::backlog::taxonomy_reference_count(&client, item_id).await {
        Ok(n) if n > 0 => {
            let noun = if n == 1 {
                "entity references"
            } else {
                "entities reference"
            };
            return Problem::new(
                StatusCode::CONFLICT,
                "in_use",
                "Taxonomy item in use",
                Some(format!("{n} {noun} this item")),
                &ctx.rid,
            )
            .into_response_with_status(StatusCode::CONFLICT);
        }
        Ok(_) => {}
        Err(_) => return internal(&ctx.rid),
    }

    match taxdb::delete(&client, ctx.project.id, kind, item_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/taxonomy/{kind}/{item_id}/move`
pub async fn move_item(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<MoveTaxonomyItemRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let kind = match parse_kind(&params, &ctx.rid) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Some(item_id) = params.get("item_id").and_then(|s| Uuid::parse_str(s).ok()) else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    match taxdb::move_item(
        &mut client,
        ctx.project.id,
        kind,
        item_id,
        req.before_id,
        req.after_id,
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}
