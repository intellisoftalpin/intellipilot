//! Wiki endpoints: pages, immutable revisions, diff, and restore.
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::manual_let_else
)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::perms::Permission;
use intellipilot_db::wiki as wdb;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::dto::{CreateWikiPageRequest, UpdateWikiPageRequest};
use crate::markdown;
use crate::problem::Problem;
use crate::projects::{ProjectContext, slugify};
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

fn page_id(params: &HashMap<String, String>) -> Option<Uuid> {
    params.get("wiki_id").and_then(|s| Uuid::parse_str(s).ok())
}

fn rev_num(params: &HashMap<String, String>) -> Option<i32> {
    params.get("rev").and_then(|s| s.parse::<i32>().ok())
}

/// `POST /api/v1/projects/{project_id}/wiki`
pub async fn create(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<CreateWikiPageRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::WikiCreate) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let slug = req.slug.clone().unwrap_or_else(|| slugify(&req.title));
    let html = markdown::render(&req.body);
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    match wdb::create(
        &mut client,
        ctx.project.id,
        &slug,
        &req.title,
        &req.body,
        &html,
        ctx.actor_id,
    )
    .await
    {
        Ok(page) => (StatusCode::CREATED, Json(page)).into_response(),
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "already_exists",
            "Already Exists",
            Some("wiki slug already used".to_owned()),
            &ctx.rid,
        ),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/wiki`
pub async fn list(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::WikiView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match wdb::list(&client, ctx.project.id).await {
        Ok(pages) => Json(json!({ "pages": pages })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/wiki/{wiki_id}`
pub async fn get(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::WikiView) {
        return r;
    }
    let Some(id) = page_id(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match wdb::get(&client, ctx.project.id, id).await {
        Ok(Some(p)) => Json(p).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/wiki/{wiki_id}` — saves a new revision.
pub async fn update(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateWikiPageRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::WikiModify) {
        return r;
    }
    let Some(id) = page_id(&params) else {
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
    let Ok(Some(existing)) = wdb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    let title = req.title.unwrap_or(existing.title);
    let new_body = req.body.unwrap_or(existing.body);
    let html = markdown::render(&new_body);
    match wdb::update(
        &mut client,
        ctx.project.id,
        id,
        &title,
        &new_body,
        &html,
        ctx.actor_id,
    )
    .await
    {
        Ok(Some(p)) => Json(p).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/wiki/{wiki_id}`
pub async fn delete(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::WikiDelete) {
        return r;
    }
    let Some(id) = page_id(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match wdb::soft_delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/wiki/{wiki_id}/revisions`
pub async fn list_revisions(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::WikiView) {
        return r;
    }
    let Some(id) = page_id(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // 404 if the page itself isn't visible.
    if wdb::get(&client, ctx.project.id, id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return not_found(&ctx.rid);
    }
    match wdb::list_revisions(&client, id).await {
        Ok(revs) => Json(json!({ "revisions": revs })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/wiki/{wiki_id}/revisions/{rev}`
pub async fn get_revision(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::WikiView) {
        return r;
    }
    let (Some(id), Some(rev)) = (page_id(&params), rev_num(&params)) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if wdb::get(&client, ctx.project.id, id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return not_found(&ctx.rid);
    }
    match wdb::get_revision(&client, id, rev).await {
        Ok(Some(r)) => Json(r).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    /// Revision to diff against; defaults to the page's current body.
    to: Option<i32>,
}

/// `GET /api/v1/projects/{project_id}/wiki/{wiki_id}/revisions/{rev}/diff`
///
/// Unified diff from revision `{rev}` to `?to=` (or the current page body).
pub async fn diff(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    Query(q): Query<DiffQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::WikiView) {
        return r;
    }
    let (Some(id), Some(rev)) = (page_id(&params), rev_num(&params)) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some(page)) = wdb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    let Ok(Some(from)) = wdb::get_revision(&client, id, rev).await else {
        return not_found(&ctx.rid);
    };
    let from_body = from.body.unwrap_or_default();

    let (to_label, to_body) = match q.to {
        Some(to_rev) => match wdb::get_revision(&client, id, to_rev).await {
            Ok(Some(r)) => (format!("rev {to_rev}"), r.body.unwrap_or_default()),
            Ok(None) => return not_found(&ctx.rid),
            Err(_) => return internal(&ctx.rid),
        },
        None => (format!("current (rev {})", page.version), page.body),
    };

    let diff = similar::TextDiff::from_lines(&from_body, &to_body);
    let unified = diff
        .unified_diff()
        .context_radius(3)
        .header(&format!("rev {rev}"), &to_label)
        .to_string();
    Json(json!({ "from": rev, "to": q.to, "diff": unified })).into_response()
}

/// `POST /api/v1/projects/{project_id}/wiki/{wiki_id}/revisions/{rev}/restore`
///
/// Non-destructive: restoring revision `{rev}` writes a *new* revision with
/// that content.
pub async fn restore(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::WikiModify) {
        return r;
    }
    let (Some(id), Some(rev)) = (page_id(&params), rev_num(&params)) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    let Ok(Some(snapshot)) = wdb::get_revision(&client, id, rev).await else {
        return not_found(&ctx.rid);
    };
    let body = snapshot.body.unwrap_or_default();
    let html = markdown::render(&body);
    match wdb::update(
        &mut client,
        ctx.project.id,
        id,
        &snapshot.title,
        &body,
        &html,
        ctx.actor_id,
    )
    .await
    {
        Ok(Some(p)) => Json(p).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}
