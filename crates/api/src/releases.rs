//! Release + version endpoints, component↔release links, and the fix-version
//! picker. View needs `project.view`; mutate needs `project.modify`.
#![allow(clippy::result_large_err, clippy::implicit_hasher)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::perms::Permission;
use intellipilot_core::release::ReleaseStatus;
use intellipilot_db::{
    component_releases as crdb, components as compdb, release_versions as rvdb, releases as reldb,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

// --- DTOs ------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct CreateReleaseRequest {
    #[garde(length(min = 1, max = 128))]
    pub name: String,
    #[garde(length(max = 5000))]
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct UpdateReleaseRequest {
    #[garde(length(min = 1, max = 128))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(skip)]
    #[serde(default, with = "serde_with::rust::double_option")]
    pub description: Option<Option<String>>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct CreateVersionRequest {
    #[garde(length(min = 1, max = 64))]
    pub version: String,
    #[garde(skip)]
    #[serde(default)]
    pub status: Option<ReleaseStatus>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub target_date: Option<time::Date>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub released_at: Option<time::OffsetDateTime>,
    #[garde(length(max = 100_000))]
    #[serde(default)]
    pub notes: String,
    #[garde(skip)]
    #[serde(default)]
    pub repository_id: Option<Uuid>,
    #[garde(length(max = 255))]
    #[serde(default)]
    pub git_tag: Option<String>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct UpdateVersionRequest {
    #[garde(length(min = 1, max = 64))]
    #[serde(default)]
    pub version: Option<String>,
    #[garde(skip)]
    #[serde(default)]
    pub status: Option<ReleaseStatus>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub target_date: Option<time::Date>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub released_at: Option<time::OffsetDateTime>,
    #[garde(length(max = 100_000))]
    #[serde(default)]
    pub notes: Option<String>,
    #[garde(skip)]
    #[serde(default, with = "serde_with::rust::double_option")]
    pub repository_id: Option<Option<Uuid>>,
    #[garde(skip)]
    #[serde(default, with = "serde_with::rust::double_option")]
    pub git_tag: Option<Option<String>>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct ForComponentsRequest {
    #[garde(length(max = 50))]
    pub component_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct LinkReleaseRequest {
    #[garde(skip)]
    pub release_id: Uuid,
}

// --- helpers ---------------------------------------------------------------

fn problem(status: StatusCode, code: &'static str, detail: Option<String>, rid: &str) -> Response {
    Problem::new(status, code, code, detail, rid).into_response_with_status(status)
}
fn internal(rid: &str) -> Response {
    problem(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        None,
        rid,
    )
}
fn not_found(rid: &str) -> Response {
    problem(StatusCode::NOT_FOUND, "not_found", None, rid)
}
fn conflict(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        "already_exists",
        Some(detail.to_owned()),
        rid,
    )
}
fn unprocessable(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
        Some(detail.to_owned()),
        rid,
    )
}
fn parse_body<T: serde::de::DeserializeOwned + Validate<Context = ()>>(
    body: Result<Json<T>, JsonRejection>,
    rid: &str,
) -> Result<T, Response> {
    let Ok(Json(v)) = body else {
        return Err(problem(StatusCode::BAD_REQUEST, "invalid_body", None, rid));
    };
    if v.validate().is_err() {
        return Err(problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            None,
            rid,
        ));
    }
    Ok(v)
}
fn item_id(params: &HashMap<String, String>, key: &str) -> Option<Uuid> {
    params.get(key).and_then(|s| Uuid::parse_str(s).ok())
}
async fn component_in_project(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    component_id: Uuid,
) -> bool {
    matches!(
        compdb::list(client, ctx.project.id).await,
        Ok(items) if items.iter().any(|c| c.id == component_id)
    )
}

// --- releases --------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/releases`
pub async fn list_releases(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match reldb::list(&client, ctx.project.id).await {
        Ok(items) => Json(json!({ "releases": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/releases`
pub async fn create_release(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<CreateReleaseRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ReleaseCreate) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match reldb::create(
        &client,
        ctx.project.id,
        ctx.actor_id,
        &req.name,
        req.description.as_deref(),
    )
    .await
    {
        Ok(rel) => (StatusCode::CREATED, Json(rel)).into_response(),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid, "release name already used"),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/releases/{release_id}`
pub async fn update_release(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateReleaseRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ReleaseModify) {
        return r;
    }
    let Some(id) = item_id(&params, "release_id") else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let desc = req.description.as_ref().map(|o| o.as_deref());
    match reldb::update(&client, ctx.project.id, id, req.name.as_deref(), desc).await {
        Ok(Some(rel)) => Json(rel).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid, "release name already used"),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/releases/{release_id}`
pub async fn delete_release(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ReleaseDelete) {
        return r;
    }
    let Some(id) = item_id(&params, "release_id") else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match reldb::delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// --- versions --------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/releases/{release_id}/versions`
pub async fn list_versions(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(rid) = item_id(&params, "release_id") else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match rvdb::list_for_release(&client, ctx.project.id, rid).await {
        Ok(items) => Json(json!({ "versions": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/releases/{release_id}/versions`
pub async fn create_version(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<CreateVersionRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ReleaseCreate) {
        return r;
    }
    let Some(release_id) = item_id(&params, "release_id") else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // Release must belong to the project.
    match reldb::get(&client, ctx.project.id, release_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&ctx.rid),
        Err(_) => return internal(&ctx.rid),
    }
    let status = req.status.unwrap_or(ReleaseStatus::Planned);
    let w = rvdb::VersionWrite {
        version: &req.version,
        status: status.as_str(),
        target_date: req.target_date,
        released_at: req.released_at,
        notes: &req.notes,
        repository_id: req.repository_id,
        git_tag: req.git_tag.as_deref(),
    };
    match rvdb::create(&client, release_id, &w).await {
        Ok(v) => (StatusCode::CREATED, Json(v)).into_response(),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid, "version already exists"),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/releases/{release_id}/versions/{version_id}`
pub async fn update_version(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateVersionRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ReleaseModify) {
        return r;
    }
    let Some(id) = item_id(&params, "version_id") else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some(old)) = rvdb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    let version = req.version.unwrap_or(old.version);
    let status = req.status.unwrap_or(old.status);
    let target_date = req.target_date.or(old.target_date);
    let released_at = req.released_at.or(old.released_at);
    let notes = req.notes.unwrap_or(old.notes);
    let repository_id = req.repository_id.unwrap_or(old.repository_id);
    let git_tag = req.git_tag.unwrap_or(old.git_tag);
    let w = rvdb::VersionWrite {
        version: &version,
        status: status.as_str(),
        target_date,
        released_at,
        notes: &notes,
        repository_id,
        git_tag: git_tag.as_deref(),
    };
    match rvdb::update(&client, ctx.project.id, id, &w).await {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid, "version already exists"),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/releases/{release_id}/versions/{version_id}`
pub async fn delete_version(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ReleaseDelete) {
        return r;
    }
    let Some(id) = item_id(&params, "version_id") else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match rvdb::delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/release-versions/for-components`
///
/// Versions available for a set of components (drives the issue fix-version
/// picker). Returns an empty list when no components link any releases.
pub async fn versions_for_components(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<ForComponentsRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match rvdb::for_components(&client, &req.component_ids).await {
        Ok(items) => Json(json!({ "versions": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

// --- component <-> release links -------------------------------------------

/// `GET /api/v1/projects/{project_id}/components/{component_id}/releases`
pub async fn list_component_releases(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(component_id) = item_id(&params, "component_id") else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if !component_in_project(&client, &ctx, component_id).await {
        return not_found(&ctx.rid);
    }
    match crdb::list_for_component(&client, component_id).await {
        Ok(items) => Json(json!({ "releases": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/components/{component_id}/releases`
pub async fn link_component_release(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<LinkReleaseRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ReleaseModify) {
        return r;
    }
    let Some(component_id) = item_id(&params, "component_id") else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if !component_in_project(&client, &ctx, component_id).await {
        return not_found(&ctx.rid);
    }
    match reldb::get(&client, ctx.project.id, req.release_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return unprocessable(&ctx.rid, "release not found in this project"),
        Err(_) => return internal(&ctx.rid),
    }
    match crdb::link(&client, component_id, req.release_id).await {
        Ok(link) => (StatusCode::CREATED, Json(link)).into_response(),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid, "release already linked"),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/components/{component_id}/releases/{release_id}`
pub async fn unlink_component_release(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ReleaseModify) {
        return r;
    }
    let (Some(component_id), Some(release_id)) = (
        item_id(&params, "component_id"),
        item_id(&params, "release_id"),
    ) else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match crdb::unlink(&client, component_id, release_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}
