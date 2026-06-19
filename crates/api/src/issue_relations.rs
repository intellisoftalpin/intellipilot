//! Issue relationship + watcher sub-resources. View needs `issue.view`; mutate
//! needs `issue.modify`.
#![allow(clippy::result_large_err, clippy::implicit_hasher)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::backlog::LinkType;
use intellipilot_core::perms::Permission;
use intellipilot_db::{backlog as bl, issue_links as ildb, issue_watchers as iwdb};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct CreateLinkRequest {
    #[garde(skip)]
    pub target_issue_id: Uuid,
    #[garde(skip)]
    pub link_type: LinkType,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct AddWatcherRequest {
    /// Defaults to the caller when omitted.
    #[garde(skip)]
    #[serde(default)]
    pub user_id: Option<Uuid>,
}

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

// --- relationships ---------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/issues/{id}/links`
pub async fn list_links(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueView) {
        return r;
    }
    let Some(issue_id) = item_id(&params, "id") else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if !bl::issue_in_project(&client, ctx.project.id, issue_id)
        .await
        .unwrap_or(false)
    {
        return not_found(&ctx.rid);
    }
    match ildb::list_for_issue(&client, issue_id).await {
        Ok(items) => Json(json!({ "links": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/issues/{id}/links`
pub async fn create_link(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<CreateLinkRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueModify) {
        return r;
    }
    let Some(issue_id) = item_id(&params, "id") else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if req.target_issue_id == issue_id {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            Some("an issue cannot link to itself".to_owned()),
            &ctx.rid,
        );
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let source_ok = bl::issue_in_project(&client, ctx.project.id, issue_id)
        .await
        .unwrap_or(false);
    if !source_ok {
        return not_found(&ctx.rid);
    }
    if !bl::issue_in_project(&client, ctx.project.id, req.target_issue_id)
        .await
        .unwrap_or(false)
    {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            Some("target issue not found in this project".to_owned()),
            &ctx.rid,
        );
    }
    match ildb::create(
        &client,
        ctx.project.id,
        issue_id,
        req.target_issue_id,
        req.link_type.as_str(),
    )
    .await
    {
        Ok(link) => (StatusCode::CREATED, Json(link)).into_response(),
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "already_exists",
            Some("link already exists".to_owned()),
            &ctx.rid,
        ),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/issues/{id}/links/{link_id}`
pub async fn delete_link(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueModify) {
        return r;
    }
    let Some(link_id) = item_id(&params, "link_id") else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ildb::delete(&client, ctx.project.id, link_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// --- watchers --------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/issues/{id}/watchers`
pub async fn list_watchers(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueView) {
        return r;
    }
    let Some(issue_id) = item_id(&params, "id") else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if !bl::issue_in_project(&client, ctx.project.id, issue_id)
        .await
        .unwrap_or(false)
    {
        return not_found(&ctx.rid);
    }
    match iwdb::list(&client, issue_id).await {
        Ok(items) => Json(json!({ "watchers": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/issues/{id}/watchers`
pub async fn add_watcher(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<AddWatcherRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueModify) {
        return r;
    }
    let Some(issue_id) = item_id(&params, "id") else {
        return not_found(&ctx.rid);
    };
    // Body is optional; default to watching as the caller.
    let user_id = match body {
        Ok(Json(b)) => b.user_id.unwrap_or(ctx.actor_id),
        Err(_) => ctx.actor_id,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if !bl::issue_in_project(&client, ctx.project.id, issue_id)
        .await
        .unwrap_or(false)
    {
        return not_found(&ctx.rid);
    }
    match iwdb::add(&client, issue_id, user_id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/issues/{id}/watchers/{user_id}`
pub async fn remove_watcher(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueModify) {
        return r;
    }
    let (Some(issue_id), Some(user_id)) = (item_id(&params, "id"), item_id(&params, "user_id"))
    else {
        return not_found(&ctx.rid);
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match iwdb::remove(&client, issue_id, user_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}
