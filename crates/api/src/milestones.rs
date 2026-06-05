//! Milestone (sprint) endpoints: CRUD, close, board, and stats.
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::arithmetic_side_effects
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
use intellipilot_db::{backlog as bl, milestones as msdb, taxonomy as taxdb};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::dto::{CreateMilestoneRequest, UpdateMilestoneRequest};
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

fn mid_param(params: &HashMap<String, String>) -> Option<Uuid> {
    params
        .get("milestone_id")
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// `POST /api/v1/projects/{project_id}/milestones`
pub async fn create(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<CreateMilestoneRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneCreate) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !dates_ok(req.start_date, req.end_date) {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_dates",
            "Invalid dates",
            Some("end_date must be on or after start_date".to_owned()),
            &ctx.rid,
        );
    }
    let slug = req.slug.clone().unwrap_or_else(|| slugify(&req.name));
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match msdb::create(
        &client,
        ctx.project.id,
        &req.name,
        &slug,
        req.start_date,
        req.end_date,
    )
    .await
    {
        Ok(m) => (StatusCode::CREATED, Json(m)).into_response(),
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "already_exists",
            "Already Exists",
            Some("milestone slug already used".to_owned()),
            &ctx.rid,
        ),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/milestones`
pub async fn list(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match msdb::list(&client, ctx.project.id).await {
        Ok(items) => Json(json!({ "milestones": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/milestones/{milestone_id}`
pub async fn get(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneView) {
        return r;
    }
    let Some(id) = mid_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match msdb::get(&client, ctx.project.id, id).await {
        Ok(Some(m)) => Json(m).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/milestones/{milestone_id}`
pub async fn update(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateMilestoneRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneModify) {
        return r;
    }
    let Some(id) = mid_param(&params) else {
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
    // Validate effective dates against the stored row.
    let Ok(Some(existing)) = msdb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    let start = req.start_date.or(existing.start_date);
    let end = req.end_date.or(existing.end_date);
    if !dates_ok(start, end) {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_dates",
            "Invalid dates",
            Some("end_date must be on or after start_date".to_owned()),
            &ctx.rid,
        );
    }
    match msdb::update(
        &client,
        ctx.project.id,
        id,
        req.name.as_deref(),
        req.start_date,
        req.end_date,
    )
    .await
    {
        Ok(Some(m)) => Json(m).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/milestones/{milestone_id}/close`
pub async fn close(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneModify) {
        return r;
    }
    let Some(id) = mid_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match msdb::close(&client, ctx.project.id, id).await {
        Ok(Some(m)) => Json(m).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/milestones/{milestone_id}`
pub async fn delete(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneDelete) {
        return r;
    }
    let Some(id) = mid_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match msdb::soft_delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/milestones/{milestone_id}/board`
///
/// Columns are the project's user-story statuses; each column lists the
/// milestone's user stories in that status, each with its tasks. Stories with
/// no status fall into a trailing `status: null` column.
pub async fn board(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneView) {
        return r;
    }
    let Some(id) = mid_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if !msdb::in_project(&client, ctx.project.id, id)
        .await
        .unwrap_or(false)
    {
        return not_found(&ctx.rid);
    }

    let Ok(statuses) = taxdb::list(&client, ctx.project.id, TaxonomyKind::IssueStatus).await else {
        return internal(&ctx.rid);
    };
    let Ok(issues) = bl::issues_in_milestone(&client, ctx.project.id, id).await else {
        return internal(&ctx.rid);
    };

    // Attach each issue's sub-tasks (child issues) to its card.
    let mut cards: Vec<Value> = Vec::with_capacity(issues.len());
    for iss in &issues {
        let subtasks = bl::children_for_parent(&client, ctx.project.id, iss.id)
            .await
            .unwrap_or_default();
        let mut card = serde_json::to_value(iss).unwrap_or(Value::Null);
        if let Value::Object(ref mut map) = card {
            map.insert(
                "subtasks".to_owned(),
                serde_json::to_value(&subtasks).unwrap_or(Value::Null),
            );
        }
        cards.push(card);
    }

    let column = |status: Option<&Value>, status_id: Option<Uuid>| -> Value {
        let issues: Vec<&Value> = cards
            .iter()
            .filter(|c| {
                c.get("status_id")
                    .and_then(Value::as_str)
                    .and_then(|s| Uuid::parse_str(s).ok())
                    == status_id
            })
            .collect();
        json!({ "status": status, "issues": issues })
    };

    let mut columns: Vec<Value> = Vec::with_capacity(statuses.len() + 1);
    for s in &statuses {
        let sv = serde_json::to_value(s).unwrap_or(Value::Null);
        columns.push(column(Some(&sv), Some(s.id)));
    }
    // Trailing column for stories with no status.
    columns.push(column(None, None));

    Json(json!({ "milestone_id": id, "columns": columns })).into_response()
}

/// `GET /api/v1/projects/{project_id}/milestones/{milestone_id}/stats`
pub async fn stats(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneView) {
        return r;
    }
    let Some(id) = mid_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if !msdb::in_project(&client, ctx.project.id, id)
        .await
        .unwrap_or(false)
    {
        return not_found(&ctx.rid);
    }
    match msdb::stats(&client, ctx.project.id, id).await {
        Ok(s) => Json(s).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `end_date >= start_date` when both are present; otherwise always ok.
fn dates_ok(start: Option<time::Date>, end: Option<time::Date>) -> bool {
    match (start, end) {
        (Some(s), Some(e)) => e >= s,
        _ => true,
    }
}
