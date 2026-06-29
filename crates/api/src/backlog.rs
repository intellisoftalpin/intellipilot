//! Backlog endpoints: epics and the unified issue (Story/Task/Bug/sub-task),
//! plus comments, history and the ref resolver. Cross-cutting: ETag/If-Match
//! OCC, JSON-merge-patch updates, auto-generated history, bulk create,
//! reordering, and Idempotency-Key.
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::manual_let_else,
    clippy::too_many_lines,
    clippy::collapsible_if,
    clippy::too_many_arguments,
    clippy::arithmetic_side_effects,
    clippy::ref_option,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::too_long_first_doc_paragraph
)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::backlog::{EntityKind, etag};
use intellipilot_core::perms::Permission;
use intellipilot_db::backlog::UpdateOutcome;
use intellipilot_db::{
    attachments as adb, audit, backlog as bl, comments as cdb, components as compdb,
    customers as custdb, history, idempotency, labels as ldb, milestones as msdb,
    release_versions as rvdb,
};
use serde::Serialize;
use serde_json::{Value, json};
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use crate::auth::{client_ip, user_agent};
use crate::dto::{
    BulkCreateIssuesRequest, CommentRequest, CreateEpicRequest, CreateIssueRequest, ReorderRequest,
    UpdateEpicRequest, UpdateIssueRequest,
};
use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

const COMMENT_EDIT_WINDOW_SECS: i64 = 24 * 60 * 60;
const IDEMPOTENCY_TTL_SECS: i64 = 24 * 60 * 60;
const ERASE_GRACE_DAYS: i64 = 30;

// --------------------------------------------------------------------------
// response/error helpers
// --------------------------------------------------------------------------

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
fn unprocessable(rid: &str, code: &'static str, detail: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        code,
        "Unprocessable",
        Some(detail.to_owned()),
        rid,
    )
}

/// Build a JSON response with an ETag header.
fn with_etag<T: Serialize>(status: StatusCode, id: Uuid, version: i32, body: &T) -> Response {
    let mut resp = (status, Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(&etag(id, version)) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    resp
}

/// Drop an optional weak-validator prefix (`W/`) so a strong ETag and its
/// weakened form compare equal. Reverse proxies (e.g. nginx when it gzips a
/// response) rewrite a strong `"x"` to `W/"x"`; our revision token's meaning is
/// unchanged by that marker, so we treat them as equivalent for `If-Match`.
fn strip_weak(tag: &str) -> &str {
    tag.strip_prefix("W/").unwrap_or(tag)
}

/// Validate the `If-Match` precondition: 428 if missing, 412 if it doesn't
/// match the current ETag (weak and strong forms are treated as equal).
fn check_if_match(headers: &HeaderMap, current: &str, rid: &str) -> Result<(), Response> {
    match headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()) {
        None => Err(problem(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "Precondition Required",
            Some("If-Match header is required for updates".to_owned()),
            rid,
        )),
        Some(val)
            if val.trim() == "*"
                || val
                    .split(',')
                    .map(str::trim)
                    .any(|e| strip_weak(e) == strip_weak(current)) =>
        {
            Ok(())
        }
        Some(_) => Err(problem(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "Precondition Failed",
            Some("ETag mismatch; reload and retry".to_owned()),
            rid,
        )),
    }
}

fn parse_create<T: serde::de::DeserializeOwned + Validate<Context = ()>>(
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
        return Err(unprocessable(rid, "validation_failed", "validation failed"));
    }
    Ok(v)
}

/// Parse a merge-patch body. Unknown fields (deny_unknown_fields) surface as a
/// JSON data error → 400.
fn parse_patch<T: serde::de::DeserializeOwned>(
    body: Result<Json<T>, JsonRejection>,
    rid: &str,
) -> Result<T, Response> {
    match body {
        Ok(Json(v)) => Ok(v),
        Err(JsonRejection::JsonDataError(_) | JsonRejection::JsonSyntaxError(_)) => Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            Some("unknown or malformed field".to_owned()),
            rid,
        )),
        Err(_) => Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            None,
            rid,
        )),
    }
}

fn diff_field(map: &mut serde_json::Map<String, Value>, field: &str, old: &Value, new: &Value) {
    if old != new {
        map.insert(field.to_owned(), json!([old, new]));
    }
}

// --------------------------------------------------------------------------
// idempotency
// --------------------------------------------------------------------------

fn idem_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// If a prior response is stored for this key, return it (with the
/// `Idempotent-Replayed: true` header).
async fn replay(
    auth: &crate::state::AuthContext,
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    key: &Option<String>,
    method: &str,
    path: &str,
) -> Option<Response> {
    let _ = auth;
    let key = key.as_ref()?;
    let stored = idempotency::lookup(client, user_id, key, method, path)
        .await
        .ok()??;
    let status =
        StatusCode::from_u16(u16::try_from(stored.status).unwrap_or(200)).unwrap_or(StatusCode::OK);
    let mut resp = (status, Json(&stored.body)).into_response();
    resp.headers_mut()
        .insert("idempotent-replayed", HeaderValue::from_static("true"));
    Some(resp)
}

async fn remember(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    key: &Option<String>,
    method: &str,
    path: &str,
    status: StatusCode,
    body: &Value,
) {
    if let Some(key) = key {
        let expires = OffsetDateTime::now_utc() + TimeDuration::seconds(IDEMPOTENCY_TTL_SECS);
        if let Err(e) = idempotency::store(
            client,
            user_id,
            key,
            method,
            path,
            i32::from(status.as_u16()),
            body,
            expires,
        )
        .await
        {
            tracing::warn!(error = %e, "failed to store idempotency key");
        }
    }
}

// ==========================================================================
// epics
// ==========================================================================

/// `POST /api/v1/projects/{project_id}/epics`
pub async fn create_epic(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    body: Result<Json<CreateEpicRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::EpicCreate) {
        return r;
    }
    let req = match parse_create(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let key = idem_key(&headers);
    let path = format!("/projects/{}/epics", ctx.project.id);
    if let Some(r) = replay(auth, &client, ctx.actor_id, &key, "POST", &path).await {
        return r;
    }
    match bl::create_epic(
        &client,
        ctx.project.id,
        ctx.actor_id,
        &req.subject,
        &req.description,
        req.status_id,
        &req.color,
        req.assigned_to,
        req.milestone_id,
    )
    .await
    {
        Ok(epic) => {
            history::record(
                &client,
                ctx.project.id,
                "epic",
                epic.id,
                Some(ctx.actor_id),
                &json!({"created": true}),
            )
            .await;
            let body = serde_json::to_value(&epic).unwrap_or(Value::Null);
            remember(
                &client,
                ctx.actor_id,
                &key,
                "POST",
                &path,
                StatusCode::CREATED,
                &body,
            )
            .await;
            with_etag(StatusCode::CREATED, epic.id, epic.version, &epic)
        }
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/epics`
pub async fn list_epics(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::EpicView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bl::list_epics(&client, ctx.project.id).await {
        Ok(items) => Json(json!({ "epics": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/epics/{id}`
pub async fn get_epic(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::EpicView) {
        return r;
    }
    let Some(id) = id_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bl::get_epic(&client, ctx.project.id, id).await {
        Ok(Some(e)) => with_etag(StatusCode::OK, e.id, e.version, &e),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/epics/{id}`
pub async fn update_epic(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: HeaderMap,
    body: Result<Json<UpdateEpicRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::EpicModify) {
        return r;
    }
    let Some(id) = id_param(&params) else {
        return not_found(&ctx.rid);
    };
    let patch = match parse_patch(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some(old)) = bl::get_epic(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    if let Err(r) = check_if_match(&headers, &etag(old.id, old.version), &ctx.rid) {
        return r;
    }

    let subject = patch.subject.unwrap_or(old.subject.clone());
    let description = patch.description.unwrap_or(old.description.clone());
    let color = patch.color.unwrap_or(old.color.clone());
    let status_id = patch.status_id.unwrap_or(old.status_id);
    let assigned_to = patch.assigned_to.unwrap_or(old.assigned_to);
    let milestone_id = patch.milestone_id.unwrap_or(old.milestone_id);
    let start_date = patch.start_date.or(old.start_date);
    let end_date = patch.end_date.or(old.end_date);

    let mut diff = serde_json::Map::new();
    diff_field(&mut diff, "subject", &json!(old.subject), &json!(subject));
    diff_field(
        &mut diff,
        "description",
        &json!(old.description),
        &json!(description),
    );
    diff_field(&mut diff, "color", &json!(old.color), &json!(color));
    diff_field(
        &mut diff,
        "status_id",
        &json!(old.status_id),
        &json!(status_id),
    );
    diff_field(
        &mut diff,
        "assigned_to",
        &json!(old.assigned_to),
        &json!(assigned_to),
    );
    diff_field(
        &mut diff,
        "milestone_id",
        &json!(old.milestone_id),
        &json!(milestone_id),
    );
    diff_field(
        &mut diff,
        "start_date",
        &json!(old.start_date.map(|d| d.to_string())),
        &json!(start_date.map(|d| d.to_string())),
    );
    diff_field(
        &mut diff,
        "end_date",
        &json!(old.end_date.map(|d| d.to_string())),
        &json!(end_date.map(|d| d.to_string())),
    );

    match bl::update_epic(
        &client,
        ctx.project.id,
        id,
        old.version,
        &subject,
        &description,
        status_id,
        &color,
        assigned_to,
        milestone_id,
        start_date,
        end_date,
    )
    .await
    {
        Ok(UpdateOutcome::Updated(e)) => {
            if !diff.is_empty() {
                history::record(
                    &client,
                    ctx.project.id,
                    "epic",
                    e.id,
                    Some(ctx.actor_id),
                    &Value::Object(diff),
                )
                .await;
            }
            with_etag(StatusCode::OK, e.id, e.version, &e)
        }
        Ok(UpdateOutcome::NotFound) => not_found(&ctx.rid),
        Ok(UpdateOutcome::Conflict) => problem(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "Precondition Failed",
            None,
            &ctx.rid,
        ),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/epics/{id}`
pub async fn delete_epic(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    delete_entity(
        state,
        ctx,
        &params,
        &headers,
        "epics",
        "epic",
        Permission::EpicDelete,
    )
    .await
}

/// `POST /api/v1/projects/{project_id}/epics/{id}/move`
pub async fn move_epic(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<ReorderRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::EpicModify) {
        return r;
    }
    let Some(id) = id_param(&params) else {
        return not_found(&ctx.rid);
    };
    let req = match parse_create(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    let Ok(items) = bl::list_epics(&client, ctx.project.id).await else {
        return internal(&ctx.rid);
    };
    reorder(
        &mut client,
        "epics",
        ctx.project.id,
        id,
        req.before_id,
        req.after_id,
        items.iter().map(|i| (i.id, i.order)).collect(),
        &ctx.rid,
    )
    .await
}

// --------------------------------------------------------------------------
// bulk purge (project danger zone — hard, irreversible)
// --------------------------------------------------------------------------

/// `DELETE /api/v1/projects/{project_id}/issues` — hard-purge ALL issues in the
/// project (and their comments/history/attachments). Project-level destructive
/// action, gated on `ProjectModify`.
pub async fn purge_issues(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    match bl::purge_project_issues(&mut client, ctx.project.id).await {
        Ok((n, keys)) => {
            for k in &keys {
                auth.attachments.storage.delete(k).await.ok();
            }
            audit::record(
                &client,
                Some(ctx.actor_id),
                "project_issues_purged",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "project_id": ctx.project.id.to_string(), "deleted": n }),
            )
            .await;
            Json(json!({ "deleted": n })).into_response()
        }
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/epics` — hard-purge ALL epics in the
/// project. Issues are kept but detached (`epic_id` cleared). Gated on
/// `ProjectModify`.
pub async fn purge_epics(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    match bl::purge_project_epics(&mut client, ctx.project.id).await {
        Ok((n, keys)) => {
            for k in &keys {
                auth.attachments.storage.delete(k).await.ok();
            }
            audit::record(
                &client,
                Some(ctx.actor_id),
                "project_epics_purged",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "project_id": ctx.project.id.to_string(), "deleted": n }),
            )
            .await;
            Json(json!({ "deleted": n })).into_response()
        }
        Err(_) => internal(&ctx.rid),
    }
}

// ==========================================================================
// issues
// ==========================================================================

/// Validate an issue's optional associations: epic and parent must be in the
/// project (422); the milestone must be in the project (422) and not closed
/// (409). `None` for any is always allowed.
async fn validate_issue_associations(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    epic_id: Option<Uuid>,
    parent_id: Option<Uuid>,
    milestone_id: Option<Uuid>,
    rid: &str,
) -> Result<(), Response> {
    if let Some(eid) = epic_id {
        if !bl::epic_in_project(client, project_id, eid)
            .await
            .unwrap_or(false)
        {
            return Err(unprocessable(
                rid,
                "invalid_association",
                "epic is not in this project",
            ));
        }
    }
    if let Some(pid) = parent_id {
        if !bl::issue_in_project(client, project_id, pid)
            .await
            .unwrap_or(false)
        {
            return Err(unprocessable(
                rid,
                "invalid_association",
                "parent issue is not in this project",
            ));
        }
    }
    validate_milestone_assignment(client, project_id, milestone_id, rid).await
}

/// Build the DB write-set from a create request (borrows from `req`).
fn write_from_create(req: &CreateIssueRequest) -> bl::IssueWrite<'_> {
    bl::IssueWrite {
        subject: &req.subject,
        description: &req.description,
        status_id: req.status_id,
        type_id: req.type_id,
        priority_id: req.priority_id,
        size_id: req.size_id,
        epic_id: req.epic_id,
        parent_id: req.parent_id,
        milestone_id: req.milestone_id,
        assigned_to: req.assigned_to,
        category: req
            .category
            .map(intellipilot_core::backlog::IssueCategory::as_str),
        customer_id: req.customer_id,
        start_date: req.start_date,
        due_date: req.due_date,
        resolution: req
            .resolution
            .map(intellipilot_core::backlog::Resolution::as_str),
        release_version_id: req.release_version_id,
        release_text: req.release_text.as_deref(),
    }
}

/// Validate the fix-version (mutually-exclusive) plus the optional customer /
/// release-version references against the project.
async fn validate_issue_extras(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    customer_id: Option<Uuid>,
    release_version_id: Option<Uuid>,
    release_text: Option<&str>,
    rid: &str,
) -> Result<(), Response> {
    let has_text = release_text.is_some_and(|t| !t.trim().is_empty());
    if release_version_id.is_some() && has_text {
        return Err(unprocessable(
            rid,
            "invalid_fix_version",
            "set either release_version_id or release_text, not both",
        ));
    }
    if let Some(cid) = customer_id
        && !custdb::in_project(client, project_id, cid)
            .await
            .unwrap_or(false)
    {
        return Err(unprocessable(
            rid,
            "invalid_association",
            "customer not found in this project",
        ));
    }
    if let Some(vid) = release_version_id
        && !rvdb::in_project(client, project_id, vid)
            .await
            .unwrap_or(false)
    {
        return Err(unprocessable(
            rid,
            "invalid_association",
            "release version not found in this project",
        ));
    }
    Ok(())
}

pub async fn create_issue(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    body: Result<Json<CreateIssueRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueCreate) {
        return r;
    }
    let req = match parse_create(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    // Labels/components must belong to this project.
    if let Err(r) = validate_label_component_ids(
        &client,
        ctx.project.id,
        &req.labels,
        &req.components,
        &ctx.rid,
    )
    .await
    {
        return r;
    }
    if let Err(r) = validate_issue_associations(
        &client,
        ctx.project.id,
        req.epic_id,
        req.parent_id,
        req.milestone_id,
        &ctx.rid,
    )
    .await
    {
        return r;
    }
    if let Err(r) = validate_issue_extras(
        &client,
        ctx.project.id,
        req.customer_id,
        req.release_version_id,
        req.release_text.as_deref(),
        &ctx.rid,
    )
    .await
    {
        return r;
    }
    let key = idem_key(&headers);
    let path = format!("/projects/{}/issues", ctx.project.id);
    if let Some(r) = replay(auth, &client, ctx.actor_id, &key, "POST", &path).await {
        return r;
    }
    let created = bl::create_issue(
        &client,
        ctx.project.id,
        ctx.actor_id,
        &write_from_create(&req),
    )
    .await;
    let i = match created {
        Ok(i) => i,
        Err(_) => return internal(&ctx.rid),
    };
    if bl::set_issue_labels(&mut client, i.id, &req.labels)
        .await
        .is_err()
        || bl::set_issue_components(&mut client, i.id, &req.components)
            .await
            .is_err()
    {
        return internal(&ctx.rid);
    }
    let full = match bl::get_issue(&client, ctx.project.id, i.id).await {
        Ok(Some(f)) => f,
        _ => return internal(&ctx.rid),
    };
    history::record(
        &client,
        ctx.project.id,
        "issue",
        full.id,
        Some(ctx.actor_id),
        &json!({"created": true}),
    )
    .await;
    let body = serde_json::to_value(&full).unwrap_or(Value::Null);
    remember(
        &client,
        ctx.actor_id,
        &key,
        "POST",
        &path,
        StatusCode::CREATED,
        &body,
    )
    .await;
    with_etag(StatusCode::CREATED, full.id, full.version, &full)
}

/// `POST /api/v1/projects/{project_id}/issues/bulk`
pub async fn bulk_create_issues(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<BulkCreateIssuesRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueCreate) {
        return r;
    }
    let req = match parse_create(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    // Validate associations + labels/components up front so the batch is
    // all-or-nothing.
    for item in &req.items {
        if let Err(r) = validate_label_component_ids(
            &client,
            ctx.project.id,
            &item.labels,
            &item.components,
            &ctx.rid,
        )
        .await
        {
            return r;
        }
        if let Err(r) = validate_issue_associations(
            &client,
            ctx.project.id,
            item.epic_id,
            item.parent_id,
            item.milestone_id,
            &ctx.rid,
        )
        .await
        {
            return r;
        }
        if let Err(r) = validate_issue_extras(
            &client,
            ctx.project.id,
            item.customer_id,
            item.release_version_id,
            item.release_text.as_deref(),
            &ctx.rid,
        )
        .await
        {
            return r;
        }
    }
    let mut created = Vec::with_capacity(req.items.len());
    for item in &req.items {
        let i = match bl::create_issue(
            &client,
            ctx.project.id,
            ctx.actor_id,
            &write_from_create(item),
        )
        .await
        {
            Ok(i) => i,
            Err(_) => return internal(&ctx.rid),
        };
        if bl::set_issue_labels(&mut client, i.id, &item.labels)
            .await
            .is_err()
            || bl::set_issue_components(&mut client, i.id, &item.components)
                .await
                .is_err()
        {
            return internal(&ctx.rid);
        }
        history::record(
            &client,
            ctx.project.id,
            "issue",
            i.id,
            Some(ctx.actor_id),
            &json!({"created": true}),
        )
        .await;
        match bl::get_issue(&client, ctx.project.id, i.id).await {
            Ok(Some(f)) => created.push(f),
            _ => return internal(&ctx.rid),
        }
    }
    (StatusCode::CREATED, Json(json!({ "issues": created }))).into_response()
}

/// `POST /api/v1/projects/{project_id}/issues/{id}/move`
pub async fn move_issue(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<ReorderRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueModify) {
        return r;
    }
    let Some(id) = id_param(&params) else {
        return not_found(&ctx.rid);
    };
    let req = match parse_create(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    let Ok(items) = bl::list_issues(&client, ctx.project.id).await else {
        return internal(&ctx.rid);
    };
    reorder(
        &mut client,
        "issues",
        ctx.project.id,
        id,
        req.before_id,
        req.after_id,
        items.iter().map(|i| (i.id, i.order)).collect(),
        &ctx.rid,
    )
    .await
}

/// Validate an issue→milestone assignment: the milestone must be in the
/// project (422) and not closed (409). A `None` assignment is always allowed.
async fn validate_milestone_assignment(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    milestone_id: Option<Uuid>,
    rid: &str,
) -> Result<(), Response> {
    let Some(mid) = milestone_id else {
        return Ok(());
    };
    if !msdb::in_project(client, project_id, mid)
        .await
        .unwrap_or(false)
    {
        return Err(unprocessable(
            rid,
            "invalid_association",
            "milestone is not in this project",
        ));
    }
    if msdb::is_closed(client, project_id, mid)
        .await
        .unwrap_or(false)
    {
        return Err(problem(
            StatusCode::CONFLICT,
            "milestone_closed",
            "Milestone closed",
            Some("cannot assign an issue to a closed milestone".to_owned()),
            rid,
        ));
    }
    Ok(())
}

/// Validate that all label/component ids belong to the project (422 otherwise).
async fn validate_label_component_ids(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    labels: &[Uuid],
    components: &[Uuid],
    rid: &str,
) -> Result<(), Response> {
    if !ldb::all_in_project(client, project_id, labels)
        .await
        .unwrap_or(false)
    {
        return Err(unprocessable(
            rid,
            "invalid_label",
            "a label is not in this project",
        ));
    }
    if !compdb::all_in_project(client, project_id, components)
        .await
        .unwrap_or(false)
    {
        return Err(unprocessable(
            rid,
            "invalid_component",
            "a component is not in this project",
        ));
    }
    Ok(())
}

pub async fn list_issues(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::IssueView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bl::list_issues(&client, ctx.project.id).await {
        Ok(items) => Json(json!({ "issues": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

pub async fn get_issue(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueView) {
        return r;
    }
    let Some(id) = id_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bl::get_issue(&client, ctx.project.id, id).await {
        Ok(Some(e)) => with_etag(StatusCode::OK, e.id, e.version, &e),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

pub async fn update_issue(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: HeaderMap,
    body: Result<Json<UpdateIssueRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueModify) {
        return r;
    }
    let Some(id) = id_param(&params) else {
        return not_found(&ctx.rid);
    };
    let patch = match parse_patch(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&ctx.rid),
    };
    let Ok(Some(old)) = bl::get_issue(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    if let Err(r) = check_if_match(&headers, &etag(old.id, old.version), &ctx.rid) {
        return r;
    }
    // Validate any label/component replacement up front.
    let new_labels = patch.labels.clone();
    let new_components = patch.components.clone();
    if let Err(r) = validate_label_component_ids(
        &client,
        ctx.project.id,
        new_labels.as_deref().unwrap_or(&[]),
        new_components.as_deref().unwrap_or(&[]),
        &ctx.rid,
    )
    .await
    {
        return r;
    }

    let subject = patch.subject.unwrap_or(old.subject.clone());
    let description = patch.description.unwrap_or(old.description.clone());
    let status_id = patch.status_id.unwrap_or(old.status_id);
    let type_id = patch.type_id.unwrap_or(old.type_id);
    let priority_id = patch.priority_id.unwrap_or(old.priority_id);
    let size_id = patch.size_id.unwrap_or(old.size_id);
    let epic_id = patch.epic_id.unwrap_or(old.epic_id);
    let parent_id = patch.parent_id.unwrap_or(old.parent_id);
    let milestone_id = patch.milestone_id.unwrap_or(old.milestone_id);
    let assigned_to = patch.assigned_to.unwrap_or(old.assigned_to);
    let category = patch.category.unwrap_or(old.category);
    let customer_id = patch.customer_id.unwrap_or(old.customer_id);
    // Dates: absent leaves unchanged (no clear), matching milestones.
    let start_date = patch.start_date.or(old.start_date);
    let due_date = patch.due_date.or(old.due_date);
    let resolution = patch.resolution.unwrap_or(old.resolution);
    let release_version_id = patch.release_version_id.unwrap_or(old.release_version_id);
    let release_text = patch.release_text.unwrap_or(old.release_text.clone());

    // Validate only associations that actually changed.
    let epic_changed = epic_id != old.epic_id;
    let parent_changed = parent_id != old.parent_id;
    let milestone_changed = milestone_id != old.milestone_id;
    if epic_changed || parent_changed || milestone_changed {
        if let Err(r) = validate_issue_associations(
            &client,
            ctx.project.id,
            if epic_changed { epic_id } else { None },
            if parent_changed { parent_id } else { None },
            if milestone_changed {
                milestone_id
            } else {
                None
            },
            &ctx.rid,
        )
        .await
        {
            return r;
        }
    }
    // An issue cannot be its own parent.
    if parent_id == Some(id) {
        return unprocessable(
            &ctx.rid,
            "invalid_association",
            "an issue cannot be its own parent",
        );
    }
    if let Err(r) = validate_issue_extras(
        &client,
        ctx.project.id,
        customer_id,
        release_version_id,
        release_text.as_deref(),
        &ctx.rid,
    )
    .await
    {
        return r;
    }

    let date_str = |d: Option<time::Date>| json!(d.map(|v| v.to_string()));
    let mut diff = serde_json::Map::new();
    diff_field(&mut diff, "subject", &json!(old.subject), &json!(subject));
    diff_field(
        &mut diff,
        "description",
        &json!(old.description),
        &json!(description),
    );
    diff_field(
        &mut diff,
        "status_id",
        &json!(old.status_id),
        &json!(status_id),
    );
    diff_field(&mut diff, "type_id", &json!(old.type_id), &json!(type_id));
    diff_field(
        &mut diff,
        "priority_id",
        &json!(old.priority_id),
        &json!(priority_id),
    );
    diff_field(&mut diff, "size_id", &json!(old.size_id), &json!(size_id));
    diff_field(&mut diff, "epic_id", &json!(old.epic_id), &json!(epic_id));
    diff_field(
        &mut diff,
        "parent_id",
        &json!(old.parent_id),
        &json!(parent_id),
    );
    diff_field(
        &mut diff,
        "milestone_id",
        &json!(old.milestone_id),
        &json!(milestone_id),
    );
    diff_field(
        &mut diff,
        "assigned_to",
        &json!(old.assigned_to),
        &json!(assigned_to),
    );
    diff_field(
        &mut diff,
        "category",
        &json!(old.category),
        &json!(category),
    );
    diff_field(
        &mut diff,
        "customer_id",
        &json!(old.customer_id),
        &json!(customer_id),
    );
    diff_field(
        &mut diff,
        "start_date",
        &date_str(old.start_date),
        &date_str(start_date),
    );
    diff_field(
        &mut diff,
        "due_date",
        &date_str(old.due_date),
        &date_str(due_date),
    );
    diff_field(
        &mut diff,
        "resolution",
        &json!(old.resolution),
        &json!(resolution),
    );
    diff_field(
        &mut diff,
        "release_version_id",
        &json!(old.release_version_id),
        &json!(release_version_id),
    );
    diff_field(
        &mut diff,
        "release_text",
        &json!(old.release_text),
        &json!(release_text),
    );

    let write = bl::IssueWrite {
        subject: &subject,
        description: &description,
        status_id,
        type_id,
        priority_id,
        size_id,
        epic_id,
        parent_id,
        milestone_id,
        assigned_to,
        category: category.map(intellipilot_core::backlog::IssueCategory::as_str),
        customer_id,
        start_date,
        due_date,
        resolution: resolution.map(intellipilot_core::backlog::Resolution::as_str),
        release_version_id,
        release_text: release_text.as_deref(),
    };
    match bl::update_issue(&client, ctx.project.id, id, old.version, &write).await {
        Ok(UpdateOutcome::Updated(e)) => {
            // Apply label/component replacements if the patch included them.
            if let Some(labels) = &new_labels {
                if bl::set_issue_labels(&mut client, e.id, labels)
                    .await
                    .is_err()
                {
                    return internal(&ctx.rid);
                }
            }
            if let Some(components) = &new_components {
                if bl::set_issue_components(&mut client, e.id, components)
                    .await
                    .is_err()
                {
                    return internal(&ctx.rid);
                }
            }
            if !diff.is_empty() {
                history::record(
                    &client,
                    ctx.project.id,
                    "issue",
                    e.id,
                    Some(ctx.actor_id),
                    &Value::Object(diff),
                )
                .await;
            }
            let full = match bl::get_issue(&client, ctx.project.id, e.id).await {
                Ok(Some(f)) => f,
                _ => return internal(&ctx.rid),
            };
            with_etag(StatusCode::OK, full.id, full.version, &full)
        }
        Ok(UpdateOutcome::NotFound) => not_found(&ctx.rid),
        Ok(UpdateOutcome::Conflict) => problem(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "Precondition Failed",
            None,
            &ctx.rid,
        ),
        Err(_) => internal(&ctx.rid),
    }
}

pub async fn delete_issue(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    delete_entity(
        state,
        ctx,
        &params,
        &headers,
        "issues",
        "issue",
        Permission::IssueDelete,
    )
    .await
}

// ==========================================================================
// comments (polymorphic)
// ==========================================================================

/// `GET /api/v1/projects/{project_id}/{entity}/{id}/comments`
pub async fn list_comments(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let Some((kind, id)) = entity_target(&params) else {
        return not_found(&ctx.rid);
    };
    if let Err(r) = ctx.require(view_perm(kind)) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match cdb::list(&client, kind.as_str(), id).await {
        Ok(items) => Json(json!({ "comments": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/{entity}/{id}/comments`
pub async fn create_comment(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<CommentRequest>, JsonRejection>,
) -> Response {
    let Some((kind, id)) = entity_target(&params) else {
        return not_found(&ctx.rid);
    };
    if let Err(r) = ctx.require(Permission::CommentCreate) {
        return r;
    }
    let req = match parse_create(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let html = render_markdown(&req.body);
    match cdb::create(
        &client,
        ctx.project.id,
        kind.as_str(),
        id,
        ctx.actor_id,
        &req.body,
        &html,
    )
    .await
    {
        Ok(c) => (StatusCode::CREATED, Json(c)).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/{entity}/{id}/comments/{comment_id}`
pub async fn update_comment(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<CommentRequest>, JsonRejection>,
) -> Response {
    let Some(comment_id) = params
        .get("comment_id")
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return not_found(&ctx.rid);
    };
    let req = match parse_create(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some((author, created))) = cdb::meta(&client, comment_id).await else {
        return not_found(&ctx.rid);
    };
    if let Err(r) = authorize_comment_mutation(&ctx, author, created) {
        return r;
    }
    let html = render_markdown(&req.body);
    match cdb::update(&client, comment_id, &req.body, &html).await {
        Ok(Some(c)) => Json(c).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/{entity}/{id}/comments/{comment_id}`
pub async fn delete_comment(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let Some(comment_id) = params
        .get("comment_id")
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some((author, created))) = cdb::meta(&client, comment_id).await else {
        return not_found(&ctx.rid);
    };
    if let Err(r) = authorize_comment_mutation(&ctx, author, created) {
        return r;
    }
    match cdb::soft_delete(&client, comment_id).await {
        Ok(true) => {
            // Best-effort: tidy up any attachments hanging off the comment.
            if adb::soft_delete_for_target(&client, "comment", comment_id)
                .await
                .is_err()
            {
                tracing::warn!(%comment_id, "failed to soft-delete comment attachments");
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/{entity}/{id}/history`
pub async fn list_history(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let Some((kind, id)) = entity_target(&params) else {
        return not_found(&ctx.rid);
    };
    if let Err(r) = ctx.require(view_perm(kind)) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match history::list(&client, kind.as_str(), id).await {
        Ok(entries) => Json(json!({ "history": entries })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/resolve/{ref}`
pub async fn resolve_ref(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(reference) = params.get("ref").and_then(|s| s.parse::<i64>().ok()) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match bl::resolve_ref(&client, ctx.project.id, reference).await {
        Ok(Some((kind, id))) => {
            Json(json!({ "kind": kind, "id": id, "ref": reference })).into_response()
        }
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// --------------------------------------------------------------------------
// shared helpers
// --------------------------------------------------------------------------

fn id_param(params: &HashMap<String, String>) -> Option<Uuid> {
    params.get("id").and_then(|s| Uuid::parse_str(s).ok())
}

fn entity_target(params: &HashMap<String, String>) -> Option<(EntityKind, Uuid)> {
    let kind = params.get("entity").and_then(|s| match s.as_str() {
        "epics" => Some(EntityKind::Epic),
        "issues" => Some(EntityKind::Issue),
        _ => None,
    })?;
    let id = id_param(params)?;
    Some((kind, id))
}

fn view_perm(kind: EntityKind) -> Permission {
    match kind {
        EntityKind::Epic => Permission::EpicView,
        EntityKind::Issue => Permission::IssueView,
    }
}

/// Comment edit/delete: the author within the 24h window, or anyone with
/// `comment.moderate`.
fn authorize_comment_mutation(
    ctx: &ProjectContext,
    author: Option<Uuid>,
    created: OffsetDateTime,
) -> Result<(), Response> {
    let is_moderator = ctx
        .access
        .as_ref()
        .is_some_and(|a| a.has(Permission::CommentModerate));
    if is_moderator {
        return Ok(());
    }
    let is_author = author == Some(ctx.actor_id);
    let within_window =
        OffsetDateTime::now_utc() - created <= TimeDuration::seconds(COMMENT_EDIT_WINDOW_SECS);
    if is_author && within_window {
        Ok(())
    } else {
        Err(problem(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
            None,
            &ctx.rid,
        ))
    }
}

/// Render + sanitize comment markdown (comrak + ammonia).
fn render_markdown(body: &str) -> String {
    crate::markdown::render(body)
}

async fn reorder(
    client: &mut deadpool_postgres::Client,
    table: &str,
    project_id: Uuid,
    id: Uuid,
    before_id: Option<Uuid>,
    after_id: Option<Uuid>,
    items: Vec<(Uuid, f64)>,
    rid: &str,
) -> Response {
    if !items.iter().any(|(i, _)| *i == id) {
        return not_found(rid);
    }
    let before_order = before_id.and_then(|b| items.iter().find(|(i, _)| *i == b).map(|(_, o)| *o));
    let after_order = after_id.and_then(|a| items.iter().find(|(i, _)| *i == a).map(|(_, o)| *o));

    // Target order for renormalization: current order, move `id` after
    // before_id (or before after_id, or to the end).
    let mut order: Vec<Uuid> = items.iter().map(|(i, _)| *i).filter(|x| *x != id).collect();
    let pos = if let Some(b) = before_id {
        order
            .iter()
            .position(|x| *x == b)
            .map_or(order.len(), |p| p.saturating_add(1))
    } else if let Some(a) = after_id {
        order.iter().position(|x| *x == a).unwrap_or(0)
    } else {
        order.len()
    };
    order.insert(pos.min(order.len()), id);

    match bl::set_order(
        client,
        table,
        project_id,
        id,
        before_order,
        after_order,
        order,
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(rid),
        Err(_) => internal(rid),
    }
}

/// Shared delete: requires the entity's delete permission; if the entity is in
/// a closed status, additionally requires admin. Soft-deletes with grace.
async fn delete_entity(
    state: AppState,
    ctx: ProjectContext,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
    table: &str,
    kind: &str,
    perm: Permission,
) -> Response {
    if let Err(r) = ctx.require(perm) {
        return r;
    }
    let Some(id) = id_param(params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };

    // Closed entities may only be deleted by admins.
    let closed = bl::is_in_closed_status(&client, table, ctx.project.id, id)
        .await
        .unwrap_or(false);
    if closed && !ctx.access.as_ref().is_some_and(|a| a.is_admin) {
        return problem(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
            Some("only admins may delete closed items".to_owned()),
            &ctx.rid,
        );
    }

    let grace = OffsetDateTime::now_utc() + TimeDuration::days(ERASE_GRACE_DAYS);
    match bl::soft_delete(&client, table, ctx.project.id, id, grace).await {
        Ok(true) => {
            history::record(
                &client,
                ctx.project.id,
                kind,
                id,
                Some(ctx.actor_id),
                &json!({"deleted": true}),
            )
            .await;
            crate::backlog::audit_delete(&client, &ctx, headers, kind, id).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

async fn audit_delete(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    headers: &HeaderMap,
    kind: &str,
    id: Uuid,
) {
    intellipilot_db::audit::record(
        client,
        Some(ctx.actor_id),
        "entity_deleted",
        Some(client_ip(headers)),
        Some(&user_agent(headers)),
        &json!({ "kind": kind, "id": id.to_string() }),
    )
    .await;
}
