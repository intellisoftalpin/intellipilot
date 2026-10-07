//! Milestone endpoints: CRUD, complete/reopen, epics, board, and stats.
//!
//! Two invariants shape this module:
//!
//! * **Membership is structural.** Issues belong to epics, epics belong to
//!   milestones. Nothing here (or anywhere else) lets a client point an issue
//!   at a milestone directly — a database trigger owns that column.
//! * **The business release date is need-to-know.** It is stripped from every
//!   response for callers without `milestone.business_release.view`, so an
//!   absent key means either "unset" or "not yours to see".
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::arithmetic_side_effects
)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::backlog::etag;
use intellipilot_core::milestone::Milestone;
use intellipilot_core::perms::Permission;
use intellipilot_core::taxonomy::TaxonomyKind;
use intellipilot_db::backlog::UpdateOutcome;
use intellipilot_db::milestones::MilestonePatch;
use intellipilot_db::{backlog as bl, milestones as msdb, taxonomy as taxdb};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{Caller, request_id};
use crate::backlog::{check_if_match, with_etag};
use crate::dto::{CreateMilestoneRequest, SetMilestoneEpicsRequest, UpdateMilestoneRequest};
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
fn invalid_dates(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_dates",
        "Invalid dates",
        Some(detail.to_owned()),
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

/// `?state=` on the milestone listings: `open`, `completed`, or `all`
/// (default — what clients predating the filter expect).
#[derive(Debug, Default, Deserialize)]
pub struct StateQuery {
    #[serde(default)]
    pub state: Option<String>,
}

impl StateQuery {
    /// The `closed` filter this query asks for: `Ok(None)` for every
    /// milestone, `Err(())` for an unknown value.
    fn closed(&self) -> Result<Option<bool>, ()> {
        match self.state.as_deref() {
            None | Some("all") => Ok(None),
            Some("open") => Ok(Some(false)),
            Some("completed") => Ok(Some(true)),
            Some(_) => Err(()),
        }
    }
}

fn invalid_state(rid: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_state",
        "Invalid state filter",
        Some("state must be one of: open, completed, all".to_owned()),
        rid,
    )
}

fn mid_param(params: &HashMap<String, String>) -> Option<Uuid> {
    params
        .get("milestone_id")
        .and_then(|s| Uuid::parse_str(s).ok())
}

// ---------------------------------------------------------------------------
// business release visibility
// ---------------------------------------------------------------------------

/// Serialize a milestone, dropping `business_release_date` when the caller may
/// not see it. Removing the key (rather than nulling it) means an unauthorized
/// caller cannot tell a set date from an unset one.
fn view(m: &Milestone, may_see_business_release: bool) -> Value {
    let mut v = serde_json::to_value(m).unwrap_or(Value::Null);
    if !may_see_business_release && let Value::Object(ref mut map) = v {
        map.remove("business_release_date");
    }
    v
}

// ---------------------------------------------------------------------------
// date rules
// ---------------------------------------------------------------------------

/// `end_date >= start_date` when both are present; otherwise always ok.
fn dates_ok(start: Option<time::Date>, end: Option<time::Date>) -> bool {
    match (start, end) {
        (Some(s), Some(e)) => e >= s,
        _ => true,
    }
}

/// Explanation returned when the business release does not trail a technical
/// one. Shared so create and update cannot drift apart.
/// Explanation returned when the actual end precedes the actual start. Mirrors
/// the V029 CHECK.
const ACTUAL_RANGE_RULE: &str = "actual_end_date must be on or after actual_start_date";

const BUSINESS_RELEASE_RULE: &str = "business_release_date must be after the technical end date \
     (actual_end_date when set, otherwise end_date)";

/// The technical end that really happened: the actual date when recorded,
/// otherwise the plan. Everything downstream — the business-release rule,
/// ordering, the gantt — keys off this rather than off `end_date` alone.
const fn effective_end(
    planned: Option<time::Date>,
    actual: Option<time::Date>,
) -> Option<time::Date> {
    match actual {
        Some(a) => Some(a),
        None => planned,
    }
}

/// A business release only exists relative to a technical one: it needs an end
/// date and must land strictly after it. Mirrors the table CHECK, so the user
/// gets a 422 rather than a 500 from the constraint.
fn business_release_ok(end: Option<time::Date>, business: Option<time::Date>) -> bool {
    business.is_none_or(|b| end.is_some_and(|e| b > e))
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
    if req.business_release_date.is_some()
        && let Err(r) = ctx.require(Permission::MilestoneBusinessReleaseModify)
    {
        return r;
    }
    if !dates_ok(req.start_date, req.end_date) {
        return invalid_dates(&ctx.rid, "end_date must be on or after start_date");
    }
    if !dates_ok(req.actual_start_date, req.actual_end_date) {
        return invalid_dates(&ctx.rid, ACTUAL_RANGE_RULE);
    }
    if !business_release_ok(
        effective_end(req.end_date, req.actual_end_date),
        req.business_release_date,
    ) {
        return invalid_dates(&ctx.rid, BUSINESS_RELEASE_RULE);
    }
    let slug = req.slug.clone().unwrap_or_else(|| slugify(&req.name));
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let new = msdb::MilestoneNew {
        name: &req.name,
        slug: &slug,
        description: &req.description,
        start_date: req.start_date,
        actual_start_date: req.actual_start_date,
        end_date: req.end_date,
        actual_end_date: req.actual_end_date,
        business_release_date: req.business_release_date,
    };
    match msdb::create(&client, ctx.project.id, &new).await {
        Ok(m) => {
            let may = ctx.has(Permission::MilestoneBusinessReleaseView);
            with_etag(StatusCode::CREATED, m.id, m.version, &view(&m, may))
        }
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

/// `GET /api/v1/projects/{project_id}/milestones?state=open|completed|all`
///
/// `completed_count` always counts every completed milestone, whatever
/// `state` filtered out, so a collapsed "Completed" band can show its size
/// before it is loaded.
pub async fn list(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Query(q): Query<StateQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneView) {
        return r;
    }
    let Ok(closed) = q.closed() else {
        return invalid_state(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(completed_count) = msdb::completed_count(&client, ctx.project.id).await else {
        return internal(&ctx.rid);
    };
    match msdb::list_filtered(&client, ctx.project.id, closed).await {
        Ok(items) => {
            let may = ctx.has(Permission::MilestoneBusinessReleaseView);
            let out: Vec<Value> = items.iter().map(|m| view(m, may)).collect();
            Json(json!({ "milestones": out, "completed_count": completed_count })).into_response()
        }
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/milestones?state=open|completed|all`
///
/// Every milestone the caller may see, across all of their projects: those
/// where they hold `milestone.view` (superadmins: every project; app tokens:
/// their scoped projects with a granted `milestone.view`). Each row carries
/// its project's id, name, prefix and colour plus task/epic roll-ups, so the
/// global timeline needs no per-project fetches. The business release date is
/// stripped per project, exactly as on the project endpoints.
/// `completed_count` counts completed milestones across those same projects,
/// whatever `state` filtered out.
pub async fn list_all(
    State(state): State<AppState>,
    headers: HeaderMap,
    caller: Caller,
    Query(q): Query<StateQuery>,
) -> Response {
    let rid = request_id(&headers);
    let Ok(closed) = q.closed() else {
        return invalid_state(&rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    // (project, may it see business release dates)
    let mut visible: Vec<(intellipilot_core::project::Project, bool)> = Vec::new();
    match caller {
        Caller::User(user_id) => {
            let is_superadmin = intellipilot_db::users::is_active_superadmin(&client, user_id)
                .await
                .unwrap_or(false);
            let listing = if is_superadmin {
                intellipilot_db::projects::list_all(&client).await
            } else {
                intellipilot_db::projects::list_for_member(&client, user_id).await
            };
            let Ok(projects) = listing else {
                return internal(&rid);
            };
            for p in projects {
                if is_superadmin {
                    visible.push((p, true));
                    continue;
                }
                let Ok(access) = intellipilot_db::memberships::access(&client, p.id, user_id).await
                else {
                    return internal(&rid);
                };
                if let Some(a) = access
                    && a.has(Permission::MilestoneView)
                {
                    let may = a.has(Permission::MilestoneBusinessReleaseView);
                    visible.push((p, may));
                }
            }
        }
        Caller::AppToken(tok) => {
            if tok.permissions.contains(&Permission::MilestoneView) {
                let Ok(projects) =
                    intellipilot_db::projects::list_by_ids(&client, &tok.project_ids).await
                else {
                    return internal(&rid);
                };
                let may = tok
                    .permissions
                    .contains(&Permission::MilestoneBusinessReleaseView);
                visible.extend(projects.into_iter().map(|p| (p, may)));
            }
        }
    }

    let ids: Vec<Uuid> = visible.iter().map(|(p, _)| p.id).collect();
    let Ok(rows) = msdb::list_across(&client, &ids, closed).await else {
        return internal(&rid);
    };
    let Ok(completed_count) = msdb::completed_count_across(&client, &ids).await else {
        return internal(&rid);
    };
    let by_id: HashMap<Uuid, &(intellipilot_core::project::Project, bool)> =
        visible.iter().map(|v| (v.0.id, v)).collect();
    let mut out: Vec<Value> = Vec::with_capacity(rows.len());
    for r in &rows {
        let Some((project, may)) = by_id.get(&r.milestone.project_id).copied() else {
            continue;
        };
        let mut v = view(&r.milestone, *may);
        if let Value::Object(ref mut map) = v {
            map.insert(
                "project".to_owned(),
                json!({
                    "id": project.id,
                    "name": project.name,
                    "prefix": project.issue_prefix,
                    "color": project.color,
                }),
            );
            map.insert("task_total".to_owned(), json!(r.task_total));
            map.insert("task_closed".to_owned(), json!(r.task_closed));
            map.insert("epic_count".to_owned(), json!(r.epic_count));
        }
        out.push(v);
    }
    Json(json!({ "milestones": out, "completed_count": completed_count })).into_response()
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
        Ok(Some(m)) => {
            let may = ctx.has(Permission::MilestoneBusinessReleaseView);
            with_etag(StatusCode::OK, m.id, m.version, &view(&m, may))
        }
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/milestones/{milestone_id}`
///
/// Requires `If-Match` with the milestone's current ETag: the detail sidebar
/// edits every field at once, so a lost update here would be a silent one.
pub async fn update(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: HeaderMap,
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
    if req.business_release_date.is_some()
        && let Err(r) = ctx.require(Permission::MilestoneBusinessReleaseModify)
    {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some(existing)) = msdb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    if let Err(r) = check_if_match(&headers, &etag(existing.id, existing.version), &ctx.rid) {
        return r;
    }

    // Resolve the effective row the patch would produce, then validate it as a
    // whole — a rule that spans fields cannot be checked field by field.
    let start = req.start_date.unwrap_or(existing.start_date);
    let actual_start = req.actual_start_date.unwrap_or(existing.actual_start_date);
    let end = req.end_date.unwrap_or(existing.end_date);
    let actual = req.actual_end_date.unwrap_or(existing.actual_end_date);
    let effective = effective_end(end, actual);
    // Losing every technical end date clears the business release with it
    // (mirrored in the UPDATE statement), so validate against that outcome.
    let business = if effective.is_none() {
        None
    } else {
        req.business_release_date
            .unwrap_or(existing.business_release_date)
    };
    if !dates_ok(start, end) {
        return invalid_dates(&ctx.rid, "end_date must be on or after start_date");
    }
    // An actual end before the start would draw a bar running backwards.
    if !dates_ok(start, actual) {
        return invalid_dates(&ctx.rid, "actual_end_date must be on or after start_date");
    }
    if !dates_ok(actual_start, actual) {
        return invalid_dates(&ctx.rid, ACTUAL_RANGE_RULE);
    }
    if !business_release_ok(effective, business) {
        return invalid_dates(&ctx.rid, BUSINESS_RELEASE_RULE);
    }

    let patch = MilestonePatch {
        name: req.name.as_deref(),
        description: req.description.as_deref(),
        start_date: req.start_date,
        actual_start_date: req.actual_start_date,
        end_date: req.end_date,
        actual_end_date: req.actual_end_date,
        business_release_date: req.business_release_date,
    };
    match msdb::update(&client, ctx.project.id, id, existing.version, &patch).await {
        Ok(UpdateOutcome::Updated(m)) => {
            let may = ctx.has(Permission::MilestoneBusinessReleaseView);
            with_etag(StatusCode::OK, m.id, m.version, &view(&m, may))
        }
        Ok(UpdateOutcome::NotFound) => not_found(&ctx.rid),
        Ok(UpdateOutcome::Conflict) => problem(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "Precondition Failed",
            Some("milestone changed since it was loaded; reload and retry".to_owned()),
            &ctx.rid,
        ),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/milestones/{milestone_id}/close` —
/// mark the milestone completed. Idempotent.
pub async fn close(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    set_completed(state, ctx, &params, true).await
}

/// `POST /api/v1/projects/{project_id}/milestones/{milestone_id}/reopen` —
/// move a completed milestone back to in progress. Idempotent.
pub async fn reopen(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    set_completed(state, ctx, &params, false).await
}

async fn set_completed(
    state: AppState,
    ctx: ProjectContext,
    params: &HashMap<String, String>,
    completed: bool,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneModify) {
        return r;
    }
    let Some(id) = mid_param(params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let outcome = if completed {
        msdb::close(&client, ctx.project.id, id).await
    } else {
        msdb::reopen(&client, ctx.project.id, id).await
    };
    match outcome {
        Ok(Some(m)) => {
            let may = ctx.has(Permission::MilestoneBusinessReleaseView);
            with_etag(StatusCode::OK, m.id, m.version, &view(&m, may))
        }
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/milestones/{milestone_id}`
///
/// Refused while epics still compose the milestone (409): deleting would
/// detach them silently, and through the epic→issue cascade would strip the
/// milestone off every issue under them.
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
    match msdb::has_epics(&client, ctx.project.id, id).await {
        Ok(true) => {
            return problem(
                StatusCode::CONFLICT,
                "milestone_has_epics",
                "Milestone not empty",
                Some("remove every epic from the milestone before deleting it".to_owned()),
                &ctx.rid,
            );
        }
        Ok(false) => {}
        Err(_) => return internal(&ctx.rid),
    }
    match msdb::soft_delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/milestones/{milestone_id}/epics` —
/// the epics composing this milestone, each with the task counts backing its
/// readiness ring.
pub async fn epics(
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
    match bl::epics_in_milestone(&client, ctx.project.id, id).await {
        Ok(items) => Json(json!({ "epics": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/milestones/{milestone_id}/board`
///
/// Columns are the project's issue statuses; each column lists the milestone's
/// issues in that status, each with its sub-tasks. Issues with no status fall
/// into a trailing `status: null` column.
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
    // Trailing column for issues with no status.
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

/// `PUT /api/v1/projects/{project_id}/milestones/{milestone_id}/epics` —
/// replace the set of epics belonging to this milestone.
pub async fn set_epics(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<SetMilestoneEpicsRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MilestoneModify) {
        return r;
    }
    let Some(id) = mid_param(&params) else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body::<SetMilestoneEpicsRequest>(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
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
    // Adding scope to a completed milestone is refused, same as on the epic
    // itself. Detaching is always allowed, so an empty set still empties a
    // completed milestone (which is how it becomes deletable).
    if !req.epic_ids.is_empty()
        && msdb::is_closed(&client, ctx.project.id, id)
            .await
            .unwrap_or(false)
    {
        return problem(
            StatusCode::CONFLICT,
            "milestone_closed",
            "Milestone completed",
            Some("cannot add an epic to a completed milestone".to_owned()),
            &ctx.rid,
        );
    }
    match bl::set_milestone_epics(&client, ctx.project.id, id, &req.epic_ids).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal(&ctx.rid),
    }
}
