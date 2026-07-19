//! Time-tracking HTTP handlers.
//!
//! Three surfaces:
//! * personal `/api/v1/me/...` — log time, book absences, summary, balance,
//!   export (own data).
//! * project `/api/v1/projects/{id}/...` — team view, corrections, locks,
//!   availability (permission-gated).
//! * admin `/api/v1/admin/users/{id}/...` — vacation allowances + the per-user
//!   daily target (superadmin).
#![allow(
    clippy::arithmetic_side_effects,
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::too_many_lines,
    clippy::module_name_repetitions,
    clippy::manual_let_else,
    clippy::option_if_let_else,
    clippy::cast_possible_truncation
)]

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::perms::Permission;
use intellipilot_core::time_tracking::EntryKind;
use intellipilot_db::time_tracking::{self as ttdb, EntryUpdate, NewEntry};
use intellipilot_db::{audit, memberships as memdb};
use serde::Deserialize;
use serde_json::json;
use time::{Date, Duration, Month};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{AuthUser, SuperadminUser, client_ip, request_id, user_agent};
use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

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
fn unprocessable(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
        "Validation failed",
        Some(detail.to_owned()),
        rid,
    )
}
fn locked(rid: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        "period_locked",
        "Period locked",
        Some("this timesheet period is locked".to_owned()),
        rid,
    )
}
fn stale(rid: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        "version_conflict",
        "Version conflict",
        Some("the entry was modified; reload and retry".to_owned()),
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
        return Err(unprocessable(rid, "invalid fields"));
    }
    Ok(v)
}

const ISO: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");

fn parse_date(s: &str, rid: &str) -> Result<Date, Response> {
    Date::parse(s, &ISO).map_err(|_| unprocessable(rid, "invalid date (expected YYYY-MM-DD)"))
}

/// (year, month-as-i32) for an entry date — used for lock lookups.
fn year_month(d: Date) -> (i32, i32) {
    (d.year(), i32::from(u8::from(d.month())))
}

/// Default to the current calendar month when a range is not supplied.
fn default_range() -> (Date, Date) {
    let today = ttdb::today_utc();
    let start = today.replace_day(1).unwrap_or(today);
    let (ny, nm) = if today.month() == Month::December {
        (today.year() + 1, Month::January)
    } else {
        (today.year(), today.month().next())
    };
    let end = Date::from_calendar_date(ny, nm, 1)
        .map(|d| d - Duration::days(1))
        .unwrap_or(today);
    (start, end)
}

fn resolve_range(
    from: Option<&str>,
    to: Option<&str>,
    rid: &str,
) -> Result<(Date, Date), Response> {
    let (def_from, def_to) = default_range();
    let from = match from {
        Some(s) => parse_date(s, rid)?,
        None => def_from,
    };
    let to = match to {
        Some(s) => parse_date(s, rid)?,
        None => def_to,
    };
    Ok((from, to))
}

// ---------------------------------------------------------------------------
// query + request DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RangeQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub project_id: Option<Uuid>,
    pub issue_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct MonthQuery {
    pub year: Option<i32>,
    pub month: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct DateQuery {
    pub date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub format: Option<String>,
    pub user_id: Option<Uuid>,
}

/// Log worked time. `kind` is `work` (default) or `meeting`.
///
/// - Work: against a task (`issue_id`) OR against a project with no task
///   (`project_id` + a mandatory `note`).
/// - Meeting: optionally against a project, with an optional `meeting_type`; no
///   task.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LogTimeRequest {
    /// `work` (default) or `meeting`.
    #[garde(length(max = 16))]
    #[serde(default)]
    pub kind: Option<String>,
    /// The task to log against (work only). When omitted, `note` is required.
    #[garde(skip)]
    #[serde(default)]
    pub issue_id: Option<Uuid>,
    /// Explicit project when there is no task (work without a task; meeting).
    #[garde(skip)]
    #[serde(default)]
    pub project_id: Option<Uuid>,
    /// `daily`|`planning`|`troubleshooting`|`retro`|`refinement`|`other`
    /// (meeting only).
    #[garde(length(max = 16))]
    #[serde(default)]
    pub meeting_type: Option<String>,
    #[garde(length(min = 10, max = 10))]
    pub date: String,
    #[garde(range(min = 1, max = 1440))]
    pub minutes: i32,
    #[garde(length(max = 2000))]
    #[serde(default)]
    pub note: Option<String>,
}

/// Update an entry's minutes/note/date (optimistic concurrency via `version`).
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateTimeRequest {
    #[garde(range(min = 1, max = 1440))]
    pub minutes: i32,
    #[garde(length(max = 2000))]
    #[serde(default)]
    pub note: Option<String>,
    /// New entry date (YYYY-MM-DD); omitted → unchanged.
    #[garde(length(min = 10, max = 10))]
    #[serde(default)]
    pub date: Option<String>,
    #[garde(range(min = 1, max = 1_000_000))]
    pub version: i32,
}

/// Book an absence over a date range (materialised one entry per working day).
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct BookAbsenceRequest {
    /// `vacation` | `illness` | `day_off` | `holiday`.
    #[garde(length(min = 1, max = 16))]
    pub kind: String,
    #[garde(length(min = 10, max = 10))]
    pub start_date: String,
    #[garde(length(min = 10, max = 10))]
    pub end_date: String,
    /// Minutes per day; defaults to the user's daily target (full day).
    #[garde(range(min = 1, max = 1440))]
    #[serde(default)]
    pub minutes_per_day: Option<i32>,
    #[garde(length(max = 2000))]
    #[serde(default)]
    pub note: Option<String>,
    /// Skip Sat/Sun when materialising (default true).
    #[garde(skip)]
    #[serde(default)]
    pub skip_weekends: Option<bool>,
}

/// Admin adds/corrects worked time on a member's behalf.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AdminLogTimeRequest {
    #[garde(skip)]
    pub user_id: Uuid,
    #[garde(skip)]
    #[serde(default)]
    pub issue_id: Option<Uuid>,
    #[garde(length(min = 10, max = 10))]
    pub date: String,
    #[garde(range(min = 1, max = 1440))]
    pub minutes: i32,
    #[garde(length(max = 2000))]
    #[serde(default)]
    pub note: Option<String>,
}

/// Lock a project-month.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LockPeriodRequest {
    #[garde(range(min = 1970, max = 3000))]
    pub year: i32,
    #[garde(range(min = 1, max = 12))]
    pub month: i32,
}

/// Set a user's vacation allowance for a year (superadmin).
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SetAllowanceRequest {
    #[garde(range(min = 0.0, max = 366.0))]
    pub allowance_days: f64,
    #[garde(range(min = 0.0, max = 366.0))]
    #[serde(default)]
    pub carried_over_days: Option<f64>,
    #[garde(length(max = 500))]
    #[serde(default)]
    pub note: Option<String>,
}

/// Set a user's daily work target (superadmin).
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SetWorkSettingsRequest {
    #[garde(range(min = 1, max = 1440))]
    pub work_minutes_per_day: i32,
}

// ---------------------------------------------------------------------------
// personal: /api/v1/me
// ---------------------------------------------------------------------------

/// `GET /api/v1/me/time-entries`
#[utoipa::path(get, path = "/api/v1/me/time-entries", responses((status = 200), (status = 401)))]
pub async fn list_my_entries(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Query(q): Query<RangeQuery>,
) -> Response {
    let rid = request_id(&headers);
    let (from, to) = match resolve_range(q.from.as_deref(), q.to.as_deref(), &rid) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::list_for_user(&client, user.user_id, from, to, q.project_id, q.issue_id).await {
        Ok(entries) => Json(json!({ "entries": entries })).into_response(),
        Err(_) => internal(&rid),
    }
}

/// `GET /api/v1/me/assigned-issues` — tasks assigned to the caller (for the
/// "log time" picker).
#[utoipa::path(get, path = "/api/v1/me/assigned-issues", responses((status = 200), (status = 401)))]
pub async fn list_my_assigned_issues(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::assigned_issues_for_user(&client, user.user_id).await {
        Ok(issues) => Json(json!({ "issues": issues })).into_response(),
        Err(_) => internal(&rid),
    }
}

/// Query for the searchable log-time task picker.
#[derive(Debug, Deserialize)]
pub struct LoggableQuery {
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub project_id: Option<Uuid>,
}

/// `GET /api/v1/me/loggable-issues?search=&project_id=` — issues in any project
/// the caller belongs to (not just assigned), for logging time against any task.
#[utoipa::path(get, path = "/api/v1/me/loggable-issues", responses((status = 200), (status = 401)))]
pub async fn list_my_loggable_issues(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Query(q): Query<LoggableQuery>,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::loggable_issues_for_user(
        &client,
        user.user_id,
        q.search.as_deref(),
        q.project_id,
        50,
    )
    .await
    {
        Ok(issues) => Json(json!({ "issues": issues })).into_response(),
        Err(_) => internal(&rid),
    }
}

/// `POST /api/v1/me/time-entries` — log worked time against an assigned task.
#[utoipa::path(post, path = "/api/v1/me/time-entries", request_body = LogTimeRequest,
    responses((status = 201), (status = 403), (status = 409), (status = 422)))]
pub async fn log_my_time(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    body: Result<Json<LogTimeRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let req = match parse_body(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let date = match parse_date(&req.date, &rid) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };

    // Kind: work (default) or meeting. Absences go through book_absence.
    let kind = match req.kind.as_deref().unwrap_or("work") {
        "work" => EntryKind::Work,
        "meeting" => EntryKind::Meeting,
        _ => return unprocessable(&rid, "kind must be 'work' or 'meeting'"),
    };
    let note = req.note.as_deref().unwrap_or("").trim();

    // Meeting type is only valid for meetings.
    let meeting_type = match &req.meeting_type {
        Some(m) if kind == EntryKind::Meeting => {
            match intellipilot_core::time_tracking::MeetingType::parse(m) {
                Some(t) => Some(t.as_str()),
                None => return unprocessable(&rid, "invalid meeting_type"),
            }
        }
        _ => None,
    };

    // Resolve the project this entry attributes to (if any), and the task.
    let issue_id = if kind == EntryKind::Work {
        req.issue_id
    } else {
        None
    };
    let project_id: Option<Uuid> = if let Some(iid) = issue_id {
        // Log to ANY task (no assigned-to check): the task must exist and be
        // live; its project gates the permission.
        match ttdb::issue_assignment(&client, iid).await {
            Ok(Some((pid, _assigned, false))) => Some(pid),
            Ok(Some((_, _, true))) => return unprocessable(&rid, "task no longer exists"),
            Ok(None) => return unprocessable(&rid, "task not found"),
            Err(_) => return internal(&rid),
        }
    } else {
        req.project_id
    };

    // Work always needs a project; work without a task needs a note.
    if kind == EntryKind::Work {
        if project_id.is_none() {
            return unprocessable(&rid, "work needs a task or a project");
        }
        if issue_id.is_none() && note.is_empty() {
            return unprocessable(&rid, "a note is required when no task is selected");
        }
    }

    // When attributed to a project, require time.log there (and respect locks).
    if let Some(pid) = project_id {
        let access = memdb::access(&client, pid, user.user_id)
            .await
            .ok()
            .flatten();
        let can_log = access.as_ref().is_some_and(|a| a.has(Permission::TimeLog));
        let can_manage = access
            .as_ref()
            .is_some_and(|a| a.has(Permission::TimeManage));
        if !can_log {
            return problem(StatusCode::FORBIDDEN, "forbidden", "Forbidden", None, &rid);
        }
        let (yr, mo) = year_month(date);
        match ttdb::is_locked(&client, pid, yr, mo).await {
            Ok(true) if !can_manage => return locked(&rid),
            Ok(_) => {}
            Err(_) => return internal(&rid),
        }
    }

    let new = NewEntry {
        user_id: user.user_id,
        kind,
        meeting_type,
        project_id,
        issue_id,
        entry_date: date,
        minutes: req.minutes,
        note,
        booking_id: None,
    };
    match ttdb::create_entry(&client, &new).await {
        Ok(entry) => {
            audit::record(
                &client,
                Some(user.user_id),
                "time_entry_logged",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "entry_id": entry.id, "project_id": project_id, "minutes": req.minutes }),
            )
            .await;
            (StatusCode::CREATED, Json(entry)).into_response()
        }
        Err(_) => internal(&rid),
    }
}

/// `PATCH /api/v1/me/time-entries/{id}`
#[utoipa::path(patch, path = "/api/v1/me/time-entries/{id}", request_body = UpdateTimeRequest,
    responses((status = 200), (status = 404), (status = 409)))]
pub async fn update_my_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<Uuid>,
    body: Result<Json<UpdateTimeRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let req = match parse_body(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };

    let entry = match ttdb::get_entry(&client, id).await {
        Ok(Some(e)) if e.user_id == user.user_id => e,
        Ok(_) => return not_found(&rid), // hide others' entries
        Err(_) => return internal(&rid),
    };
    if let Some(resp) = guard_locked(&client, &entry, user.user_id, &rid).await {
        return resp;
    }
    // A date move must also respect the lock on the target month.
    let new_date = match &req.date {
        None => None,
        Some(s) => match parse_date(s, &rid) {
            Ok(d) => Some(d),
            Err(r) => return r,
        },
    };
    if let Some(d) = new_date
        && d != entry.entry_date
    {
        let mut moved = entry.clone();
        moved.entry_date = d;
        if let Some(resp) = guard_locked(&client, &moved, user.user_id, &rid).await {
            return resp;
        }
    }

    let note = req.note.clone().unwrap_or_else(|| entry.note.clone());
    match ttdb::update_entry(&client, id, req.minutes, &note, new_date, req.version).await {
        Ok(EntryUpdate::Updated(e)) => {
            audit::record(
                &client,
                Some(user.user_id),
                "time_entry_updated",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "entry_id": id }),
            )
            .await;
            Json(*e).into_response()
        }
        Ok(EntryUpdate::Stale) => stale(&rid),
        Ok(EntryUpdate::Missing) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}

/// `DELETE /api/v1/me/time-entries/{id}`
#[utoipa::path(delete, path = "/api/v1/me/time-entries/{id}", responses((status = 204), (status = 404)))]
pub async fn delete_my_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    let entry = match ttdb::get_entry(&client, id).await {
        Ok(Some(e)) if e.user_id == user.user_id => e,
        Ok(_) => return not_found(&rid),
        Err(_) => return internal(&rid),
    };
    if let Some(resp) = guard_locked(&client, &entry, user.user_id, &rid).await {
        return resp;
    }
    match ttdb::delete_entry(&client, id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(user.user_id),
                "time_entry_deleted",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "entry_id": id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}

/// 409 if `entry` is a work entry in a locked project-month and the actor lacks
/// manage rights; otherwise None.
async fn guard_locked(
    client: &deadpool_postgres::Client,
    entry: &intellipilot_core::time_tracking::TimeEntry,
    actor: Uuid,
    rid: &str,
) -> Option<Response> {
    let project_id = entry.project_id?;
    let (yr, mo) = year_month(entry.entry_date);
    match ttdb::is_locked(client, project_id, yr, mo).await {
        Ok(true) => {
            let can_manage = memdb::access(client, project_id, actor)
                .await
                .ok()
                .flatten()
                .is_some_and(|a| a.has(Permission::TimeManage));
            (!can_manage).then(|| locked(rid))
        }
        Ok(false) => None,
        Err(_) => Some(internal(rid)),
    }
}

/// `POST /api/v1/me/absences` — book vacation / illness / day-off / holiday.
#[utoipa::path(post, path = "/api/v1/me/absences", request_body = BookAbsenceRequest,
    responses((status = 201), (status = 422)))]
pub async fn book_absence(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    body: Result<Json<BookAbsenceRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let req = match parse_body(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(kind) = EntryKind::parse(&req.kind) else {
        return unprocessable(&rid, "unknown absence kind");
    };
    if !kind.is_absence() {
        return unprocessable(&rid, "kind must be an absence, not work");
    }
    let start = match parse_date(&req.start_date, &rid) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let end = match parse_date(&req.end_date, &rid) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if end < start {
        return unprocessable(&rid, "end_date is before start_date");
    }
    if (end - start).whole_days() > 366 {
        return unprocessable(&rid, "range too long (max 366 days)");
    }
    let Ok(mut client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };

    let minutes = match req.minutes_per_day {
        Some(m) => m,
        None => ttdb::work_minutes_per_day(&client, user.user_id)
            .await
            .ok()
            .flatten()
            .unwrap_or(480),
    };
    let skip_weekends = req.skip_weekends.unwrap_or(true);

    match ttdb::create_booking(
        &mut client,
        user.user_id,
        kind,
        start,
        end,
        minutes,
        req.note.as_deref().unwrap_or(""),
        skip_weekends,
    )
    .await
    {
        Ok((booking_id, entries)) => {
            audit::record(
                &client,
                Some(user.user_id),
                "absence_booked",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "booking_id": booking_id, "kind": kind.as_str(), "days": entries.len() }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(json!({ "booking_id": booking_id, "entries": entries })),
            )
                .into_response()
        }
        Err(_) => internal(&rid),
    }
}

/// `DELETE /api/v1/me/absences/{booking_id}`
#[utoipa::path(delete, path = "/api/v1/me/absences/{booking_id}", responses((status = 204), (status = 404)))]
pub async fn delete_absence_booking(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(booking_id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::delete_booking(&client, user.user_id, booking_id).await {
        Ok(0) => not_found(&rid),
        Ok(_) => {
            audit::record(
                &client,
                Some(user.user_id),
                "absence_cancelled",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "booking_id": booking_id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => internal(&rid),
    }
}

/// `GET /api/v1/me/timesheet/summary`
#[utoipa::path(get, path = "/api/v1/me/timesheet/summary", responses((status = 200)))]
pub async fn my_timesheet_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Query(q): Query<MonthQuery>,
) -> Response {
    let rid = request_id(&headers);
    let today = ttdb::today_utc();
    let year = q.year.unwrap_or_else(|| today.year());
    let month = q.month.unwrap_or_else(|| u8::from(today.month()));
    if !(1..=12).contains(&month) {
        return unprocessable(&rid, "month must be 1..12");
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::timesheet_summary(&client, user.user_id, year, month, today).await {
        Ok(s) => Json(s).into_response(),
        Err(_) => internal(&rid),
    }
}

/// `GET /api/v1/me/vacation-balance`
#[utoipa::path(get, path = "/api/v1/me/vacation-balance", responses((status = 200)))]
pub async fn my_vacation_balance(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::vacation_balance(&client, user.user_id).await {
        Ok(b) => Json(b).into_response(),
        Err(_) => internal(&rid),
    }
}

/// `GET /api/v1/me/time-entries/export`
#[utoipa::path(get, path = "/api/v1/me/time-entries/export", responses((status = 200)))]
pub async fn export_my_time(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Query(q): Query<ExportQuery>,
) -> Response {
    let rid = request_id(&headers);
    let (from, to) = match resolve_range(q.from.as_deref(), q.to.as_deref(), &rid) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    let entries = match ttdb::list_for_user(&client, user.user_id, from, to, None, None).await {
        Ok(e) => e,
        Err(_) => return internal(&rid),
    };
    export_response(&entries, q.format.as_deref(), false, &rid)
}

// ---------------------------------------------------------------------------
// project / team: /api/v1/projects/{project_id}
// ---------------------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/time-entries` — team timesheet.
#[utoipa::path(get, path = "/api/v1/projects/{project_id}/time-entries", responses((status = 200), (status = 403)))]
pub async fn list_project_time(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Query(q): Query<RangeQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::TimeViewAll) {
        return r;
    }
    let (from, to) = match resolve_range(q.from.as_deref(), q.to.as_deref(), &ctx.rid) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ttdb::list_for_project(&client, ctx.project.id, from, to, q.user_id).await {
        Ok(entries) => Json(json!({ "entries": entries })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/time/summary` — team grid for a month.
#[utoipa::path(get, path = "/api/v1/projects/{project_id}/time/summary", responses((status = 200), (status = 403)))]
pub async fn project_team_month(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Query(q): Query<MonthQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::TimeViewAll) {
        return r;
    }
    let today = ttdb::today_utc();
    let year = q.year.unwrap_or_else(|| today.year());
    let month = q.month.unwrap_or_else(|| u8::from(today.month()));
    if !(1..=12).contains(&month) {
        return unprocessable(&ctx.rid, "month must be 1..12");
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ttdb::team_month(&client, ctx.project.id, year, month).await {
        Ok(members) => {
            Json(json!({ "year": year, "month": month, "members": members })).into_response()
        }
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/time-entries` — admin logs on behalf.
#[utoipa::path(post, path = "/api/v1/projects/{project_id}/time-entries", request_body = AdminLogTimeRequest,
    responses((status = 201), (status = 403), (status = 422)))]
pub async fn admin_log_time(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    body: Result<Json<AdminLogTimeRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::TimeManage) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let date = match parse_date(&req.date, &ctx.rid) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // Target must be a member of this project.
    let is_member = memdb::access(&client, ctx.project.id, req.user_id)
        .await
        .ok()
        .flatten()
        .is_some();
    if !is_member {
        return unprocessable(&ctx.rid, "target user is not a project member");
    }
    // If an issue is given it must belong to this project and be live.
    if let Some(issue_id) = req.issue_id {
        match ttdb::issue_assignment(&client, issue_id).await {
            Ok(Some((pid, _, false))) if pid == ctx.project.id => {}
            Ok(_) => return unprocessable(&ctx.rid, "task not found in this project"),
            Err(_) => return internal(&ctx.rid),
        }
    }
    let new = NewEntry {
        user_id: req.user_id,
        kind: EntryKind::Work,
        meeting_type: None,
        project_id: Some(ctx.project.id),
        issue_id: req.issue_id,
        entry_date: date,
        minutes: req.minutes,
        note: req.note.as_deref().unwrap_or(""),
        booking_id: None,
    };
    match ttdb::create_entry(&client, &new).await {
        Ok(entry) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "time_entry_admin_logged",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "entry_id": entry.id, "for_user": req.user_id, "project_id": ctx.project.id }),
            )
            .await;
            (StatusCode::CREATED, Json(entry)).into_response()
        }
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/time-entries/{entry_id}` — admin corrects.
#[utoipa::path(patch, path = "/api/v1/projects/{project_id}/time-entries/{entry_id}",
    request_body = UpdateTimeRequest, responses((status = 200), (status = 403), (status = 404), (status = 409)))]
pub async fn admin_update_entry(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    Path((_project_id, entry_id)): Path<(Uuid, Uuid)>,
    body: Result<Json<UpdateTimeRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::TimeManage) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // The entry must belong to this project (managers bypass period locks).
    match ttdb::get_entry(&client, entry_id).await {
        Ok(Some(e)) if e.project_id == Some(ctx.project.id) => {}
        Ok(_) => return not_found(&ctx.rid),
        Err(_) => return internal(&ctx.rid),
    }
    let note = req.note.clone().unwrap_or_default();
    let new_date = match &req.date {
        None => None,
        Some(s) => match parse_date(s, &ctx.rid) {
            Ok(d) => Some(d),
            Err(r) => return r,
        },
    };
    match ttdb::update_entry(&client, entry_id, req.minutes, &note, new_date, req.version).await {
        Ok(EntryUpdate::Updated(e)) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "time_entry_corrected",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "entry_id": entry_id, "project_id": ctx.project.id }),
            )
            .await;
            Json(*e).into_response()
        }
        Ok(EntryUpdate::Stale) => stale(&ctx.rid),
        Ok(EntryUpdate::Missing) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/time-entries/{entry_id}` — admin removes.
#[utoipa::path(delete, path = "/api/v1/projects/{project_id}/time-entries/{entry_id}",
    responses((status = 204), (status = 403), (status = 404)))]
pub async fn admin_delete_entry(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    Path((_project_id, entry_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(r) = ctx.require(Permission::TimeManage) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ttdb::get_entry(&client, entry_id).await {
        Ok(Some(e)) if e.project_id == Some(ctx.project.id) => {}
        Ok(_) => return not_found(&ctx.rid),
        Err(_) => return internal(&ctx.rid),
    }
    match ttdb::delete_entry(&client, entry_id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "time_entry_admin_deleted",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "entry_id": entry_id, "project_id": ctx.project.id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/time/locks`
#[utoipa::path(get, path = "/api/v1/projects/{project_id}/time/locks", responses((status = 200), (status = 403)))]
pub async fn list_locks(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::TimeViewAll) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ttdb::list_locks(&client, ctx.project.id).await {
        Ok(locks) => Json(json!({ "locks": locks })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/time/locks` — lock a month.
#[utoipa::path(post, path = "/api/v1/projects/{project_id}/time/locks", request_body = LockPeriodRequest,
    responses((status = 201), (status = 403)))]
pub async fn lock_period(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    body: Result<Json<LockPeriodRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::TimeManage) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ttdb::lock_period(&client, ctx.project.id, req.year, req.month, ctx.actor_id).await {
        Ok(lock) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "time_period_locked",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "project_id": ctx.project.id, "year": req.year, "month": req.month }),
            )
            .await;
            (StatusCode::CREATED, Json(lock)).into_response()
        }
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/time/locks/{year}/{month}` — unlock.
#[utoipa::path(delete, path = "/api/v1/projects/{project_id}/time/locks/{year}/{month}",
    responses((status = 204), (status = 403), (status = 404)))]
pub async fn unlock_period(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    Path((_project_id, year, month)): Path<(Uuid, i32, i32)>,
) -> Response {
    if let Err(r) = ctx.require(Permission::TimeManage) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ttdb::unlock_period(&client, ctx.project.id, year, month).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "time_period_unlocked",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "project_id": ctx.project.id, "year": year, "month": month }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/availability` — who is out on a date.
#[utoipa::path(get, path = "/api/v1/projects/{project_id}/availability", responses((status = 200), (status = 403)))]
pub async fn project_availability(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Query(q): Query<DateQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MemberView) {
        return r;
    }
    let date = match q.date.as_deref() {
        Some(s) => match parse_date(s, &ctx.rid) {
            Ok(d) => d,
            Err(r) => return r,
        },
        None => ttdb::today_utc(),
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ttdb::availability(&client, ctx.project.id, date).await {
        Ok(people) => Json(json!({ "date": q.date, "unavailable": people })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/issues/{id}/time` — time on a task.
#[utoipa::path(get, path = "/api/v1/projects/{project_id}/issues/{id}/time", responses((status = 200), (status = 403)))]
pub async fn issue_time(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, issue_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueView) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // Wide range so all entries for the task are included.
    let from =
        Date::from_calendar_date(1970, Month::January, 1).unwrap_or_else(|_| ttdb::today_utc());
    let to =
        Date::from_calendar_date(3000, Month::December, 31).unwrap_or_else(|_| ttdb::today_utc());
    let see_all = ctx
        .access
        .as_ref()
        .is_some_and(|a| a.has(Permission::TimeViewAll))
        || ctx.is_superadmin;
    let user_filter = if see_all { None } else { Some(ctx.actor_id) };

    match ttdb::list_for_project(&client, ctx.project.id, from, to, user_filter).await {
        Ok(all) => {
            let entries: Vec<_> = all
                .into_iter()
                .filter(|e| e.issue_id == Some(issue_id))
                .collect();
            let total: i64 = entries.iter().map(|e| i64::from(e.minutes)).sum();
            let mine: i64 = entries
                .iter()
                .filter(|e| e.user_id == ctx.actor_id)
                .map(|e| i64::from(e.minutes))
                .sum();
            Json(json!({
                "entries": entries,
                "total_minutes": total,
                "my_minutes": mine,
                "can_see_all": see_all,
            }))
            .into_response()
        }
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/time-entries/export`
#[utoipa::path(get, path = "/api/v1/projects/{project_id}/time-entries/export", responses((status = 200), (status = 403)))]
pub async fn export_project_time(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Query(q): Query<ExportQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::TimeViewAll) {
        return r;
    }
    let (from, to) = match resolve_range(q.from.as_deref(), q.to.as_deref(), &ctx.rid) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match ttdb::list_for_project(&client, ctx.project.id, from, to, q.user_id).await {
        Ok(entries) => export_response(&entries, q.format.as_deref(), true, &ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// ---------------------------------------------------------------------------
// admin (superadmin): vacation allowances + work settings
// ---------------------------------------------------------------------------

/// `GET /api/v1/admin/users/{id}/vacation-allowances`
#[utoipa::path(get, path = "/api/v1/admin/users/{id}/vacation-allowances", responses((status = 200), (status = 403)))]
pub async fn list_user_allowances(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
    Path(user_id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    let allowances = match ttdb::list_allowances(&client, user_id).await {
        Ok(a) => a,
        Err(_) => return internal(&rid),
    };
    let balance = match ttdb::vacation_balance(&client, user_id).await {
        Ok(b) => b,
        Err(_) => return internal(&rid),
    };
    Json(json!({ "allowances": allowances, "balance": balance })).into_response()
}

/// `PUT /api/v1/admin/users/{id}/vacation-allowances/{year}`
#[utoipa::path(put, path = "/api/v1/admin/users/{id}/vacation-allowances/{year}",
    request_body = SetAllowanceRequest, responses((status = 200), (status = 403)))]
pub async fn set_user_allowance(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path((user_id, year)): Path<(Uuid, i32)>,
    body: Result<Json<SetAllowanceRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let req = match parse_body(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::upsert_allowance(
        &client,
        user_id,
        year,
        req.allowance_days,
        req.carried_over_days.unwrap_or(0.0),
        req.note.as_deref().unwrap_or(""),
        admin.user_id,
    )
    .await
    {
        Ok(a) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "vacation_allowance_set",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "user_id": user_id, "year": year, "days": req.allowance_days }),
            )
            .await;
            Json(a).into_response()
        }
        Err(_) => internal(&rid),
    }
}

/// `PATCH /api/v1/admin/users/{id}/work-settings`
#[utoipa::path(patch, path = "/api/v1/admin/users/{id}/work-settings",
    request_body = SetWorkSettingsRequest, responses((status = 204), (status = 403), (status = 404)))]
pub async fn set_user_work_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(user_id): Path<Uuid>,
    body: Result<Json<SetWorkSettingsRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let req = match parse_body(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::set_work_minutes_per_day(&client, user_id, req.work_minutes_per_day).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "work_settings_set",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "user_id": user_id, "minutes": req.work_minutes_per_day }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}

/// `GET /api/v1/admin/time/summary?year=&month=` — cross-project team grid
/// (all users, all projects) for a month. Superadmin only.
#[utoipa::path(get, path = "/api/v1/admin/time/summary", responses((status = 200), (status = 403)))]
pub async fn global_team_month(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
    Query(q): Query<MonthQuery>,
) -> Response {
    let rid = request_id(&headers);
    let today = ttdb::today_utc();
    let year = q.year.unwrap_or_else(|| today.year());
    let month = q.month.unwrap_or_else(|| u8::from(today.month()));
    if !(1..=12).contains(&month) {
        return unprocessable(&rid, "month must be 1..12");
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::global_team_month(&client, year, month).await {
        Ok(members) => {
            Json(json!({ "year": year, "month": month, "members": members })).into_response()
        }
        Err(_) => internal(&rid),
    }
}

/// Query for the cross-project entry list.
#[derive(Debug, Deserialize)]
pub struct AdminTimeQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub user_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub kind: Option<String>,
}

/// `GET /api/v1/admin/time-entries?from=&to=&user_id=&project_id=&kind=` —
/// cross-project entry list. Superadmin only.
#[utoipa::path(get, path = "/api/v1/admin/time-entries", responses((status = 200), (status = 403)))]
pub async fn list_all_time(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
    Query(q): Query<AdminTimeQuery>,
) -> Response {
    let rid = request_id(&headers);
    let (from, to) = match resolve_range(q.from.as_deref(), q.to.as_deref(), &rid) {
        Ok(r) => r,
        Err(r) => return r,
    };
    // Validate the optional kind filter.
    let kind = match &q.kind {
        Some(k) if EntryKind::parse(k).is_none() => return unprocessable(&rid, "invalid kind"),
        other => other.as_deref(),
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match ttdb::list_all_entries(&client, from, to, q.user_id, q.project_id, kind).await {
        Ok(entries) => Json(json!({ "entries": entries })).into_response(),
        Err(_) => internal(&rid),
    }
}

// ---------------------------------------------------------------------------
// export rendering (CSV + XLSX)
// ---------------------------------------------------------------------------

use intellipilot_core::time_tracking::TimeEntryDetail;

fn hours(minutes: i32) -> f64 {
    f64::from(minutes) / 60.0
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn build_csv(entries: &[TimeEntryDetail], with_user: bool) -> String {
    let mut out = String::new();
    if with_user {
        out.push_str("Date,User,Kind,Project,Task,Subject,Minutes,Hours,Note\n");
    } else {
        out.push_str("Date,Kind,Project,Task,Subject,Minutes,Hours,Note\n");
    }
    for e in entries {
        let date = e.entry_date.format(&ISO).unwrap_or_default();
        let task = e.issue_ref.map(|r| format!("#{r}")).unwrap_or_default();
        let subject = e.issue_subject.clone().unwrap_or_default();
        let project = e.project_name.clone().unwrap_or_default();
        let name = e.full_name.clone().unwrap_or_default();
        let mut row = vec![csv_field(&date)];
        if with_user {
            row.push(csv_field(&name));
        }
        row.push(csv_field(e.kind.as_str()));
        row.push(csv_field(&project));
        row.push(csv_field(&task));
        row.push(csv_field(&subject));
        row.push(e.minutes.to_string());
        row.push(format!("{:.2}", hours(e.minutes)));
        row.push(csv_field(&e.note));
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

fn build_xlsx(
    entries: &[TimeEntryDetail],
    with_user: bool,
) -> Result<Vec<u8>, rust_xlsxwriter::XlsxError> {
    use rust_xlsxwriter::{Format, Workbook};
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    let bold = Format::new().set_bold();

    let headers: &[&str] = if with_user {
        &[
            "Date", "User", "Kind", "Project", "Task", "Subject", "Minutes", "Hours", "Note",
        ]
    } else {
        &[
            "Date", "Kind", "Project", "Task", "Subject", "Minutes", "Hours", "Note",
        ]
    };
    for (c, h) in headers.iter().enumerate() {
        ws.write_string_with_format(0, c as u16, *h, &bold)?;
    }
    for (i, e) in entries.iter().enumerate() {
        let row = (i + 1) as u32;
        let mut c: u16 = 0;
        let date = e.entry_date.format(&ISO).unwrap_or_default();
        ws.write_string(row, c, &date)?;
        c += 1;
        if with_user {
            ws.write_string(row, c, e.full_name.clone().unwrap_or_default())?;
            c += 1;
        }
        ws.write_string(row, c, e.kind.as_str())?;
        c += 1;
        ws.write_string(row, c, e.project_name.clone().unwrap_or_default())?;
        c += 1;
        ws.write_string(
            row,
            c,
            e.issue_ref.map(|r| format!("#{r}")).unwrap_or_default(),
        )?;
        c += 1;
        ws.write_string(row, c, e.issue_subject.clone().unwrap_or_default())?;
        c += 1;
        ws.write_number(row, c, f64::from(e.minutes))?;
        c += 1;
        ws.write_number(row, c, hours(e.minutes))?;
        c += 1;
        ws.write_string(row, c, &e.note)?;
    }
    wb.save_to_buffer()
}

fn export_response(
    entries: &[TimeEntryDetail],
    format: Option<&str>,
    with_user: bool,
    rid: &str,
) -> Response {
    match format.unwrap_or("csv").to_ascii_lowercase().as_str() {
        "xlsx" => match build_xlsx(entries, with_user) {
            Ok(bytes) => download(
                bytes,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "timesheet.xlsx",
            ),
            Err(_) => internal(rid),
        },
        "csv" => download(
            build_csv(entries, with_user).into_bytes(),
            "text/csv; charset=utf-8",
            "timesheet.csv",
        ),
        _ => unprocessable(rid, "format must be csv or xlsx"),
    }
}

fn download(bytes: Vec<u8>, content_type: &str, filename: &str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type.to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        bytes,
    )
        .into_response()
}
