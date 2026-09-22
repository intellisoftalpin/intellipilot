//! Meeting endpoints: CRUD, calendar range listing, links (participants,
//! issues, epics, customers), meeting files, and transcript/summary import.
//!
//! Meetings are internal to the team: every endpoint needs `meeting.view` or
//! stronger, which the default stakeholder role does not hold. Live events
//! carry identifiers only (see `events::MeetingEventKind`), because the change
//! feed is open to every holder of `issue.view`.
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use intellipilot_core::attachment::Attachment;
use intellipilot_core::backlog::etag;
use intellipilot_core::meeting::{
    ArtifactKind, Meeting, MeetingDayCount, MeetingListItem, TextFormat, times_ok, to_plain_text,
};
use intellipilot_core::perms::Permission;
use intellipilot_db::attachments as adb;
use intellipilot_db::backlog::UpdateOutcome;
use intellipilot_db::meetings::{self as mdb, LinkKind, MeetingLinks, MeetingNew, MeetingPatch};
use serde::{Deserialize, Serialize};
use time::{Date, Time};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::attachments::{
    Received, content_type_for, mime_mismatch, receive_file, store_and_record,
};
use crate::backlog::{check_if_match, with_etag};
use crate::events::MeetingEventKind;
use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

/// Widest calendar window one request may ask for.
const MAX_RANGE_DAYS: i64 = 400;
/// Largest transcript/summary file accepted for import.
const MAX_IMPORT_BYTES: u64 = 20 * 1024 * 1024;

const MAX_TITLE: usize = 300;
const MAX_LOCATION: usize = 2_000;
const MAX_DESCRIPTION: usize = 100_000;
const MAX_SUMMARY: usize = 1_000_000;
const MAX_TRANSCRIPT: usize = 5_000_000;
const MAX_TIMEZONE: usize = 64;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// A meeting plus its files — the shape every single-meeting endpoint returns.
#[derive(Debug, Serialize, ToSchema)]
pub struct MeetingDetail {
    #[serde(flatten)]
    pub meeting: Meeting,
    /// Every file of the meeting, oldest first; `kind` says what each is.
    pub artifacts: Vec<Attachment>,
}

/// Calendar listing: the meetings in range plus a count per day that has any.
#[derive(Debug, Serialize, ToSchema)]
pub struct MeetingRangeResponse {
    pub meetings: Vec<MeetingListItem>,
    pub days: Vec<MeetingDayCount>,
}

/// Meetings linked to an issue or epic, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct LinkedMeetingsResponse {
    pub meetings: Vec<MeetingListItem>,
}

/// The files of a meeting.
#[derive(Debug, Serialize, ToSchema)]
pub struct MeetingArtifactsResponse {
    pub artifacts: Vec<Attachment>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RangeQuery {
    /// First day, inclusive (`YYYY-MM-DD`).
    pub from: String,
    /// Last day, inclusive (`YYYY-MM-DD`). At most 400 days after `from`.
    pub to: String,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ArtifactQuery {
    /// `recording`, `transcript`, `summary` or `other` (default). May also be
    /// sent as a `kind` form field before the file.
    #[serde(default)]
    pub kind: Option<String>,
}

/// Create a meeting. Only `title` and `meeting_date` are required.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateMeetingRequest {
    pub title: String,
    /// `YYYY-MM-DD`.
    #[schema(value_type = String)]
    #[serde(with = "intellipilot_core::serde_date::required")]
    pub meeting_date: Date,
    /// Local `HH:MM`.
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::meeting::serde_hm::option")]
    pub start_time: Option<Time>,
    /// Local `HH:MM`; needs `start_time` and must be later the same day.
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::meeting::serde_hm::option")]
    pub end_time: Option<Time>,
    /// IANA zone name (default `UTC`).
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub transcript: Option<String>,
    /// Project members who took part.
    #[serde(default)]
    pub participant_ids: Vec<Uuid>,
    #[serde(default)]
    pub issue_ids: Vec<Uuid>,
    #[serde(default)]
    pub epic_ids: Vec<Uuid>,
    #[serde(default)]
    pub customer_ids: Vec<Uuid>,
}

/// Partial update (requires `If-Match`). Absent fields are left alone; `null`
/// clears `start_time`/`end_time`. Link arrays, when present, replace the set.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UpdateMeetingRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub meeting_date: Option<Date>,
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::meeting::serde_hm::double_option")]
    pub start_time: Option<Option<Time>>,
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::meeting::serde_hm::double_option")]
    pub end_time: Option<Option<Time>>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub transcript: Option<String>,
    #[serde(default)]
    pub participant_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub issue_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub epic_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub customer_ids: Option<Vec<Uuid>>,
}

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
fn invalid(rid: &str, code: &'static str, detail: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        code,
        "Validation failed",
        Some(detail.to_owned()),
        rid,
    )
}

fn parse_body<T>(body: Result<Json<T>, JsonRejection>, rid: &str) -> Result<T, Response> {
    body.map(|Json(v)| v).map_err(|e| {
        problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            Some(e.body_text()),
            rid,
        )
    })
}

/// Length checks on the free-text fields; `Err` names the offending field.
fn check_lengths(
    title: Option<&str>,
    location: Option<&str>,
    description: Option<&str>,
    summary: Option<&str>,
    transcript: Option<&str>,
) -> Result<(), &'static str> {
    if let Some(t) = title
        && (t.trim().is_empty() || t.chars().count() > MAX_TITLE)
    {
        return Err("title must be 1-300 characters");
    }
    let too_long = |v: Option<&str>, max: usize| v.is_some_and(|s| s.chars().count() > max);
    if too_long(location, MAX_LOCATION) {
        return Err("location is too long");
    }
    if too_long(description, MAX_DESCRIPTION) {
        return Err("description is too long");
    }
    if too_long(summary, MAX_SUMMARY) {
        return Err("summary is too long");
    }
    if too_long(transcript, MAX_TRANSCRIPT) {
        return Err("transcript is too long");
    }
    Ok(())
}

const fn link_error(kind: LinkKind) -> &'static str {
    match kind {
        LinkKind::Participants => "every participant must be a member of the project",
        LinkKind::Issues => "every issue must be a live issue of this project",
        LinkKind::Epics => "every epic must be a live epic of this project",
        LinkKind::Customers => "every customer must belong to this project",
    }
}

async fn validate_timezone(
    client: &deadpool_postgres::Client,
    tz: &str,
    rid: &str,
) -> Result<(), Response> {
    if tz.is_empty() || tz.len() > MAX_TIMEZONE {
        return Err(invalid(rid, "invalid_timezone", "unknown time zone"));
    }
    match mdb::timezone_exists(client, tz).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(invalid(rid, "invalid_timezone", "unknown time zone")),
        Err(_) => Err(internal(rid)),
    }
}

async fn validate_links(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    links: &MeetingLinks<'_>,
    rid: &str,
) -> Result<(), Response> {
    match mdb::invalid_link(client, project_id, links).await {
        Ok(None) => Ok(()),
        Ok(Some(kind)) => Err(invalid(rid, "invalid_link", link_error(kind))),
        Err(_) => Err(internal(rid)),
    }
}

/// Load a meeting's files and wrap it as a [`MeetingDetail`] with its ETag.
async fn detail_response(
    client: &deadpool_postgres::Client,
    status: StatusCode,
    meeting: Meeting,
    rid: &str,
) -> Response {
    let Ok(artifacts) = adb::list(client, "meeting", meeting.id).await else {
        return internal(rid);
    };
    let (id, version) = (meeting.id, meeting.version);
    with_etag(status, id, version, &MeetingDetail { meeting, artifacts })
}

// ---------------------------------------------------------------------------
// meetings
// ---------------------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/meetings?from=&to=`
#[utoipa::path(
    get, path = "/api/v1/projects/{project_id}/meetings", tag = "meetings",
    params(RangeQuery),
    responses((status = 200, body = MeetingRangeResponse))
)]
pub async fn list(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Query(q): Query<RangeQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingView) {
        return r;
    }
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    let (Ok(from), Ok(to)) = (Date::parse(&q.from, &fmt), Date::parse(&q.to, &fmt)) else {
        return invalid(&ctx.rid, "invalid_range", "from and to must be YYYY-MM-DD");
    };
    let latest = from.checked_add(time::Duration::days(MAX_RANGE_DAYS));
    if to < from || latest.is_none_or(|l| to > l) {
        return invalid(
            &ctx.rid,
            "invalid_range",
            "to must be on or after from, at most 400 days later",
        );
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(meetings) = mdb::list_range(&client, ctx.project.id, from, to).await else {
        return internal(&ctx.rid);
    };
    let mut per_day: BTreeMap<Date, i64> = BTreeMap::new();
    for m in &meetings {
        let n = per_day.entry(m.meeting_date).or_insert(0);
        *n = n.saturating_add(1);
    }
    let days = per_day
        .into_iter()
        .map(|(date, count)| MeetingDayCount { date, count })
        .collect();
    Json(MeetingRangeResponse { meetings, days }).into_response()
}

/// `POST /api/v1/projects/{project_id}/meetings`
#[utoipa::path(
    post, path = "/api/v1/projects/{project_id}/meetings", tag = "meetings",
    request_body = CreateMeetingRequest,
    responses((status = 201, body = MeetingDetail))
)]
pub async fn create(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<CreateMeetingRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingCreate) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(d) = check_lengths(
        Some(&req.title),
        req.location.as_deref(),
        req.description.as_deref(),
        req.summary.as_deref(),
        req.transcript.as_deref(),
    ) {
        return invalid(&ctx.rid, "validation_failed", d);
    }
    if !times_ok(req.start_time, req.end_time) {
        return invalid(
            &ctx.rid,
            "invalid_times",
            "end_time needs a start_time and must be later the same day",
        );
    }
    let auth = state.auth();
    let Ok(mut client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let tz = req.timezone.as_deref().unwrap_or("UTC").trim().to_owned();
    if let Err(r) = validate_timezone(&client, &tz, &ctx.rid).await {
        return r;
    }
    let links = MeetingLinks {
        participant_ids: Some(&req.participant_ids),
        issue_ids: Some(&req.issue_ids),
        epic_ids: Some(&req.epic_ids),
        customer_ids: Some(&req.customer_ids),
    };
    if let Err(r) = validate_links(&client, ctx.project.id, &links, &ctx.rid).await {
        return r;
    }
    let new = MeetingNew {
        title: req.title.trim(),
        meeting_date: req.meeting_date,
        start_time: req.start_time,
        end_time: req.end_time,
        timezone: &tz,
        location: req.location.as_deref().unwrap_or_default(),
        description: req.description.as_deref().unwrap_or_default(),
        summary: req.summary.as_deref().unwrap_or_default(),
        transcript: req.transcript.as_deref().unwrap_or_default(),
    };
    match mdb::create(&mut client, ctx.project.id, ctx.actor_id, &new, &links).await {
        Ok(m) => {
            state.events.publish_meeting(
                MeetingEventKind::Created,
                ctx.project.id,
                ctx.actor_id,
                m.id,
            );
            detail_response(&client, StatusCode::CREATED, m, &ctx.rid).await
        }
        Err(e) => {
            tracing::warn!(error = %e, "meeting create failed");
            internal(&ctx.rid)
        }
    }
}

/// `GET /api/v1/projects/{project_id}/meetings/{meeting_id}`
#[utoipa::path(
    get, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}", tag = "meetings",
    responses((status = 200, body = MeetingDetail), (status = 404))
)]
pub async fn get(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingView) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match mdb::get(&client, ctx.project.id, id).await {
        Ok(Some(m)) => detail_response(&client, StatusCode::OK, m, &ctx.rid).await,
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/meetings/{meeting_id}` (If-Match)
#[utoipa::path(
    patch, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}", tag = "meetings",
    request_body = UpdateMeetingRequest,
    responses((status = 200, body = MeetingDetail), (status = 412), (status = 428))
)]
pub async fn update(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    Path((_project_id, id)): Path<(Uuid, Uuid)>,
    body: Result<Json<UpdateMeetingRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingModify) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(mut client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let current = match mdb::get(&client, ctx.project.id, id).await {
        Ok(Some(m)) => m,
        Ok(None) => return not_found(&ctx.rid),
        Err(_) => return internal(&ctx.rid),
    };
    if let Err(r) = check_if_match(&headers, &etag(current.id, current.version), &ctx.rid) {
        return r;
    }
    if let Err(d) = check_lengths(
        req.title.as_deref(),
        req.location.as_deref(),
        req.description.as_deref(),
        req.summary.as_deref(),
        req.transcript.as_deref(),
    ) {
        return invalid(&ctx.rid, "validation_failed", d);
    }
    // The time rule applies to the merged result, not just to the patch.
    let start = req.start_time.unwrap_or(current.start_time);
    let end = req.end_time.unwrap_or(current.end_time);
    if !times_ok(start, end) {
        return invalid(
            &ctx.rid,
            "invalid_times",
            "end_time needs a start_time and must be later the same day",
        );
    }
    let tz = req.timezone.as_deref().map(str::trim);
    if let Some(tz) = tz
        && let Err(r) = validate_timezone(&client, tz, &ctx.rid).await
    {
        return r;
    }
    let links = MeetingLinks {
        participant_ids: req.participant_ids.as_deref(),
        issue_ids: req.issue_ids.as_deref(),
        epic_ids: req.epic_ids.as_deref(),
        customer_ids: req.customer_ids.as_deref(),
    };
    if let Err(r) = validate_links(&client, ctx.project.id, &links, &ctx.rid).await {
        return r;
    }
    let patch = MeetingPatch {
        title: req.title.as_deref().map(str::trim),
        meeting_date: req.meeting_date,
        start_time: req.start_time,
        end_time: req.end_time,
        timezone: tz,
        location: req.location.as_deref(),
        description: req.description.as_deref(),
        summary: req.summary.as_deref(),
        transcript: req.transcript.as_deref(),
    };
    match mdb::update(
        &mut client,
        ctx.project.id,
        id,
        current.version,
        &patch,
        &links,
    )
    .await
    {
        Ok(UpdateOutcome::Updated(m)) => {
            state.events.publish_meeting(
                MeetingEventKind::Updated,
                ctx.project.id,
                ctx.actor_id,
                id,
            );
            detail_response(&client, StatusCode::OK, m, &ctx.rid).await
        }
        Ok(UpdateOutcome::NotFound) => not_found(&ctx.rid),
        Ok(UpdateOutcome::Conflict) => problem(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "Precondition Failed",
            Some("the meeting changed; reload and retry".to_owned()),
            &ctx.rid,
        ),
        Err(e) => {
            tracing::warn!(error = %e, "meeting update failed");
            internal(&ctx.rid)
        }
    }
}

/// `DELETE /api/v1/projects/{project_id}/meetings/{meeting_id}` — the
/// meeting and its files (files are purged by GC after the grace period).
#[utoipa::path(
    delete, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}", tag = "meetings",
    responses((status = 204), (status = 404))
)]
pub async fn delete(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingDelete) {
        return r;
    }
    let Ok(mut client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match mdb::soft_delete(&mut client, ctx.project.id, id).await {
        Ok(true) => {
            state.events.publish_meeting(
                MeetingEventKind::Deleted,
                ctx.project.id,
                ctx.actor_id,
                id,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// ---------------------------------------------------------------------------
// links
// ---------------------------------------------------------------------------

/// `POST /api/v1/projects/{project_id}/meetings/{meeting_id}/links/{kind}/{target_id}`
/// — `kind` is `participants`, `issues`, `epics` or `customers`.
#[utoipa::path(
    post, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}/links/{kind}/{target_id}",
    tag = "meetings",
    responses((status = 200, body = MeetingDetail), (status = 404), (status = 422))
)]
pub async fn add_link(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id, kind, target)): Path<(Uuid, Uuid, String, Uuid)>,
) -> Response {
    toggle_link(state, ctx, id, &kind, target, true).await
}

/// `DELETE /api/v1/projects/{project_id}/meetings/{meeting_id}/links/{kind}/{target_id}`
#[utoipa::path(
    delete, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}/links/{kind}/{target_id}",
    tag = "meetings",
    responses((status = 200, body = MeetingDetail), (status = 404))
)]
pub async fn remove_link(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id, kind, target)): Path<(Uuid, Uuid, String, Uuid)>,
) -> Response {
    toggle_link(state, ctx, id, &kind, target, false).await
}

async fn toggle_link(
    state: AppState,
    ctx: ProjectContext,
    id: Uuid,
    kind: &str,
    target: Uuid,
    add: bool,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingModify) {
        return r;
    }
    let Some(kind) = LinkKind::parse(kind) else {
        return not_found(&ctx.rid);
    };
    let Ok(mut client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    if add {
        let one = [target];
        let links = match kind {
            LinkKind::Participants => MeetingLinks {
                participant_ids: Some(&one),
                ..MeetingLinks::default()
            },
            LinkKind::Issues => MeetingLinks {
                issue_ids: Some(&one),
                ..MeetingLinks::default()
            },
            LinkKind::Epics => MeetingLinks {
                epic_ids: Some(&one),
                ..MeetingLinks::default()
            },
            LinkKind::Customers => MeetingLinks {
                customer_ids: Some(&one),
                ..MeetingLinks::default()
            },
        };
        if let Err(r) = validate_links(&client, ctx.project.id, &links, &ctx.rid).await {
            return r;
        }
    }
    match mdb::toggle_link(&mut client, ctx.project.id, id, kind, target, add).await {
        Ok(Some(m)) => {
            state.events.publish_meeting(
                MeetingEventKind::Updated,
                ctx.project.id,
                ctx.actor_id,
                id,
            );
            detail_response(&client, StatusCode::OK, m, &ctx.rid).await
        }
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/issues/{id}/meetings`
#[utoipa::path(
    get, path = "/api/v1/projects/{project_id}/issues/{id}/meetings", tag = "meetings",
    responses((status = 200, body = LinkedMeetingsResponse))
)]
pub async fn issue_meetings(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id)): Path<(Uuid, Uuid)>,
) -> Response {
    linked_meetings(state, ctx, id, LinkKind::Issues, Permission::IssueView).await
}

/// `GET /api/v1/projects/{project_id}/epics/{id}/meetings`
#[utoipa::path(
    get, path = "/api/v1/projects/{project_id}/epics/{id}/meetings", tag = "meetings",
    responses((status = 200, body = LinkedMeetingsResponse))
)]
pub async fn epic_meetings(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id)): Path<(Uuid, Uuid)>,
) -> Response {
    linked_meetings(state, ctx, id, LinkKind::Epics, Permission::EpicView).await
}

async fn linked_meetings(
    state: AppState,
    ctx: ProjectContext,
    target: Uuid,
    kind: LinkKind,
    item_perm: Permission,
) -> Response {
    for perm in [item_perm, Permission::MeetingView] {
        if let Err(r) = ctx.require(perm) {
            return r;
        }
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match mdb::list_for_target(&client, ctx.project.id, kind, target).await {
        Ok(meetings) => Json(LinkedMeetingsResponse { meetings }).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/meetings/{meeting_id}/artifacts`
#[utoipa::path(
    get, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}/artifacts", tag = "meetings",
    responses((status = 200, body = MeetingArtifactsResponse))
)]
pub async fn list_artifacts(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingView) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match mdb::get(&client, ctx.project.id, id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&ctx.rid),
        Err(_) => return internal(&ctx.rid),
    }
    match adb::list(&client, "meeting", id).await {
        Ok(artifacts) => Json(MeetingArtifactsResponse { artifacts }).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// Make sure the meeting exists (and is live) before receiving a file for it.
async fn require_meeting(state: &AppState, ctx: &ProjectContext, id: Uuid) -> Result<(), Response> {
    let Ok(client) = state.auth().db.pool.get().await else {
        return Err(internal(&ctx.rid));
    };
    match mdb::get(&client, ctx.project.id, id).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(not_found(&ctx.rid)),
        Err(_) => Err(internal(&ctx.rid)),
    }
}

/// `POST /api/v1/projects/{project_id}/meetings/{meeting_id}/artifacts?kind=`
///
/// Multipart, one file, streamed to disk. Up to the meeting media limit
/// (`INTELLIPILOT_MEETING_MEDIA_MAX_BYTES`, default 2 GiB). A `recording`
/// must be audio or video by its content.
#[utoipa::path(
    post, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}/artifacts", tag = "meetings",
    params(ArtifactQuery),
    responses((status = 201, body = Attachment), (status = 413), (status = 422))
)]
pub async fn upload_artifact(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id)): Path<(Uuid, Uuid)>,
    Query(q): Query<ArtifactQuery>,
    mut multipart: Multipart,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingModify) {
        return r;
    }
    if let Err(r) = require_meeting(&state, &ctx, id).await {
        return r;
    }
    let auth = state.auth();
    let max = auth.attachments.media_max_bytes;
    let (received, fields) =
        match receive_file(&mut multipart, auth.attachments.storage.as_ref(), max).await {
            Ok(v) => v,
            Err(e) => return e.into_response(max, &ctx.rid),
        };
    let kind_raw = q
        .kind
        .or_else(|| fields.get("kind").cloned())
        .unwrap_or_else(|| "other".to_owned());
    let Some(kind) = ArtifactKind::parse(&kind_raw) else {
        return invalid(
            &ctx.rid,
            "invalid_kind",
            "kind must be recording, transcript, summary or other",
        );
    };
    let content_type = match content_type_for(&received.head, &received.filename) {
        Ok(ct) => ct,
        Err(detail) => return mime_mismatch(detail, &ctx.rid),
    };
    if kind == ArtifactKind::Recording
        && !(content_type.starts_with("audio/") || content_type.starts_with("video/"))
    {
        return invalid(
            &ctx.rid,
            "not_media",
            "a recording must be an audio or video file",
        );
    }
    let resp = store_and_record(
        &state,
        &ctx,
        received,
        &content_type,
        "meeting",
        id,
        Some(kind.as_str()),
    )
    .await;
    if resp.status() == StatusCode::CREATED {
        state
            .events
            .publish_meeting(MeetingEventKind::Updated, ctx.project.id, ctx.actor_id, id);
    }
    resp
}

/// `DELETE /api/v1/projects/{project_id}/meetings/{meeting_id}/artifacts/{attachment_id}`
#[utoipa::path(
    delete, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}/artifacts/{attachment_id}",
    tag = "meetings",
    responses((status = 204), (status = 404))
)]
pub async fn delete_artifact(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id, att_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingModify) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // The file must hang off this very meeting.
    match adb::get(&client, ctx.project.id, att_id).await {
        Ok(Some(att)) if att.target_type == "meeting" && att.target_id == id => {}
        Ok(_) => return not_found(&ctx.rid),
        Err(_) => return internal(&ctx.rid),
    }
    match adb::soft_delete(&client, ctx.project.id, att_id).await {
        Ok(true) => {
            state.events.publish_meeting(
                MeetingEventKind::Updated,
                ctx.project.id,
                ctx.actor_id,
                id,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// ---------------------------------------------------------------------------
// transcript / summary import
// ---------------------------------------------------------------------------

/// `POST /api/v1/projects/{project_id}/meetings/{meeting_id}/transcript/import`
///
/// Multipart `.txt`, `.md`, `.vtt` or `.srt`. The text (subtitle timings and
/// tags stripped) replaces the meeting's transcript; the original file is
/// kept as a `transcript` file.
#[utoipa::path(
    post, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}/transcript/import",
    tag = "meetings",
    responses((status = 200, body = MeetingDetail), (status = 422))
)]
pub async fn import_transcript(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id)): Path<(Uuid, Uuid)>,
    multipart: Multipart,
) -> Response {
    import_text(state, ctx, id, multipart, ArtifactKind::Transcript).await
}

/// `POST /api/v1/projects/{project_id}/meetings/{meeting_id}/summary/import`
///
/// Multipart `.md` or `.txt` (subtitle files are accepted too). The text
/// replaces the meeting's summary; the original is kept as a `summary` file.
#[utoipa::path(
    post, path = "/api/v1/projects/{project_id}/meetings/{meeting_id}/summary/import",
    tag = "meetings",
    responses((status = 200, body = MeetingDetail), (status = 422))
)]
pub async fn import_summary(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path((_project_id, id)): Path<(Uuid, Uuid)>,
    multipart: Multipart,
) -> Response {
    import_text(state, ctx, id, multipart, ArtifactKind::Summary).await
}

async fn import_text(
    state: AppState,
    ctx: ProjectContext,
    id: Uuid,
    mut multipart: Multipart,
    kind: ArtifactKind,
) -> Response {
    if let Err(r) = ctx.require(Permission::MeetingModify) {
        return r;
    }
    if let Err(r) = require_meeting(&state, &ctx, id).await {
        return r;
    }
    let auth = state.auth();
    let (received, _) = match receive_file(
        &mut multipart,
        auth.attachments.storage.as_ref(),
        MAX_IMPORT_BYTES,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return e.into_response(MAX_IMPORT_BYTES, &ctx.rid),
    };
    let Some(format) = TextFormat::from_filename(&received.filename) else {
        return invalid(
            &ctx.rid,
            "unsupported_format",
            "expected a .txt, .md, .vtt or .srt file",
        );
    };
    let text = match read_text(&received).await {
        Ok(t) => to_plain_text(&t, format),
        Err(r) => return r(&ctx.rid),
    };
    let limit = if kind == ArtifactKind::Transcript {
        MAX_TRANSCRIPT
    } else {
        MAX_SUMMARY
    };
    if text.chars().count() > limit {
        return invalid(
            &ctx.rid,
            "validation_failed",
            "the imported text is too long",
        );
    }
    let content_type = match format {
        TextFormat::Vtt => "text/vtt",
        TextFormat::Srt | TextFormat::Plain => "text/plain",
    };
    let stored = store_and_record(
        &state,
        &ctx,
        received,
        content_type,
        "meeting",
        id,
        Some(kind.as_str()),
    )
    .await;
    if stored.status() != StatusCode::CREATED {
        return stored;
    }
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let (transcript, summary) = if kind == ArtifactKind::Transcript {
        (Some(text.as_str()), None)
    } else {
        (None, Some(text.as_str()))
    };
    match mdb::set_text(&client, ctx.project.id, id, transcript, summary).await {
        Ok(Some(m)) => {
            state.events.publish_meeting(
                MeetingEventKind::Updated,
                ctx.project.id,
                ctx.actor_id,
                id,
            );
            detail_response(&client, StatusCode::OK, m, &ctx.rid).await
        }
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// Read a spooled text upload as UTF-8.
async fn read_text(received: &Received) -> Result<String, fn(&str) -> Response> {
    let Ok(bytes) = tokio::fs::read(received.path()).await else {
        return Err(internal);
    };
    String::from_utf8(bytes).map_err(|_| -> fn(&str) -> Response {
        |rid| invalid(rid, "invalid_encoding", "the file must be UTF-8 text")
    })
}
