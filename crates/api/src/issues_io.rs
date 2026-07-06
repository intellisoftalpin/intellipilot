//! Issue import (JIRA / IntelliPilot CSV) + export (CSV / XLSX).
//!
//! Import is a two-step flow: `preview` parses the file and reports the
//! distinct type/status/priority/component values (matched against the
//! project's taxonomy) plus unmatched users and warnings — no writes; `commit`
//! takes the file plus a mapping payload and creates the issues, comments and
//! parent/epic links. Categorical values map to existing taxonomy items or are
//! created when the mapping says so; components map to existing only.
#![allow(
    clippy::too_many_lines,
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::module_name_repetitions,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::items_after_statements,
    clippy::collapsible_if
)]

use std::collections::HashMap;

use axum::Json;
use axum::body::Body;
use axum::extract::{Multipart, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use intellipilot_core::perms::Permission;
use intellipilot_core::taxonomy::TaxonomyKind;
use intellipilot_db::backlog::IssueWrite;
use intellipilot_db::{
    audit, backlog as bdb, comments as cdb, components as compdb, labels as labeldb,
    memberships as memdb, milestones as msdb, taxonomy as txdb,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{Date, Month};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{client_ip, user_agent};
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
fn unprocessable(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_csv",
        "Invalid CSV",
        Some(detail.to_owned()),
        rid,
    )
}

const ISO: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");

fn iso(d: Date) -> String {
    d.format(&ISO).unwrap_or_default()
}

// ===========================================================================
// parsing
// ===========================================================================

#[derive(Debug, Default, Clone)]
struct ParsedRow {
    external_id: String,
    external_key: String,
    subject: String,
    description: String,
    type_name: String,
    status_name: String,
    priority_name: String,
    assignee: String,
    reporter: String,
    due_date: Option<Date>,
    components: Vec<String>,
    comments: Vec<String>,
    parent_ref: String,
    epic_ref: String,
}

/// All values (non-empty) across every column whose header equals `name`.
fn values<'a>(
    record: &'a csv::StringRecord,
    cols: &HashMap<String, Vec<usize>>,
    name: &str,
) -> Vec<&'a str> {
    cols.get(name)
        .map(|idxs| {
            idxs.iter()
                .filter_map(|&i| record.get(i))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn first(record: &csv::StringRecord, cols: &HashMap<String, Vec<usize>>, name: &str) -> String {
    values(record, cols, name)
        .first()
        .map(|s| (*s).to_owned())
        .unwrap_or_default()
}

fn strip_hash(s: &str) -> String {
    s.trim().trim_start_matches('#').trim().to_owned()
}

/// Parse a date in ISO (`YYYY-MM-DD`) or JIRA (`13/Apr/26 …`) form.
fn parse_date(s: &str) -> Option<Date> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(d) = Date::parse(s, &ISO) {
        return Some(d);
    }
    // JIRA: take the leading `dd/Mon/yy` token.
    let token = s.split_whitespace().next()?;
    let mut parts = token.split('/');
    let day: u8 = parts.next()?.trim().parse().ok()?;
    let month = month_from_short(parts.next()?)?;
    let yy: i32 = parts.next()?.trim().parse().ok()?;
    let year = if yy < 100 { 2000 + yy } else { yy };
    Date::from_calendar_date(year, month, day).ok()
}

fn month_from_short(m: &str) -> Option<Month> {
    Some(match m.trim().to_ascii_lowercase().as_str() {
        "jan" => Month::January,
        "feb" => Month::February,
        "mar" => Month::March,
        "apr" => Month::April,
        "may" => Month::May,
        "jun" => Month::June,
        "jul" => Month::July,
        "aug" => Month::August,
        "sep" => Month::September,
        "oct" => Month::October,
        "nov" => Month::November,
        "dec" => Month::December,
        _ => return None,
    })
}

/// Re-shape a JIRA comment cell (`<datetime>;<author>;<text>`) into a readable,
/// attributed markdown comment. Falls back to the raw cell.
fn format_comment(raw: &str) -> String {
    let parts: Vec<&str> = raw.splitn(3, ';').collect();
    if parts.len() == 3 && parts[0].contains('/') {
        format!(
            "**{}** ({}):\n\n{}",
            parts[1].trim(),
            parts[0].trim(),
            parts[2].trim()
        )
    } else {
        raw.trim().to_owned()
    }
}

/// Parse CSV bytes into rows. Detects JIRA vs IntelliPilot exports by headers.
fn parse_csv(bytes: &[u8]) -> Result<Vec<ParsedRow>, String> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);
    let headers = reader
        .headers()
        .map_err(|e| format!("bad header: {e}"))?
        .clone();
    let mut cols: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, h) in headers.iter().enumerate() {
        cols.entry(h.trim().to_owned()).or_default().push(i);
    }
    let jira = cols.contains_key("Issue key");
    if !jira && !cols.contains_key("Subject") {
        return Err("unrecognised CSV (expected a JIRA or IntelliPilot issue export)".to_owned());
    }

    let mut out = Vec::new();
    for rec in reader.records() {
        let rec = rec.map_err(|e| format!("bad row: {e}"))?;
        let row = if jira {
            ParsedRow {
                external_id: first(&rec, &cols, "Issue id"),
                external_key: first(&rec, &cols, "Issue key"),
                subject: first(&rec, &cols, "Summary"),
                description: first(&rec, &cols, "Description"),
                type_name: first(&rec, &cols, "Issue Type"),
                status_name: first(&rec, &cols, "Status"),
                priority_name: first(&rec, &cols, "Priority"),
                assignee: first(&rec, &cols, "Assignee"),
                reporter: first(&rec, &cols, "Reporter"),
                due_date: parse_date(&first(&rec, &cols, "Due Date")),
                components: values(&rec, &cols, "Component/s")
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                comments: values(&rec, &cols, "Comment")
                    .into_iter()
                    .map(format_comment)
                    .collect(),
                parent_ref: first(&rec, &cols, "Parent id"),
                epic_ref: first(&rec, &cols, "Custom field (Epic Link)"),
            }
        } else {
            ParsedRow {
                external_id: first(&rec, &cols, "Ref"),
                external_key: first(&rec, &cols, "Ref"),
                subject: first(&rec, &cols, "Subject"),
                description: first(&rec, &cols, "Description"),
                type_name: first(&rec, &cols, "Type"),
                status_name: first(&rec, &cols, "Status"),
                priority_name: first(&rec, &cols, "Priority"),
                assignee: first(&rec, &cols, "Assignee"),
                reporter: first(&rec, &cols, "Reporter"),
                due_date: parse_date(&first(&rec, &cols, "Due date")),
                components: first(&rec, &cols, "Components")
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
                comments: Vec::new(),
                parent_ref: strip_hash(&first(&rec, &cols, "Parent")),
                epic_ref: strip_hash(&first(&rec, &cols, "Epic")),
            }
        };
        if row.subject.is_empty() {
            continue; // skip blank/total rows
        }
        out.push(row);
    }
    Ok(out)
}

// ===========================================================================
// export
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub format: Option<String>,
}

const EXPORT_HEADERS: [&str; 17] = [
    "Ref",
    "Subject",
    "Type",
    "Status",
    "Priority",
    "Size",
    "Assignee",
    "Reporter",
    "Epic",
    "Parent",
    "Milestone",
    "Labels",
    "Components",
    "Start date",
    "Due date",
    "Resolution",
    "Description",
];

/// `GET /api/v1/projects/{project_id}/issues/export`
#[utoipa::path(get, path = "/api/v1/projects/{project_id}/issues/export", responses((status = 200), (status = 403)))]
pub async fn export_issues(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Query(q): Query<ExportQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueView) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let pid = ctx.project.id;

    macro_rules! tax_names {
        ($kind:expr) => {{
            let items = txdb::list(&client, pid, $kind).await.unwrap_or_default();
            items
                .into_iter()
                .map(|i| (i.id, i.name))
                .collect::<HashMap<_, _>>()
        }};
    }
    let statuses = tax_names!(TaxonomyKind::IssueStatus);
    let types = tax_names!(TaxonomyKind::IssueType);
    let priorities = tax_names!(TaxonomyKind::Priority);
    let sizes = tax_names!(TaxonomyKind::Size);
    let members: HashMap<Uuid, String> = memdb::list_for_project(&client, pid)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| {
            let name = if m.full_name.is_empty() {
                m.username
            } else {
                m.full_name
            };
            (m.user_id, name)
        })
        .collect();
    let epics: HashMap<Uuid, i64> = bdb::list_epics(&client, pid)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.id, e.reference))
        .collect();
    let milestones: HashMap<Uuid, String> = msdb::list(&client, pid)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| (m.id, m.name))
        .collect();
    let labels: HashMap<Uuid, String> = labeldb::list(&client, pid)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|l| (l.id, l.name))
        .collect();
    let components: HashMap<Uuid, String> = compdb::list(&client, pid)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| (c.id, c.name))
        .collect();

    let issues = match bdb::list_issues(&client, pid).await {
        Ok(v) => v,
        Err(_) => return internal(&ctx.rid),
    };
    let by_id: HashMap<Uuid, i64> = issues.iter().map(|i| (i.id, i.reference)).collect();

    let opt = |m: &HashMap<Uuid, String>, id: Option<Uuid>| {
        id.and_then(|i| m.get(&i)).cloned().unwrap_or_default()
    };
    let names = |m: &HashMap<Uuid, String>, ids: &[Uuid]| {
        ids.iter()
            .filter_map(|i| m.get(i))
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut rows: Vec<Vec<String>> = Vec::with_capacity(issues.len());
    for i in &issues {
        rows.push(vec![
            format!("#{}", i.reference),
            i.subject.clone(),
            opt(&types, i.type_id),
            opt(&statuses, i.status_id),
            opt(&priorities, i.priority_id),
            opt(&sizes, i.size_id),
            opt(&members, i.assigned_to),
            opt(&members, i.owner_id),
            i.epic_id
                .and_then(|e| epics.get(&e))
                .map(|r| format!("#{r}"))
                .unwrap_or_default(),
            i.parent_id
                .and_then(|p| by_id.get(&p))
                .map(|r| format!("#{r}"))
                .unwrap_or_default(),
            opt(&milestones, i.milestone_id),
            names(&labels, &i.labels),
            names(&components, &i.components),
            i.start_date.map(iso).unwrap_or_default(),
            i.due_date.map(iso).unwrap_or_default(),
            i.resolution
                .map(|r| r.as_str().to_owned())
                .unwrap_or_default(),
            i.description.clone(),
        ]);
    }

    match q
        .format
        .as_deref()
        .unwrap_or("csv")
        .to_ascii_lowercase()
        .as_str()
    {
        "xlsx" => match build_xlsx(&rows) {
            Ok(bytes) => download(
                bytes,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "issues.xlsx",
            ),
            Err(_) => internal(&ctx.rid),
        },
        "csv" => download(build_csv(&rows), "text/csv; charset=utf-8", "issues.csv"),
        _ => unprocessable(&ctx.rid, "format must be csv or xlsx"),
    }
}

fn build_csv(rows: &[Vec<String>]) -> Vec<u8> {
    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record(EXPORT_HEADERS).ok();
    for r in rows {
        w.write_record(r).ok();
    }
    w.into_inner().unwrap_or_default()
}

fn build_xlsx(rows: &[Vec<String>]) -> Result<Vec<u8>, rust_xlsxwriter::XlsxError> {
    use rust_xlsxwriter::{Format, Workbook};
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    let bold = Format::new().set_bold();
    for (c, h) in EXPORT_HEADERS.iter().enumerate() {
        ws.write_string_with_format(0, c as u16, *h, &bold)?;
    }
    for (r, row) in rows.iter().enumerate() {
        for (c, v) in row.iter().enumerate() {
            ws.write_string((r + 1) as u32, c as u16, v)?;
        }
    }
    wb.save_to_buffer()
}

fn download(bytes: Vec<u8>, content_type: &str, filename: &str) -> Response {
    let ct = HeaderValue::from_str(content_type)
        .unwrap_or(HeaderValue::from_static("application/octet-stream"));
    let cd = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .unwrap_or(HeaderValue::from_static("attachment"));
    (
        [
            (header::CONTENT_TYPE, ct),
            (header::CONTENT_DISPOSITION, cd),
        ],
        Body::from(bytes),
    )
        .into_response()
}

// ===========================================================================
// import — preview
// ===========================================================================

/// A distinct categorical value and the project item it already matches (if any).
#[derive(Debug, Serialize, ToSchema)]
pub struct ValueMatch {
    pub value: String,
    pub matched_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportPreview {
    pub issue_count: usize,
    pub types: Vec<ValueMatch>,
    pub statuses: Vec<ValueMatch>,
    pub priorities: Vec<ValueMatch>,
    pub components: Vec<ValueMatch>,
    pub unmatched_users: Vec<String>,
    pub warnings: Vec<String>,
}

/// Read the first `file` field of a multipart body.
async fn read_file(multipart: &mut Multipart, rid: &str) -> Result<Vec<u8>, Response> {
    while let Ok(Some(field)) = multipart.next_field().await {
        let is_file = field.name() == Some("file") || field.file_name().is_some();
        let bytes = field.bytes().await.map_err(|_| {
            problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "Payload Too Large",
                None,
                rid,
            )
        })?;
        if is_file {
            return Ok(bytes.to_vec());
        }
    }
    Err(unprocessable(rid, "no CSV file provided"))
}

/// Read `file` (bytes) + `mapping` (JSON text) fields from a multipart body.
async fn read_file_and_mapping(
    multipart: &mut Multipart,
    rid: &str,
) -> Result<(Vec<u8>, String), Response> {
    let mut file: Option<Vec<u8>> = None;
    let mut mapping = String::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().map(str::to_owned);
        let is_file = name.as_deref() == Some("file") || field.file_name().is_some();
        let bytes = field.bytes().await.map_err(|_| {
            problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "Payload Too Large",
                None,
                rid,
            )
        })?;
        if is_file {
            file = Some(bytes.to_vec());
        } else if name.as_deref() == Some("mapping") {
            mapping = String::from_utf8_lossy(&bytes).into_owned();
        }
    }
    match file {
        Some(f) => Ok((f, mapping)),
        None => Err(unprocessable(rid, "no CSV file provided")),
    }
}

fn distinct(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for v in values {
        if !v.is_empty() && seen.insert(v.to_lowercase()) {
            out.push(v);
        }
    }
    out
}

/// `POST /api/v1/projects/{project_id}/issues/import/preview`
#[utoipa::path(post, path = "/api/v1/projects/{project_id}/issues/import/preview", responses((status = 200), (status = 403), (status = 422)))]
pub async fn import_preview(
    State(state): State<AppState>,
    ctx: ProjectContext,
    mut multipart: Multipart,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueCreate) {
        return r;
    }
    let bytes = match read_file(&mut multipart, &ctx.rid).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let rows = match parse_csv(&bytes) {
        Ok(r) => r,
        Err(e) => return unprocessable(&ctx.rid, &e),
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let pid = ctx.project.id;

    let match_against = |items: &[(String, Uuid)], value: &str| {
        items
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(value))
            .map(|(_, id)| *id)
    };
    let to_pairs = |v: Vec<intellipilot_core::taxonomy::TaxonomyItem>| {
        v.into_iter().map(|i| (i.name, i.id)).collect::<Vec<_>>()
    };
    let types = to_pairs(
        txdb::list(&client, pid, TaxonomyKind::IssueType)
            .await
            .unwrap_or_default(),
    );
    let statuses = to_pairs(
        txdb::list(&client, pid, TaxonomyKind::IssueStatus)
            .await
            .unwrap_or_default(),
    );
    let priorities = to_pairs(
        txdb::list(&client, pid, TaxonomyKind::Priority)
            .await
            .unwrap_or_default(),
    );
    let comps: Vec<(String, Uuid)> = compdb::list(&client, pid)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| (c.name, c.id))
        .collect();
    let users: Vec<(String, Uuid)> = memdb::list_for_project(&client, pid)
        .await
        .unwrap_or_default()
        .into_iter()
        .flat_map(|m| {
            [m.username, m.email, m.full_name]
                .into_iter()
                .filter(|s| !s.is_empty())
                .map(move |s| (s, m.user_id))
        })
        .collect();

    let vm = |values: Vec<String>, items: &[(String, Uuid)]| {
        values
            .into_iter()
            .map(|v| ValueMatch {
                matched_id: match_against(items, &v),
                value: v,
            })
            .collect::<Vec<_>>()
    };

    let unmatched_users = distinct(
        rows.iter()
            .flat_map(|r| [r.assignee.clone(), r.reporter.clone()]),
    )
    .into_iter()
    .filter(|u| match_against(&users, u).is_none())
    .collect::<Vec<_>>();

    let mut warnings = Vec::new();
    if rows.is_empty() {
        warnings.push("No issues found in the file.".to_owned());
    }
    let no_subject = rows.iter().filter(|r| r.subject.trim().is_empty()).count();
    if no_subject > 0 {
        warnings.push(format!(
            "{no_subject} row(s) have no summary and were skipped."
        ));
    }

    let preview = ImportPreview {
        issue_count: rows.len(),
        types: vm(distinct(rows.iter().map(|r| r.type_name.clone())), &types),
        statuses: vm(
            distinct(rows.iter().map(|r| r.status_name.clone())),
            &statuses,
        ),
        priorities: vm(
            distinct(rows.iter().map(|r| r.priority_name.clone())),
            &priorities,
        ),
        components: vm(
            distinct(rows.iter().flat_map(|r| r.components.clone())),
            &comps,
        ),
        unmatched_users,
        warnings,
    };
    Json(preview).into_response()
}

// ===========================================================================
// import — commit
// ===========================================================================

/// One value's resolution: an existing item id, or create a new one named after
/// the value (taxonomy kinds only).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ValueChoice {
    pub value: String,
    #[serde(default)]
    pub target: Option<Uuid>,
    #[serde(default)]
    pub create: bool,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ImportMapping {
    #[serde(default)]
    pub types: Vec<ValueChoice>,
    #[serde(default)]
    pub statuses: Vec<ValueChoice>,
    #[serde(default)]
    pub priorities: Vec<ValueChoice>,
    /// Components map to existing only (`target`); `create` is ignored.
    #[serde(default)]
    pub components: Vec<ValueChoice>,
    /// Unmatched JIRA users map to an existing project member (`target`) or are
    /// skipped (left unassigned). `create` is ignored — users are never created.
    #[serde(default)]
    pub users: Vec<ValueChoice>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportResult {
    pub created_issues: usize,
    pub created_epics: usize,
    pub created_comments: usize,
    pub created_taxonomy: usize,
    pub skipped: Vec<String>,
}

/// `POST /api/v1/projects/{project_id}/issues/import`
#[utoipa::path(post, path = "/api/v1/projects/{project_id}/issues/import", responses((status = 200), (status = 403), (status = 422)))]
pub async fn import_commit(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: axum::http::HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Err(r) = ctx.require(Permission::IssueCreate) {
        return r;
    }
    let (bytes, mapping_json) = match read_file_and_mapping(&mut multipart, &ctx.rid).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mapping: ImportMapping = if mapping_json.trim().is_empty() {
        ImportMapping::default()
    } else {
        match serde_json::from_str(&mapping_json) {
            Ok(m) => m,
            Err(e) => return unprocessable(&ctx.rid, &format!("bad mapping: {e}")),
        }
    };
    let rows = match parse_csv(&bytes) {
        Ok(r) => r,
        Err(e) => return unprocessable(&ctx.rid, &e),
    };
    let Ok(mut client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let pid = ctx.project.id;

    // Resolve each mapping into value(lowercased) -> taxonomy id, creating new
    // items where requested.
    let mut created_taxonomy = 0usize;

    async fn build_value_map(
        client: &deadpool_postgres::Client,
        pid: Uuid,
        kind: TaxonomyKind,
        choices: &[ValueChoice],
        created: &mut usize,
    ) -> HashMap<String, Uuid> {
        // Existing items by lower-cased name — so a "create" choice for a value
        // that already exists reuses it instead of failing on the unique slug.
        let existing: HashMap<String, Uuid> = txdb::list(client, pid, kind)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|i| (i.name.to_lowercase(), i.id))
            .collect();
        let mut map = HashMap::new();
        for c in choices {
            let key = c.value.to_lowercase();
            if let Some(id) = c.target {
                map.insert(key, id);
            } else if c.create && !c.value.trim().is_empty() {
                if let Some(&id) = existing.get(&key) {
                    map.insert(key, id);
                } else if let Ok(item) = txdb::create(
                    client,
                    pid,
                    kind,
                    &c.value,
                    &slugify(&c.value),
                    "#9e9e9e",
                    "",
                    None,
                    None,
                    None,
                )
                .await
                {
                    *created += 1;
                    map.insert(key, item.id);
                }
            }
        }
        map
    }

    let type_map = build_value_map(
        &client,
        pid,
        TaxonomyKind::IssueType,
        &mapping.types,
        &mut created_taxonomy,
    )
    .await;
    let status_map = build_value_map(
        &client,
        pid,
        TaxonomyKind::IssueStatus,
        &mapping.statuses,
        &mut created_taxonomy,
    )
    .await;
    let priority_map = build_value_map(
        &client,
        pid,
        TaxonomyKind::Priority,
        &mapping.priorities,
        &mut created_taxonomy,
    )
    .await;
    let component_map: HashMap<String, Uuid> = mapping
        .components
        .iter()
        .filter_map(|c| c.target.map(|t| (c.value.to_lowercase(), t)))
        .collect();

    // Users: auto-match by username / email / full_name, then overlay the
    // explicit mapping (a chosen project member for each unmatched JIRA user).
    let mut user_map: HashMap<String, Uuid> = memdb::list_for_project(&client, pid)
        .await
        .unwrap_or_default()
        .into_iter()
        .flat_map(|m| {
            [m.username, m.email, m.full_name]
                .into_iter()
                .filter(|s| !s.is_empty())
                .map(move |s| (s.to_lowercase(), m.user_id))
        })
        .collect();
    for c in &mapping.users {
        if let Some(target) = c.target {
            user_map.insert(c.value.to_lowercase(), target);
        }
    }

    let look = |m: &HashMap<String, Uuid>, k: &str| m.get(&k.to_lowercase()).copied();

    // Issue id maps for parent links; epic id maps for epic links. Epics are a
    // separate entity, so a JIRA "Epic"-type row becomes an IntelliPilot epic
    // and a child's epic link resolves against the epic maps (never an issue id
    // — that would violate the epic_id FK).
    let mut by_id: HashMap<String, Uuid> = HashMap::new();
    let mut by_key: HashMap<String, Uuid> = HashMap::new();
    let mut epic_by_id: HashMap<String, Uuid> = HashMap::new();
    let mut epic_by_key: HashMap<String, Uuid> = HashMap::new();
    let mut created_issues = 0usize;
    let mut created_epics = 0usize;
    let mut skipped: Vec<String> = Vec::new();
    let mut created: Vec<(usize, Uuid, bool)> = Vec::new(); // (idx, id, is_epic)

    for (idx, row) in rows.iter().enumerate() {
        // Preserve the source key for traceability.
        let description = if row.external_key.is_empty() {
            row.description.clone()
        } else {
            format!(
                "> Imported from {}\n\n{}",
                row.external_key, row.description
            )
        };
        if row.type_name.eq_ignore_ascii_case("epic") {
            match bdb::create_epic(
                &client,
                pid,
                ctx.actor_id,
                &row.subject,
                &description,
                look(&status_map, &row.status_name),
                "#7e57c2",
                look(&user_map, &row.assignee),
                None,
            )
            .await
            {
                Ok(e) => {
                    created_epics += 1;
                    if !row.external_id.is_empty() {
                        epic_by_id.insert(row.external_id.clone(), e.id);
                    }
                    if !row.external_key.is_empty() {
                        epic_by_key.insert(row.external_key.clone(), e.id);
                    }
                    created.push((idx, e.id, true));
                }
                Err(_) => skipped.push(format!("{}: {}", row.external_key, row.subject)),
            }
            continue;
        }
        let w = IssueWrite {
            subject: &row.subject,
            description: &description,
            status_id: look(&status_map, &row.status_name),
            type_id: look(&type_map, &row.type_name),
            priority_id: look(&priority_map, &row.priority_name),
            size_id: None,
            epic_id: None,
            parent_id: None,
            milestone_id: None,
            assigned_to: look(&user_map, &row.assignee),
            // QA / reviewer are not part of the CSV import format.
            qa_assignee_id: None,
            reviewer_id: None,
            category: None,
            start_date: None,
            due_date: row.due_date,
            resolution: None,
            release_version_id: None,
            release_text: None,
        };
        match bdb::create_issue(&client, pid, ctx.actor_id, &w).await {
            Ok(issue) => {
                created_issues += 1;
                if !row.external_id.is_empty() {
                    by_id.insert(row.external_id.clone(), issue.id);
                }
                if !row.external_key.is_empty() {
                    by_key.insert(row.external_key.clone(), issue.id);
                }
                created.push((idx, issue.id, false));
            }
            Err(_) => skipped.push(format!("{}: {}", row.external_key, row.subject)),
        }
    }

    // Second pass: parent + epic links, components, comments.
    let mut created_comments = 0usize;
    for (idx, id, is_epic) in &created {
        let row = &rows[*idx];
        if !is_epic {
            let parent = by_id
                .get(&row.parent_ref)
                .or_else(|| by_key.get(&row.parent_ref))
                .copied();
            let epic = epic_by_key
                .get(&row.epic_ref)
                .or_else(|| epic_by_id.get(&row.epic_ref))
                .copied();
            if parent.is_some() || epic.is_some() {
                client
                    .execute(
                        "UPDATE issues SET parent_id = COALESCE($2, parent_id), \
                             epic_id = COALESCE($3, epic_id) WHERE id = $1",
                        &[id, &parent, &epic],
                    )
                    .await
                    .ok();
            }
            let comp_ids: Vec<Uuid> = row
                .components
                .iter()
                .filter_map(|c| component_map.get(&c.to_lowercase()).copied())
                .collect();
            if !comp_ids.is_empty() {
                bdb::set_issue_components(&mut client, *id, &comp_ids)
                    .await
                    .ok();
            }
        }
        let target = if *is_epic { "epic" } else { "issue" };
        for body in &row.comments {
            let html = crate::markdown::render(body);
            if cdb::create(&client, pid, target, *id, ctx.actor_id, body, &html)
                .await
                .is_ok()
            {
                created_comments += 1;
            }
        }
    }

    audit::record(
        &client,
        Some(ctx.actor_id),
        "issues_imported",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "project_id": pid, "issues": created_issues, "epics": created_epics, "comments": created_comments }),
    )
    .await;

    Json(ImportResult {
        created_issues,
        created_epics,
        created_comments,
        created_taxonomy,
        skipped,
    })
    .into_response()
}
