//! Backlog entity persistence: epics and the unified issue.
//!
//! The backlog is Jira-style: `epics` are a separate table; everything else
//! (formerly user stories, tasks and issues) is a single `issues` table whose
//! *type* is a per-project `issue_type` taxonomy item, with sub-tasks via
//! `parent_id` and optional grouping under an epic via `epic_id`.
//!
//! Shared concerns: atomic per-project `ref` allocation, optimistic
//! concurrency via a `version` column, soft-delete, and fractional ordering.
#![allow(clippy::too_many_arguments)]

use intellipilot_core::backlog::{Epic, Issue, IssueCategory, Resolution};
use intellipilot_core::ordering::{normalized_ranks, rank_between};
use time::{Date, OffsetDateTime};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

/// Result of an optimistic-concurrency update.
#[derive(Debug)]
pub enum UpdateOutcome<T> {
    Updated(T),
    NotFound,
    Conflict,
}

/// Allocate the next per-project ref atomically (shared across all kinds).
pub async fn alloc_ref(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "INSERT INTO project_ref_counters (project_id, last_ref) VALUES ($1, 1) \
             ON CONFLICT (project_id) DO UPDATE \
               SET last_ref = project_ref_counters.last_ref + 1 \
             RETURNING last_ref",
            &[&project_id],
        )
        .await?;
    Ok(row.get("last_ref"))
}

async fn next_order(
    client: &deadpool_postgres::Client,
    table: &str,
    project_id: Uuid,
) -> Result<f64, DbError> {
    let sql = format!("SELECT max(\"order\") AS m FROM {table} WHERE project_id = $1");
    let row = client.query_one(&sql, &[&project_id]).await?;
    let max: Option<f64> = row.get("m");
    Ok(rank_between(max, None).unwrap_or(1.0))
}

// ==========================================================================
// epics
// ==========================================================================

const EPIC_COLS: &str = "id, project_id, ref, subject, description, status_id, color, \
     owner_id, assigned_to, milestone_id, start_date, end_date, cover_image_kind, \
     cover_image_updated_at, \"order\", version, created_at, modified_at";

fn row_to_epic(r: &Row) -> Epic {
    Epic {
        id: r.get("id"),
        project_id: r.get("project_id"),
        reference: r.get("ref"),
        subject: r.get("subject"),
        description: r.get("description"),
        status_id: r.get("status_id"),
        color: r.get("color"),
        owner_id: r.get("owner_id"),
        assigned_to: r.get("assigned_to"),
        milestone_id: r.get("milestone_id"),
        start_date: r.get("start_date"),
        end_date: r.get("end_date"),
        cover_image_kind: r.get("cover_image_kind"),
        cover_image_updated_at: r.get("cover_image_updated_at"),
        // Derived; hydrated by list_epics / get_epic from the issues table.
        task_total: 0,
        task_closed: 0,
        order: r.get("order"),
        version: r.get("version"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

/// Per-epic task counts for a project: epic_id → (total, closed). Counts only
/// non-deleted issues directly grouped under an epic; "closed" follows the
/// issue's status `is_closed` flag.
pub async fn epic_task_counts(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<std::collections::HashMap<Uuid, (i64, i64)>, DbError> {
    let rows = client
        .query(
            "SELECT i.epic_id, count(*) AS total, \
               count(*) FILTER (WHERE COALESCE(t.is_closed, false)) AS closed \
             FROM issues i LEFT JOIN taxonomy_items t ON t.id = i.status_id \
             WHERE i.project_id = $1 AND i.deleted_at IS NULL AND i.epic_id IS NOT NULL \
             GROUP BY i.epic_id",
            &[&project_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<_, Uuid>("epic_id"),
                (r.get::<_, i64>("total"), r.get::<_, i64>("closed")),
            )
        })
        .collect())
}

/// Task counts for a single epic (total, closed).
pub async fn epic_task_count_one(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    epic_id: Uuid,
) -> Result<(i64, i64), DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS total, \
               count(*) FILTER (WHERE COALESCE(t.is_closed, false)) AS closed \
             FROM issues i LEFT JOIN taxonomy_items t ON t.id = i.status_id \
             WHERE i.project_id = $1 AND i.epic_id = $2 AND i.deleted_at IS NULL",
            &[&project_id, &epic_id],
        )
        .await?;
    Ok((row.get("total"), row.get("closed")))
}

pub async fn create_epic(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    owner_id: Uuid,
    subject: &str,
    description: &str,
    status_id: Option<Uuid>,
    color: &str,
    assigned_to: Option<Uuid>,
    milestone_id: Option<Uuid>,
) -> Result<Epic, DbError> {
    let reference = alloc_ref(client, project_id).await?;
    let order = next_order(client, "epics", project_id).await?;
    let row = client
        .query_one(
            &format!(
                "INSERT INTO epics (project_id, ref, subject, description, status_id, color, \
                   owner_id, assigned_to, milestone_id, \"order\") \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING {EPIC_COLS}"
            ),
            &[
                &project_id,
                &reference,
                &subject,
                &description,
                &status_id,
                &color,
                &owner_id,
                &assigned_to,
                &milestone_id,
                &order,
            ],
        )
        .await?;
    Ok(row_to_epic(&row))
}

pub async fn get_epic(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Epic>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {EPIC_COLS} FROM epics WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL"
            ),
            &[&id, &project_id],
        )
        .await?;
    let Some(r) = row else { return Ok(None) };
    let mut epic = row_to_epic(&r);
    let (total, closed) = epic_task_count_one(client, project_id, epic.id).await?;
    epic.task_total = total;
    epic.task_closed = closed;
    Ok(Some(epic))
}

pub async fn list_epics(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<Epic>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {EPIC_COLS} FROM epics WHERE project_id=$1 AND deleted_at IS NULL ORDER BY \"order\""),
            &[&project_id],
        )
        .await?;
    let counts = epic_task_counts(client, project_id).await?;
    Ok(rows
        .iter()
        .map(|r| {
            let mut epic = row_to_epic(r);
            if let Some(&(total, closed)) = counts.get(&epic.id) {
                epic.task_total = total;
                epic.task_closed = closed;
            }
            epic
        })
        .collect())
}

pub async fn update_epic(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    expected_version: i32,
    subject: &str,
    description: &str,
    status_id: Option<Uuid>,
    color: &str,
    assigned_to: Option<Uuid>,
    milestone_id: Option<Uuid>,
    start_date: Option<Date>,
    end_date: Option<Date>,
) -> Result<UpdateOutcome<Epic>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE epics SET subject=$4, description=$5, status_id=$6, color=$7, \
                   assigned_to=$8, milestone_id=$9, start_date=$10, end_date=$11, \
                   version=version+1 \
                 WHERE id=$1 AND project_id=$2 AND version=$3 AND deleted_at IS NULL \
                 RETURNING {EPIC_COLS}"
            ),
            &[
                &id,
                &project_id,
                &expected_version,
                &subject,
                &description,
                &status_id,
                &color,
                &assigned_to,
                &milestone_id,
                &start_date,
                &end_date,
            ],
        )
        .await?;
    match row {
        Some(r) => {
            let mut epic = row_to_epic(&r);
            let (total, closed) = epic_task_count_one(client, project_id, epic.id).await?;
            epic.task_total = total;
            epic.task_closed = closed;
            Ok(UpdateOutcome::Updated(epic))
        }
        None => Ok(classify_miss(client, "epics", project_id, id, expected_version).await?),
    }
}

// --- epic cover image (mirrors the user-avatar object model) ---------------

/// The stored cover-image object (key + mime) when the epic has an uploaded
/// image, else `None`. For the cover-serving endpoint.
pub async fn epic_cover_object(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<(String, String)>, DbError> {
    let row = client
        .query_opt(
            "SELECT cover_image_storage_key, cover_image_mime FROM epics \
             WHERE id = $1 AND project_id = $2 AND cover_image_kind = 'image' \
               AND deleted_at IS NULL",
            &[&id, &project_id],
        )
        .await?;
    Ok(row.and_then(|r| {
        match (
            r.get::<_, Option<String>>("cover_image_storage_key"),
            r.get::<_, Option<String>>("cover_image_mime"),
        ) {
            (Some(k), Some(m)) => Some((k, m)),
            _ => None,
        }
    }))
}

/// Point an epic's cover at an uploaded image object.
pub async fn set_epic_cover_image(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    storage_key: &str,
    mime: &str,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE epics SET cover_image_kind = 'image', cover_image_storage_key = $3, \
                 cover_image_mime = $4, cover_image_updated_at = now() \
             WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL",
            &[&id, &project_id, &storage_key, &mime],
        )
        .await?;
    Ok(n > 0)
}

/// Reset an epic's cover to the colour-swatch fallback.
pub async fn clear_epic_cover_image(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE epics SET cover_image_kind = 'none', cover_image_storage_key = NULL, \
                 cover_image_mime = NULL, cover_image_updated_at = now() \
             WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// Replace the set of epics belonging to a milestone: detach every epic
/// currently in it, then attach the given ones (all scoped to the project).
pub async fn set_milestone_epics(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    milestone_id: Uuid,
    epic_ids: &[Uuid],
) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE epics SET milestone_id = NULL \
             WHERE project_id = $1 AND milestone_id = $2 AND deleted_at IS NULL",
            &[&project_id, &milestone_id],
        )
        .await?;
    if !epic_ids.is_empty() {
        let ids: Vec<Uuid> = epic_ids.to_vec();
        client
            .execute(
                "UPDATE epics SET milestone_id = $2 \
                 WHERE project_id = $1 AND id = ANY($3) AND deleted_at IS NULL",
                &[&project_id, &milestone_id, &ids],
            )
            .await?;
    }
    Ok(())
}

/// Whether an epic exists in this project (for cross-project assoc checks).
pub async fn epic_in_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    epic_id: Uuid,
) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM epics WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL) AS e",
            &[&epic_id, &project_id],
        )
        .await?;
    Ok(row.get("e"))
}

// ==========================================================================
// issues (unified: Story / Task / Bug / sub-task)
// ==========================================================================

const ISSUE_COLS: &str = "id, project_id, ref, subject, description, status_id, type_id, \
     priority_id, size_id, epic_id, parent_id, milestone_id, owner_id, assigned_to, \
     category, customer_id, start_date, due_date, resolution, resolved_at, \
     release_version_id, release_text, \"order\", version, created_at, modified_at";

fn row_to_issue(r: &Row) -> Issue {
    Issue {
        id: r.get("id"),
        project_id: r.get("project_id"),
        reference: r.get("ref"),
        subject: r.get("subject"),
        description: r.get("description"),
        status_id: r.get("status_id"),
        type_id: r.get("type_id"),
        priority_id: r.get("priority_id"),
        size_id: r.get("size_id"),
        epic_id: r.get("epic_id"),
        parent_id: r.get("parent_id"),
        milestone_id: r.get("milestone_id"),
        owner_id: r.get("owner_id"),
        assigned_to: r.get("assigned_to"),
        category: r
            .get::<_, Option<String>>("category")
            .and_then(|s| IssueCategory::parse(&s)),
        customer_id: r.get("customer_id"),
        start_date: r.get("start_date"),
        due_date: r.get("due_date"),
        resolution: r
            .get::<_, Option<String>>("resolution")
            .and_then(|s| Resolution::parse(&s)),
        resolved_at: r.get("resolved_at"),
        release_version_id: r.get("release_version_id"),
        release_text: r.get("release_text"),
        // Filled by the caller from the junction tables.
        labels: Vec::new(),
        components: Vec::new(),
        watchers: Vec::new(),
        order: r.get("order"),
        version: r.get("version"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

/// User ids watching an issue.
pub async fn issue_watcher_ids(
    client: &deadpool_postgres::Client,
    issue_id: Uuid,
) -> Result<Vec<Uuid>, DbError> {
    let rows = client
        .query(
            "SELECT user_id FROM issue_watchers WHERE issue_id = $1 ORDER BY user_id",
            &[&issue_id],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("user_id")).collect())
}

/// Column values for creating/updating an issue (the full-replace set). The
/// `resolved_at` timestamp is system-managed in SQL from the (new) status, so
/// it is intentionally absent here.
#[derive(Debug, Default)]
pub struct IssueWrite<'a> {
    pub subject: &'a str,
    pub description: &'a str,
    pub status_id: Option<Uuid>,
    pub type_id: Option<Uuid>,
    pub priority_id: Option<Uuid>,
    pub size_id: Option<Uuid>,
    pub epic_id: Option<Uuid>,
    pub parent_id: Option<Uuid>,
    pub milestone_id: Option<Uuid>,
    pub assigned_to: Option<Uuid>,
    pub category: Option<&'a str>,
    pub customer_id: Option<Uuid>,
    pub start_date: Option<Date>,
    pub due_date: Option<Date>,
    pub resolution: Option<&'a str>,
    pub release_version_id: Option<Uuid>,
    pub release_text: Option<&'a str>,
}

/// Label ids attached to an issue.
pub async fn issue_label_ids(
    client: &deadpool_postgres::Client,
    issue_id: Uuid,
) -> Result<Vec<Uuid>, DbError> {
    let rows = client
        .query(
            "SELECT label_id FROM issue_labels WHERE issue_id = $1 ORDER BY label_id",
            &[&issue_id],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("label_id")).collect())
}

/// Component ids attached to an issue.
pub async fn issue_component_ids(
    client: &deadpool_postgres::Client,
    issue_id: Uuid,
) -> Result<Vec<Uuid>, DbError> {
    let rows = client
        .query(
            "SELECT component_id FROM issue_components WHERE issue_id = $1 ORDER BY component_id",
            &[&issue_id],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("component_id")).collect())
}

/// Replace the full set of labels on an issue (validated to be in-project by
/// the caller). Transactional.
pub async fn set_issue_labels(
    client: &mut deadpool_postgres::Client,
    issue_id: Uuid,
    label_ids: &[Uuid],
) -> Result<(), DbError> {
    let tx = client.transaction().await?;
    tx.execute("DELETE FROM issue_labels WHERE issue_id = $1", &[&issue_id])
        .await?;
    for lid in label_ids {
        tx.execute(
            "INSERT INTO issue_labels (issue_id, label_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&issue_id, lid],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Replace the full set of components on an issue.
pub async fn set_issue_components(
    client: &mut deadpool_postgres::Client,
    issue_id: Uuid,
    component_ids: &[Uuid],
) -> Result<(), DbError> {
    let tx = client.transaction().await?;
    tx.execute(
        "DELETE FROM issue_components WHERE issue_id = $1",
        &[&issue_id],
    )
    .await?;
    for cid in component_ids {
        tx.execute(
            "INSERT INTO issue_components (issue_id, component_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&issue_id, cid],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn create_issue(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    owner_id: Uuid,
    w: &IssueWrite<'_>,
) -> Result<Issue, DbError> {
    let reference = alloc_ref(client, project_id).await?;
    let order = next_order(client, "issues", project_id).await?;
    let row = client
        .query_one(
            &format!(
                "INSERT INTO issues (project_id, ref, subject, description, status_id, type_id, \
                   priority_id, size_id, epic_id, parent_id, milestone_id, owner_id, assigned_to, \
                   category, customer_id, start_date, due_date, resolution, release_version_id, \
                   release_text, \"order\", resolved_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21, \
                   CASE WHEN $5::uuid IS NOT NULL \
                          AND (SELECT is_closed FROM taxonomy_items WHERE id = $5::uuid) IS TRUE \
                        THEN now() END) \
                 RETURNING {ISSUE_COLS}"
            ),
            &[
                &project_id,
                &reference,
                &w.subject,
                &w.description,
                &w.status_id,
                &w.type_id,
                &w.priority_id,
                &w.size_id,
                &w.epic_id,
                &w.parent_id,
                &w.milestone_id,
                &owner_id,
                &w.assigned_to,
                &w.category,
                &w.customer_id,
                &w.start_date,
                &w.due_date,
                &w.resolution,
                &w.release_version_id,
                &w.release_text,
                &order,
            ],
        )
        .await?;
    Ok(row_to_issue(&row))
}

pub async fn get_issue(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Issue>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {ISSUE_COLS} FROM issues WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL"),
            &[&id, &project_id],
        )
        .await?;
    match row {
        None => Ok(None),
        Some(r) => {
            let mut issue = row_to_issue(&r);
            issue.labels = issue_label_ids(client, issue.id).await?;
            issue.components = issue_component_ids(client, issue.id).await?;
            issue.watchers = issue_watcher_ids(client, issue.id).await?;
            Ok(Some(issue))
        }
    }
}

pub async fn list_issues(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<Issue>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {ISSUE_COLS} FROM issues WHERE project_id=$1 AND deleted_at IS NULL ORDER BY \"order\""),
            &[&project_id],
        )
        .await?;
    let mut issues = Vec::with_capacity(rows.len());
    for r in &rows {
        let mut issue = row_to_issue(r);
        issue.labels = issue_label_ids(client, issue.id).await?;
        issue.components = issue_component_ids(client, issue.id).await?;
        issue.watchers = issue_watcher_ids(client, issue.id).await?;
        issues.push(issue);
    }
    Ok(issues)
}

pub async fn update_issue(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    expected_version: i32,
    w: &IssueWrite<'_>,
) -> Result<UpdateOutcome<Issue>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE issues SET subject=$4, description=$5, status_id=$6, type_id=$7, \
                   priority_id=$8, size_id=$9, epic_id=$10, parent_id=$11, milestone_id=$12, \
                   assigned_to=$13, category=$14, customer_id=$15, start_date=$16, due_date=$17, \
                   resolution=$18, release_version_id=$19, release_text=$20, \
                   resolved_at = CASE WHEN $6::uuid IS NOT NULL \
                          AND (SELECT is_closed FROM taxonomy_items WHERE id = $6::uuid) IS TRUE \
                        THEN COALESCE(resolved_at, now()) ELSE NULL END, \
                   version=version+1 \
                 WHERE id=$1 AND project_id=$2 AND version=$3 AND deleted_at IS NULL \
                 RETURNING {ISSUE_COLS}"
            ),
            &[
                &id,
                &project_id,
                &expected_version,
                &w.subject,
                &w.description,
                &w.status_id,
                &w.type_id,
                &w.priority_id,
                &w.size_id,
                &w.epic_id,
                &w.parent_id,
                &w.milestone_id,
                &w.assigned_to,
                &w.category,
                &w.customer_id,
                &w.start_date,
                &w.due_date,
                &w.resolution,
                &w.release_version_id,
                &w.release_text,
            ],
        )
        .await?;
    match row {
        Some(r) => Ok(UpdateOutcome::Updated(row_to_issue(&r))),
        None => Ok(classify_miss(client, "issues", project_id, id, expected_version).await?),
    }
}

/// Whether an issue exists in this project (for parent / cross-project checks).
pub async fn issue_in_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    issue_id: Uuid,
) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM issues WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL) AS e",
            &[&issue_id, &project_id],
        )
        .await?;
    Ok(row.get("e"))
}

/// Issues assigned to a milestone (ordered, with labels/components hydrated).
pub async fn issues_in_milestone(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    milestone_id: Uuid,
) -> Result<Vec<Issue>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {ISSUE_COLS} FROM issues \
                 WHERE project_id=$1 AND milestone_id=$2 AND deleted_at IS NULL ORDER BY \"order\""
            ),
            &[&project_id, &milestone_id],
        )
        .await?;
    let mut issues = Vec::with_capacity(rows.len());
    for r in &rows {
        let mut issue = row_to_issue(r);
        issue.labels = issue_label_ids(client, issue.id).await?;
        issue.components = issue_component_ids(client, issue.id).await?;
        issue.watchers = issue_watcher_ids(client, issue.id).await?;
        issues.push(issue);
    }
    Ok(issues)
}

/// Sub-tasks (child issues) of a parent issue, ordered.
pub async fn children_for_parent(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    parent_id: Uuid,
) -> Result<Vec<Issue>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {ISSUE_COLS} FROM issues \
                 WHERE project_id=$1 AND parent_id=$2 AND deleted_at IS NULL ORDER BY \"order\""
            ),
            &[&project_id, &parent_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_issue).collect())
}

// ==========================================================================
// shared helpers
// ==========================================================================

/// After a guarded UPDATE affected no rows, decide whether it was a missing
/// entity (404) or a version conflict (412).
async fn classify_miss<T>(
    client: &deadpool_postgres::Client,
    table: &str,
    project_id: Uuid,
    id: Uuid,
    expected_version: i32,
) -> Result<UpdateOutcome<T>, DbError> {
    let sql =
        format!("SELECT version FROM {table} WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL");
    let row = client.query_opt(&sql, &[&id, &project_id]).await?;
    // The row exists but the guarded update matched nothing → version
    // mismatch (conflict). No row → genuinely missing.
    let _ = expected_version;
    Ok(row.map_or(UpdateOutcome::NotFound, |_| UpdateOutcome::Conflict))
}

/// Soft-delete an entity (any kind) by table. Returns whether a row was hit.
pub async fn soft_delete(
    client: &deadpool_postgres::Client,
    table: &str,
    project_id: Uuid,
    id: Uuid,
    grace_until: OffsetDateTime,
) -> Result<bool, DbError> {
    let sql = format!(
        "UPDATE {table} SET deleted_at = now(), deleted_grace_until = $3 \
         WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL"
    );
    let n = client
        .execute(&sql, &[&id, &project_id, &grace_until])
        .await?;
    Ok(n > 0)
}

/// Whether the entity (by table) is currently in a closed status.
pub async fn is_in_closed_status(
    client: &deadpool_postgres::Client,
    table: &str,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let sql = format!(
        "SELECT COALESCE(t.is_closed, false) AS closed \
         FROM {table} e LEFT JOIN taxonomy_items t ON t.id = e.status_id \
         WHERE e.id=$1 AND e.project_id=$2 AND e.deleted_at IS NULL"
    );
    let row = client.query_opt(&sql, &[&id, &project_id]).await?;
    Ok(row.is_some_and(|r| r.get::<_, bool>("closed")))
}

/// Set the fractional order of an entity (reorder). `table` is trusted (one of
/// our known table names).
pub async fn set_order(
    client: &mut deadpool_postgres::Client,
    table: &str,
    project_id: Uuid,
    id: Uuid,
    before_order: Option<f64>,
    after_order: Option<f64>,
    all_ids_in_target_order: Vec<Uuid>,
) -> Result<bool, DbError> {
    if let Some(rank) = rank_between(before_order, after_order) {
        let sql = format!("UPDATE {table} SET \"order\"=$3 WHERE id=$1 AND project_id=$2");
        let n = client.execute(&sql, &[&id, &project_id, &rank]).await?;
        return Ok(n > 0);
    }
    // Renormalize the provided full order.
    let ranks = normalized_ranks(all_ids_in_target_order.len());
    let tx = client.transaction().await?;
    let sql = format!("UPDATE {table} SET \"order\"=$3 WHERE id=$1 AND project_id=$2");
    for (oid, rank) in all_ids_in_target_order.iter().zip(ranks.iter()) {
        tx.execute(&sql, &[oid, &project_id, rank]).await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Resolve a per-project ref to (kind, id).
pub async fn resolve_ref(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    reference: i64,
) -> Result<Option<(&'static str, Uuid)>, DbError> {
    for (table, kind) in [("epics", "epic"), ("issues", "issue")] {
        let sql =
            format!("SELECT id FROM {table} WHERE project_id=$1 AND ref=$2 AND deleted_at IS NULL");
        if let Some(row) = client.query_opt(&sql, &[&project_id, &reference]).await? {
            return Ok(Some((kind, row.get("id"))));
        }
    }
    Ok(None)
}

/// Count backlog references to a taxonomy item (for delete-in-use guard).
pub async fn taxonomy_reference_count(
    client: &deadpool_postgres::Client,
    item_id: Uuid,
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT \
               (SELECT count(*) FROM epics WHERE status_id=$1) \
             + (SELECT count(*) FROM issues \
                  WHERE status_id=$1 OR type_id=$1 OR priority_id=$1 OR size_id=$1) \
             AS n",
            &[&item_id],
        )
        .await?;
    Ok(row.get("n"))
}

// ==========================================================================
// bulk purge (project danger zone — hard, irreversible)
// ==========================================================================

/// Of the storage keys just removed (within `tx`), the ones no surviving
/// attachment row still references — safe to delete from object storage.
/// Mirrors the content-addressed dedup check in `attachments::gc`.
async fn orphan_storage_keys(
    tx: &tokio_postgres::Transaction<'_>,
    removed: &[Row],
) -> Result<Vec<String>, DbError> {
    let mut keys: Vec<String> = removed
        .iter()
        .map(|r| r.get::<_, String>("storage_key"))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let still = tx
        .query(
            "SELECT DISTINCT storage_key FROM attachments WHERE storage_key = ANY($1)",
            &[&keys],
        )
        .await?;
    let still: Vec<String> = still
        .iter()
        .map(|r| r.get::<_, String>("storage_key"))
        .collect();
    keys.retain(|k| !still.contains(k));
    Ok(keys)
}

/// Hard-delete every issue in a project. Irreversible.
///
/// Also removes their comments/history/attachment rows; junction rows
/// (labels/components/links/watchers) cascade via FK; time logs detach
/// (`issue_id` → NULL); sub-task `parent_id` clears. Returns the issue count and
/// the now-orphaned attachment storage keys (the caller deletes those blobs).
pub async fn purge_project_issues(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<(u64, Vec<String>), DbError> {
    let tx = client.transaction().await?;
    tx.execute(
        "DELETE FROM comments WHERE target_type = 'issue' \
           AND target_id IN (SELECT id FROM issues WHERE project_id = $1)",
        &[&project_id],
    )
    .await?;
    tx.execute(
        "DELETE FROM history_entries WHERE target_type = 'issue' \
           AND target_id IN (SELECT id FROM issues WHERE project_id = $1)",
        &[&project_id],
    )
    .await?;
    let removed = tx
        .query(
            "DELETE FROM attachments WHERE target_type = 'issue' \
               AND target_id IN (SELECT id FROM issues WHERE project_id = $1) \
             RETURNING storage_key",
            &[&project_id],
        )
        .await?;
    let n = tx
        .execute("DELETE FROM issues WHERE project_id = $1", &[&project_id])
        .await?;
    let orphans = orphan_storage_keys(&tx, &removed).await?;
    tx.commit().await?;
    Ok((n, orphans))
}

/// Hard-delete every epic in a project. Irreversible.
///
/// Also removes their comments/history/attachment rows. Issues are kept; their
/// `epic_id` clears automatically (FK `ON DELETE SET NULL`). Returns the epic
/// count and orphaned attachment storage keys.
pub async fn purge_project_epics(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<(u64, Vec<String>), DbError> {
    let tx = client.transaction().await?;
    tx.execute(
        "DELETE FROM comments WHERE target_type = 'epic' \
           AND target_id IN (SELECT id FROM epics WHERE project_id = $1)",
        &[&project_id],
    )
    .await?;
    tx.execute(
        "DELETE FROM history_entries WHERE target_type = 'epic' \
           AND target_id IN (SELECT id FROM epics WHERE project_id = $1)",
        &[&project_id],
    )
    .await?;
    let removed = tx
        .query(
            "DELETE FROM attachments WHERE target_type = 'epic' \
               AND target_id IN (SELECT id FROM epics WHERE project_id = $1) \
             RETURNING storage_key",
            &[&project_id],
        )
        .await?;
    let n = tx
        .execute("DELETE FROM epics WHERE project_id = $1", &[&project_id])
        .await?;
    let orphans = orphan_storage_keys(&tx, &removed).await?;
    tx.commit().await?;
    Ok((n, orphans))
}
