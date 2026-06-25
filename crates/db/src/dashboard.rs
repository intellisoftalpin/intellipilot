//! Dashboard aggregation queries.
//!
//! Two read-only snapshots: [`home`] (the current user's plate across every
//! project) and [`project`] (one project's backlog health, the personal lens,
//! epic readiness, and Kanban throughput). All grouping/counting is pushed into
//! Postgres; the caller passes `today` so timezone handling stays at the HTTP
//! boundary.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use intellipilot_core::dashboard::{
    AttentionItem, EpicReadiness, HomeDashboard, NamedCount, ProjectBucket, ProjectDashboard,
    StatusBucket, WeekCount,
};
use time::{Date, Duration};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const ISO: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");

fn iso(d: Date) -> String {
    d.format(&ISO).unwrap_or_default()
}

fn status_bucket(r: &Row) -> StatusBucket {
    StatusBucket {
        name: r.get("name"),
        color: r.get("color"),
        is_closed: r.get("is_closed"),
        count: r.get("cnt"),
    }
}

// ---------------------------------------------------------------------------
// global home dashboard
// ---------------------------------------------------------------------------

/// The current user's cross-project plate: KPI counts, work by status, open
/// work per project, attention items, and current-year vacation remaining.
pub async fn home(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    today: Date,
) -> Result<HomeDashboard, DbError> {
    let due_soon_end = today + Duration::days(7);

    let k = client
        .query_one(
            "SELECT count(*)::int8 AS total, \
                    count(*) FILTER (WHERE st.is_closed IS NOT TRUE AND i.due_date < $2)::int8 \
                      AS overdue, \
                    count(*) FILTER (WHERE st.is_closed IS NOT TRUE AND i.due_date >= $2 \
                      AND i.due_date <= $3)::int8 AS due_soon \
             FROM issues i LEFT JOIN taxonomy_items st ON st.id = i.status_id \
             WHERE i.assigned_to = $1 AND i.deleted_at IS NULL",
            &[&user_id, &today, &due_soon_end],
        )
        .await?;

    let status_rows = client
        .query(
            "SELECT COALESCE(st.name, '—') AS name, COALESCE(st.color, '') AS color, \
                    COALESCE(st.is_closed, false) AS is_closed, count(*)::int8 AS cnt \
             FROM issues i LEFT JOIN taxonomy_items st ON st.id = i.status_id \
             WHERE i.assigned_to = $1 AND i.deleted_at IS NULL \
             GROUP BY st.name, st.color, st.is_closed \
             ORDER BY is_closed, cnt DESC",
            &[&user_id],
        )
        .await?;
    let by_status = status_rows.iter().map(status_bucket).collect();

    let proj_rows = client
        .query(
            "SELECT p.id, p.slug, p.name, count(*)::int8 AS cnt \
             FROM issues i JOIN projects p ON p.id = i.project_id \
             LEFT JOIN taxonomy_items st ON st.id = i.status_id \
             WHERE i.assigned_to = $1 AND i.deleted_at IS NULL AND st.is_closed IS NOT TRUE \
             GROUP BY p.id, p.slug, p.name \
             ORDER BY cnt DESC, p.name",
            &[&user_id],
        )
        .await?;
    let by_project = proj_rows
        .iter()
        .map(|r| ProjectBucket {
            project_id: r.get("id"),
            slug: r.get("slug"),
            name: r.get("name"),
            open_count: r.get("cnt"),
        })
        .collect();

    let att_rows = client
        .query(
            "SELECT p.id AS project_id, i.id AS issue_id, p.slug AS project_slug, \
                    i.ref AS reference, i.subject, \
                    i.due_date, COALESCE(st.name, '—') AS status_name, \
                    (i.due_date < $2) AS overdue \
             FROM issues i JOIN projects p ON p.id = i.project_id \
             LEFT JOIN taxonomy_items st ON st.id = i.status_id \
             WHERE i.assigned_to = $1 AND i.deleted_at IS NULL AND st.is_closed IS NOT TRUE \
               AND i.due_date IS NOT NULL AND i.due_date <= $3 \
             ORDER BY i.due_date ASC LIMIT 20",
            &[&user_id, &today, &due_soon_end],
        )
        .await?;
    let attention = att_rows
        .iter()
        .map(|r| {
            let due: Option<Date> = r.get("due_date");
            AttentionItem {
                project_id: r.get("project_id"),
                issue_id: r.get("issue_id"),
                project_slug: r.get("project_slug"),
                reference: r.get("reference"),
                subject: r.get("subject"),
                due_date: due.map(iso),
                status_name: r.get("status_name"),
                overdue: r.get("overdue"),
            }
        })
        .collect();

    let balance = crate::time_tracking::vacation_balance(client, user_id).await?;
    let this_year = today.year();
    let vacation_days_left = balance
        .years
        .iter()
        .find(|y| y.year == this_year)
        .map_or(0.0, |y| y.remaining_days);

    Ok(HomeDashboard {
        assigned_total: k.get("total"),
        overdue: k.get("overdue"),
        due_soon: k.get("due_soon"),
        vacation_days_left,
        by_status,
        by_project,
        attention,
    })
}

// ---------------------------------------------------------------------------
// per-project dashboard
// ---------------------------------------------------------------------------

/// All Kanban columns for a project's `issue_status` taxonomy with their issue
/// counts, in board order. When `user` is set, counts only that user's issues.
async fn status_columns(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user: Option<Uuid>,
) -> Result<Vec<StatusBucket>, DbError> {
    let rows = if let Some(uid) = user {
        client
            .query(
                "SELECT t.name, t.color, COALESCE(t.is_closed, false) AS is_closed, \
                        count(i.id)::int8 AS cnt \
                 FROM taxonomy_items t \
                 LEFT JOIN issues i ON i.status_id = t.id AND i.deleted_at IS NULL \
                      AND i.assigned_to = $2 \
                 WHERE t.project_id = $1 AND t.kind = 'issue_status' \
                 GROUP BY t.id, t.name, t.color, t.is_closed, t.\"order\" \
                 ORDER BY t.\"order\"",
                &[&project_id, &uid],
            )
            .await?
    } else {
        client
            .query(
                "SELECT t.name, t.color, COALESCE(t.is_closed, false) AS is_closed, \
                        count(i.id)::int8 AS cnt \
                 FROM taxonomy_items t \
                 LEFT JOIN issues i ON i.status_id = t.id AND i.deleted_at IS NULL \
                 WHERE t.project_id = $1 AND t.kind = 'issue_status' \
                 GROUP BY t.id, t.name, t.color, t.is_closed, t.\"order\" \
                 ORDER BY t.\"order\"",
                &[&project_id],
            )
            .await?
    };
    Ok(rows.iter().map(status_bucket).collect())
}

/// Issue counts grouped by a taxonomy `kind`, joined on `col` (an internal,
/// non-user column name), in taxonomy order.
async fn named_counts(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    col: &str,
    kind: &str,
) -> Result<Vec<NamedCount>, DbError> {
    let sql = format!(
        "SELECT t.name, t.color, count(i.id)::int8 AS cnt \
         FROM taxonomy_items t \
         LEFT JOIN issues i ON i.{col} = t.id AND i.deleted_at IS NULL \
         WHERE t.project_id = $1 AND t.kind = $2 \
         GROUP BY t.id, t.name, t.color, t.\"order\" \
         ORDER BY t.\"order\""
    );
    let rows = client.query(&sql, &[&project_id, &kind]).await?;
    Ok(rows
        .iter()
        .map(|r| NamedCount {
            name: r.get("name"),
            color: r.get("color"),
            count: r.get("cnt"),
        })
        .collect())
}

/// One project's dashboard snapshot.
#[allow(clippy::too_many_lines)] // a flat sequence of independent aggregations
pub async fn project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
    today: Date,
) -> Result<ProjectDashboard, DbError> {
    let k = client
        .query_one(
            "SELECT count(*)::int8 AS total, \
                    count(*) FILTER (WHERE st.is_closed IS NOT TRUE)::int8 AS open, \
                    count(*) FILTER (WHERE st.is_closed IS NOT TRUE AND i.due_date < $3)::int8 \
                      AS overdue, \
                    count(*) FILTER (WHERE st.is_closed IS NOT TRUE AND i.assigned_to IS NULL)::int8 \
                      AS unassigned, \
                    count(*) FILTER (WHERE st.is_closed IS NOT TRUE AND lower(ty.name) = 'bug')::int8 \
                      AS bugs_open, \
                    count(*) FILTER (WHERE st.is_closed IS NOT TRUE AND i.assigned_to = $2)::int8 \
                      AS my_assigned, \
                    count(*) FILTER (WHERE st.is_closed IS NOT TRUE AND i.assigned_to = $2 \
                      AND i.due_date < $3)::int8 AS my_overdue \
             FROM issues i \
             LEFT JOIN taxonomy_items st ON st.id = i.status_id \
             LEFT JOIN taxonomy_items ty ON ty.id = i.type_id \
             WHERE i.project_id = $1 AND i.deleted_at IS NULL",
            &[&project_id, &user_id, &today],
        )
        .await?;

    let by_status = status_columns(client, project_id, None).await?;
    let my_by_status = status_columns(client, project_id, Some(user_id)).await?;
    let by_type = named_counts(client, project_id, "type_id", "issue_type").await?;
    let by_priority = named_counts(client, project_id, "priority_id", "priority").await?;

    // Issues by business category (a fixed enum column, not a taxonomy).
    let cat_rows = client
        .query(
            "SELECT COALESCE(category, 'other') AS name, count(*)::int8 AS cnt \
             FROM issues \
             WHERE project_id = $1 AND deleted_at IS NULL \
             GROUP BY COALESCE(category, 'other') \
             ORDER BY cnt DESC",
            &[&project_id],
        )
        .await?;
    let by_category = cat_rows
        .iter()
        .map(|r| NamedCount {
            name: r.get("name"),
            color: String::new(),
            count: r.get("cnt"),
        })
        .collect();

    let epic_rows = client
        .query(
            "SELECT e.id, e.ref AS reference, e.subject, e.color, \
                    count(i.id)::int8 AS total, \
                    count(i.id) FILTER (WHERE st.is_closed IS TRUE)::int8 AS done, \
                    COALESCE(round(100.0 * count(i.id) FILTER (WHERE st.is_closed IS TRUE) \
                      / NULLIF(count(i.id), 0)), 0)::int4 AS percent \
             FROM epics e \
             LEFT JOIN issues i ON i.epic_id = e.id AND i.deleted_at IS NULL \
             LEFT JOIN taxonomy_items st ON st.id = i.status_id \
             WHERE e.project_id = $1 AND e.deleted_at IS NULL \
             GROUP BY e.id, e.ref, e.subject, e.color, e.\"order\" \
             ORDER BY e.\"order\"",
            &[&project_id],
        )
        .await?;
    let epics = epic_rows
        .iter()
        .map(|r| EpicReadiness {
            epic_id: r.get("id"),
            reference: r.get("reference"),
            subject: r.get("subject"),
            color: r.get("color"),
            total: r.get("total"),
            done: r.get("done"),
            percent: r.get("percent"),
        })
        .collect();

    // Throughput: issues closed per ISO week over the last 8 weeks, zero-filled.
    let offset = i64::from(today.weekday().number_days_from_monday());
    let this_monday = today - Duration::days(offset);
    let start = this_monday - Duration::weeks(7);
    let since = start.midnight().assume_utc();
    let week_rows = client
        .query(
            "SELECT date_trunc('week', i.resolved_at)::date AS wk, count(*)::int8 AS cnt \
             FROM issues i \
             WHERE i.project_id = $1 AND i.deleted_at IS NULL \
               AND i.resolved_at IS NOT NULL AND i.resolved_at >= $2 \
             GROUP BY wk",
            &[&project_id, &since],
        )
        .await?;
    let mut counts: BTreeMap<Date, i64> = BTreeMap::new();
    for r in &week_rows {
        counts.insert(r.get("wk"), r.get("cnt"));
    }
    let mut throughput = Vec::with_capacity(8);
    let mut wk = start;
    for _ in 0..8 {
        throughput.push(WeekCount {
            week_start: iso(wk),
            closed: counts.get(&wk).copied().unwrap_or(0),
        });
        wk += Duration::weeks(1);
    }

    Ok(ProjectDashboard {
        total: k.get("total"),
        open: k.get("open"),
        overdue: k.get("overdue"),
        unassigned: k.get("unassigned"),
        bugs_open: k.get("bugs_open"),
        my_assigned: k.get("my_assigned"),
        my_overdue: k.get("my_overdue"),
        by_status,
        my_by_status,
        by_type,
        by_priority,
        by_category,
        epics,
        throughput,
    })
}
