//! Meeting persistence: the meeting row, its link sets, and calendar queries.
//! Meeting files live in `attachments` (target_type `meeting`).
#![allow(clippy::too_many_lines)]

use intellipilot_core::meeting::{Meeting, MeetingListItem};
use time::{Date, Time};
use tokio_postgres::Row;
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::DbError;
use crate::backlog::UpdateOutcome;

/// Columns of a full meeting, including its link sets. Soft-deleted issues
/// and epics drop out of the link lists without the link rows being touched,
/// so an undeleted item reappears.
const COLS: &str = "m.id, m.project_id, m.title, m.meeting_date, m.start_time, m.end_time, \
     m.timezone, m.location, m.description, m.summary, m.transcript, m.created_by, \
     m.version, m.created_at, m.modified_at, \
     ARRAY(SELECT p.user_id FROM meeting_participants p \
           WHERE p.meeting_id = m.id ORDER BY p.user_id) AS participant_ids, \
     ARRAY(SELECT mi.issue_id FROM meeting_issues mi \
           JOIN issues i ON i.id = mi.issue_id AND i.deleted_at IS NULL \
           WHERE mi.meeting_id = m.id ORDER BY i.ref) AS issue_ids, \
     ARRAY(SELECT me.epic_id FROM meeting_epics me \
           JOIN epics e ON e.id = me.epic_id AND e.deleted_at IS NULL \
           WHERE me.meeting_id = m.id ORDER BY e.ref) AS epic_ids, \
     ARRAY(SELECT mc.customer_id FROM meeting_customers mc \
           JOIN customers c ON c.id = mc.customer_id \
           WHERE mc.meeting_id = m.id ORDER BY c.name) AS customer_ids";

/// Columns of a calendar row: no long text, just flags and counts.
const LIST_COLS: &str = "m.id, m.project_id, m.title, m.meeting_date, m.start_time, \
     m.end_time, m.timezone, m.location, \
     (m.summary <> '') AS has_summary, (m.transcript <> '') AS has_transcript, \
     (SELECT count(*) FROM attachments a WHERE a.target_type = 'meeting' \
        AND a.target_id = m.id AND a.deleted_at IS NULL AND a.kind = 'recording') \
        AS recording_count, \
     (SELECT count(*) FROM attachments a WHERE a.target_type = 'meeting' \
        AND a.target_id = m.id AND a.deleted_at IS NULL) AS file_count, \
     ARRAY(SELECT p.user_id FROM meeting_participants p \
           WHERE p.meeting_id = m.id ORDER BY p.user_id) AS participant_ids";

/// Calendar order: by day, then untimed meetings first, then by start.
const LIST_ORDER: &str = "m.meeting_date, m.start_time NULLS FIRST, m.title, m.id";

fn row_to_meeting(r: &Row) -> Meeting {
    Meeting {
        id: r.get("id"),
        project_id: r.get("project_id"),
        title: r.get("title"),
        meeting_date: r.get("meeting_date"),
        start_time: r.get("start_time"),
        end_time: r.get("end_time"),
        timezone: r.get("timezone"),
        location: r.get("location"),
        description: r.get("description"),
        summary: r.get("summary"),
        transcript: r.get("transcript"),
        created_by: r.get("created_by"),
        participant_ids: r.get("participant_ids"),
        issue_ids: r.get("issue_ids"),
        epic_ids: r.get("epic_ids"),
        customer_ids: r.get("customer_ids"),
        version: r.get("version"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

fn row_to_item(r: &Row) -> MeetingListItem {
    MeetingListItem {
        id: r.get("id"),
        project_id: r.get("project_id"),
        title: r.get("title"),
        meeting_date: r.get("meeting_date"),
        start_time: r.get("start_time"),
        end_time: r.get("end_time"),
        timezone: r.get("timezone"),
        location: r.get("location"),
        has_summary: r.get("has_summary"),
        has_transcript: r.get("has_transcript"),
        recording_count: r.get("recording_count"),
        file_count: r.get("file_count"),
        participant_ids: r.get("participant_ids"),
    }
}

/// Which link set of a meeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Participants,
    Issues,
    Epics,
    Customers,
}

impl LinkKind {
    /// Parse the URL segment (`participants`, `issues`, `epics`, `customers`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "participants" => Self::Participants,
            "issues" => Self::Issues,
            "epics" => Self::Epics,
            "customers" => Self::Customers,
            _ => return None,
        })
    }

    /// (link table, target column) — static strings, never user input.
    const fn table(self) -> (&'static str, &'static str) {
        match self {
            Self::Participants => ("meeting_participants", "user_id"),
            Self::Issues => ("meeting_issues", "issue_id"),
            Self::Epics => ("meeting_epics", "epic_id"),
            Self::Customers => ("meeting_customers", "customer_id"),
        }
    }

    /// Query counting how many of `$1` (uuid[]) are valid link targets in
    /// project `$2`: live issues/epics, the project's customers, and project
    /// members.
    const fn valid_targets_sql(self) -> &'static str {
        match self {
            Self::Participants => {
                "SELECT count(DISTINCT user_id) AS n FROM memberships \
                 WHERE user_id = ANY($1) AND project_id = $2"
            }
            Self::Issues => {
                "SELECT count(*) AS n FROM issues \
                 WHERE id = ANY($1) AND project_id = $2 AND deleted_at IS NULL"
            }
            Self::Epics => {
                "SELECT count(*) AS n FROM epics \
                 WHERE id = ANY($1) AND project_id = $2 AND deleted_at IS NULL"
            }
            Self::Customers => {
                "SELECT count(*) AS n FROM customers WHERE id = ANY($1) AND project_id = $2"
            }
        }
    }
}

/// The four link sets, each `None` to leave alone or `Some` to replace.
#[derive(Debug, Default, Clone)]
pub struct MeetingLinks<'a> {
    pub participant_ids: Option<&'a [Uuid]>,
    pub issue_ids: Option<&'a [Uuid]>,
    pub epic_ids: Option<&'a [Uuid]>,
    pub customer_ids: Option<&'a [Uuid]>,
}

impl<'a> MeetingLinks<'a> {
    const fn sets(&self) -> [(LinkKind, Option<&'a [Uuid]>); 4] {
        [
            (LinkKind::Participants, self.participant_ids),
            (LinkKind::Issues, self.issue_ids),
            (LinkKind::Epics, self.epic_ids),
            (LinkKind::Customers, self.customer_ids),
        ]
    }
}

/// Check that every id is a valid target of `kind` in the project. Returns
/// the first kind with an invalid id, if any.
pub async fn invalid_link(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    links: &MeetingLinks<'_>,
) -> Result<Option<LinkKind>, DbError> {
    for (kind, ids) in links.sets() {
        let Some(ids) = ids else { continue };
        let mut distinct: Vec<Uuid> = ids.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.is_empty() {
            continue;
        }
        let n: i64 = client
            .query_one(kind.valid_targets_sql(), &[&distinct, &project_id])
            .await?
            .get("n");
        if usize::try_from(n).ok() != Some(distinct.len()) {
            return Ok(Some(kind));
        }
    }
    Ok(None)
}

/// Field set for a new meeting.
#[derive(Debug, Clone)]
pub struct MeetingNew<'a> {
    pub title: &'a str,
    pub meeting_date: Date,
    pub start_time: Option<Time>,
    pub end_time: Option<Time>,
    pub timezone: &'a str,
    pub location: &'a str,
    pub description: &'a str,
    pub summary: &'a str,
    pub transcript: &'a str,
}

/// A partial meeting edit. `None` leaves a field alone; `Some(None)` clears a
/// nullable one.
#[derive(Debug, Default, Clone)]
pub struct MeetingPatch<'a> {
    pub title: Option<&'a str>,
    pub meeting_date: Option<Date>,
    pub start_time: Option<Option<Time>>,
    pub end_time: Option<Option<Time>>,
    pub timezone: Option<&'a str>,
    pub location: Option<&'a str>,
    pub description: Option<&'a str>,
    pub summary: Option<&'a str>,
    pub transcript: Option<&'a str>,
}

/// Whether `tz` is a time zone name PostgreSQL knows.
pub async fn timezone_exists(
    client: &deadpool_postgres::Client,
    tz: &str,
) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1) AS ok",
            &[&tz],
        )
        .await?;
    Ok(row.get("ok"))
}

async fn replace_links(
    tx: &deadpool_postgres::Transaction<'_>,
    meeting_id: Uuid,
    links: &MeetingLinks<'_>,
) -> Result<(), DbError> {
    for (kind, ids) in links.sets() {
        let Some(ids) = ids else { continue };
        let (table, col) = kind.table();
        tx.execute(
            &format!("DELETE FROM {table} WHERE meeting_id = $1"),
            &[&meeting_id],
        )
        .await?;
        tx.execute(
            &format!(
                "INSERT INTO {table} (meeting_id, {col}) \
                 SELECT $1, t FROM unnest($2::uuid[]) AS t ON CONFLICT DO NOTHING"
            ),
            &[&meeting_id, &ids],
        )
        .await?;
    }
    Ok(())
}

pub async fn create(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
    created_by: Uuid,
    new: &MeetingNew<'_>,
    links: &MeetingLinks<'_>,
) -> Result<Meeting, DbError> {
    let tx = client.transaction().await?;
    let row = tx
        .query_one(
            "INSERT INTO meetings (project_id, title, meeting_date, start_time, end_time, \
               timezone, location, description, summary, transcript, created_by) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id",
            &[
                &project_id,
                &new.title,
                &new.meeting_date,
                &new.start_time,
                &new.end_time,
                &new.timezone,
                &new.location,
                &new.description,
                &new.summary,
                &new.transcript,
                &created_by,
            ],
        )
        .await?;
    let id: Uuid = row.get("id");
    replace_links(&tx, id, links).await?;
    let row = tx
        .query_one(
            &format!("SELECT {COLS} FROM meetings m WHERE m.id = $1"),
            &[&id],
        )
        .await?;
    tx.commit().await?;
    Ok(row_to_meeting(&row))
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Meeting>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {COLS} FROM meetings m \
                 WHERE m.id = $1 AND m.project_id = $2 AND m.deleted_at IS NULL"
            ),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_meeting))
}

/// Apply a patch and/or replace link sets, guarded by `expected_version`.
pub async fn update(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    expected_version: i32,
    patch: &MeetingPatch<'_>,
    links: &MeetingLinks<'_>,
) -> Result<UpdateOutcome<Meeting>, DbError> {
    let tx = client.transaction().await?;
    let (start_set, start) = (patch.start_time.is_some(), patch.start_time.flatten());
    let (end_set, end) = (patch.end_time.is_some(), patch.end_time.flatten());
    let params: [&(dyn ToSql + Sync); 21] = [
        &id,
        &project_id,
        &expected_version,
        &patch.title.is_some(),
        &patch.title,
        &patch.meeting_date.is_some(),
        &patch.meeting_date,
        &start_set,
        &start,
        &end_set,
        &end,
        &patch.timezone.is_some(),
        &patch.timezone,
        &patch.location.is_some(),
        &patch.location,
        &patch.description.is_some(),
        &patch.description,
        &patch.summary.is_some(),
        &patch.summary,
        &patch.transcript.is_some(),
        &patch.transcript,
    ];
    let updated = tx
        .query_opt(
            "UPDATE meetings SET \
               title = CASE WHEN $4::bool THEN $5::text ELSE title END, \
               meeting_date = CASE WHEN $6::bool THEN $7::date ELSE meeting_date END, \
               start_time = CASE WHEN $8::bool THEN $9::time ELSE start_time END, \
               end_time = CASE WHEN $10::bool THEN $11::time ELSE end_time END, \
               timezone = CASE WHEN $12::bool THEN $13::text ELSE timezone END, \
               location = CASE WHEN $14::bool THEN $15::text ELSE location END, \
               description = CASE WHEN $16::bool THEN $17::text ELSE description END, \
               summary = CASE WHEN $18::bool THEN $19::text ELSE summary END, \
               transcript = CASE WHEN $20::bool THEN $21::text ELSE transcript END, \
               version = version + 1, modified_at = now() \
             WHERE id = $1 AND project_id = $2 AND version = $3 AND deleted_at IS NULL \
             RETURNING id",
            &params,
        )
        .await?;
    if updated.is_none() {
        let exists = tx
            .query_opt(
                "SELECT 1 FROM meetings WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL",
                &[&id, &project_id],
            )
            .await?
            .is_some();
        tx.rollback().await?;
        return Ok(if exists {
            UpdateOutcome::Conflict
        } else {
            UpdateOutcome::NotFound
        });
    }
    replace_links(&tx, id, links).await?;
    let row = tx
        .query_one(
            &format!("SELECT {COLS} FROM meetings m WHERE m.id = $1"),
            &[&id],
        )
        .await?;
    tx.commit().await?;
    Ok(UpdateOutcome::Updated(row_to_meeting(&row)))
}

/// Set the transcript or summary text outright (an import), bumping the
/// version. Returns `None` when the meeting does not exist.
pub async fn set_text(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    transcript: Option<&str>,
    summary: Option<&str>,
) -> Result<Option<Meeting>, DbError> {
    let n = client
        .execute(
            "UPDATE meetings SET \
               transcript = COALESCE($3, transcript), summary = COALESCE($4, summary), \
               version = version + 1, modified_at = now() \
             WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL",
            &[&id, &project_id, &transcript, &summary],
        )
        .await?;
    if n == 0 {
        return Ok(None);
    }
    get(client, project_id, id).await
}

/// Add (`add = true`) or remove one link. Bumps the meeting's version when
/// the set actually changed. Returns `None` when the meeting does not exist.
pub async fn toggle_link(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    kind: LinkKind,
    target: Uuid,
    add: bool,
) -> Result<Option<Meeting>, DbError> {
    let tx = client.transaction().await?;
    let live = tx
        .query_opt(
            "SELECT 1 FROM meetings WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL \
             FOR UPDATE",
            &[&id, &project_id],
        )
        .await?
        .is_some();
    if !live {
        tx.rollback().await?;
        return Ok(None);
    }
    let (table, col) = kind.table();
    let changed = if add {
        tx.execute(
            &format!(
                "INSERT INTO {table} (meeting_id, {col}) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            ),
            &[&id, &target],
        )
        .await?
    } else {
        tx.execute(
            &format!("DELETE FROM {table} WHERE meeting_id = $1 AND {col} = $2"),
            &[&id, &target],
        )
        .await?
    };
    if changed > 0 {
        tx.execute(
            "UPDATE meetings SET version = version + 1, modified_at = now() WHERE id = $1",
            &[&id],
        )
        .await?;
    }
    let row = tx
        .query_one(
            &format!("SELECT {COLS} FROM meetings m WHERE m.id = $1"),
            &[&id],
        )
        .await?;
    tx.commit().await?;
    Ok(Some(row_to_meeting(&row)))
}

/// Soft-delete a meeting and its files. Returns `false` when nothing matched.
pub async fn soft_delete(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let tx = client.transaction().await?;
    let n = tx
        .execute(
            "UPDATE meetings SET deleted_at = now(), modified_at = now() \
             WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL",
            &[&id, &project_id],
        )
        .await?;
    if n > 0 {
        tx.execute(
            "UPDATE attachments SET deleted_at = now() \
             WHERE target_type = 'meeting' AND target_id = $1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(n > 0)
}

/// Meetings of a project whose date falls in `[from, to]`, calendar order.
pub async fn list_range(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    from: Date,
    to: Date,
) -> Result<Vec<MeetingListItem>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {LIST_COLS} FROM meetings m \
                 WHERE m.project_id = $1 AND m.deleted_at IS NULL \
                   AND m.meeting_date BETWEEN $2 AND $3 \
                 ORDER BY {LIST_ORDER}"
            ),
            &[&project_id, &from, &to],
        )
        .await?;
    Ok(rows.iter().map(row_to_item).collect())
}

/// Meetings linked to an issue or an epic, newest first.
pub async fn list_for_target(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    kind: LinkKind,
    target: Uuid,
) -> Result<Vec<MeetingListItem>, DbError> {
    let (table, col) = kind.table();
    let rows = client
        .query(
            &format!(
                "SELECT {LIST_COLS} FROM meetings m \
                 WHERE m.project_id = $1 AND m.deleted_at IS NULL \
                   AND m.id IN (SELECT meeting_id FROM {table} WHERE {col} = $2) \
                 ORDER BY m.meeting_date DESC, m.start_time DESC NULLS LAST, m.id"
            ),
            &[&project_id, &target],
        )
        .await?;
    Ok(rows.iter().map(row_to_item).collect())
}
