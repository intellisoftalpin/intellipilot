//! Time-tracking persistence.
//!
//! Covers entries (worked time + absences), multi-day absence bookings,
//! project-month locks, vacation allowances, and the derived report queries
//! (timesheet completeness, vacation balance, team grid, availability).
//!
//! Date math (month bounds, working-day iteration) is done in Rust against
//! `time::Date` so it stays testable and timezone handling lives at the HTTP
//! boundary (the caller passes `today`).
#![allow(clippy::arithmetic_side_effects, clippy::too_many_arguments)]

use intellipilot_core::time_tracking::{
    Availability, DayMinutes, EntryKind, PeriodLock, TeamMemberMonth, TimeEntry, TimeEntryDetail,
    TimesheetSummary, VacationAllowance, VacationBalance, VacationYear,
};
use std::collections::BTreeMap;
use time::{Date, Duration, Month, OffsetDateTime, Weekday};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const ISO: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");

fn iso(d: Date) -> String {
    d.format(&ISO).unwrap_or_default()
}

/// First day of a month, as a typed `Date`.
fn month_start(year: i32, month: u8) -> Result<Date, DbError> {
    let m = Month::try_from(month).map_err(|e| DbError::Build(e.to_string()))?;
    Date::from_calendar_date(year, m, 1).map_err(|e| DbError::Build(e.to_string()))
}

/// Last calendar day of a month.
fn month_end(year: i32, month: u8) -> Result<Date, DbError> {
    let (ny, nm) = if month == 12 {
        (year + 1, Month::January)
    } else {
        (
            year,
            Month::try_from(month + 1).map_err(|e| DbError::Build(e.to_string()))?,
        )
    };
    let next_first =
        Date::from_calendar_date(ny, nm, 1).map_err(|e| DbError::Build(e.to_string()))?;
    Ok(next_first - Duration::days(1))
}

const fn is_working_day(d: Date) -> bool {
    !matches!(d.weekday(), Weekday::Saturday | Weekday::Sunday)
}

// ---------------------------------------------------------------------------
// row mappers
// ---------------------------------------------------------------------------

fn kind_from_row(row: &Row) -> EntryKind {
    let s: String = row.get("kind");
    EntryKind::parse(&s).unwrap_or(EntryKind::Work)
}

fn row_to_entry(row: &Row) -> TimeEntry {
    TimeEntry {
        id: row.get("id"),
        user_id: row.get("user_id"),
        kind: kind_from_row(row),
        project_id: row.get("project_id"),
        issue_id: row.get("issue_id"),
        entry_date: row.get("entry_date"),
        minutes: row.get("minutes"),
        note: row.get("note"),
        booking_id: row.get("booking_id"),
        created_at: row.get("created_at"),
        modified_at: row.get("modified_at"),
        version: row.get("version"),
    }
}

fn row_to_detail(row: &Row) -> TimeEntryDetail {
    TimeEntryDetail {
        id: row.get("id"),
        user_id: row.get("user_id"),
        kind: kind_from_row(row),
        project_id: row.get("project_id"),
        issue_id: row.get("issue_id"),
        entry_date: row.get("entry_date"),
        minutes: row.get("minutes"),
        note: row.get("note"),
        booking_id: row.get("booking_id"),
        created_at: row.get("created_at"),
        modified_at: row.get("modified_at"),
        version: row.get("version"),
        issue_ref: row.get("issue_ref"),
        issue_subject: row.get("issue_subject"),
        project_name: row.get("project_name"),
        project_slug: row.get("project_slug"),
        username: row.get("username"),
        full_name: row.get("full_name"),
    }
}

fn row_to_lock(row: &Row) -> PeriodLock {
    PeriodLock {
        id: row.get("id"),
        project_id: row.get("project_id"),
        year: row.get("year"),
        month: row.get("month"),
        locked_by: row.get("locked_by"),
        locked_at: row.get("locked_at"),
    }
}

fn row_to_allowance(row: &Row) -> VacationAllowance {
    VacationAllowance {
        id: row.get("id"),
        user_id: row.get("user_id"),
        year: row.get("year"),
        allowance_days: row.get("allowance_days"),
        carried_over_days: row.get("carried_over_days"),
        note: row.get("note"),
        set_by: row.get("set_by"),
        created_at: row.get("created_at"),
        modified_at: row.get("modified_at"),
    }
}

// ---------------------------------------------------------------------------
// entries
// ---------------------------------------------------------------------------

/// Insertable time entry.
#[derive(Debug)]
pub struct NewEntry<'a> {
    pub user_id: Uuid,
    pub kind: EntryKind,
    pub project_id: Option<Uuid>,
    pub issue_id: Option<Uuid>,
    pub entry_date: Date,
    pub minutes: i32,
    pub note: &'a str,
    pub booking_id: Option<Uuid>,
}

const ENTRY_COLS: &str = "id, user_id, kind, project_id, issue_id, entry_date, minutes, note, \
                          booking_id, created_at, modified_at, version";

/// Insert a single entry.
pub async fn create_entry(
    client: &deadpool_postgres::Client,
    e: &NewEntry<'_>,
) -> Result<TimeEntry, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO time_entries \
                   (user_id, kind, project_id, issue_id, entry_date, minutes, note, booking_id) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 RETURNING {ENTRY_COLS}"
            ),
            &[
                &e.user_id,
                &e.kind.as_str(),
                &e.project_id,
                &e.issue_id,
                &e.entry_date,
                &e.minutes,
                &e.note,
                &e.booking_id,
            ],
        )
        .await?;
    Ok(row_to_entry(&row))
}

/// Fetch a single entry by id.
pub async fn get_entry(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<TimeEntry>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {ENTRY_COLS} FROM time_entries WHERE id = $1"),
            &[&id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_entry))
}

/// Outcome of an optimistic-concurrency update.
#[derive(Debug)]
pub enum EntryUpdate {
    Updated(Box<TimeEntry>),
    Stale,
    Missing,
}

/// Update an entry's minutes/note, guarded by `expected_version`.
pub async fn update_entry(
    client: &deadpool_postgres::Client,
    id: Uuid,
    minutes: i32,
    note: &str,
    expected_version: i32,
) -> Result<EntryUpdate, DbError> {
    let Some(current) = get_entry(client, id).await? else {
        return Ok(EntryUpdate::Missing);
    };
    if current.version != expected_version {
        return Ok(EntryUpdate::Stale);
    }
    let row = client
        .query_opt(
            &format!(
                "UPDATE time_entries SET minutes = $2, note = $3, version = version + 1 \
                 WHERE id = $1 AND version = $4 RETURNING {ENTRY_COLS}"
            ),
            &[&id, &minutes, &note, &expected_version],
        )
        .await?;
    row.map_or(Ok(EntryUpdate::Stale), |r| {
        Ok(EntryUpdate::Updated(Box::new(row_to_entry(&r))))
    })
}

/// Delete an entry. Returns true if a row was removed.
pub async fn delete_entry(client: &deadpool_postgres::Client, id: Uuid) -> Result<bool, DbError> {
    let n = client
        .execute("DELETE FROM time_entries WHERE id = $1", &[&id])
        .await?;
    Ok(n > 0)
}

const DETAIL_SELECT: &str = "SELECT te.id, te.user_id, te.kind, te.project_id, te.issue_id, \
        te.entry_date, te.minutes, te.note, te.booking_id, te.created_at, te.modified_at, \
        te.version, i.ref AS issue_ref, i.subject AS issue_subject, p.name AS project_name, \
        p.slug AS project_slug, u.username, u.full_name \
     FROM time_entries te \
     LEFT JOIN issues i ON i.id = te.issue_id \
     LEFT JOIN projects p ON p.id = te.project_id \
     LEFT JOIN users u ON u.id = te.user_id";

/// List one user's entries (work + absence) within a date range, optionally
/// filtered to a project and/or a single issue.
pub async fn list_for_user(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    from: Date,
    to: Date,
    project_id: Option<Uuid>,
    issue_id: Option<Uuid>,
) -> Result<Vec<TimeEntryDetail>, DbError> {
    let rows = client
        .query(
            &format!(
                "{DETAIL_SELECT} \
                 WHERE te.user_id = $1 AND te.entry_date BETWEEN $2 AND $3 \
                   AND ($4::uuid IS NULL OR te.project_id = $4) \
                   AND ($5::uuid IS NULL OR te.issue_id = $5) \
                 ORDER BY te.entry_date, te.created_at"
            ),
            &[&user_id, &from, &to, &project_id, &issue_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_detail).collect())
}

/// List a project's work entries within a range (team view), optionally for a
/// single member.
pub async fn list_for_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    from: Date,
    to: Date,
    user_id: Option<Uuid>,
) -> Result<Vec<TimeEntryDetail>, DbError> {
    let rows = client
        .query(
            &format!(
                "{DETAIL_SELECT} \
                 WHERE te.project_id = $1 AND te.kind = 'work' \
                   AND te.entry_date BETWEEN $2 AND $3 \
                   AND ($4::uuid IS NULL OR te.user_id = $4) \
                 ORDER BY u.full_name, te.entry_date, te.created_at"
            ),
            &[&project_id, &from, &to, &user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_detail).collect())
}

// ---------------------------------------------------------------------------
// absence bookings (multi-day)
// ---------------------------------------------------------------------------

/// Materialise a multi-day absence as one entry per date (sharing a
/// `booking_id`). Skips weekends. Returns the booking id and created entries.
pub async fn create_booking(
    client: &mut deadpool_postgres::Client,
    user_id: Uuid,
    kind: EntryKind,
    start: Date,
    end: Date,
    minutes_per_day: i32,
    note: &str,
    skip_weekends: bool,
) -> Result<(Uuid, Vec<TimeEntry>), DbError> {
    let booking_id = Uuid::now_v7();
    let tx = client.transaction().await?;
    let mut created = Vec::new();
    let mut d = start;
    while d <= end {
        if !skip_weekends || is_working_day(d) {
            let row = tx
                .query_one(
                    &format!(
                        "INSERT INTO time_entries \
                           (user_id, kind, entry_date, minutes, note, booking_id) \
                         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {ENTRY_COLS}"
                    ),
                    &[
                        &user_id,
                        &kind.as_str(),
                        &d,
                        &minutes_per_day,
                        &note,
                        &booking_id,
                    ],
                )
                .await?;
            created.push(row_to_entry(&row));
        }
        d += Duration::days(1);
    }
    tx.commit().await?;
    Ok((booking_id, created))
}

/// Delete all entries belonging to a booking owned by `user_id`. Returns the
/// number of rows removed.
pub async fn delete_booking(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    booking_id: Uuid,
) -> Result<u64, DbError> {
    let n = client
        .execute(
            "DELETE FROM time_entries WHERE booking_id = $1 AND user_id = $2",
            &[&booking_id, &user_id],
        )
        .await?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// project-month locks
// ---------------------------------------------------------------------------

/// True if the project's given month is locked.
pub async fn is_locked(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    year: i32,
    month: i32,
) -> Result<bool, DbError> {
    let row = client
        .query_opt(
            "SELECT 1 FROM time_period_locks WHERE project_id = $1 AND year = $2 AND month = $3",
            &[&project_id, &year, &month],
        )
        .await?;
    Ok(row.is_some())
}

/// Lock a project-month (idempotent). Returns the lock row.
pub async fn lock_period(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    year: i32,
    month: i32,
    locked_by: Uuid,
) -> Result<PeriodLock, DbError> {
    let row = client
        .query_one(
            "INSERT INTO time_period_locks (project_id, year, month, locked_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (project_id, year, month) DO UPDATE SET project_id = EXCLUDED.project_id \
             RETURNING id, project_id, year, month, locked_by, locked_at",
            &[&project_id, &year, &month, &locked_by],
        )
        .await?;
    Ok(row_to_lock(&row))
}

/// Unlock a project-month. Returns true if a lock was removed.
pub async fn unlock_period(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    year: i32,
    month: i32,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM time_period_locks WHERE project_id = $1 AND year = $2 AND month = $3",
            &[&project_id, &year, &month],
        )
        .await?;
    Ok(n > 0)
}

/// List all locks for a project (newest first).
pub async fn list_locks(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<PeriodLock>, DbError> {
    let rows = client
        .query(
            "SELECT id, project_id, year, month, locked_by, locked_at \
             FROM time_period_locks WHERE project_id = $1 ORDER BY year DESC, month DESC",
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_lock).collect())
}

// ---------------------------------------------------------------------------
// vacation allowances + balance
// ---------------------------------------------------------------------------

const ALLOWANCE_COLS: &str = "id, user_id, year, allowance_days, carried_over_days, note, \
                              set_by, created_at, modified_at";

/// All allowance rows for a user (newest year first).
pub async fn list_allowances(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<Vec<VacationAllowance>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {ALLOWANCE_COLS} FROM vacation_allowances \
                 WHERE user_id = $1 ORDER BY year DESC"
            ),
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_allowance).collect())
}

/// Create or update a user's allowance for a year.
pub async fn upsert_allowance(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    year: i32,
    allowance_days: f64,
    carried_over_days: f64,
    note: &str,
    set_by: Uuid,
) -> Result<VacationAllowance, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO vacation_allowances \
                   (user_id, year, allowance_days, carried_over_days, note, set_by) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (user_id, year) DO UPDATE SET \
                   allowance_days = EXCLUDED.allowance_days, \
                   carried_over_days = EXCLUDED.carried_over_days, \
                   note = EXCLUDED.note, set_by = EXCLUDED.set_by \
                 RETURNING {ALLOWANCE_COLS}"
            ),
            &[
                &user_id,
                &year,
                &allowance_days,
                &carried_over_days,
                &note,
                &set_by,
            ],
        )
        .await?;
    Ok(row_to_allowance(&row))
}

/// Per-user daily work target in minutes (None if the user does not exist).
pub async fn work_minutes_per_day(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<Option<i32>, DbError> {
    let row = client
        .query_opt(
            "SELECT work_minutes_per_day FROM users WHERE id = $1 AND deleted_at IS NULL",
            &[&user_id],
        )
        .await?;
    Ok(row.map(|r| r.get("work_minutes_per_day")))
}

/// Set a user's daily work target. Returns true if the user row was updated.
pub async fn set_work_minutes_per_day(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    minutes: i32,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE users SET work_minutes_per_day = $2 WHERE id = $1 AND deleted_at IS NULL",
            &[&user_id, &minutes],
        )
        .await?;
    Ok(n > 0)
}

/// Compute a user's vacation balance across all years that have either an
/// allowance row or booked vacation. `used_days` = booked vacation minutes that
/// year ÷ the daily target.
pub async fn vacation_balance(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<VacationBalance, DbError> {
    let target = work_minutes_per_day(client, user_id).await?.unwrap_or(480);
    let per_day = f64::from(target.max(1));

    let allowances = list_allowances(client, user_id).await?;

    // Booked vacation minutes grouped by calendar year.
    let used_rows = client
        .query(
            "SELECT EXTRACT(YEAR FROM entry_date)::int AS yr, sum(minutes)::bigint AS mins \
             FROM time_entries WHERE user_id = $1 AND kind = 'vacation' GROUP BY yr",
            &[&user_id],
        )
        .await?;
    let mut used: BTreeMap<i32, i64> = BTreeMap::new();
    for r in &used_rows {
        used.insert(r.get::<_, i32>("yr"), r.get::<_, i64>("mins"));
    }

    // Union of years that appear in either source.
    let mut years: BTreeMap<i32, (f64, f64)> = BTreeMap::new();
    for a in &allowances {
        years.insert(a.year, (a.allowance_days, a.carried_over_days));
    }
    for y in used.keys() {
        years.entry(*y).or_insert((0.0, 0.0));
    }

    let mut out: Vec<VacationYear> = years
        .into_iter()
        .map(|(year, (allowance, carried))| {
            let used_days =
                f64::from(i32::try_from(used.get(&year).copied().unwrap_or(0)).unwrap_or(i32::MAX))
                    / per_day;
            VacationYear {
                year,
                allowance_days: allowance,
                carried_over_days: carried,
                used_days,
                remaining_days: allowance + carried - used_days,
            }
        })
        .collect();
    out.sort_by(|a, b| b.year.cmp(&a.year));

    Ok(VacationBalance {
        user_id,
        work_minutes_per_day: target,
        years: out,
    })
}

// ---------------------------------------------------------------------------
// reports: timesheet completeness, team grid, availability
// ---------------------------------------------------------------------------

/// Per-date total minutes (all kinds) for a user within `[from, to]`.
async fn minutes_by_date(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    from: Date,
    to: Date,
) -> Result<BTreeMap<Date, i64>, DbError> {
    let rows = client
        .query(
            "SELECT entry_date, sum(minutes)::bigint AS mins FROM time_entries \
             WHERE user_id = $1 AND entry_date BETWEEN $2 AND $3 GROUP BY entry_date",
            &[&user_id, &from, &to],
        )
        .await?;
    let mut map = BTreeMap::new();
    for r in &rows {
        map.insert(r.get::<_, Date>("entry_date"), r.get::<_, i64>("mins"));
    }
    Ok(map)
}

/// Timesheet completeness for `user_id` in the given month. `today` bounds the
/// "expected" range so future working days are not yet flagged as missing.
pub async fn timesheet_summary(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    year: i32,
    month: u8,
    today: Date,
) -> Result<TimesheetSummary, DbError> {
    let target = work_minutes_per_day(client, user_id).await?.unwrap_or(480);
    let start = month_start(year, month)?;
    let end = month_end(year, month)?;
    let by_date = minutes_by_date(client, user_id, start, end).await?;

    let logged_minutes: i64 = by_date.values().copied().sum();

    // Only require days up to and including today.
    let upto = if today < end { today } else { end };
    let mut working_days = 0i32;
    let mut complete_days = 0i32;
    let mut missing_days = Vec::new();
    if upto >= start {
        let mut d = start;
        while d <= upto {
            if is_working_day(d) {
                working_days += 1;
                let logged = by_date.get(&d).copied().unwrap_or(0);
                if logged >= i64::from(target) {
                    complete_days += 1;
                } else {
                    missing_days.push(iso(d));
                }
            }
            d += Duration::days(1);
        }
    }

    Ok(TimesheetSummary {
        year,
        month: i32::from(month),
        work_minutes_per_day: target,
        logged_minutes,
        required_minutes: i64::from(working_days) * i64::from(target),
        working_days,
        complete_days,
        missing_days,
    })
}

/// Team grid: every member's per-day worked minutes for `project_id` in the
/// month (members with no entries still appear, with an empty day list).
pub async fn team_month(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    year: i32,
    month: u8,
) -> Result<Vec<TeamMemberMonth>, DbError> {
    let start = month_start(year, month)?;
    let end = month_end(year, month)?;

    let rows = client
        .query(
            "SELECT m.user_id, u.username, u.full_name, te.entry_date, \
                    sum(te.minutes)::bigint AS mins \
             FROM memberships m JOIN users u ON u.id = m.user_id \
             LEFT JOIN time_entries te ON te.user_id = m.user_id AND te.project_id = $1 \
                  AND te.kind = 'work' AND te.entry_date BETWEEN $2 AND $3 \
             WHERE m.project_id = $1 \
             GROUP BY m.user_id, u.username, u.full_name, te.entry_date \
             ORDER BY u.full_name",
            &[&project_id, &start, &end],
        )
        .await?;

    // Preserve first-seen member order while accumulating days.
    let mut order: Vec<Uuid> = Vec::new();
    let mut acc: BTreeMap<Uuid, TeamMemberMonth> = BTreeMap::new();
    for r in &rows {
        let uid: Uuid = r.get("user_id");
        let entry = acc.entry(uid).or_insert_with(|| {
            order.push(uid);
            TeamMemberMonth {
                user_id: uid,
                username: r.get("username"),
                full_name: r.get("full_name"),
                total_minutes: 0,
                days: Vec::new(),
            }
        });
        let date: Option<Date> = r.get("entry_date");
        if let Some(d) = date {
            let mins: i64 = r.get("mins");
            entry.total_minutes += mins;
            entry.days.push(DayMinutes {
                date: iso(d),
                minutes: mins,
            });
        }
    }
    Ok(order.into_iter().filter_map(|u| acc.remove(&u)).collect())
}

/// Project members who are unavailable on `date` (any non-work entry that day).
pub async fn availability(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    date: Date,
) -> Result<Vec<Availability>, DbError> {
    let rows = client
        .query(
            "SELECT DISTINCT u.id AS user_id, u.username, u.full_name, te.kind, te.minutes \
             FROM memberships m JOIN users u ON u.id = m.user_id \
             JOIN time_entries te ON te.user_id = m.user_id \
             WHERE m.project_id = $1 AND te.entry_date = $2 AND te.kind <> 'work' \
             ORDER BY u.full_name",
            &[&project_id, &date],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Availability {
            user_id: r.get("user_id"),
            username: r.get("username"),
            full_name: r.get("full_name"),
            kind: kind_from_row(r),
            minutes: r.get("minutes"),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// issue assignment lookup (validates work entries)
// ---------------------------------------------------------------------------

/// Project + assignee + soft-delete state of an issue (None if it doesn't
/// exist). Used to validate that a user logs work only against a task assigned
/// to them in the named project.
pub async fn issue_assignment(
    client: &deadpool_postgres::Client,
    issue_id: Uuid,
) -> Result<Option<(Uuid, Option<Uuid>, bool)>, DbError> {
    let row = client
        .query_opt(
            "SELECT project_id, assigned_to, (deleted_at IS NOT NULL) AS is_deleted \
             FROM issues WHERE id = $1",
            &[&issue_id],
        )
        .await?;
    Ok(row.map(|r| {
        (
            r.get::<_, Uuid>("project_id"),
            r.get::<_, Option<Uuid>>("assigned_to"),
            r.get::<_, bool>("is_deleted"),
        )
    }))
}

/// Live tasks assigned to `user_id` across all projects (for the timesheet
/// "log time" picker).
pub async fn assigned_issues_for_user(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<Vec<intellipilot_core::time_tracking::AssignedTask>, DbError> {
    use intellipilot_core::time_tracking::AssignedTask;
    let rows = client
        .query(
            "SELECT i.id, i.project_id, p.name AS project_name, p.slug AS project_slug, \
                    i.ref AS reference, i.subject \
             FROM issues i JOIN projects p ON p.id = i.project_id \
             WHERE i.assigned_to = $1 AND i.deleted_at IS NULL \
             ORDER BY p.name, i.ref",
            &[&user_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| AssignedTask {
            id: r.get("id"),
            project_id: r.get("project_id"),
            project_name: r.get("project_name"),
            project_slug: r.get("project_slug"),
            reference: r.get("reference"),
            subject: r.get("subject"),
        })
        .collect())
}

/// Current UTC date (handlers may pass a tz-adjusted date instead).
#[must_use]
pub fn today_utc() -> Date {
    OffsetDateTime::now_utc().date()
}
