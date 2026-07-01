//! Time-tracking domain types: entries (worked time + absences), period locks,
//! vacation allowances, and the derived report shapes (timesheet completeness,
//! vacation balance, team grids, availability).
//!
//! Pure data — no I/O. The persistence layer maps rows onto these and the HTTP
//! layer serialises them.

use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime};
use utoipa::ToSchema;
use uuid::Uuid;

/// The category of a time entry. `Work` is logged against a project/task and
/// `Meeting` against a (optional) project; every other variant is a
/// person-level absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Work,
    Meeting,
    Vacation,
    Illness,
    DayOff,
    Holiday,
}

impl EntryKind {
    /// Stable wire/DB string for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Meeting => "meeting",
            Self::Vacation => "vacation",
            Self::Illness => "illness",
            Self::DayOff => "day_off",
            Self::Holiday => "holiday",
        }
    }

    /// Parse a stored/wire string back into a kind.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "work" => Some(Self::Work),
            "meeting" => Some(Self::Meeting),
            "vacation" => Some(Self::Vacation),
            "illness" => Some(Self::Illness),
            "day_off" => Some(Self::DayOff),
            "holiday" => Some(Self::Holiday),
            _ => None,
        }
    }

    /// True for absences (person-level, project-less). `Work` and `Meeting` are
    /// worked time, not absences.
    #[must_use]
    pub const fn is_absence(self) -> bool {
        !matches!(self, Self::Work | Self::Meeting)
    }
}

/// The kind of meeting a `Meeting` entry represents (optional).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeetingType {
    Daily,
    Planning,
    Troubleshooting,
    Retro,
    Refinement,
    Other,
}

impl MeetingType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Planning => "planning",
            Self::Troubleshooting => "troubleshooting",
            Self::Retro => "retro",
            Self::Refinement => "refinement",
            Self::Other => "other",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "daily" => Some(Self::Daily),
            "planning" => Some(Self::Planning),
            "troubleshooting" => Some(Self::Troubleshooting),
            "retro" => Some(Self::Retro),
            "refinement" => Some(Self::Refinement),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

/// A single time entry. A `work` row carries `project_id` (and usually
/// `issue_id`); an absence row carries neither.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimeEntry {
    pub id: Uuid,
    pub user_id: Uuid,
    pub kind: EntryKind,
    /// The meeting type (only for `kind = meeting`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meeting_type: Option<MeetingType>,
    pub project_id: Option<Uuid>,
    pub issue_id: Option<Uuid>,
    #[serde(with = "crate::serde_date::required")]
    pub entry_date: Date,
    pub minutes: i32,
    pub note: String,
    pub booking_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
    pub version: i32,
}

/// A time entry enriched with joined display fields, for list/grid views.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimeEntryDetail {
    pub id: Uuid,
    pub user_id: Uuid,
    pub kind: EntryKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meeting_type: Option<MeetingType>,
    pub project_id: Option<Uuid>,
    pub issue_id: Option<Uuid>,
    #[serde(with = "crate::serde_date::required")]
    pub entry_date: Date,
    pub minutes: i32,
    pub note: String,
    pub booking_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
    pub version: i32,
    /// Per-project reference of the linked task (None once the task is deleted).
    pub issue_ref: Option<i64>,
    pub issue_subject: Option<String>,
    pub project_name: Option<String>,
    pub project_slug: Option<String>,
    /// Set on team/admin views so each row shows who logged it.
    pub username: Option<String>,
    pub full_name: Option<String>,
}

/// A project-month lock. While present, the project's work entries in the month
/// are read-only to members without `time.manage`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PeriodLock {
    pub id: Uuid,
    pub project_id: Uuid,
    pub year: i32,
    pub month: i32,
    pub locked_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub locked_at: OffsetDateTime,
}

/// Superadmin-managed yearly vacation quota for a user.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct VacationAllowance {
    pub id: Uuid,
    pub user_id: Uuid,
    pub year: i32,
    pub allowance_days: f64,
    pub carried_over_days: f64,
    pub note: String,
    pub set_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

/// One year of a user's vacation accounting (allowance + carryover − used).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct VacationYear {
    pub year: i32,
    pub allowance_days: f64,
    pub carried_over_days: f64,
    pub used_days: f64,
    pub remaining_days: f64,
}

/// A user's full vacation balance across the years that have an allowance row
/// or booked vacation, newest first.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct VacationBalance {
    pub user_id: Uuid,
    pub work_minutes_per_day: i32,
    pub years: Vec<VacationYear>,
}

/// Personal timesheet completeness for a month. `missing_days` lists working
/// days (Mon–Fri, not in the future) whose total logged minutes are under the
/// user's daily target.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimesheetSummary {
    pub year: i32,
    pub month: i32,
    pub work_minutes_per_day: i32,
    pub logged_minutes: i64,
    pub required_minutes: i64,
    pub working_days: i32,
    pub complete_days: i32,
    /// ISO `YYYY-MM-DD` strings.
    pub missing_days: Vec<String>,
}

/// One member's per-day worked minutes within a project for a month (the team
/// grid the admin sees at a glance).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TeamMemberMonth {
    pub user_id: Uuid,
    pub username: String,
    pub full_name: String,
    pub total_minutes: i64,
    pub days: Vec<DayMinutes>,
}

/// Minutes logged on a single date (used inside [`TeamMemberMonth`]).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DayMinutes {
    pub date: String,
    pub minutes: i64,
}

/// A task assigned to the current user, used to populate the "log time"
/// picker on the global timesheet page.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AssignedTask {
    pub id: Uuid,
    pub project_id: Uuid,
    pub project_name: String,
    pub project_slug: String,
    pub reference: i64,
    pub subject: String,
}

/// A project member who is unavailable on a given date (absence in effect).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Availability {
    pub user_id: Uuid,
    pub username: String,
    pub full_name: String,
    pub kind: EntryKind,
    pub minutes: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kind_round_trips() {
        for k in [
            EntryKind::Work,
            EntryKind::Meeting,
            EntryKind::Vacation,
            EntryKind::Illness,
            EntryKind::DayOff,
            EntryKind::Holiday,
        ] {
            assert_eq!(EntryKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(EntryKind::parse("nope"), None);
    }

    #[test]
    fn work_and_meeting_are_not_absences() {
        assert!(!EntryKind::Work.is_absence());
        assert!(!EntryKind::Meeting.is_absence());
        assert!(EntryKind::Vacation.is_absence());
        assert!(EntryKind::Holiday.is_absence());
    }

    #[test]
    fn meeting_type_round_trips() {
        for m in [
            MeetingType::Daily,
            MeetingType::Planning,
            MeetingType::Troubleshooting,
            MeetingType::Retro,
            MeetingType::Refinement,
            MeetingType::Other,
        ] {
            assert_eq!(MeetingType::parse(m.as_str()), Some(m));
        }
        assert_eq!(MeetingType::parse("nope"), None);
    }
}
