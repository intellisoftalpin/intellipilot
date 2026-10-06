//! Dashboard aggregate types: the global (home) dashboard and the per-project
//! dashboard. These are read-only, computed snapshots assembled by the db layer
//! and serialized straight to the HTTP layer.

use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// A count of work items grouped under one status (a Kanban column).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StatusBucket {
    pub name: String,
    pub color: String,
    pub is_closed: bool,
    pub count: i64,
}

/// A generic named breakdown bucket (issue type, priority, …).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct NamedCount {
    pub name: String,
    pub color: String,
    pub count: i64,
}

/// One of the current user's projects on the home dashboard.
///
/// Every project the user is a member of, ordered by how many of its tickets
/// they are involved in (the My Issues roles, closed tickets included), so the
/// projects they work in most come first. That count only orders the list.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ProjectBucket {
    pub project_id: Uuid,
    pub slug: String,
    pub name: String,
    /// Open issues assigned to the user. Kept for clients before 0.7.8,
    /// which print it on the project cards.
    pub open_count: i64,
    pub issue_prefix: String,
    /// Card color (hex).
    pub color: String,
    /// `none` (prefix-initials fallback) or `image` (uploaded icon).
    pub icon_image_kind: String,
    /// Cache-buster for the uploaded icon; `None` when no icon is set.
    #[serde(with = "time::serde::rfc3339::option")]
    pub icon_image_updated_at: Option<time::OffsetDateTime>,
}

/// An assigned issue that needs attention (overdue or due soon).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AttentionItem {
    pub project_id: Uuid,
    pub issue_id: Uuid,
    pub project_slug: String,
    pub reference: i64,
    pub subject: String,
    /// ISO `YYYY-MM-DD`.
    pub due_date: Option<String>,
    pub status_name: String,
    pub overdue: bool,
}

/// The global home dashboard: the current user's plate across every project.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct HomeDashboard {
    pub assigned_total: i64,
    pub overdue: i64,
    pub due_soon: i64,
    pub vacation_days_left: f64,
    pub by_status: Vec<StatusBucket>,
    pub by_project: Vec<ProjectBucket>,
    pub attention: Vec<AttentionItem>,
}

/// Completion of an epic, measured by closed issues over total issues.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EpicReadiness {
    pub epic_id: Uuid,
    pub reference: i64,
    pub subject: String,
    pub color: String,
    pub total: i64,
    pub done: i64,
    /// Rounded 0–100.
    pub percent: i32,
}

/// Issues closed within one ISO week (throughput point).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WeekCount {
    /// ISO `YYYY-MM-DD` of the week's Monday.
    pub week_start: String,
    pub closed: i64,
}

/// The per-project dashboard: backlog health, the personal lens, epic
/// readiness, and Kanban throughput.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ProjectDashboard {
    pub total: i64,
    pub open: i64,
    pub overdue: i64,
    pub unassigned: i64,
    pub bugs_open: i64,
    pub my_assigned: i64,
    pub my_overdue: i64,
    pub by_status: Vec<StatusBucket>,
    pub my_by_status: Vec<StatusBucket>,
    pub by_type: Vec<NamedCount>,
    pub by_priority: Vec<NamedCount>,
    pub by_category: Vec<NamedCount>,
    pub epics: Vec<EpicReadiness>,
    pub throughput: Vec<WeekCount>,
}
