//! Backlog domain types: epics, unified issues, comments.
//!
//! The backlog is Jira-style: `epics` are a separate entity; everything else
//! (formerly user stories, tasks and issues) is a single `Issue` whose *type*
//! is a per-project `issue_type` taxonomy item, with sub-tasks expressed via
//! `parent_id` and optional grouping under an epic via `epic_id`.

use serde::Serialize;
use time::{Date, OffsetDateTime};
use utoipa::ToSchema;
use uuid::Uuid;

/// The kind of backlog entity (used for comments/history polymorphism and the
/// ref resolver).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Epic,
    Issue,
}

impl EntityKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Epic => "epic",
            Self::Issue => "issue",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "epic" => Self::Epic,
            "issue" => Self::Issue,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Epic {
    pub id: Uuid,
    pub project_id: Uuid,
    #[serde(rename = "ref")]
    pub reference: i64,
    pub subject: String,
    pub description: String,
    pub status_id: Option<Uuid>,
    pub color: String,
    pub owner_id: Option<Uuid>,
    pub assigned_to: Option<Uuid>,
    /// Milestone this epic belongs to (a milestone is composed of epics).
    pub milestone_id: Option<Uuid>,
    #[serde(with = "crate::serde_date::option")]
    pub start_date: Option<Date>,
    #[serde(with = "crate::serde_date::option")]
    pub end_date: Option<Date>,
    /// Cover image kind: `none` (render the colour swatch) or `image` (uploaded,
    /// served at `GET /epics/{id}/cover-image`).
    pub cover_image_kind: String,
    /// When the cover image last changed — clients use it for cache-busting.
    #[serde(with = "time::serde::rfc3339::option")]
    pub cover_image_updated_at: Option<OffsetDateTime>,
    /// Total non-deleted tasks grouped under this epic (derived; 0 unless the
    /// query hydrated it, e.g. `list_epics`).
    #[serde(default)]
    pub task_total: i64,
    /// Tasks under this epic whose status is closed (derived; for progress).
    #[serde(default)]
    pub task_closed: i64,
    pub order: f64,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

/// Unified work item (Story / Task / Bug / sub-task).
///
/// `type_id` (an `issue_type` taxonomy item) tells Story from Task from Bug;
/// `parent_id` nests sub-tasks; `epic_id` groups under an epic; `milestone_id`
/// assigns to a sprint; `size_id` is the T-shirt estimate.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Issue {
    pub id: Uuid,
    pub project_id: Uuid,
    #[serde(rename = "ref")]
    pub reference: i64,
    pub subject: String,
    pub description: String,
    pub status_id: Option<Uuid>,
    pub type_id: Option<Uuid>,
    pub priority_id: Option<Uuid>,
    /// T-shirt size estimate (taxonomy `size`).
    pub size_id: Option<Uuid>,
    pub epic_id: Option<Uuid>,
    pub parent_id: Option<Uuid>,
    pub milestone_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub assigned_to: Option<Uuid>,
    /// Who tests this issue (informational; distinct from the assignee).
    pub qa_assignee_id: Option<Uuid>,
    /// Who reviews the implementation (informational; a second dev).
    pub reviewer_id: Option<Uuid>,
    /// Business-driver category (fixed enum).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<IssueCategory>,
    /// Requesting customers (meaningful when `category = customer_request`). An
    /// issue may serve several customers (many-to-many).
    pub customer_ids: Vec<Uuid>,
    #[serde(with = "crate::serde_date::option")]
    pub start_date: Option<time::Date>,
    #[serde(with = "crate::serde_date::option")]
    pub due_date: Option<time::Date>,
    /// Why the issue was closed (fixed enum); user-set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
    /// When the issue entered a closed status; system-managed.
    #[serde(with = "time::serde::rfc3339::option")]
    pub resolved_at: Option<OffsetDateTime>,
    /// Fix version (a specific `release_versions` row) when chosen structurally.
    pub release_version_id: Option<Uuid>,
    /// Free-text fix version when no structured release applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_text: Option<String>,
    /// Label ids attached to this issue.
    pub labels: Vec<Uuid>,
    /// Component ids attached to this issue.
    pub components: Vec<Uuid>,
    /// User ids watching this issue.
    pub watchers: Vec<Uuid>,
    pub order: f64,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

/// Business-driver category for an issue (why we're doing it). Fixed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IssueCategory {
    CustomerRequest,
    Compliance,
    Security,
    Roadmap,
    TechnicalDebt,
    Operational,
    ResearchDiscovery,
    Other,
}

impl IssueCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CustomerRequest => "customer_request",
            Self::Compliance => "compliance",
            Self::Security => "security",
            Self::Roadmap => "roadmap",
            Self::TechnicalDebt => "technical_debt",
            Self::Operational => "operational",
            Self::ResearchDiscovery => "research_discovery",
            Self::Other => "other",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "customer_request" => Self::CustomerRequest,
            "compliance" => Self::Compliance,
            "security" => Self::Security,
            "roadmap" => Self::Roadmap,
            "technical_debt" => Self::TechnicalDebt,
            "operational" => Self::Operational,
            "research_discovery" => Self::ResearchDiscovery,
            "other" => Self::Other,
            _ => return None,
        })
    }
}

/// Resolution (why an issue was closed). Fixed set; distinct from status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Fixed,
    WontDo,
    Duplicate,
    CannotReproduce,
}

impl Resolution {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::WontDo => "wont_do",
            Self::Duplicate => "duplicate",
            Self::CannotReproduce => "cannot_reproduce",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "fixed" => Self::Fixed,
            "wont_do" => Self::WontDo,
            "duplicate" => Self::Duplicate,
            "cannot_reproduce" => Self::CannotReproduce,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Comment {
    pub id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub author_id: Option<Uuid>,
    pub body: String,
    pub body_html: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub edited_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The author's avatar + identity for rendering (None for a deleted user
    /// or on the create response, which isn't joined).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<crate::user::UserBrief>,
}

/// Relationship type between two issues. Inverses (*is-blocked-by*,
/// *duplicated-by*) are rendered from the stored direction, not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkType {
    Blocks,
    Relates,
    Duplicates,
}

impl LinkType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocks => "blocks",
            Self::Relates => "relates",
            Self::Duplicates => "duplicates",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "blocks" => Self::Blocks,
            "relates" => Self::Relates,
            "duplicates" => Self::Duplicates,
            _ => return None,
        })
    }
}

/// A relationship from one issue to another, as returned for a given issue.
/// `direction` tells whether the queried issue is the source (`outgoing`) or
/// the target (`incoming`) of the stored link.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IssueLink {
    pub id: Uuid,
    /// The other issue in the relationship.
    pub other_issue_id: Uuid,
    pub other_ref: i64,
    pub other_subject: String,
    pub link_type: LinkType,
    /// `outgoing` or `incoming` relative to the queried issue.
    pub direction: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Strong ETag for an entity revision (`"<id>:<version>"`).
#[must_use]
pub fn etag(id: Uuid, version: i32) -> String {
    format!("\"{id}:{version}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_kind_round_trips() {
        for s in ["epic", "issue"] {
            assert_eq!(EntityKind::parse(s).map(EntityKind::as_str), Some(s));
        }
        assert!(EntityKind::parse("nope").is_none());
        assert!(EntityKind::parse("task").is_none());
    }

    #[test]
    fn etag_is_strong_and_versioned() {
        let id = Uuid::nil();
        assert_eq!(etag(id, 1), "\"00000000-0000-0000-0000-000000000000:1\"");
        assert_ne!(etag(id, 1), etag(id, 2));
    }
}
