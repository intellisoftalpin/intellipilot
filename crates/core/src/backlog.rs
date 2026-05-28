//! Backlog domain types: epics, user stories, tasks, issues, comments.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// The kind of backlog entity (used for comments/history polymorphism and the
/// ref resolver).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Epic,
    UserStory,
    Task,
    Issue,
}

impl EntityKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Epic => "epic",
            Self::UserStory => "user_story",
            Self::Task => "task",
            Self::Issue => "issue",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "epic" => Self::Epic,
            "user_story" => Self::UserStory,
            "task" => Self::Task,
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
    pub order: f64,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserStory {
    pub id: Uuid,
    pub project_id: Uuid,
    #[serde(rename = "ref")]
    pub reference: i64,
    pub subject: String,
    pub description: String,
    pub status_id: Option<Uuid>,
    pub epic_id: Option<Uuid>,
    pub milestone_id: Option<Uuid>,
    pub points_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub assigned_to: Option<Uuid>,
    pub order: f64,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Task {
    pub id: Uuid,
    pub project_id: Uuid,
    #[serde(rename = "ref")]
    pub reference: i64,
    pub subject: String,
    pub description: String,
    pub status_id: Option<Uuid>,
    pub user_story_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub assigned_to: Option<Uuid>,
    pub order: f64,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

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
    pub severity_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub assigned_to: Option<Uuid>,
    /// Label ids attached to this issue.
    pub labels: Vec<Uuid>,
    /// Component ids attached to this issue.
    pub components: Vec<Uuid>,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
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
        for s in ["epic", "user_story", "task", "issue"] {
            assert_eq!(EntityKind::parse(s).map(EntityKind::as_str), Some(s));
        }
        assert!(EntityKind::parse("nope").is_none());
    }

    #[test]
    fn etag_is_strong_and_versioned() {
        let id = Uuid::nil();
        assert_eq!(etag(id, 1), "\"00000000-0000-0000-0000-000000000000:1\"");
        assert_ne!(etag(id, 1), etag(id, 2));
    }
}
