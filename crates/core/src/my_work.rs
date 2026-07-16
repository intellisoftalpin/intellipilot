//! Cross-project "my work" listing: the issues a user is involved in, by role.
//!
//! Backs `GET /api/v1/me/issues`, the personal work feed consumed by API
//! clients (MCP servers, scripts). Unlike the per-project backlog listing,
//! rows here span every project and carry enough project context to render a
//! full issue key (`PS-42`) without further lookups.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// The relation between the user and the issues being listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MyIssueRole {
    /// `assigned_to` is the user.
    Assignee,
    /// `owner_id` (the creator/reporter) is the user.
    Reporter,
    /// `reviewer_id` is the user.
    Reviewer,
    /// `qa_assignee_id` is the user.
    Qa,
    /// `@username` appears in the issue description or a comment.
    Mentioned,
}

/// One issue in the personal work feed.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MyIssue {
    pub id: Uuid,
    /// Numeric part of the issue key.
    #[serde(rename = "ref")]
    pub reference: i64,
    /// Full display key, e.g. `PS-42`.
    pub key: String,
    pub subject: String,
    pub project_id: Uuid,
    pub project_slug: String,
    pub project_name: String,
    pub status: Option<String>,
    pub is_closed: bool,
    #[serde(rename = "type")]
    pub issue_type: Option<String>,
    pub priority: Option<String>,
    pub assigned_to: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub reviewer_id: Option<Uuid>,
    pub qa_assignee_id: Option<Uuid>,
    /// ISO date (`YYYY-MM-DD`), if set.
    pub due_date: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}
