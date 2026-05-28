//! Wiki domain types: pages and immutable revisions.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WikiPage {
    pub id: Uuid,
    pub project_id: Uuid,
    pub slug: String,
    pub title: String,
    pub body: String,
    /// Sanitized HTML cache of `body`.
    pub body_html: String,
    /// Current revision number.
    pub version: i32,
    pub editor_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

/// An immutable snapshot of a page at a given revision.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WikiRevision {
    pub id: Uuid,
    pub page_id: Uuid,
    pub rev: i32,
    pub title: String,
    /// Omitted from revision *listings*; present when a single revision is
    /// fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub editor_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
