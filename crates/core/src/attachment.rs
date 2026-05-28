//! Attachment domain type.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// File attached to a backlog entity (or, later, a wiki page). The internal
/// `storage_key` is never exposed.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Attachment {
    pub id: Uuid,
    pub project_id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub uploader_id: Option<Uuid>,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub sha256: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
