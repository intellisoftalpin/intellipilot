//! Project-level Labels and Components (applied to issues).

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// A free-form label (name + color), managed per project, many-to-many with
/// issues.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Label {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub color: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A component (name + color), managed per project, many-to-many with issues.
/// Git repositories are linked separately via [`crate::repo`].
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Component {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub color: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
