//! Releases and their versions.
//!
//! A [`Release`] is a named product / release line (e.g. "PSBP"); versioning
//! lives in a separate [`ReleaseVersion`] table (1.0, 1.1, …). A version may
//! optionally map to a git tag on a linked repository. Releases may be linked
//! to components ([`ComponentReleaseLink`]); an issue's fix-version points at a
//! specific version.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// A release line / product.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Release {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Lifecycle state of a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    Planned,
    InProgress,
    Released,
}

impl ReleaseStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::InProgress => "in_progress",
            Self::Released => "released",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "planned" => Self::Planned,
            "in_progress" => Self::InProgress,
            "released" => Self::Released,
            _ => return None,
        })
    }
}

/// A concrete version under a release (e.g. "1.1").
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReleaseVersion {
    pub id: Uuid,
    pub release_id: Uuid,
    pub version: String,
    pub status: ReleaseStatus,
    #[serde(with = "crate::serde_date::option")]
    pub target_date: Option<time::Date>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub released_at: Option<OffsetDateTime>,
    pub notes: String,
    /// Optional repository this version's tag lives on.
    pub repository_id: Option<Uuid>,
    /// Optional git tag/branch for this version (e.g. `v1.1.0`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_tag: Option<String>,
    pub order: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A link between a component and a release (many-to-many).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ComponentReleaseLink {
    pub component_id: Uuid,
    pub release_id: Uuid,
    pub release_name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
