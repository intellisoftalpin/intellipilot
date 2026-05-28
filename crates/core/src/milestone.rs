//! Milestone (sprint) domain type.

use serde::Serialize;
use time::{Date, OffsetDateTime};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Milestone {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub slug: String,
    /// ISO `YYYY-MM-DD`.
    #[schema(value_type = Option<String>)]
    #[serde(with = "crate::serde_date::option")]
    pub start_date: Option<Date>,
    /// ISO `YYYY-MM-DD`.
    #[schema(value_type = Option<String>)]
    #[serde(with = "crate::serde_date::option")]
    pub end_date: Option<Date>,
    pub closed: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub closed_at: Option<OffsetDateTime>,
    pub order: f64,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

/// Sprint statistics for a milestone.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MilestoneStats {
    pub total_points: f64,
    pub completed_points: f64,
    pub total_tasks: i64,
    pub completed_tasks: i64,
}
