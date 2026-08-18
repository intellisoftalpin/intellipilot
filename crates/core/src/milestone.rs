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
    /// Free-form markdown notes. Empty string when unset.
    pub description: String,
    /// ISO `YYYY-MM-DD`.
    #[schema(value_type = Option<String>)]
    #[serde(with = "crate::serde_date::option")]
    pub start_date: Option<Date>,
    /// The *planned* technical release date. ISO `YYYY-MM-DD`.
    #[schema(value_type = Option<String>)]
    #[serde(with = "crate::serde_date::option")]
    pub end_date: Option<Date>,
    /// When the milestone actually finished. `None` while it is still open or
    /// was never recorded. The gap against [`Self::end_date`] is the slip —
    /// or, when earlier, the time saved. ISO `YYYY-MM-DD`.
    #[schema(value_type = Option<String>)]
    #[serde(with = "crate::serde_date::option")]
    pub actual_end_date: Option<Date>,
    /// Commercial ship date, always strictly after whichever technical end
    /// really happened — [`Self::actual_end_date`] when set, otherwise
    /// [`Self::end_date`].
    ///
    /// Visible only to holders of `milestone.business_release.view`; the API
    /// strips the field entirely for everyone else, so an absent key means
    /// either "unset" or "not yours to see" — deliberately indistinguishable.
    #[schema(value_type = Option<String>)]
    #[serde(with = "crate::serde_date::option")]
    pub business_release_date: Option<Date>,
    /// `true` once the milestone is marked completed. Reversible.
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
