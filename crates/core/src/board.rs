//! Per-user kanban board configuration (named saved views + last-used).
//!
//! `config` is an opaque JSON blob owned by the SPA — it holds the visible
//! columns, column order, the active filter, and the swimlane grouping. The
//! backend stores and returns it verbatim so the shape can evolve without a
//! schema migration.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// A named, per-user saved kanban board state.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BoardView {
    pub id: Uuid,
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}
