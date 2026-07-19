//! First-class kanban boards (personal + shared) and the board-data shapes
//! returned by the performant per-column endpoint.
//!
//! A board's `config` is an opaque JSON blob owned by the SPA (visible columns
//! and their order, swimlane grouping, locked filters, display options). The
//! backend stores and returns it verbatim so the shape can evolve without a
//! migration.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// Who can see a board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BoardVisibility {
    /// Visible only to its owner. Any project viewer may create/manage their own.
    Personal,
    /// Visible to every project member. Managing needs `board.shared.*`.
    Shared,
}

impl BoardVisibility {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Shared => "shared",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "personal" => Some(Self::Personal),
            "shared" => Some(Self::Shared),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_shared(self) -> bool {
        matches!(self, Self::Shared)
    }
}

/// A first-class kanban board definition.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Board {
    pub id: Uuid,
    pub project_id: Uuid,
    /// Creator; `None` for the system-seeded default shared board.
    pub owner_id: Option<Uuid>,
    pub visibility: BoardVisibility,
    pub name: String,
    /// Short lowercase slug, unique per project — the board's URL segment
    /// (`/projects/ip/boards/sb`). Auto-derived from the name; editable.
    pub key: String,
    pub color: String,
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    pub order: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

/// One board column (a status bucket): the total matching count plus a capped
/// slice of cards. `cards.len() < total` ⇒ more can be loaded via the paginated
/// issues endpoint scoped to this status.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BoardColumn {
    pub status_id: Option<Uuid>,
    pub total: i64,
    pub cards: Vec<crate::backlog::Issue>,
}

/// One swimlane (a distinct group value) with its per-column buckets.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BoardLane {
    /// The group value as a string (a uuid, or `"none"` for the unset lane).
    pub key: String,
    pub total: i64,
    pub columns: Vec<BoardColumn>,
}
