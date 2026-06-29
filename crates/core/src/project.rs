//! Project, role, membership, and invitation domain types.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::perms::Permission;

/// Who can see a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Visible only to members. Non-members get 404 (no existence disclosure).
    Private,
    /// Visible (read) to any authenticated user.
    Internal,
    /// Readable without authentication.
    PublicReadonly,
}

impl Visibility {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Internal => "internal",
            Self::PublicReadonly => "public_readonly",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "private" => Some(Self::Private),
            "internal" => Some(Self::Internal),
            "public_readonly" => Some(Self::PublicReadonly),
            _ => None,
        }
    }
}

/// Per-project configuration for the epics board's columns.
///
/// The board has three mutually-exclusive columns: **All**, **In Progress** and
/// **Done**. `in_progress_status_ids` lists the `issue_status` taxonomy items
/// that land in *In Progress*; *Done* is derived from `is_closed` statuses; and
/// *All* is the remainder (no status, or any status in neither bucket). An empty
/// list means nothing is mapped yet (everything sits in *All* / *Done*).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct EpicBoardSettings {
    #[serde(default)]
    pub in_progress_status_ids: Vec<Uuid>,
}

/// Predefined card-color palette (kept in sync with the frontend
/// `ColorPalette.swatches`). New projects without an explicit color get a
/// random entry; existing projects are backfilled deterministically.
pub const PROJECT_COLORS: [&str; 10] = [
    "#999999", "#ff8a84", "#ffcc00", "#9dce0a", "#669900", "#0079bc", "#5c3566", "#cc0000",
    "#ff7518", "#34495e",
];

#[derive(Debug, Clone, Serialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)] // feature flags, not state machine
pub struct Project {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub owner_id: Uuid,
    pub visibility: Visibility,
    /// Issue-key prefix: 2–3 uppercase letters, globally unique. Issue keys
    /// render as `<issue_prefix>-<ref>`, epic keys as `<issue_prefix>-E-<ref>`.
    pub issue_prefix: String,
    /// Card color (hex, from `PROJECT_COLORS`).
    pub color: String,
    /// `none` (render prefix-initials fallback) or `image` (uploaded icon).
    pub icon_image_kind: String,
    /// Cache-buster for the uploaded icon; `None` when no icon is set.
    #[serde(with = "time::serde::rfc3339::option")]
    pub icon_image_updated_at: Option<OffsetDateTime>,
    pub kanban_enabled: bool,
    pub backlog_enabled: bool,
    pub wiki_enabled: bool,
    pub epics_enabled: bool,
    /// Column → status mapping for the epics board.
    pub epic_board: EpicBoardSettings,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewProject {
    pub name: String,
    pub slug: String,
    pub description: String,
    pub owner_id: Uuid,
    pub visibility: Visibility,
    pub issue_prefix: String,
    pub color: String,
}

#[derive(Debug, Clone, Default)]
pub struct ProjectUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub visibility: Option<Visibility>,
    pub issue_prefix: Option<String>,
    pub color: Option<String>,
    pub kanban_enabled: Option<bool>,
    pub backlog_enabled: Option<bool>,
    pub wiki_enabled: Option<bool>,
    pub epics_enabled: Option<bool>,
    pub epic_board: Option<EpicBoardSettings>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Role {
    pub id: Uuid,
    pub project_id: Uuid,
    pub slug: String,
    pub name: String,
    pub order: i32,
    pub is_admin: bool,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Membership {
    pub id: Uuid,
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub full_name: String,
    pub email: String,
    pub role_id: Uuid,
    pub role_slug: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Avatar + motto + mood + out-of-office, so every place that lists a
    /// member can render the avatar and hover card without extra calls.
    #[serde(flatten)]
    pub card: crate::user::ProfileCard,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Invitation {
    pub id: Uuid,
    pub project_id: Uuid,
    pub email: String,
    pub role_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
