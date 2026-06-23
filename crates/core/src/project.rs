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

#[derive(Debug, Clone, Serialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)] // feature flags, not state machine
pub struct Project {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub owner_id: Uuid,
    pub visibility: Visibility,
    pub kanban_enabled: bool,
    pub backlog_enabled: bool,
    pub wiki_enabled: bool,
    pub epics_enabled: bool,
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
}

#[derive(Debug, Clone, Default)]
pub struct ProjectUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub visibility: Option<Visibility>,
    pub kanban_enabled: Option<bool>,
    pub backlog_enabled: Option<bool>,
    pub wiki_enabled: Option<bool>,
    pub epics_enabled: Option<bool>,
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
