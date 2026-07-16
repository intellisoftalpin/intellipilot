//! App token domain types + the INTELLIBOT system actor.
//!
//! An app token is a long-lived machine credential a superadmin mints. It is
//! scoped to a set of projects and a set of [`Permission`]s and authenticates
//! as the synthetic INTELLIBOT user, so anything it does is attributed to
//! INTELLIBOT rather than a real person.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::perms::Permission;

/// Fixed id of the INTELLIBOT system user. Mirrors the row seeded in migration
/// `V004__app_tokens.sql`. App-token actions use this as their actor.
pub const INTELLIBOT_USER_ID: Uuid = Uuid::from_u128(0xb070_0000_0000_7000_8000_0000_0000_0000);

/// Display name of the system actor.
pub const INTELLIBOT_USERNAME: &str = "INTELLIBOT";

/// Raw app-token secrets carry this prefix, so the auth layer can tell them
/// apart from Paseto access tokens in the same `Authorization: Bearer` header.
pub const TOKEN_PREFIX: &str = "ipat_";

/// Raw personal-token secrets carry this prefix. A personal token
/// authenticates as its owning user (unlike `ipat_` tokens, which act as
/// INTELLIBOT), so the auth layer needs to tell the two kinds apart.
pub const PERSONAL_TOKEN_PREFIX: &str = "ippt_";

/// An app token as returned to the admin UI. Never carries the secret — only
/// the [`prefix`](Self::prefix) + [`last4`](Self::last4) display hints.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AppToken {
    pub id: Uuid,
    pub name: String,
    /// Leading hint of the secret, e.g. `ipat_Ab12cd`.
    pub prefix: String,
    /// Last 4 chars of the secret.
    pub last4: String,
    pub permissions: Vec<Permission>,
    /// Projects the token is scoped to.
    pub project_ids: Vec<Uuid>,
    pub created_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl AppToken {
    /// A short masked identifier for logs/UI, e.g. `ipat_Ab12cd…wx90`.
    #[must_use]
    pub fn masked(&self) -> String {
        format!("{}…{}", self.prefix, self.last4)
    }
}

/// A user's personal app token as returned to its owner. Never carries the
/// secret — only the [`prefix`](Self::prefix) + [`last4`](Self::last4)
/// display hints. At most one exists per user.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PersonalAppToken {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Leading hint of the secret, e.g. `ippt_Ab12cd`.
    pub prefix: String,
    /// Last 4 chars of the secret.
    pub last4: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub disabled_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl PersonalAppToken {
    /// A short masked identifier for logs/UI, e.g. `ippt_Ab12cd…wx90`.
    #[must_use]
    pub fn masked(&self) -> String {
        format!("{}…{}", self.prefix, self.last4)
    }
}
