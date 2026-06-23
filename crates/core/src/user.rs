//! User domain types shared between the persistence and HTTP layers.

use serde::Serialize;
use time::{Date, OffsetDateTime};
use utoipa::ToSchema;
use uuid::Uuid;

/// An absence in effect for a user *today* (vacation / illness / day_off /
/// holiday), with the booking's full date range — surfaced as an avatar badge
/// and on the profile hover card.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OutToday {
    /// `vacation` | `illness` | `day_off` | `holiday`.
    pub kind: String,
    #[serde(with = "crate::serde_date::required")]
    pub start_date: Date,
    #[serde(with = "crate::serde_date::required")]
    pub end_date: Date,
}

/// The display fields every user-bearing response carries so avatars, the
/// hover card, and the out-of-office badge render without extra round-trips.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ProfileCard {
    /// `default` | `image` | `emoji`.
    pub avatar_kind: String,
    /// The chosen emoji when `avatar_kind == "emoji"`, else empty.
    pub avatar_emoji: String,
    /// Cache-busting marker; the image is fetched from
    /// `GET /api/v1/users/{id}/avatar?v=<this>` when `avatar_kind == "image"`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub avatar_updated_at: Option<OffsetDateTime>,
    pub motto: String,
    /// Today's mood (blank once the day it was set has passed).
    pub mood_emoji: String,
    pub mood_text: String,
    /// Absence in effect today, if any.
    pub out_today: Option<OutToday>,
}

/// A compact, embeddable user reference (identity + profile card) — used where
/// a row references a user, e.g. a comment's author.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserBrief {
    pub id: Uuid,
    pub username: String,
    pub full_name: String,
    pub email: String,
    #[serde(flatten)]
    pub card: ProfileCard,
}

/// A user as exposed in API responses. Never contains the password hash.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub full_name: String,
    pub lang: String,
    pub timezone: String,
    pub is_active: bool,
    /// Platform-wide admin flag (V011). Distinct from per-project `is_admin`
    /// which lives on `roles`.
    pub is_superadmin: bool,
    /// True when the account was created by an admin and has yet to change
    /// its temporary password. The frontend force-redirects to the change-
    /// password page while this is set.
    pub must_change_password: bool,
    /// How this account authenticates: `"local"` (Argon2 password) or
    /// `"ldap"` (directory). LDAP accounts cannot change/reset a local
    /// password — it is managed in the directory.
    pub auth_source: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(flatten)]
    pub card: ProfileCard,
}

/// Fields accepted when creating a user.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub email: String,
    pub username: String,
    pub full_name: String,
    pub password_hash: String,
}

/// Admin-driven user creation. The public register path uses `NewUser`; this
/// variant carries the extra platform flags that only an admin can set.
#[derive(Debug, Clone)]
pub struct NewUserWithFlags {
    pub new: NewUser,
    pub is_superadmin: bool,
    pub must_change_password: bool,
}

/// Partial profile update. `None` fields are left unchanged. Setting either
/// mood field stamps "today" so it can auto-expire.
#[derive(Debug, Clone, Default)]
pub struct ProfileUpdate {
    pub full_name: Option<String>,
    pub lang: Option<String>,
    pub timezone: Option<String>,
    pub motto: Option<String>,
    pub mood_emoji: Option<String>,
    pub mood_text: Option<String>,
}
