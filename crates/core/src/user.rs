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
// The flags are independent account facts, not a state machine: grouping them
// into a sub-struct to satisfy the lint would change the wire shape every
// client already consumes.
#[allow(clippy::struct_excessive_bools)]
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
    /// Hide this user from timesheet reports (V024): the team grids, the
    /// project time-entry list and its export, and their unfilled-days
    /// warning. A reporting exclusion only — the user can still track time,
    /// and their hours stay in per-issue logs and the admin entry list.
    pub exclude_from_time_reports: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(flatten)]
    pub card: ProfileCard,
}

/// Which second factors an account actually has.
///
/// `enabled` is the value the login path gates on — a user is challenged when
/// *any* factor is present. It matters for recovery: clearing TOTP alone
/// leaves a passkey-only user just as locked out, so the admin reset clears
/// every factor listed here.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TwoFactorStatus {
    /// True when at least one factor is active (confirmed TOTP or a passkey).
    pub enabled: bool,
    /// A confirmed TOTP authenticator is registered.
    pub totp: bool,
    /// Number of registered passkeys.
    pub passkeys: i64,
    /// Unused single-use recovery codes remaining.
    pub recovery_codes_left: i64,
}

/// One logical session (a refresh-token family), as shown to an admin.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionInfo {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen_at: OffsetDateTime,
    /// Most recent address seen on this session.
    pub ip: Option<String>,
    /// ISO 3166-1 alpha-2. `None` when geolocation is disabled (the default),
    /// the address is private, or the database has no entry.
    pub country_code: Option<String>,
    /// `None` for country-only databases and unresolved ranges.
    pub city: Option<String>,
    pub user_agent: String,
}

/// Security posture of an account, shown only on the admin user list.
///
/// Carried separately from [`User`] so the fields never leak into `/me` or the
/// embedded [`UserBrief`] that rides along with every issue and comment.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdminUserRow {
    #[serde(flatten)]
    pub user: User,
    /// `active` | `inactive` | `banned`. Precomputed because the three inputs
    /// (`is_active`, `banned_at`, deletion) have a precedence the client
    /// should not have to reimplement.
    pub status: String,
    pub two_factor: TwoFactorStatus,
    /// Sessions that are neither revoked nor fully expired.
    pub active_sessions: i64,
    /// The most recently active session, source of the country/city shown in
    /// the list. `None` when the user has no live session.
    pub last_session: Option<SessionInfo>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_seen_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub banned_at: Option<OffsetDateTime>,
    pub ban_reason: Option<String>,
    /// Who imposed the ban; `None` if that admin has since been deleted.
    pub banned_by: Option<Uuid>,
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
