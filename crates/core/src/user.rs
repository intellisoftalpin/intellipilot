//! User domain types shared between the persistence and HTTP layers.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

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
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
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

/// Partial profile update. `None` fields are left unchanged.
#[derive(Debug, Clone, Default)]
pub struct ProfileUpdate {
    pub full_name: Option<String>,
    pub lang: Option<String>,
    pub timezone: Option<String>,
}
