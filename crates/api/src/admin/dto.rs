//! Admin endpoint request/response DTOs (V011).
#![allow(unexpected_cfgs)]

use garde::Validate;
use intellipilot_core::user::User;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListResponse {
    pub items: Vec<User>,
    pub total: i64,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateUserRequest {
    #[garde(email, length(max = 254))]
    pub email: String,
    #[garde(length(min = 3, max = 64), pattern(r"^[a-zA-Z0-9_.-]+$"))]
    pub username: String,
    #[garde(length(max = 256))]
    #[serde(default)]
    pub full_name: String,
    /// Optional admin-chosen password. When absent, the server generates a
    /// 24-character random one and returns it in [`CreateUserResponse`].
    #[garde(length(min = 0, max = 1024))]
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    #[garde(skip)]
    pub is_superadmin: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateUserResponse {
    pub user: User,
    /// One-time delivery of a server-generated temporary password. Present
    /// only when the request omitted `password`. Not stored anywhere after
    /// the response is sent. The new account is marked
    /// `must_change_password=true` so first login forces a rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_password: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateUserRequest {
    #[serde(default)]
    #[garde(skip)]
    pub is_active: Option<bool>,
    #[serde(default)]
    #[garde(skip)]
    pub is_superadmin: Option<bool>,
    #[serde(default)]
    #[garde(length(max = 256))]
    pub full_name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasswordResetIssuedResponse {
    /// Raw token, returned ONLY when the mailer is not configured (dev mode).
    /// Production sends it by email instead and this field is omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_token: Option<String>,
    pub expires_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateInvitationRequest {
    #[garde(email, length(max = 254))]
    pub email: String,
    /// `user` (default) or `superadmin`.
    #[garde(length(max = 16))]
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "user".to_owned()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateInvitationResponse {
    pub invitation_id: Uuid,
    pub email: String,
    pub role: String,
    pub expires_at: OffsetDateTime,
    /// Raw token, returned ONLY when the mailer is not configured (dev mode).
    /// The admin UI uses this to display a copy-paste link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PendingInvitation {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub invited_by: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct PlatformSettingsResponse {
    pub open_registration: bool,
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateSettingsRequest {
    #[garde(skip)]
    pub open_registration: bool,
}
