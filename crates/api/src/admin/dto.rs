//! Admin endpoint request/response DTOs (V011).
#![allow(unexpected_cfgs)]

use garde::Validate;
use intellipilot_core::activity::ActivityEvent;
use intellipilot_core::user::User;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// Paginated activity-log response (superadmin).
#[derive(Debug, Serialize, ToSchema)]
pub struct ActivityListResponse {
    pub items: Vec<ActivityEvent>,
    pub total: i64,
    pub limit: u32,
    pub offset: u32,
}

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
    #[serde(with = "time::serde::rfc3339")]
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
    #[serde(with = "time::serde::rfc3339")]
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
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct PlatformSettingsResponse {
    pub open_registration: bool,
    /// White-label name override. `null` means the bundled default is in use.
    pub app_name: Option<String>,
    /// Optional notice shown to users on the login screen.
    pub app_message: Option<String>,
    /// Whether a custom app icon is stored (served from `GET /branding/icon`).
    pub has_custom_icon: bool,
    /// When the custom icon was last changed — clients use it for cache-busting.
    #[serde(with = "time::serde::rfc3339::option")]
    pub app_icon_updated_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateSettingsRequest {
    #[garde(skip)]
    pub open_registration: bool,
}

/// White-label branding update. An empty or absent string clears the field,
/// reverting to the bundled default (name / no message).
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateBrandingRequest {
    #[serde(default)]
    #[garde(length(max = 64))]
    pub app_name: Option<String>,
    #[serde(default)]
    #[garde(length(max = 500))]
    pub app_message: Option<String>,
}

// ---------------------------------------------------------------------------
// LDAP settings
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)]
pub struct LdapSettingsResponse {
    pub enabled: bool,
    pub server_url: String,
    pub use_start_tls: bool,
    pub skip_tls_verify: bool,
    pub base_dn: String,
    pub default_domain: String,
    pub bind_dn_format: String,
    pub user_search_filter: String,
    pub superadmin_group: String,
    pub attr_email: String,
    pub attr_display_name: String,
    pub attr_username: String,
    pub connection_timeout_secs: i32,
    /// `direct` or `search`.
    pub bind_mode: String,
    pub service_bind_dn: String,
    /// Whether a service-account password is stored (the value is never returned).
    pub service_bind_password_set: bool,
    pub user_search_base: String,
    pub group_search_base: String,
    pub group_search_filter: String,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateLdapSettingsRequest {
    #[garde(skip)]
    pub enabled: bool,
    #[garde(length(max = 512))]
    pub server_url: String,
    #[garde(skip)]
    pub use_start_tls: bool,
    #[garde(skip)]
    pub skip_tls_verify: bool,
    #[garde(length(max = 512))]
    pub base_dn: String,
    #[garde(length(max = 255))]
    pub default_domain: String,
    #[garde(length(min = 1, max = 255))]
    pub bind_dn_format: String,
    #[garde(length(min = 1, max = 512))]
    pub user_search_filter: String,
    #[garde(length(max = 512))]
    pub superadmin_group: String,
    #[garde(length(min = 1, max = 64))]
    pub attr_email: String,
    #[garde(length(min = 1, max = 64))]
    pub attr_display_name: String,
    #[garde(length(min = 1, max = 64))]
    pub attr_username: String,
    #[garde(range(min = 1, max = 120))]
    pub connection_timeout_secs: i32,
    /// `direct` (bind as the user) or `search` (service-account search then bind).
    #[garde(length(max = 16))]
    #[serde(default = "default_bind_mode")]
    pub bind_mode: String,
    #[garde(length(max = 512))]
    #[serde(default)]
    pub service_bind_dn: String,
    /// Optional — blank/absent keeps the stored service password.
    #[garde(skip)]
    #[serde(default)]
    pub service_bind_password: Option<String>,
    #[garde(length(max = 512))]
    #[serde(default)]
    pub user_search_base: String,
    #[garde(length(max = 512))]
    #[serde(default)]
    pub group_search_base: String,
    #[garde(length(max = 512))]
    #[serde(default = "default_group_filter")]
    pub group_search_filter: String,
}

fn default_bind_mode() -> String {
    "direct".to_owned()
}

fn default_group_filter() -> String {
    "(member=%s)".to_owned()
}

/// Request body for the "test connection" endpoint: the (possibly unsaved)
/// settings plus a real username/password to attempt a bind with.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TestLdapRequest {
    #[garde(dive)]
    pub settings: UpdateLdapSettingsRequest,
    #[garde(length(min = 1, max = 254))]
    pub username: String,
    #[garde(length(min = 1, max = 1024))]
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TestLdapResponse {
    pub ok: bool,
    pub message: String,
    /// Resolved details on success (helps confirm attribute mappings).
    pub email: Option<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub would_be_superadmin: Option<bool>,
}

// ---------------------------------------------------------------------------
// Notification settings (email: SMTP/Mailgun, Matrix, Telegram)
// ---------------------------------------------------------------------------

/// Current notification config. Secrets are never returned — only `*_set`
/// booleans indicate whether a value is stored.
#[derive(Debug, Serialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)]
pub struct NotificationSettingsResponse {
    pub mail_enabled: bool,
    pub mail_provider: String,
    pub mail_from_address: String,
    pub mail_from_name: String,
    pub smtp_host: String,
    pub smtp_port: i32,
    pub smtp_username: String,
    pub smtp_password_set: bool,
    pub smtp_use_starttls: bool,
    pub smtp_skip_tls_verify: bool,
    pub mailgun_api_key_set: bool,
    pub mailgun_domain: String,
    pub mailgun_base_url: String,
    pub matrix_enabled: bool,
    pub matrix_homeserver: String,
    pub matrix_room_id: String,
    pub matrix_access_token_set: bool,
    pub telegram_enabled: bool,
    pub telegram_bot_token_set: bool,
    pub telegram_chat_id: String,
    pub mail_on_login: bool,
    pub mail_on_issue_created: bool,
    pub mail_on_issue_resolved: bool,
    pub mail_on_daily_report: bool,
    pub msg_on_login: bool,
    pub msg_on_issue_created: bool,
    pub msg_on_issue_resolved: bool,
    pub msg_on_daily_report: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

/// Update payload. Secret fields are optional — an empty/absent value keeps the
/// currently-stored secret.
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[allow(clippy::struct_excessive_bools)]
pub struct UpdateNotificationSettingsRequest {
    #[garde(skip)]
    pub mail_enabled: bool,
    /// `smtp` | `mailgun`.
    #[garde(length(max = 16))]
    pub mail_provider: String,
    #[garde(length(max = 254))]
    pub mail_from_address: String,
    #[garde(length(max = 128))]
    pub mail_from_name: String,
    #[garde(length(max = 255))]
    pub smtp_host: String,
    #[garde(range(min = 1, max = 65535))]
    pub smtp_port: i32,
    #[garde(length(max = 255))]
    pub smtp_username: String,
    #[garde(skip)]
    #[serde(default)]
    pub smtp_password: Option<String>,
    #[garde(skip)]
    pub smtp_use_starttls: bool,
    #[garde(skip)]
    pub smtp_skip_tls_verify: bool,
    #[garde(skip)]
    #[serde(default)]
    pub mailgun_api_key: Option<String>,
    #[garde(length(max = 255))]
    pub mailgun_domain: String,
    #[garde(length(max = 255))]
    pub mailgun_base_url: String,
    #[garde(skip)]
    pub matrix_enabled: bool,
    #[garde(length(max = 512))]
    pub matrix_homeserver: String,
    #[garde(length(max = 255))]
    pub matrix_room_id: String,
    #[garde(skip)]
    #[serde(default)]
    pub matrix_access_token: Option<String>,
    #[garde(skip)]
    pub telegram_enabled: bool,
    #[garde(skip)]
    #[serde(default)]
    pub telegram_bot_token: Option<String>,
    #[garde(length(max = 64))]
    pub telegram_chat_id: String,
    #[garde(skip)]
    pub mail_on_login: bool,
    #[garde(skip)]
    pub mail_on_issue_created: bool,
    #[garde(skip)]
    pub mail_on_issue_resolved: bool,
    #[garde(skip)]
    pub mail_on_daily_report: bool,
    #[garde(skip)]
    pub msg_on_login: bool,
    #[garde(skip)]
    pub msg_on_issue_created: bool,
    #[garde(skip)]
    pub msg_on_issue_resolved: bool,
    #[garde(skip)]
    pub msg_on_daily_report: bool,
}

/// Send a test email to `to` using the saved configuration.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TestMailRequest {
    #[garde(email, length(max = 254))]
    pub to: String,
}

/// Result of a "send test" action for any channel.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationTestResponse {
    pub ok: bool,
    pub message: String,
}
