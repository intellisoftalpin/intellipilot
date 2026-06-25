//! Request/response DTOs for the identity endpoints.
//!
//! `unexpected_cfgs` is allowed because `garde_derive`'s `Validate` macro
//! emits a `cfg(feature = "js-sys")` gate that isn't surfaced as a feature in
//! this crate. Harmless; remove once garde stops emitting it.
#![allow(unexpected_cfgs)]

use garde::Validate;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    #[garde(email, length(max = 254))]
    pub email: String,
    #[garde(length(min = 3, max = 64), pattern(r"^[a-zA-Z0-9_.-]+$"))]
    pub username: String,
    /// Strength (length + zxcvbn) is enforced in the handler, not here.
    #[garde(length(min = 1, max = 1024))]
    pub password: String,
    #[garde(length(max = 256))]
    #[serde(default)]
    pub full_name: String,
    /// Platform-invitation token issued by a superadmin (V011). Required when
    /// `platform_settings.open_registration = false`; ignored otherwise.
    #[garde(skip)]
    #[serde(default)]
    pub invitation_token: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[garde(length(min = 1, max = 254))]
    pub email: String,
    #[garde(length(min = 1, max = 1024))]
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    /// Present only in development when the refresh cookie can't be relied on
    /// (e.g. non-browser clients). In production this is omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ProfileUpdateRequest {
    #[garde(length(max = 256))]
    #[serde(default)]
    pub full_name: Option<String>,
    #[garde(length(max = 8))]
    #[serde(default)]
    pub lang: Option<String>,
    #[garde(length(max = 64))]
    #[serde(default)]
    pub timezone: Option<String>,
    #[garde(length(max = 140))]
    #[serde(default)]
    pub motto: Option<String>,
    /// Daily mood — an emoji + short status. Sending either stamps "today" so
    /// it auto-expires; send empty strings to clear.
    #[garde(length(max = 16))]
    #[serde(default)]
    pub mood_emoji: Option<String>,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub mood_text: Option<String>,
}

/// Self-service password change for the logged-in user. Local accounts only;
/// LDAP-backed accounts are rejected (their password lives in the directory).
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    #[garde(length(min = 1, max = 1024))]
    pub current_password: String,
    /// Strength (length + zxcvbn) is enforced in the handler, not here.
    #[garde(length(min = 1, max = 1024))]
    pub new_password: String,
}

/// Public auth configuration for unauthenticated UIs.
///
/// Lets the login / register / forgot-password pages adapt: whether
/// self-service signup is open, and whether email-based password reset is
/// available (a mailer is configured). Invitation links work regardless of
/// `open_registration`.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthConfigResponse {
    pub open_registration: bool,
    pub password_reset_enabled: bool,
    /// White-label name override. `null` means the bundled default
    /// ("IntelliPilot") is in use.
    pub app_name: Option<String>,
    /// Optional notice shown to users on the login screen.
    pub app_message: Option<String>,
    /// Whether a custom app icon is available at `GET /api/v1/branding/icon`.
    pub has_custom_icon: bool,
    /// When the custom icon was last changed — clients use it for cache-busting.
    #[serde(with = "time::serde::rfc3339::option")]
    pub app_icon_updated_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct PasswordResetRequestBody {
    #[garde(email, length(max = 254))]
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasswordResetRequestResponse {
    pub status: &'static str,
    /// Dev-only: the reset token, returned when no mailer is configured and
    /// the environment is development.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_token: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct PasswordResetConfirmBody {
    #[garde(length(min = 1, max = 512))]
    pub token: String,
    #[garde(length(min = 1, max = 1024))]
    pub new_password: String,
}

// --- Phase 2: two-factor --------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct TotpStartResponse {
    pub secret_base32: String,
    pub provisioning_uri: String,
    pub qr_png_base64: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TotpConfirmRequest {
    #[garde(length(min = 6, max = 10), pattern(r"^[0-9]+$"))]
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

/// Second-factor verification after a password challenge. `method` is one of
/// `totp` | `recovery`.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TwoFactorVerifyRequest {
    #[garde(length(min = 1, max = 1024))]
    pub mfa_token: String,
    #[garde(length(min = 1, max = 16))]
    pub method: String,
    #[garde(length(min = 1, max = 64))]
    pub code: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct PasskeyNicknameQuery {
    #[garde(length(max = 64))]
    #[serde(default)]
    pub nickname: Option<String>,
}

/// Finish a passkey ceremony. `credential` is the browser's WebAuthn JSON.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct PasskeyFinishRequest {
    #[garde(skip)]
    pub state_id: uuid::Uuid,
    #[garde(skip)]
    #[schema(value_type = Object)]
    pub credential: serde_json::Value,
    #[garde(length(max = 64))]
    #[serde(default)]
    pub nickname: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct PasskeyAuthStartRequest {
    #[garde(email, length(max = 254))]
    pub email: String,
}

// --- Phase 3: projects, roles, memberships --------------------------------

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateProjectRequest {
    #[garde(length(min = 1, max = 200))]
    pub name: String,
    /// Optional explicit slug; derived from the name when omitted.
    #[garde(length(max = 100), pattern(r"^[a-z0-9]+(?:-[a-z0-9]+)*$"))]
    #[serde(default)]
    pub slug: Option<String>,
    #[garde(length(max = 4000))]
    #[serde(default)]
    pub description: String,
    /// `private` (default) | `internal` | `public_readonly`.
    #[garde(length(max = 16))]
    #[serde(default)]
    pub visibility: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateProjectRequest {
    #[garde(length(min = 1, max = 200))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(length(max = 4000))]
    #[serde(default)]
    pub description: Option<String>,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub visibility: Option<String>,
    #[garde(skip)]
    #[serde(default)]
    pub kanban_enabled: Option<bool>,
    #[garde(skip)]
    #[serde(default)]
    pub backlog_enabled: Option<bool>,
    #[garde(skip)]
    #[serde(default)]
    pub wiki_enabled: Option<bool>,
    #[garde(skip)]
    #[serde(default)]
    pub epics_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateRoleRequest {
    #[garde(length(min = 1, max = 64))]
    pub name: String,
    #[garde(length(min = 1, max = 64), pattern(r"^[a-z0-9_]+$"))]
    pub slug: String,
    #[garde(skip)]
    #[serde(default)]
    pub permissions: Vec<intellipilot_core::perms::Permission>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateRoleRequest {
    #[garde(length(min = 1, max = 64))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(skip)]
    #[serde(default)]
    pub permissions: Option<Vec<intellipilot_core::perms::Permission>>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct InviteRequest {
    #[garde(email, length(max = 254))]
    pub email: String,
    /// Role slug to grant on acceptance.
    #[garde(length(min = 1, max = 64))]
    pub role: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InviteResponse {
    pub invitation_id: uuid::Uuid,
    /// Dev-only: the raw token, returned when no mailer is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AcceptInviteRequest {
    #[garde(length(min = 1, max = 512))]
    pub token: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangeMemberRoleRequest {
    #[garde(length(min = 1, max = 64))]
    pub role: String,
}

/// Add an existing user to a project directly. Provide `user_id` (from the
/// user picker) or `identifier` (exact email / username); `role` is a role slug.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AddMemberRequest {
    #[garde(skip)]
    #[serde(default)]
    pub user_id: Option<uuid::Uuid>,
    #[garde(length(max = 254))]
    #[serde(default)]
    pub identifier: Option<String>,
    #[garde(length(min = 1, max = 64))]
    pub role: String,
}

// --- Phase 4: taxonomy ----------------------------------------------------

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateTaxonomyItemRequest {
    #[garde(length(min = 1, max = 64))]
    pub name: String,
    #[garde(length(min = 1, max = 64), pattern(r"^[a-z0-9]+(?:-[a-z0-9]+)*$"))]
    pub slug: String,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: String,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub emoji: String,
    #[garde(skip)]
    #[serde(default)]
    pub is_closed: Option<bool>,
    #[garde(skip)]
    #[serde(default)]
    pub value: Option<f64>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateTaxonomyItemRequest {
    #[garde(length(min = 1, max = 64))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: Option<String>,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub emoji: Option<String>,
    #[garde(skip)]
    #[serde(default)]
    pub is_closed: Option<bool>,
    #[garde(skip)]
    #[serde(default)]
    pub value: Option<f64>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct MoveTaxonomyItemRequest {
    #[garde(skip)]
    #[serde(default)]
    pub before_id: Option<uuid::Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub after_id: Option<uuid::Uuid>,
}

// --- Phase 5: backlog -----------------------------------------------------

use uuid::Uuid;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateEpicRequest {
    #[garde(length(min = 1, max = 500))]
    pub subject: String,
    #[garde(length(max = 100_000))]
    #[serde(default)]
    pub description: String,
    #[garde(skip)]
    #[serde(default)]
    pub status_id: Option<Uuid>,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: String,
    #[garde(skip)]
    #[serde(default)]
    pub assigned_to: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub milestone_id: Option<Uuid>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateEpicRequest {
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub status_id: Option<Option<Uuid>>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub assigned_to: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub milestone_id: Option<Option<Uuid>>,
}

/// Create a unified issue.
///
/// `type_id` (an `issue_type` taxonomy item) picks Story / Task / Bug;
/// `parent_id` makes it a sub-task; `epic_id` groups it under an epic;
/// `milestone_id` assigns a sprint; `size_id` is the T-shirt estimate.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateIssueRequest {
    #[garde(length(min = 1, max = 500))]
    pub subject: String,
    #[garde(length(max = 100_000))]
    #[serde(default)]
    pub description: String,
    #[garde(skip)]
    #[serde(default)]
    pub status_id: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub type_id: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub priority_id: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub size_id: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub epic_id: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub milestone_id: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub assigned_to: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub category: Option<intellipilot_core::backlog::IssueCategory>,
    #[garde(skip)]
    #[serde(default)]
    pub customer_id: Option<Uuid>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub start_date: Option<time::Date>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub due_date: Option<time::Date>,
    #[garde(skip)]
    #[serde(default)]
    pub resolution: Option<intellipilot_core::backlog::Resolution>,
    #[garde(skip)]
    #[serde(default)]
    pub release_version_id: Option<Uuid>,
    #[garde(length(max = 100))]
    #[serde(default)]
    pub release_text: Option<String>,
    #[garde(length(max = 50))]
    #[serde(default)]
    pub labels: Vec<Uuid>,
    #[garde(length(max = 50))]
    #[serde(default)]
    pub components: Vec<Uuid>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateIssueRequest {
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub status_id: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub type_id: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub priority_id: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub size_id: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub epic_id: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub parent_id: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub milestone_id: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub assigned_to: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub category: Option<Option<intellipilot_core::backlog::IssueCategory>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub customer_id: Option<Option<Uuid>>,
    /// Absent leaves the date unchanged (clearing is not supported, matching
    /// milestones).
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub start_date: Option<time::Date>,
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub due_date: Option<time::Date>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub resolution: Option<Option<intellipilot_core::backlog::Resolution>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub release_version_id: Option<Option<Uuid>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub release_text: Option<Option<String>>,
    /// Full replacement of the issue's labels when present.
    #[serde(default)]
    pub labels: Option<Vec<Uuid>>,
    /// Full replacement of the issue's components when present.
    #[serde(default)]
    pub components: Option<Vec<Uuid>>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct BulkCreateIssuesRequest {
    #[garde(length(min = 1, max = 100), dive)]
    pub items: Vec<CreateIssueRequest>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ReorderRequest {
    #[garde(skip)]
    #[serde(default)]
    pub before_id: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub after_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CommentRequest {
    #[garde(length(min = 1, max = 50_000))]
    pub body: String,
}

// --- Labels & Components --------------------------------------------------

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateLabelRequest {
    #[garde(length(min = 1, max = 64))]
    pub name: String,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateLabelRequest {
    #[garde(length(min = 1, max = 64))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateComponentRequest {
    #[garde(length(min = 1, max = 64))]
    pub name: String,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateComponentRequest {
    #[garde(length(min = 1, max = 64))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: Option<String>,
}

// --- Phase 8: wiki --------------------------------------------------------

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateWikiPageRequest {
    #[garde(length(min = 1, max = 300))]
    pub title: String,
    #[garde(length(max = 200), pattern(r"^[a-z0-9]+(?:-[a-z0-9]+)*$"))]
    #[serde(default)]
    pub slug: Option<String>,
    #[garde(length(max = 1_000_000))]
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateWikiPageRequest {
    #[garde(length(min = 1, max = 300))]
    #[serde(default)]
    pub title: Option<String>,
    #[garde(length(max = 1_000_000))]
    #[serde(default)]
    pub body: Option<String>,
}

// --- Phase 6: milestones --------------------------------------------------

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateMilestoneRequest {
    #[garde(length(min = 1, max = 200))]
    pub name: String,
    #[garde(length(max = 100), pattern(r"^[a-z0-9]+(?:-[a-z0-9]+)*$"))]
    #[serde(default)]
    pub slug: Option<String>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub start_date: Option<time::Date>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub end_date: Option<time::Date>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateMilestoneRequest {
    #[garde(length(min = 1, max = 200))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub start_date: Option<time::Date>,
    #[garde(skip)]
    #[schema(value_type = Option<String>)]
    #[serde(default, with = "intellipilot_core::serde_date::option")]
    pub end_date: Option<time::Date>,
}

/// Replace the full set of epics belonging to a milestone.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SetMilestoneEpicsRequest {
    #[garde(skip)]
    #[serde(default)]
    pub epic_ids: Vec<Uuid>,
}
