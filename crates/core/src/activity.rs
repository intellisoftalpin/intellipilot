//! Activity / audit event as surfaced to superadmins.
//!
//! Backed by the universal `audit_log` table — every recorded action (auth
//! attempts, admin operations, …) is an activity event. New event types are
//! added simply by recording a new `action` string; this model needs no
//! change.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ActivityEvent {
    pub id: Uuid,
    /// Stable event key, e.g. `login_success`, `login_failure`, `login_first`,
    /// `password_changed`.
    pub action: String,
    /// The acting user, when known (absent for e.g. failed logins of an
    /// unknown identifier).
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub actor_username: Option<String>,
    /// Best-effort client IP (from the reverse proxy).
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// Arbitrary event context (e.g. `{ "reason": "...", "identifier": "..." }`).
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
