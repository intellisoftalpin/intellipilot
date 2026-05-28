//! Search result type.

use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SearchHit {
    pub entity_type: String,
    pub entity_id: Uuid,
    pub project_id: Uuid,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<i64>,
    pub title: String,
    /// HTML-sanitized snippet (≤ 200 chars), highlights in `<b>`.
    pub snippet: String,
    pub rank: f32,
}
