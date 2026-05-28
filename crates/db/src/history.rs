//! Append-only field-change history per backlog entity.

use serde_json::Value;
use uuid::Uuid;

use crate::DbError;

/// Record a change. `diff` is `{ "field": [old, new], … }`. Best-effort: a
/// failure is logged, not propagated (history must never block the write).
pub async fn record(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    target_type: &str,
    target_id: Uuid,
    actor_id: Option<Uuid>,
    diff: &Value,
) {
    let result = client
        .execute(
            "INSERT INTO history_entries (project_id, target_type, target_id, actor_id, diff) \
             VALUES ($1,$2,$3,$4,$5)",
            &[&project_id, &target_type, &target_id, &actor_id, &diff],
        )
        .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, target_type, "failed to record history entry");
    }
}

/// History entries for an entity, oldest first.
pub async fn list(
    client: &deadpool_postgres::Client,
    target_type: &str,
    target_id: Uuid,
) -> Result<Vec<Value>, DbError> {
    let rows = client
        .query(
            "SELECT diff, actor_id, created_at FROM history_entries \
             WHERE target_type=$1 AND target_id=$2 ORDER BY created_at",
            &[&target_type, &target_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let diff: Value = r.get("diff");
            let actor: Option<Uuid> = r.get("actor_id");
            let created: time::OffsetDateTime = r.get("created_at");
            serde_json::json!({
                "diff": diff,
                "actor_id": actor,
                "created_at": created.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            })
        })
        .collect())
}
