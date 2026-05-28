//! Append-only audit log for security-relevant events.

use std::net::IpAddr;

use uuid::Uuid;

use crate::DbError;

/// Record an audit event. `metadata` is arbitrary JSON context.
///
/// Best-effort: a failure is logged (the security event is more important than
/// the request) but never propagated, so call sites stay clean.
pub async fn record(
    client: &deadpool_postgres::Client,
    actor_id: Option<Uuid>,
    action: &str,
    ip: Option<IpAddr>,
    user_agent: Option<&str>,
    metadata: &serde_json::Value,
) {
    let result = client
        .execute(
            "INSERT INTO audit_log (actor_id, action, ip, user_agent, metadata) \
             VALUES ($1, $2, $3, $4, $5)",
            &[&actor_id, &action, &ip, &user_agent, &metadata],
        )
        .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, action, "failed to write audit log");
    }
}

/// Count audit rows for an actor+action (used by tests/assertions).
pub async fn count_for_action(
    client: &deadpool_postgres::Client,
    action: &str,
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM audit_log WHERE action = $1",
            &[&action],
        )
        .await?;
    Ok(row.get("n"))
}
