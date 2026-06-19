//! Append-only audit log for security-relevant events. Doubles as the
//! universal activity log surfaced to superadmins.

use std::net::IpAddr;

use intellipilot_core::activity::ActivityEvent;
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

/// Count audit rows for an action (used by tests/assertions).
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

/// Count an actor's events matching any of `actions` (e.g. to detect a user's
/// first successful login).
pub async fn count_for_actor_actions(
    client: &deadpool_postgres::Client,
    actor_id: Uuid,
    actions: &[&str],
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM audit_log WHERE actor_id = $1 AND action = ANY($2)",
            &[&actor_id, &actions],
        )
        .await?;
    Ok(row.get("n"))
}

fn row_to_event(r: &tokio_postgres::Row) -> ActivityEvent {
    ActivityEvent {
        id: r.get("id"),
        action: r.get("action"),
        actor_id: r.get("actor_id"),
        actor_email: r.get("actor_email"),
        actor_username: r.get("actor_username"),
        ip: r.get::<_, Option<IpAddr>>("ip").map(|a| a.to_string()),
        user_agent: r.get("user_agent"),
        metadata: r.get("metadata"),
        created_at: r.get("created_at"),
    }
}

/// List activity events (newest first), optionally filtered by an exact
/// `action`, joining the acting user's email/username when present.
pub async fn list(
    client: &deadpool_postgres::Client,
    action: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ActivityEvent>, DbError> {
    let rows = client
        .query(
            "SELECT a.id, a.action, a.actor_id, u.email AS actor_email, \
                    u.username AS actor_username, a.ip, a.user_agent, a.metadata, a.created_at \
             FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id \
             WHERE ($1::text IS NULL OR a.action = $1) \
             ORDER BY a.created_at DESC, a.id DESC \
             LIMIT $2 OFFSET $3",
            &[&action, &limit, &offset],
        )
        .await?;
    Ok(rows.iter().map(row_to_event).collect())
}

/// Total activity events (with the same optional `action` filter).
pub async fn count(
    client: &deadpool_postgres::Client,
    action: Option<&str>,
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM audit_log WHERE ($1::text IS NULL OR action = $1)",
            &[&action],
        )
        .await?;
    Ok(row.get("n"))
}
