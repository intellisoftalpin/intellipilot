//! Failed-login tracking for progressive lockout.

use std::net::IpAddr;

use time::OffsetDateTime;

use crate::DbError;

/// Record a login attempt. `identifier_hash` is sha256(email) to avoid storing
/// raw identifiers. Best-effort: failures are logged, not propagated.
pub async fn record(
    client: &deadpool_postgres::Client,
    identifier_hash: &str,
    ip: IpAddr,
    succeeded: bool,
) {
    let result = client
        .execute(
            "INSERT INTO login_attempts (identifier_hash, ip, succeeded) \
             VALUES ($1, $2, $3)",
            &[&identifier_hash, &ip, &succeeded],
        )
        .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, "failed to record login attempt");
    }
}

/// Count failed attempts for an (identifier OR ip) since `since`. Used to
/// compute the progressive delay.
pub async fn recent_failures(
    client: &deadpool_postgres::Client,
    identifier_hash: &str,
    ip: IpAddr,
    since: OffsetDateTime,
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM login_attempts \
             WHERE succeeded = false AND created_at >= $3 \
               AND (identifier_hash = $1 OR ip = $2)",
            &[&identifier_hash, &ip, &since],
        )
        .await?;
    Ok(row.get("n"))
}

/// Delete attempt rows older than `before` (background sweep).
pub async fn prune(
    client: &deadpool_postgres::Client,
    before: OffsetDateTime,
) -> Result<u64, DbError> {
    let affected = client
        .execute(
            "DELETE FROM login_attempts WHERE created_at < $1",
            &[&before],
        )
        .await?;
    Ok(affected)
}
