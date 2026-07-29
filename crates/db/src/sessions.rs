//! Refresh-token sessions: families + rotating tokens with reuse detection.

use std::net::IpAddr;

use intellipilot_core::user::SessionInfo;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

/// Result of looking up a refresh token by its hash.
#[derive(Debug, Clone)]
pub struct RefreshLookup {
    pub token_id: Uuid,
    pub family_id: Uuid,
    pub user_id: Uuid,
    pub used_at: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
    pub family_revoked: bool,
}

/// Create a new refresh-token family (one logical session).
pub async fn create_family(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    user_agent: &str,
    ip: Option<IpAddr>,
) -> Result<Uuid, DbError> {
    let row = client
        .query_one(
            "INSERT INTO refresh_token_families (user_id, user_agent, ip) \
             VALUES ($1, $2, $3) RETURNING id",
            &[&user_id, &user_agent, &ip],
        )
        .await?;
    Ok(row.get("id"))
}

/// Insert a refresh token into a family.
pub async fn insert_token(
    client: &deadpool_postgres::Client,
    family_id: Uuid,
    token_hash: &str,
    parent_id: Option<Uuid>,
    expires_at: OffsetDateTime,
) -> Result<Uuid, DbError> {
    let row = client
        .query_one(
            "INSERT INTO refresh_tokens (family_id, token_hash, parent_id, expires_at) \
             VALUES ($1, $2, $3, $4) RETURNING id",
            &[&family_id, &token_hash, &parent_id, &expires_at],
        )
        .await?;
    Ok(row.get("id"))
}

/// Look up a refresh token by hash, joined with its family revocation state.
pub async fn find_by_hash(
    client: &deadpool_postgres::Client,
    token_hash: &str,
) -> Result<Option<RefreshLookup>, DbError> {
    let row = client
        .query_opt(
            "SELECT t.id, t.family_id, f.user_id, t.used_at, t.expires_at, \
                    (f.revoked_at IS NOT NULL) AS family_revoked \
             FROM refresh_tokens t \
             JOIN refresh_token_families f ON f.id = t.family_id \
             WHERE t.token_hash = $1",
            &[&token_hash],
        )
        .await?;
    Ok(row.map(|r| RefreshLookup {
        token_id: r.get("id"),
        family_id: r.get("family_id"),
        user_id: r.get("user_id"),
        used_at: r.get("used_at"),
        expires_at: r.get("expires_at"),
        family_revoked: r.get("family_revoked"),
    }))
}

/// Atomically mark a token used. Returns `true` if this call performed the
/// transition; `false` means it was already used (concurrent reuse).
pub async fn mark_used(
    client: &deadpool_postgres::Client,
    token_id: Uuid,
) -> Result<bool, DbError> {
    let affected = client
        .execute(
            "UPDATE refresh_tokens SET used_at = now() \
             WHERE id = $1 AND used_at IS NULL",
            &[&token_id],
        )
        .await?;
    Ok(affected > 0)
}

/// Revoke an entire family (reuse detection or logout). Best-effort: failures
/// are logged, not propagated.
pub async fn revoke_family(client: &deadpool_postgres::Client, family_id: Uuid, reason: &str) {
    let result = client
        .execute(
            "UPDATE refresh_token_families SET revoked_at = now(), revoked_reason = $2 \
             WHERE id = $1 AND revoked_at IS NULL",
            &[&family_id, &reason],
        )
        .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, reason, "failed to revoke refresh family");
    }
}

/// Revoke all of a user's active families (e.g. on account erase). Best-effort.
pub async fn revoke_all_for_user(client: &deadpool_postgres::Client, user_id: Uuid, reason: &str) {
    drop(revoke_all_for_user_counted(client, user_id, reason).await);
}

/// Revoke all of a user's active families, reporting how many were closed.
///
/// The count is surfaced to the admin who triggered it ("signed out of 3
/// sessions") and recorded in the audit entry.
pub async fn revoke_all_for_user_counted(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    reason: &str,
) -> Result<u64, DbError> {
    let result = client
        .execute(
            "UPDATE refresh_token_families SET revoked_at = now(), revoked_reason = $2 \
             WHERE user_id = $1 AND revoked_at IS NULL",
            &[&user_id, &reason],
        )
        .await;
    match result {
        Ok(n) => Ok(n),
        Err(e) => {
            tracing::warn!(error = %e, reason, "failed to revoke user's refresh families");
            Err(e.into())
        }
    }
}

/// Stamp a session's current activity and resolved location.
///
/// Called on refresh rotation, which is the only regular signal we get about
/// where a long-lived session actually is. `country`/`city` are `None` when
/// geolocation is disabled (the default) or the address did not resolve;
/// passing `None` deliberately leaves the previous values in place rather than
/// wiping known-good data on a single failed lookup.
pub async fn touch_family(
    client: &deadpool_postgres::Client,
    family_id: Uuid,
    ip: Option<IpAddr>,
    country: Option<&str>,
    city: Option<&str>,
) {
    let result = client
        .execute(
            "UPDATE refresh_token_families \
             SET last_seen_at = now(), \
                 last_ip = COALESCE($2, last_ip), \
                 country_code = COALESCE($3, country_code), \
                 city = COALESCE($4, city) \
             WHERE id = $1",
            &[&family_id, &ip, &country, &city],
        )
        .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, "failed to stamp session activity");
    }
}

/// Record where a session was created. Split from [`create_family`] so the
/// insert stays independent of whether geolocation is switched on.
pub async fn set_family_location(
    client: &deadpool_postgres::Client,
    family_id: Uuid,
    country: Option<&str>,
    city: Option<&str>,
) {
    if country.is_none() && city.is_none() {
        return;
    }
    let result = client
        .execute(
            "UPDATE refresh_token_families SET country_code = $2, city = $3 WHERE id = $1",
            &[&family_id, &country, &city],
        )
        .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, "failed to store session location");
    }
}

/// List a user's live sessions, most recently active first.
pub async fn list_active_for_user(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<Vec<SessionInfo>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT f.id, f.created_at, f.last_seen_at, f.last_ip, f.country_code, \
                        f.city, f.user_agent \
                 FROM refresh_token_families f \
                 WHERE f.user_id = $1 AND {active} \
                 ORDER BY f.last_seen_at DESC",
                active = crate::users::ACTIVE_FAMILY,
            ),
            &[&user_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| SessionInfo {
            id: r.get("id"),
            created_at: r.get("created_at"),
            last_seen_at: r.get("last_seen_at"),
            ip: r.get::<_, Option<IpAddr>>("last_ip").map(|a| a.to_string()),
            country_code: r.get("country_code"),
            city: r.get("city"),
            user_agent: r.get("user_agent"),
        })
        .collect())
}

/// Forget every stored session location.
///
/// Backs the admin "clear collected location data" action: IP-derived city is
/// personal data, so switching geolocation off must be able to erase what was
/// already gathered, not merely stop gathering more. Returns the row count.
pub async fn purge_locations(client: &deadpool_postgres::Client) -> Result<u64, DbError> {
    let n = client
        .execute(
            "UPDATE refresh_token_families SET country_code = NULL, city = NULL \
             WHERE country_code IS NOT NULL OR city IS NOT NULL",
            &[],
        )
        .await?;
    Ok(n)
}
