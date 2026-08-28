//! In-flight OIDC flows (V025): browser authorization requests and brokered
//! device-code requests.
//!
//! Both tables hold short-lived server-side secrets that must never reach a
//! client — the PKCE verifier and nonce for the browser flow, the IdP's device
//! code for the native one. Both are single-use: the redeeming endpoint deletes
//! or consumes the row, and `create_*` sweeps expired rows first, which keeps
//! the tables small without a background job.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

// --------------------------------------------------------------------------
// Browser authorization requests
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub state: String,
    pub provider_id: Uuid,
    pub nonce: String,
    pub code_verifier: String,
    /// `login` mints a session; `link` binds an identity to [`Self::link_user_id`].
    pub purpose: String,
    pub link_user_id: Option<Uuid>,
    pub redirect_to: String,
    pub expires_at: OffsetDateTime,
}

/// What to create. `redirect_to` must already have been validated by the API
/// layer — this module stores what it is given.
#[derive(Debug, Clone)]
pub struct NewAuthRequest {
    pub state: String,
    pub provider_id: Uuid,
    pub nonce: String,
    pub code_verifier: String,
    pub purpose: String,
    pub link_user_id: Option<Uuid>,
    pub redirect_to: String,
    pub expires_at: OffsetDateTime,
}

const AUTH_COLS: &str = "state, provider_id, nonce, code_verifier, purpose, link_user_id, \
                         redirect_to, expires_at";

fn row_to_auth_request(row: &tokio_postgres::Row) -> AuthRequest {
    AuthRequest {
        state: row.get("state"),
        provider_id: row.get("provider_id"),
        nonce: row.get("nonce"),
        code_verifier: row.get("code_verifier"),
        purpose: row.get("purpose"),
        link_user_id: row.get("link_user_id"),
        redirect_to: row.get("redirect_to"),
        expires_at: row.get("expires_at"),
    }
}

/// Store a pending authorization request, sweeping expired rows on the way.
pub async fn create_auth_request(
    client: &deadpool_postgres::Client,
    new: &NewAuthRequest,
) -> Result<(), DbError> {
    purge_expired(client).await;
    client
        .execute(
            &format!(
                "INSERT INTO oidc_auth_requests ({AUTH_COLS}) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
            ),
            &[
                &new.state,
                &new.provider_id,
                &new.nonce,
                &new.code_verifier,
                &new.purpose,
                &new.link_user_id,
                &new.redirect_to,
                &new.expires_at,
            ],
        )
        .await?;
    Ok(())
}

/// Atomically claim a pending request by its `state`.
///
/// The `DELETE ... RETURNING` is the point: redemption and removal happen in
/// one statement, so two concurrent callbacks carrying the same `state` cannot
/// both succeed. An expired row is deleted and reported as absent, which the
/// caller renders identically to an unknown one.
pub async fn take_auth_request(
    client: &deadpool_postgres::Client,
    state: &str,
) -> Result<Option<AuthRequest>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "DELETE FROM oidc_auth_requests WHERE state = $1 \
                 RETURNING {AUTH_COLS}"
            ),
            &[&state],
        )
        .await?;
    Ok(row
        .as_ref()
        .map(row_to_auth_request)
        .filter(|r| r.expires_at > OffsetDateTime::now_utc()))
}

/// Best-effort sweep of both request tables. Failure is irrelevant — the rows
/// are already rejected on age, this only stops the tables growing.
pub async fn purge_expired(client: &deadpool_postgres::Client) {
    drop(
        client
            .execute(
                "DELETE FROM oidc_auth_requests WHERE expires_at < now()",
                &[],
            )
            .await,
    );
    drop(
        client
            .execute(
                "DELETE FROM oidc_device_requests WHERE expires_at < now()",
                &[],
            )
            .await,
    );
}

// --------------------------------------------------------------------------
// Device-code requests
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DeviceRequest {
    pub id: Uuid,
    pub provider_id: Uuid,
    /// The IdP's device code. Server-side only; never leaves this process.
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub interval_secs: i32,
    pub last_polled_at: Option<OffsetDateTime>,
    pub purpose: String,
    pub link_user_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct NewDeviceRequest {
    pub provider_id: Uuid,
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub interval_secs: i32,
    pub poll_token_hash: String,
    pub purpose: String,
    pub link_user_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
}

const DEVICE_COLS: &str = "id, provider_id, device_code, user_code, verification_uri, \
                           verification_uri_complete, interval_secs, last_polled_at, purpose, \
                           link_user_id, expires_at, consumed_at";

fn row_to_device_request(row: &tokio_postgres::Row) -> DeviceRequest {
    DeviceRequest {
        id: row.get("id"),
        provider_id: row.get("provider_id"),
        device_code: row.get("device_code"),
        user_code: row.get("user_code"),
        verification_uri: row.get("verification_uri"),
        verification_uri_complete: row.get("verification_uri_complete"),
        interval_secs: row.get("interval_secs"),
        last_polled_at: row.get("last_polled_at"),
        purpose: row.get("purpose"),
        link_user_id: row.get("link_user_id"),
        expires_at: row.get("expires_at"),
        consumed_at: row.get("consumed_at"),
    }
}

pub async fn create_device_request(
    client: &deadpool_postgres::Client,
    new: &NewDeviceRequest,
) -> Result<DeviceRequest, DbError> {
    purge_expired(client).await;
    let row = client
        .query_one(
            &format!(
                "INSERT INTO oidc_device_requests \
                   (provider_id, device_code, user_code, verification_uri, \
                    verification_uri_complete, interval_secs, poll_token_hash, purpose, \
                    link_user_id, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING {DEVICE_COLS}"
            ),
            &[
                &new.provider_id,
                &new.device_code,
                &new.user_code,
                &new.verification_uri,
                &new.verification_uri_complete,
                &new.interval_secs,
                &new.poll_token_hash,
                &new.purpose,
                &new.link_user_id,
                &new.expires_at,
            ],
        )
        .await?;
    Ok(row_to_device_request(&row))
}

/// Look up an outstanding device request by the hash of the client's poll
/// token. Consumed and expired rows are excluded, so a replayed poll token
/// cannot mint a second session.
pub async fn find_device_request(
    client: &deadpool_postgres::Client,
    poll_token_hash: &str,
) -> Result<Option<DeviceRequest>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {DEVICE_COLS} FROM oidc_device_requests \
                  WHERE poll_token_hash = $1 AND consumed_at IS NULL AND expires_at > now()"
            ),
            &[&poll_token_hash],
        )
        .await?;
    Ok(row.as_ref().map(row_to_device_request))
}

/// Record a poll attempt, so the server can enforce the IdP's requested
/// interval on the client's behalf.
pub async fn stamp_device_poll(client: &deadpool_postgres::Client, id: Uuid) {
    drop(
        client
            .execute(
                "UPDATE oidc_device_requests SET last_polled_at = now() WHERE id = $1",
                &[&id],
            )
            .await,
    );
}

/// Mark a device request spent. Returns false when someone else got there
/// first, which the caller treats exactly like an unknown token.
pub async fn consume_device_request(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE oidc_device_requests SET consumed_at = now() \
              WHERE id = $1 AND consumed_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(n > 0)
}

/// Drop a device request outright — used when the IdP reports the flow is dead
/// (denied, expired) so the client stops polling a row that can never succeed.
pub async fn delete_device_request(client: &deadpool_postgres::Client, id: Uuid) {
    drop(
        client
            .execute("DELETE FROM oidc_device_requests WHERE id = $1", &[&id])
            .await,
    );
}
