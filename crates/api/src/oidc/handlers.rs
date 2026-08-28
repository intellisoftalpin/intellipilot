//! Public sign-in and per-user linking endpoints for OIDC (V025).
//!
//! Two shapes of client are served from one set of flows:
//!
//! * a **browser**, which is redirected out to the provider and back to
//!   `/callback`, where the server sets the refresh cookie and redirects into
//!   the app. Nothing is returned as JSON, because a redirect has no body a
//!   single-page app could read.
//! * a **native client** (desktop, mobile), which uses the device-code flow.
//!   It receives a user code to type at the provider and an opaque poll token,
//!   and gets an ordinary `TokenResponse` once the human finishes — including
//!   the refresh token in the body when it asks, exactly as password login
//!   already does for the multi-account clients.
//!
//! Both end at [`crate::auth::handlers::establish_session`], so an SSO session
//! is indistinguishable from any other once minted.
//!
//! IntelliPilot's own MFA challenge is deliberately *not* applied on this path:
//! the identity provider owns authentication strength here, and stacking a
//! second factor on top of one the IdP already enforced would prompt twice for
//! no gain. Password and LDAP logins are untouched.
//!
//! Lint notes, matching [`crate::auth::handlers`]: `arithmetic_side_effects` is
//! allowed because every arithmetic operation here is bounded time math, and
//! `result_large_err` because an axum `Response` is the intentional error type.
#![allow(clippy::arithmetic_side_effects, clippy::result_large_err)]

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use utoipa::ToSchema;
use uuid::Uuid;

use intellipilot_auth::refresh;
use intellipilot_db::oidc_providers::{self, OidcProvider};
use intellipilot_db::oidc_requests::{self, NewAuthRequest, NewDeviceRequest};
use intellipilot_db::{audit, oidc_identities, sessions, users};

use crate::auth::handlers::establish_session;
use crate::auth::{AuthUser, client_ip, request_id, user_agent};
use crate::problem::Problem;
use crate::state::AppState;

use super::resolve::ResolveError;
use super::{OidcError, backchannel, device, flow, redirect_uri, resolve, safe_redirect_to};

/// How long a browser has to complete an authorization once started.
const AUTH_REQUEST_TTL_SECS: i64 = 10 * 60;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StartQuery {
    /// App-relative path to land on afterwards. Sanitised by
    /// [`safe_redirect_to`] before it is ever stored or emitted.
    #[serde(default)]
    pub redirect_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    /// The provider's own error, when the user declined or it refused.
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceStartResponse {
    /// What the human types at the provider.
    pub user_code: String,
    pub verification_uri: String,
    /// Same page with the code pre-filled, when the provider offers it.
    pub verification_uri_complete: Option<String>,
    /// Opaque token this client polls with. Unrelated to the provider's device
    /// code, which never leaves the server.
    pub poll_token: String,
    pub interval: i32,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DevicePollRequest {
    pub poll_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OidcIdentityResponse {
    pub id: Uuid,
    pub provider_slug: String,
    pub provider_display_name: String,
    pub subject: String,
    pub email_at_link: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LogoutTokenForm {
    #[serde(default)]
    pub logout_token: String,
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn problem(
    status: StatusCode,
    code: &'static str,
    title: &str,
    detail: Option<String>,
    rid: &str,
) -> Response {
    Problem::new(status, code, title, detail, rid).into_response_with_status(status)
}

fn internal(rid: &str) -> Response {
    problem(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal Server Error",
        None,
        rid,
    )
}

fn not_found(rid: &str) -> Response {
    problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, rid)
}

/// Send the browser somewhere in the app.
fn redirect_to_app(origin: &str, path: &str) -> Response {
    let location = format!("{}{}", origin.trim_end_matches('/'), path);
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

/// Bounce back to the login screen with a machine-readable reason.
///
/// The browser flow cannot return a problem document — the user is mid-redirect
/// and would be looking at raw JSON — so the failure travels as a query
/// parameter the login page renders as a message.
fn redirect_with_error(origin: &str, code: &str) -> Response {
    redirect_to_app(origin, &format!("/login?sso_error={code}"))
}

/// The stable error code for a resolution refusal, shared by both flows so the
/// web and native clients can show the same wording.
const fn resolve_code(err: &ResolveError) -> &'static str {
    match err {
        ResolveError::EmailUnverified => "email_unverified",
        ResolveError::EmailConflict => "email_conflict",
        ResolveError::ProvisioningDisabled => "provisioning_disabled",
        ResolveError::SubjectTaken => "already_linked",
        ResolveError::Banned => "account_banned",
        ResolveError::Inactive => "account_inactive",
        ResolveError::InsufficientClaims => "insufficient_claims",
        ResolveError::Db => "internal_error",
    }
}

fn resolve_problem(err: &ResolveError, rid: &str) -> Response {
    let (status, detail) = match err {
        ResolveError::EmailUnverified => (
            StatusCode::FORBIDDEN,
            "your identity provider has not verified your email address",
        ),
        ResolveError::EmailConflict => (
            StatusCode::CONFLICT,
            "an account already uses this email address. Sign in with your existing \
             credentials and connect single sign-on from Security settings.",
        ),
        ResolveError::ProvisioningDisabled => (
            StatusCode::FORBIDDEN,
            "this provider may not create new accounts; ask an administrator to invite you",
        ),
        ResolveError::SubjectTaken => (
            StatusCode::CONFLICT,
            "this identity is already linked to another account",
        ),
        ResolveError::Banned => (StatusCode::FORBIDDEN, "this account has been banned"),
        ResolveError::Inactive => (StatusCode::UNAUTHORIZED, "account is inactive"),
        ResolveError::InsufficientClaims => (
            StatusCode::FORBIDDEN,
            "your identity provider returned no usable account details",
        ),
        ResolveError::Db => return internal(rid),
    };
    problem(
        status,
        resolve_code(err),
        status.canonical_reason().unwrap_or("Error"),
        Some(detail.to_owned()),
        rid,
    )
}

/// Map a provider-side failure onto a status. An unreachable IdP is a 503, not
/// a 500 — the same distinction the LDAP path already draws.
fn oidc_problem(err: &OidcError, rid: &str) -> Response {
    match err {
        OidcError::Config(m) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "oidc_misconfigured",
            "Internal Server Error",
            Some(m.clone()),
            rid,
        ),
        OidcError::Unavailable(m) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc_unavailable",
            "Service Unavailable",
            Some(m.clone()),
            rid,
        ),
        OidcError::Rejected(m) => problem(
            StatusCode::UNAUTHORIZED,
            "oidc_rejected",
            "Unauthorized",
            Some(m.clone()),
            rid,
        ),
        OidcError::Pending | OidcError::SlowDown => problem(
            StatusCode::ACCEPTED,
            "authorization_pending",
            "Accepted",
            None,
            rid,
        ),
    }
}

const fn oidc_code(err: &OidcError) -> &'static str {
    match err {
        OidcError::Config(_) => "oidc_misconfigured",
        OidcError::Unavailable(_) => "oidc_unavailable",
        OidcError::Rejected(_) => "oidc_rejected",
        OidcError::Pending | OidcError::SlowDown => "authorization_pending",
    }
}

/// Fetch an enabled provider by slug.
///
/// A disabled provider is reported as absent rather than as forbidden: the
/// existence of a half-configured provider is not something an unauthenticated
/// caller needs to learn.
async fn enabled_provider(client: &deadpool_postgres::Client, slug: &str) -> Option<OidcProvider> {
    oidc_providers::get_by_slug(client, slug)
        .await
        .ok()
        .flatten()
        .filter(|p| p.enabled)
}

// ---------------------------------------------------------------------------
// Browser flow
// ---------------------------------------------------------------------------

/// `GET /api/v1/auth/oidc/{slug}/start` — begin a browser sign-in.
#[utoipa::path(get, path = "/api/v1/auth/oidc/{slug}/start",
    responses((status = 302, description = "redirect to the identity provider"),
              (status = 404, description = "no such enabled provider")))]
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(q): Query<StartQuery>,
) -> Response {
    start_inner(state, headers, slug, q.redirect_to.as_deref(), None).await
}

/// `GET /api/v1/me/oidc/{slug}/link/start` — begin linking a provider to the
/// signed-in account.
///
/// The self-service half of linking: the user proves control of the
/// IntelliPilot account by being signed in, and control of the IdP account by
/// completing the flow. No email is trusted anywhere in it.
#[utoipa::path(get, path = "/api/v1/me/oidc/{slug}/link/start",
    responses((status = 302), (status = 401), (status = 404)))]
pub async fn link_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(slug): Path<String>,
    Query(q): Query<StartQuery>,
) -> Response {
    start_inner(
        state,
        headers,
        slug,
        q.redirect_to.as_deref(),
        Some(user.user_id),
    )
    .await
}

async fn start_inner(
    state: AppState,
    headers: HeaderMap,
    slug: String,
    redirect_to: Option<&str>,
    link_user_id: Option<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Some(provider) = enabled_provider(&client, &slug).await else {
        return not_found(&rid);
    };

    let uri = redirect_uri(&auth.config.public_origin, &provider.slug);
    let started = match flow::start(&state.oidc, &provider, &uri).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, slug = %slug, "oidc start failed");
            return redirect_with_error(&auth.config.public_origin, oidc_code(&e));
        }
    };

    let purpose = if link_user_id.is_some() {
        "link"
    } else {
        "login"
    };
    let request = NewAuthRequest {
        state: started.state.clone(),
        provider_id: provider.id,
        nonce: started.nonce,
        code_verifier: started.code_verifier,
        purpose: purpose.to_owned(),
        link_user_id,
        redirect_to: safe_redirect_to(redirect_to),
        expires_at: OffsetDateTime::now_utc() + TimeDuration::seconds(AUTH_REQUEST_TTL_SECS),
    };
    if let Err(e) = oidc_requests::create_auth_request(&client, &request).await {
        tracing::error!(error = %e, "failed to store oidc auth request");
        return internal(&rid);
    }

    (
        StatusCode::FOUND,
        [(header::LOCATION, started.authorize_url)],
    )
        .into_response()
}

/// `GET /api/v1/auth/oidc/{slug}/callback` — the provider's redirect target.
///
/// Always answers with a redirect into the app, never a problem document: the
/// caller here is a browser mid-navigation, and showing it JSON would be a
/// dead end for the user. Failures travel as `?sso_error=<code>` on the login
/// page.
#[utoipa::path(get, path = "/api/v1/auth/oidc/{slug}/callback",
    responses((status = 302, description = "redirect into the application")))]
#[allow(clippy::too_many_lines)]
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(slug): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let origin = auth.config.public_origin.clone();

    if let Some(err) = q.error {
        tracing::info!(slug = %slug, error = %err, "identity provider refused authorization");
        return redirect_with_error(&origin, "provider_refused");
    }
    let (Some(code), Some(state_param)) = (q.code, q.state) else {
        return redirect_with_error(&origin, "invalid_callback");
    };

    let Ok(client) = auth.db.pool.get().await else {
        return redirect_with_error(&origin, "internal_error");
    };

    // Single-use claim of the pending request. Doubles as the CSRF check: a
    // `state` we did not mint, already spent, or expired resolves to nothing.
    let pending = match oidc_requests::take_auth_request(&client, &state_param).await {
        Ok(Some(p)) => p,
        Ok(None) => return redirect_with_error(&origin, "invalid_state"),
        Err(e) => {
            tracing::error!(error = %e, "failed to claim oidc auth request");
            return redirect_with_error(&origin, "internal_error");
        }
    };

    let Ok(Some(provider)) = oidc_providers::get(&client, pending.provider_id).await else {
        return redirect_with_error(&origin, "unknown_provider");
    };
    // Checked after the request row is claimed, not before: an admin may have
    // disabled the provider while this flow was in the air.
    if !provider.enabled {
        return redirect_with_error(&origin, "provider_disabled");
    }

    let uri = redirect_uri(&origin, &provider.slug);
    let claims = match flow::exchange(
        &state.oidc,
        &provider,
        &uri,
        &code,
        &pending.code_verifier,
        &pending.nonce,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, slug = %provider.slug, "oidc code exchange failed");
            return redirect_with_error(&origin, oidc_code(&e));
        }
    };
    let facts = resolve::facts_from_claims(&provider, &claims);

    // ---- link flow: bind the identity, mint nothing ----
    if let Some(link_user_id) = pending.link_user_id {
        return match resolve::link_subject(&client, &provider, &facts, link_user_id).await {
            Ok(()) => {
                audit::record(
                    &client,
                    Some(link_user_id),
                    "oidc_identity_linked",
                    Some(client_ip(&headers)),
                    Some(&user_agent(&headers)),
                    &json!({ "provider": provider.slug, "via": "self_service" }),
                )
                .await;
                redirect_to_app(&origin, &format!("{}?sso_linked=1", pending.redirect_to))
            }
            Err(e) => redirect_with_error(&origin, resolve_code(&e)),
        };
    }

    // ---- login flow ----
    let user_id = match resolve::resolve_login(&client, &provider, &facts).await {
        Ok(id) => id,
        Err(e) => {
            tracing::info!(slug = %provider.slug, reason = ?e, "oidc sign-in refused");
            return redirect_with_error(&origin, resolve_code(&e));
        }
    };
    if let Err(e) = resolve::check_account_usable(&client, user_id).await {
        return redirect_with_error(&origin, resolve_code(&e));
    }
    drop(client);

    // Needs a mutable client for the last-superadmin transaction.
    let Ok(mut client) = auth.db.pool.get().await else {
        return redirect_with_error(&origin, "internal_error");
    };
    resolve::sync_superadmin(&mut client, &provider, &facts, user_id).await;

    // The token payload is dropped on purpose: this response is a redirect,
    // and the session travels in the refresh cookie the jar now carries.
    if let Ok((jar, _)) = establish_session(
        auth,
        &state.geoip,
        &client,
        user_id,
        &headers,
        jar,
        "login_success_oidc",
    )
    .await
    {
        (jar, redirect_to_app(&origin, &pending.redirect_to)).into_response()
    } else {
        tracing::error!(request_id = %rid, "failed to establish session after oidc sign-in");
        redirect_with_error(&origin, "internal_error")
    }
}

// ---------------------------------------------------------------------------
// Device flow
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/oidc/{slug}/device/start`
#[utoipa::path(post, path = "/api/v1/auth/oidc/{slug}/device/start",
    responses((status = 200, body = DeviceStartResponse), (status = 404), (status = 503)))]
pub async fn device_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Response {
    device_start_inner(state, headers, slug, None).await
}

/// `POST /api/v1/me/oidc/{slug}/device/link/start` — the native equivalent of
/// [`link_start`].
#[utoipa::path(post, path = "/api/v1/me/oidc/{slug}/device/link/start",
    responses((status = 200, body = DeviceStartResponse), (status = 401), (status = 404)))]
pub async fn device_link_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(slug): Path<String>,
) -> Response {
    device_start_inner(state, headers, slug, Some(user.user_id)).await
}

async fn device_start_inner(
    state: AppState,
    headers: HeaderMap,
    slug: String,
    link_user_id: Option<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Some(provider) = enabled_provider(&client, &slug).await else {
        return not_found(&rid);
    };
    if !provider.device_flow_enabled {
        return not_found(&rid);
    }

    let authorization = match device::start(&state.oidc, &provider).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, slug = %slug, "device authorization failed");
            return oidc_problem(&e, &rid);
        }
    };

    // The client's poll token is independent of the provider's device code and
    // is stored hashed, so a database leak yields nothing pollable.
    let poll = refresh::generate();
    let expires_in = authorization.expires_in_secs();
    let request = NewDeviceRequest {
        provider_id: provider.id,
        device_code: authorization.device_code.clone(),
        user_code: authorization.user_code.clone(),
        verification_uri: authorization.verification_uri.clone(),
        verification_uri_complete: authorization
            .verification_uri_complete
            .clone()
            .unwrap_or_default(),
        interval_secs: authorization.clamped_interval(),
        poll_token_hash: poll.hash.clone(),
        purpose: if link_user_id.is_some() {
            "link".to_owned()
        } else {
            "login".to_owned()
        },
        link_user_id,
        expires_at: OffsetDateTime::now_utc() + TimeDuration::seconds(expires_in),
    };
    match oidc_requests::create_device_request(&client, &request).await {
        Ok(row) => Json(DeviceStartResponse {
            user_code: row.user_code,
            verification_uri: row.verification_uri,
            verification_uri_complete: authorization.verification_uri_complete,
            poll_token: poll.raw,
            interval: row.interval_secs,
            expires_in,
        })
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to store device request");
            internal(&rid)
        }
    }
}

/// `POST /api/v1/auth/oidc/device/poll`
///
/// `202 Accepted` while the human has not finished — an ordinary state of this
/// flow, not an error, so the client simply waits and asks again.
#[utoipa::path(post, path = "/api/v1/auth/oidc/device/poll",
    request_body = DevicePollRequest,
    responses((status = 200, description = "session established"),
              (status = 202, description = "still waiting for the user"),
              (status = 401)))]
#[allow(clippy::too_many_lines)]
pub async fn device_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Result<Json<DevicePollRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(Json(req)) = body else {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            None,
            &rid,
        );
    };

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let hash = refresh::hash_token(req.poll_token.trim());
    let Ok(Some(pending)) = oidc_requests::find_device_request(&client, &hash).await else {
        return problem(
            StatusCode::UNAUTHORIZED,
            "unknown_poll_token",
            "Unauthorized",
            Some("this sign-in attempt has expired; start again".to_owned()),
            &rid,
        );
    };

    // Enforce the provider's poll interval ourselves, so a client that ignores
    // it cannot turn us into a hammer aimed at someone else's IdP.
    if let Some(last) = pending.last_polled_at {
        let wait = TimeDuration::seconds(i64::from(pending.interval_secs));
        if OffsetDateTime::now_utc() - last < wait {
            return problem(
                StatusCode::TOO_MANY_REQUESTS,
                "slow_down",
                "Too Many Requests",
                Some(format!(
                    "wait {} seconds between polls",
                    pending.interval_secs
                )),
                &rid,
            );
        }
    }
    oidc_requests::stamp_device_poll(&client, pending.id).await;

    let Ok(Some(provider)) = oidc_providers::get(&client, pending.provider_id).await else {
        return not_found(&rid);
    };
    if !provider.enabled {
        oidc_requests::delete_device_request(&client, pending.id).await;
        return not_found(&rid);
    }

    let claims = match device::poll(&state.oidc, &provider, &pending.device_code).await {
        Ok(c) => c,
        Err(OidcError::Pending | OidcError::SlowDown) => {
            return (
                StatusCode::ACCEPTED,
                Json(json!({ "status": "pending", "interval": pending.interval_secs })),
            )
                .into_response();
        }
        Err(e) => {
            // Terminal: the human declined, or the code expired. Drop the row so
            // the client stops polling something that can never succeed.
            if matches!(e, OidcError::Rejected(_)) {
                oidc_requests::delete_device_request(&client, pending.id).await;
            }
            tracing::info!(error = %e, slug = %provider.slug, "device poll ended");
            return oidc_problem(&e, &rid);
        }
    };

    // Single-use: whoever wins this race gets the session, everyone else is
    // told the token is unknown.
    match oidc_requests::consume_device_request(&client, pending.id).await {
        Ok(true) => {}
        Ok(false) => {
            return problem(
                StatusCode::UNAUTHORIZED,
                "unknown_poll_token",
                "Unauthorized",
                None,
                &rid,
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to consume device request");
            return internal(&rid);
        }
    }

    let facts = resolve::facts_from_claims(&provider, &claims);

    if let Some(link_user_id) = pending.link_user_id {
        return match resolve::link_subject(&client, &provider, &facts, link_user_id).await {
            Ok(()) => {
                audit::record(
                    &client,
                    Some(link_user_id),
                    "oidc_identity_linked",
                    Some(client_ip(&headers)),
                    Some(&user_agent(&headers)),
                    &json!({ "provider": provider.slug, "via": "device" }),
                )
                .await;
                StatusCode::NO_CONTENT.into_response()
            }
            Err(e) => resolve_problem(&e, &rid),
        };
    }

    let user_id = match resolve::resolve_login(&client, &provider, &facts).await {
        Ok(id) => id,
        Err(e) => return resolve_problem(&e, &rid),
    };
    if let Err(e) = resolve::check_account_usable(&client, user_id).await {
        return resolve_problem(&e, &rid);
    }
    drop(client);

    let Ok(mut client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    resolve::sync_superadmin(&mut client, &provider, &facts, user_id).await;

    crate::auth::handlers::issue_session(
        auth,
        &state.geoip,
        &client,
        user_id,
        &headers,
        jar,
        "login_success_oidc",
    )
    .await
}

// ---------------------------------------------------------------------------
// Back-channel logout
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/oidc/{slug}/backchannel-logout`
///
/// Without this, revoking a user at the identity provider would leave their
/// IntelliPilot session alive for the full refresh-token lifetime — the one
/// respect in which SSO would otherwise be weaker than the LDAP path it sits
/// beside.
#[utoipa::path(post, path = "/api/v1/auth/oidc/{slug}/backchannel-logout",
    responses((status = 200, description = "logout processed"),
              (status = 400, description = "the token did not verify")))]
pub async fn backchannel_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    axum::extract::Form(form): axum::extract::Form<LogoutTokenForm>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Some(provider) = enabled_provider(&client, &slug).await else {
        return not_found(&rid);
    };

    let subject = match backchannel::verify(&state.oidc, &provider, &form.logout_token).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, slug = %slug, "back-channel logout token refused");
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid_logout_token",
                "Bad Request",
                Some(e.to_string()),
                &rid,
            );
        }
    };

    // A token identifying the session only by `sid` is accepted and ignored:
    // we do not record the provider's session id, so there is nothing to match.
    // Answering 400 would make a conforming provider retry forever.
    let Some(sub) = subject.subject else {
        return StatusCode::OK.into_response();
    };

    let user_ids = oidc_identities::find_users_by_issuer_subject(&client, &subject.issuer, &sub)
        .await
        .unwrap_or_default();
    for user_id in &user_ids {
        sessions::revoke_all_for_user(&client, *user_id, "oidc_backchannel_logout").await;
        audit::record(
            &client,
            Some(*user_id),
            "oidc_backchannel_logout",
            Some(client_ip(&headers)),
            Some(&user_agent(&headers)),
            &json!({ "provider": provider.slug }),
        )
        .await;
    }
    tracing::info!(
        slug = %provider.slug,
        sessions_revoked_for = user_ids.len(),
        "processed back-channel logout"
    );
    StatusCode::OK.into_response()
}

// ---------------------------------------------------------------------------
// Linked identities
// ---------------------------------------------------------------------------

/// `GET /api/v1/me/oidc/identities`
#[utoipa::path(get, path = "/api/v1/me/oidc/identities",
    responses((status = 200, body = Vec<OidcIdentityResponse>), (status = 401)))]
pub async fn list_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match oidc_identities::list_for_user(&client, user.user_id).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|v| OidcIdentityResponse {
                    id: v.identity.id,
                    provider_slug: v.provider_slug,
                    provider_display_name: v.provider_display_name,
                    subject: v.identity.subject,
                    email_at_link: v.identity.email_at_link,
                    created_at: v.identity.created_at,
                    last_login_at: v.identity.last_login_at,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to list linked identities");
            internal(&rid)
        }
    }
}

/// `DELETE /api/v1/me/oidc/identities/{id}`
///
/// Refused when it would leave the account with no way back in — no local
/// password and no other linked identity. Locking yourself out by tidying up
/// your Security page is not a thing this should let you do.
#[utoipa::path(delete, path = "/api/v1/me/oidc/identities/{id}",
    responses((status = 204), (status = 401), (status = 404),
              (status = 409, description = "would leave the account unreachable")))]
pub async fn unlink_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };

    let has_password = users::has_local_password(&client, user.user_id)
        .await
        .unwrap_or(false);
    let identity_count = oidc_identities::count_for_user(&client, user.user_id)
        .await
        .unwrap_or(0);
    if !has_password && identity_count <= 1 {
        return problem(
            StatusCode::CONFLICT,
            "last_auth_method",
            "Conflict",
            Some(
                "this is the only way you can sign in; set a password or link another \
                 provider first"
                    .to_owned(),
            ),
            &rid,
        );
    }

    match oidc_identities::unlink(&client, user.user_id, id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(user.user_id),
                "oidc_identity_unlinked",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "identity_id": id.to_string() }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&rid),
        Err(e) => {
            tracing::error!(error = %e, "failed to unlink identity");
            internal(&rid)
        }
    }
}
