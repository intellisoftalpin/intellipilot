//! Identity & session HTTP handlers.
//!
//! Lint notes:
//! - `arithmetic_side_effects`: every arithmetic op here is bounded time math
//!   (`now() + Duration::seconds(ttl)`), which cannot realistically overflow.
//! - `result_large_err`: handlers return `Result<_, Response>`; an axum
//!   `Response` is intentionally the error type and boxing it adds no value.
#![allow(clippy::arithmetic_side_effects, clippy::result_large_err)]

use std::sync::LazyLock;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use garde::Validate;
use intellipilot_auth::password::{check_strength, hash_password, verify_password};
use intellipilot_auth::refresh::{self, REFRESH_TTL_SECS};
use intellipilot_auth::token::{
    ACCESS_TTL_SECS, MFA_TTL_SECS, issue_access_token, issue_mfa_token,
};
use intellipilot_core::user::{NewUser, NewUserWithFlags};
use intellipilot_db::platform_invitations::{self, PlatformInviteRole};
use intellipilot_db::platform_settings;
use intellipilot_db::{audit, login_attempts, password_reset, sessions, users};
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use crate::auth::{client_ip, lockout_delay, request_id, sha256_hex, user_agent};
use crate::dto::{
    LoginRequest, PasswordResetConfirmBody, PasswordResetRequestBody, PasswordResetRequestResponse,
    RegisterRequest, TokenResponse,
};
use crate::problem::Problem;
use crate::state::{AppState, AuthContext};

const REFRESH_COOKIE: &str = "refresh_token";
const REFRESH_PATH: &str = "/api/v1/auth";
const RESET_TTL_SECS: i64 = 60 * 60; // 1 hour
const FAILURE_WINDOW_SECS: i64 = 60 * 60; // 1 hour

/// A fixed valid Argon2id hash used to equalize timing when a user is not
/// found during login (anti-enumeration).
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    hash_password("timing-equalizer-placeholder", None).unwrap_or_else(|_| {
        // Fallback PHC-shaped string; verification will simply fail.
        "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()
    })
});

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn pepper_bytes(auth: &AuthContext) -> Option<&[u8]> {
    auth.pepper.as_deref().map(Vec::as_slice)
}

// --------------------------------------------------------------------------
// Response helpers
// --------------------------------------------------------------------------

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

fn validation_problem(report: &garde::Report, rid: &str) -> Response {
    use intellipilot_core::error::FieldError;
    let errors: Vec<FieldError> = report
        .iter()
        .map(|(path, err)| FieldError {
            field: path.to_string(),
            code: "invalid".to_owned(),
            message: err.to_string(),
        })
        .collect();
    Problem::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
        "Validation failed",
        None,
        rid,
    )
    .with_errors(errors)
    .into_response_with_status(StatusCode::UNPROCESSABLE_ENTITY)
}

fn parse_json<T: serde::de::DeserializeOwned>(
    body: Result<Json<T>, JsonRejection>,
    rid: &str,
) -> Result<T, Response> {
    match body {
        Ok(Json(v)) => Ok(v),
        Err(JsonRejection::MissingJsonContentType(_)) => Err(problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Unsupported Media Type",
            Some("expected application/json".to_owned()),
            rid,
        )),
        Err(_) => Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            Some("could not parse JSON".to_owned()),
            rid,
        )),
    }
}

fn set_refresh_cookie(jar: CookieJar, raw: &str, auth: &AuthContext) -> CookieJar {
    let cookie = Cookie::build((REFRESH_COOKIE, raw.to_owned()))
        .http_only(true)
        .secure(auth.config.cookie_secure)
        .same_site(SameSite::Strict)
        .path(REFRESH_PATH)
        .max_age(TimeDuration::seconds(REFRESH_TTL_SECS))
        .build();
    jar.add(cookie)
}

fn clear_refresh_cookie(jar: CookieJar) -> CookieJar {
    let cookie = Cookie::build((REFRESH_COOKIE, ""))
        .path(REFRESH_PATH)
        .max_age(TimeDuration::ZERO)
        .build();
    jar.remove(cookie)
}

fn token_response(access: String, dev_refresh: Option<String>) -> TokenResponse {
    TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECS,
        refresh_token: dev_refresh,
    }
}

// --------------------------------------------------------------------------
// POST /api/v1/auth/register
// --------------------------------------------------------------------------

#[utoipa::path(post, path = "/api/v1/auth/register", request_body = RegisterRequest,
    responses(
        (status = 201, body = intellipilot_core::user::User),
        (status = 403, description = "registration is closed or invitation token mismatch"),
        (status = 409),
        (status = 410, description = "invitation token expired or already consumed"),
        (status = 422),
    ))]
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<RegisterRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }
    if check_strength(&req.password, &[&req.email, &req.username]).is_err() {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "weak_password",
            "Weak password",
            Some("password is too short or too guessable".to_owned()),
            &rid,
        );
    }

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    // V011: gate on platform_settings.open_registration. When closed, require
    // a valid invitation_token whose email matches the request email.
    let settings = match platform_settings::get(&client).await {
        Ok(s) => s,
        Err(_) => return internal(&rid),
    };

    let invitation_role = if settings.open_registration {
        // Open registration — anyone can sign up; invitation_token is ignored
        // even if supplied. Always assigns the bare `user` role.
        PlatformInviteRole::User
    } else {
        let Some(raw_token) = req.invitation_token.as_deref().filter(|s| !s.is_empty())
        else {
            return problem(
                StatusCode::FORBIDDEN,
                "registration_closed",
                "Registration is invite-only",
                Some("an invitation token is required".to_owned()),
                &rid,
            );
        };
        let token_hash = sha256_hex(raw_token);

        let invite = match platform_invitations::find_pending(&client, &token_hash).await {
            Ok(Some(inv)) => inv,
            Ok(None) => {
                // Distinguish "never existed" from "already consumed / expired".
                let exists = platform_invitations::exists(&client, &token_hash)
                    .await
                    .unwrap_or(false);
                if exists {
                    return problem(
                        StatusCode::GONE,
                        "invitation_consumed",
                        "Invitation no longer valid",
                        Some("the invitation has already been used or has expired".to_owned()),
                        &rid,
                    );
                }
                return problem(
                    StatusCode::FORBIDDEN,
                    "invitation_invalid",
                    "Invitation invalid",
                    Some("the invitation token was not recognised".to_owned()),
                    &rid,
                );
            }
            Err(_) => return internal(&rid),
        };

        // Email must match the invitation (case-insensitive). Stops token reuse
        // by a third party who happens to learn the token.
        let req_email_norm = req.email.trim().to_lowercase();
        if invite.email.trim().to_lowercase() != req_email_norm {
            return problem(
                StatusCode::FORBIDDEN,
                "invitation_email_mismatch",
                "Invitation email mismatch",
                Some("the email does not match the invitation".to_owned()),
                &rid,
            );
        }

        // Atomically consume the token before doing the insert; if the
        // CAS fails, somebody else just consumed it.
        let consumed = platform_invitations::mark_accepted(&client, &token_hash)
            .await
            .unwrap_or(false);
        if !consumed {
            return problem(
                StatusCode::GONE,
                "invitation_consumed",
                "Invitation no longer valid",
                Some("the invitation has already been used or has expired".to_owned()),
                &rid,
            );
        }

        invite.role
    };

    // Hash AFTER token check (the cheap unrelated work) — argon2 cost only
    // borne by attempts that pass authorization. Anti-enumeration timing
    // parity is already provided by the conflict path below.
    let Ok(hash) = hash_password(&req.password, pepper_bytes(auth)) else {
        return internal(&rid);
    };

    let new = NewUserWithFlags {
        new: NewUser {
            email: req.email.clone(),
            username: req.username.clone(),
            full_name: req.full_name.clone(),
            password_hash: hash,
        },
        is_superadmin: matches!(invitation_role, PlatformInviteRole::Superadmin),
        must_change_password: false,
    };
    match users::create_with_flags(&client, &new).await {
        Ok(user) => {
            let ip = client_ip(&headers);
            audit::record(
                &client,
                Some(user.id),
                "register",
                Some(ip),
                Some(&user_agent(&headers)),
                &json!({"is_superadmin": user.is_superadmin}),
            )
            .await;
            (StatusCode::CREATED, Json(user)).into_response()
        }
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "already_exists",
            "Already Exists",
            Some("email or username is already taken".to_owned()),
            &rid,
        ),
        Err(_) => internal(&rid),
    }
}

// --------------------------------------------------------------------------
// POST /api/v1/auth/login
// --------------------------------------------------------------------------

#[utoipa::path(post, path = "/api/v1/auth/login", request_body = LoginRequest,
    responses((status = 200, body = TokenResponse), (status = 401)))]
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }

    let ip = client_ip(&headers);
    let id_hash = sha256_hex(&users::normalize_email(&req.email));

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    // Progressive lockout based on recent failures.
    let since = now() - TimeDuration::seconds(FAILURE_WINDOW_SECS);
    let failures = login_attempts::recent_failures(&client, &id_hash, ip, since)
        .await
        .unwrap_or(0);
    let delay = lockout_delay(failures);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }

    let found = users::find_by_email_with_secret(&client, &req.email)
        .await
        .ok()
        .flatten();

    // Verify with timing parity: when no user/hash, verify against a dummy.
    let verified = if let Some(hash) = found.as_ref().and_then(|u| u.password_hash.as_deref()) {
        verify_password(&req.password, hash, pepper_bytes(auth)).unwrap_or(false)
    } else {
        let _ = verify_password(&req.password, &DUMMY_HASH, pepper_bytes(auth));
        false
    };

    let active = found.as_ref().is_some_and(|u| u.user.is_active);
    if !verified || !active {
        login_attempts::record(&client, &id_hash, ip, false).await;
        let actor = found.as_ref().map(|u| u.user.id);
        audit::record(
            &client,
            actor,
            "login_failure",
            Some(ip),
            Some(&user_agent(&headers)),
            &json!({}),
        )
        .await;
        return problem(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Unauthorized",
            Some("invalid email or password".to_owned()),
            &rid,
        );
    }

    // `verified` is only true when `found` is `Some`, but make it explicit.
    let Some(found_user) = found else {
        return internal(&rid);
    };
    let user = found_user.user;
    login_attempts::record(&client, &id_hash, ip, true).await;

    // If the user has a second factor, issue a short-lived MFA challenge
    // instead of a session; the client completes via /auth/2fa/verify (or a
    // passkey ceremony).
    if users::has_active_2fa(&client, user.id)
        .await
        .unwrap_or(false)
    {
        let Ok(mfa_token) = issue_mfa_token(&auth.access_key, user.id, MFA_TTL_SECS) else {
            return internal(&rid);
        };
        audit::record(
            &client,
            Some(user.id),
            "login_mfa_challenge",
            Some(ip),
            Some(&user_agent(&headers)),
            &json!({}),
        )
        .await;
        return Json(json!({
            "mfa_required": true,
            "mfa_token": mfa_token,
            "methods": ["totp", "recovery", "passkey"],
        }))
        .into_response();
    }

    issue_session(auth, &client, user.id, &headers, jar, "login_success").await
}

/// Create a session (refresh family + access token), set the cookie, write an
/// audit entry, and return a [`TokenResponse`]. Shared by login, 2FA verify,
/// and passkey authentication.
pub(crate) async fn issue_session(
    auth: &AuthContext,
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    headers: &HeaderMap,
    jar: CookieJar,
    audit_action: &str,
) -> Response {
    let rid = request_id(headers);
    let ip = client_ip(headers);
    let ua = user_agent(headers);

    let Ok(family_id) = sessions::create_family(client, user_id, &ua, Some(ip)).await else {
        return internal(&rid);
    };
    let new_refresh = refresh::generate();
    let expires = now() + TimeDuration::seconds(REFRESH_TTL_SECS);
    if sessions::insert_token(client, family_id, &new_refresh.hash, None, expires)
        .await
        .is_err()
    {
        return internal(&rid);
    }
    let Ok(access) = issue_access_token(&auth.access_key, user_id, ACCESS_TTL_SECS) else {
        return internal(&rid);
    };
    audit::record(
        client,
        Some(user_id),
        audit_action,
        Some(ip),
        Some(&ua),
        &json!({}),
    )
    .await;

    let dev_refresh = auth.config.env.is_dev().then(|| new_refresh.raw.clone());
    let jar = set_refresh_cookie(jar, &new_refresh.raw, auth);
    (jar, Json(token_response(access, dev_refresh))).into_response()
}

// --------------------------------------------------------------------------
// POST /api/v1/auth/refresh
// --------------------------------------------------------------------------

#[utoipa::path(post, path = "/api/v1/auth/refresh",
    responses((status = 200, body = TokenResponse), (status = 401)))]
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();

    let Some(raw) = jar.get(REFRESH_COOKIE).map(|c| c.value().to_owned()) else {
        return problem(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
            None,
            &rid,
        );
    };
    let hash = refresh::hash_token(&raw);

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let Ok(lookup) = sessions::find_by_hash(&client, &hash).await else {
        return internal(&rid);
    };
    let Some(lk) = lookup else {
        return problem(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
            None,
            &rid,
        );
    };

    if lk.family_revoked {
        return unauthorized_clear(&rid, jar);
    }

    // Reuse detection: a token already used means the family is compromised.
    if lk.used_at.is_some() {
        sessions::revoke_family(&client, lk.family_id, "reuse_detected").await;
        audit::record(
            &client,
            Some(lk.user_id),
            "refresh_reuse_detected",
            Some(client_ip(&headers)),
            Some(&user_agent(&headers)),
            &json!({ "family_id": lk.family_id.to_string() }),
        )
        .await;
        return unauthorized_clear(&rid, jar);
    }

    if lk.expires_at <= now() {
        return unauthorized_clear(&rid, jar);
    }

    // Atomic rotate: if we lose the race, treat as reuse.
    match sessions::mark_used(&client, lk.token_id).await {
        Ok(true) => {}
        Ok(false) => {
            sessions::revoke_family(&client, lk.family_id, "reuse_detected").await;
            return unauthorized_clear(&rid, jar);
        }
        Err(_) => return internal(&rid),
    }

    let new_refresh = refresh::generate();
    let expires = now() + TimeDuration::seconds(REFRESH_TTL_SECS);
    if sessions::insert_token(
        &client,
        lk.family_id,
        &new_refresh.hash,
        Some(lk.token_id),
        expires,
    )
    .await
    .is_err()
    {
        return internal(&rid);
    }
    let Ok(access) = issue_access_token(&auth.access_key, lk.user_id, ACCESS_TTL_SECS) else {
        return internal(&rid);
    };
    audit::record(
        &client,
        Some(lk.user_id),
        "refresh",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({}),
    )
    .await;

    let dev_refresh = auth.config.env.is_dev().then(|| new_refresh.raw.clone());
    let jar = set_refresh_cookie(jar, &new_refresh.raw, auth);
    (jar, Json(token_response(access, dev_refresh))).into_response()
}

fn unauthorized_clear(rid: &str, jar: CookieJar) -> Response {
    let jar = clear_refresh_cookie(jar);
    (
        jar,
        problem(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
            None,
            rid,
        ),
    )
        .into_response()
}

// --------------------------------------------------------------------------
// POST /api/v1/auth/logout
// --------------------------------------------------------------------------

#[utoipa::path(post, path = "/api/v1/auth/logout", responses((status = 204)))]
pub async fn logout(State(state): State<AppState>, headers: HeaderMap, jar: CookieJar) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();

    if let Some(raw) = jar.get(REFRESH_COOKIE).map(|c| c.value().to_owned()) {
        if let Ok(client) = auth.db.pool.get().await {
            let hash = refresh::hash_token(&raw);
            if let Ok(Some(lk)) = sessions::find_by_hash(&client, &hash).await {
                sessions::revoke_family(&client, lk.family_id, "logout").await;
                audit::record(
                    &client,
                    Some(lk.user_id),
                    "logout",
                    Some(client_ip(&headers)),
                    Some(&user_agent(&headers)),
                    &json!({}),
                )
                .await;
            }
        } else {
            return internal(&rid);
        }
    }

    let jar = clear_refresh_cookie(jar);
    (jar, StatusCode::NO_CONTENT).into_response()
}

// --------------------------------------------------------------------------
// POST /api/v1/auth/password/reset/request
// --------------------------------------------------------------------------

#[utoipa::path(post, path = "/api/v1/auth/password/reset/request",
    request_body = PasswordResetRequestBody, responses((status = 200)))]
pub async fn password_reset_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PasswordResetRequestBody>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    // Always respond 200 regardless of account existence (anti-enumeration).
    let mut dev_token = None;
    if let Ok(Some(found)) = users::find_by_email_with_secret(&client, &req.email).await {
        let token = refresh::generate();
        let expires = now() + TimeDuration::seconds(RESET_TTL_SECS);
        if let Err(e) = password_reset::create(&client, found.user.id, &token.hash, expires).await {
            tracing::warn!(error = %e, "failed to create password reset token");
        }
        audit::record(
            &client,
            Some(found.user.id),
            "password_reset_requested",
            Some(client_ip(&headers)),
            Some(&user_agent(&headers)),
            &json!({}),
        )
        .await;
        // Mailer is off by default; in dev surface the token directly.
        if !auth.mailer.is_configured() && auth.config.env.is_dev() {
            dev_token = Some(token.raw);
        }
        // (When a mailer is configured, send the email here.)
    }

    Json(PasswordResetRequestResponse {
        status: "ok",
        reset_token: dev_token,
    })
    .into_response()
}

// --------------------------------------------------------------------------
// POST /api/v1/auth/password/reset/confirm
// --------------------------------------------------------------------------

#[utoipa::path(post, path = "/api/v1/auth/password/reset/confirm",
    request_body = PasswordResetConfirmBody, responses((status = 204), (status = 400), (status = 422)))]
pub async fn password_reset_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PasswordResetConfirmBody>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }
    if check_strength(&req.new_password, &[]).is_err() {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "weak_password",
            "Weak password",
            Some("password is too short or too guessable".to_owned()),
            &rid,
        );
    }

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let token_hash = refresh::hash_token(&req.token);
    let user_id = match password_reset::consume(&client, &token_hash).await {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid_token",
                "Invalid or expired token",
                None,
                &rid,
            );
        }
        Err(_) => return internal(&rid),
    };

    let Ok(hash) = hash_password(&req.new_password, pepper_bytes(auth)) else {
        return internal(&rid);
    };
    if client
        .execute(
            "UPDATE users SET password_hash = $2 WHERE id = $1",
            &[&user_id, &hash],
        )
        .await
        .is_err()
    {
        return internal(&rid);
    }
    // Revoke all sessions after a password change.
    sessions::revoke_all_for_user(&client, user_id, "password_reset").await;
    audit::record(
        &client,
        Some(user_id),
        "password_changed",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({}),
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}
