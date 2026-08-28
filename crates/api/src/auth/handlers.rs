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
use intellipilot_db::{audit, ldap_settings, login_attempts, password_reset, sessions, users};
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use crate::auth::{client_ip, lockout_delay, request_id, sha256_hex, user_agent};
use crate::dto::{
    AuthConfigResponse, LoginRequest, PasswordResetConfirmBody, PasswordResetRequestBody,
    PasswordResetRequestResponse, RefreshRequest, RegisterRequest, SsoProviderSummary,
    TokenResponse,
};
use crate::ldap::{LdapAuthenticator, LdapConfig, LdapError, RealLdap};
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
    let summary = errors
        .iter()
        .map(|e| format!("{}: {}", e.field, e.message))
        .collect::<Vec<_>>()
        .join("; ");
    tracing::warn!(request_id = %rid, fields = %summary, "request validation failed");
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
        Err(e) => {
            tracing::warn!(request_id = %rid, error = %e, "request body parse failed");
            Err(problem(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "Invalid Request Body",
                Some("could not parse JSON".to_owned()),
                rid,
            ))
        }
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

/// Header a cookie-less client sends to ask for the refresh token in the
/// response body.
///
/// Desktop and mobile hold several accounts at once and therefore cannot keep
/// one refresh cookie per account in a single jar — they store each account's
/// token in the OS keychain instead. `POST /auth/refresh` already honours this
/// by echoing the rotated token to a caller that authenticated by body; the
/// session-creating endpoints had no equivalent, so a native client could sign
/// in and never receive a token it could persist.
///
/// Checked in [`issue_session`] rather than per endpoint on purpose: login, 2FA
/// verify, passkey authentication and invitation acceptance all mint sessions,
/// and gating this per handler is exactly how login came to be the one that
/// was missed. Browsers never send it, so the cookie stays the only carrier
/// there and remains HttpOnly.
pub(crate) const REFRESH_IN_BODY_HEADER: &str = "x-intellipilot-refresh-in-body";

/// The refresh token this request carries, and whether it came from the body.
///
/// Cookie wins; the body is the fallback. Which one it was decides whether the
/// rotated token goes back in the response, since a body caller has no cookie
/// jar to receive it — see [`should_echo_refresh`].
fn refresh_token_from(
    jar: &CookieJar,
    body: Option<Json<RefreshRequest>>,
) -> Option<(String, bool)> {
    if let Some(c) = jar.get(REFRESH_COOKIE) {
        return Some((c.value().to_owned(), false));
    }
    body.and_then(|Json(b)| b.refresh_token)
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .map(|t| (t, true))
}

/// Whether the refresh token belongs in this response's body.
///
/// One policy, three reasons: the caller authenticated by body and so has no
/// cookie to read the rotation from (`by_body`), the caller asked via
/// [`REFRESH_IN_BODY_HEADER`], or the server is in dev, which has always handed
/// it over for clients with no cookie jar.
fn should_echo_refresh(by_body: bool, headers: &HeaderMap, auth: &AuthContext) -> bool {
    by_body
        || auth.config.env.is_dev()
        || headers
            .get(REFRESH_IN_BODY_HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn token_response(access: String, refresh_in_body: Option<String>) -> TokenResponse {
    TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECS,
        refresh_token: refresh_in_body,
    }
}

// --------------------------------------------------------------------------
// GET /api/v1/auth/config
// --------------------------------------------------------------------------

/// `GET /api/v1/auth/config` — public. Tells unauthenticated UIs whether
/// self-service signup is open and whether email password reset is available.
#[utoipa::path(get, path = "/api/v1/auth/config",
    responses((status = 200, body = AuthConfigResponse)))]
pub async fn config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Ok(settings) = platform_settings::get(&client).await else {
        return internal(&rid);
    };
    // Email reset is available when an outbound mail channel is configured.
    let password_reset_enabled = intellipilot_db::notification_settings::get(&client)
        .await
        .map(|s| crate::notify::mail_ready(&s))
        .unwrap_or(false);
    // Enabled providers only; a half-configured one must not appear on a
    // login screen. A failure here degrades to "no SSO buttons" rather than
    // taking the login screen down with it.
    let sso_providers = intellipilot_db::oidc_providers::list_enabled(&client)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|p| SsoProviderSummary {
            slug: p.slug,
            display_name: p.display_name,
            device_flow_enabled: p.device_flow_enabled,
            sort_order: p.sort_order,
        })
        .collect();

    Json(AuthConfigResponse {
        open_registration: settings.open_registration,
        password_reset_enabled,
        app_name: settings.app_name,
        app_message: settings.app_message,
        has_custom_icon: settings.app_icon_mime.is_some(),
        app_icon_updated_at: settings.app_icon_updated_at,
        sso_providers,
        local_password_login_disabled: settings.local_password_login_disabled,
    })
    .into_response()
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
#[allow(clippy::too_many_lines)]
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
    let Ok(settings) = platform_settings::get(&client).await else {
        return internal(&rid);
    };

    let invitation_role = if settings.open_registration {
        // Open registration — anyone can sign up; invitation_token is ignored
        // even if supplied. Always assigns the bare `user` role.
        PlatformInviteRole::User
    } else {
        let Some(raw_token) = req.invitation_token.as_deref().filter(|s| !s.is_empty()) else {
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
#[allow(clippy::too_many_lines)]
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

    // Accept either an email or a username as the login identifier.
    let found = users::find_by_identifier_with_secret(&client, &req.email)
        .await
        .ok()
        .flatten();

    // LDAP routing: when LDAP is enabled, every account EXCEPT a local
    // superadmin (one that still has a local password — break-glass)
    // authenticates against the directory.
    let is_local_superadmin = found
        .as_ref()
        .is_some_and(|u| u.user.is_superadmin && u.password_hash.is_some());

    // SSO enforcement (V025). A deployment that has proven its identity
    // provider can switch the password form off; this refuses the endpoint too,
    // so hiding the form in the UI is not the only thing standing in the way.
    //
    // It covers the LDAP path as well as the local one, because both arrive
    // through this same form — "password login is off" would be a lie if a
    // directory password still worked. The break-glass carve-out is the same
    // one LDAP already relies on, and is the reason enabling this can never
    // lock an operator out of their own deployment.
    if !is_local_superadmin
        && platform_settings::get(&client)
            .await
            .is_ok_and(|s| s.local_password_login_disabled)
    {
        audit::record(
            &client,
            found.as_ref().map(|u| u.user.id),
            "login_failure",
            Some(ip),
            Some(&user_agent(&headers)),
            &json!({ "reason": "local_login_disabled", "identifier": req.email }),
        )
        .await;
        return problem(
            StatusCode::FORBIDDEN,
            "local_login_disabled",
            "Forbidden",
            Some("password sign-in is disabled on this server; use single sign-on".to_owned()),
            &rid,
        );
    }
    if let Ok(settings) = ldap_settings::get(&client).await
        && settings.enabled
        && !is_local_superadmin
    {
        let ua = user_agent(&headers);
        let result = RealLdap::new(LdapConfig::from(&settings))
            .authenticate(&req.email, &req.password)
            .await;
        return match result {
            Ok(u) => {
                let Ok(user) = users::find_or_link_ldap_user(
                    &client,
                    &u.email,
                    &u.username,
                    &u.display_name,
                    u.dn.as_deref(),
                    u.is_superadmin,
                )
                .await
                else {
                    return internal(&rid);
                };
                // Checked AFTER the link/sync above, which is the whole point:
                // `find_or_link_ldap_user` re-enables `is_active` on every
                // directory login, so a ban that lived in `is_active` would be
                // silently undone here. `banned_at` is never touched by the
                // sync, so it survives.
                if users::is_banned(&client, user.id).await.unwrap_or(false) {
                    login_attempts::record(&client, &id_hash, ip, false).await;
                    audit::record(
                        &client,
                        Some(user.id),
                        "login_failure",
                        Some(ip),
                        Some(&ua),
                        &json!({ "reason": "account_banned", "identifier": req.email, "via": "ldap" }),
                    )
                    .await;
                    return problem(
                        StatusCode::FORBIDDEN,
                        "account_banned",
                        "Forbidden",
                        Some("this account has been banned".to_owned()),
                        &rid,
                    );
                }
                if !user.is_active {
                    login_attempts::record(&client, &id_hash, ip, false).await;
                    audit::record(
                        &client,
                        Some(user.id),
                        "login_failure",
                        Some(ip),
                        Some(&ua),
                        &json!({ "reason": "account_inactive", "identifier": req.email, "via": "ldap" }),
                    )
                    .await;
                    return problem(
                        StatusCode::UNAUTHORIZED,
                        "invalid_credentials",
                        "Unauthorized",
                        Some("account is inactive".to_owned()),
                        &rid,
                    );
                }
                login_attempts::record(&client, &id_hash, ip, true).await;
                if users::has_active_2fa(&client, user.id)
                    .await
                    .unwrap_or(false)
                {
                    let Ok(mfa_token) = issue_mfa_token(&auth.access_key, user.id, MFA_TTL_SECS)
                    else {
                        return internal(&rid);
                    };
                    audit::record(
                        &client,
                        Some(user.id),
                        "login_mfa_challenge",
                        Some(ip),
                        Some(&ua),
                        &json!({ "via": "ldap" }),
                    )
                    .await;
                    return Json(json!({
                        "mfa_required": true,
                        "mfa_token": mfa_token,
                        "methods": ["totp", "recovery", "passkey"],
                    }))
                    .into_response();
                }
                issue_session(
                    auth,
                    &state.geoip,
                    &client,
                    user.id,
                    &headers,
                    jar,
                    "login_success_ldap",
                )
                .await
            }
            Err(LdapError::InvalidCredentials) => {
                login_attempts::record(&client, &id_hash, ip, false).await;
                audit::record(
                    &client,
                    found.as_ref().map(|u| u.user.id),
                    "login_failure",
                    Some(ip),
                    Some(&ua),
                    &json!({ "reason": "invalid_credentials", "identifier": req.email, "via": "ldap" }),
                )
                .await;
                problem(
                    StatusCode::UNAUTHORIZED,
                    "invalid_credentials",
                    "Unauthorized",
                    Some("invalid email or password".to_owned()),
                    &rid,
                )
            }
            Err(e) => {
                audit::record(
                    &client,
                    None,
                    "login_ldap_error",
                    Some(ip),
                    Some(&ua),
                    &json!({ "error": e.to_string() }),
                )
                .await;
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ldap_unavailable",
                    "Service Unavailable",
                    Some("directory authentication is unavailable".to_owned()),
                    &rid,
                )
            }
        };
    }

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
        // Internal-only reason (this is an admin audit log, not the client
        // response, which stays deliberately vague).
        let reason = if found.is_none() {
            "unknown_user"
        } else if !verified {
            "bad_password"
        } else {
            "account_inactive"
        };
        audit::record(
            &client,
            actor,
            "login_failure",
            Some(ip),
            Some(&user_agent(&headers)),
            &json!({ "reason": reason, "identifier": req.email, "via": "password" }),
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

    // A ban is independent of `is_active`, so the check above does not cover
    // it. Deliberately reported distinctly from bad credentials: the operator
    // took this action knowingly, and leaving the user to guess at a password
    // that is not the problem helps nobody.
    if users::is_banned(&client, user.id).await.unwrap_or(false) {
        login_attempts::record(&client, &id_hash, ip, false).await;
        audit::record(
            &client,
            Some(user.id),
            "login_failure",
            Some(ip),
            Some(&user_agent(&headers)),
            &json!({ "reason": "account_banned", "identifier": req.email, "via": "password" }),
        )
        .await;
        return problem(
            StatusCode::FORBIDDEN,
            "account_banned",
            "Forbidden",
            Some("this account has been banned".to_owned()),
            &rid,
        );
    }

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

    issue_session(
        auth,
        &state.geoip,
        &client,
        user.id,
        &headers,
        jar,
        "login_success",
    )
    .await
}

/// Create a session (refresh family + access token), set the cookie, write an
/// audit entry, and return a [`TokenResponse`]. Shared by login, 2FA verify,
/// and passkey authentication.
pub(crate) async fn issue_session(
    auth: &AuthContext,
    geoip: &crate::geoip::GeoIp,
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    headers: &HeaderMap,
    jar: CookieJar,
    audit_action: &str,
) -> Response {
    match establish_session(auth, geoip, client, user_id, headers, jar, audit_action).await {
        Ok((jar, body)) => (jar, Json(body)).into_response(),
        Err(response) => response,
    }
}

/// The body of [`issue_session`], handing back the cookie jar and the token
/// payload separately.
///
/// The OIDC browser callback needs exactly this: it must set the refresh
/// cookie, but its response is a redirect back to the app rather than a JSON
/// body. Splitting it here means both paths mint sessions through the same
/// code — session family, geolocation, first-login detection and audit trail
/// included — instead of the redirect path growing its own copy that would
/// drift.
pub(crate) async fn establish_session(
    auth: &AuthContext,
    geoip: &crate::geoip::GeoIp,
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    headers: &HeaderMap,
    jar: CookieJar,
    audit_action: &str,
) -> Result<(CookieJar, TokenResponse), Response> {
    let rid = request_id(headers);
    let ip = client_ip(headers);
    let ua = user_agent(headers);

    let Ok(family_id) = sessions::create_family(client, user_id, &ua, Some(ip)).await else {
        return Err(internal(&rid));
    };
    // Resolve where this session started. Inert unless a superadmin enabled
    // geolocation and a database is installed; entirely local either way.
    if let Some(loc) = geoip.lookup(ip) {
        sessions::set_family_location(
            client,
            family_id,
            loc.country_code.as_deref(),
            loc.city.as_deref(),
        )
        .await;
    }
    let new_refresh = refresh::generate();
    let expires = now() + TimeDuration::seconds(REFRESH_TTL_SECS);
    if sessions::insert_token(client, family_id, &new_refresh.hash, None, expires)
        .await
        .is_err()
    {
        return Err(internal(&rid));
    }
    let Ok(access) = issue_access_token(&auth.access_key, user_id, ACCESS_TTL_SECS) else {
        return Err(internal(&rid));
    };
    // Detect the user's first-ever successful login (across password + LDAP)
    // BEFORE recording this success, then emit a one-time `login_first` event.
    let is_first_login = audit::count_for_actor_actions(
        client,
        user_id,
        // Every action that establishes a session must be listed. Miss one and
        // that route's users get a fresh `login_first` event on *every* login.
        &["login_success", "login_success_ldap", "login_success_oidc"],
    )
    .await
    .unwrap_or(1)
        == 0;
    let via = if audit_action.contains("ldap") {
        "ldap"
    } else if audit_action.contains("oidc") {
        "oidc"
    } else {
        "password"
    };
    audit::record(
        client,
        Some(user_id),
        audit_action,
        Some(ip),
        Some(&ua),
        &json!({ "via": via }),
    )
    .await;
    if is_first_login {
        audit::record(
            client,
            Some(user_id),
            "login_first",
            Some(ip),
            Some(&ua),
            &json!({ "via": via }),
        )
        .await;
    }
    if let Err(e) = users::stamp_login(client, user_id).await {
        // Cosmetic for the admin list — never fail a login over it.
        tracing::warn!(error = %e, "failed to stamp last_login_at");
    }

    // A client with no cookie jar must be handed the token, or it has no way to
    // stay signed in.
    let echo_refresh = should_echo_refresh(false, headers, auth).then(|| new_refresh.raw.clone());
    let jar = set_refresh_cookie(jar, &new_refresh.raw, auth);
    Ok((jar, token_response(access, echo_refresh)))
}

// --------------------------------------------------------------------------
// POST /api/v1/auth/refresh
// --------------------------------------------------------------------------

/// Rotate a refresh token.
///
/// The token comes from the `refresh_token` cookie when present, and only
/// otherwise from an optional JSON body. Cookie-first is deliberate: browsers
/// always have the cookie, so the web client's behaviour is untouched and the
/// body path exists purely for clients that cannot keep one cookie per
/// account in a single jar (the desktop and mobile apps, which hold several
/// accounts at once).
#[utoipa::path(post, path = "/api/v1/auth/refresh", request_body = Option<RefreshRequest>,
    responses((status = 200, body = TokenResponse), (status = 401)))]
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Option<Json<RefreshRequest>>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();

    let Some((raw, by_body)) = refresh_token_from(&jar, body) else {
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

    // A banned or deactivated account must not be able to extend its session.
    // Without this a ban would only bite once the 15-minute access token ran
    // out AND the client stopped refreshing — i.e. never.
    match users::touch_last_seen(&client, lk.user_id).await {
        Ok(Some(status)) if status.may_authenticate() => {}
        Ok(_) => {
            sessions::revoke_family(&client, lk.family_id, "account_blocked").await;
            return unauthorized_clear(&rid, jar);
        }
        Err(_) => return internal(&rid),
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

    stamp_session_activity(&state, &client, lk.family_id, &headers).await;

    // A body caller must be handed the rotated token — it has nowhere else to
    // get it, and the previous one is now spent.
    let echo_refresh =
        should_echo_refresh(by_body, &headers, auth).then(|| new_refresh.raw.clone());
    let jar = set_refresh_cookie(jar, &new_refresh.raw, auth);
    (jar, Json(token_response(access, echo_refresh))).into_response()
}

/// Record where and when a session was last used.
///
/// Refresh rotation is the only regular signal we get about a long-lived
/// session, so this is the source of both the admin list's "last active" and
/// the location shown for that session. The geolocation lookup is local and
/// inert unless a superadmin enabled it.
async fn stamp_session_activity(
    state: &AppState,
    client: &deadpool_postgres::Client,
    family_id: Uuid,
    headers: &HeaderMap,
) {
    let ip = client_ip(headers);
    let loc = state.geoip.lookup(ip);
    sessions::touch_family(
        client,
        family_id,
        Some(ip),
        loc.as_ref().and_then(|l| l.country_code.as_deref()),
        loc.as_ref().and_then(|l| l.city.as_deref()),
    )
    .await;
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

/// Revoke a session family. Token source mirrors [`refresh`]: cookie first,
/// optional body second.
#[utoipa::path(post, path = "/api/v1/auth/logout", request_body = Option<RefreshRequest>,
    responses((status = 204)))]
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Option<Json<RefreshRequest>>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();

    let token = jar
        .get(REFRESH_COOKIE)
        .map(|c| c.value().to_owned())
        .or_else(|| {
            body.and_then(|Json(b)| b.refresh_token)
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
        });
    if let Some(raw) = token {
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
