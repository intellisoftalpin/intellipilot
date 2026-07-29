//! Two-factor: TOTP enrollment, recovery codes, and the MFA login challenge.
//!
//! `manual_let_else`/`collapsible_if` are allowed: several handlers match on a
//! pool/result and need the error arm to build a tailored Problem response,
//! which `let...else` can't express cleanly.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::manual_let_else,
    clippy::collapsible_if,
    clippy::result_large_err
)]

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use garde::Validate;
use intellipilot_auth::token::verify_mfa_token;
use intellipilot_auth::{recovery, secret, totp};
use intellipilot_db::{audit, recovery as db_recovery, users};
use serde_json::json;

use crate::auth::handlers::issue_session;
use crate::auth::{AuthUser, client_ip, request_id, user_agent};
use crate::dto::{
    RecoveryCodesResponse, TotpConfirmRequest, TotpStartResponse, TwoFactorVerifyRequest,
};
use crate::problem::Problem;
use crate::state::{AppState, AuthContext};

const ISSUER: &str = "IntelliPilot";

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

fn unauthorized(rid: &str) -> Response {
    problem(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "Unauthorized",
        None,
        rid,
    )
}

fn require_pepper<'a>(auth: &'a AuthContext, rid: &str) -> Result<&'a [u8], Response> {
    auth.pepper_bytes().ok_or_else(|| {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "totp_unavailable",
            "TOTP unavailable",
            Some("server is not configured with a pepper for secret encryption".to_owned()),
            rid,
        )
    })
}

/// `POST /api/v1/me/totp/start`
#[utoipa::path(post, path = "/api/v1/me/totp/start",
    responses((status = 200, body = TotpStartResponse), (status = 401), (status = 503)))]
pub async fn totp_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let pepper = match require_pepper(auth, &rid) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Ok(Some(u)) = users::find_by_id(&client, user.user_id).await else {
        return internal(&rid);
    };

    let secret_bytes = totp::new_secret();
    let Ok(enc) = secret::encrypt(Some(pepper), &secret_bytes) else {
        return internal(&rid);
    };
    if users::set_totp_secret(&client, user.user_id, &enc)
        .await
        .is_err()
    {
        return internal(&rid);
    }

    let (Ok(uri), Ok(qr)) = (
        totp::provisioning_uri(&secret_bytes, ISSUER, &u.email),
        totp::qr_png_base64(&secret_bytes, ISSUER, &u.email),
    ) else {
        return internal(&rid);
    };

    Json(TotpStartResponse {
        secret_base32: totp::secret_base32(&secret_bytes),
        provisioning_uri: uri,
        qr_png_base64: qr,
    })
    .into_response()
}

/// `POST /api/v1/me/totp/confirm` — verify a code, activate TOTP, return codes.
#[utoipa::path(post, path = "/api/v1/me/totp/confirm", request_body = TotpConfirmRequest,
    responses((status = 200, body = RecoveryCodesResponse), (status = 401), (status = 422)))]
pub async fn totp_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    body: Result<Json<TotpConfirmRequest>, JsonRejection>,
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
    if req.validate().is_err() {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
            None,
            &rid,
        );
    }
    let pepper = match require_pepper(auth, &rid) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&rid),
    };

    let Ok(Some((enc, _confirmed))) = users::get_totp(&client, user.user_id).await else {
        return problem(
            StatusCode::CONFLICT,
            "totp_not_started",
            "TOTP not started",
            None,
            &rid,
        );
    };
    let Ok(secret_bytes) = secret::decrypt(Some(pepper), &enc) else {
        return internal(&rid);
    };
    if !totp::verify(&secret_bytes, &req.code) {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_code",
            "Invalid code",
            None,
            &rid,
        );
    }
    if users::confirm_totp(&client, user.user_id).await.is_err() {
        return internal(&rid);
    }

    let codes = match generate_and_store_recovery_codes(auth, &mut client, user.user_id).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    audit::record(
        &client,
        Some(user.user_id),
        "totp_enabled",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({}),
    )
    .await;
    Json(RecoveryCodesResponse {
        recovery_codes: codes,
    })
    .into_response()
}

/// `DELETE /api/v1/me/totp`
#[utoipa::path(delete, path = "/api/v1/me/totp", responses((status = 204), (status = 401)))]
pub async fn totp_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    if users::disable_totp(&client, user.user_id).await.is_err() {
        return internal(&rid);
    }
    audit::record(
        &client,
        Some(user.user_id),
        "totp_disabled",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({}),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /api/v1/me/recovery-codes/regenerate`
#[utoipa::path(post, path = "/api/v1/me/recovery-codes/regenerate",
    responses((status = 200, body = RecoveryCodesResponse), (status = 401)))]
pub async fn recovery_regenerate(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&rid),
    };
    if !users::has_active_2fa(&client, user.user_id)
        .await
        .unwrap_or(false)
    {
        return problem(
            StatusCode::CONFLICT,
            "no_2fa",
            "No active second factor",
            None,
            &rid,
        );
    }
    let codes = match generate_and_store_recovery_codes(auth, &mut client, user.user_id).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    audit::record(
        &client,
        Some(user.user_id),
        "recovery_codes_regenerated",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({}),
    )
    .await;
    Json(RecoveryCodesResponse {
        recovery_codes: codes,
    })
    .into_response()
}

/// `POST /api/v1/auth/2fa/verify` — complete login with a second factor.
#[utoipa::path(post, path = "/api/v1/auth/2fa/verify", request_body = TwoFactorVerifyRequest,
    responses((status = 200), (status = 401)))]
pub async fn two_factor_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Result<Json<TwoFactorVerifyRequest>, JsonRejection>,
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
    if req.validate().is_err() {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
            None,
            &rid,
        );
    }
    let Ok(claims) = verify_mfa_token(&auth.access_key, &req.mfa_token) else {
        return unauthorized(&rid);
    };
    let user_id = claims.user_id;

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let ok = match req.method.as_str() {
        "totp" => verify_totp_factor(auth, &client, user_id, &req.code).await,
        "recovery" => verify_recovery_factor(auth, &client, user_id, &req.code).await,
        _ => false,
    };
    if !ok {
        audit::record(
            &client,
            Some(user_id),
            "login_2fa_failure",
            Some(client_ip(&headers)),
            Some(&user_agent(&headers)),
            &json!({ "method": req.method }),
        )
        .await;
        return unauthorized(&rid);
    }

    issue_session(
        auth,
        &state.geoip,
        &client,
        user_id,
        &headers,
        jar,
        "login_2fa_success",
    )
    .await
}

async fn verify_totp_factor(
    auth: &AuthContext,
    client: &deadpool_postgres::Client,
    user_id: uuid::Uuid,
    code: &str,
) -> bool {
    let Some(pepper) = auth.pepper_bytes() else {
        return false;
    };
    match users::get_totp(client, user_id).await {
        Ok(Some((enc, confirmed))) if confirmed => secret::decrypt(Some(pepper), &enc)
            .map(|s| totp::verify(&s, code))
            .unwrap_or(false),
        _ => false,
    }
}

async fn verify_recovery_factor(
    auth: &AuthContext,
    client: &deadpool_postgres::Client,
    user_id: uuid::Uuid,
    code: &str,
) -> bool {
    let Ok(unused) = db_recovery::list_unused(client, user_id).await else {
        return false;
    };
    for uc in unused {
        if recovery::verify(code, &uc.code_hash, auth.pepper_bytes()) {
            // Atomically consume; if it lost a race, treat as failure.
            return db_recovery::mark_used(client, uc.id).await.unwrap_or(false);
        }
    }
    false
}

async fn generate_and_store_recovery_codes(
    auth: &AuthContext,
    client: &mut deadpool_postgres::Client,
    user_id: uuid::Uuid,
) -> Result<Vec<String>, Response> {
    let rid = "internal";
    let Ok(codes) = recovery::generate_set(auth.pepper_bytes()) else {
        return Err(internal(rid));
    };
    let hashes: Vec<String> = codes.iter().map(|c| c.hash.clone()).collect();
    if db_recovery::replace_all(client, user_id, &hashes)
        .await
        .is_err()
    {
        return Err(internal(rid));
    }
    Ok(codes.into_iter().map(|c| c.plaintext).collect())
}
