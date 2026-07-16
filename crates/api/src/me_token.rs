//! Personal app token self-service (`/api/v1/me/app-token`).
//!
//! Every user can mint exactly one personal token. The raw secret is returned
//! only by create/reset; every other read exposes just the masked hints. The
//! token authenticates as its owner (see `auth::extractor`), so there is no
//! permission or project scoping to manage here — disable/enable/delete/reset
//! is the whole lifecycle.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use intellipilot_core::app_token::PersonalAppToken;
use intellipilot_db::{audit, personal_tokens};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;

use crate::auth::{AuthUser, client_ip, request_id, user_agent};
use crate::problem::Problem;
use crate::state::AppState;

/// Create/reset response: the only place the raw secret ever appears.
#[derive(Debug, Serialize, ToSchema)]
pub struct PersonalTokenSecretResponse {
    pub token: PersonalAppToken,
    /// The raw `ippt_…` secret. Shown exactly once — store it now.
    pub secret: String,
}

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
    problem(
        StatusCode::NOT_FOUND,
        "not_found",
        "Not Found",
        Some("you have no personal app token".to_owned()),
        rid,
    )
}

async fn record(
    client: &deadpool_postgres::Client,
    headers: &HeaderMap,
    user: AuthUser,
    action: &str,
) {
    audit::record(
        client,
        Some(user.user_id),
        action,
        Some(client_ip(headers)),
        Some(&user_agent(headers)),
        &json!({ "self_service": true }),
    )
    .await;
}

/// `GET /api/v1/me/app-token` — the current user's token, masked.
#[utoipa::path(get, path = "/api/v1/me/app-token",
    responses((status = 200, body = PersonalAppToken), (status = 401), (status = 404)))]
pub async fn get_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match personal_tokens::get_by_user(&client, user.user_id).await {
        Ok(Some(t)) => Json(t).into_response(),
        Ok(None) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}

/// `POST /api/v1/me/app-token` — mint the token. 409 if one already exists.
#[utoipa::path(post, path = "/api/v1/me/app-token",
    responses((status = 201, body = PersonalTokenSecretResponse), (status = 401), (status = 409)))]
pub async fn create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let minted = intellipilot_auth::app_token::generate_personal();
    match personal_tokens::create(
        &client,
        user.user_id,
        &minted.hash,
        &minted.prefix,
        &minted.last4,
    )
    .await
    {
        Ok(Some(token)) => {
            record(&client, &headers, user, "personal_token_created").await;
            (
                StatusCode::CREATED,
                Json(PersonalTokenSecretResponse {
                    token,
                    secret: minted.raw,
                }),
            )
                .into_response()
        }
        Ok(None) => problem(
            StatusCode::CONFLICT,
            "personal_token_exists",
            "Conflict",
            Some("you already have a personal app token — reset it instead".to_owned()),
            &rid,
        ),
        Err(_) => internal(&rid),
    }
}

/// `POST /api/v1/me/app-token/reset` — replace the secret. The old secret
/// stops working immediately; a disabled token is re-enabled.
#[utoipa::path(post, path = "/api/v1/me/app-token/reset",
    responses((status = 200, body = PersonalTokenSecretResponse), (status = 401), (status = 404)))]
pub async fn reset_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let minted = intellipilot_auth::app_token::generate_personal();
    match personal_tokens::rotate(
        &client,
        user.user_id,
        &minted.hash,
        &minted.prefix,
        &minted.last4,
    )
    .await
    {
        Ok(Some(token)) => {
            record(&client, &headers, user, "personal_token_reset").await;
            Json(PersonalTokenSecretResponse {
                token,
                secret: minted.raw,
            })
            .into_response()
        }
        Ok(None) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}

async fn set_disabled(
    state: &AppState,
    headers: &HeaderMap,
    user: AuthUser,
    disabled: bool,
    action: &str,
) -> Response {
    let rid = request_id(headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match personal_tokens::set_disabled(&client, user.user_id, disabled).await {
        Ok(true) => {
            record(&client, headers, user, action).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}

/// `POST /api/v1/me/app-token/disable` — keep the token but reject its use.
#[utoipa::path(post, path = "/api/v1/me/app-token/disable",
    responses((status = 204), (status = 401), (status = 404)))]
pub async fn disable_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    set_disabled(&state, &headers, user, true, "personal_token_disabled").await
}

/// `POST /api/v1/me/app-token/enable` — lift a disable.
#[utoipa::path(post, path = "/api/v1/me/app-token/enable",
    responses((status = 204), (status = 401), (status = 404)))]
pub async fn enable_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    set_disabled(&state, &headers, user, false, "personal_token_enabled").await
}

/// `DELETE /api/v1/me/app-token` — remove the token entirely.
#[utoipa::path(delete, path = "/api/v1/me/app-token",
    responses((status = 204), (status = 401), (status = 404)))]
pub async fn delete_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match personal_tokens::delete(&client, user.user_id).await {
        Ok(true) => {
            record(&client, &headers, user, "personal_token_deleted").await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}
