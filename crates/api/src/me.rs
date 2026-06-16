//! Current-user endpoints: profile read/update, GDPR export & erase.
//!
//! `arithmetic_side_effects` is allowed: the only arithmetic is bounded time
//! math (`now() + Duration::days(grace)`).
#![allow(clippy::arithmetic_side_effects)]

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_auth::password::{check_strength, hash_password, verify_password};
use intellipilot_core::user::ProfileUpdate;
use intellipilot_db::{audit, sessions, users};
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::auth::{AuthUser, client_ip, request_id, user_agent};
use crate::dto::{ChangePasswordRequest, ProfileUpdateRequest};
use crate::problem::Problem;
use crate::state::AppState;

const ERASE_GRACE_DAYS: i64 = 30;

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

/// A 422 carrying a single field error. Used for self-service password change,
/// where a wrong current password or a weak new password is an input problem —
/// returning 401 there would wrongly trip the client's token-refresh retry.
fn validation_field(rid: &str, field: &str, message: &str) -> Response {
    use intellipilot_core::error::FieldError;
    Problem::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
        "Validation failed",
        None,
        rid,
    )
    .with_errors(vec![FieldError {
        field: field.to_owned(),
        code: "invalid".to_owned(),
        message: message.to_owned(),
    }])
    .into_response_with_status(StatusCode::UNPROCESSABLE_ENTITY)
}

/// `GET /api/v1/me`
#[utoipa::path(get, path = "/api/v1/me",
    responses((status = 200, body = intellipilot_core::user::User), (status = 401)))]
pub async fn get_me(State(state): State<AppState>, headers: HeaderMap, user: AuthUser) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match users::find_by_id(&client, user.user_id).await {
        Ok(Some(u)) => Json(u).into_response(),
        Ok(None) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}

/// `PATCH /api/v1/me`
#[utoipa::path(patch, path = "/api/v1/me", request_body = ProfileUpdateRequest,
    responses((status = 200, body = intellipilot_core::user::User), (status = 401), (status = 422)))]
pub async fn patch_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    body: Result<Json<ProfileUpdateRequest>, JsonRejection>,
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
    if let Err(report) = req.validate() {
        use intellipilot_core::error::FieldError;
        let errors: Vec<FieldError> = report
            .iter()
            .map(|(p, e)| FieldError {
                field: p.to_string(),
                code: "invalid".to_owned(),
                message: e.to_string(),
            })
            .collect();
        return Problem::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
            None,
            &rid,
        )
        .with_errors(errors)
        .into_response_with_status(StatusCode::UNPROCESSABLE_ENTITY);
    }

    let upd = ProfileUpdate {
        full_name: req.full_name,
        lang: req.lang,
        timezone: req.timezone,
    };
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match users::update_profile(&client, user.user_id, &upd).await {
        Ok(Some(u)) => Json(u).into_response(),
        Ok(None) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}

/// `POST /api/v1/me/password` — change own password.
///
/// Local accounts only: LDAP-backed users are rejected (409) since their
/// password is managed by the directory. Requires the current password,
/// enforces strength on the new one, then revokes ALL sessions (the client
/// must log in again) and clears any pending `must_change_password` flag.
#[utoipa::path(post, path = "/api/v1/me/password", request_body = ChangePasswordRequest,
    responses((status = 204), (status = 401), (status = 409), (status = 422)))]
pub async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    body: Result<Json<ChangePasswordRequest>, JsonRejection>,
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
        return validation_field(&rid, "new_password", "password is required");
    }

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let found = match users::find_by_id_with_secret(&client, user.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(&rid),
        Err(_) => return internal(&rid),
    };

    // LDAP accounts have no local password to change.
    if found.user.auth_source != "local" {
        return problem(
            StatusCode::CONFLICT,
            "password_managed_externally",
            "Conflict",
            Some("password is managed by your directory and cannot be changed here".to_owned()),
            &rid,
        );
    }

    // Re-verify the current password.
    let current_ok = found.password_hash.as_deref().is_some_and(|h| {
        verify_password(&req.current_password, h, auth.pepper_bytes()).unwrap_or(false)
    });
    if !current_ok {
        return validation_field(&rid, "current_password", "current password is incorrect");
    }

    // Enforce strength on the new password (length + zxcvbn).
    if check_strength(
        &req.new_password,
        &[&found.user.email, &found.user.username],
    )
    .is_err()
    {
        return validation_field(&rid, "new_password", "password is too weak");
    }

    let Ok(hash) = hash_password(&req.new_password, auth.pepper_bytes()) else {
        return internal(&rid);
    };
    if client
        .execute(
            "UPDATE users SET password_hash = $2, must_change_password = false WHERE id = $1",
            &[&user.user_id, &hash],
        )
        .await
        .is_err()
    {
        return internal(&rid);
    }
    // Revoke every session after a password change; the user re-authenticates.
    sessions::revoke_all_for_user(&client, user.user_id, "password_changed").await;
    audit::record(
        &client,
        Some(user.user_id),
        "password_changed",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "self_service": true }),
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

/// `DELETE /api/v1/me` — GDPR erase (soft, with grace period).
#[utoipa::path(delete, path = "/api/v1/me", responses((status = 202), (status = 401)))]
pub async fn delete_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let grace = OffsetDateTime::now_utc() + TimeDuration::days(ERASE_GRACE_DAYS);
    match users::soft_delete(&client, user.user_id, grace).await {
        Ok(true) => {
            sessions::revoke_all_for_user(&client, user.user_id, "account_erased").await;
            audit::record(
                &client,
                Some(user.user_id),
                "account_erase_requested",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "grace_until": grace.to_string() }),
            )
            .await;
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "status": "scheduled_for_erasure",
                    "grace_until": grace.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                })),
            )
                .into_response()
        }
        Ok(false) => not_found(&rid),
        Err(_) => internal(&rid),
    }
}

/// `GET /api/v1/me/export` — GDPR data export.
#[utoipa::path(get, path = "/api/v1/me/export", responses((status = 200), (status = 401)))]
pub async fn export_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let Ok(Some(u)) = users::find_by_id(&client, user.user_id).await else {
        return not_found(&rid);
    };

    // Collect the user's audit trail.
    let audit_rows = client
        .query(
            "SELECT action, created_at FROM audit_log WHERE actor_id = $1 ORDER BY created_at",
            &[&user.user_id],
        )
        .await
        .unwrap_or_default();
    let audit_events: Vec<serde_json::Value> = audit_rows
        .iter()
        .map(|r| {
            let action: String = r.get("action");
            let created: OffsetDateTime = r.get("created_at");
            json!({
                "action": action,
                "created_at": created.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            })
        })
        .collect();

    Json(json!({
        "user": u,
        "audit_events": audit_events,
        "exported_at": OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    }))
    .into_response()
}
