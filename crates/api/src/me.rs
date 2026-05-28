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
use intellipilot_core::user::ProfileUpdate;
use intellipilot_db::{audit, sessions, users};
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::auth::{AuthUser, client_ip, request_id, user_agent};
use crate::dto::ProfileUpdateRequest;
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
