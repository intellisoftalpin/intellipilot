//! Liveness and readiness handlers.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

use crate::state::AppState;

#[derive(Debug, Serialize, ToSchema)]
pub struct LiveResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub checks: serde_json::Value,
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    resp
}

/// `GET /health/live` — process is alive.
#[utoipa::path(
    get,
    path = "/health/live",
    responses((status = 200, body = LiveResponse, description = "Process is alive"))
)]
pub async fn live() -> Response {
    no_store((StatusCode::OK, Json(LiveResponse { status: "ok" })).into_response())
}

/// `GET /health/ready` — all readiness checks pass.
#[utoipa::path(
    get,
    path = "/health/ready",
    responses(
        (status = 200, body = ReadyResponse, description = "All checks passing"),
        (status = 503, body = ReadyResponse, description = "One or more checks failing")
    )
)]
pub async fn ready(State(state): State<AppState>) -> Response {
    let mut all_ok = true;
    let mut checks = serde_json::Map::new();
    for check in state.readiness.iter() {
        match check.check().await {
            Ok(()) => {
                checks.insert(check.name().to_owned(), serde_json::Value::from("ok"));
            }
            Err(e) => {
                all_ok = false;
                checks.insert(check.name().to_owned(), serde_json::Value::from(e));
            }
        }
    }

    let body = ReadyResponse {
        status: if all_ok { "ready" } else { "degraded" },
        checks: serde_json::Value::Object(checks),
    };
    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    no_store((status, Json(body)).into_response())
}
