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

/// Build/version metadata, captured at compile time (see `build.rs`).
#[derive(Debug, Serialize, ToSchema)]
pub struct VersionResponse {
    /// Cargo workspace version (= the git tag for releases).
    pub version: &'static str,
    /// `git describe --tags --always --dirty`, or empty if unavailable.
    pub git_describe: &'static str,
    /// Short commit SHA, or empty if unavailable.
    pub git_sha: &'static str,
}

/// `GET /api/v1/version` — service version + build metadata. Public.
#[utoipa::path(
    get,
    path = "/api/v1/version",
    responses((status = 200, body = VersionResponse, description = "Service version"))
)]
pub async fn version() -> Response {
    no_store(
        (
            StatusCode::OK,
            Json(VersionResponse {
                version: env!("CARGO_PKG_VERSION"),
                git_describe: env!("IP_GIT_DESCRIBE"),
                git_sha: env!("IP_GIT_SHA"),
            }),
        )
            .into_response(),
    )
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
