#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
//! Phase 0 acceptance: liveness & readiness endpoints.
//!
//! These tests pin the shape of `/health/live` and `/health/ready`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use intellipilot_api::{AppState, ReadyCheck, build_router};
use intellipilot_testkit::init_tracing;
use serde_json::Value;
use tower::ServiceExt;

#[derive(Debug, Default, Clone)]
struct AlwaysReady;

#[async_trait::async_trait]
impl ReadyCheck for AlwaysReady {
    fn name(&self) -> &'static str {
        "always_ready"
    }
    async fn check(&self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
struct AlwaysFailing;

#[async_trait::async_trait]
impl ReadyCheck for AlwaysFailing {
    fn name(&self) -> &'static str {
        "always_failing"
    }
    async fn check(&self) -> Result<(), String> {
        Err("simulated outage".to_owned())
    }
}

fn state_with(checks: Vec<Arc<dyn ReadyCheck>>) -> AppState {
    AppState::builder().readiness_checks(checks).build()
}

#[tokio::test]
async fn health_live_returns_200_with_status_ok() {
    init_tracing();
    let app = build_router(state_with(vec![]));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn health_ready_returns_200_when_all_checks_pass() {
    init_tracing();
    let app = build_router(state_with(vec![Arc::new(AlwaysReady)]));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "ready");
    assert!(body["checks"].is_object());
    assert_eq!(body["checks"]["always_ready"], "ok");
}

#[tokio::test]
async fn health_ready_returns_503_when_a_check_fails() {
    init_tracing();
    let app = build_router(state_with(vec![
        Arc::new(AlwaysReady),
        Arc::new(AlwaysFailing),
    ]));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["always_failing"], "simulated outage");
}

#[tokio::test]
async fn health_endpoints_have_no_cache_headers() {
    init_tracing();
    let app = build_router(state_with(vec![]));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let cache_control = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cache_control.contains("no-store"),
        "health endpoints must set cache-control: no-store, got {cache_control:?}"
    );
}
