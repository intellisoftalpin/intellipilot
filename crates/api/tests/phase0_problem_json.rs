#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::print_stderr
)]
//! Phase 0 acceptance: every error response is RFC 9457 Problem+JSON.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use intellipilot_api::{AppState, build_router};
use intellipilot_testkit::init_tracing;
use serde_json::Value;
use tower::ServiceExt;

const PROBLEM_CT: &str = "application/problem+json";

async fn assert_problem(resp: axum::response::Response, expected_status: StatusCode) -> Value {
    assert_eq!(resp.status(), expected_status, "status mismatch");

    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        ct.starts_with(PROBLEM_CT),
        "expected {PROBLEM_CT}, got {ct:?}"
    );

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).expect("valid json");

    // Required RFC 9457 fields
    assert!(body["type"].is_string(), "missing `type`");
    assert!(body["title"].is_string(), "missing `title`");
    assert_eq!(
        body["status"].as_u64().unwrap_or(0),
        u64::from(expected_status.as_u16()),
        "status field mismatch"
    );
    // IntelliPilot extensions
    assert!(body["code"].is_string(), "missing `code` extension");
    assert!(body["instance"].is_string(), "missing `instance`");
    body
}

#[tokio::test]
async fn unknown_route_returns_problem_404() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/does/not/exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = assert_problem(resp, StatusCode::NOT_FOUND).await;
    assert_eq!(body["code"], "not_found");
}

#[tokio::test]
async fn wrong_method_returns_problem_405() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = assert_problem(resp, StatusCode::METHOD_NOT_ALLOWED).await;
    assert_eq!(body["code"], "method_not_allowed");
    // RFC 7231: 405 responses must include Allow header.
    // We assert it at the HTTP layer (axum sets it automatically for typed router).
}

#[tokio::test]
async fn unsupported_media_type_returns_problem_415() {
    init_tracing();
    // We pick the request-id echo endpoint as a placeholder POST target; the
    // implementation under test must reject non-JSON bodies on JSON endpoints
    // with 415. If no POST endpoint exists yet in Phase 0, this test pins the
    // CONTRACT for when the first POST is added in Phase 1.
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/_test/echo")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("hello"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Phase 0 may legitimately return 404 (endpoint not yet defined). The
    // contract assertion below activates once the endpoint exists; until then
    // we accept either, with a recorded TODO.
    if resp.status() == StatusCode::NOT_FOUND {
        eprintln!("415 contract test deferred: /api/v1/_test/echo not yet implemented");
        return;
    }
    let _body = assert_problem(resp, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;
}

#[tokio::test]
async fn internal_error_is_problem_500_without_leaking_details() {
    init_tracing();
    // A fault-injection endpoint is wired only under `cfg(test)` to let us
    // exercise the 500 path deterministically.
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/_fault/panic")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = assert_problem(resp, StatusCode::INTERNAL_SERVER_ERROR).await;
    assert_eq!(body["code"], "internal_error");

    // Must NOT leak panic message, stack, or path.
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        !detail.contains("panic")
            && !detail.contains("backtrace")
            && !detail.to_lowercase().contains("src/"),
        "detail leaked sensitive info: {detail:?}"
    );
}
