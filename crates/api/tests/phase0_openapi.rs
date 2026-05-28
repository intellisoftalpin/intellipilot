#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
//! Phase 0 acceptance: OpenAPI 3.1 document and UI mounts.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use intellipilot_api::{AppState, build_router};
use intellipilot_testkit::init_tracing;
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn openapi_json_serves_valid_3_1_spec() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(ct.starts_with("application/json"), "got {ct}");

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: Value = serde_json::from_slice(&bytes).expect("valid json");

    let version = doc["openapi"].as_str().expect("openapi field");
    assert!(
        version.starts_with("3.1"),
        "expected OpenAPI 3.1.x, got {version}"
    );

    assert!(doc["info"]["title"].is_string());
    assert!(doc["info"]["version"].is_string());
    assert!(doc["paths"].is_object());
    assert!(doc["paths"]["/health/live"].is_object());
    assert!(doc["paths"]["/health/ready"].is_object());
}

#[tokio::test]
async fn swagger_ui_renders_at_docs() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(Request::builder().uri("/docs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    // Either 200 with HTML or 3xx redirecting to the index — both acceptable.
    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "unexpected status {}",
        resp.status()
    );
}

#[tokio::test]
async fn scalar_ui_renders_at_reference() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/reference")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "unexpected status {}",
        resp.status()
    );
}

#[tokio::test]
async fn openapi_doc_declares_problem_json_for_errors() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: Value = serde_json::from_slice(&bytes).unwrap();

    let components = &doc["components"]["schemas"];
    assert!(
        components["Problem"].is_object(),
        "OpenAPI must declare the Problem (RFC 9457) schema"
    );
}
