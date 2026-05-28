#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
//! Phase 0 acceptance: x-request-id is generated when missing, preserved when
//! client-provided (within format constraints), and rejected when malformed.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use intellipilot_api::{AppState, build_router};
use intellipilot_testkit::init_tracing;
use tower::ServiceExt;

const HEADER: &str = "x-request-id";

#[tokio::test]
async fn request_id_generated_when_missing() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let id = resp
        .headers()
        .get(HEADER)
        .expect("x-request-id header must be present on every response")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(!id.is_empty());
    // UUIDv7 textual form is 36 chars.
    assert_eq!(id.len(), 36, "generated id should be a UUID v7, got {id}");
}

#[tokio::test]
async fn request_id_preserved_when_client_provides_valid_id() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    // 32 hex chars — a permitted client format (alphanumeric, <=128 chars).
    let given = "abc123def456ababab1234567890abcd";
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header(HEADER, given)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let echoed = resp.headers().get(HEADER).unwrap().to_str().unwrap();
    assert_eq!(echoed, given);
}

#[tokio::test]
async fn request_id_rejected_when_malformed() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    // Spaces and punctuation are valid HTTP header bytes but disallowed by
    // our stricter request-id format (alphanumeric + `-`/`_`).
    let bad = "id with spaces and: punct!";
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header(HEADER, bad)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let echoed = resp.headers().get(HEADER).unwrap().to_str().unwrap();
    // Server must replace the bad ID with a fresh one, never echo it.
    assert_ne!(echoed, bad);
}

#[tokio::test]
async fn request_id_too_long_is_rejected() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let too_long = "a".repeat(200);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header(HEADER, too_long.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
