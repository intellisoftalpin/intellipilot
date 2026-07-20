#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::let_underscore_untyped
)]
//! Phase 26 acceptance: delta sync for cached board clients — the board-data
//! cursor, `GET .../issues/delta` (changes + tombstones + next cursor), and
//! the resync-required guard for over-age cursors.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, post_json_bearer, req};
use serde_json::json;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn owner_with_project(app: &TestApp, tag: &str) -> (String, String) {
    let _ = app
        .register(&format!("{tag}@example.com"), tag, STRONG_PW)
        .await;
    let token = app
        .login(&format!("{tag}@example.com"), STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let project = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "Delta" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (token, project.json["id"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn delta_requires_valid_since() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "delta-badsince").await;

    let missing = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/delta"),
            &token,
        ))
        .await;
    assert_eq!(missing.status, 400, "{:?}", missing.json);
    assert_eq!(missing.json["code"], "invalid_since");

    let garbage = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/delta?since=yesterday"),
            &token,
        ))
        .await;
    assert_eq!(garbage.status, 400, "{:?}", garbage.json);
}

#[tokio::test]
async fn delta_over_age_cursor_requires_resync() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "delta-ancient").await;

    // 40 days ago — past the 30-day erase grace window.
    let old = (time::OffsetDateTime::now_utc() - time::Duration::days(40))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let resp = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/delta?since={old}"),
            &token,
        ))
        .await;
    assert_eq!(resp.status, 410, "{:?}", resp.json);
    assert_eq!(resp.json["code"], "resync_required");
}

#[tokio::test]
async fn board_cursor_then_delta_reports_changes_and_tombstones() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "delta-roundtrip").await;

    // Two issues exist before the client "loads its board".
    let a = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "A", "description": "" }),
        ))
        .await;
    assert_eq!(a.status, 201, "{:?}", a.json);
    let a_id = a.json["id"].as_str().unwrap().to_owned();
    let a_etag = a.header("etag").unwrap().to_owned();
    let c = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "C", "description": "" }),
        ))
        .await;
    assert_eq!(c.status, 201, "{:?}", c.json);
    let c_id = c.json["id"].as_str().unwrap().to_owned();

    // Board data carries the sync cursor.
    let board = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/board"),
            &token,
        ))
        .await;
    assert_eq!(board.status, 200, "{:?}", board.json);
    let cursor = board.json["cursor"].as_str().unwrap().to_owned();
    assert!(!cursor.is_empty());

    // Afterwards: B is created, A is updated, C is deleted.
    let b = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "B", "description": "" }),
        ))
        .await;
    assert_eq!(b.status, 201, "{:?}", b.json);
    let b_id = b.json["id"].as_str().unwrap().to_owned();
    let upd = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/issues/{a_id}"),
            Some(&token),
            &[("if-match", &a_etag)],
            Some(&json!({ "subject": "A2" })),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/issues/{c_id}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);

    // Delta from the board cursor sees all three changes exactly once each.
    let delta = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/delta?since={cursor}"),
            &token,
        ))
        .await;
    assert_eq!(delta.status, 200, "{:?}", delta.json);
    let issues = delta.json["issues"].as_array().unwrap();
    let ids: Vec<&str> = issues.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&b_id.as_str()), "{ids:?}");
    // A was updated after the cursor (its creation may also fall inside the
    // 5s overlap window — either way it appears once, with the final state).
    let a_row = issues.iter().find(|i| i["id"] == a_id.as_str()).unwrap();
    assert_eq!(a_row["subject"], "A2");
    assert_eq!(a_row["version"], 2);
    // Deleted issues never come back as live rows, only as tombstones.
    assert!(!ids.contains(&c_id.as_str()), "{ids:?}");
    let tombstones = delta.json["tombstones"].as_array().unwrap();
    assert!(
        tombstones.iter().any(|t| t["id"] == c_id.as_str()),
        "{tombstones:?}"
    );
    assert_eq!(delta.json["has_more"], false);
    assert!(!delta.json["cursor"].as_str().unwrap().is_empty());
}
