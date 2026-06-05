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
//! Phase 6 acceptance: milestones / sprints (CRUD, close, board, stats).

mod common;

use common::{TestApp, get_with_bearer, post_json_bearer, req};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn owner_project(app: &TestApp) -> (String, String) {
    let _ = app.register("ms@example.com", "msuser", STRONG_PW).await;
    let token = app
        .login("ms@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "MS" }),
        ))
        .await;
    assert_eq!(p.status, 201, "{:?}", p.json);
    (token, p.json["id"].as_str().unwrap().to_owned())
}

/// Find a taxonomy item id by display name within a kind.
async fn tax_id(app: &TestApp, token: &str, pid: &str, kind: &str, name: &str) -> String {
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/{kind}"),
            token,
        ))
        .await;
    list.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == name)
        .unwrap_or_else(|| panic!("taxonomy {kind} '{name}' not found"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn milestone_crud() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({ "name": "Sprint 1", "start_date": "2026-05-01", "end_date": "2026-05-14" }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    assert_eq!(created.json["slug"], "sprint-1");
    assert_eq!(created.json["start_date"], "2026-05-01");
    assert_eq!(created.json["closed"], false);
    let id = created.json["id"].as_str().unwrap().to_owned();

    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
        ))
        .await;
    assert_eq!(list.json["milestones"].as_array().unwrap().len(), 1);

    let patched = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/milestones/{id}"),
            Some(&token),
            &[],
            Some(&json!({ "name": "Sprint One" })),
        ))
        .await;
    assert_eq!(patched.status, 200);
    assert_eq!(patched.json["name"], "Sprint One");

    let del = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/milestones/{id}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    assert_eq!(del.status, 204);
    let gone = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{id}"),
            &token,
        ))
        .await;
    assert_eq!(gone.status, 404);
}

#[tokio::test]
async fn invalid_dates_rejected() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let resp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({ "name": "Bad", "start_date": "2026-05-14", "end_date": "2026-05-01" }),
        ))
        .await;
    assert_eq!(resp.status, 422);
    assert_eq!(resp.json["code"], "invalid_dates");
}

#[tokio::test]
async fn closing_milestone_blocks_further_assignment() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({ "name": "Sprint" }),
        ))
        .await;
    let mid = m.json["id"].as_str().unwrap().to_owned();

    // A US can be assigned while open.
    let us = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "Assigned", "milestone_id": mid }),
        ))
        .await;
    assert_eq!(us.status, 201, "{:?}", us.json);
    assert_eq!(us.json["milestone_id"], mid);

    // Close the milestone.
    let closed = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}/close"),
            &token,
            &json!({}),
        ))
        .await;
    assert_eq!(closed.status, 200);
    assert_eq!(closed.json["closed"], true);
    assert!(closed.json["closed_at"].is_string(), "closed_at frozen");

    // Assigning another US to the closed milestone → 409.
    let blocked = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "TooLate", "milestone_id": mid }),
        ))
        .await;
    assert_eq!(blocked.status, 409, "{:?}", blocked.json);
    assert_eq!(blocked.json["code"], "milestone_closed");
}

#[tokio::test]
async fn cross_project_milestone_is_422() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid_a) = owner_project(&app).await;
    let pb = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "Other" }),
        ))
        .await;
    let pid_b = pb.json["id"].as_str().unwrap();
    let mb = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid_b}/milestones"),
            &token,
            &json!({ "name": "S" }),
        ))
        .await;
    let mb_id = mb.json["id"].as_str().unwrap();

    let us = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid_a}/issues"),
            &token,
            &json!({ "subject": "X", "milestone_id": mb_id }),
        ))
        .await;
    assert_eq!(us.status, 422);
}

#[tokio::test]
async fn milestone_stats_from_fixture() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({ "name": "Sprint" }),
        ))
        .await;
    let mid = m.json["id"].as_str().unwrap().to_owned();

    let p5 = tax_id(&app, &token, &pid, "point", "5").await;
    let p3 = tax_id(&app, &token, &pid, "point", "3").await;
    let st_done = tax_id(&app, &token, &pid, "issue_status", "Done").await; // closed
    let st_new = tax_id(&app, &token, &pid, "issue_status", "New").await; // open

    // Issue 1: 5 points, closed status, in the sprint.
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "I1", "milestone_id": mid, "points_id": p5, "status_id": st_done }),
        ))
        .await;
    // Issue 2: 3 points, open status, in the sprint.
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "I2", "milestone_id": mid, "points_id": p3, "status_id": st_new }),
        ))
        .await;

    let stats = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}/stats"),
            &token,
        ))
        .await;
    assert_eq!(stats.status, 200, "{:?}", stats.json);
    assert_eq!(stats.json["total_points"], 8.0);
    assert_eq!(stats.json["completed_points"], 5.0);
    assert_eq!(stats.json["total_tasks"], 2);
    assert_eq!(stats.json["completed_tasks"], 1);
}

#[tokio::test]
async fn milestone_board_shape() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({ "name": "Sprint" }),
        ))
        .await;
    let mid = m.json["id"].as_str().unwrap().to_owned();
    let st_new = tax_id(&app, &token, &pid, "issue_status", "New").await;

    // A top-level issue in the sprint, plus one sub-task hanging off it.
    let parent = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "Card", "milestone_id": mid, "status_id": st_new }),
        ))
        .await;
    let parent_id = parent.json["id"].as_str().unwrap().to_owned();
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "Sub", "parent_id": parent_id }),
        ))
        .await;

    let board = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}/board"),
            &token,
        ))
        .await;
    assert_eq!(board.status, 200, "{:?}", board.json);

    // Schema snapshot: column status slugs + the subjects/sub-task-counts placed
    // in each. Derived to avoid non-deterministic UUIDs.
    let columns = board.json["columns"].as_array().unwrap();
    let shape: Vec<Value> = columns
        .iter()
        .map(|c| {
            let status_slug = c["status"].get("slug").and_then(Value::as_str).map(str::to_owned);
            let cards: Vec<Value> = c["issues"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| json!({ "subject": u["subject"], "subtasks": u["subtasks"].as_array().unwrap().len() }))
                .collect();
            json!({ "status": status_slug, "issues": cards })
        })
        .collect();
    insta::assert_json_snapshot!(shape);
}
