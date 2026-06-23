#![cfg(test)]
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
//! Phase 18 acceptance: issue import (JIRA / IntelliPilot CSV) + export.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::{TestApp, get_with_bearer, multipart_upload, post_json_bearer};
use serde_json::json;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// A small JIRA-style export: repeated `Component/s` headers, a parent link
/// (child's Parent id = parent's Issue id), a comment, JIRA usernames.
const JIRA_CSV: &str = "Summary,Issue key,Issue id,Parent id,Issue Type,Status,Priority,Assignee,Reporter,Due Date,Component/s,Component/s,Description,Custom field (Epic Link),Comment\n\
Parent task,SS-1,1001,,Task,To Do,High,alice.jira,bob.jira,15/Jul/26,Backend,Frontend,A description,,\"12/Apr/26 3:30 PM;alice.jira;Looks good\"\n\
Child bug,SS-2,1002,1001,Bug,In Progress,Critical,bob.jira,bob.jira,,Backend,,Child desc,,\n";

async fn owner_project(app: &TestApp) -> (String, String) {
    let _ = app.register("owner@x", "owneruser", STRONG_PW).await;
    let token = app
        .login("owner@x", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "IO" }),
        ))
        .await;
    assert_eq!(p.status, 201, "{:?}", p.json);
    (token, p.json["id"].as_str().unwrap().to_owned())
}

/// Multipart POST with a `file` part and a `mapping` (JSON text) part.
fn import_request(uri: &str, token: &str, csv: &str, mapping: Option<&str>) -> Request<Body> {
    let boundary = "----ipimportboundary";
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"issues.csv\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: text/csv\r\n\r\n");
    body.extend_from_slice(csv.as_bytes());
    body.extend_from_slice(b"\r\n");
    if let Some(m) = mapping {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"mapping\"\r\n\r\n");
        body.extend_from_slice(m.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap()
}

/// `mapping` that creates every distinct Type/Status/Priority value as new.
fn create_all_mapping() -> String {
    json!({
        "types": [
            {"value": "Task", "create": true},
            {"value": "Bug", "create": true},
        ],
        "statuses": [
            {"value": "To Do", "create": true},
            {"value": "In Progress", "create": true},
        ],
        "priorities": [
            {"value": "High", "create": true},
            {"value": "Critical", "create": true},
        ],
        "components": [],
    })
    .to_string()
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn export_csv_and_xlsx() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    for s in ["Alpha", "Beta"] {
        let _ = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/issues"),
                &token,
                &json!({ "subject": s }),
            ))
            .await;
    }

    let (status, headers, bytes) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/export?format=csv"),
            &token,
        ))
        .await;
    assert_eq!(status, 200);
    assert!(headers["content-type"].contains("csv"));
    let csv = String::from_utf8(bytes).unwrap();
    assert!(csv.contains("Ref,Subject,Type"), "header present");
    assert!(csv.contains("Alpha") && csv.contains("Beta"));

    let (xs, xh, xb) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/export?format=xlsx"),
            &token,
        ))
        .await;
    assert_eq!(xs, 200);
    assert!(xh["content-type"].contains("spreadsheetml"));
    assert_eq!(&xb[0..2], b"PK", "xlsx is a zip");
}

#[tokio::test]
async fn import_preview_reports_values_and_unmatched_users() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let r = app
        .send(multipart_upload(
            &format!("/api/v1/projects/{pid}/issues/import/preview"),
            &token,
            "issues.csv",
            JIRA_CSV.as_bytes(),
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["issue_count"], 2);
    let types: Vec<&str> = r.json["types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["value"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"Task") && types.contains(&"Bug"));
    // alice.jira / bob.jira aren't project members.
    let unmatched = r.json["unmatched_users"].as_array().unwrap();
    assert!(unmatched.iter().any(|u| u.as_str() == Some("alice.jira")));
}

#[tokio::test]
async fn import_commit_creates_issues_parent_and_comment() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let mapping = create_all_mapping();
    let r = app
        .send(import_request(
            &format!("/api/v1/projects/{pid}/issues/import"),
            &token,
            JIRA_CSV,
            Some(&mapping),
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["created_issues"], 2);
    assert_eq!(r.json["created_comments"], 1);

    // Both issues exist; the child is linked to the parent.
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
        ))
        .await;
    let issues = list.json["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 2);
    let parent = issues
        .iter()
        .find(|i| i["subject"] == "Parent task")
        .unwrap();
    let child = issues.iter().find(|i| i["subject"] == "Child bug").unwrap();
    assert_eq!(child["parent_id"], parent["id"]);
    // The mapping resolved type + status onto the issues.
    assert!(!child["type_id"].is_null(), "type mapped");
    assert!(!child["status_id"].is_null(), "status mapped");
    // The source key is preserved in the description.
    assert!(child["description"].as_str().unwrap().contains("SS-2"));
}

#[tokio::test]
async fn round_trip_export_then_import() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    for s in ["One", "Two", "Three"] {
        let _ = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/issues"),
                &token,
                &json!({ "subject": s }),
            ))
            .await;
    }
    // Export project A.
    let (_s, _h, bytes) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/export?format=csv"),
            &token,
        ))
        .await;
    let csv = String::from_utf8(bytes).unwrap();

    // Import into a fresh project B (no mapping needed — no type/status set).
    let p2 = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "B" }),
        ))
        .await;
    let pid2 = p2.json["id"].as_str().unwrap().to_owned();
    let r = app
        .send(import_request(
            &format!("/api/v1/projects/{pid2}/issues/import"),
            &token,
            &csv,
            Some("{}"),
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["created_issues"], 3);
}

#[tokio::test]
async fn import_requires_issue_create_permission() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    // A stakeholder (view-only) member.
    let _ = app.register("sh@x", "shuser", STRONG_PW).await;
    let sh = app.login("sh@x", STRONG_PW).await.access_token().unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &sh)).await;
    let sid = me.json["id"].as_str().unwrap().to_owned();
    let add = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &owner,
            &json!({ "user_id": sid, "role": "stakeholder" }),
        ))
        .await;
    assert_eq!(add.status, 201, "{:?}", add.json);

    let r = app
        .send(multipart_upload(
            &format!("/api/v1/projects/{pid}/issues/import/preview"),
            &sh,
            "issues.csv",
            JIRA_CSV.as_bytes(),
        ))
        .await;
    assert_eq!(r.status, 403);
}
