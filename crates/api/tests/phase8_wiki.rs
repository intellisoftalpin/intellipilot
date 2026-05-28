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
//! Phase 8 acceptance: wiki pages, revisions, diff, restore, sanitization.

mod common;

use common::{TestApp, get_with_bearer, multipart_upload, post_json_bearer, req};
use serde_json::json;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";
const PNG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

async fn owner_project(app: &TestApp) -> (String, String) {
    let _ = app
        .register("wiki@example.com", "wikiuser", STRONG_PW)
        .await;
    let token = app
        .login("wiki@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "WK" }),
        ))
        .await;
    (token.clone(), p.json["id"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn wiki_crud_and_slug_unique() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/wiki"),
            &token,
            &json!({ "title": "Getting Started", "body": "# Hello\n\nsome **text**" }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    assert_eq!(created.json["slug"], "getting-started");
    assert_eq!(created.json["version"], 1);
    assert!(
        created.json["body_html"].as_str().unwrap().contains("<h1>"),
        "html cached"
    );
    let id = created.json["id"].as_str().unwrap().to_owned();

    // Duplicate slug → 409.
    let dup = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/wiki"),
            &token,
            &json!({ "title": "x", "slug": "getting-started", "body": "" }),
        ))
        .await;
    assert_eq!(dup.status, 409);

    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/wiki"),
            &token,
        ))
        .await;
    assert_eq!(list.json["pages"].as_array().unwrap().len(), 1);

    // Update → version 2.
    let upd = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/wiki/{id}"),
            Some(&token),
            &[],
            Some(&json!({ "body": "## Changed" })),
        ))
        .await;
    assert_eq!(upd.status, 200);
    assert_eq!(upd.json["version"], 2);

    let del = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/wiki/{id}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    assert_eq!(del.status, 204);
    let gone = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/wiki/{id}"),
            &token,
        ))
        .await;
    assert_eq!(gone.status, 404);
}

#[tokio::test]
async fn wiki_body_is_sanitized() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/wiki"),
            &token,
            &json!({ "title": "XSS", "body": "ok <script>alert(1)</script> <img src=x onerror=alert(1)>" }),
        ))
        .await;
    assert_eq!(created.status, 201);
    let html = created.json["body_html"].as_str().unwrap();
    assert!(!html.contains("<script"), "script stripped: {html}");
    assert!(!html.contains("<img"), "raw img stripped: {html}");
}

#[tokio::test]
async fn revisions_diff_and_restore() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/wiki"),
            &token,
            &json!({ "title": "Doc", "body": "line one\nline two" }),
        ))
        .await;
    let id = created.json["id"].as_str().unwrap().to_owned();
    let wiki = format!("/api/v1/projects/{pid}/wiki/{id}");

    // Two edits → revisions 2 and 3.
    let _ = app
        .send(req(
            "PATCH",
            &wiki,
            Some(&token),
            &[],
            Some(&json!({ "body": "line one\nline two CHANGED" })),
        ))
        .await;
    let v3 = app
        .send(req(
            "PATCH",
            &wiki,
            Some(&token),
            &[],
            Some(&json!({ "body": "line one\nline three" })),
        ))
        .await;
    assert_eq!(v3.json["version"], 3);

    // Revision list: newest first.
    let revs = app
        .send(get_with_bearer(&format!("{wiki}/revisions"), &token))
        .await;
    let arr = revs.json["revisions"].as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["rev"], 3);
    assert_eq!(arr[2]["rev"], 1);
    // Listings omit the body.
    assert!(arr[0].get("body").is_none());

    // Single revision includes the body.
    let r1 = app
        .send(get_with_bearer(&format!("{wiki}/revisions/1"), &token))
        .await;
    assert_eq!(r1.json["body"], "line one\nline two");

    // Diff rev1 → current (rev3).
    let diff = app
        .send(get_with_bearer(&format!("{wiki}/revisions/1/diff"), &token))
        .await;
    assert_eq!(diff.status, 200);
    let text = diff.json["diff"].as_str().unwrap();
    assert!(text.contains("line three"), "diff shows new line: {text}");
    assert!(
        text.contains("-line two") || text.contains("line two"),
        "diff references old line"
    );

    // Restore rev1 → a NEW revision (version 4); page body matches rev1.
    let restored = app
        .send(post_json_bearer(
            &format!("{wiki}/revisions/1/restore"),
            &token,
            &json!({}),
        ))
        .await;
    assert_eq!(restored.status, 200, "{:?}", restored.json);
    assert_eq!(
        restored.json["version"], 4,
        "restore is non-destructive (new revision)"
    );
    assert_eq!(restored.json["body"], "line one\nline two");

    // The original rev1 is still intact (immutable history).
    let r1_again = app
        .send(get_with_bearer(&format!("{wiki}/revisions/1"), &token))
        .await;
    assert_eq!(r1_again.json["body"], "line one\nline two");
    let revs2 = app
        .send(get_with_bearer(&format!("{wiki}/revisions"), &token))
        .await;
    assert_eq!(revs2.json["revisions"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn wiki_attachments_via_phase7() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/wiki"),
            &token,
            &json!({ "title": "Page", "body": "" }),
        ))
        .await;
    let id = created.json["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/projects/{pid}/wiki/{id}/attachments");

    let up = app
        .send(multipart_upload(&base, &token, "diagram.png", PNG))
        .await;
    assert_eq!(up.status, 201, "{:?}", up.json);
    assert_eq!(up.json["target_type"], "wiki");

    let list = app.send(get_with_bearer(&base, &token)).await;
    assert_eq!(list.json["attachments"].as_array().unwrap().len(), 1);
}
