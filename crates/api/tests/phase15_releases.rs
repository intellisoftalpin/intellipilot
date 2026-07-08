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
//! Phase 15 acceptance: releases + versions, component↔release links, and the
//! issue fix-version (structured + picker).

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, patch_json_bearer, post_json_bearer};
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
            &json!({ "name": "Rel" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (token, project.json["id"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn releases_and_versions_crud() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "relcrud").await;

    let rel = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/releases"),
            &token,
            &json!({ "name": "PSBP", "description": "Main product", "color": "#336699" }),
        ))
        .await;
    assert_eq!(rel.status, 201, "{:?}", rel.json);
    assert_eq!(rel.json["name"], "PSBP");
    assert_eq!(rel.json["color"], "#336699");
    let rid = rel.json["id"].as_str().unwrap().to_owned();

    // Update the color.
    let recolor = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}/releases/{rid}"),
            &token,
            &json!({ "color": "#aa3311" }),
        ))
        .await;
    assert_eq!(recolor.status, 200, "{:?}", recolor.json);
    assert_eq!(recolor.json["color"], "#aa3311");
    assert_eq!(recolor.json["name"], "PSBP");

    // Duplicate name → 409.
    let dup = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/releases"),
            &token,
            &json!({ "name": "PSBP" }),
        ))
        .await;
    assert_eq!(dup.status, 409);

    // Create two versions.
    let v10 = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/releases/{rid}/versions"),
            &token,
            &json!({ "version": "1.0", "status": "released", "git_tag": "v1.0.0" }),
        ))
        .await;
    assert_eq!(v10.status, 201, "{:?}", v10.json);
    assert_eq!(v10.json["status"], "released");
    assert_eq!(v10.json["git_tag"], "v1.0.0");
    let vid = v10.json["id"].as_str().unwrap().to_owned();
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/releases/{rid}/versions"),
            &token,
            &json!({ "version": "1.1", "status": "planned" }),
        ))
        .await;

    // Duplicate version → 409.
    let dupv = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/releases/{rid}/versions"),
            &token,
            &json!({ "version": "1.0" }),
        ))
        .await;
    assert_eq!(dupv.status, 409);

    let versions = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/releases/{rid}/versions"),
            &token,
        ))
        .await;
    assert_eq!(versions.json["versions"].as_array().unwrap().len(), 2);

    // Update a version.
    let upd = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}/releases/{rid}/versions/{vid}"),
            &token,
            &json!({ "status": "in_progress" }),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["status"], "in_progress");
    assert_eq!(upd.json["version"], "1.0");

    // Delete version, then release.
    let deleted_version = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/releases/{rid}/versions/{vid}"),
            &token,
        ))
        .await;
    assert_eq!(deleted_version.status, 204);
    let deleted_release = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/releases/{rid}"),
            &token,
        ))
        .await;
    assert_eq!(deleted_release.status, 204);
}

#[tokio::test]
async fn component_release_link_drives_fix_version() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "rellink").await;

    // Component + release + version.
    let comp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components"),
            &token,
            &json!({ "name": "backend", "color": "#112233" }),
        ))
        .await;
    let cid = comp.json["id"].as_str().unwrap().to_owned();
    let rel = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/releases"),
            &token,
            &json!({ "name": "PSBP", "color": "#f0ad4e" }),
        ))
        .await;
    let rid = rel.json["id"].as_str().unwrap().to_owned();
    let ver = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/releases/{rid}/versions"),
            &token,
            &json!({ "version": "1.1" }),
        ))
        .await;
    let vid = ver.json["id"].as_str().unwrap().to_owned();

    // Link the release to the component.
    let link = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components/{cid}/releases"),
            &token,
            &json!({ "release_id": rid }),
        ))
        .await;
    assert_eq!(link.status, 201, "{:?}", link.json);
    assert_eq!(link.json["release_name"], "PSBP");

    // The picker returns versions for the component's linked releases,
    // enriched with the parent release's name and color.
    let picker = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/release-versions/for-components"),
            &token,
            &json!({ "component_ids": [cid] }),
        ))
        .await;
    let avail = picker.json["versions"].as_array().unwrap();
    assert_eq!(avail.len(), 1);
    assert_eq!(avail[0]["id"].as_str().unwrap(), vid);
    assert_eq!(avail[0]["release_name"], "PSBP");
    assert_eq!(avail[0]["release_color"], "#f0ad4e");

    // The flat project-wide endpoint returns the same enriched shape.
    let all_versions = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/release-versions"),
            &token,
        ))
        .await;
    assert_eq!(all_versions.status, 200, "{:?}", all_versions.json);
    let all = all_versions.json["versions"].as_array().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["id"].as_str().unwrap(), vid);
    assert_eq!(all[0]["release_name"], "PSBP");
    assert_eq!(all[0]["release_color"], "#f0ad4e");

    // Create an issue with the structured fix-version.
    let issue = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "Ship it", "components": [cid], "release_version_id": vid }),
        ))
        .await;
    assert_eq!(issue.status, 201, "{:?}", issue.json);
    assert_eq!(issue.json["release_version_id"], vid);

    // An unknown release version is rejected.
    let bad = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "Bad", "release_version_id": uuid::Uuid::now_v7() }),
        ))
        .await;
    assert_eq!(bad.status, 422, "{:?}", bad.json);

    // Unlink the release from the component.
    let unlink = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/components/{cid}/releases/{rid}"),
            &token,
        ))
        .await;
    assert_eq!(unlink.status, 204);
}
