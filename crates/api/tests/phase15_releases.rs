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

use common::{TestApp, delete_bearer, get_with_bearer, patch_json_bearer, post_json_bearer, req};
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

/// Issues use optimistic concurrency, so every PATCH needs the current ETag;
/// fetch it rather than tracking the version by hand.
async fn issue_etag(app: &TestApp, url: &str, token: &str) -> String {
    app.send(get_with_bearer(url, token))
        .await
        .header("etag")
        .expect("issue etag")
        .to_owned()
}

/// A change can ship in a different version of each component it touches, so
/// the fix version belongs to the (issue, component) pair rather than to the
/// issue alone.
#[tokio::test]
async fn each_component_carries_its_own_fix_version() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "compver").await;

    // Two components, each shipping in its own release.
    let mut components = Vec::new();
    let mut versions = Vec::new();
    for (name, release, version) in [("backend", "Server", "2.1"), ("frontend", "Web", "5.0")] {
        let comp = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/components"),
                &token,
                &json!({ "name": name }),
            ))
            .await;
        let cid = comp.json["id"].as_str().unwrap().to_owned();
        let rel = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/releases"),
                &token,
                &json!({ "name": release }),
            ))
            .await;
        let rid = rel.json["id"].as_str().unwrap().to_owned();
        let ver = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/releases/{rid}/versions"),
                &token,
                &json!({ "version": version }),
            ))
            .await;
        let _ = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/components/{cid}/releases"),
                &token,
                &json!({ "release_id": rid }),
            ))
            .await;
        components.push(cid);
        versions.push(ver.json["id"].as_str().unwrap().to_owned());
    }

    let statuses = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/issue_status"),
            &token,
        ))
        .await;
    let status_id = statuses.json["items"][0]["id"].as_str().unwrap().to_owned();

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({
                "subject": "Ships in two places",
                "status_id": status_id,
                "components": [components[0], components[1]],
                "component_versions": [
                    { "component_id": components[0], "release_version_id": versions[0] },
                    { "component_id": components[1], "release_version_id": versions[1] },
                ],
            }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    let pairs = created.json["component_versions"].as_array().unwrap();
    assert_eq!(pairs.len(), 2);
    // The legacy single field mirrors one of them, so the list `?version=`
    // filter, the exports and the board keep working untouched.
    assert!(created.json["release_version_id"].is_string());

    let id = created.json["id"].as_str().unwrap().to_owned();
    let url = format!("/api/v1/projects/{pid}/issues/{id}");

    // A version for a component the issue does not affect is refused: the
    // row would only be pruned again by trigger.
    let tag = issue_etag(&app, &url, &token).await;
    let stray = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &tag)],
            Some(&json!({
                "components": [components[0]],
                "component_versions": [
                    { "component_id": components[1], "release_version_id": versions[1] },
                ],
            })),
        ))
        .await;
    assert_eq!(stray.status, 422, "{:?}", stray.json);
    assert_eq!(stray.json["code"], "component_version_unassigned");

    // Nor is a version from a release that component does not ship in.
    let tag = issue_etag(&app, &url, &token).await;
    let unrelated = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &tag)],
            Some(&json!({
                "component_versions": [
                    { "component_id": components[0], "release_version_id": versions[1] },
                ],
            })),
        ))
        .await;
    assert_eq!(unrelated.status, 422, "{:?}", unrelated.json);
    assert_eq!(unrelated.json["code"], "component_version_unrelated");

    // Two versions for one component contradict "one version per component".
    let tag = issue_etag(&app, &url, &token).await;
    let duplicated = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &tag)],
            Some(&json!({
                "component_versions": [
                    { "component_id": components[0], "release_version_id": versions[0] },
                    { "component_id": components[0], "release_version_id": versions[0] },
                ],
            })),
        ))
        .await;
    assert_eq!(duplicated.status, 422, "{:?}", duplicated.json);
    assert_eq!(duplicated.json["code"], "component_version_duplicate");

    // Dropping a component takes its version with it.
    let tag = issue_etag(&app, &url, &token).await;
    let narrowed = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &tag)],
            Some(&json!({ "components": [components[0]] })),
        ))
        .await;
    assert_eq!(narrowed.status, 200, "{:?}", narrowed.json);
    let after = app.send(get_with_bearer(&url, &token)).await;
    let remaining = after.json["component_versions"].as_array().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0]["component_id"], components[0]);

    // Clearing them all clears the mirror too, so the filter cannot keep
    // matching on a version the issue no longer claims.
    let tag = issue_etag(&app, &url, &token).await;
    let cleared = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &tag)],
            Some(&json!({ "component_versions": [] })),
        ))
        .await;
    assert_eq!(cleared.status, 200, "{:?}", cleared.json);
    let empty = app.send(get_with_bearer(&url, &token)).await;
    assert!(
        empty.json["component_versions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(empty.json["release_version_id"].is_null());
}
