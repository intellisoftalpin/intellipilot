#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::print_stderr,
    clippy::let_underscore_untyped
)]
//! Phase 38: the home dashboard's projects — every project the user is a
//! member of, ordered by the tickets they are involved in, with the fields the
//! project icon needs.

mod common;

use common::{TestApp, get_with_bearer, post_json_bearer};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn user(app: &TestApp, tag: &str) -> String {
    let _ = app
        .register(&format!("{tag}@example.com"), tag, STRONG_PW)
        .await;
    app.login(&format!("{tag}@example.com"), STRONG_PW)
        .await
        .access_token()
        .unwrap()
}

async fn project(app: &TestApp, token: &str, name: &str) -> String {
    let r = app
        .send(post_json_bearer(
            "/api/v1/projects",
            token,
            &json!({ "name": name }),
        ))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    r.json["id"].as_str().unwrap().to_owned()
}

/// Every issue the caller creates makes them its reporter — one of the
/// My Issues roles — so each one adds to their involvement in the project.
async fn issues(app: &TestApp, token: &str, project: &str, n: usize) {
    for i in 0..n {
        let r = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{project}/issues"),
                token,
                &json!({ "subject": format!("issue {i}") }),
            ))
            .await;
        assert_eq!(r.status, 201, "{:?}", r.json);
    }
}

async fn home_projects(app: &TestApp, token: &str) -> Vec<Value> {
    let r = app
        .send(get_with_bearer("/api/v1/me/dashboard", token))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    r.json["by_project"].as_array().unwrap().clone()
}

#[tokio::test]
async fn every_member_project_ordered_by_involvement() {
    require_db!();
    let app = TestApp::spawn().await;
    let me = user(&app, "homeprojme").await;
    let other = user(&app, "homeprojother").await;

    let little = project(&app, &me, "Little").await;
    let most = project(&app, &me, "Most").await;
    // No tickets at all: still listed, alphabetically after the rest.
    let quiet_b = project(&app, &me, "Quiet B").await;
    let quiet_a = project(&app, &me, "quiet A").await;
    // Someone else's project the user is not a member of: never listed.
    let foreign = project(&app, &other, "Foreign").await;
    issues(&app, &me, &little, 1).await;
    issues(&app, &me, &most, 3).await;
    issues(&app, &other, &foreign, 2).await;

    let listed = home_projects(&app, &me).await;
    let order: Vec<&str> = listed
        .iter()
        .map(|p| p["project_id"].as_str().unwrap())
        .collect();
    assert_eq!(order, [&most, &little, &quiet_a, &quiet_b]);
}

#[tokio::test]
async fn projects_carry_their_icon_fields() {
    require_db!();
    let app = TestApp::spawn().await;
    let me = user(&app, "homeprojicon").await;
    let id = project(&app, &me, "Icons").await;

    let listed = home_projects(&app, &me).await;
    let p = listed
        .iter()
        .find(|p| p["project_id"] == id.as_str())
        .unwrap();
    assert!(!p["issue_prefix"].as_str().unwrap().is_empty());
    assert!(p["color"].is_string());
    assert_eq!(p["icon_image_kind"], "none");
    assert!(p["icon_image_updated_at"].is_null());
    // Kept for clients before 0.7.8.
    assert_eq!(p["open_count"], 0);
}
