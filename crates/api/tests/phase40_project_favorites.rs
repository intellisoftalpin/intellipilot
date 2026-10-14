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
//! Phase 40: favorite projects — a per-user set of at most four projects the
//! user can see, read and replaced whole.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, post_json_bearer, req};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";
const URI: &str = "/api/v1/me/project-favorites";

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

async fn favorites(app: &TestApp, token: &str) -> Vec<String> {
    let r = app.send(get_with_bearer(URI, token)).await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    ids(&r.json)
}

fn ids(v: &Value) -> Vec<String> {
    v["project_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_str().unwrap().to_owned())
        .collect()
}

async fn put(app: &TestApp, token: &str, project_ids: &[&String]) -> common::TestResponse {
    app.send(req(
        "PUT",
        URI,
        Some(token),
        &[],
        Some(&json!({ "project_ids": project_ids })),
    ))
    .await
}

#[tokio::test]
async fn empty_then_replaced_in_order() {
    require_db!();
    let app = TestApp::spawn().await;
    let me = user(&app, "favorder").await;
    let a = project(&app, &me, "Fav A").await;
    let b = project(&app, &me, "Fav B").await;

    assert!(favorites(&app, &me).await.is_empty());

    let r = put(&app, &me, &[&b, &a]).await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(ids(&r.json), [b.clone(), a.clone()]);
    assert_eq!(favorites(&app, &me).await, [b.clone(), a.clone()]);

    let r = put(&app, &me, &[&a]).await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(favorites(&app, &me).await, [a]);
}

#[tokio::test]
async fn rejects_too_many_duplicates_and_foreign_projects() {
    require_db!();
    let app = TestApp::spawn().await;
    let me = user(&app, "favreject").await;
    let other = user(&app, "favrejectother").await;
    let mut mine = Vec::new();
    for i in 0..5 {
        mine.push(project(&app, &me, &format!("Mine {i}")).await);
    }
    let foreign = project(&app, &other, "Foreign").await;

    let five: Vec<&String> = mine.iter().collect();
    let r = put(&app, &me, &five).await;
    assert_eq!(r.status, 422, "{:?}", r.json);
    assert_eq!(r.json["code"], "too_many_favorites");

    let r = put(&app, &me, &[&mine[0], &mine[0]]).await;
    assert_eq!(r.status, 422, "{:?}", r.json);
    assert_eq!(r.json["code"], "duplicate_favorite");

    let r = put(&app, &me, &[&mine[0], &foreign]).await;
    assert_eq!(r.status, 422, "{:?}", r.json);
    assert_eq!(r.json["code"], "unknown_project");

    // Nothing was written by the rejected requests.
    assert!(favorites(&app, &me).await.is_empty());
}

#[tokio::test]
async fn deleted_projects_drop_out() {
    require_db!();
    let app = TestApp::spawn().await;
    let me = user(&app, "favdeleted").await;
    let keep = project(&app, &me, "Keep").await;
    let gone = project(&app, &me, "Gone").await;
    let r = put(&app, &me, &[&keep, &gone]).await;
    assert_eq!(r.status, 200, "{:?}", r.json);

    let r = app
        .send(delete_bearer(&format!("/api/v1/projects/{gone}"), &me))
        .await;
    assert!(r.status == 204 || r.status == 200, "{:?}", r.json);

    assert_eq!(favorites(&app, &me).await, [keep]);
}
