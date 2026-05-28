#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::let_underscore_untyped,
    clippy::format_push_string
)]
//! Phase 9 acceptance: unified search.

mod common;

use common::{TestApp, get_with_bearer, post_json_bearer};
use serde_json::json;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn user_token(app: &TestApp, email: &str, username: &str) -> String {
    let _ = app.register(email, username, STRONG_PW).await;
    app.login(email, STRONG_PW).await.access_token().unwrap()
}

async fn make_project(app: &TestApp, token: &str, name: &str) -> String {
    app.send(post_json_bearer(
        "/api/v1/projects",
        token,
        &json!({ "name": name }),
    ))
    .await
    .json["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn triggers_index_and_search_returns_ranked_results() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = user_token(&app, "s@example.com", "suser").await;
    let pid = make_project(&app, &token, "Search").await;

    // Batch insert several entities; triggers populate search_index.
    for n in 0..10 {
        let _ = app.send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": format!("Bug {n}"), "description": "the deployment pipeline is broken" }),
        )).await;
    }
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/userstories"),
            &token,
            &json!({ "subject": "Pipeline automation", "description": "automate the deployment" }),
        ))
        .await;

    let res = app
        .send(get_with_bearer(
            &format!("/api/v1/search?q=deployment+pipeline&project_id={pid}"),
            &token,
        ))
        .await;
    assert_eq!(res.status, 200, "{:?}", res.json);
    let results = res.json["results"].as_array().unwrap();
    assert!(!results.is_empty(), "found results");
    // Ranked: descending rank.
    let ranks: Vec<f64> = results
        .iter()
        .map(|r| r["rank"].as_f64().unwrap())
        .collect();
    for w in ranks.windows(2) {
        assert!(w[0] >= w[1], "results ranked desc: {ranks:?}");
    }
    // Snippet present, highlight tag allowed, no script.
    let snip = results[0]["snippet"].as_str().unwrap();
    assert!(!snip.contains("<script"));
}

#[tokio::test]
async fn type_filter_restricts_results() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = user_token(&app, "tf@example.com", "tfuser").await;
    let pid = make_project(&app, &token, "Types").await;
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "widget defect" }),
        ))
        .await;
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/userstories"),
            &token,
            &json!({ "subject": "widget feature" }),
        ))
        .await;

    let only_issues = app
        .send(get_with_bearer(
            &format!("/api/v1/search?q=widget&project_id={pid}&types=issue"),
            &token,
        ))
        .await;
    let arr = only_issues.json["results"].as_array().unwrap();
    assert!(!arr.is_empty());
    assert!(
        arr.iter().all(|r| r["entity_type"] == "issue"),
        "only issues: {arr:?}"
    );
}

#[tokio::test]
async fn fuzzy_match_for_short_queries() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = user_token(&app, "fz@example.com", "fzuser").await;
    let pid = make_project(&app, &token, "Fuzzy").await;
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "kubernetes deployment" }),
        ))
        .await;

    // Misspelled single token → trigram fuzzy should still find it.
    let res = app
        .send(get_with_bearer(
            &format!("/api/v1/search?q=kubernets&project_id={pid}"),
            &token,
        ))
        .await;
    assert_eq!(res.status, 200);
    assert_eq!(res.json["fuzzy"], true, "short query uses fuzzy");
    assert!(
        !res.json["results"].as_array().unwrap().is_empty(),
        "fuzzy found the misspelling"
    );
}

#[tokio::test]
async fn search_respects_membership_no_cross_project_leak() {
    require_db!();
    let app = TestApp::spawn().await;

    // Several users, each owning a project containing the SAME keyword.
    let mut owners = Vec::new();
    for i in 0..5 {
        let token = user_token(&app, &format!("u{i}@example.com"), &format!("member{i}")).await;
        let pid = make_project(&app, &token, &format!("P{i}")).await;
        let _ = app.send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "shared confidential keyword", "description": format!("secret of project {i}") }),
        )).await;
        owners.push((token, pid));
    }

    // Each user searching the shared keyword sees ONLY their own project.
    for (token, pid) in &owners {
        let res = app
            .send(get_with_bearer(
                "/api/v1/search?q=confidential+keyword",
                token,
            ))
            .await;
        assert_eq!(res.status, 200);
        let arr = res.json["results"].as_array().unwrap();
        assert!(!arr.is_empty(), "owner finds their own");
        assert!(
            arr.iter()
                .all(|r| r["project_id"].as_str() == Some(pid.as_str())),
            "no cross-project leak: {arr:?}"
        );
    }
}

#[tokio::test]
async fn soft_deleted_entities_drop_out_of_index() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = user_token(&app, "sd@example.com", "sduser").await;
    let pid = make_project(&app, &token, "Del").await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "ephemeral artifact" }),
        ))
        .await;
    let id = created.json["id"].as_str().unwrap().to_owned();

    let before = app
        .send(get_with_bearer(
            &format!("/api/v1/search?q=ephemeral&project_id={pid}"),
            &token,
        ))
        .await;
    assert!(!before.json["results"].as_array().unwrap().is_empty());

    // Delete (closed-status not required; default open) — soft delete.
    let _ = app
        .send(common::req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/issues/{id}"),
            Some(&token),
            &[],
            None,
        ))
        .await;

    let after = app
        .send(get_with_bearer(
            &format!("/api/v1/search?q=ephemeral&project_id={pid}"),
            &token,
        ))
        .await;
    assert!(
        after.json["results"].as_array().unwrap().is_empty(),
        "deleted entity left the index"
    );
}

#[tokio::test]
async fn pathological_queries_do_not_error() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = user_token(&app, "pq@example.com", "pquser").await;
    let _ = make_project(&app, &token, "Path").await;

    // websearch_to_tsquery tolerates arbitrary input; these must not 500.
    for q in [
        "((((",
        ":*!&|",
        "\"unterminated",
        "a & b | !c",
        "%00",
        "the and or not",
    ] {
        let enc = urlencode(q);
        let res = app
            .send(get_with_bearer(&format!("/api/v1/search?q={enc}"), &token))
            .await;
        assert!(res.status == 200, "pathological q {q:?} -> {}", res.status);
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
