#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::let_underscore_untyped
)]
//! Search by work-item key, partial/non-English words, fuzzy titles, the
//! boosted current project, and superadmin/non-member visibility (V026).

mod common;

use std::fmt::Write as _;

use common::{TestApp, get_with_bearer, post_json_bearer, req};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn user_token(app: &TestApp, email: &str, username: &str) -> String {
    let _ = app.register(email, username, STRONG_PW).await;
    app.login(email, STRONG_PW).await.access_token().unwrap()
}

/// Returns (project id, issue prefix).
async fn make_project(
    app: &TestApp,
    token: &str,
    name: &str,
    visibility: &str,
) -> (String, String) {
    let r = app
        .send(post_json_bearer(
            "/api/v1/projects",
            token,
            &json!({ "name": name, "visibility": visibility }),
        ))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    (
        r.json["id"].as_str().unwrap().to_owned(),
        r.json["issue_prefix"].as_str().unwrap().to_owned(),
    )
}

async fn create(app: &TestApp, token: &str, pid: &str, kind: &str, body: &Value) -> Value {
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/{kind}"),
            token,
            body,
        ))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    r.json
}

async fn search(app: &TestApp, token: &str, query: &str) -> Vec<Value> {
    let r = app
        .send(get_with_bearer(&format!("/api/v1/search?{query}"), token))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    r.json["results"].as_array().unwrap().clone()
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[tokio::test]
async fn finds_issues_and_epics_by_key_in_every_spelling() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = user_token(&app, "k@example.com", "kuser").await;
    let (pid, prefix) = make_project(&app, &token, "Keys", "private").await;

    let epic = create(
        &app,
        &token,
        &pid,
        "epics",
        &json!({ "subject": "Epic one" }),
    )
    .await;
    let mut last = Value::Null;
    for n in 0..3 {
        last = create(
            &app,
            &token,
            &pid,
            "issues",
            &json!({ "subject": format!("Plain issue {n}") }),
        )
        .await;
    }
    let issue_ref = last["ref"].as_i64().unwrap();
    let issue_key = format!("{prefix}-{issue_ref}");
    let epic_key = format!("{prefix}-E-{}", epic["ref"].as_i64().unwrap());

    for q in [
        issue_key.clone(),
        issue_key.to_lowercase(),
        format!("#{issue_ref}"),
        issue_ref.to_string(),
    ] {
        let hits = search(&app, &token, &format!("q={}", enc(&q))).await;
        assert!(!hits.is_empty(), "{q:?} found nothing");
        assert_eq!(hits[0]["key"], issue_key.as_str(), "{q:?}: {hits:?}");
        assert_eq!(hits[0]["key_match"], true, "{q:?}");
        assert_eq!(hits[0]["entity_id"], last["id"], "{q:?}");
    }

    // The epic counter is separate: PS-E-1 is the epic, not issue #1.
    let hits = search(&app, &token, &format!("q={}", enc(&epic_key))).await;
    assert_eq!(hits[0]["entity_type"], "epic", "{hits:?}");
    assert_eq!(hits[0]["key"], epic_key.as_str());
    assert!(
        hits.iter()
            .filter(|h| h["key_match"] == true)
            .all(|h| h["entity_type"] == "epic"),
        "an epic key matches no issue: {hits:?}"
    );

    // A bare number that is both an issue and an epic ref returns both, the
    // issue first.
    let hits = search(&app, &token, "q=1").await;
    let keyed: Vec<&Value> = hits.iter().filter(|h| h["key_match"] == true).collect();
    assert_eq!(keyed.len(), 2, "{hits:?}");
    assert_eq!(keyed[0]["entity_type"], "issue");
    assert_eq!(keyed[1]["entity_type"], "epic");

    // Text hits carry their key too.
    let hits = search(&app, &token, "q=plain").await;
    assert!(
        hits.iter()
            .all(|h| h["key"].as_str().is_some_and(|k| k.starts_with(&prefix))),
        "{hits:?}"
    );
}

#[tokio::test]
async fn bare_number_ranks_the_current_project_first() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = user_token(&app, "b@example.com", "buser").await;
    let (a, _) = make_project(&app, &token, "Alpha", "private").await;
    let (b, _) = make_project(&app, &token, "Beta", "private").await;
    create(
        &app,
        &token,
        &a,
        "issues",
        &json!({ "subject": "alpha one" }),
    )
    .await;
    create(
        &app,
        &token,
        &b,
        "issues",
        &json!({ "subject": "beta one" }),
    )
    .await;

    for current in [&a, &b] {
        let hits = search(&app, &token, &format!("q=1&boost_project_id={current}")).await;
        let keyed: Vec<&Value> = hits.iter().filter(|h| h["key_match"] == true).collect();
        assert_eq!(keyed.len(), 2, "global, not filtered: {hits:?}");
        assert_eq!(keyed[0]["project_id"], current.as_str(), "{hits:?}");
    }

    // project_id is still a hard filter for existing callers.
    let hits = search(&app, &token, &format!("q=1&project_id={a}")).await;
    assert!(
        hits.iter().all(|h| h["project_id"] == a.as_str()),
        "{hits:?}"
    );
}

#[tokio::test]
async fn renamed_prefix_still_finds_the_issue() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = user_token(&app, "r@example.com", "ruser").await;
    let (pid, old) = make_project(&app, &token, "Rename", "private").await;
    let issue = create(&app, &token, &pid, "issues", &json!({ "subject": "moved" })).await;
    let new = if old == "ZQX" { "ZQY" } else { "ZQX" };
    let r = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}"),
            Some(&token),
            &[],
            Some(&json!({ "issue_prefix": new })),
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);

    let n = issue["ref"].as_i64().unwrap();
    let hits = search(&app, &token, &format!("q={old}-{n}")).await;
    assert_eq!(hits[0]["entity_id"], issue["id"], "{hits:?}");
    // The rendered key uses the current prefix.
    assert_eq!(hits[0]["key"], format!("{new}-{n}").as_str());
}

#[tokio::test]
async fn partial_words_non_english_and_fuzzy_titles_match() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = user_token(&app, "t@example.com", "tuser").await;
    let (pid, _) = make_project(&app, &token, "Text", "private").await;
    let long_body = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(40);
    let deploy = create(
        &app,
        &token,
        &pid,
        "issues",
        &json!({ "subject": "Deployment pipeline", "description": long_body }),
    )
    .await;
    let german = create(
        &app,
        &token,
        &pid,
        "issues",
        &json!({ "subject": "Überweisungen werden doppelt gebucht" }),
    )
    .await;
    let russian = create(
        &app,
        &token,
        &pid,
        "issues",
        &json!({ "subject": "Ошибка при сохранении отчёта" }),
    )
    .await;

    let cases = [
        ("deplo", &deploy),
        ("deployment pipel", &deploy),
        // A typo in a title whose long description would drown whole-text
        // similarity.
        ("pipline", &deploy),
        ("überweis", &german),
        ("сохранен", &russian),
    ];
    for (q, want) in cases {
        let hits = search(&app, &token, &format!("q={}", enc(q))).await;
        assert!(
            hits.iter().any(|h| h["entity_id"] == want["id"]),
            "{q:?} missed {}: {hits:?}",
            want["subject"]
        );
    }
}

#[tokio::test]
async fn superadmin_sees_all_and_non_members_see_nothing() {
    require_db!();
    let app = TestApp::spawn().await;
    let owner = user_token(&app, "o@example.com", "owner").await;
    let outsider = user_token(&app, "x@example.com", "outsider").await;
    let (private, _) = make_project(&app, &owner, "Hidden", "private").await;
    let (internal, _) = make_project(&app, &owner, "Open", "internal").await;
    for pid in [&private, &internal] {
        create(
            &app,
            &owner,
            pid,
            "issues",
            &json!({ "subject": "quarterly zebra report" }),
        )
        .await;
    }

    // Visible project or not, a non-member cannot open its issues, so search
    // must not offer them.
    let hits = search(&app, &outsider, "q=zebra").await;
    assert!(hits.is_empty(), "outsider sees nothing: {hits:?}");

    // Superadmin: every project, without membership.
    {
        let client = app.db.pool.get().await.unwrap();
        client
            .execute(
                "UPDATE users SET is_superadmin = true WHERE email = 'x@example.com'",
                &[],
            )
            .await
            .unwrap();
    }
    let hits = search(&app, &outsider, "q=zebra").await;
    let mut projects: Vec<&str> = hits
        .iter()
        .map(|h| h["project_id"].as_str().unwrap())
        .collect();
    projects.sort_unstable();
    let mut want = vec![private.as_str(), internal.as_str()];
    want.sort_unstable();
    assert_eq!(projects, want, "{hits:?}");
}
