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
//! Phase 25 acceptance: short deep links — case-agnostic project-prefix
//! resolution with rename history, per-project board keys (auto-generated,
//! editable, case-agnostic lookup, rename history), and the superadmin
//! history maintenance endpoints.

mod common;

use common::{TestApp, get_with_bearer, post_json_bearer, req};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// Register + login, returning (token, user_id).
async fn user(app: &TestApp, email: &str, username: &str) -> (String, String) {
    let _ = app.register(email, username, STRONG_PW).await;
    let token = app.login(email, STRONG_PW).await.access_token().unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    let id = me.json["id"].as_str().unwrap().to_owned();
    (token, id)
}

/// Owner with a fresh project. Returns (token, project_id, issue_prefix).
async fn owner_project(app: &TestApp, name: &str) -> (String, String, String) {
    let (token, _uid) = user(app, "owner@x", "owneruser").await;
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": name }),
        ))
        .await;
    assert_eq!(p.status, 201, "{:?}", p.json);
    (
        token,
        p.json["id"].as_str().unwrap().to_owned(),
        p.json["issue_prefix"].as_str().unwrap().to_owned(),
    )
}

async fn promote_superadmin(app: &TestApp, email: &str) {
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE users SET is_superadmin = true WHERE email = $1",
            &[&email.trim().to_lowercase()],
        )
        .await
        .unwrap();
}

/// Every letter-case variant of an ASCII prefix (2^len combinations).
fn case_variants(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    for mask in 0..(1_u32 << chars.len()) {
        out.push(
            chars
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    if mask & (1 << i) == 0 {
                        c.to_ascii_lowercase()
                    } else {
                        c.to_ascii_uppercase()
                    }
                })
                .collect(),
        );
    }
    out
}

/// PATCH the project's issue prefix (loads a fresh ETag-free PATCH — project
/// updates are not ETag-guarded).
async fn rename_prefix(app: &TestApp, token: &str, pid: &str, prefix: &str) {
    let r = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}"),
            Some(token),
            &[],
            Some(&json!({ "issue_prefix": prefix })),
        ))
        .await;
    assert_eq!(r.status, 200, "rename prefix: {:?}", r.json);
}

// ---------------------------------------------------------------------------
// project prefix resolution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prefix_resolves_in_any_case_and_stays_private() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid, prefix) = owner_project(&app, "Shortlinks").await;

    // IP / Ip / iP / ip — every combination resolves to the same project.
    for variant in case_variants(&prefix) {
        let r = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/by-prefix/{variant}"),
                &owner,
            ))
            .await;
        assert_eq!(r.status, 200, "variant {variant}: {:?}", r.json);
        assert_eq!(r.json["id"], Value::String(pid.clone()));
        // The canonical (uppercase) prefix comes back for link generation.
        assert_eq!(r.json["issue_prefix"], Value::String(prefix.clone()));
    }

    // Unknown prefix → 404.
    let r = app
        .send(get_with_bearer("/api/v1/projects/by-prefix/ZZQ", &owner))
        .await;
    assert_eq!(r.status, 404);

    // A non-member gets 404 for a private project — prefix probing must not
    // disclose existence.
    let (stranger, _sid) = user(&app, "stranger@x", "strangeruser").await;
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/by-prefix/{prefix}"),
            &stranger,
        ))
        .await;
    assert_eq!(r.status, 404, "{:?}", r.json);
}

#[tokio::test]
async fn renamed_prefix_resolves_via_history_until_pruned() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid, old_prefix) = owner_project(&app, "History").await;
    promote_superadmin(&app, "owner@x").await;

    rename_prefix(&app, &owner, &pid, "ZQA").await;

    // The retired prefix still resolves (any case) through history.
    for variant in [old_prefix.clone(), old_prefix.to_lowercase()] {
        let r = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/by-prefix/{variant}"),
                &owner,
            ))
            .await;
        assert_eq!(r.status, 200, "historic {variant}: {:?}", r.json);
        assert_eq!(r.json["id"], Value::String(pid.clone()));
    }
    // And the new prefix resolves live.
    let r = app
        .send(get_with_bearer("/api/v1/projects/by-prefix/zqa", &owner))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json["id"], Value::String(pid.clone()));

    // Superadmin sees the history entry…
    let hist = app
        .send(get_with_bearer("/api/v1/admin/short-link-history", &owner))
        .await;
    assert_eq!(hist.status, 200, "{:?}", hist.json);
    let entries = hist.json["projects"].as_array().unwrap();
    let entry = entries
        .iter()
        .find(|e| e["prefix"] == Value::String(old_prefix.clone()))
        .expect("history entry present");
    let entry_id = entry["id"].as_str().unwrap().to_owned();

    // …and prunes it; the old short link stops resolving.
    let del = app
        .send(post_json_bearer(
            "/api/v1/admin/short-link-history/delete",
            &owner,
            &json!({ "project_ids": [entry_id] }),
        ))
        .await;
    assert_eq!(del.status, 200, "{:?}", del.json);
    assert_eq!(del.json["deleted_projects"], 1);
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/by-prefix/{old_prefix}"),
            &owner,
        ))
        .await;
    assert_eq!(r.status, 404, "pruned prefix no longer resolves");
}

#[tokio::test]
async fn live_prefix_shadows_history() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid_a, old_prefix) = owner_project(&app, "First").await;

    rename_prefix(&app, &owner, &pid_a, "ZQB").await;

    // Another project claims the freed prefix — live beats history.
    let b = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &owner,
            &json!({ "name": "Second", "issue_prefix": old_prefix }),
        ))
        .await;
    assert_eq!(b.status, 201, "{:?}", b.json);
    let pid_b = b.json["id"].as_str().unwrap().to_owned();

    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/by-prefix/{old_prefix}"),
            &owner,
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json["id"], Value::String(pid_b), "live claim wins");
}

#[tokio::test]
async fn history_endpoints_are_superadmin_only() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _pid, _prefix) = owner_project(&app, "Locked").await;

    let r = app
        .send(get_with_bearer("/api/v1/admin/short-link-history", &owner))
        .await;
    assert_eq!(r.status, 403, "{:?}", r.json);
    let r = app
        .send(post_json_bearer(
            "/api/v1/admin/short-link-history/delete",
            &owner,
            &json!({ "project_ids": [] }),
        ))
        .await;
    assert_eq!(r.status, 403, "{:?}", r.json);
}

// ---------------------------------------------------------------------------
// board keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn board_keys_generate_resolve_and_rename() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid, _prefix) = owner_project(&app, "Boards").await;
    promote_superadmin(&app, "owner@x").await;

    // The seeded default board carries the key "board".
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/boards"),
            &owner,
        ))
        .await;
    assert_eq!(list.status, 200, "{:?}", list.json);
    assert_eq!(list.json["boards"][0]["key"], "board");

    // Multi-word names shorten to initials; a clone gets a suffix.
    let b1 = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/boards"),
            &owner,
            &json!({ "name": "Sprint Board", "shared": true }),
        ))
        .await;
    assert_eq!(b1.status, 201, "{:?}", b1.json);
    assert_eq!(b1.json["key"], "sb");
    let b1_id = b1.json["id"].as_str().unwrap().to_owned();
    let b2 = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/boards"),
            &owner,
            &json!({ "name": "Sprint Board", "shared": true }),
        ))
        .await;
    assert_eq!(b2.json["key"], "sb-2");

    // Lookup by key works in any case; by UUID keeps working (legacy links).
    for needle in ["sb", "SB", "Sb", &b1_id] {
        let r = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/{pid}/boards/{needle}"),
                &owner,
            ))
            .await;
        assert_eq!(r.status, 200, "lookup {needle}: {:?}", r.json);
        assert_eq!(r.json["id"], Value::String(b1_id.clone()));
    }

    // Rename the key (input uppercased on purpose → stored lowercase).
    let upd = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/boards/{b1_id}"),
            Some(&owner),
            &[],
            Some(&json!({ "name": "Sprint Board", "key": "ROADMAP" })),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["key"], "roadmap");

    // The old key still resolves through history; the new one live.
    for needle in ["sb", "roadmap", "RoadMap"] {
        let r = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/{pid}/boards/{needle}"),
                &owner,
            ))
            .await;
        assert_eq!(r.status, 200, "post-rename {needle}: {:?}", r.json);
        assert_eq!(r.json["id"], Value::String(b1_id.clone()));
    }

    // Duplicate key (case-insensitive) → 409; invalid format → 422.
    let b2_id = b2.json["id"].as_str().unwrap().to_owned();
    let dup = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/boards/{b2_id}"),
            Some(&owner),
            &[],
            Some(&json!({ "name": "Sprint Board", "key": "Roadmap" })),
        ))
        .await;
    assert_eq!(dup.status, 409, "{:?}", dup.json);
    let bad = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/boards/{b2_id}"),
            Some(&owner),
            &[],
            Some(&json!({ "name": "Sprint Board", "key": "bad key!" })),
        ))
        .await;
    assert_eq!(bad.status, 422, "{:?}", bad.json);

    // Superadmin prunes the board-key history; the old key stops resolving.
    let hist = app
        .send(get_with_bearer("/api/v1/admin/short-link-history", &owner))
        .await;
    let entry = hist.json["boards"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["key"] == "sb")
        .expect("board history entry present")
        .clone();
    assert_eq!(entry["board_id"], Value::String(b1_id.clone()));
    let del = app
        .send(post_json_bearer(
            "/api/v1/admin/short-link-history/delete",
            &owner,
            &json!({ "board_ids": [entry["id"]] }),
        ))
        .await;
    assert_eq!(del.status, 200, "{:?}", del.json);
    assert_eq!(del.json["deleted_boards"], 1);
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/boards/sb"),
            &owner,
        ))
        .await;
    assert_eq!(r.status, 404, "pruned board key no longer resolves");
}
