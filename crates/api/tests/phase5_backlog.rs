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
//! Phase 5 acceptance: epics + unified issues (Story/Task/Bug) + cross-cutting.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, post_json_bearer, req};
use serde_json::{Value, json};
use std::collections::HashSet;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn owner_project(app: &TestApp) -> (String, String) {
    let _ = app.register("bk@example.com", "bkuser", STRONG_PW).await;
    let token = app
        .login("bk@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "BL" }),
        ))
        .await;
    assert_eq!(p.status, 201, "{:?}", p.json);
    (token, p.json["id"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn epics_and_issues_number_independently() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    // Epics have their own ref series (key <PREFIX>-E-<ref>).
    let e1 = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "E1" }),
        ))
        .await;
    assert_eq!(e1.status, 201, "{:?}", e1.json);
    assert_eq!(e1.json["ref"], 1);
    assert!(e1.header("etag").is_some(), "response carries an ETag");

    // Issues number independently of epics, starting at 1.
    let u1 = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "U1" }),
        ))
        .await;
    assert_eq!(u1.json["ref"], 1);
    let u2 = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "T1" }),
        ))
        .await;
    assert_eq!(u2.json["ref"], 2);

    // A second epic continues the epic series, unaffected by the issues.
    let e2 = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "E2" }),
        ))
        .await;
    assert_eq!(e2.json["ref"], 2);

    // And a third issue continues the issue series.
    let u3 = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "I1" }),
        ))
        .await;
    assert_eq!(u3.json["ref"], 3);
}

#[tokio::test]
async fn concurrent_creates_yield_unique_contiguous_refs() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let uri = format!("/api/v1/projects/{pid}/issues");

    let mut futs = Vec::new();
    for n in 0..100 {
        let f = app.send(post_json_bearer(
            &uri,
            &token,
            &json!({ "subject": format!("U{n}") }),
        ));
        futs.push(f);
    }
    let results = futures::future::join_all(futs).await;
    let refs: Vec<i64> = results
        .iter()
        .map(|r| r.json["ref"].as_i64().unwrap())
        .collect();
    let uniq: HashSet<i64> = refs.iter().copied().collect();
    assert_eq!(uniq.len(), 100, "no duplicate refs under concurrency");
    assert_eq!(*refs.iter().min().unwrap(), 1);
    assert_eq!(
        *refs.iter().max().unwrap(),
        100,
        "refs are contiguous 1..=100"
    );
}

#[tokio::test]
async fn occ_etag_if_match_flow() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "E" }),
        ))
        .await;
    let id = created.json["id"].as_str().unwrap().to_owned();
    let etag = created.header("etag").unwrap().to_owned();
    let base = format!("/api/v1/projects/{pid}/epics/{id}");

    // PATCH without If-Match → 428.
    let no_if = app
        .send(req(
            "PATCH",
            &base,
            Some(&token),
            &[],
            Some(&json!({ "subject": "X" })),
        ))
        .await;
    assert_eq!(no_if.status, 428);

    // PATCH with wrong If-Match → 412.
    let wrong = app
        .send(req(
            "PATCH",
            &base,
            Some(&token),
            &[("if-match", "\"bogus\"")],
            Some(&json!({ "subject": "X" })),
        ))
        .await;
    assert_eq!(wrong.status, 412);

    // PATCH with correct If-Match → 200, version bumps.
    let ok = app
        .send(req(
            "PATCH",
            &base,
            Some(&token),
            &[("if-match", &etag)],
            Some(&json!({ "subject": "Renamed" })),
        ))
        .await;
    assert_eq!(ok.status, 200, "{:?}", ok.json);
    assert_eq!(ok.json["subject"], "Renamed");
    assert_eq!(ok.json["version"], 2);
    assert_ne!(
        ok.header("etag").unwrap(),
        etag,
        "ETag changes after update"
    );

    // PATCH with the *weak* form of the current ETag (as a gzip-ing reverse
    // proxy would rewrite it) is still accepted.
    let new_etag = ok.header("etag").unwrap().to_owned();
    let weak = app
        .send(req(
            "PATCH",
            &base,
            Some(&token),
            &[("if-match", &format!("W/{new_etag}"))],
            Some(&json!({ "subject": "Weak" })),
        ))
        .await;
    assert_eq!(weak.status, 200, "weak If-Match accepted: {:?}", weak.json);
    assert_eq!(weak.json["version"], 3);
}

#[tokio::test]
async fn merge_patch_rejects_unknown_fields() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "E" }),
        ))
        .await;
    let id = created.json["id"].as_str().unwrap();
    let etag = created.header("etag").unwrap().to_owned();
    let resp = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/epics/{id}"),
            Some(&token),
            &[("if-match", &etag)],
            Some(&json!({ "totally_unknown": 1 })),
        ))
        .await;
    assert_eq!(resp.status, 400);
}

#[tokio::test]
async fn bulk_create_issues() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let items: Vec<Value> = (0..5)
        .map(|n| json!({ "subject": format!("BU{n}") }))
        .collect();
    let resp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/bulk"),
            &token,
            &json!({ "items": items }),
        ))
        .await;
    assert_eq!(resp.status, 201, "{:?}", resp.json);
    assert_eq!(resp.json["issues"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn reorder_issues() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let mut ids = Vec::new();
    for n in 0..3 {
        let r = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/issues"),
                &token,
                &json!({ "subject": format!("R{n}") }),
            ))
            .await;
        ids.push(r.json["id"].as_str().unwrap().to_owned());
    }
    // Move the 3rd to the front (before the 1st).
    let mv = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/{}/move", ids[2]),
            &token,
            &json!({ "after_id": ids[0] }),
        ))
        .await;
    assert_eq!(mv.status, 204, "{:?}", mv.json);
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
        ))
        .await;
    let order: Vec<&str> = list.json["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["id"].as_str().unwrap())
        .collect();
    assert_eq!(order[0], ids[2], "moved item is first");
}

#[tokio::test]
async fn cross_project_epic_association_is_422() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid_a) = owner_project(&app).await;
    // Second project owned by same user.
    let pb = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "Other" }),
        ))
        .await;
    let pid_b = pb.json["id"].as_str().unwrap().to_owned();
    let epic_b = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid_b}/epics"),
            &token,
            &json!({ "subject": "EB" }),
        ))
        .await;
    let epic_b_id = epic_b.json["id"].as_str().unwrap();

    // Create an issue in project A referencing project B's epic → 422.
    let us = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid_a}/issues"),
            &token,
            &json!({ "subject": "U", "epic_id": epic_b_id }),
        ))
        .await;
    assert_eq!(us.status, 422);
}

#[tokio::test]
async fn ref_resolver() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let t = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "TT" }),
        ))
        .await;
    let reference = t.json["ref"].as_i64().unwrap();
    let id = t.json["id"].as_str().unwrap();

    let resolved = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/resolve/{reference}"),
            &token,
        ))
        .await;
    assert_eq!(resolved.status, 200);
    assert_eq!(resolved.json["kind"], "issue");
    assert_eq!(resolved.json["id"], id);
}

#[tokio::test]
async fn idempotency_key_replays_create() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let uri = format!("/api/v1/projects/{pid}/epics");
    let key = "test-idem-key-123";

    let first = app
        .send(req(
            "POST",
            &uri,
            Some(&token),
            &[("idempotency-key", key)],
            Some(&json!({ "subject": "Once" })),
        ))
        .await;
    assert_eq!(first.status, 201);
    let first_id = first.json["id"].as_str().unwrap().to_owned();

    let second = app
        .send(req(
            "POST",
            &uri,
            Some(&token),
            &[("idempotency-key", key)],
            Some(&json!({ "subject": "Once" })),
        ))
        .await;
    assert_eq!(second.status, 201);
    assert_eq!(
        second.json["id"].as_str().unwrap(),
        first_id,
        "replay returns the same entity"
    );
    assert_eq!(second.header("idempotent-replayed"), Some("true"));

    // Only one epic exists.
    let list = app.send(get_with_bearer(&uri, &token)).await;
    assert_eq!(list.json["epics"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn history_records_field_changes() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "H" }),
        ))
        .await;
    let id = created.json["id"].as_str().unwrap().to_owned();
    let etag = created.header("etag").unwrap().to_owned();
    let _ = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/epics/{id}"),
            Some(&token),
            &[("if-match", &etag)],
            Some(&json!({ "subject": "Changed" })),
        ))
        .await;

    let hist = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/epics/{id}/history"),
            &token,
        ))
        .await;
    assert_eq!(hist.status, 200);
    let entries = hist.json["history"].as_array().unwrap();
    // creation + one field-change entry; the latest diff records subject change.
    assert!(entries.len() >= 2);
    let last = entries.last().unwrap();
    assert!(
        last["diff"]["subject"].is_array(),
        "diff records subject [old,new]"
    );
}

#[tokio::test]
async fn comments_lifecycle() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let us = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "C" }),
        ))
        .await;
    let id = us.json["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/projects/{pid}/issues/{id}/comments");

    let c = app
        .send(post_json_bearer(
            &base,
            &token,
            &json!({ "body": "first comment" }),
        ))
        .await;
    assert_eq!(c.status, 201, "{:?}", c.json);
    let cid = c.json["id"].as_str().unwrap().to_owned();

    let list = app.send(get_with_bearer(&base, &token)).await;
    assert_eq!(list.json["comments"].as_array().unwrap().len(), 1);

    // Author edits within window.
    let edit = app
        .send(req(
            "PATCH",
            &format!("{base}/{cid}"),
            Some(&token),
            &[],
            Some(&json!({ "body": "edited" })),
        ))
        .await;
    assert_eq!(edit.status, 200);
    assert_eq!(edit.json["body"], "edited");

    let del = app
        .send(req(
            "DELETE",
            &format!("{base}/{cid}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    assert_eq!(del.status, 204);
}

#[tokio::test]
async fn taxonomy_in_use_delete_is_409() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    // Grab an issue_status taxonomy item and attach it to a new issue.
    let statuses = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/issue_status"),
            &token,
        ))
        .await;
    let status_id = statuses.json["items"][0]["id"].as_str().unwrap().to_owned();
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "S", "status_id": status_id }),
        ))
        .await;

    // Deleting that in-use status → 409.
    let del = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/taxonomy/issue_status/{status_id}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    assert_eq!(del.status, 409, "{:?}", del.json);
    assert_eq!(del.json["code"], "in_use");
}

#[tokio::test]
async fn labels_and_components_crud() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let label = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/labels"),
            &token,
            &json!({ "name": "backend", "color": "#0079bc" }),
        ))
        .await;
    assert_eq!(label.status, 201, "{:?}", label.json);
    assert_eq!(label.json["name"], "backend");
    let dup = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/labels"),
            &token,
            &json!({ "name": "backend" }),
        ))
        .await;
    assert_eq!(dup.status, 409);

    let comp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components"),
            &token,
            &json!({ "name": "api", "color": "#669900" }),
        ))
        .await;
    assert_eq!(comp.status, 201, "{:?}", comp.json);
    assert_eq!(comp.json["name"], "api");

    let labels = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/labels"),
            &token,
        ))
        .await;
    assert_eq!(labels.json["labels"].as_array().unwrap().len(), 1);
    let comps = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/components"),
            &token,
        ))
        .await;
    assert_eq!(comps.json["components"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn issue_carries_labels_and_components() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let l = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/labels"),
            &token,
            &json!({ "name": "urgent" }),
        ))
        .await;
    let label_id = l.json["id"].as_str().unwrap().to_owned();
    let c = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components"),
            &token,
            &json!({ "name": "web" }),
        ))
        .await;
    let component_id = c.json["id"].as_str().unwrap().to_owned();

    let issue = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "Bug", "labels": [label_id], "components": [component_id] }),
        ))
        .await;
    assert_eq!(issue.status, 201, "{:?}", issue.json);
    assert_eq!(issue.json["labels"].as_array().unwrap().len(), 1);
    assert_eq!(issue.json["components"].as_array().unwrap().len(), 1);

    // A label from another project is rejected (422).
    let pb = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "P2" }),
        ))
        .await;
    let pid_b = pb.json["id"].as_str().unwrap();
    let lb = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid_b}/labels"),
            &token,
            &json!({ "name": "x" }),
        ))
        .await;
    let foreign_label = lb.json["id"].as_str().unwrap();
    let bad = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "Bad", "labels": [foreign_label] }),
        ))
        .await;
    assert_eq!(bad.status, 422);

    // PATCH replaces labels (clear to empty), leaving components untouched.
    let id = issue.json["id"].as_str().unwrap();
    let etag = issue.header("etag").unwrap().to_owned();
    let patched = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/issues/{id}"),
            Some(&token),
            &[("if-match", &etag)],
            Some(&json!({ "labels": [] })),
        ))
        .await;
    assert_eq!(patched.status, 200, "{:?}", patched.json);
    assert_eq!(patched.json["labels"].as_array().unwrap().len(), 0);
    assert_eq!(
        patched.json["components"].as_array().unwrap().len(),
        1,
        "components unchanged"
    );
}

#[tokio::test]
async fn bulk_purge_epics_detaches_issues_then_purge_issues_clears_all() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let epic = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "E" }),
        ))
        .await;
    assert_eq!(epic.status, 201, "{:?}", epic.json);
    let epic_id = epic.json["id"].as_str().unwrap().to_owned();

    // One issue grouped under the epic, one standalone.
    let linked = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "linked", "epic_id": epic_id }),
        ))
        .await;
    assert_eq!(linked.status, 201, "{:?}", linked.json);
    let _solo = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "solo" }),
        ))
        .await;

    // Purge epics: the epic is gone but both issues survive, detached.
    let pe = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
        ))
        .await;
    assert_eq!(pe.status, 200, "{:?}", pe.json);
    assert_eq!(pe.json["deleted"], 1);

    let epics = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
        ))
        .await;
    assert_eq!(epics.json["epics"].as_array().unwrap().len(), 0);

    let issues = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
        ))
        .await;
    let list = issues.json["issues"].as_array().unwrap();
    assert_eq!(list.len(), 2, "issues survive an epic purge");
    for i in list {
        assert!(i["epic_id"].is_null(), "epic_id detached after purge");
    }

    // Purge issues: now everything is gone.
    let pi = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
        ))
        .await;
    assert_eq!(pi.status, 200, "{:?}", pi.json);
    assert_eq!(pi.json["deleted"], 2);

    let issues2 = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
        ))
        .await;
    assert_eq!(issues2.json["issues"].as_array().unwrap().len(), 0);
}
