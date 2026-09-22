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
//! Phase 35 acceptance: customers on any issue — the customer filter on the
//! issue list and board, the customers column in import/export, and the V027
//! restore of customers wiped by the old web client's category auto-clear.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::{TestApp, delete_bearer, get_with_bearer, post_json_bearer, req};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// The V027 body, re-run against seeded history (the migration itself already
/// ran on the empty schema when the test database was created).
const RESTORE_SQL: &str = include_str!("../../db/migrations/V027__restore_issue_customers.sql");

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
            &json!({ "name": "Customers" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (token, project.json["id"].as_str().unwrap().to_owned())
}

async fn create_customer(app: &TestApp, token: &str, pid: &str, name: &str) -> String {
    let resp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/customers"),
            token,
            &json!({ "name": name }),
        ))
        .await;
    assert_eq!(resp.status, 201, "{:?}", resp.json);
    resp.json["id"].as_str().unwrap().to_owned()
}

async fn create_issue(app: &TestApp, token: &str, pid: &str, body: &Value) -> (String, String) {
    let resp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            token,
            body,
        ))
        .await;
    assert_eq!(resp.status, 201, "{:?}", resp.json);
    (
        resp.json["id"].as_str().unwrap().to_owned(),
        resp.header("etag").unwrap().to_owned(),
    )
}

async fn patch_issue(
    app: &TestApp,
    token: &str,
    pid: &str,
    id: &str,
    etag: &str,
    body: &Value,
) -> String {
    let resp = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/issues/{id}"),
            Some(token),
            &[("if-match", etag)],
            Some(body),
        ))
        .await;
    assert_eq!(resp.status, 200, "{:?}", resp.json);
    resp.header("etag").unwrap().to_owned()
}

async fn get_issue(app: &TestApp, token: &str, pid: &str, id: &str) -> Value {
    let resp = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{id}"),
            token,
        ))
        .await;
    assert_eq!(resp.status, 200, "{:?}", resp.json);
    resp.json
}

fn ids(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect();
    out.sort();
    out
}

async fn history_count(client: &deadpool_postgres::Client) -> i64 {
    client
        .query_one("SELECT count(*) AS n FROM history_entries", &[])
        .await
        .unwrap()
        .get("n")
}

fn subjects(list: &Value) -> Vec<String> {
    let mut out: Vec<String> = list["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["subject"].as_str().unwrap().to_owned())
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// customers are independent of the category
// ---------------------------------------------------------------------------

#[tokio::test]
async fn customers_survive_category_change() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "custcat").await;
    let a = create_customer(&app, &token, &pid, "Acme").await;

    // Customers on a non-customer-request issue are accepted.
    let (id, etag) = create_issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "roadmap work", "category": "roadmap", "customer_ids": [a] }),
    )
    .await;
    let _ = patch_issue(
        &app,
        &token,
        &pid,
        &id,
        &etag,
        &json!({ "category": "security" }),
    )
    .await;
    let got = get_issue(&app, &token, &pid, &id).await;
    assert_eq!(ids(&got["customer_ids"]), vec![a]);
}

// ---------------------------------------------------------------------------
// customer filter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_and_board_filter_by_customer() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "custfilter").await;
    let a = create_customer(&app, &token, &pid, "Acme").await;
    let b = create_customer(&app, &token, &pid, "Globex").await;
    let c = create_customer(&app, &token, &pid, "Initech").await;
    let _ = create_issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "only-a", "customer_ids": [a] }),
    )
    .await;
    let _ = create_issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "a-and-b", "customer_ids": [a, b] }),
    )
    .await;
    let _ = create_issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "only-b", "customer_ids": [b] }),
    )
    .await;
    let _ = create_issue(&app, &token, &pid, &json!({ "subject": "nobody" })).await;

    let list = |q: String| {
        let app = &app;
        let token = token.clone();
        let pid = pid.clone();
        async move {
            let resp = app
                .send(get_with_bearer(
                    &format!("/api/v1/projects/{pid}/issues?{q}"),
                    &token,
                ))
                .await;
            assert_eq!(resp.status, 200, "{:?}", resp.json);
            (subjects(&resp.json), resp.json["total"].as_i64().unwrap())
        }
    };

    let (s, total) = list(format!("customer={a}")).await;
    assert_eq!(s, vec!["a-and-b", "only-a"]);
    assert_eq!(total, 2);

    // Several ids match issues linked to any of them.
    let (s, _) = list(format!("customer={a},{b}")).await;
    assert_eq!(s, vec!["a-and-b", "only-a", "only-b"]);

    let (s, _) = list(format!("customer={c}")).await;
    assert!(s.is_empty());

    let (s, _) = list("customer=none".to_owned()).await;
    assert_eq!(s, vec!["nobody"]);

    // Garbage applies no filter, like the other reference filters.
    let (_, total) = list("customer=not-a-uuid".to_owned()).await;
    assert_eq!(total, 4);

    // The board honours the same filter.
    let board = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/board?customer={b}"),
            &token,
        ))
        .await;
    assert_eq!(board.status, 200, "{:?}", board.json);
    let cards: usize = board.json["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| usize::try_from(c["total"].as_i64().unwrap()).unwrap())
        .sum();
    assert_eq!(cards, 2);

    // …and the grouped board (lanes) too.
    let lanes = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/board?group=assignee&customer=none"),
            &token,
        ))
        .await;
    assert_eq!(lanes.status, 200, "{:?}", lanes.json);
    let lane_total: i64 = lanes.json["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["total"].as_i64().unwrap())
        .sum();
    assert_eq!(lane_total, 1);
}

// ---------------------------------------------------------------------------
// import / export
// ---------------------------------------------------------------------------

/// Multipart POST with a `file` part and an optional `mapping` JSON part.
fn import_request(uri: &str, token: &str, csv: &str, mapping: Option<&str>) -> Request<Body> {
    let boundary = "----ipcustomerboundary";
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

#[tokio::test]
async fn export_and_import_carry_customers() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "custio").await;
    let a = create_customer(&app, &token, &pid, "Acme").await;
    let b = create_customer(&app, &token, &pid, "Globex").await;
    let _ = create_issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "shared", "customer_ids": [a, b] }),
    )
    .await;

    let (status, _, bytes) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/export?format=csv"),
            &token,
        ))
        .await;
    assert_eq!(status, 200);
    let csv = String::from_utf8(bytes).unwrap();
    assert!(csv.lines().next().unwrap().contains(",Customers,"), "{csv}");
    assert!(csv.contains("\"Acme, Globex\""), "{csv}");

    // Import into the same project: the preview matches both names plus
    // reports an unknown one; the commit links only mapped customers.
    let import_csv = "Subject,Customers\nimported,\"Acme, Globex, Unknown Co\"\n";
    let preview = app
        .send(import_request(
            &format!("/api/v1/projects/{pid}/issues/import/preview"),
            &token,
            import_csv,
            None,
        ))
        .await;
    assert_eq!(preview.status, 200, "{:?}", preview.json);
    let customer_matches = preview.json["customers"].as_array().unwrap();
    assert_eq!(customer_matches.len(), 3);
    let matched = |name: &str| {
        customer_matches
            .iter()
            .find(|m| m["value"] == name)
            .map(|m| m["matched_id"].clone())
            .unwrap()
    };
    assert_eq!(matched("Acme"), json!(a));
    assert_eq!(matched("Globex"), json!(b));
    assert!(matched("Unknown Co").is_null());

    // A target from another project is refused (dropped), never linked.
    let (other_token, other_pid) = owner_with_project(&app, "custioother").await;
    let foreign = create_customer(&app, &other_token, &other_pid, "Foreign").await;
    let mapping = json!({
        "customers": [
            { "value": "Acme", "target": a },
            { "value": "Globex", "target": foreign },
        ]
    })
    .to_string();
    let commit = app
        .send(import_request(
            &format!("/api/v1/projects/{pid}/issues/import"),
            &token,
            import_csv,
            Some(&mapping),
        ))
        .await;
    assert_eq!(commit.status, 200, "{:?}", commit.json);
    assert_eq!(commit.json["created_issues"], 1);

    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues?search=imported"),
            &token,
        ))
        .await;
    let issue = &list.json["issues"][0];
    assert_eq!(ids(&issue["customer_ids"]), vec![a]);
}

// ---------------------------------------------------------------------------
// V027: restore customers wiped by the category auto-clear
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_migration_puts_back_auto_cleared_customers() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "custrestore").await;
    let a = create_customer(&app, &token, &pid, "Acme").await;
    let b = create_customer(&app, &token, &pid, "Globex").await;
    let gone = create_customer(&app, &token, &pid, "Defunct").await;

    // What the pre-0.7.2 web client sent: category and an empty customer set
    // in one PATCH.
    let old_client_clear = json!({ "category": "roadmap", "customer_ids": [] });
    let base = |s: &str, custs: &[&String]| json!({ "subject": s, "category": "customer_request", "customer_ids": custs });

    // 1. Plain auto-clear → restored.
    let (wiped, e) = create_issue(&app, &token, &pid, &base("wiped", &[&a, &b])).await;
    let _ = patch_issue(&app, &token, &pid, &wiped, &e, &old_client_clear).await;

    // 2. Auto-clear, then someone set customers again → left alone.
    let (reset, e) = create_issue(&app, &token, &pid, &base("reset", &[&a])).await;
    let e = patch_issue(&app, &token, &pid, &reset, &e, &old_client_clear).await;
    let _ = patch_issue(
        &app,
        &token,
        &pid,
        &reset,
        &e,
        &json!({ "customer_ids": [b] }),
    )
    .await;

    // 3. Customers removed deliberately, no category change → left alone.
    let (manual, e) = create_issue(&app, &token, &pid, &base("manual", &[&a])).await;
    let _ = patch_issue(
        &app,
        &token,
        &pid,
        &manual,
        &e,
        &json!({ "customer_ids": [] }),
    )
    .await;

    // 4. Auto-clear including a customer deleted since → only the live one.
    let (partial, e) = create_issue(&app, &token, &pid, &base("partial", &[&a, &gone])).await;
    let _ = patch_issue(&app, &token, &pid, &partial, &e, &old_client_clear).await;
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/customers/{gone}"),
            &token,
        ))
        .await;
    assert!(del.status == 204 || del.status == 200, "{:?}", del.json);

    let version_before = get_issue(&app, &token, &pid, &wiped).await["version"].clone();

    let client = app.db.pool.get().await.unwrap();
    client.batch_execute(RESTORE_SQL).await.unwrap();

    let w = get_issue(&app, &token, &pid, &wiped).await;
    let mut ab = vec![a.clone(), b.clone()];
    ab.sort();
    assert_eq!(ids(&w["customer_ids"]), ab);
    assert_ne!(
        w["version"], version_before,
        "restored issue is re-versioned"
    );
    assert_eq!(
        ids(&get_issue(&app, &token, &pid, &reset).await["customer_ids"]),
        vec![b.clone()]
    );
    assert!(ids(&get_issue(&app, &token, &pid, &manual).await["customer_ids"]).is_empty());
    assert_eq!(
        ids(&get_issue(&app, &token, &pid, &partial).await["customer_ids"]),
        vec![a.clone()]
    );

    // The restore is visible in the issue's history, attributed to nobody.
    let hist = client
        .query(
            "SELECT diff, actor_id FROM history_entries \
             WHERE target_id = $1::text::uuid ORDER BY created_at DESC, id DESC LIMIT 1",
            &[&wiped],
        )
        .await
        .unwrap();
    let diff: Value = hist[0].get("diff");
    let actor: Option<uuid::Uuid> = hist[0].get("actor_id");
    assert!(actor.is_none());
    assert_eq!(diff["customer_ids"][0], json!([]));
    assert_eq!(ids(&diff["customer_ids"][1]), ab);

    // Idempotent: a second run changes nothing and records nothing.
    let before = history_count(&client).await;
    client.batch_execute(RESTORE_SQL).await.unwrap();
    assert_eq!(history_count(&client).await, before);
    assert_eq!(
        ids(&get_issue(&app, &token, &pid, &wiped).await["customer_ids"]),
        ab
    );
}
