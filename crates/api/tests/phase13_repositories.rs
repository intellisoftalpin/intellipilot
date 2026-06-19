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
//! Phase 13 acceptance: per-project SSH credential vault, repositories,
//! component↔repository links, and basic git integration.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, patch_json_bearer, post_json_bearer};
use serde_json::json;
use uuid::Uuid;

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
            &json!({ "name": "GitProj" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (token, project.json["id"].as_str().unwrap().to_owned())
}

/// Invite a Developer (role `dev`, which lacks `project.modify`) and return
/// their access token.
async fn invite_dev(app: &TestApp, owner: &str, pid: &str, tag: &str) -> String {
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            owner,
            &json!({ "email": format!("{tag}@example.com"), "role": "dev" }),
        ))
        .await;
    let token = invite.json["invite_token"].as_str().unwrap().to_owned();
    let _ = app
        .register(&format!("{tag}@example.com"), tag, STRONG_PW)
        .await;
    let dev = app
        .login(&format!("{tag}@example.com"), STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let _ = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &dev,
            &json!({ "token": token }),
        ))
        .await;
    dev
}

async fn create_key(app: &TestApp, token: &str, pid: &str, name: &str, read_only: bool) -> String {
    let resp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys"),
            token,
            &json!({ "name": name, "read_only": read_only }),
        ))
        .await;
    assert_eq!(resp.status, 201, "{:?}", resp.json);
    resp.json["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn ssh_key_lifecycle_and_no_private_leak() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "keyowner").await;

    // Generate a key.
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys"),
            &token,
            &json!({ "name": "deploy", "read_only": true }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    assert!(
        created.json["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
    assert!(
        created.json["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );
    assert_eq!(created.json["read_only"], true);
    assert_eq!(created.json["used_by_repo_count"], 0);

    // The private key must never appear anywhere in the response.
    let body = created.json.to_string();
    assert!(!body.contains("PRIVATE"), "private key leaked: {body}");
    assert!(
        !body.to_lowercase().contains("private_key"),
        "private field leaked"
    );
    let key_id = created.json["id"].as_str().unwrap().to_owned();

    // List shows it, still no private material.
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys"),
            &token,
        ))
        .await;
    assert_eq!(list.status, 200);
    assert_eq!(list.json["ssh_keys"].as_array().unwrap().len(), 1);
    assert!(!list.json.to_string().contains("PRIVATE"));

    // Rename + flip read_only.
    let upd = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys/{key_id}"),
            &token,
            &json!({ "name": "deploy-rw", "read_only": false }),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["name"], "deploy-rw");
    assert_eq!(upd.json["read_only"], false);

    // Delete.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys/{key_id}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
}

#[tokio::test]
async fn duplicate_key_name_conflicts() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "dupkey").await;
    let _ = create_key(&app, &token, &pid, "dup", true).await;
    let again = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys"),
            &token,
            &json!({ "name": "dup" }),
        ))
        .await;
    assert_eq!(again.status, 409, "{:?}", again.json);
}

#[tokio::test]
async fn private_key_is_encrypted_at_rest() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "encrest").await;
    let key_id = create_key(&app, &token, &pid, "enc", true).await;

    let client = app.db.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT private_key_enc FROM ssh_keys WHERE id = $1",
            &[&Uuid::parse_str(&key_id).unwrap()],
        )
        .await
        .unwrap();
    let blob: Vec<u8> = row.get("private_key_enc");
    assert!(!blob.is_empty());
    // The ciphertext must not contain the plaintext OpenSSH PEM markers.
    let needle = b"OPENSSH PRIVATE KEY";
    assert!(
        !blob.windows(needle.len()).any(|w| w == needle),
        "private key stored in plaintext!"
    );
}

#[tokio::test]
async fn ssh_url_validation_rejects_http() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "urlval").await;
    let resp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/repositories"),
            &token,
            &json!({ "name": "r", "ssh_url": "https://github.com/o/r.git" }),
        ))
        .await;
    assert_eq!(resp.status, 422, "{:?}", resp.json);
}

#[tokio::test]
async fn keyless_repository_crud() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "repocrud").await;

    // Create without a key (allowed; no reachability check).
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/repositories"),
            &token,
            &json!({ "name": "api", "ssh_url": "git@github.com:org/api.git" }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    let rid = created.json["id"].as_str().unwrap().to_owned();

    // Duplicate URL conflicts.
    let dup = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/repositories"),
            &token,
            &json!({ "name": "api2", "ssh_url": "git@github.com:org/api.git" }),
        ))
        .await;
    assert_eq!(dup.status, 409, "{:?}", dup.json);

    // Rename.
    let upd = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}/repositories/{rid}"),
            &token,
            &json!({ "name": "api-renamed", "default_branch": "main" }),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["name"], "api-renamed");
    assert_eq!(upd.json["default_branch"], "main");

    // List.
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/repositories"),
            &token,
        ))
        .await;
    assert_eq!(list.json["repositories"].as_array().unwrap().len(), 1);

    // Branch listing without a key is a clean 422 (no key to authenticate).
    let branches = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/repositories/{rid}/branches"),
            &token,
        ))
        .await;
    assert_eq!(branches.status, 422, "{:?}", branches.json);

    // Delete.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/repositories/{rid}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
}

#[tokio::test]
async fn deleting_key_detaches_repositories() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "detach").await;
    let key_id = create_key(&app, &token, &pid, "shared", true).await;

    // Insert a repo wired to the key directly (bypasses the network check).
    let client = app.db.pool.get().await.unwrap();
    let pid_u = Uuid::parse_str(&pid).unwrap();
    let key_u = Uuid::parse_str(&key_id).unwrap();
    let repo_u: Uuid = client
        .query_one(
            "INSERT INTO repositories (project_id, name, ssh_url, ssh_key_id) \
             VALUES ($1, 'wired', 'git@github.com:o/wired.git', $2) RETURNING id",
            &[&pid_u, &key_u],
        )
        .await
        .unwrap()
        .get("id");

    // The key now reports one user.
    let keys = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys"),
            &token,
        ))
        .await;
    assert_eq!(keys.json["ssh_keys"][0]["used_by_repo_count"], 1);

    // Delete the key — the repo must survive but lose its key.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys/{key_id}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);

    let repo = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/repositories"),
            &token,
        ))
        .await;
    let repos = repo.json["repositories"].as_array().unwrap();
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["id"].as_str().unwrap(), repo_u.to_string());
    // No ssh_key_id field (serialized as absent when None).
    assert!(repos[0].get("ssh_key_id").is_none());
}

#[tokio::test]
async fn branch_endpoint_reports_git_error_for_unreachable() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "ureach").await;
    let key_id = create_key(&app, &token, &pid, "k", true).await;

    // Wire a repo to an unresolvable host (RFC 6761 .invalid → fast NXDOMAIN).
    let client = app.db.pool.get().await.unwrap();
    let repo_u: Uuid = client
        .query_one(
            "INSERT INTO repositories (project_id, name, ssh_url, ssh_key_id) \
             VALUES ($1, 'bad', 'git@nonexistent.invalid:o/r.git', $2) RETURNING id",
            &[
                &Uuid::parse_str(&pid).unwrap(),
                &Uuid::parse_str(&key_id).unwrap(),
            ],
        )
        .await
        .unwrap()
        .get("id");

    let resp = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/repositories/{repo_u}/branches"),
            &token,
        ))
        .await;
    assert!(
        matches!(resp.status, 422 | 500 | 502 | 504),
        "unexpected status {}: {:?}",
        resp.status,
        resp.json
    );
}

#[tokio::test]
async fn component_repository_link_lifecycle() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "linklife").await;

    // A component and a keyless repo (so branch validation is skipped).
    let comp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components"),
            &token,
            &json!({ "name": "backend", "color": "#112233" }),
        ))
        .await;
    let cid = comp.json["id"].as_str().unwrap().to_owned();
    let repo = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/repositories"),
            &token,
            &json!({ "name": "svc", "ssh_url": "git@github.com:org/svc.git" }),
        ))
        .await;
    let rid = repo.json["id"].as_str().unwrap().to_owned();

    // Link on a custom branch.
    let link = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components/{cid}/repositories"),
            &token,
            &json!({ "repository_id": rid, "branch": "develop" }),
        ))
        .await;
    assert_eq!(link.status, 201, "{:?}", link.json);
    assert_eq!(link.json["branch"], "develop");
    assert_eq!(link.json["repository_name"], "svc");

    // Duplicate link conflicts.
    let dup = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components/{cid}/repositories"),
            &token,
            &json!({ "repository_id": rid, "branch": "main" }),
        ))
        .await;
    assert_eq!(dup.status, 409, "{:?}", dup.json);

    // List.
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/components/{cid}/repositories"),
            &token,
        ))
        .await;
    assert_eq!(list.json["repositories"].as_array().unwrap().len(), 1);

    // Change branch.
    let upd = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}/components/{cid}/repositories/{rid}"),
            &token,
            &json!({ "branch": "release" }),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["branch"], "release");

    // Unlink.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/components/{cid}/repositories/{rid}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);

    let after = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/components/{cid}/repositories"),
            &token,
        ))
        .await;
    assert_eq!(after.json["repositories"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn link_rejects_repo_from_another_project() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "xproj").await;
    let comp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components"),
            &token,
            &json!({ "name": "c", "color": "#000000" }),
        ))
        .await;
    let cid = comp.json["id"].as_str().unwrap().to_owned();
    // A random repository id that doesn't exist in this project.
    let bogus = Uuid::now_v7();
    let link = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components/{cid}/repositories"),
            &token,
            &json!({ "repository_id": bogus, "branch": "main" }),
        ))
        .await;
    assert_eq!(link.status, 422, "{:?}", link.json);
}

#[tokio::test]
async fn project_modify_required_for_mutations() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_with_project(&app, "permown").await;
    let dev = invite_dev(&app, &owner, &pid, "permdev").await;

    // Dev can view keys (project.view).
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys"),
            &dev,
        ))
        .await;
    assert_eq!(list.status, 200, "{:?}", list.json);

    // But cannot create a key (needs project.modify).
    let create = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys"),
            &dev,
            &json!({ "name": "nope" }),
        ))
        .await;
    assert_eq!(create.status, 403, "{:?}", create.json);

    // Nor create a repository.
    let repo = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/repositories"),
            &dev,
            &json!({ "name": "r", "ssh_url": "git@github.com:o/r.git" }),
        ))
        .await;
    assert_eq!(repo.status, 403, "{:?}", repo.json);
}

#[tokio::test]
async fn non_member_cannot_reach_endpoints() {
    require_db!();
    let app = TestApp::spawn().await;
    let (_owner, pid) = owner_with_project(&app, "secrowner").await;
    // A stranger with no membership.
    let _ = app
        .register("stranger@example.com", "stranger", STRONG_PW)
        .await;
    let stranger = app
        .login("stranger@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let resp = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys"),
            &stranger,
        ))
        .await;
    // Private project is hidden from non-members.
    assert_eq!(resp.status, 404, "{:?}", resp.json);
}

#[tokio::test]
async fn ssh_key_cap_is_enforced() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "capcheck").await;

    // Seed up to the cap (100) directly for speed.
    let client = app.db.pool.get().await.unwrap();
    let pid_u = Uuid::parse_str(&pid).unwrap();
    let dummy: Vec<u8> = vec![0, 1, 2, 3];
    for i in 0..100 {
        client
            .execute(
                "INSERT INTO ssh_keys (project_id, name, public_key, private_key_enc, fingerprint) \
                 VALUES ($1, $2, 'ssh-ed25519 AAAA', $3, 'SHA256:x')",
                &[&pid_u, &format!("k{i}"), &dummy],
            )
            .await
            .unwrap();
    }
    let resp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys"),
            &token,
            &json!({ "name": "over-cap" }),
        ))
        .await;
    assert_eq!(resp.status, 409, "{:?}", resp.json);
    assert_eq!(resp.json["code"], "limit_reached");
}

#[tokio::test]
async fn audit_records_key_events() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "auditkey").await;
    let key_id = create_key(&app, &token, &pid, "audited", true).await;
    let _ = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/ssh-keys/{key_id}"),
            &token,
        ))
        .await;

    let client = app.db.pool.get().await.unwrap();
    let created: i64 = client
        .query_one(
            "SELECT count(*) AS n FROM audit_log WHERE action = 'ssh_key.create'",
            &[],
        )
        .await
        .unwrap()
        .get("n");
    let deleted: i64 = client
        .query_one(
            "SELECT count(*) AS n FROM audit_log WHERE action = 'ssh_key.delete'",
            &[],
        )
        .await
        .unwrap()
        .get("n");
    assert_eq!(created, 1);
    assert_eq!(deleted, 1);
}
