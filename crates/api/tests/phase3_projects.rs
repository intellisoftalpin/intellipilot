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
//! Phase 3 acceptance: projects, roles, memberships, invitations.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, patch_json_bearer, post_json_bearer};
use serde_json::{Value, json};
use uuid::Uuid;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// Register + login; returns (access_token, user_id).
async fn user(app: &TestApp, email: &str, username: &str) -> (String, String) {
    let reg = app.register(email, username, STRONG_PW).await;
    let id = reg.json["id"].as_str().unwrap().to_owned();
    let token = app.login(email, STRONG_PW).await.access_token().unwrap();
    (token, id)
}

async fn create_project(app: &TestApp, token: &str, name: &str) -> Value {
    let resp = app
        .send(post_json_bearer(
            "/api/v1/projects",
            token,
            &json!({ "name": name, "visibility": "private" }),
        ))
        .await;
    assert_eq!(resp.status, 201, "create project: {:?}", resp.json);
    resp.json
}

#[tokio::test]
async fn create_project_makes_owner_admin() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, _id) = user(&app, "owner@example.com", "owner").await;
    let project = create_project(&app, &token, "Apollo").await;
    let pid = project["id"].as_str().unwrap();
    assert_eq!(project["slug"], "apollo");

    // Owner can read it and it appears in their list.
    let get = app
        .send(get_with_bearer(&format!("/api/v1/projects/{pid}"), &token))
        .await;
    assert_eq!(get.status, 200);

    let list = app.send(get_with_bearer("/api/v1/projects", &token)).await;
    assert_eq!(list.json["projects"].as_array().unwrap().len(), 1);

    // Four default roles seeded.
    let roles = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/roles"),
            &token,
        ))
        .await;
    assert_eq!(roles.status, 200);
    assert_eq!(roles.json["roles"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn private_project_is_404_for_non_members() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _) = user(&app, "a@example.com", "usera").await;
    let project = create_project(&app, &owner, "Secret").await;
    let pid = project["id"].as_str().unwrap();

    let (outsider, _) = user(&app, "b@example.com", "userb").await;
    let resp = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}"),
            &outsider,
        ))
        .await;
    assert_eq!(
        resp.status, 404,
        "private project must be hidden (404, not 403)"
    );
}

#[tokio::test]
async fn invite_and_accept_then_member_can_access() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _) = user(&app, "inv-o@example.com", "invo").await;
    let project = create_project(&app, &owner, "Gemini").await;
    let pid = project["id"].as_str().unwrap();

    // Invite as developer.
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            &owner,
            &json!({ "email": "inv-b@example.com", "role": "dev" }),
        ))
        .await;
    assert_eq!(invite.status, 201, "invite: {:?}", invite.json);
    let token = invite.json["invite_token"].as_str().unwrap().to_owned();

    // Invitee joins.
    let (member, _) = user(&app, "inv-b@example.com", "invb").await;
    let accept = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &member,
            &json!({ "token": token }),
        ))
        .await;
    assert_eq!(accept.status, 200, "accept: {:?}", accept.json);

    // Now they can read the project.
    let get = app
        .send(get_with_bearer(&format!("/api/v1/projects/{pid}"), &member))
        .await;
    assert_eq!(get.status, 200);

    // Re-accepting the consumed token → 410 Gone.
    let again = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &member,
            &json!({ "token": token }),
        ))
        .await;
    assert_eq!(again.status, 410);
}

#[tokio::test]
async fn removing_member_blocks_access() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _) = user(&app, "rm-o@example.com", "rmo").await;
    let project = create_project(&app, &owner, "Mercury").await;
    let pid = project["id"].as_str().unwrap();

    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            &owner,
            &json!({ "email": "rm-b@example.com", "role": "dev" }),
        ))
        .await;
    let token = invite.json["invite_token"].as_str().unwrap().to_owned();
    let (member, member_id) = user(&app, "rm-b@example.com", "rmb").await;
    let _ = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &member,
            &json!({ "token": token }),
        ))
        .await;
    assert_eq!(
        app.send(get_with_bearer(&format!("/api/v1/projects/{pid}"), &member))
            .await
            .status,
        200
    );

    // Owner removes the member.
    let rm = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/members/{member_id}"),
            &owner,
        ))
        .await;
    assert_eq!(rm.status, 204);

    // Next request from the removed member is blocked (404 — private project).
    let after = app
        .send(get_with_bearer(&format!("/api/v1/projects/{pid}"), &member))
        .await;
    assert_eq!(after.status, 404);
}

#[tokio::test]
async fn developer_lacks_admin_permissions() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _) = user(&app, "perm-o@example.com", "permo").await;
    let project = create_project(&app, &owner, "Saturn").await;
    let pid = project["id"].as_str().unwrap();
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            &owner,
            &json!({ "email": "perm-b@example.com", "role": "dev" }),
        ))
        .await;
    let token = invite.json["invite_token"].as_str().unwrap().to_owned();
    let (dev, _) = user(&app, "perm-b@example.com", "permb").await;
    let _ = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &dev,
            &json!({ "token": token }),
        ))
        .await;

    // Dev cannot delete the project (no project.delete).
    let del = app
        .send(delete_bearer(&format!("/api/v1/projects/{pid}"), &dev))
        .await;
    assert_eq!(del.status, 403);

    // Dev cannot modify the project (no project.modify).
    let patch = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}"),
            &dev,
            &json!({ "name": "Hijacked" }),
        ))
        .await;
    assert_eq!(patch.status, 403);

    // Dev cannot invite (no member.add).
    let inv = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            &dev,
            &json!({ "email": "x@example.com", "role": "dev" }),
        ))
        .await;
    assert_eq!(inv.status, 403);
}

#[tokio::test]
async fn idor_cannot_read_others_projects() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _) = user(&app, "idor-o@example.com", "idoro").await;
    let project = create_project(&app, &owner, "Vault").await;
    let pid = project["id"].as_str().unwrap();

    let (attacker, _) = user(&app, "idor-x@example.com", "idorx").await;
    // The real project id → 404 (hidden).
    assert_eq!(
        app.send(get_with_bearer(
            &format!("/api/v1/projects/{pid}"),
            &attacker
        ))
        .await
        .status,
        404
    );
    // Random guesses → all 404.
    for _ in 0..50 {
        let guess = Uuid::now_v7();
        let resp = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/{guess}"),
                &attacker,
            ))
            .await;
        assert_eq!(resp.status, 404);
    }
}

#[tokio::test]
async fn cannot_remove_last_admin() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, owner_id) = user(&app, "last@example.com", "lastadmin").await;
    let project = create_project(&app, &owner, "Solo").await;
    let pid = project["id"].as_str().unwrap();

    // Owner is the only admin; removing self must be refused.
    let rm = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/members/{owner_id}"),
            &owner,
        ))
        .await;
    assert_eq!(rm.status, 409, "last admin must be protected");
}

#[tokio::test]
async fn audit_records_membership_grant() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _) = user(&app, "aud-o@example.com", "audo").await;
    let project = create_project(&app, &owner, "Audit").await;
    let pid = project["id"].as_str().unwrap();
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            &owner,
            &json!({ "email": "aud-b@example.com", "role": "dev" }),
        ))
        .await;
    let token = invite.json["invite_token"].as_str().unwrap().to_owned();
    let (member, _) = user(&app, "aud-b@example.com", "audb").await;
    let _ = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &member,
            &json!({ "token": token }),
        ))
        .await;

    let client = app.db.pool.get().await.unwrap();
    let granted: i64 = client
        .query_one(
            "SELECT count(*) AS n FROM audit_log WHERE action = 'membership_granted'",
            &[],
        )
        .await
        .unwrap()
        .get("n");
    let invited: i64 = client
        .query_one(
            "SELECT count(*) AS n FROM audit_log WHERE action = 'member_invited'",
            &[],
        )
        .await
        .unwrap()
        .get("n");
    assert_eq!(granted, 1);
    assert_eq!(invited, 1);
}

#[tokio::test]
async fn add_existing_user_directly() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid) = user(&app, "owner@example.com", "owner").await;
    let (_t2, uid2) = user(&app, "bob@example.com", "bob").await;
    let project = create_project(&app, &owner, "Apollo").await;
    let pid = project["id"].as_str().unwrap();

    // Add bob by exact email identifier, as the dev role.
    let add = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &owner,
            &json!({ "identifier": "bob@example.com", "role": "dev" }),
        ))
        .await;
    assert_eq!(add.status, 201, "{:?}", add.json);

    // Membership list now has owner + bob.
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &owner,
        ))
        .await;
    assert_eq!(list.json["members"].as_array().unwrap().len(), 2);

    // Adding the same user again (by id this time) → 409.
    let dup = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &owner,
            &json!({ "user_id": uid2, "role": "dev" }),
        ))
        .await;
    assert_eq!(dup.status, 409, "{:?}", dup.json);
    assert_eq!(dup.json["code"], "conflict");

    // Unknown identifier → 404.
    let nope = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &owner,
            &json!({ "identifier": "ghost@example.com", "role": "dev" }),
        ))
        .await;
    assert_eq!(nope.status, 404, "{:?}", nope.json);

    // Unknown role → 422.
    let bad_role = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &owner,
            &json!({ "identifier": "bob@example.com", "role": "nope" }),
        ))
        .await;
    assert_eq!(bad_role.status, 422, "{:?}", bad_role.json);
}
