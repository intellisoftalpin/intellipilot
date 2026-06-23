#![cfg(test)]
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
    clippy::cast_possible_truncation
)]
//! Phase 17 acceptance: profile fields (motto + daily mood) and avatars
//! (upload / emoji / default), the avatar descriptor on user-bearing responses,
//! and the out-of-office badge.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::{TestApp, delete_bearer, get, get_with_bearer, patch_json_bearer, post_json_bearer};
use serde_json::json;
use time::OffsetDateTime;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// PNG 8-byte magic + filler; enough for `infer` to classify it as image/png.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 42,
];
/// GIF87a/89a magic + filler.
const GIF: &[u8] = b"GIF89a\x01\x00\x01\x00\x00\x00\x00";

async fn user(app: &TestApp, email: &str, username: &str) -> (String, String) {
    let _ = app.register(email, username, STRONG_PW).await;
    let token = app.login(email, STRONG_PW).await.access_token().unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    (token, me.json["id"].as_str().unwrap().to_owned())
}

fn today_iso() -> String {
    let d = OffsetDateTime::now_utc().date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// A `PUT` multipart request with one `file` field (avatar upload is PUT).
fn put_avatar(token: &str, filename: &str, content: &[u8]) -> Request<Body> {
    let boundary = "----intellipilotavatarboundary";
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Request::builder()
        .method("PUT")
        .uri("/api/v1/me/avatar")
        .header("authorization", format!("Bearer {token}"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap()
}

// ---------------------------------------------------------------------------
// profile: motto + daily mood
// ---------------------------------------------------------------------------

#[tokio::test]
async fn motto_and_mood_round_trip() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, _id) = user(&app, "p@x", "puser").await;

    let r = app
        .send(patch_json_bearer(
            "/api/v1/me",
            &token,
            &json!({ "motto": "Ship it", "mood_emoji": "🚀", "mood_text": "in the zone" }),
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["motto"], "Ship it");
    assert_eq!(r.json["mood_emoji"], "🚀");
    assert_eq!(r.json["mood_text"], "in the zone");

    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    assert_eq!(me.json["motto"], "Ship it");
    assert_eq!(me.json["mood_text"], "in the zone");
}

#[tokio::test]
async fn mood_auto_expires_after_its_day() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, id) = user(&app, "p@x", "puser").await;

    let _ = app
        .send(patch_json_bearer(
            "/api/v1/me",
            &token,
            &json!({ "mood_emoji": "😴", "mood_text": "tired" }),
        ))
        .await;

    // Backdate the mood to yesterday — the read layer should now blank it.
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE users SET mood_set_on = mood_set_on - 1 WHERE id = $1::uuid",
            &[&uuid::Uuid::parse_str(&id).unwrap()],
        )
        .await
        .unwrap();

    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    assert_eq!(me.json["mood_text"], "");
    assert_eq!(me.json["mood_emoji"], "");
}

// ---------------------------------------------------------------------------
// avatars
// ---------------------------------------------------------------------------

#[tokio::test]
async fn emoji_avatar_set_and_appears_in_descriptor() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, _id) = user(&app, "p@x", "puser").await;

    let put = app
        .send(common::req(
            "PUT",
            "/api/v1/me/avatar/emoji",
            Some(&token),
            &[],
            Some(&json!({ "emoji": "🦊" })),
        ))
        .await;
    assert_eq!(put.status, 200, "{:?}", put.json);
    assert_eq!(put.json["avatar_kind"], "emoji");
    assert_eq!(put.json["avatar_emoji"], "🦊");
}

#[tokio::test]
async fn image_avatar_upload_serve_and_delete() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, id) = user(&app, "p@x", "puser").await;

    // Upload a PNG.
    let up = app.send(put_avatar(&token, "me.png", PNG)).await;
    assert_eq!(up.status, 200, "{:?}", up.json);
    assert_eq!(up.json["avatar_kind"], "image");
    assert!(up.json["avatar_updated_at"].is_string());

    // Serve it back (bytes + content-type round-trip).
    let (status, headers, bytes) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/users/{id}/avatar"),
            &token,
        ))
        .await;
    assert_eq!(status, 200);
    assert_eq!(headers["content-type"], "image/png");
    assert_eq!(bytes, PNG);

    // Animated GIF is accepted too.
    let gif = app.send(put_avatar(&token, "me.gif", GIF)).await;
    assert_eq!(gif.status, 200, "{:?}", gif.json);

    // Non-image is rejected.
    let bad = app
        .send(put_avatar(&token, "notes.txt", b"hello world"))
        .await;
    assert_eq!(bad.status, 422);
    assert_eq!(bad.json["code"], "not_an_image");

    // Delete → back to default, image no longer served.
    let del = app.send(delete_bearer("/api/v1/me/avatar", &token)).await;
    assert_eq!(del.status, 204);
    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    assert_eq!(me.json["avatar_kind"], "default");
    let (gone, _h, _b) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/users/{id}/avatar"),
            &token,
        ))
        .await;
    assert_eq!(gone, 404);
}

#[tokio::test]
async fn serving_avatar_requires_auth() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, id) = user(&app, "p@x", "puser").await;
    let _ = app.send(put_avatar(&token, "me.png", PNG)).await;

    let anon = app.send(get(&format!("/api/v1/users/{id}/avatar"))).await;
    assert_eq!(anon.status, 401);
}

// ---------------------------------------------------------------------------
// descriptor on members + out-of-office badge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn members_carry_avatar_and_out_today() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, oid) = user(&app, "owner@x", "owneruser").await;
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &owner,
            &json!({ "name": "AV" }),
        ))
        .await;
    let pid = p.json["id"].as_str().unwrap().to_owned();

    // Owner picks an emoji avatar and books vacation for today.
    let _ = app
        .send(common::req(
            "PUT",
            "/api/v1/me/avatar/emoji",
            Some(&owner),
            &[],
            Some(&json!({ "emoji": "🐱" })),
        ))
        .await;
    let today = today_iso();
    let booked = app
        .send(post_json_bearer(
            "/api/v1/me/absences",
            &owner,
            &json!({ "kind": "vacation", "start_date": today, "end_date": today, "skip_weekends": false }),
        ))
        .await;
    assert_eq!(booked.status, 201, "{:?}", booked.json);

    let members = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &owner,
        ))
        .await;
    assert_eq!(members.status, 200);
    let me_row = members.json["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["user_id"] == json!(oid))
        .unwrap();
    assert_eq!(me_row["avatar_kind"], "emoji");
    assert_eq!(me_row["avatar_emoji"], "🐱");
    assert_eq!(me_row["out_today"]["kind"], "vacation");
    assert_eq!(me_row["out_today"]["start_date"], today);
    assert_eq!(me_row["out_today"]["end_date"], today);

    // And /me carries the same out-of-office badge.
    let me = app.send(get_with_bearer("/api/v1/me", &owner)).await;
    assert_eq!(me.json["out_today"]["kind"], "vacation");
}

#[tokio::test]
async fn comment_carries_author_descriptor() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, oid) = user(&app, "owner@x", "owneruser").await;
    // Owner picks an emoji avatar so the author descriptor is non-trivial.
    let _ = app
        .send(common::req(
            "PUT",
            "/api/v1/me/avatar/emoji",
            Some(&owner),
            &[],
            Some(&json!({ "emoji": "🐝" })),
        ))
        .await;
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &owner,
            &json!({ "name": "C" }),
        ))
        .await;
    let pid = p.json["id"].as_str().unwrap().to_owned();
    let issue = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &owner,
            &json!({ "subject": "T" }),
        ))
        .await;
    let iid = issue.json["id"].as_str().unwrap().to_owned();

    let posted = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/{iid}/comments"),
            &owner,
            &json!({ "body": "hello" }),
        ))
        .await;
    assert_eq!(posted.status, 201, "{:?}", posted.json);

    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{iid}/comments"),
            &owner,
        ))
        .await;
    assert_eq!(list.status, 200);
    let c = &list.json["comments"][0];
    assert_eq!(c["author"]["id"], json!(oid));
    assert_eq!(c["author"]["username"], "owneruser");
    assert_eq!(c["author"]["avatar_kind"], "emoji");
    assert_eq!(c["author"]["avatar_emoji"], "🐝");
}

#[tokio::test]
async fn admin_user_list_includes_avatar_fields() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, _id) = user(&app, "admin@x", "adminx").await;
    {
        let client = app.db.pool.get().await.unwrap();
        client
            .execute(
                "UPDATE users SET is_superadmin = true WHERE email = 'admin@x'",
                &[],
            )
            .await
            .unwrap();
    }
    let list = app
        .send(get_with_bearer("/api/v1/admin/users", &token))
        .await;
    assert_eq!(list.status, 200);
    let first = &list.json["items"][0];
    assert!(first["avatar_kind"].is_string());
    assert!(first.get("motto").is_some());
}
