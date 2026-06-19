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
//! Phase 7 acceptance: attachments (upload, MIME, sanitization, download, GC).

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, multipart_upload, post_json_bearer, req};
use serde_json::json;
use time::{Duration, OffsetDateTime};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// A minimal valid PNG signature + IHDR-ish bytes (enough for `infer`).
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
];

async fn project_with_issue(app: &TestApp) -> (String, String, String) {
    let _ = app.register("att@example.com", "attuser", STRONG_PW).await;
    let token = app
        .login("att@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "AT" }),
        ))
        .await;
    let pid = p.json["id"].as_str().unwrap().to_owned();
    let issue = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "I" }),
        ))
        .await;
    let iid = issue.json["id"].as_str().unwrap().to_owned();
    (token, pid, iid)
}

#[tokio::test]
async fn upload_list_sign_download_round_trip() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, iid) = project_with_issue(&app).await;
    let base = format!("/api/v1/projects/{pid}/issues/{iid}/attachments");

    let up = app
        .send(multipart_upload(&base, &token, "pic.png", PNG))
        .await;
    assert_eq!(up.status, 201, "{:?}", up.json);
    assert_eq!(up.json["filename"], "pic.png");
    assert_eq!(
        up.json["content_type"], "image/png",
        "MIME re-derived from bytes"
    );
    let att_id = up.json["id"].as_str().unwrap().to_owned();

    let list = app.send(get_with_bearer(&base, &token)).await;
    assert_eq!(list.json["attachments"].as_array().unwrap().len(), 1);

    // Signed URL.
    let signed = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/attachments/{att_id}"),
            &token,
        ))
        .await;
    assert_eq!(signed.status, 200);
    let url = signed.json["url"].as_str().unwrap().to_owned();

    // Download via the signed URL, with auth.
    let (status, headers, body) = app
        .download_bytes(req("GET", &url, Some(&token), &[], None))
        .await;
    assert_eq!(status, 200);
    assert_eq!(body, PNG, "bytes round-trip");
    assert_eq!(
        headers.get("x-content-type-options").map(String::as_str),
        Some("nosniff")
    );
    assert!(
        headers
            .get("content-disposition")
            .unwrap()
            .starts_with("attachment")
    );
    assert!(
        headers
            .get("content-security-policy")
            .unwrap()
            .contains("default-src 'none'")
    );
}

#[tokio::test]
async fn mime_extension_mismatch_is_422() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, iid) = project_with_issue(&app).await;
    let base = format!("/api/v1/projects/{pid}/issues/{iid}/attachments");
    // PNG bytes but an .exe extension → mismatch.
    let up = app
        .send(multipart_upload(&base, &token, "evil.exe", PNG))
        .await;
    assert_eq!(up.status, 422, "{:?}", up.json);
    assert_eq!(up.json["code"], "mime_mismatch");
}

#[tokio::test]
async fn plain_text_stored_as_octet_stream() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, iid) = project_with_issue(&app).await;
    let base = format!("/api/v1/projects/{pid}/issues/{iid}/attachments");
    let up = app
        .send(multipart_upload(
            &base,
            &token,
            "notes.txt",
            b"just some text",
        ))
        .await;
    assert_eq!(up.status, 201, "{:?}", up.json);
    assert_eq!(up.json["content_type"], "application/octet-stream");
}

#[tokio::test]
async fn filename_is_sanitized() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, iid) = project_with_issue(&app).await;
    let base = format!("/api/v1/projects/{pid}/issues/{iid}/attachments");
    let up = app
        .send(multipart_upload(&base, &token, "../../../etc/passwd", PNG))
        .await;
    assert_eq!(up.status, 201, "{:?}", up.json);
    assert_eq!(up.json["filename"], "passwd", "path stripped");
}

#[tokio::test]
async fn oversize_upload_rejected() {
    require_db!();
    // Tiny limit so the test payload is small.
    let app = TestApp::spawn_with_attachment_limit(8).await;
    let (token, pid, iid) = project_with_issue(&app).await;
    let base = format!("/api/v1/projects/{pid}/issues/{iid}/attachments");
    let up = app
        .send(multipart_upload(&base, &token, "big.png", &[0u8; 64]))
        .await;
    assert_eq!(up.status, 413, "{:?}", up.json);
}

#[tokio::test]
async fn download_rejects_tampered_signature() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, iid) = project_with_issue(&app).await;
    let base = format!("/api/v1/projects/{pid}/issues/{iid}/attachments");
    let up = app
        .send(multipart_upload(&base, &token, "pic.png", PNG))
        .await;
    let att_id = up.json["id"].as_str().unwrap().to_owned();

    // Forge a URL with a bad signature.
    let exp = (OffsetDateTime::now_utc() + Duration::minutes(10)).unix_timestamp();
    let forged =
        format!("/api/v1/projects/{pid}/attachments/{att_id}/download?exp={exp}&sig=deadbeef");
    let (status, _h, _b) = app
        .download_bytes(req("GET", &forged, Some(&token), &[], None))
        .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn identical_uploads_share_storage() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, iid) = project_with_issue(&app).await;
    let base = format!("/api/v1/projects/{pid}/issues/{iid}/attachments");

    // Two uploads of the same bytes.
    let a = app
        .send(multipart_upload(&base, &token, "one.png", PNG))
        .await;
    let b = app
        .send(multipart_upload(&base, &token, "two.png", PNG))
        .await;
    assert_eq!(a.status, 201);
    assert_eq!(b.status, 201);
    // Content-addressed: identical content → identical SHA-256.
    assert_eq!(
        a.json["sha256"], b.json["sha256"],
        "same content, same hash"
    );
    let a_id = a.json["id"].as_str().unwrap().to_owned();
    let b_id = b.json["id"].as_str().unwrap().to_owned();

    let client = app.db.pool.get().await.unwrap();

    // Delete the first; GC must NOT purge the shared object (still referenced
    // by the second) — proving content-addressed dedup + reference counting.
    let _ = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/attachments/{a_id}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    let purged = intellipilot_api::attachments::run_gc(
        &client,
        app.storage.as_ref(),
        OffsetDateTime::now_utc() + Duration::days(1),
    )
    .await;
    assert_eq!(purged, 0, "shared object survives while still referenced");

    // The second is still downloadable.
    let signed = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/attachments/{b_id}"),
            &token,
        ))
        .await;
    let url = signed.json["url"].as_str().unwrap().to_owned();
    let (status, _h, body) = app
        .download_bytes(req("GET", &url, Some(&token), &[], None))
        .await;
    assert_eq!(status, 200);
    assert_eq!(body, PNG);

    // Delete the last reference; now GC purges the object.
    let _ = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/attachments/{b_id}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    let purged2 = intellipilot_api::attachments::run_gc(
        &client,
        app.storage.as_ref(),
        OffsetDateTime::now_utc() + Duration::days(2),
    )
    .await;
    assert_eq!(purged2, 1, "object purged once unreferenced");
}

#[tokio::test]
async fn delete_then_gc_purges_object() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, iid) = project_with_issue(&app).await;
    let base = format!("/api/v1/projects/{pid}/issues/{iid}/attachments");
    let up = app
        .send(multipart_upload(&base, &token, "pic.png", PNG))
        .await;
    let att_id = up.json["id"].as_str().unwrap().to_owned();

    // Soft-delete.
    let del = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/attachments/{att_id}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    assert_eq!(del.status, 204);
    let list = app.send(get_with_bearer(&base, &token)).await;
    assert_eq!(
        list.json["attachments"].as_array().unwrap().len(),
        0,
        "hidden after delete"
    );

    let client = app.db.pool.get().await.unwrap();

    // GC with a past cutoff purges nothing (row was just deleted).
    let purged_past = intellipilot_api::attachments::run_gc(
        &client,
        app.storage.as_ref(),
        OffsetDateTime::now_utc() - Duration::days(1),
    )
    .await;
    assert_eq!(purged_past, 0, "recent deletions survive an old cutoff");

    // GC with a future cutoff purges the object + row.
    let purged = intellipilot_api::attachments::run_gc(
        &client,
        app.storage.as_ref(),
        OffsetDateTime::now_utc() + Duration::days(1),
    )
    .await;
    assert_eq!(purged, 1, "object purged");

    // Second sweep finds nothing (row hard-deleted).
    let again = intellipilot_api::attachments::run_gc(
        &client,
        app.storage.as_ref(),
        OffsetDateTime::now_utc() + Duration::days(2),
    )
    .await;
    assert_eq!(again, 0);
}

#[tokio::test]
async fn comment_attachments_upload_and_cleanup() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, iid) = project_with_issue(&app).await;

    // Create a comment on the issue, then attach a file to that comment.
    let c = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/{iid}/comments"),
            &token,
            &json!({ "body": "see attached" }),
        ))
        .await;
    assert_eq!(c.status, 201, "{:?}", c.json);
    let cmt = c.json["id"].as_str().unwrap().to_owned();
    let base = format!("/api/v1/projects/{pid}/comments/{cmt}/attachments");

    let up = app
        .send(multipart_upload(&base, &token, "note.png", PNG))
        .await;
    assert_eq!(up.status, 201, "{:?}", up.json);

    let list = app.send(get_with_bearer(&base, &token)).await;
    assert_eq!(list.json["attachments"].as_array().unwrap().len(), 1);

    // Deleting the comment soft-deletes its attachments.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/issues/{iid}/comments/{cmt}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
    let after = app.send(get_with_bearer(&base, &token)).await;
    assert_eq!(after.json["attachments"].as_array().unwrap().len(), 0);
}
