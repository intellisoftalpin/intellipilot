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
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
//! V028 acceptance: project meetings — CRUD, calendar range, permissions
//! (stakeholders see nothing), links in both directions, streamed file
//! uploads, byte-range downloads, transcript import, search, GC and events.

mod common;

use common::{
    MEDIA_MAX_BYTES_FOR_TESTS, TestApp, delete_bearer, get_with_bearer, multipart_upload,
    post_bearer, post_json_bearer, req,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// An ISO-BMFF header `infer` recognizes as `video/mp4`, padded to `len`.
fn mp4(len: usize) -> Vec<u8> {
    let mut v = vec![
        0x00, 0x00, 0x00, 0x18, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm', 0x00, 0x00, 0x02,
        0x00, b'i', b's', b'o', b'm', b'm', b'p', b'4', b'1',
    ];
    v.extend((0..len.saturating_sub(v.len())).map(|i| (i % 251) as u8));
    v
}

const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
];

struct Fixture {
    app: TestApp,
    owner: String,
    owner_id: String,
    pid: String,
}

async fn fixture() -> Fixture {
    let app = TestApp::spawn().await;
    let _ = app.register("mt@example.com", "mtowner", STRONG_PW).await;
    let owner = app
        .login("mt@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let owner_id = app.send(get_with_bearer("/api/v1/me", &owner)).await.json["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &owner,
            &json!({ "name": "Meetings" }),
        ))
        .await;
    let pid = p.json["id"].as_str().unwrap().to_owned();
    Fixture {
        app,
        owner,
        owner_id,
        pid,
    }
}

impl Fixture {
    fn url(&self, rest: &str) -> String {
        format!("/api/v1/projects/{}{rest}", self.pid)
    }

    async fn create(&self, body: &Value) -> common::TestResponse {
        self.app
            .send(post_json_bearer(&self.url("/meetings"), &self.owner, body))
            .await
    }

    /// Register a user and add them to the project with `role`.
    async fn member(&self, email: &str, username: &str, role: &str) -> (String, String) {
        let _ = self.app.register(email, username, STRONG_PW).await;
        let token = self
            .app
            .login(email, STRONG_PW)
            .await
            .access_token()
            .unwrap();
        let id = self
            .app
            .send(get_with_bearer("/api/v1/me", &token))
            .await
            .json["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let add = self
            .app
            .send(post_json_bearer(
                &self.url("/members"),
                &self.owner,
                &json!({ "user_id": id, "role": role }),
            ))
            .await;
        assert_eq!(add.status, 201, "{:?}", add.json);
        (token, id)
    }

    async fn patch(&self, id: &str, etag: Option<&str>, body: &Value) -> common::TestResponse {
        let headers: Vec<(&str, &str)> = etag.map(|e| vec![("if-match", e)]).unwrap_or_default();
        self.app
            .send(req(
                "PATCH",
                &self.url(&format!("/meetings/{id}")),
                Some(&self.owner),
                &headers,
                Some(body),
            ))
            .await
    }
}

#[tokio::test]
async fn create_edit_list_and_delete() {
    require_db!();
    let f = fixture().await;

    // Only title + date are required; times and zone are optional.
    let bare = f
        .create(&json!({ "title": "Kick-off", "meeting_date": "2026-09-22" }))
        .await;
    assert_eq!(bare.status, 201, "{:?}", bare.json);
    assert_eq!(bare.json["timezone"], "UTC");
    assert_eq!(bare.json["start_time"], Value::Null);
    assert_eq!(bare.json["artifacts"], json!([]));

    let timed = f
        .create(&json!({
            "title": "Planning", "meeting_date": "2026-09-22",
            "start_time": "09:30", "end_time": "10:15:00", "timezone": "Europe/Zurich",
            "location": "https://meet.example/abc", "summary": "We agreed."
        }))
        .await;
    assert_eq!(timed.status, 201, "{:?}", timed.json);
    assert_eq!(timed.json["start_time"], "09:30");
    assert_eq!(timed.json["end_time"], "10:15", "seconds are dropped");
    let id = timed.json["id"].as_str().unwrap().to_owned();
    let etag = timed.header("etag").unwrap().to_owned();

    let _ = f
        .create(&json!({ "title": "Retro", "meeting_date": "2026-10-01" }))
        .await;

    // Validation.
    for (body, code) in [
        (
            json!({ "title": "x", "meeting_date": "2026-09-22", "end_time": "10:00" }),
            "invalid_times",
        ),
        (
            json!({ "title": "x", "meeting_date": "2026-09-22", "start_time": "10:00", "end_time": "09:00" }),
            "invalid_times",
        ),
        (
            json!({ "title": "x", "meeting_date": "2026-09-22", "timezone": "Mars/Olympus" }),
            "invalid_timezone",
        ),
        (
            json!({ "title": "   ", "meeting_date": "2026-09-22" }),
            "validation_failed",
        ),
    ] {
        let r = f.create(&body).await;
        assert_eq!(r.status, 422, "{body}: {:?}", r.json);
        assert_eq!(r.json["code"], code, "{body}");
    }
    let missing_date = f.create(&json!({ "title": "x" })).await;
    assert_eq!(missing_date.status, 400);

    // Calendar range: September only, with a per-day count.
    let sept = f
        .app
        .send(get_with_bearer(
            &f.url("/meetings?from=2026-09-01&to=2026-09-30"),
            &f.owner,
        ))
        .await;
    assert_eq!(sept.status, 200, "{:?}", sept.json);
    let items = sept.json["meetings"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["title"], "Kick-off", "untimed meetings sort first");
    assert_eq!(items[1]["has_summary"], true);
    assert!(
        items[1].get("transcript").is_none(),
        "list rows carry no long text"
    );
    assert_eq!(
        sept.json["days"],
        json!([{ "date": "2026-09-22", "count": 2 }])
    );
    let bad_range = f
        .app
        .send(get_with_bearer(
            &f.url("/meetings?from=2026-01-01&to=2027-12-31"),
            &f.owner,
        ))
        .await;
    assert_eq!(bad_range.status, 422);

    // PATCH needs If-Match, rejects a stale one, and validates merged times.
    let no_match = f.patch(&id, None, &json!({ "title": "P2" })).await;
    assert_eq!(no_match.status, 428);
    let ok = f
        .patch(
            &id,
            Some(&etag),
            &json!({ "title": "Planning 2", "transcript": "Alice: hi" }),
        )
        .await;
    assert_eq!(ok.status, 200, "{:?}", ok.json);
    assert_eq!(ok.json["title"], "Planning 2");
    assert_eq!(ok.json["transcript"], "Alice: hi");
    let stale = f.patch(&id, Some(&etag), &json!({ "title": "P3" })).await;
    assert_eq!(stale.status, 412);
    let etag = ok.header("etag").unwrap().to_owned();
    let bad_merge = f
        .patch(&id, Some(&etag), &json!({ "start_time": null }))
        .await;
    assert_eq!(bad_merge.status, 422, "end without start");
    let cleared = f
        .patch(
            &id,
            Some(&etag),
            &json!({ "start_time": null, "end_time": null, "meeting_date": "2026-09-23" }),
        )
        .await;
    assert_eq!(cleared.status, 200, "{:?}", cleared.json);
    assert_eq!(cleared.json["end_time"], Value::Null);
    assert_eq!(cleared.json["meeting_date"], "2026-09-23");

    // Delete: gone from detail and calendar.
    let del = f
        .app
        .send(delete_bearer(&f.url(&format!("/meetings/{id}")), &f.owner))
        .await;
    assert_eq!(del.status, 204);
    let gone = f
        .app
        .send(get_with_bearer(
            &f.url(&format!("/meetings/{id}")),
            &f.owner,
        ))
        .await;
    assert_eq!(gone.status, 404);
    let sept = f
        .app
        .send(get_with_bearer(
            &f.url("/meetings?from=2026-09-01&to=2026-09-30"),
            &f.owner,
        ))
        .await;
    assert_eq!(sept.json["meetings"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn stakeholders_see_no_meetings_developers_edit_but_do_not_delete() {
    require_db!();
    let f = fixture().await;
    let m = f
        .create(&json!({ "title": "Internal", "meeting_date": "2026-09-22" }))
        .await;
    let id = m.json["id"].as_str().unwrap().to_owned();
    let up = f
        .app
        .send(multipart_upload(
            &f.url(&format!("/meetings/{id}/artifacts?kind=other")),
            &f.owner,
            "slide.png",
            PNG,
        ))
        .await;
    assert_eq!(up.status, 201, "{:?}", up.json);
    let att = up.json["id"].as_str().unwrap().to_owned();

    let (stake, _) = f.member("sh@example.com", "shuser", "stakeholder").await;
    for uri in [
        f.url("/meetings?from=2026-09-01&to=2026-09-30"),
        f.url(&format!("/meetings/{id}")),
        f.url(&format!("/meetings/{id}/artifacts")),
        // Nor can a stakeholder mint a download URL for a meeting file.
        f.url(&format!("/attachments/{att}")),
    ] {
        let r = f.app.send(get_with_bearer(&uri, &stake)).await;
        assert_eq!(r.status, 403, "{uri}: {:?}", r.json);
    }
    let r = f
        .app
        .send(post_json_bearer(
            &f.url("/meetings"),
            &stake,
            &json!({ "title": "x", "meeting_date": "2026-09-22" }),
        ))
        .await;
    assert_eq!(r.status, 403);
    // The generic attachment delete is gated by meeting.modify for these.
    let r = f
        .app
        .send(delete_bearer(
            &f.url(&format!("/attachments/{att}")),
            &stake,
        ))
        .await;
    assert_eq!(r.status, 403);

    let (dev, _) = f.member("dev@example.com", "devuser", "dev").await;
    let r = f
        .app
        .send(get_with_bearer(&f.url(&format!("/meetings/{id}")), &dev))
        .await;
    assert_eq!(r.status, 200);
    let r = f
        .app
        .send(post_json_bearer(
            &f.url("/meetings"),
            &dev,
            &json!({ "title": "Dev sync", "meeting_date": "2026-09-22" }),
        ))
        .await;
    assert_eq!(r.status, 201);
    let r = f
        .app
        .send(delete_bearer(&f.url(&format!("/meetings/{id}")), &dev))
        .await;
    assert_eq!(r.status, 403, "only a product owner deletes meetings");
}

#[tokio::test]
async fn links_are_validated_and_visible_from_both_sides() {
    require_db!();
    let f = fixture().await;
    let issue = f
        .app
        .send(post_json_bearer(
            &f.url("/issues"),
            &f.owner,
            &json!({ "subject": "Bug" }),
        ))
        .await;
    let iid = issue.json["id"].as_str().unwrap().to_owned();
    let epic = f
        .app
        .send(post_json_bearer(
            &f.url("/epics"),
            &f.owner,
            &json!({ "subject": "Epic" }),
        ))
        .await;
    assert_eq!(epic.status, 201, "{:?}", epic.json);
    let eid = epic.json["id"].as_str().unwrap().to_owned();
    let cust = f
        .app
        .send(post_json_bearer(
            &f.url("/customers"),
            &f.owner,
            &json!({ "name": "ACME" }),
        ))
        .await;
    assert_eq!(cust.status, 201, "{:?}", cust.json);
    let cid = cust.json["id"].as_str().unwrap().to_owned();

    let m = f
        .create(&json!({
            "title": "Review", "meeting_date": "2026-09-22",
            "participant_ids": [f.owner_id], "issue_ids": [iid], "customer_ids": [cid]
        }))
        .await;
    assert_eq!(m.status, 201, "{:?}", m.json);
    let id = m.json["id"].as_str().unwrap().to_owned();
    assert_eq!(m.json["participant_ids"], json!([f.owner_id]));
    assert_eq!(m.json["issue_ids"], json!([iid]));
    assert_eq!(m.json["customer_ids"], json!([cid]));

    // Add an epic link; it shows on the meeting and from the epic.
    let add = f
        .app
        .send(post_bearer(
            &f.url(&format!("/meetings/{id}/links/epics/{eid}")),
            &f.owner,
        ))
        .await;
    assert_eq!(add.status, 200, "{:?}", add.json);
    assert_eq!(add.json["epic_ids"], json!([eid]));
    for (uri, n) in [
        (f.url(&format!("/issues/{iid}/meetings")), 1),
        (f.url(&format!("/epics/{eid}/meetings")), 1),
    ] {
        let r = f.app.send(get_with_bearer(&uri, &f.owner)).await;
        assert_eq!(r.status, 200, "{uri}");
        assert_eq!(r.json["meetings"].as_array().unwrap().len(), n, "{uri}");
        assert_eq!(r.json["meetings"][0]["id"], id.as_str());
    }

    // Unlink the issue.
    let rm = f
        .app
        .send(delete_bearer(
            &f.url(&format!("/meetings/{id}/links/issues/{iid}")),
            &f.owner,
        ))
        .await;
    assert_eq!(rm.status, 200);
    assert_eq!(rm.json["issue_ids"], json!([]));
    let r = f
        .app
        .send(get_with_bearer(
            &f.url(&format!("/issues/{iid}/meetings")),
            &f.owner,
        ))
        .await;
    assert_eq!(r.json["meetings"], json!([]));

    // Targets outside the project, and non-members, are refused.
    let _ = f
        .app
        .register("out@example.com", "outsider", STRONG_PW)
        .await;
    let out_token = f
        .app
        .login("out@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let out_id = f
        .app
        .send(get_with_bearer("/api/v1/me", &out_token))
        .await
        .json["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let bad = f
        .app
        .send(post_bearer(
            &f.url(&format!("/meetings/{id}/links/participants/{out_id}")),
            &f.owner,
        ))
        .await;
    assert_eq!(bad.status, 422, "{:?}", bad.json);
    assert_eq!(bad.json["code"], "invalid_link");
    let other = f
        .app
        .send(post_json_bearer(
            "/api/v1/projects",
            &f.owner,
            &json!({ "name": "Other" }),
        ))
        .await;
    let other_pid = other.json["id"].as_str().unwrap();
    let foreign = f
        .app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{other_pid}/issues"),
            &f.owner,
            &json!({ "subject": "Elsewhere" }),
        ))
        .await;
    let fid = foreign.json["id"].as_str().unwrap();
    let bad = f
        .create(&json!({ "title": "x", "meeting_date": "2026-09-22", "issue_ids": [fid] }))
        .await;
    assert_eq!(bad.status, 422);
    let bad_kind = f
        .app
        .send(post_bearer(
            &f.url(&format!("/meetings/{id}/links/wikis/{iid}")),
            &f.owner,
        ))
        .await;
    assert_eq!(bad_kind.status, 404);
}

#[tokio::test]
async fn recordings_stream_in_and_download_by_range() {
    require_db!();
    let f = fixture().await;
    let m = f
        .create(&json!({ "title": "Recorded", "meeting_date": "2026-09-22" }))
        .await;
    let id = m.json["id"].as_str().unwrap().to_owned();
    let files = f.url(&format!("/meetings/{id}/artifacts"));

    // 3 MiB: many multipart chunks, so it exercises the streamed path.
    let video = mp4(3 * 1024 * 1024);
    let up = f
        .app
        .send(multipart_upload(
            &format!("{files}?kind=recording"),
            &f.owner,
            "standup.mp4",
            &video,
        ))
        .await;
    assert_eq!(up.status, 201, "{:?}", up.json);
    assert_eq!(up.json["kind"], "recording");
    assert_eq!(up.json["content_type"], "video/mp4");
    assert_eq!(up.json["size_bytes"], video.len());
    let rec = up.json["id"].as_str().unwrap().to_owned();

    // Over the meeting media limit → 413, and nothing is left spooled.
    let huge = mp4(usize::try_from(MEDIA_MAX_BYTES_FOR_TESTS).unwrap() + 1024);
    let too_big = f
        .app
        .send(multipart_upload(
            &format!("{files}?kind=recording"),
            &f.owner,
            "long.mp4",
            &huge,
        ))
        .await;
    assert_eq!(too_big.status, 413, "{:?}", too_big.json);
    let mut spooled = tokio::fs::read_dir(f.app.storage.staging_dir())
        .await
        .unwrap();
    assert!(
        spooled.next_entry().await.unwrap().is_none(),
        "a rejected upload leaves no spool file behind"
    );

    // A recording must actually be audio/video.
    let not_media = f
        .app
        .send(multipart_upload(
            &format!("{files}?kind=recording"),
            &f.owner,
            "shot.png",
            PNG,
        ))
        .await;
    assert_eq!(not_media.status, 422);
    assert_eq!(not_media.json["code"], "not_media");
    let bad_kind = f
        .app
        .send(multipart_upload(
            &format!("{files}?kind=movie"),
            &f.owner,
            "shot.png",
            PNG,
        ))
        .await;
    assert_eq!(bad_kind.status, 422);

    let other = f
        .app
        .send(multipart_upload(&files, &f.owner, "slide.png", PNG))
        .await;
    assert_eq!(other.status, 201);
    assert_eq!(other.json["kind"], "other", "kind defaults to other");
    let png_id = other.json["id"].as_str().unwrap().to_owned();

    let listed = f.app.send(get_with_bearer(&files, &f.owner)).await;
    assert_eq!(listed.json["artifacts"].as_array().unwrap().len(), 2);
    let cal = f
        .app
        .send(get_with_bearer(
            &f.url("/meetings?from=2026-09-22&to=2026-09-22"),
            &f.owner,
        ))
        .await;
    assert_eq!(cal.json["meetings"][0]["recording_count"], 1);
    assert_eq!(cal.json["meetings"][0]["file_count"], 2);

    // Signed media URLs live for hours, not minutes.
    let signed = f
        .app
        .send(get_with_bearer(
            &f.url(&format!("/attachments/{rec}")),
            &f.owner,
        ))
        .await;
    assert_eq!(signed.status, 200);
    let ttl =
        signed.json["expires_at"].as_i64().unwrap() - OffsetDateTime::now_utc().unix_timestamp();
    assert!(ttl > 5 * 3600, "media TTL {ttl}s");
    let url = signed.json["url"].as_str().unwrap().to_owned();

    // Whole file.
    let (status, headers, body) = f
        .app
        .download_bytes(req("GET", &url, None, &[], None))
        .await;
    assert_eq!(status, 200);
    assert_eq!(body, video);
    assert_eq!(headers["accept-ranges"], "bytes");
    assert_eq!(headers["content-length"], video.len().to_string());
    assert!(
        headers["content-disposition"].starts_with("inline"),
        "media plays inline"
    );

    // First 100 bytes.
    let (status, headers, body) = f
        .app
        .download_bytes(req("GET", &url, None, &[("range", "bytes=0-99")], None))
        .await;
    assert_eq!(status, 206);
    assert_eq!(body, video[..100]);
    assert_eq!(
        headers["content-range"],
        format!("bytes 0-99/{}", video.len())
    );
    assert_eq!(headers["content-length"], "100");

    // A slice from the middle and a suffix.
    let (status, _, body) = f
        .app
        .download_bytes(req(
            "GET",
            &url,
            None,
            &[("range", "bytes=1000000-1000009")],
            None,
        ))
        .await;
    assert_eq!(status, 206);
    assert_eq!(body, video[1_000_000..1_000_010]);
    let (status, _, body) = f
        .app
        .download_bytes(req("GET", &url, None, &[("range", "bytes=-10")], None))
        .await;
    assert_eq!(status, 206);
    assert_eq!(body, video[video.len() - 10..]);

    // Past the end → 416 with the size.
    let (status, headers, _) = f
        .app
        .download_bytes(req(
            "GET",
            &url,
            None,
            &[("range", &format!("bytes={}-", video.len()))],
            None,
        ))
        .await;
    assert_eq!(status, 416);
    assert_eq!(headers["content-range"], format!("bytes */{}", video.len()));

    // Non-media stays a download.
    let signed = f
        .app
        .send(get_with_bearer(
            &f.url(&format!("/attachments/{png_id}")),
            &f.owner,
        ))
        .await;
    let (status, headers, _) = f
        .app
        .download_bytes(req(
            "GET",
            signed.json["url"].as_str().unwrap(),
            None,
            &[],
            None,
        ))
        .await;
    assert_eq!(status, 200);
    assert!(headers["content-disposition"].starts_with("attachment"));

    // Removing a file through the meeting endpoint; a file of another meeting
    // cannot be removed through this one.
    let m2 = f
        .create(&json!({ "title": "Other", "meeting_date": "2026-09-22" }))
        .await;
    let id2 = m2.json["id"].as_str().unwrap();
    let wrong = f
        .app
        .send(delete_bearer(
            &f.url(&format!("/meetings/{id2}/artifacts/{png_id}")),
            &f.owner,
        ))
        .await;
    assert_eq!(wrong.status, 404);
    let del = f
        .app
        .send(delete_bearer(
            &f.url(&format!("/meetings/{id}/artifacts/{png_id}")),
            &f.owner,
        ))
        .await;
    assert_eq!(del.status, 204);
    let listed = f.app.send(get_with_bearer(&files, &f.owner)).await;
    assert_eq!(listed.json["artifacts"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn ordinary_attachments_still_stream_and_support_ranges() {
    require_db!();
    let f = fixture().await;
    let issue = f
        .app
        .send(post_json_bearer(
            &f.url("/issues"),
            &f.owner,
            &json!({ "subject": "I" }),
        ))
        .await;
    let iid = issue.json["id"].as_str().unwrap();
    let up = f
        .app
        .send(multipart_upload(
            &f.url(&format!("/issues/{iid}/attachments")),
            &f.owner,
            "pic.png",
            PNG,
        ))
        .await;
    assert_eq!(up.status, 201, "{:?}", up.json);
    assert!(
        up.json.get("kind").is_none(),
        "kind only appears on meeting files"
    );
    let att = up.json["id"].as_str().unwrap();
    let signed = f
        .app
        .send(get_with_bearer(
            &f.url(&format!("/attachments/{att}")),
            &f.owner,
        ))
        .await;
    let ttl =
        signed.json["expires_at"].as_i64().unwrap() - OffsetDateTime::now_utc().unix_timestamp();
    assert!(ttl <= 15 * 60, "non-media keeps the short TTL");
    let (status, _, body) = f
        .app
        .download_bytes(req(
            "GET",
            signed.json["url"].as_str().unwrap(),
            None,
            &[("range", "bytes=1-3")],
            None,
        ))
        .await;
    assert_eq!(status, 206);
    assert_eq!(body, PNG[1..4]);
}

#[tokio::test]
async fn transcript_and_summary_import() {
    require_db!();
    let f = fixture().await;
    let m = f
        .create(&json!({ "title": "Imported", "meeting_date": "2026-09-22" }))
        .await;
    let id = m.json["id"].as_str().unwrap().to_owned();

    let vtt = b"WEBVTT\n\n00:00:01.000 --> 00:00:03.000\n<v Alice>Good morning\n\n00:00:04.000 --> 00:00:05.000\n<v Bob>Hello <i>all</i>\n";
    let r = f
        .app
        .send(multipart_upload(
            &f.url(&format!("/meetings/{id}/transcript/import")),
            &f.owner,
            "call.vtt",
            vtt,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["transcript"], "Alice: Good morning\nBob: Hello all");
    let files = r.json["artifacts"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["kind"], "transcript");
    assert_eq!(files[0]["content_type"], "text/vtt");

    let srt = b"1\n00:00:01,000 --> 00:00:02,000\nLine one\n\n2\n00:00:03,000 --> 00:00:04,000\nLine two\n";
    let r = f
        .app
        .send(multipart_upload(
            &f.url(&format!("/meetings/{id}/transcript/import")),
            &f.owner,
            "call.srt",
            srt,
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json["transcript"], "Line one\nLine two",
        "an import replaces the text"
    );

    let md = b"# Decisions\n\n- Ship Friday\n";
    let r = f
        .app
        .send(multipart_upload(
            &f.url(&format!("/meetings/{id}/summary/import")),
            &f.owner,
            "summary.md",
            md,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["summary"], "# Decisions\n\n- Ship Friday");
    assert_eq!(r.json["artifacts"].as_array().unwrap().len(), 3);

    let bad = f
        .app
        .send(multipart_upload(
            &f.url(&format!("/meetings/{id}/transcript/import")),
            &f.owner,
            "call.pdf",
            b"%PDF-1.4",
        ))
        .await;
    assert_eq!(bad.status, 422);
    let not_utf8 = f
        .app
        .send(multipart_upload(
            &f.url(&format!("/meetings/{id}/transcript/import")),
            &f.owner,
            "call.txt",
            &[0xff, 0xfe, 0x41, 0x00, 0xc3],
        ))
        .await;
    assert_eq!(not_utf8.status, 422);
    assert_eq!(not_utf8.json["code"], "invalid_encoding");
}

#[tokio::test]
async fn meetings_are_indexed_for_search_and_dropped_on_delete() {
    require_db!();
    let f = fixture().await;
    let m = f
        .create(&json!({
            "title": "Architecture sync", "meeting_date": "2026-09-22",
            "transcript": "we discussed the zeppelinfield migration"
        }))
        .await;
    let id: uuid::Uuid = m.json["id"].as_str().unwrap().parse().unwrap();
    let client = f.app.db.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT title, body FROM search_index WHERE entity_type = 'meeting' AND entity_id = $1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("title"), "Architecture sync");
    assert!(row.get::<_, String>("body").contains("zeppelinfield"));

    let _ = f
        .app
        .send(delete_bearer(&f.url(&format!("/meetings/{id}")), &f.owner))
        .await;
    let n: i64 = client
        .query_one(
            "SELECT count(*) FROM search_index WHERE entity_type = 'meeting' AND entity_id = $1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0);
}

/// Meeting hits are gated on `meeting.view`, not the `issue.view` fallback:
/// a stakeholder searching a transcript word must not see the meeting.
#[tokio::test]
async fn meeting_search_hits_require_meeting_view() {
    require_db!();
    let f = fixture().await;
    let m = f
        .create(&json!({
            "title": "Pricing review", "meeting_date": "2026-09-22",
            "transcript": "the quorvalent discount stays confidential"
        }))
        .await;
    assert_eq!(m.status, 201, "{:?}", m.json);
    let id = m.json["id"].as_str().unwrap().to_owned();
    let (stake, _) = f.member("shs@example.com", "shsearch", "stakeholder").await;
    let (dev, _) = f.member("devs@example.com", "devsearch", "dev").await;

    let meeting_hits = |json: &Value| -> Vec<String> {
        json["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|h| h["entity_type"] == "meeting")
            .map(|h| h["entity_id"].as_str().unwrap().to_owned())
            .collect()
    };

    let all = "/api/v1/search?q=quorvalent";
    let typed = "/api/v1/search?q=quorvalent&types=meeting";
    for uri in [all, typed] {
        let r = f.app.send(get_with_bearer(uri, &stake)).await;
        assert_eq!(r.status, 200, "{:?}", r.json);
        assert!(
            meeting_hits(&r.json).is_empty(),
            "stakeholder: {:?}",
            r.json
        );

        let r = f.app.send(get_with_bearer(uri, &dev)).await;
        assert_eq!(r.status, 200, "{:?}", r.json);
        assert_eq!(meeting_hits(&r.json), vec![id.clone()], "dev: {:?}", r.json);
    }

    // The type filter narrows to meetings only.
    let r = f.app.send(get_with_bearer(typed, &f.owner)).await;
    assert!(
        r.json["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|h| h["entity_type"] == "meeting"),
        "{:?}",
        r.json
    );
}

#[tokio::test]
async fn deleted_meeting_files_are_purged_by_gc() {
    require_db!();
    let f = fixture().await;
    let m = f
        .create(&json!({ "title": "Short-lived", "meeting_date": "2026-09-22" }))
        .await;
    let id = m.json["id"].as_str().unwrap().to_owned();
    let video = mp4(64 * 1024);
    let up = f
        .app
        .send(multipart_upload(
            &f.url(&format!("/meetings/{id}/artifacts?kind=recording")),
            &f.owner,
            "a.mp4",
            &video,
        ))
        .await;
    assert_eq!(up.status, 201);
    let sha = up.json["sha256"].as_str().unwrap().to_owned();
    let key = intellipilot_storage::shard_key(&sha);
    assert!(f.app.storage.size(&key).await.is_ok());

    // Deleting the meeting soft-deletes its files ...
    let del = f
        .app
        .send(delete_bearer(&f.url(&format!("/meetings/{id}")), &f.owner))
        .await;
    assert_eq!(del.status, 204);
    let client = f.app.db.pool.get().await.unwrap();

    // ... which survive a GC inside the grace period ...
    let kept = intellipilot_api::attachments::run_gc(
        &client,
        f.app.storage.as_ref(),
        OffsetDateTime::now_utc() - Duration::days(7),
    )
    .await;
    assert_eq!(kept, 0);
    assert!(f.app.storage.size(&key).await.is_ok());

    // ... and are purged after it.
    let purged = intellipilot_api::attachments::run_gc(
        &client,
        f.app.storage.as_ref(),
        OffsetDateTime::now_utc() + Duration::minutes(1),
    )
    .await;
    assert_eq!(purged, 1);
    assert!(f.app.storage.size(&key).await.is_err());
}

#[tokio::test]
async fn meeting_events_carry_only_ids() {
    require_db!();
    let f = fixture().await;
    let pid: uuid::Uuid = f.pid.parse().unwrap();
    let mut rx = f.app.events.subscribe(pid);
    let m = f
        .create(&json!({ "title": "Secret agenda", "meeting_date": "2026-09-22", "summary": "top secret" }))
        .await;
    let ev: Value = serde_json::from_str(rx.recv().await.unwrap().as_str()).unwrap();
    assert_eq!(ev["event"], "meeting.created");
    assert_eq!(ev["meeting_id"], m.json["id"]);
    assert!(
        !ev.to_string().contains("secret"),
        "no meeting content: {ev}"
    );
}
