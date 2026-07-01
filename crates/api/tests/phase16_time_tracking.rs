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
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
//! Phase 16 acceptance: time tracking — worked time, absences, completeness,
//! team views, period locks, vacation balances, and export.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, patch_json_bearer, post_json_bearer, req};
use serde_json::json;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Register + login, returning (token, user_id).
async fn user(app: &TestApp, email: &str, username: &str) -> (String, String) {
    let _ = app.register(email, username, STRONG_PW).await;
    let token = app.login(email, STRONG_PW).await.access_token().unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    let id = me.json["id"].as_str().unwrap().to_owned();
    (token, id)
}

/// Owner with a fresh project. Returns (token, owner_id, project_id).
async fn owner_project(app: &TestApp) -> (String, String, String) {
    let (token, uid) = user(app, "owner@x", "owneruser").await;
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "TT" }),
        ))
        .await;
    assert_eq!(p.status, 201, "{:?}", p.json);
    (token, uid, p.json["id"].as_str().unwrap().to_owned())
}

async fn add_member(app: &TestApp, owner: &str, pid: &str, user_id: &str, role: &str) {
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            owner,
            &json!({ "user_id": user_id, "role": role }),
        ))
        .await;
    assert_eq!(r.status, 201, "add member: {:?}", r.json);
}

/// Create an issue in `pid` assigned to `assignee`, returning its id.
async fn issue_for(app: &TestApp, token: &str, pid: &str, assignee: &str) -> String {
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            token,
            &json!({ "subject": "Task", "assigned_to": assignee }),
        ))
        .await;
    assert_eq!(r.status, 201, "create issue: {:?}", r.json);
    r.json["id"].as_str().unwrap().to_owned()
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

// ---------------------------------------------------------------------------
// worked time: log / list / update / delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn log_list_update_delete_own_time() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, uid, pid) = owner_project(&app).await;
    let issue = issue_for(&app, &token, &pid, &uid).await;

    // Log 90 minutes on an assigned task.
    let logged = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &token,
            &json!({ "issue_id": issue, "date": "2020-03-04", "minutes": 90, "note": "work" }),
        ))
        .await;
    assert_eq!(logged.status, 201, "{:?}", logged.json);
    let entry_id = logged.json["id"].as_str().unwrap().to_owned();
    assert_eq!(logged.json["minutes"], 90);
    assert_eq!(logged.json["kind"], "work");

    // It shows up in the personal timesheet with the joined task subject.
    let list = app
        .send(get_with_bearer(
            "/api/v1/me/time-entries?from=2020-03-01&to=2020-03-31",
            &token,
        ))
        .await;
    assert_eq!(list.status, 200);
    let entries = list.json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["issue_subject"], "Task");
    assert_eq!(entries[0]["project_name"], "TT");

    // Update with the correct version.
    let upd = app
        .send(patch_json_bearer(
            &format!("/api/v1/me/time-entries/{entry_id}"),
            &token,
            &json!({ "minutes": 120, "version": 1 }),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["minutes"], 120);
    assert_eq!(upd.json["version"], 2);

    // Stale version → 409.
    let stale = app
        .send(patch_json_bearer(
            &format!("/api/v1/me/time-entries/{entry_id}"),
            &token,
            &json!({ "minutes": 60, "version": 1 }),
        ))
        .await;
    assert_eq!(stale.status, 409);
    assert_eq!(stale.json["code"], "version_conflict");

    // Delete.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/me/time-entries/{entry_id}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
}

#[tokio::test]
async fn can_log_to_any_task_but_not_without_membership() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid, pid) = owner_project(&app).await;
    let (_dev, did) = user(&app, "dev@x", "devuser").await;
    add_member(&app, &owner, &pid, &did, "dev").await;

    // Task is assigned to dev, not to the owner.
    let issue = issue_for(&app, &owner, &pid, &did).await;

    // The owner (a member with time.log) may now log time to ANY task, not just
    // ones assigned to them.
    let ok = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &owner,
            &json!({ "issue_id": issue, "date": "2020-03-04", "minutes": 30 }),
        ))
        .await;
    assert_eq!(ok.status, 201, "{:?}", ok.json);

    // A non-member cannot log against the project's tasks → 403.
    let (outsider, _) = user(&app, "out@x", "outsider").await;
    let denied = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &outsider,
            &json!({ "issue_id": issue, "date": "2020-03-04", "minutes": 30 }),
        ))
        .await;
    assert_eq!(denied.status, 403, "{:?}", denied.json);
}

#[tokio::test]
async fn assigned_issues_listed_for_picker() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, oid, pid) = owner_project(&app).await;
    let assigned = issue_for(&app, &owner, &pid, &oid).await;
    // An unassigned issue must not appear.
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &owner,
            &json!({ "subject": "Unassigned" }),
        ))
        .await;

    let r = app
        .send(get_with_bearer("/api/v1/me/assigned-issues", &owner))
        .await;
    assert_eq!(r.status, 200);
    let issues = r.json["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0]["id"], json!(assigned));
    assert_eq!(issues[0]["project_name"], "TT");
}

// ---------------------------------------------------------------------------
// absences (vacation / illness / day_off / holiday) + booking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn book_absence_materialises_working_days() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, _uid, _pid) = owner_project(&app).await;

    // Mon 2020-01-06 .. Fri 2020-01-10 = 5 working days; weekend skipped.
    let booked = app
        .send(post_json_bearer(
            "/api/v1/me/absences",
            &token,
            &json!({
                "kind": "vacation",
                "start_date": "2020-01-06",
                "end_date": "2020-01-12",
            }),
        ))
        .await;
    assert_eq!(booked.status, 201, "{:?}", booked.json);
    let booking_id = booked.json["booking_id"].as_str().unwrap().to_owned();
    let entries = booked.json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 5, "weekends skipped, 5 weekdays booked");
    assert_eq!(entries[0]["kind"], "vacation");
    assert!(
        entries[0]["project_id"].is_null(),
        "absences are person-level"
    );

    // Cancel the booking removes all its entries.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/me/absences/{booking_id}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
    let list = app
        .send(get_with_bearer(
            "/api/v1/me/time-entries?from=2020-01-01&to=2020-01-31",
            &token,
        ))
        .await;
    assert_eq!(list.json["entries"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn holiday_and_illness_kinds_accepted() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, _uid, _pid) = owner_project(&app).await;

    for kind in ["holiday", "illness", "day_off"] {
        let r = app
            .send(post_json_bearer(
                "/api/v1/me/absences",
                &token,
                &json!({ "kind": kind, "start_date": "2020-04-06", "end_date": "2020-04-06" }),
            ))
            .await;
        assert_eq!(r.status, 201, "kind {kind}: {:?}", r.json);
        assert_eq!(r.json["entries"][0]["kind"], kind);
    }

    // 'work' is not a valid absence.
    let bad = app
        .send(post_json_bearer(
            "/api/v1/me/absences",
            &token,
            &json!({ "kind": "work", "start_date": "2020-04-06", "end_date": "2020-04-06" }),
        ))
        .await;
    assert_eq!(bad.status, 422);
}

// ---------------------------------------------------------------------------
// timesheet completeness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn timesheet_summary_tracks_missing_days() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, uid, pid) = owner_project(&app).await;
    let issue = issue_for(&app, &token, &pid, &uid).await;

    // A fully-past month: every working day is "due".
    let empty = app
        .send(get_with_bearer(
            "/api/v1/me/timesheet/summary?year=2020&month=2",
            &token,
        ))
        .await;
    assert_eq!(empty.status, 200);
    let working = empty.json["working_days"].as_i64().unwrap();
    assert!(working >= 19, "Feb 2020 has 20 weekdays, got {working}");
    assert_eq!(empty.json["complete_days"], 0);
    let missing = empty.json["missing_days"].as_array().unwrap().len() as i64;
    assert_eq!(
        missing, working,
        "nothing logged → all working days missing"
    );

    // Fill a full day (480 min) on Mon 2020-02-03.
    let _ = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &token,
            &json!({ "issue_id": issue, "date": "2020-02-03", "minutes": 480 }),
        ))
        .await;
    let after = app
        .send(get_with_bearer(
            "/api/v1/me/timesheet/summary?year=2020&month=2",
            &token,
        ))
        .await;
    assert_eq!(after.json["complete_days"], 1);
    assert_eq!(after.json["logged_minutes"], 480);
    let missing_after = after.json["missing_days"].as_array().unwrap().len() as i64;
    assert_eq!(missing_after, working - 1);
}

// ---------------------------------------------------------------------------
// team views + corrections + permission gating
// ---------------------------------------------------------------------------

#[tokio::test]
async fn team_view_and_admin_correction() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid, pid) = owner_project(&app).await;
    let (dev, did) = user(&app, "dev@x", "devuser").await;
    add_member(&app, &owner, &pid, &did, "dev").await;
    let issue = issue_for(&app, &owner, &pid, &did).await;

    let logged = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &dev,
            &json!({ "issue_id": issue, "date": "2020-05-04", "minutes": 100 }),
        ))
        .await;
    let entry_id = logged.json["id"].as_str().unwrap().to_owned();

    // Dev lacks time.view_all → cannot see the team timesheet.
    let denied = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/time-entries?from=2020-05-01&to=2020-05-31"),
            &dev,
        ))
        .await;
    assert_eq!(denied.status, 403);

    // Owner (admin) sees the whole team's entries.
    let team = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/time-entries?from=2020-05-01&to=2020-05-31"),
            &owner,
        ))
        .await;
    assert_eq!(team.status, 200);
    assert_eq!(team.json["entries"].as_array().unwrap().len(), 1);
    assert_eq!(team.json["entries"][0]["full_name"], "Test");

    // Team monthly grid lists the dev with a per-day total.
    let grid = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/time/summary?year=2020&month=5"),
            &owner,
        ))
        .await;
    assert_eq!(grid.status, 200);
    let members = grid.json["members"].as_array().unwrap();
    let dev_row = members.iter().find(|m| m["user_id"] == json!(did)).unwrap();
    assert_eq!(dev_row["total_minutes"], 100);

    // Owner corrects the dev's entry.
    let fixed = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}/time-entries/{entry_id}"),
            &owner,
            &json!({ "minutes": 150, "version": 1 }),
        ))
        .await;
    assert_eq!(fixed.status, 200, "{:?}", fixed.json);
    assert_eq!(fixed.json["minutes"], 150);
}

// ---------------------------------------------------------------------------
// period locks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn period_lock_blocks_members_not_managers() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid, pid) = owner_project(&app).await;
    let (dev, did) = user(&app, "dev@x", "devuser").await;
    add_member(&app, &owner, &pid, &did, "dev").await;
    let issue = issue_for(&app, &owner, &pid, &did).await;

    let first = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &dev,
            &json!({ "issue_id": issue, "date": "2020-06-02", "minutes": 60 }),
        ))
        .await;
    assert_eq!(first.status, 201);
    let entry_id = first.json["id"].as_str().unwrap().to_owned();

    // Owner locks June 2020.
    let lock = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/time/locks"),
            &owner,
            &json!({ "year": 2020, "month": 6 }),
        ))
        .await;
    assert_eq!(lock.status, 201, "{:?}", lock.json);

    // Dev can no longer add to or edit the locked month.
    let blocked = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &dev,
            &json!({ "issue_id": issue, "date": "2020-06-03", "minutes": 60 }),
        ))
        .await;
    assert_eq!(blocked.status, 409);
    assert_eq!(blocked.json["code"], "period_locked");

    let edit_blocked = app
        .send(patch_json_bearer(
            &format!("/api/v1/me/time-entries/{entry_id}"),
            &dev,
            &json!({ "minutes": 90, "version": 1 }),
        ))
        .await;
    assert_eq!(edit_blocked.status, 409);

    // Manager (owner) can still correct inside the locked month.
    let corrected = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}/time-entries/{entry_id}"),
            &owner,
            &json!({ "minutes": 90, "version": 1 }),
        ))
        .await;
    assert_eq!(corrected.status, 200);

    // Unlock → dev can log again.
    let unlock = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/time/locks/2020/6"),
            &owner,
        ))
        .await;
    assert_eq!(unlock.status, 204);
    let again = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &dev,
            &json!({ "issue_id": issue, "date": "2020-06-03", "minutes": 60 }),
        ))
        .await;
    assert_eq!(again.status, 201);
}

// ---------------------------------------------------------------------------
// availability (who is out today)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn availability_shows_absent_members() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid, pid) = owner_project(&app).await;
    let (dev, did) = user(&app, "dev@x", "devuser").await;
    add_member(&app, &owner, &pid, &did, "dev").await;

    let _ = app
        .send(post_json_bearer(
            "/api/v1/me/absences",
            &dev,
            &json!({ "kind": "vacation", "start_date": "2020-07-06", "end_date": "2020-07-06" }),
        ))
        .await;

    let avail = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/availability?date=2020-07-06"),
            &owner,
        ))
        .await;
    assert_eq!(avail.status, 200);
    let out = avail.json["unavailable"].as_array().unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["user_id"], json!(did));
    assert_eq!(out[0]["kind"], "vacation");

    // A day with nobody out.
    let clear = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/availability?date=2020-07-07"),
            &owner,
        ))
        .await;
    assert_eq!(clear.json["unavailable"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// vacation allowances + balance + work settings (superadmin)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vacation_balance_with_carryover_and_work_settings() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid, _pid) = owner_project(&app).await;
    let (dev, did) = user(&app, "dev@x", "devuser").await;
    promote_superadmin(&app, "owner@x").await;

    // Superadmin grants 25 days + 5 carried over for 2020.
    let set = app
        .send(req(
            "PUT",
            &format!("/api/v1/admin/users/{did}/vacation-allowances/2020"),
            Some(&owner),
            &[],
            Some(&json!({ "allowance_days": 25.0, "carried_over_days": 5.0 })),
        ))
        .await;
    assert_eq!(set.status, 200, "{:?}", set.json);

    // Dev books 5 vacation days (Mon–Fri).
    let _ = app
        .send(post_json_bearer(
            "/api/v1/me/absences",
            &dev,
            &json!({ "kind": "vacation", "start_date": "2020-08-03", "end_date": "2020-08-07" }),
        ))
        .await;

    // Dev sees the balance: used 5, remaining 25 (25 + 5 − 5).
    let bal = app
        .send(get_with_bearer("/api/v1/me/vacation-balance", &dev))
        .await;
    assert_eq!(bal.status, 200);
    let year = bal.json["years"]
        .as_array()
        .unwrap()
        .iter()
        .find(|y| y["year"] == json!(2020))
        .unwrap();
    assert_eq!(year["used_days"], json!(5.0));
    assert_eq!(year["remaining_days"], json!(25.0));

    // Superadmin's allowance view exposes the same accounting.
    let admin_view = app
        .send(get_with_bearer(
            &format!("/api/v1/admin/users/{did}/vacation-allowances"),
            &owner,
        ))
        .await;
    assert_eq!(admin_view.status, 200);
    assert_eq!(admin_view.json["allowances"].as_array().unwrap().len(), 1);

    // Change the dev's daily target to 6h; balance recomputes used = 2400/360.
    let ws = app
        .send(patch_json_bearer(
            &format!("/api/v1/admin/users/{did}/work-settings"),
            &owner,
            &json!({ "work_minutes_per_day": 360 }),
        ))
        .await;
    assert_eq!(ws.status, 204);
    let bal2 = app
        .send(get_with_bearer("/api/v1/me/vacation-balance", &dev))
        .await;
    let year2 = bal2.json["years"]
        .as_array()
        .unwrap()
        .iter()
        .find(|y| y["year"] == json!(2020))
        .unwrap();
    // 5 days × 480 min ÷ 360 = 6.667 used.
    let used = year2["used_days"].as_f64().unwrap();
    assert!((used - 6.6667).abs() < 0.01, "used={used}");
}

#[tokio::test]
async fn allowance_endpoints_require_superadmin() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, oid, _pid) = owner_project(&app).await;

    let r = app
        .send(req(
            "PUT",
            &format!("/api/v1/admin/users/{oid}/vacation-allowances/2020"),
            Some(&owner),
            &[],
            Some(&json!({ "allowance_days": 10.0 })),
        ))
        .await;
    assert_eq!(r.status, 403, "non-superadmin blocked");
}

// ---------------------------------------------------------------------------
// task-level time + export
// ---------------------------------------------------------------------------

#[tokio::test]
async fn issue_time_totals() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, uid, pid) = owner_project(&app).await;
    let issue = issue_for(&app, &owner, &pid, &uid).await;
    let _ = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &owner,
            &json!({ "issue_id": issue, "date": "2020-09-01", "minutes": 45 }),
        ))
        .await;
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{issue}/time"),
            &owner,
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json["total_minutes"], 45);
    assert_eq!(r.json["my_minutes"], 45);
}

#[tokio::test]
async fn export_csv_and_xlsx() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, uid, pid) = owner_project(&app).await;
    let issue = issue_for(&app, &token, &pid, &uid).await;
    let _ = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &token,
            &json!({ "issue_id": issue, "date": "2020-10-01", "minutes": 75, "note": "x,y" }),
        ))
        .await;

    // CSV.
    let (status, headers, bytes) = app
        .download_bytes(get_with_bearer(
            "/api/v1/me/time-entries/export?format=csv&from=2020-10-01&to=2020-10-31",
            &token,
        ))
        .await;
    assert_eq!(status, 200);
    assert!(headers["content-type"].contains("csv"));
    let csv = String::from_utf8(bytes).unwrap();
    assert!(csv.contains("Date,Kind,Project"));
    assert!(csv.contains("\"x,y\""), "comma note is quoted");

    // XLSX (zip magic 'PK').
    let (xstatus, xheaders, xbytes) = app
        .download_bytes(get_with_bearer(
            "/api/v1/me/time-entries/export?format=xlsx&from=2020-10-01&to=2020-10-31",
            &token,
        ))
        .await;
    assert_eq!(xstatus, 200);
    assert!(xheaders["content-type"].contains("spreadsheetml"));
    assert_eq!(&xbytes[0..2], b"PK", "xlsx is a zip archive");
}

// ---------------------------------------------------------------------------
// v0.6.1: log any/no task, meetings, loggable-issues, superadmin cross-project
// ---------------------------------------------------------------------------

#[tokio::test]
async fn log_work_without_task_requires_note() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid, pid) = owner_project(&app).await;

    // No task + no note → 422.
    let no_note = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &owner,
            &json!({ "project_id": pid, "date": "2020-03-04", "minutes": 60 }),
        ))
        .await;
    assert_eq!(no_note.status, 422, "{:?}", no_note.json);

    // No task + note → 201 (work attributed to the project, no issue).
    let ok = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &owner,
            &json!({ "project_id": pid, "date": "2020-03-04", "minutes": 60, "note": "admin work" }),
        ))
        .await;
    assert_eq!(ok.status, 201, "{:?}", ok.json);
    assert_eq!(ok.json["kind"], "work");
    assert!(ok.json["issue_id"].is_null());
    assert_eq!(ok.json["project_id"], pid);
}

#[tokio::test]
async fn log_meeting_with_type_and_projectless() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid, pid) = owner_project(&app).await;

    // Project meeting with a type.
    let m = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &owner,
            &json!({ "kind": "meeting", "meeting_type": "daily", "project_id": pid,
                     "date": "2020-03-04", "minutes": 15 }),
        ))
        .await;
    assert_eq!(m.status, 201, "{:?}", m.json);
    assert_eq!(m.json["kind"], "meeting");
    assert_eq!(m.json["meeting_type"], "daily");
    assert_eq!(m.json["project_id"], pid);

    // Project-less meeting is allowed (company-wide).
    let g = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &owner,
            &json!({ "kind": "meeting", "date": "2020-03-04", "minutes": 30, "note": "all-hands" }),
        ))
        .await;
    assert_eq!(g.status, 201, "{:?}", g.json);
    assert!(g.json["project_id"].is_null());

    // Unknown meeting type → 422.
    let bad = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &owner,
            &json!({ "kind": "meeting", "meeting_type": "party", "date": "2020-03-04", "minutes": 5 }),
        ))
        .await;
    assert_eq!(bad.status, 422);
}

#[tokio::test]
async fn loggable_issues_search_and_membership() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid, pid) = owner_project(&app).await;
    for s in ["Alpha login", "Beta logout"] {
        let _ = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/issues"),
                &owner,
                &json!({ "subject": s }),
            ))
            .await;
    }

    // A member sees all project issues (not just assigned).
    let all = app
        .send(get_with_bearer("/api/v1/me/loggable-issues", &owner))
        .await;
    assert_eq!(all.status, 200);
    assert_eq!(all.json["issues"].as_array().unwrap().len(), 2);

    // Search narrows by subject.
    let s = app
        .send(get_with_bearer(
            "/api/v1/me/loggable-issues?search=logout",
            &owner,
        ))
        .await;
    assert_eq!(s.json["issues"].as_array().unwrap().len(), 1);
    assert_eq!(s.json["issues"][0]["subject"], "Beta logout");

    // A non-member sees nothing.
    let (outsider, _) = user(&app, "out2@x", "outsider2").await;
    let none = app
        .send(get_with_bearer("/api/v1/me/loggable-issues", &outsider))
        .await;
    assert_eq!(none.json["issues"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn superadmin_cross_project_timesheet() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, oid, pid) = owner_project(&app).await;
    let issue = issue_for(&app, &owner, &pid, &oid).await;
    let _ = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &owner,
            &json!({ "issue_id": issue, "date": "2020-03-04", "minutes": 120, "note": "x" }),
        ))
        .await;

    // Non-superadmin is blocked from the global views.
    let blocked = app
        .send(get_with_bearer(
            "/api/v1/admin/time/summary?year=2020&month=3",
            &owner,
        ))
        .await;
    assert_eq!(blocked.status, 403);

    promote_superadmin(&app, "owner@x").await;

    // Global month grid includes the user with their total.
    let grid = app
        .send(get_with_bearer(
            "/api/v1/admin/time/summary?year=2020&month=3",
            &owner,
        ))
        .await;
    assert_eq!(grid.status, 200, "{:?}", grid.json);
    let members = grid.json["members"].as_array().unwrap();
    let me = members.iter().find(|m| m["user_id"] == oid).unwrap();
    assert_eq!(me["total_minutes"], 120);

    // Global entry list returns the entry across projects.
    let entries = app
        .send(get_with_bearer(
            "/api/v1/admin/time-entries?from=2020-03-01&to=2020-03-31",
            &owner,
        ))
        .await;
    assert_eq!(entries.status, 200);
    assert!(!entries.json["entries"].as_array().unwrap().is_empty());
}
