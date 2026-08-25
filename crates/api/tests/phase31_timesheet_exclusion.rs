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
//! Phase 31 acceptance: the timesheet-report exclusion flag (V024).
//!
//! The flag hides a user from team timesheet tables, project time-entry lists
//! and their export, and suppresses their unfilled-days warning. It must NOT
//! restrict their own time tracking, and must NOT remove their hours from
//! per-issue time logs or the admin cross-project entry list.

mod common;

use common::{TestApp, get_with_bearer, patch_json_bearer, post_json_bearer};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn user(app: &TestApp, email: &str, username: &str) -> (String, String) {
    let _ = app.register(email, username, STRONG_PW).await;
    let token = app.login(email, STRONG_PW).await.access_token().unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    (token, me.json["id"].as_str().unwrap().to_owned())
}

async fn promote_to_superadmin(app: &TestApp, email: &str) {
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE users SET is_superadmin = true WHERE email = $1",
            &[&email.trim().to_lowercase()],
        )
        .await
        .unwrap();
}

/// Set the flag over the real admin endpoint, as a superadmin would.
async fn set_excluded(app: &TestApp, admin: &str, user_id: &str, value: bool) {
    let r = app
        .send(patch_json_bearer(
            &format!("/api/v1/admin/users/{user_id}"),
            admin,
            &json!({ "exclude_from_time_reports": value }),
        ))
        .await;
    assert_eq!(r.status, 200, "set flag: {:?}", r.json);
    assert_eq!(r.json["exclude_from_time_reports"], json!(value));
}

struct Fixture {
    admin: String,
    consultant: String,
    consultant_id: String,
    project: String,
    issue: String,
}

/// A superadmin owner plus a "consultant" member who has logged an hour on an
/// issue in the owner's project.
async fn fixture(app: &TestApp, tag: &str) -> Fixture {
    let (admin, _admin_id) = user(app, &format!("{tag}admin@x"), &format!("{tag}admin")).await;
    promote_to_superadmin(app, &format!("{tag}admin@x")).await;
    // Re-login so the token carries the superadmin claim.
    let admin = app
        .login(&format!("{tag}admin@x"), STRONG_PW)
        .await
        .access_token()
        .unwrap_or(admin);

    let project = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &admin,
            &json!({ "name": "Excl" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    let project = project.json["id"].as_str().unwrap().to_owned();

    let (consultant, consultant_id) = user(app, &format!("{tag}con@x"), &format!("{tag}con")).await;
    let add = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{project}/members"),
            &admin,
            &json!({ "user_id": consultant_id, "role": "dev" }),
        ))
        .await;
    assert_eq!(add.status, 201, "{:?}", add.json);

    let issue = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{project}/issues"),
            &admin,
            &json!({ "subject": "work item" }),
        ))
        .await;
    assert_eq!(issue.status, 201, "{:?}", issue.json);
    let issue = issue.json["id"].as_str().unwrap().to_owned();

    let logged = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &consultant,
            &json!({ "issue_id": issue, "date": "2020-03-04", "minutes": 90, "note": "c" }),
        ))
        .await;
    assert_eq!(logged.status, 201, "consultant log: {:?}", logged.json);

    Fixture {
        admin,
        consultant,
        consultant_id,
        project,
        issue,
    }
}

fn member_ids(body: &Value) -> Vec<String> {
    body["members"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|m| m["user_id"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

async fn project_grid(app: &TestApp, token: &str, pid: &str) -> Value {
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/time/summary?year=2020&month=3"),
            token,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    r.json
}

#[tokio::test]
async fn flag_hides_the_row_from_both_grids() {
    require_db!();
    let app = TestApp::spawn().await;
    let f = fixture(&app, "grid").await;

    let before = project_grid(&app, &f.admin, &f.project).await;
    assert!(member_ids(&before).contains(&f.consultant_id));

    set_excluded(&app, &f.admin, &f.consultant_id, true).await;

    let after = project_grid(&app, &f.admin, &f.project).await;
    assert!(
        !member_ids(&after).contains(&f.consultant_id),
        "project grid still lists the excluded user"
    );

    // The cross-project superadmin grid too.
    let global = app
        .send(get_with_bearer(
            "/api/v1/admin/time/summary?year=2020&month=3",
            &f.admin,
        ))
        .await;
    assert_eq!(global.status, 200, "{:?}", global.json);
    assert!(!member_ids(&global.json).contains(&f.consultant_id));
    assert_eq!(global.json["excluded_members"].as_i64().unwrap(), 1);
}

#[tokio::test]
async fn clearing_the_flag_restores_the_row() {
    require_db!();
    let app = TestApp::spawn().await;
    let f = fixture(&app, "restore").await;

    set_excluded(&app, &f.admin, &f.consultant_id, true).await;
    assert!(
        !member_ids(&project_grid(&app, &f.admin, &f.project).await).contains(&f.consultant_id)
    );

    set_excluded(&app, &f.admin, &f.consultant_id, false).await;
    let back = project_grid(&app, &f.admin, &f.project).await;
    assert!(member_ids(&back).contains(&f.consultant_id));
    assert_eq!(back["excluded_members"].as_i64().unwrap(), 0);
}

#[tokio::test]
async fn excluded_count_is_superadmin_only() {
    require_db!();
    let app = TestApp::spawn().await;
    let f = fixture(&app, "count").await;
    set_excluded(&app, &f.admin, &f.consultant_id, true).await;

    // The superadmin who set the flag sees why the row is missing.
    let as_admin = project_grid(&app, &f.admin, &f.project).await;
    assert_eq!(as_admin["excluded_members"].as_i64().unwrap(), 1);

    // A project manager must not be able to infer that a colleague is
    // excluded, so the field is absent — not zero.
    let (manager, manager_id) = user(&app, "countmgr@x", "countmgr").await;
    let add = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{}/members", f.project),
            &f.admin,
            &json!({ "user_id": manager_id, "role": "product_owner" }),
        ))
        .await;
    assert_eq!(add.status, 201, "{:?}", add.json);
    let as_manager = project_grid(&app, &manager, &f.project).await;
    assert!(
        as_manager.get("excluded_members").is_none(),
        "excluded_members leaked to a non-superadmin: {as_manager:?}"
    );
}

#[tokio::test]
async fn entries_leave_the_project_list_and_export_but_not_issue_time() {
    require_db!();
    let app = TestApp::spawn().await;
    let f = fixture(&app, "entries").await;
    set_excluded(&app, &f.admin, &f.consultant_id, true).await;

    // Project-wide people view: withheld.
    let list = app
        .send(get_with_bearer(
            &format!(
                "/api/v1/projects/{}/time-entries?from=2020-03-01&to=2020-03-31",
                f.project
            ),
            &f.admin,
        ))
        .await;
    assert_eq!(list.status, 200, "{:?}", list.json);
    assert!(
        list.json["entries"].as_array().unwrap().is_empty(),
        "excluded user's entries still in the project list"
    );

    // The export mirrors that list, silently.
    let export = app
        .send(get_with_bearer(
            &format!(
                "/api/v1/projects/{}/time-entries/export?from=2020-03-01&to=2020-03-31",
                f.project
            ),
            &f.admin,
        ))
        .await;
    assert_eq!(export.status, 200);

    // Accounting view: an issue must still show every hour booked against it.
    let issue_time = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{}/issues/{}/time", f.project, f.issue),
            &f.admin,
        ))
        .await;
    assert_eq!(issue_time.status, 200, "{:?}", issue_time.json);
    let total: i64 = issue_time.json["entries"]
        .as_array()
        .map_or(0, |a| a.iter().filter_map(|e| e["minutes"].as_i64()).sum());
    assert_eq!(
        total, 90,
        "issue time log lost the excluded user's hours: {:?}",
        issue_time.json
    );
}

#[tokio::test]
async fn admin_cross_project_list_stays_complete() {
    require_db!();
    let app = TestApp::spawn().await;
    let f = fixture(&app, "adminlist").await;
    set_excluded(&app, &f.admin, &f.consultant_id, true).await;

    // The superadmin needs one view that shows every hour — otherwise setting
    // the flag would look like data loss.
    let all = app
        .send(get_with_bearer(
            "/api/v1/admin/time-entries?from=2020-03-01&to=2020-03-31",
            &f.admin,
        ))
        .await;
    assert_eq!(all.status, 200, "{:?}", all.json);
    let mine = all.json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["user_id"] == json!(f.consultant_id))
        .count();
    assert_eq!(mine, 1, "admin list dropped the excluded user");
}

#[tokio::test]
async fn tracking_still_works_for_an_excluded_user() {
    require_db!();
    let app = TestApp::spawn().await;
    let f = fixture(&app, "track").await;
    set_excluded(&app, &f.admin, &f.consultant_id, true).await;

    // The whole point: this is a reporting exclusion, not a restriction.
    let logged = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &f.consultant,
            &json!({ "issue_id": f.issue, "date": "2020-03-05", "minutes": 60 }),
        ))
        .await;
    assert_eq!(
        logged.status, 201,
        "excluded user cannot log time: {:?}",
        logged.json
    );

    // And they still see their own entries.
    let own = app
        .send(get_with_bearer(
            "/api/v1/me/time-entries?from=2020-03-01&to=2020-03-31",
            &f.consultant,
        ))
        .await;
    assert_eq!(own.status, 200);
    assert_eq!(own.json["entries"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn unfilled_days_warning_is_suppressed() {
    require_db!();
    let app = TestApp::spawn().await;
    let f = fixture(&app, "warn").await;

    // March 2020 is long past and barely filled, so gaps exist beforehand.
    let before = app
        .send(get_with_bearer(
            "/api/v1/me/timesheet/summary?year=2020&month=3",
            &f.consultant,
        ))
        .await;
    assert_eq!(before.status, 200, "{:?}", before.json);
    assert!(
        !before.json["missing_days"].as_array().unwrap().is_empty(),
        "expected unfilled days before the flag is set"
    );

    set_excluded(&app, &f.admin, &f.consultant_id, true).await;

    let after = app
        .send(get_with_bearer(
            "/api/v1/me/timesheet/summary?year=2020&month=3",
            &f.consultant,
        ))
        .await;
    assert_eq!(after.status, 200);
    assert!(
        after.json["missing_days"].as_array().unwrap().is_empty(),
        "missing_days must be empty for an excluded user"
    );
    // The honest counts are preserved — only the nag list is blanked.
    assert!(after.json["working_days"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn flag_requires_superadmin() {
    require_db!();
    let app = TestApp::spawn().await;
    let f = fixture(&app, "authz").await;

    let attempt = app
        .send(patch_json_bearer(
            &format!("/api/v1/admin/users/{}", f.consultant_id),
            &f.consultant,
            &json!({ "exclude_from_time_reports": true }),
        ))
        .await;
    assert_eq!(attempt.status, 403, "{:?}", attempt.json);
}
