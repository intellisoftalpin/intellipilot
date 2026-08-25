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
//! Phase 30 acceptance: the My Issues board — `group=my_role` swimlanes, the
//! matching `my_role` filter, and the project rail counts endpoint.

mod common;

use common::{TestApp, get_with_bearer, post_json_bearer};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

struct Ctx {
    token: String,
    user_id: String,
    project: String,
}

async fn setup(app: &TestApp, tag: &str) -> Ctx {
    let _ = app
        .register(&format!("{tag}@example.com"), tag, STRONG_PW)
        .await;
    let token = app
        .login(&format!("{tag}@example.com"), STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    let user_id = me.json["id"].as_str().unwrap().to_owned();
    let project = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "My Issues" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    Ctx {
        token,
        user_id,
        project: project.json["id"].as_str().unwrap().to_owned(),
    }
}

async fn create_issue(app: &TestApp, c: &Ctx, body: &Value) -> String {
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{}/issues", c.project),
            &c.token,
            body,
        ))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    r.json["id"].as_str().unwrap().to_owned()
}

/// The `my_role` lane board, as the SPA requests it.
async fn lanes(app: &TestApp, c: &Ctx) -> Value {
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{}/board?group=my_role", c.project),
            &c.token,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["group"], "my_role");
    r.json["lanes"].clone()
}

/// Card ids in one lane, across all its columns.
fn lane_cards(lanes: &Value, key: &str) -> Vec<String> {
    let Some(lane) = lanes.as_array().unwrap().iter().find(|l| l["key"] == key) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for col in lane["columns"].as_array().unwrap() {
        for card in col["cards"].as_array().unwrap() {
            out.push(card["id"].as_str().unwrap().to_owned());
        }
    }
    out
}

fn lane_total(lanes: &Value, key: &str) -> i64 {
    lanes
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["key"] == key)
        .map_or(0, |l| l["total"].as_i64().unwrap_or(0))
}

#[tokio::test]
async fn each_role_gets_its_own_lane() {
    require_db!();
    let app = TestApp::spawn().await;
    let c = setup(&app, "myrolelanes").await;

    let assigned = create_issue(
        &app,
        &c,
        &json!({ "subject": "assigned", "assigned_to": c.user_id }),
    )
    .await;
    let qa = create_issue(
        &app,
        &c,
        &json!({ "subject": "qa", "qa_assignee_id": c.user_id }),
    )
    .await;
    let review = create_issue(
        &app,
        &c,
        &json!({ "subject": "review", "reviewer_id": c.user_id }),
    )
    .await;
    // Every issue the caller creates makes them its reporter, so a
    // reporter-only issue is simply one with nobody else set.
    let reported = create_issue(&app, &c, &json!({ "subject": "reported" })).await;
    let watched = create_issue(&app, &c, &json!({ "subject": "watched" })).await;

    let lanes = lanes(&app, &c).await;
    assert!(lane_cards(&lanes, "assignee").contains(&assigned));
    assert!(lane_cards(&lanes, "qa").contains(&qa));
    assert!(lane_cards(&lanes, "reviewer").contains(&review));
    // The creator reports all five.
    let reporter_lane = lane_cards(&lanes, "reporter");
    for id in [&assigned, &qa, &review, &reported, &watched] {
        assert!(reporter_lane.contains(id), "reporter lane missing {id}");
    }
}

#[tokio::test]
async fn watching_lane_tracks_the_watch_list() {
    require_db!();
    let app = TestApp::spawn().await;
    let c = setup(&app, "myrolewatch").await;
    let watched = create_issue(&app, &c, &json!({ "subject": "watched" })).await;
    let other = create_issue(&app, &c, &json!({ "subject": "other" })).await;

    // Watchers default to the caller when no body user_id is given.
    let add = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{}/issues/{watched}/watchers", c.project),
            &c.token,
            &json!({}),
        ))
        .await;
    assert_eq!(add.status, 204, "{:?}", add.json);

    let lanes = lanes(&app, &c).await;
    let watching = lane_cards(&lanes, "watching");
    assert!(watching.contains(&watched));
    assert!(!watching.contains(&other));
}

#[tokio::test]
async fn an_issue_with_two_roles_appears_in_both_lanes() {
    require_db!();
    let app = TestApp::spawn().await;
    let c = setup(&app, "myroleboth").await;
    let both = create_issue(
        &app,
        &c,
        &json!({ "subject": "both", "assigned_to": c.user_id, "qa_assignee_id": c.user_id }),
    )
    .await;

    let lanes = lanes(&app, &c).await;
    assert!(lane_cards(&lanes, "assignee").contains(&both));
    assert!(lane_cards(&lanes, "qa").contains(&both));
    assert!(lane_cards(&lanes, "reporter").contains(&both));
    // Duplication across lanes is the point: lane totals do not partition.
    assert_eq!(lane_total(&lanes, "assignee"), 1);
    assert_eq!(lane_total(&lanes, "qa"), 1);
}

#[tokio::test]
async fn issues_without_any_role_are_absent() {
    require_db!();
    let app = TestApp::spawn().await;
    let owner = setup(&app, "myroleowner").await;
    // A second member creates an issue naming only themselves, so the first
    // user holds no role on it.
    let _ = app
        .register("myroleother@example.com", "myroleother", STRONG_PW)
        .await;
    let other_token = app
        .login("myroleother@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let other_me = app.send(get_with_bearer("/api/v1/me", &other_token)).await;
    let other_id = other_me.json["id"].as_str().unwrap().to_owned();
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{}/members", owner.project),
            &owner.token,
            &json!({ "user_id": other_id, "role": "dev" }),
        ))
        .await;
    assert!(
        invite.status == 201 || invite.status == 200 || invite.status == 204,
        "{:?}",
        invite.json
    );

    let theirs = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{}/issues", owner.project),
            &other_token,
            &json!({ "subject": "theirs", "assigned_to": other_id }),
        ))
        .await;
    assert_eq!(theirs.status, 201, "{:?}", theirs.json);
    let theirs_id = theirs.json["id"].as_str().unwrap().to_owned();

    let lanes = lanes(&app, &owner).await;
    for key in [
        "watching",
        "assignee",
        "qa",
        "reviewer",
        "reporter",
        "mentioned",
    ] {
        assert!(
            !lane_cards(&lanes, key).contains(&theirs_id),
            "lane {key} should not hold an issue the caller has no role on"
        );
    }
}

#[tokio::test]
async fn mentioned_lane_finds_description_and_comment_mentions() {
    require_db!();
    let app = TestApp::spawn().await;
    // The mentioning user must be someone else, otherwise the reporter role
    // would carry the issue into a lane regardless.
    let author = setup(&app, "myrolementionauthor").await;
    let _ = app
        .register("myrolementioned@example.com", "myrolementioned", STRONG_PW)
        .await;
    let target_token = app
        .login("myrolementioned@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let target_me = app.send(get_with_bearer("/api/v1/me", &target_token)).await;
    let target_id = target_me.json["id"].as_str().unwrap().to_owned();
    let _ = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{}/members", author.project),
            &author.token,
            &json!({ "user_id": target_id, "role": "dev" }),
        ))
        .await;

    let in_desc = create_issue(
        &app,
        &author,
        &json!({ "subject": "desc", "description": "cc @myrolementioned please look" }),
    )
    .await;
    let in_comment = create_issue(&app, &author, &json!({ "subject": "comment" })).await;
    let c = app
        .send(post_json_bearer(
            &format!(
                "/api/v1/projects/{}/issues/{in_comment}/comments",
                author.project
            ),
            &author.token,
            &json!({ "body": "@myrolementioned can you review?" }),
        ))
        .await;
    assert_eq!(c.status, 201, "{:?}", c.json);
    let untouched = create_issue(&app, &author, &json!({ "subject": "untouched" })).await;

    // Read the board AS the mentioned user.
    let target_ctx = Ctx {
        token: target_token,
        user_id: target_id,
        project: author.project.clone(),
    };
    let lanes = lanes(&app, &target_ctx).await;
    let mentioned = lane_cards(&lanes, "mentioned");
    assert!(mentioned.contains(&in_desc), "description mention missed");
    assert!(mentioned.contains(&in_comment), "comment mention missed");
    assert!(!mentioned.contains(&untouched));
}

#[tokio::test]
async fn my_role_filter_pages_a_single_lane() {
    require_db!();
    let app = TestApp::spawn().await;
    let c = setup(&app, "myrolefilter").await;
    let assigned = create_issue(
        &app,
        &c,
        &json!({ "subject": "assigned", "assigned_to": c.user_id }),
    )
    .await;
    let _plain = create_issue(&app, &c, &json!({ "subject": "plain" })).await;

    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{}/issues?my_role=assignee", c.project),
            &c.token,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let ids: Vec<&str> = r.json["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![assigned.as_str()]);

    // `any` spans every role — both issues are reported by the caller.
    let any = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{}/issues?my_role=any", c.project),
            &c.token,
        ))
        .await;
    assert_eq!(any.json["total"].as_i64().unwrap(), 2);
}

#[tokio::test]
async fn unknown_my_role_is_rejected_not_ignored() {
    require_db!();
    let app = TestApp::spawn().await;
    let c = setup(&app, "myrolebad").await;
    let _ = create_issue(&app, &c, &json!({ "subject": "one" })).await;

    // Silently dropping the filter would widen the response to the whole
    // project, so a typo must fail loudly.
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{}/issues?my_role=asignee", c.project),
            &c.token,
        ))
        .await;
    assert_eq!(r.status, 422, "{:?}", r.json);
}

#[tokio::test]
async fn counts_report_active_objects_only() {
    require_db!();
    let app = TestApp::spawn().await;
    let c = setup(&app, "myrolecounts").await;

    let statuses = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{}/taxonomy/issue_status", c.project),
            &c.token,
        ))
        .await;
    let items = statuses.json["items"].as_array().unwrap().clone();
    let closed = items
        .iter()
        .find(|s| s["is_closed"] == json!(true))
        .expect("a closed status")
        .clone();

    let _open = create_issue(
        &app,
        &c,
        &json!({ "subject": "open", "assigned_to": c.user_id }),
    )
    .await;
    let _done = create_issue(
        &app,
        &c,
        &json!({ "subject": "done", "assigned_to": c.user_id,
                 "status_id": closed["id"].as_str().unwrap() }),
    )
    .await;

    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{}/counts", c.project),
            &c.token,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    // The closed issue is excluded from both totals.
    assert_eq!(r.json["issues"].as_i64().unwrap(), 1);
    assert_eq!(r.json["my_issues"].as_i64().unwrap(), 1);
    assert_eq!(r.json["epics"].as_i64().unwrap(), 0);
    assert_eq!(r.json["milestones"].as_i64().unwrap(), 0);
}

#[tokio::test]
async fn my_issues_count_is_distinct_across_lanes() {
    require_db!();
    let app = TestApp::spawn().await;
    let c = setup(&app, "myrolecountdistinct").await;
    // One issue, three roles: assignee, QA and reporter.
    let _ = create_issue(
        &app,
        &c,
        &json!({ "subject": "triple", "assigned_to": c.user_id, "qa_assignee_id": c.user_id }),
    )
    .await;

    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{}/counts", c.project),
            &c.token,
        ))
        .await;
    assert_eq!(
        r.json["my_issues"].as_i64().unwrap(),
        1,
        "badge must count issues, not role hits"
    );
}
