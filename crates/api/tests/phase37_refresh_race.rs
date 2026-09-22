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
//! Refresh-token rotation races.
//!
//! Two requests carrying the same refresh cookie at once — two browser tabs,
//! or a proactive refresh timer meeting a 401 after the laptop wakes — used to
//! be treated as token theft: the loser's replay revoked the whole session
//! family and signed the user out of every tab. A replay within the grace
//! window now gets `refresh_superseded` and leaves the session alone; a replay
//! after it is still reuse (see `phase1_identity::refresh_reuse_detected_revokes_family`).

mod common;

use common::{TestApp, post_with_cookie};

const STRONG_PW: &str = "Tr0ub4dor&3-horse-battery";

async fn signed_in(app: &TestApp, tag: &str) -> String {
    let _ = app
        .register(
            &format!("{tag}@example.com"),
            &format!("{tag}user"),
            STRONG_PW,
        )
        .await;
    app.login(&format!("{tag}@example.com"), STRONG_PW)
        .await
        .dev_refresh()
        .expect("login hands a refresh token in dev")
}

async fn audit_count(app: &TestApp, action: &str) -> i64 {
    let client = app.db.pool.get().await.unwrap();
    client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = $1",
            &[&action],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn replay_right_after_rotation_is_superseded_not_reuse() {
    require_db!();
    let app = TestApp::spawn().await;
    let refresh1 = signed_in(&app, "race1").await;

    let winner = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh1))
        .await;
    assert_eq!(winner.status, 200);
    let refresh2 = winner.dev_refresh().unwrap();

    // The other tab, a moment late, still sends the old cookie.
    let loser = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh1))
        .await;
    assert_eq!(loser.status, 401);
    assert_eq!(loser.json["code"], "refresh_superseded");
    assert!(
        loser.cookies.is_empty(),
        "must not clear the cookie — the jar already holds the successor: {:?}",
        loser.cookies
    );

    // The session survives: the successor still rotates.
    let next = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh2))
        .await;
    assert_eq!(next.status, 200, "family must not be revoked by a race");

    assert_eq!(audit_count(&app, "refresh_superseded").await, 1);
    assert_eq!(audit_count(&app, "refresh_reuse_detected").await, 0);
}

#[tokio::test]
async fn concurrent_refreshes_with_one_cookie_keep_the_session() {
    require_db!();
    let app = TestApp::spawn().await;
    let refresh1 = signed_in(&app, "race2").await;

    let (a, b) = tokio::join!(
        app.send(post_with_cookie("/api/v1/auth/refresh", &refresh1)),
        app.send(post_with_cookie("/api/v1/auth/refresh", &refresh1)),
    );
    let (ok, lost) = match (a.status, b.status) {
        (200, 401) => (a, b),
        (401, 200) => (b, a),
        other => panic!("exactly one refresh must win, got {other:?}"),
    };
    assert_eq!(lost.json["code"], "refresh_superseded");
    assert!(lost.cookies.is_empty());

    let successor = ok.dev_refresh().unwrap();
    let after = app
        .send(post_with_cookie("/api/v1/auth/refresh", &successor))
        .await;
    assert_eq!(after.status, 200, "the race must not revoke the family");
    assert_eq!(audit_count(&app, "refresh_reuse_detected").await, 0);
}

#[tokio::test]
async fn replay_after_the_grace_window_still_revokes() {
    require_db!();
    let app = TestApp::spawn().await;
    let refresh1 = signed_in(&app, "race3").await;

    let rotated = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh1))
        .await;
    assert_eq!(rotated.status, 200);
    let refresh2 = rotated.dev_refresh().unwrap();

    // Age the rotation past the grace window.
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE refresh_tokens SET used_at = now() - interval '5 minutes' \
             WHERE used_at IS NOT NULL",
            &[],
        )
        .await
        .unwrap();

    let replay = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh1))
        .await;
    assert_eq!(replay.status, 401);
    assert_eq!(replay.json["code"], "unauthorized");
    assert!(
        replay
            .cookies
            .iter()
            .any(|c| c.starts_with("refresh_token=;") || c.contains("Max-Age=0")),
        "a real reuse clears the cookie: {:?}",
        replay.cookies
    );

    let after = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh2))
        .await;
    assert_eq!(after.status, 401, "family must be revoked after real reuse");
    assert_eq!(audit_count(&app, "refresh_reuse_detected").await, 1);
}
