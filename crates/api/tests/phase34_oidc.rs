//! Phase 34 — OpenID Connect single sign-on (V025).
//!
//! Structured like `phase12_ldap.rs`, for the same reason: the parts that need
//! a real identity provider cannot run in CI, so they are exercised by the
//! in-app "Test connection" button against a live Authentik. What *is* covered
//! here is everything that decides who gets in:
//!
//!   * admin CRUD, superadmin gating, and the guarantee that a stored client
//!     secret is never serialized back;
//!   * the browser flow's refusals — unknown, expired and already-spent
//!     `state`, an unreachable issuer, a disabled provider;
//!   * user resolution: JIT provisioning, the email-collision refusal, the
//!     admin-armed rescue link, and the `(provider, subject)` lookup that must
//!     win over any of them;
//!   * the group → superadmin mapping in both directions, including its
//!     refusal to demote the last remaining superadmin;
//!   * the device flow's plumbing and its poll-interval enforcement;
//!   * back-channel logout's token validation;
//!   * that switching password login off still lets a break-glass superadmin
//!     in.
//!
//! A minimal fake provider (discovery document + JWKS) is served over a real
//! socket where a reachable IdP is needed. It deliberately does not mint signed
//! ID tokens: doing so would need an RSA keypair and would test the
//! `openidconnect` crate's verifier rather than our code.

#![cfg(test)]
#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

mod common;

use common::{TestApp, delete_bearer, get, get_with_bearer, post_bearer, req};
use intellipilot_api::oidc::resolve::{self, IdentityFacts, ResolveError};
use intellipilot_db::oidc_providers::OidcProvider;
use intellipilot_db::{oidc_identities, oidc_providers, users};
use serde_json::{Value, json};

const PW: &str = "correct horse battery staple";
/// A port that should refuse connections immediately.
const DEAD_ISSUER: &str = "http://127.0.0.1:14390";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

async fn register_and_login(app: &TestApp, email: &str, username: &str) -> String {
    let r = app.register(email, username, PW).await;
    assert_eq!(r.status, 201, "register: {:?}", r.json);
    let l = app.login(email, PW).await;
    assert_eq!(l.status, 200, "login: {:?}", l.json);
    l.access_token().expect("access token")
}

fn provider_body(slug: &str, issuer: &str, enabled: bool) -> Value {
    json!({
        "slug": slug,
        "display_name": "Test Provider",
        "enabled": enabled,
        "issuer_url": issuer,
        "client_id": "intellipilot",
        "client_secret": "s3cret",
        "scopes": "openid profile email",
        "claim_email": "email",
        "claim_username": "preferred_username",
        "claim_display_name": "name",
        "claim_groups": "groups",
        "superadmin_group": "IntelliPilot Admins",
        "allow_jit_provisioning": true,
        "require_email_verified": true,
        "device_flow_enabled": true,
        "sort_order": 0,
        "skip_tls_verify": false
    })
}

/// Insert an enabled provider straight into the database.
///
/// Raw SQL rather than `oidc_providers::create` because that records an actor
/// in `updated_by`, and there is no admin to attribute a fixture to.
async fn seed_provider(app: &TestApp, slug: &str, issuer: &str) -> OidcProvider {
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO oidc_providers \
               (slug, display_name, enabled, issuer_url, client_id, client_secret, \
                superadmin_group) \
             VALUES ($1, 'Seeded', true, $2, 'intellipilot', 's3cret', 'IntelliPilot Admins')",
            &[&slug, &issuer],
        )
        .await
        .unwrap_or_else(|e| panic!("seed provider {slug}: {e}"));
    oidc_providers::get_by_slug(&client, slug)
        .await
        .unwrap()
        .unwrap()
}

fn facts(subject: &str, email: &str, verified: bool, groups: &[&str]) -> IdentityFacts {
    IdentityFacts {
        issuer: "https://idp.example".to_owned(),
        subject: subject.to_owned(),
        email: email.to_owned(),
        email_verified: verified,
        username_hint: email.split('@').next().unwrap().to_owned(),
        display_name: "From The Directory".to_owned(),
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
    }
}

/// A stand-in identity provider, served over a real socket so `reqwest` can
/// reach it. Publishes just enough discovery for the flows to start.
struct FakeIdp {
    base: String,
    _shutdown: tokio::task::JoinHandle<()>,
}

impl FakeIdp {
    async fn spawn() -> Self {
        use axum::Router;
        use axum::routing::get;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let discovery_base = base.clone();

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let b = discovery_base.clone();
                    async move {
                        axum::Json(json!({
                            "issuer": b,
                            "authorization_endpoint": format!("{b}/authorize"),
                            "token_endpoint": format!("{b}/token"),
                            "userinfo_endpoint": format!("{b}/userinfo"),
                            "device_authorization_endpoint": format!("{b}/device"),
                            "jwks_uri": format!("{b}/jwks"),
                            "response_types_supported": ["code"],
                            "subject_types_supported": ["public"],
                            "id_token_signing_alg_values_supported": ["RS256"],
                        }))
                    }
                }),
            )
            .route("/jwks", get(|| async { axum::Json(json!({ "keys": [] })) }));

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base,
            _shutdown: handle,
        }
    }
}

// ---------------------------------------------------------------------------
// Admin CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_crud_is_superadmin_only_and_never_returns_the_secret() {
    let app = TestApp::spawn().await;
    let plain = register_and_login(&app, "plain@example.com", "plain").await;

    // A normal user cannot see or touch providers.
    let r = app
        .send(get_with_bearer("/api/v1/admin/oidc-providers", &plain))
        .await;
    assert_eq!(r.status, 403, "non-admin list: {:?}", r.json);
    let r = app
        .send(req(
            "POST",
            "/api/v1/admin/oidc-providers",
            Some(&plain),
            &[],
            Some(&provider_body("authentik", "https://idp.example", false)),
        ))
        .await;
    assert_eq!(r.status, 403, "non-admin create: {:?}", r.json);

    let boss = {
        let r = app.register("boss@example.com", "boss", PW).await;
        assert_eq!(r.status, 201);
        promote_to_superadmin(&app, "boss@example.com").await;
        app.login("boss@example.com", PW)
            .await
            .access_token()
            .unwrap()
    };

    let created = app
        .send(req(
            "POST",
            "/api/v1/admin/oidc-providers",
            Some(&boss),
            &[],
            Some(&provider_body("authentik", "https://idp.example", false)),
        ))
        .await;
    assert_eq!(created.status, 201, "create: {:?}", created.json);
    let body = created.json.to_string();
    assert!(
        !body.contains("s3cret"),
        "the client secret must never be serialized: {body}"
    );
    assert_eq!(created.json["client_secret_set"], json!(true));
    // The operator needs to be told exactly what to register at the provider.
    assert_eq!(
        created.json["redirect_uri"],
        json!("http://localhost/api/v1/auth/oidc/authentik/callback")
    );
    assert_eq!(
        created.json["backchannel_logout_uri"],
        json!("http://localhost/api/v1/auth/oidc/authentik/backchannel-logout")
    );

    // A second provider may not reuse the route key.
    let dup = app
        .send(req(
            "POST",
            "/api/v1/admin/oidc-providers",
            Some(&boss),
            &[],
            Some(&provider_body("authentik", "https://other.example", false)),
        ))
        .await;
    assert_eq!(dup.status, 409, "duplicate slug: {:?}", dup.json);

    // Update with a blank secret keeps the stored one.
    let id = created.json["id"].as_str().unwrap();
    let mut edit = provider_body("authentik", "https://idp.example", true);
    edit["client_secret"] = json!("");
    edit["display_name"] = json!("Renamed");
    let updated = app
        .send(req(
            "PUT",
            &format!("/api/v1/admin/oidc-providers/{id}"),
            Some(&boss),
            &[],
            Some(&edit),
        ))
        .await;
    assert_eq!(updated.status, 200, "update: {:?}", updated.json);
    assert_eq!(updated.json["display_name"], json!("Renamed"));
    assert_eq!(
        updated.json["client_secret_set"],
        json!(true),
        "a blank secret must keep the stored one"
    );

    let del = app
        .send(delete_bearer(
            &format!("/api/v1/admin/oidc-providers/{id}"),
            &boss,
        ))
        .await;
    assert_eq!(del.status, 204);
    let gone = app
        .send(get_with_bearer("/api/v1/admin/oidc-providers", &boss))
        .await;
    assert_eq!(gone.json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn provider_rejects_an_issuer_url_that_could_not_work() {
    let app = TestApp::spawn_in_production().await;
    let r = app.register("boss@example.com", "boss", PW).await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "boss@example.com").await;
    let boss = app
        .login("boss@example.com", PW)
        .await
        .access_token()
        .unwrap();

    for bad in [
        "idp.example.com",              // no scheme
        "http://idp.example.com",       // plaintext, outside development
        "ftp://idp.example.com",        // wrong scheme
        "https://idp.example.com/?a=b", // discovery would drop the query
    ] {
        let r = app
            .send(req(
                "POST",
                "/api/v1/admin/oidc-providers",
                Some(&boss),
                &[],
                Some(&provider_body("p", bad, false)),
            ))
            .await;
        assert_eq!(r.status, 422, "should have refused {bad}: {:?}", r.json);
    }
}

#[tokio::test]
async fn test_endpoint_reports_an_unreachable_provider_without_failing() {
    let app = TestApp::spawn().await;
    let r = app.register("boss@example.com", "boss", PW).await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "boss@example.com").await;
    let boss = app
        .login("boss@example.com", PW)
        .await
        .access_token()
        .unwrap();

    let provider = seed_provider(&app, "dead", DEAD_ISSUER).await;
    let r = app
        .send(post_bearer(
            &format!("/api/v1/admin/oidc-providers/{}/test", provider.id),
            &boss,
        ))
        .await;
    // A finding to display, not an HTTP failure.
    assert_eq!(r.status, 200, "test: {:?}", r.json);
    assert_eq!(r.json["ok"], json!(false));
    assert!(r.json["message"].as_str().unwrap().len() > 5);
}

#[tokio::test]
async fn test_endpoint_reports_what_a_reachable_provider_publishes() {
    let app = TestApp::spawn().await;
    let idp = FakeIdp::spawn().await;
    let r = app.register("boss@example.com", "boss", PW).await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "boss@example.com").await;
    let boss = app
        .login("boss@example.com", PW)
        .await
        .access_token()
        .unwrap();

    let provider = seed_provider(&app, "fake", &idp.base).await;
    let r = app
        .send(post_bearer(
            &format!("/api/v1/admin/oidc-providers/{}/test", provider.id),
            &boss,
        ))
        .await;
    assert_eq!(r.status, 200, "test: {:?}", r.json);
    assert_eq!(r.json["ok"], json!(true), "test result: {:?}", r.json);
    assert_eq!(r.json["issuer"], json!(idp.base));
    assert_eq!(
        r.json["supports_device_flow"],
        json!(true),
        "the fake publishes a device endpoint"
    );
}

// ---------------------------------------------------------------------------
// Login screen configuration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_config_lists_only_enabled_providers_and_leaks_nothing() {
    let app = TestApp::spawn().await;

    // No providers configured: the field is present and empty, so a client can
    // rely on it without version-sniffing.
    let r = app.send(get("/api/v1/auth/config")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json["sso_providers"], json!([]));
    assert_eq!(r.json["local_password_login_disabled"], json!(false));

    let enabled = seed_provider(&app, "visible", "https://idp.example").await;
    let hidden = seed_provider(&app, "hidden", "https://idp.example").await;
    {
        let client = app.db.pool.get().await.unwrap();
        client
            .execute(
                "UPDATE oidc_providers SET enabled = false WHERE id = $1",
                &[&hidden.id],
            )
            .await
            .unwrap();
    }

    let r = app.send(get("/api/v1/auth/config")).await;
    let list = r.json["sso_providers"].as_array().unwrap();
    assert_eq!(list.len(), 1, "only the enabled provider: {:?}", r.json);
    assert_eq!(list[0]["slug"], json!(enabled.slug));
    let body = r.json.to_string();
    assert!(
        !body.contains("s3cret") && !body.contains("idp.example"),
        "the login screen must not learn the issuer or the secret: {body}"
    );
}

// ---------------------------------------------------------------------------
// Browser flow refusals
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_is_not_found_for_unknown_or_disabled_providers() {
    let app = TestApp::spawn().await;
    let r = app.send(get("/api/v1/auth/oidc/nope/start")).await;
    assert_eq!(r.status, 404);

    let hidden = seed_provider(&app, "hidden", "https://idp.example").await;
    {
        let client = app.db.pool.get().await.unwrap();
        client
            .execute(
                "UPDATE oidc_providers SET enabled = false WHERE id = $1",
                &[&hidden.id],
            )
            .await
            .unwrap();
    }
    let r = app.send(get("/api/v1/auth/oidc/hidden/start")).await;
    assert_eq!(
        r.status, 404,
        "a disabled provider must be indistinguishable from an absent one"
    );
}

#[tokio::test]
async fn start_redirects_to_the_provider_with_state_nonce_and_pkce() {
    let app = TestApp::spawn().await;
    let idp = FakeIdp::spawn().await;
    let _ = seed_provider(&app, "fake", &idp.base).await;

    let r = app
        .send(get("/api/v1/auth/oidc/fake/start?redirect_to=/projects/7"))
        .await;
    assert_eq!(r.status, 302, "start: {:?}", r.json);
    let location = r.header("location").expect("location header");
    assert!(
        location.starts_with(&format!("{}/authorize", idp.base)),
        "should redirect to the provider: {location}"
    );
    for expected in [
        "state=",
        "nonce=",
        "code_challenge=",
        "code_challenge_method=S256",
        "scope=",
    ] {
        assert!(
            location.contains(expected),
            "authorize URL missing {expected}: {location}"
        );
    }

    // The secrets stay server-side.
    let client = app.db.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT redirect_to, code_verifier, nonce, purpose FROM oidc_auth_requests",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("redirect_to"), "/projects/7");
    assert_eq!(row.get::<_, String>("purpose"), "login");
    assert!(!row.get::<_, String>("code_verifier").is_empty());
    assert!(
        !location.contains(&row.get::<_, String>("code_verifier")),
        "the PKCE verifier must never appear in the redirect"
    );
}

#[tokio::test]
async fn start_refuses_to_store_an_off_site_landing_target() {
    let app = TestApp::spawn().await;
    let idp = FakeIdp::spawn().await;
    let _ = seed_provider(&app, "fake", &idp.base).await;

    let r = app
        .send(get(
            "/api/v1/auth/oidc/fake/start?redirect_to=https://evil.example/steal",
        ))
        .await;
    assert_eq!(r.status, 302);
    let client = app.db.pool.get().await.unwrap();
    let stored: String = client
        .query_one("SELECT redirect_to FROM oidc_auth_requests", &[])
        .await
        .unwrap()
        .get("redirect_to");
    assert_eq!(
        stored, "/",
        "an off-site landing target must be discarded, not stored"
    );
}

#[tokio::test]
async fn start_reports_an_unreachable_provider_as_a_login_error() {
    let app = TestApp::spawn().await;
    let _ = seed_provider(&app, "dead", DEAD_ISSUER).await;

    let r = app.send(get("/api/v1/auth/oidc/dead/start")).await;
    assert_eq!(
        r.status, 302,
        "browsers get a redirect, never a JSON problem"
    );
    let location = r.header("location").unwrap();
    assert!(
        location.contains("/login?sso_error=oidc_unavailable"),
        "should bounce to the login page with a reason: {location}"
    );
}

#[tokio::test]
async fn callback_refuses_unknown_spent_and_expired_state() {
    let app = TestApp::spawn().await;
    let idp = FakeIdp::spawn().await;
    let _ = seed_provider(&app, "fake", &idp.base).await;

    // Never issued.
    let r = app
        .send(get("/api/v1/auth/oidc/fake/callback?code=x&state=made-up"))
        .await;
    assert_eq!(r.status, 302);
    assert!(
        r.header("location")
            .unwrap()
            .contains("sso_error=invalid_state"),
        "location: {:?}",
        r.header("location")
    );

    // Issued, then expired.
    let start = app.send(get("/api/v1/auth/oidc/fake/start")).await;
    assert_eq!(start.status, 302);
    let client = app.db.pool.get().await.unwrap();
    let state: String = client
        .query_one("SELECT state FROM oidc_auth_requests", &[])
        .await
        .unwrap()
        .get("state");
    client
        .execute(
            "UPDATE oidc_auth_requests SET expires_at = now() - interval '1 minute'",
            &[],
        )
        .await
        .unwrap();
    let r = app
        .send(get(&format!(
            "/api/v1/auth/oidc/fake/callback?code=x&state={state}"
        )))
        .await;
    assert!(
        r.header("location")
            .unwrap()
            .contains("sso_error=invalid_state"),
        "an expired state must read as invalid"
    );

    // And it is gone, so a second attempt cannot succeed either.
    let remaining: i64 = client
        .query_one("SELECT count(*) AS n FROM oidc_auth_requests", &[])
        .await
        .unwrap()
        .get("n");
    assert_eq!(remaining, 0, "claiming a state must consume the row");
}

#[tokio::test]
async fn callback_passes_the_providers_own_refusal_back_to_the_login_page() {
    let app = TestApp::spawn().await;
    let _ = seed_provider(&app, "fake", "https://idp.example").await;
    let r = app
        .send(get(
            "/api/v1/auth/oidc/fake/callback?error=access_denied&state=x",
        ))
        .await;
    assert_eq!(r.status, 302);
    assert!(
        r.header("location")
            .unwrap()
            .contains("sso_error=provider_refused")
    );
}

// ---------------------------------------------------------------------------
// User resolution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolution_provisions_a_new_user_and_pins_the_subject() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let client = app.db.pool.get().await.unwrap();

    let f = facts("subject-1", "new@example.com", true, &[]);
    let user_id = resolve::resolve_login(&client, &provider, &f)
        .await
        .expect("provisioning");

    let user = users::find_by_id(&client, user_id).await.unwrap().unwrap();
    assert_eq!(user.email, "new@example.com");
    assert_eq!(
        user.auth_source, "oidc",
        "a JIT account must be marked external so the password endpoints refuse it"
    );
    assert!(!user.must_change_password, "there is no password to rotate");
    assert!(
        !users::has_local_password(&client, user_id).await.unwrap(),
        "a JIT account must have no local password"
    );

    // The same subject with a *different* email still resolves to the same
    // account: the subject is the identity, the address is decoration.
    let moved = facts("subject-1", "renamed@example.com", true, &[]);
    let again = resolve::resolve_login(&client, &provider, &moved)
        .await
        .unwrap();
    assert_eq!(
        again, user_id,
        "identity must follow the subject, not the email"
    );
}

#[tokio::test]
async fn resolution_refuses_to_take_over_an_existing_account_by_email() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let _ = register_and_login(&app, "existing@example.com", "existing").await;
    let client = app.db.pool.get().await.unwrap();

    let f = facts("attacker-subject", "existing@example.com", true, &[]);
    let err = resolve::resolve_login(&client, &provider, &f)
        .await
        .expect_err("must not link on email alone");
    assert_eq!(err, ResolveError::EmailConflict);

    // And nothing was bound.
    assert!(
        oidc_identities::find_by_subject(&client, provider.id, "attacker-subject")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn resolution_requires_a_verified_email_before_provisioning() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let client = app.db.pool.get().await.unwrap();

    let f = facts("subject-2", "unverified@example.com", false, &[]);
    assert_eq!(
        resolve::resolve_login(&client, &provider, &f)
            .await
            .expect_err("unverified"),
        ResolveError::EmailUnverified
    );

    // With the requirement relaxed, the same claims provision.
    client
        .execute(
            "UPDATE oidc_providers SET require_email_verified = false WHERE id = $1",
            &[&provider.id],
        )
        .await
        .unwrap();
    let relaxed = oidc_providers::get(&client, provider.id)
        .await
        .unwrap()
        .unwrap();
    assert!(resolve::resolve_login(&client, &relaxed, &f).await.is_ok());
}

#[tokio::test]
async fn resolution_honours_provisioning_being_switched_off() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE oidc_providers SET allow_jit_provisioning = false WHERE id = $1",
            &[&provider.id],
        )
        .await
        .unwrap();
    let provider = oidc_providers::get(&client, provider.id)
        .await
        .unwrap()
        .unwrap();

    let f = facts("subject-3", "nobody@example.com", true, &[]);
    assert_eq!(
        resolve::resolve_login(&client, &provider, &f)
            .await
            .expect_err("provisioning off"),
        ResolveError::ProvisioningDisabled
    );
}

#[tokio::test]
async fn an_armed_window_links_an_existing_account_and_closes_behind_itself() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let _ = register_and_login(&app, "rescue@example.com", "rescue").await;
    let client = app.db.pool.get().await.unwrap();
    let existing = users::find_by_email_basic(&client, "rescue@example.com")
        .await
        .unwrap()
        .unwrap();

    // Without the window it is a conflict.
    let f = facts("rescue-subject", "rescue@example.com", true, &[]);
    assert_eq!(
        resolve::resolve_login(&client, &provider, &f)
            .await
            .expect_err("closed window"),
        ResolveError::EmailConflict
    );

    users::set_oidc_link_arm(
        &client,
        existing.id,
        Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1)),
    )
    .await
    .unwrap();

    let linked = resolve::resolve_login(&client, &provider, &f)
        .await
        .expect("armed link");
    assert_eq!(linked, existing.id);
    assert!(
        users::find_armed_link_by_email(&client, "rescue@example.com")
            .await
            .unwrap()
            .is_none(),
        "the window must be one-shot"
    );
    // The account keeps its local password and its auth_source.
    let after = users::find_by_id(&client, existing.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.auth_source, "local");
    assert!(
        users::has_local_password(&client, existing.id)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_expired_window_does_not_link() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let _ = register_and_login(&app, "late@example.com", "late").await;
    let client = app.db.pool.get().await.unwrap();
    let existing = users::find_by_email_basic(&client, "late@example.com")
        .await
        .unwrap()
        .unwrap();
    users::set_oidc_link_arm(
        &client,
        existing.id,
        Some(time::OffsetDateTime::now_utc() - time::Duration::minutes(1)),
    )
    .await
    .unwrap();

    let f = facts("late-subject", "late@example.com", true, &[]);
    assert_eq!(
        resolve::resolve_login(&client, &provider, &f)
            .await
            .expect_err("expired window"),
        ResolveError::EmailConflict
    );
}

#[tokio::test]
async fn a_subject_cannot_be_bound_to_two_accounts() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let _ = register_and_login(&app, "first@example.com", "first").await;
    let _ = register_and_login(&app, "second@example.com", "second").await;
    let client = app.db.pool.get().await.unwrap();
    let first = users::find_by_email_basic(&client, "first@example.com")
        .await
        .unwrap()
        .unwrap();
    let second = users::find_by_email_basic(&client, "second@example.com")
        .await
        .unwrap()
        .unwrap();

    let f = facts("shared-subject", "first@example.com", true, &[]);
    resolve::link_subject(&client, &provider, &f, first.id)
        .await
        .expect("first link");
    assert_eq!(
        resolve::link_subject(&client, &provider, &f, second.id)
            .await
            .expect_err("second link"),
        ResolveError::SubjectTaken
    );
}

#[tokio::test]
async fn banned_and_inactive_accounts_are_refused_after_resolution() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let client = app.db.pool.get().await.unwrap();
    let f = facts("subject-ban", "ban@example.com", true, &[]);
    let user_id = resolve::resolve_login(&client, &provider, &f)
        .await
        .unwrap();

    client
        .execute(
            "UPDATE users SET is_active = false WHERE id = $1",
            &[&user_id],
        )
        .await
        .unwrap();
    assert_eq!(
        resolve::check_account_usable(&client, user_id)
            .await
            .expect_err("inactive"),
        ResolveError::Inactive
    );

    // Signing in again must NOT quietly reactivate the account — which is
    // exactly what the LDAP path does, and deliberately is not repeated here.
    let again = resolve::resolve_login(&client, &provider, &f)
        .await
        .unwrap();
    assert_eq!(again, user_id);
    let after = users::find_by_id(&client, user_id).await.unwrap().unwrap();
    assert!(
        !after.is_active,
        "an OIDC sign-in must not undo a deactivation"
    );

    client
        .execute(
            "UPDATE users SET is_active = true, banned_at = now() WHERE id = $1",
            &[&user_id],
        )
        .await
        .unwrap();
    assert_eq!(
        resolve::check_account_usable(&client, user_id)
            .await
            .expect_err("banned"),
        ResolveError::Banned
    );
}

// ---------------------------------------------------------------------------
// Group → superadmin mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn group_membership_promotes_and_absence_demotes() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    // A second, permanent superadmin so the last-admin guard is not what is
    // being measured here.
    let r = app.register("keeper@example.com", "keeper", PW).await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "keeper@example.com").await;

    let mut client = app.db.pool.get().await.unwrap();

    let member = facts(
        "subject-admin",
        "admin@example.com",
        true,
        &["IntelliPilot Admins"],
    );
    let user_id = resolve::resolve_login(&client, &provider, &member)
        .await
        .unwrap();
    assert!(
        users::find_by_id(&client, user_id)
            .await
            .unwrap()
            .unwrap()
            .is_superadmin,
        "provisioning must apply the mapping straight away"
    );

    // Dropped from the group: the next sign-in demotes.
    let dropped = facts("subject-admin", "admin@example.com", true, &["Everyone"]);
    resolve::sync_superadmin(&mut client, &provider, &dropped, user_id).await;
    assert!(
        !users::find_by_id(&client, user_id)
            .await
            .unwrap()
            .unwrap()
            .is_superadmin
    );

    // And back again.
    resolve::sync_superadmin(&mut client, &provider, &member, user_id).await;
    assert!(
        users::find_by_id(&client, user_id)
            .await
            .unwrap()
            .unwrap()
            .is_superadmin
    );
}

#[tokio::test]
async fn group_sync_will_not_demote_the_last_superadmin() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let mut client = app.db.pool.get().await.unwrap();

    let member = facts(
        "only-admin",
        "only@example.com",
        true,
        &["IntelliPilot Admins"],
    );
    let user_id = resolve::resolve_login(&client, &provider, &member)
        .await
        .unwrap();
    assert!(
        users::find_by_id(&client, user_id)
            .await
            .unwrap()
            .unwrap()
            .is_superadmin
    );
    assert_eq!(users::count_active_superadmins(&client).await.unwrap(), 1);

    // A mistyped group name, or a provider that stopped emitting the claim,
    // must not be able to lock everyone out of the admin area.
    let dropped = facts("only-admin", "only@example.com", true, &[]);
    resolve::sync_superadmin(&mut client, &provider, &dropped, user_id).await;
    assert!(
        users::find_by_id(&client, user_id)
            .await
            .unwrap()
            .unwrap()
            .is_superadmin,
        "the last superadmin must survive a group-sync demotion"
    );
}

#[tokio::test]
async fn an_empty_superadmin_group_leaves_the_flag_alone() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let mut client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE oidc_providers SET superadmin_group = '' WHERE id = $1",
            &[&provider.id],
        )
        .await
        .unwrap();
    let provider = oidc_providers::get(&client, provider.id)
        .await
        .unwrap()
        .unwrap();

    let f = facts("subject-x", "x@example.com", true, &["IntelliPilot Admins"]);
    let user_id = resolve::resolve_login(&client, &provider, &f)
        .await
        .unwrap();
    assert!(
        !users::find_by_id(&client, user_id)
            .await
            .unwrap()
            .unwrap()
            .is_superadmin,
        "with the mapping disabled, group membership must grant nothing"
    );

    // Promoting locally must then survive a sign-in.
    users::promote_to_superadmin(&client, user_id)
        .await
        .unwrap();
    resolve::sync_superadmin(&mut client, &provider, &f, user_id).await;
    assert!(
        users::find_by_id(&client, user_id)
            .await
            .unwrap()
            .unwrap()
            .is_superadmin
    );
}

// ---------------------------------------------------------------------------
// Device flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_start_is_unavailable_when_the_provider_cannot_be_reached() {
    let app = TestApp::spawn().await;
    let _ = seed_provider(&app, "dead", DEAD_ISSUER).await;
    let r = app
        .send(req(
            "POST",
            "/api/v1/auth/oidc/dead/device/start",
            None,
            &[],
            None,
        ))
        .await;
    assert_eq!(
        r.status, 503,
        "an unreachable provider is a 503, never a 500: {:?}",
        r.json
    );
}

#[tokio::test]
async fn device_start_is_not_offered_when_the_provider_has_it_switched_off() {
    let app = TestApp::spawn().await;
    let idp = FakeIdp::spawn().await;
    let provider = seed_provider(&app, "fake", &idp.base).await;
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE oidc_providers SET device_flow_enabled = false WHERE id = $1",
            &[&provider.id],
        )
        .await
        .unwrap();

    let r = app
        .send(req(
            "POST",
            "/api/v1/auth/oidc/fake/device/start",
            None,
            &[],
            None,
        ))
        .await;
    assert_eq!(r.status, 404);
}

#[tokio::test]
async fn device_poll_rejects_an_unknown_token_and_enforces_the_interval() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", DEAD_ISSUER).await;

    let r = app
        .send(req(
            "POST",
            "/api/v1/auth/oidc/device/poll",
            None,
            &[],
            Some(&json!({ "poll_token": "never-issued" })),
        ))
        .await;
    assert_eq!(r.status, 401, "unknown poll token: {:?}", r.json);

    // Plant a request whose poll token we know, then poll it twice in a row.
    let raw = "poll-token-under-test";
    let hash = intellipilot_auth::refresh::hash_token(raw);
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO oidc_device_requests \
               (provider_id, device_code, user_code, verification_uri, interval_secs, \
                poll_token_hash, expires_at, last_polled_at) \
             VALUES ($1, 'dev-code', 'ABCD-EFGH', 'https://idp.example/device', 5, $2, \
                     now() + interval '10 minutes', now())",
            &[&provider.id, &hash],
        )
        .await
        .unwrap();

    let r = app
        .send(req(
            "POST",
            "/api/v1/auth/oidc/device/poll",
            None,
            &[],
            Some(&json!({ "poll_token": raw })),
        ))
        .await;
    assert_eq!(
        r.status, 429,
        "polling faster than the provider allows must be refused here, not passed on: {:?}",
        r.json
    );
}

// ---------------------------------------------------------------------------
// Back-channel logout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backchannel_logout_refuses_a_token_it_cannot_verify() {
    let app = TestApp::spawn().await;
    let idp = FakeIdp::spawn().await;
    let _ = seed_provider(&app, "fake", &idp.base).await;

    for token in [
        "",
        "not-a-jwt",
        "a.b",
        // Well-formed but unsigned: the classic `alg: none` forgery.
        "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIn0.",
    ] {
        let r = app
            .send(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/oidc/fake/backchannel-logout")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(format!("logout_token={token}")))
                    .unwrap(),
            )
            .await;
        assert_eq!(
            r.status, 400,
            "token {token:?} should have been refused: {:?}",
            r.json
        );
    }
}

#[tokio::test]
async fn backchannel_logout_is_not_found_for_an_unknown_provider() {
    let app = TestApp::spawn().await;
    let r = app
        .send(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/nope/backchannel-logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from("logout_token=x"))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, 404);
}

// ---------------------------------------------------------------------------
// Linked identities
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_user_can_list_and_unlink_their_identities_but_not_lock_themselves_out() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let token = register_and_login(&app, "linker@example.com", "linker").await;
    let client = app.db.pool.get().await.unwrap();
    let me = users::find_by_email_basic(&client, "linker@example.com")
        .await
        .unwrap()
        .unwrap();

    let empty = app
        .send(get_with_bearer("/api/v1/me/oidc/identities", &token))
        .await;
    assert_eq!(empty.status, 200);
    assert_eq!(empty.json.as_array().unwrap().len(), 0);

    let f = facts("linker-subject", "linker@example.com", true, &[]);
    resolve::link_subject(&client, &provider, &f, me.id)
        .await
        .unwrap();

    let listed = app
        .send(get_with_bearer("/api/v1/me/oidc/identities", &token))
        .await;
    let rows = listed.json.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["provider_slug"], json!("fake"));
    assert_eq!(rows[0]["subject"], json!("linker-subject"));

    // This account has a password, so unlinking is fine.
    let id = rows[0]["id"].as_str().unwrap();
    let r = app
        .send(delete_bearer(
            &format!("/api/v1/me/oidc/identities/{id}"),
            &token,
        ))
        .await;
    assert_eq!(r.status, 204, "unlink: {:?}", r.json);

    // Now make it the only way in and try again.
    resolve::link_subject(&client, &provider, &f, me.id)
        .await
        .unwrap();
    client
        .execute(
            "UPDATE users SET password_hash = NULL WHERE id = $1",
            &[&me.id],
        )
        .await
        .unwrap();
    let listed = app
        .send(get_with_bearer("/api/v1/me/oidc/identities", &token))
        .await;
    let id = listed.json[0]["id"].as_str().unwrap();
    let r = app
        .send(delete_bearer(
            &format!("/api/v1/me/oidc/identities/{id}"),
            &token,
        ))
        .await;
    assert_eq!(
        r.status, 409,
        "unlinking the only sign-in method must be refused: {:?}",
        r.json
    );
}

#[tokio::test]
async fn one_user_cannot_unlink_anothers_identity() {
    let app = TestApp::spawn().await;
    let provider = seed_provider(&app, "fake", "https://idp.example").await;
    let _ = register_and_login(&app, "owner@example.com", "owner").await;
    let intruder = register_and_login(&app, "intruder@example.com", "intruder").await;
    let client = app.db.pool.get().await.unwrap();
    let owner = users::find_by_email_basic(&client, "owner@example.com")
        .await
        .unwrap()
        .unwrap();
    let f = facts("owner-subject", "owner@example.com", true, &[]);
    resolve::link_subject(&client, &provider, &f, owner.id)
        .await
        .unwrap();
    let identity = oidc_identities::list_for_user(&client, owner.id)
        .await
        .unwrap()
        .remove(0);

    let r = app
        .send(delete_bearer(
            &format!("/api/v1/me/oidc/identities/{}", identity.identity.id),
            &intruder,
        ))
        .await;
    assert_eq!(r.status, 404, "must not be reachable across accounts");
    assert_eq!(
        oidc_identities::count_for_user(&client, owner.id)
            .await
            .unwrap(),
        1
    );
}

// ---------------------------------------------------------------------------
// The SSO-only switch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disabling_password_login_still_lets_the_break_glass_superadmin_in() {
    let app = TestApp::spawn().await;
    let _ = register_and_login(&app, "user@example.com", "user").await;
    let r = app.register("boss@example.com", "boss", PW).await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "boss@example.com").await;
    let boss = app
        .login("boss@example.com", PW)
        .await
        .access_token()
        .unwrap();

    let r = app
        .send(req(
            "PATCH",
            "/api/v1/admin/settings",
            Some(&boss),
            &[],
            Some(&json!({
                "open_registration": false,
                "local_password_login_disabled": true
            })),
        ))
        .await;
    assert_eq!(r.status, 200, "settings: {:?}", r.json);
    assert_eq!(r.json["local_password_login_disabled"], json!(true));

    // An ordinary account is refused, and told why.
    let denied = app.login("user@example.com", PW).await;
    assert_eq!(denied.status, 403, "ordinary login: {:?}", denied.json);
    assert_eq!(denied.json["code"], json!("local_login_disabled"));

    // The superadmin with a local password still gets in — this is the whole
    // reason the switch is safe to flip.
    let allowed = app.login("boss@example.com", PW).await;
    assert_eq!(
        allowed.status, 200,
        "break-glass superadmin must survive: {:?}",
        allowed.json
    );
    assert!(allowed.access_token().is_some());

    // And the login screen is told to hide the form.
    let cfg = app.send(get("/api/v1/auth/config")).await;
    assert_eq!(cfg.json["local_password_login_disabled"], json!(true));
}

#[tokio::test]
async fn a_settings_update_without_the_switch_leaves_it_untouched() {
    let app = TestApp::spawn().await;
    let r = app.register("boss@example.com", "boss", PW).await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "boss@example.com").await;
    let boss = app
        .login("boss@example.com", PW)
        .await
        .access_token()
        .unwrap();

    let on = app
        .send(req(
            "PATCH",
            "/api/v1/admin/settings",
            Some(&boss),
            &[],
            Some(&json!({ "open_registration": false, "local_password_login_disabled": true })),
        ))
        .await;
    assert_eq!(on.json["local_password_login_disabled"], json!(true));

    // A client written before V025 sends only `open_registration`. It must not
    // silently switch password login back on.
    let old_client = app
        .send(req(
            "PATCH",
            "/api/v1/admin/settings",
            Some(&boss),
            &[],
            Some(&json!({ "open_registration": true })),
        ))
        .await;
    assert_eq!(old_client.status, 200);
    assert_eq!(
        old_client.json["local_password_login_disabled"],
        json!(true),
        "an omitted switch must be left alone"
    );
}
