//! Shared helpers for Phase 1 integration tests.
//!
//! Each test gets a router backed by an isolated Postgres schema (via
//! `TestDb`). Requires a reachable Postgres (`INTELLIPILOT_TEST_DB_URL`).
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::option_if_let_else
)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response};
use http_body_util::BodyExt;
use intellipilot_api::state::{AttachmentConfig, DocsConfig};
use intellipilot_api::{AppState, AuthConfig, AuthContext, Env, build_router};
use intellipilot_auth::AccessKey;
use intellipilot_db::Db;
use intellipilot_mailer::NoopMailer;
use intellipilot_storage::LocalStorage;
use intellipilot_testkit::TestDb;
use serde_json::Value;
use tower::ServiceExt;

pub struct TestApp {
    pub router: Router,
    // Held to keep the schema alive for the duration of the test.
    pub db: TestDb,
    /// The same storage instance wired into the router (for GC tests).
    pub storage: Arc<dyn intellipilot_storage::Storage>,
    /// The same live-event bus the router publishes to, so tests can subscribe
    /// and assert what a change broadcasts.
    pub events: Arc<intellipilot_api::events::EventBus>,
    /// The same documentation-cache configuration the router uses, so tests
    /// can seed a bare repository where a handler will look for it.
    pub docs: DocsConfig,
}

impl TestApp {
    pub async fn spawn() -> Self {
        Self::spawn_with_attachment_limit(25 * 1024 * 1024).await
    }

    pub async fn spawn_with_attachment_limit(max_bytes: u64) -> Self {
        Self::spawn_configured(max_bytes, Env::Development).await
    }

    /// A production-env app. Needed wherever a dev-only escape hatch would
    /// otherwise mask the behaviour under test — the refresh token is echoed
    /// into every response body in development, so anything about who receives
    /// it can only be pinned here.
    pub async fn spawn_in_production() -> Self {
        Self::spawn_configured(25 * 1024 * 1024, Env::Production).await
    }

    pub async fn spawn_configured(max_bytes: u64, env: Env) -> Self {
        let db = TestDb::new().await;
        let app_db = Db {
            pool: db.pool.clone(),
        };
        let access_key = AccessKey::from_bytes(&[42u8; 32]).expect("32-byte key");
        let webauthn = Arc::new(
            intellipilot_auth::webauthn::build(&intellipilot_auth::webauthn::RpConfig::default())
                .expect("build webauthn"),
        );
        let storage: Arc<dyn intellipilot_storage::Storage> = Arc::new(LocalStorage::new(
            std::env::temp_dir().join(format!("ip-test-att-{}", uuid::Uuid::now_v7())),
        ));
        let auth = AuthContext {
            db: app_db,
            access_key: Arc::new(access_key),
            // A pepper is configured so TOTP/secret-encryption paths are
            // exercised in tests.
            pepper: Some(Arc::new(b"test-pepper-value-at-least-32bytes!!".to_vec())),
            mailer: Arc::new(NoopMailer),
            webauthn,
            config: AuthConfig {
                env,
                cookie_secure: false,
            },
            attachments: AttachmentConfig {
                storage: storage.clone(),
                max_bytes,
                signing_key: Arc::new([7u8; 32]),
            },
        };
        let docs = DocsConfig::new(
            std::env::temp_dir().join(format!("ip-test-docs-{}", uuid::Uuid::now_v7())),
        );
        let state = AppState::builder()
            .auth_context(auth)
            .docs(docs.clone())
            .build();
        let events = state.events.clone();
        let router = build_router(state);
        // The suite predates the V011 registration gate, whose migration
        // defaults `open_registration` to false. Open it so the shared
        // register -> login setup works everywhere; the platform-admin tests
        // that exercise the gate toggle it explicitly themselves.
        {
            let client = db.pool.get().await.expect("db client");
            client
                .execute(
                    "UPDATE platform_settings SET open_registration = true WHERE id = 1",
                    &[],
                )
                .await
                .expect("enable open registration for tests");
        }
        Self {
            router,
            db,
            storage,
            events,
            docs,
        }
    }

    /// Issue a request, returning (status, json-or-null, set-cookie values).
    pub async fn send(&self, req: Request<Body>) -> TestResponse {
        let resp: Response<Body> = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let cookies: Vec<String> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        let retry_after = resp
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let headers: std::collections::HashMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_owned(), s.to_owned()))
            })
            .collect();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        TestResponse {
            status,
            json,
            cookies,
            retry_after,
            headers,
        }
    }

    pub async fn register(&self, email: &str, username: &str, password: &str) -> TestResponse {
        self.send(json_post(
            "/api/v1/auth/register",
            &serde_json::json!({
                "email": email, "username": username, "password": password, "full_name": "Test"
            }),
        ))
        .await
    }

    pub async fn login(&self, email: &str, password: &str) -> TestResponse {
        self.send(json_post(
            "/api/v1/auth/login",
            &serde_json::json!({ "email": email, "password": password }),
        ))
        .await
    }
}

pub struct TestResponse {
    pub status: u16,
    pub json: Value,
    pub cookies: Vec<String>,
    pub retry_after: Option<String>,
    pub headers: std::collections::HashMap<String, String>,
}

impl TestResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

impl TestResponse {
    pub fn access_token(&self) -> Option<String> {
        self.json
            .get("access_token")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    pub fn dev_refresh(&self) -> Option<String> {
        self.json
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
}

pub fn json_post(uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// Build a `multipart/form-data` POST with a single `file` field.
pub fn multipart_upload(uri: &str, token: &str, filename: &str, content: &[u8]) -> Request<Body> {
    let boundary = "----intellipilottestboundary";
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
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap()
}

/// Read a download response body as raw bytes (after `send` is not used; this
/// issues the request directly to keep the bytes intact).
impl TestApp {
    pub async fn download_bytes(
        &self,
        req: Request<Body>,
    ) -> (u16, std::collections::HashMap<String, String>, Vec<u8>) {
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let headers: std::collections::HashMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_owned(), s.to_owned()))
            })
            .collect();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, headers, bytes)
    }
}

/// Flexible request builder with bearer + arbitrary headers + optional JSON.
pub fn req(
    method: &str,
    uri: &str,
    token: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: Option<&Value>,
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in extra_headers {
        b = b.header(*k, *v);
    }
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(serde_json::to_vec(v).unwrap())
        }
        None => Body::empty(),
    };
    b.body(body).unwrap()
}

pub fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

pub fn get_with_bearer(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

pub fn post_json_bearer(uri: &str, token: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

pub fn patch_json_bearer(uri: &str, token: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

pub fn post_bearer(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

pub fn delete_bearer(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

pub fn post_with_cookie(uri: &str, refresh: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", format!("refresh_token={refresh}"))
        .body(Body::empty())
        .unwrap()
}

/// Skip a DB-backed test gracefully when no Postgres is configured/reachable
/// locally. CI always provides one, so this only affects ad-hoc local runs.
#[macro_export]
macro_rules! require_db {
    () => {{
        if std::env::var("INTELLIPILOT_TEST_DB_URL").is_err()
            && std::env::var("DATABASE_URL").is_err()
        {
            eprintln!("skipping: no INTELLIPILOT_TEST_DB_URL / DATABASE_URL set");
            return;
        }
    }};
}
