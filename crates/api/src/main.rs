//! IntelliPilot API binary entrypoint.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use intellipilot_api::state::{AttachmentConfig, DevToggles};
use intellipilot_api::{AppState, AuthConfig, AuthContext, Env, ReadyCheck, build_router};
use intellipilot_auth::AccessKey;
use intellipilot_auth::webauthn::{RpConfig, build as build_webauthn};
use intellipilot_db::{Db, DbConfig};
use intellipilot_mailer::{LoggingMailer, Mailer, NoopMailer};
use intellipilot_storage::LocalStorage;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::signal;

/// Readiness check that pings the database pool.
#[derive(Debug)]
struct DbReadyCheck {
    db: Db,
}

#[async_trait]
impl ReadyCheck for DbReadyCheck {
    fn name(&self) -> &'static str {
        "database"
    }
    async fn check(&self) -> Result<(), String> {
        self.db.ping().await.map_err(|e| e.to_string())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dotenv_result = dotenvy::dotenv();
    drop(dotenv_result);
    init_tracing();

    let env_str = std::env::var("INTELLIPILOT_ENV").unwrap_or_else(|_| "development".to_owned());
    let env = if env_str == "production" {
        Env::Production
    } else {
        Env::Development
    };
    let dev = DevToggles {
        fault_endpoints: env != Env::Production,
    };

    let mut builder = AppState::builder().dev_toggles(dev);

    // Wire identity/session features only when a database is configured.
    match std::env::var("INTELLIPILOT_DATABASE_URL") {
        Ok(url) => {
            let db = Db::connect(&DbConfig {
                url,
                ..DbConfig::default()
            })?;
            let access_key = build_access_key(env)?;
            let pepper = std::env::var("INTELLIPILOT_PASSWORD_PEPPER")
                .ok()
                .map(|p| Arc::new(p.into_bytes()));
            let mailer = build_mailer(env);
            let webauthn = Arc::new(build_webauthn(&rp_config())?);
            let attachments = build_attachments(env)?;

            let auth = AuthContext {
                db: db.clone(),
                access_key: Arc::new(access_key),
                pepper,
                mailer,
                webauthn,
                config: AuthConfig {
                    env,
                    cookie_secure: env == Env::Production,
                },
                attachments,
            };
            builder = builder
                .readiness_checks(vec![Arc::new(DbReadyCheck { db })])
                .auth_context(auth);
            tracing::info!("identity/session endpoints enabled");
        }
        Err(_) => {
            tracing::warn!(
                "INTELLIPILOT_DATABASE_URL not set; running health/docs only (no auth endpoints)"
            );
        }
    }

    let app = build_router(builder.build());

    let bind = std::env::var("INTELLIPILOT_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let addr: SocketAddr = bind.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, env = %env_str, "intellipilot listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Derive the 32-byte Paseto v4 local key from `INTELLIPILOT_PASETO_SECRET`
/// (SHA-256 of a high-entropy secret string). In development a fixed key is
/// used if unset, so the binary runs out of the box.
fn build_access_key(env: Env) -> Result<AccessKey, Box<dyn std::error::Error + Send + Sync>> {
    match std::env::var("INTELLIPILOT_PASETO_SECRET") {
        Ok(secret) => {
            let digest = Sha256::digest(secret.as_bytes());
            Ok(AccessKey::from_bytes(&digest)?)
        }
        Err(_) if env == Env::Development => {
            tracing::warn!("INTELLIPILOT_PASETO_SECRET not set; using a dev-only ephemeral key");
            Ok(AccessKey::from_bytes(&[0u8; 32])?)
        }
        Err(_) => Err("INTELLIPILOT_PASETO_SECRET must be set in production".into()),
    }
}

/// Build the attachment subsystem: local FS storage + size limit + a signing
/// key for download URLs.
fn build_attachments(
    env: Env,
) -> Result<AttachmentConfig, Box<dyn std::error::Error + Send + Sync>> {
    let dir = std::env::var("INTELLIPILOT_STORAGE_DIR")
        .unwrap_or_else(|_| "./data/attachments".to_owned());
    let max_bytes = std::env::var("INTELLIPILOT_ATTACHMENT_MAX_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(25 * 1024 * 1024);
    let signing_key = match std::env::var("INTELLIPILOT_ATTACHMENT_SECRET") {
        Ok(secret) => Sha256::digest(secret.as_bytes()).into(),
        Err(_) if env == Env::Development => {
            tracing::warn!("INTELLIPILOT_ATTACHMENT_SECRET not set; using a dev-only key");
            [7u8; 32]
        }
        Err(_) => return Err("INTELLIPILOT_ATTACHMENT_SECRET must be set in production".into()),
    };
    Ok(AttachmentConfig {
        storage: Arc::new(LocalStorage::new(dir)),
        max_bytes,
        signing_key: Arc::new(signing_key),
    })
}

/// WebAuthn relying-party config from env, defaulting to localhost for dev.
fn rp_config() -> RpConfig {
    let mut cfg = RpConfig::default();
    if let Ok(id) = std::env::var("INTELLIPILOT_RP_ID") {
        cfg.rp_id = id;
    }
    if let Ok(origin) = std::env::var("INTELLIPILOT_RP_ORIGIN") {
        cfg.rp_origin = origin;
    }
    if let Ok(name) = std::env::var("INTELLIPILOT_RP_NAME") {
        cfg.rp_name = name;
    }
    cfg
}

/// Mailgun is feature-gated and off by default. In development without a
/// mailer we use the logging mailer; otherwise the no-op mailer (endpoints
/// that need email surface the token directly in dev, or 503 in prod).
fn build_mailer(env: Env) -> Arc<dyn Mailer> {
    if env == Env::Development {
        Arc::new(LoggingMailer)
    } else {
        Arc::new(NoopMailer)
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt::format::FmtSpan;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,intellipilot=debug"));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_current_span(true)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let result = signal::ctrl_c().await;
        drop(result);
    };
    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler; SIGINT only");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT"),
        () = terminate => tracing::info!("received SIGTERM"),
    }
    tracing::info!("shutting down");
}
