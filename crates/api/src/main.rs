//! IntelliPilot API binary entrypoint.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use intellipilot_api::state::{AttachmentConfig, DevToggles};
use intellipilot_api::{AppState, AuthConfig, AuthContext, Env, ReadyCheck, build_router};
use intellipilot_auth::AccessKey;
use intellipilot_auth::password::hash_password;
use intellipilot_auth::webauthn::{RpConfig, build as build_webauthn};
use intellipilot_core::user::{NewUser, NewUserWithFlags};
use intellipilot_db::users;
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
            // Apply any pending refinery migrations before opening the pool —
            // bootstrap and identity code below assumes the schema is current.
            //
            // Log failures via the error's Display (one concise line) and exit,
            // rather than returning the error to `main` — a returned `Err` is
            // Debug-printed by the runtime, and refinery's Debug embeds the
            // full migration SQL, dumping the entire schema into the logs.
            let report = match intellipilot_db::migrations::apply(&url).await {
                Ok(report) => report,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "database migration failed; refusing to start. If the \
                         single V001 migration changed after this database was \
                         created, the schema must be reset or reconciled."
                    );
                    std::process::exit(1);
                }
            };
            tracing::info!(
                applied = report.applied_migrations().len(),
                "db migrations applied"
            );

            let db = Db::connect(&DbConfig {
                url,
                ..DbConfig::default()
            })?;
            let access_key = build_access_key(env)?;
            let pepper = std::env::var("INTELLIPILOT_PASSWORD_PEPPER")
                .ok()
                .map(|p| Arc::new(p.into_bytes()));

            bootstrap_superadmin(&db, pepper.as_deref().map(Vec::as_slice), env).await?;
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
            // Geolocation: restore the configured state and any installed
            // database, then start the monthly refresh. All of it is inert
            // unless a superadmin has switched the feature on.
            let geoip = Arc::new(build_geoip());
            init_geoip(&db, &geoip).await;
            spawn_geoip_refresher(db.clone(), Arc::clone(&geoip));

            builder = builder
                .readiness_checks(vec![Arc::new(DbReadyCheck { db })])
                .auth_context(auth)
                .geoip(geoip);
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

/// Bootstrap an initial superadmin from environment variables (V011).
///
/// Behaviour:
///   * If `INTELLIPILOT_BOOTSTRAP_ADMIN_EMAIL` names an existing user, promote
///     that user to `is_superadmin = true`. The password is **never** touched.
///   * If no such user exists and `INTELLIPILOT_BOOTSTRAP_ADMIN_PASSWORD` is
///     also set, create a fresh superadmin with those credentials.
///   * If the env vars are unset:
///       - production with no existing superadmin → refuse to start.
///       - development with no existing superadmin → warn and continue.
///       - any env with at least one existing superadmin → silent no-op.
///
/// Idempotent across reboots: re-running with the same env + DB is a no-op
/// because the second pass finds the user already marked as superadmin.
async fn bootstrap_superadmin(
    db: &Db,
    pepper: Option<&[u8]>,
    env: Env,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let email = std::env::var("INTELLIPILOT_BOOTSTRAP_ADMIN_EMAIL")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let password = std::env::var("INTELLIPILOT_BOOTSTRAP_ADMIN_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty());
    // A present-but-empty value (`VAR=` in a .env file) must behave as "unset"
    // so the email-local-part fallback kicks in instead of an empty name.
    let username_opt = std::env::var("INTELLIPILOT_BOOTSTRAP_ADMIN_USERNAME")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let full_name_opt = std::env::var("INTELLIPILOT_BOOTSTRAP_ADMIN_FULL_NAME")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    let client = db.pool.get().await?;
    let existing_admins = users::count_active_superadmins(&client).await?;

    let Some(email_raw) = email else {
        if existing_admins == 0 {
            if env == Env::Production {
                return Err(
                    "no superadmin exists and INTELLIPILOT_BOOTSTRAP_ADMIN_EMAIL is unset \
                     — production refuses to start with no admin path"
                        .into(),
                );
            }
            tracing::warn!(
                "no superadmin exists and INTELLIPILOT_BOOTSTRAP_ADMIN_EMAIL is unset; \
                 /api/v1/admin/* will be unreachable until one is created manually"
            );
        }
        return Ok(());
    };

    let normalized = users::normalize_email(&email_raw);

    if let Some(existing) = users::find_by_email_with_secret(&client, &normalized).await? {
        if existing.user.is_superadmin {
            tracing::info!(email = %normalized, "bootstrap: user already superadmin, no-op");
        } else {
            users::promote_to_superadmin(&client, existing.user.id).await?;
            tracing::warn!(
                email = %normalized,
                user_id = %existing.user.id,
                "bootstrap: existing user promoted to superadmin"
            );
        }
        return Ok(());
    }

    // User does not exist — we have to create one, which requires a password.
    let Some(password) = password else {
        return Err(format!(
            "bootstrap: no user with email '{normalized}' exists and \
             INTELLIPILOT_BOOTSTRAP_ADMIN_PASSWORD is unset; cannot create one"
        )
        .into());
    };

    let username = username_opt.unwrap_or_else(|| {
        normalized
            .split('@')
            .next()
            .unwrap_or(&normalized)
            .to_owned()
    });
    let full_name = full_name_opt.unwrap_or_else(|| username.clone());
    let password_hash = hash_password(&password, pepper)?;

    let created = users::create_with_flags(
        &client,
        &NewUserWithFlags {
            new: NewUser {
                email: normalized.clone(),
                username,
                full_name,
                password_hash,
            },
            is_superadmin: true,
            must_change_password: false,
        },
    )
    .await?;
    tracing::warn!(
        email = %normalized,
        user_id = %created.id,
        "bootstrap: created superadmin from env"
    );
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

/// How often the refresher wakes to consider a monthly update.
///
/// The data is published monthly, so this only needs to be often enough to
/// notice a new build within a day and to recover from a failed attempt.
const GEOIP_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// Where the `.mmdb` lives: a `geoip` subdirectory of the storage root.
fn build_geoip() -> intellipilot_api::geoip::GeoIp {
    let root = std::env::var("INTELLIPILOT_STORAGE_DIR")
        .unwrap_or_else(|_| "./data/attachments".to_owned());
    intellipilot_api::geoip::GeoIp::new(std::path::PathBuf::from(root).join("geoip"))
}

/// Restore the enabled flag and load the installed database, if any.
///
/// Failures are logged and swallowed: geolocation is a display nicety, and a
/// missing or corrupt database must never stop the server from starting.
async fn init_geoip(db: &Db, geoip: &intellipilot_api::geoip::GeoIp) {
    let Ok(client) = db.pool.get().await else {
        return;
    };
    match intellipilot_db::platform_settings::get(&client).await {
        Ok(settings) => geoip.set_enabled(settings.geoip_enabled),
        Err(e) => {
            tracing::warn!(error = %e, "could not read geoip settings");
            return;
        }
    }
    let Ok(meta) = intellipilot_db::geoip::get(&client).await else {
        return;
    };
    let Some(rel) = meta.file_path.as_deref() else {
        return;
    };
    let path = geoip.dir().join(rel);
    match geoip.load(&path) {
        Ok(()) => {
            tracing::info!(
                variant = meta.variant.as_deref().unwrap_or("?"),
                build = meta.build_month.as_deref().unwrap_or("?"),
                "geoip database loaded"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "could not load geoip database");
        }
    }
}

/// Refresh the geolocation database monthly.
///
/// Runs on a timer rather than a calendar: it wakes every few hours, and the
/// month comparison inside `Updater::update` decides whether there is anything
/// to do. That makes a missed window (server down on the 1st) self-healing.
fn spawn_geoip_refresher(db: Db, geoip: Arc<intellipilot_api::geoip::GeoIp>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(GEOIP_CHECK_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(e) = geoip_refresh_once(&db, &geoip).await {
                tracing::warn!(error = %e, "scheduled geoip refresh failed");
            }
        }
    });
}

async fn geoip_refresh_once(
    db: &Db,
    geoip: &intellipilot_api::geoip::GeoIp,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = db.pool.get().await?;
    let settings = intellipilot_db::platform_settings::get(&client).await?;
    // Both switches must be on. Keep the cached flag in step while we are here,
    // which also picks up a change made on another instance.
    geoip.set_enabled(settings.geoip_enabled);
    if !settings.geoip_enabled || !settings.geoip_auto_update {
        return Ok(());
    }

    // Skip if an admin's manual update is already running.
    if !intellipilot_db::geoip::try_lock_download(&client).await? {
        tracing::debug!("geoip refresh skipped; another update holds the lock");
        return Ok(());
    }

    let meta = intellipilot_db::geoip::get(&client).await?;
    let variant = intellipilot_api::geoip::Variant::parse(&settings.geoip_variant);
    // A variant change forces a download even when the month matches.
    let installed_month = (meta.variant.as_deref() == Some(variant.as_str()))
        .then_some(meta.build_month.clone())
        .flatten();

    let base_url = std::env::var("INTELLIPILOT_GEOIP_BASE_URL")
        .unwrap_or_else(|_| intellipilot_api::geoip::DEFAULT_BASE_URL.to_owned());
    let result = intellipilot_api::geoip::Updater::new(base_url)
        .update(
            geoip,
            variant,
            installed_month.as_deref(),
            false,
            time::OffsetDateTime::now_utc(),
        )
        .await;
    intellipilot_db::geoip::unlock_download(&client).await;

    match result {
        Ok(intellipilot_api::geoip::UpdateOutcome::Installed {
            variant,
            build_month,
            file_size,
            sha256,
        }) => {
            intellipilot_db::geoip::set_installed(
                &client,
                variant.as_str(),
                &build_month,
                &format!("dbip-{}-{build_month}.mmdb", variant.as_str()),
                file_size,
                &sha256,
                "download",
            )
            .await?;
            tracing::info!(variant = variant.as_str(), build = %build_month, "geoip database updated");
        }
        Ok(intellipilot_api::geoip::UpdateOutcome::AlreadyCurrent) => {
            intellipilot_db::geoip::mark_checked(&client).await?;
        }
        Err(e) => {
            // Recorded rather than only logged, so the admin card shows a
            // refresh that has been quietly failing for months.
            intellipilot_db::geoip::mark_error(&client, &e.to_string()).await?;
            return Err(Box::new(e));
        }
    }
    Ok(())
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
