//! Shared application state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use intellipilot_auth::AccessKey;
use intellipilot_db::Db;
use intellipilot_mailer::Mailer;
use intellipilot_storage::Storage;
use uuid::Uuid;
use webauthn_rs::Webauthn;

/// Attachment subsystem configuration.
#[derive(Clone)]
pub struct AttachmentConfig {
    /// Backing object store.
    pub storage: Arc<dyn Storage>,
    /// Maximum upload size in bytes (default 25 MiB).
    pub max_bytes: u64,
    /// HMAC key for signing short-lived download URLs.
    pub signing_key: Arc<[u8; 32]>,
}

impl std::fmt::Debug for AttachmentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentConfig")
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

/// External documentation subsystem configuration.
///
/// Also owns the per-source lock registry: a clone/fetch and an edit on the
/// same cached repository must never run concurrently, or one would commit on
/// top of a ref the other is rewriting.
#[derive(Clone)]
pub struct DocsConfig {
    /// Root under which each source gets its own bare repository.
    pub cache_dir: Arc<PathBuf>,
    /// Cap on bytes transferred for one source's clone or fetch.
    pub max_source_bytes: u64,
    /// Cap on the size of a single file served or saved.
    pub max_file_bytes: u64,
    /// How often the background refresher revisits every source.
    pub sync_interval: Duration,
    /// Smallest gap between two sync attempts on one source. Rate-limits the
    /// manual refresh button and keeps two workers off the same repository.
    pub min_sync_gap: Duration,
    locks: Arc<Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>>,
}

impl DocsConfig {
    /// Build a configuration rooted at `cache_dir`, with the documented
    /// defaults for every limit.
    #[must_use]
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir: Arc::new(cache_dir),
            max_source_bytes: 500 * 1024 * 1024,
            max_file_bytes: 10 * 1024 * 1024,
            sync_interval: Duration::from_secs(900),
            min_sync_gap: Duration::from_secs(60),
            locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Cache directory of one source. Namespaced by project so a support
    /// engineer can find everything belonging to one project at a glance.
    #[must_use]
    pub fn dir_for(&self, project_id: Uuid, source_id: Uuid) -> PathBuf {
        self.cache_dir
            .join(project_id.to_string())
            .join(format!("{source_id}.git"))
    }

    /// The mutex guarding one source's cache. Entries are created on demand
    /// and kept for the process lifetime — one small allocation per source
    /// ever touched, which is bounded by 10 per project.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn lock_for(&self, source_id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        let mut guard = self
            .locks
            .lock()
            .expect("docs lock registry poisoned: a holder panicked");
        Arc::clone(guard.entry(source_id).or_default())
    }

    /// Forget a deleted source's lock so the registry does not grow without
    /// bound in a long-lived process.
    #[allow(clippy::expect_used)]
    pub fn forget_lock(&self, source_id: Uuid) {
        self.locks
            .lock()
            .expect("docs lock registry poisoned: a holder panicked")
            .remove(&source_id);
    }
}

impl std::fmt::Debug for DocsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocsConfig")
            .field("cache_dir", &self.cache_dir)
            .field("max_source_bytes", &self.max_source_bytes)
            .field("max_file_bytes", &self.max_file_bytes)
            .field("sync_interval", &self.sync_interval)
            .finish_non_exhaustive()
    }
}

/// Per-deployment toggle for endpoints that exist only to support tests and
/// local dev (e.g. `/_fault/panic`). Off in production.
#[derive(Debug, Clone, Copy)]
pub struct DevToggles {
    pub fault_endpoints: bool,
}

impl Default for DevToggles {
    /// Defaults to enabled so test code that uses [`AppState::builder`]
    /// without overrides gets the dev surface for free. The production
    /// binary explicitly disables them.
    fn default() -> Self {
        Self {
            fault_endpoints: true,
        }
    }
}

/// Deployment environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Env {
    Development,
    Production,
}

impl Env {
    #[must_use]
    pub fn is_dev(self) -> bool {
        matches!(self, Self::Development)
    }
}

/// Auth/session configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub env: Env,
    /// Set the `Secure` attribute on the refresh cookie. Should be true in
    /// production (TLS); may be false for local http dev.
    pub cookie_secure: bool,
    /// The origin browsers reach this deployment on, e.g.
    /// `https://pilot.example.com` (V025).
    ///
    /// Only OIDC needs it, and it exists as configuration rather than being
    /// read off the request because the redirect URI must match what is
    /// registered at the identity provider byte for byte — and because a
    /// `Host` header is attacker-controlled, so letting it shape the redirect
    /// URI would be a way to steal authorization codes. Sourced from
    /// `INTELLIPILOT_PUBLIC_URL`, falling back to `INTELLIPILOT_RP_ORIGIN`,
    /// which a deployment using passkeys has already had to set correctly.
    pub public_origin: String,
}

/// Everything the auth + identity endpoints need. Absent for Phase 0-only
/// routers (health/openapi), present once a database is wired.
#[derive(Clone)]
pub struct AuthContext {
    pub db: Db,
    pub access_key: Arc<AccessKey>,
    pub pepper: Option<Arc<Vec<u8>>>,
    pub mailer: Arc<dyn Mailer>,
    pub webauthn: Arc<Webauthn>,
    pub config: AuthConfig,
    pub attachments: AttachmentConfig,
}

impl AuthContext {
    /// The server pepper as a byte slice, if configured.
    #[must_use]
    pub fn pepper_bytes(&self) -> Option<&[u8]> {
        self.pepper.as_deref().map(Vec::as_slice)
    }
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthContext")
            .field("config", &self.config)
            .field("has_pepper", &self.pepper.is_some())
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait ReadyCheck: Send + Sync + 'static + std::fmt::Debug {
    /// Stable identifier used as the JSON key under `checks` in the readiness
    /// response. Must be `[a-z0-9_]+`.
    fn name(&self) -> &'static str;

    /// `Ok(())` if the dependency is healthy, `Err(msg)` otherwise.
    async fn check(&self) -> Result<(), String>;
}

#[derive(Clone)]
pub struct AppState {
    pub readiness: Arc<Vec<Arc<dyn ReadyCheck>>>,
    pub dev: DevToggles,
    pub auth: Option<AuthContext>,
    /// In-process change-feed bus backing the per-project SSE endpoint.
    pub events: Arc<crate::events::EventBus>,
    /// Cached account status + last-activity stamping (V018).
    pub presence: crate::presence::Presence,
    /// Local IP geolocation. Always present; inert until a superadmin enables
    /// it and a database is installed.
    pub geoip: Arc<crate::geoip::GeoIp>,
    /// External documentation caches, limits and per-source locks.
    pub docs: DocsConfig,
    /// Cached OIDC provider discovery documents and JWKS (V025). Inert until a
    /// superadmin configures a provider.
    pub oidc: crate::oidc::OidcCache,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("readiness_count", &self.readiness.len())
            .field("dev", &self.dev)
            .field("has_auth", &self.auth.is_some())
            .finish_non_exhaustive()
    }
}

impl AppState {
    #[must_use]
    pub fn builder() -> AppStateBuilder {
        AppStateBuilder::default()
    }

    /// Access the auth context, or panic — only call from routes that are
    /// mounted exclusively when auth is configured.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn auth(&self) -> &AuthContext {
        self.auth
            .as_ref()
            .expect("auth context must be present for auth routes")
    }
}

#[derive(Default)]
pub struct AppStateBuilder {
    readiness: Vec<Arc<dyn ReadyCheck>>,
    dev: DevToggles,
    auth: Option<AuthContext>,
    geoip: Option<Arc<crate::geoip::GeoIp>>,
    docs: Option<DocsConfig>,
}

impl std::fmt::Debug for AppStateBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStateBuilder")
            .field("readiness_count", &self.readiness.len())
            .field("dev", &self.dev)
            .field("has_auth", &self.auth.is_some())
            .finish_non_exhaustive()
    }
}

impl AppStateBuilder {
    #[must_use]
    pub fn readiness_checks(mut self, checks: Vec<Arc<dyn ReadyCheck>>) -> Self {
        self.readiness = checks;
        self
    }

    #[must_use]
    pub fn dev_toggles(mut self, dev: DevToggles) -> Self {
        self.dev = dev;
        self
    }

    #[must_use]
    pub fn auth_context(mut self, auth: AuthContext) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Override the geolocation subsystem. Tests use this to point at a
    /// temporary directory; the binary supplies the storage-backed one.
    #[must_use]
    pub fn geoip(mut self, geoip: Arc<crate::geoip::GeoIp>) -> Self {
        self.geoip = Some(geoip);
        self
    }

    /// Override the documentation-cache configuration. Tests point this at a
    /// temporary directory; the binary derives it from the storage root.
    #[must_use]
    pub fn docs(mut self, docs: DocsConfig) -> Self {
        self.docs = Some(docs);
        self
    }

    #[must_use]
    pub fn build(self) -> AppState {
        AppState {
            readiness: Arc::new(self.readiness),
            dev: self.dev,
            auth: self.auth,
            events: Arc::new(crate::events::EventBus::default()),
            presence: crate::presence::Presence::default(),
            geoip: self.geoip.unwrap_or_else(|| {
                // Disabled with no database: harmless, and the binary replaces
                // it during startup.
                Arc::new(crate::geoip::GeoIp::new(std::path::PathBuf::from(
                    "geoip-unconfigured",
                )))
            }),
            docs: self
                .docs
                .unwrap_or_else(|| DocsConfig::new(PathBuf::from("doc-cache-unconfigured"))),
            oidc: crate::oidc::OidcCache::default(),
        }
    }
}
