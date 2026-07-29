//! Shared application state.

use std::sync::Arc;

use async_trait::async_trait;
use intellipilot_auth::AccessKey;
use intellipilot_db::Db;
use intellipilot_mailer::Mailer;
use intellipilot_storage::Storage;
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
        }
    }
}
