//! Postgres data-access layer over `tokio-postgres` + `deadpool-postgres`.
//!
//! Deliberately does NOT use sqlx — see workspace `Cargo.toml` for the
//! security rationale (sqlx-core pulls in `paste` and `rsa`).

pub mod attachments;
pub mod audit;
pub mod backlog;
pub mod comments;
pub mod components;
pub mod history;
pub mod idempotency;
pub mod invitations;
pub mod labels;
pub mod ldap_settings;
pub mod login_attempts;
pub mod memberships;
pub mod migrations;
pub mod milestones;
pub mod notification_settings;
pub mod password_reset;
pub mod platform_invitations;
pub mod platform_settings;
pub mod projects;
pub mod recovery;
pub mod roles;
pub mod search;
pub mod sessions;
pub mod taxonomy;
pub mod users;
pub mod webauthn;
pub mod wiki;

use std::time::Duration;

use deadpool_postgres::{ManagerConfig, Pool, PoolError, RecyclingMethod, Runtime};
use thiserror::Error;
use tokio_postgres::NoTls;
use tokio_postgres::error::SqlState;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("postgres error: {0}")]
    Postgres(#[from] tokio_postgres::Error),
    #[error("pool error: {0}")]
    Pool(#[from] PoolError),
    #[error("pool build error: {0}")]
    Build(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl DbError {
    /// True when the error is a unique-constraint violation (SQLSTATE 23505).
    #[must_use]
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, Self::Postgres(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION))
    }
}

#[derive(Debug, Clone)]
pub struct DbConfig {
    pub url: String,
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: "postgres://localhost/intellipilot".to_owned(),
            max_connections: 16,
            acquire_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Db {
    pub pool: Pool,
}

impl Db {
    /// Connect using `NoTls`. Phase 1 ships NoTls; a TLS-aware constructor is
    /// a small follow-up once deployment TLS config is finalized.
    pub fn connect(cfg: &DbConfig) -> Result<Self, DbError> {
        let pg_config: tokio_postgres::Config = cfg.url.parse()?;
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = deadpool_postgres::Manager::from_config(pg_config, NoTls, mgr_config);
        let pool = Pool::builder(mgr)
            .max_size(cfg.max_connections as usize)
            .runtime(Runtime::Tokio1)
            .wait_timeout(Some(cfg.acquire_timeout))
            .build()
            .map_err(|e| DbError::Build(e.to_string()))?;
        Ok(Self { pool })
    }

    /// Returns `Ok(())` if the database responds. Used by `/health/ready`.
    pub async fn ping(&self) -> Result<(), DbError> {
        let client = self.pool.get().await?;
        client.simple_query("SELECT 1").await?;
        Ok(())
    }
}
