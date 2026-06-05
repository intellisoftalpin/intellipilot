//! Embedded refinery migrations. SQL files in `crates/db/migrations/`.
//!
//! All migrations run in the current `search_path`; production deployments
//! leave it at `public`, tests redirect into a per-test schema.

use thiserror::Error;
use tokio_postgres::{Client, NoTls};

#[derive(Debug, Error)]
pub enum MigrateError {
    #[error("migration error: {0}")]
    Refinery(#[from] refinery::Error),
    #[error("postgres error: {0}")]
    Postgres(#[from] tokio_postgres::Error),
}

mod embedded {
    refinery::embed_migrations!("./migrations");
}

/// Run all pending migrations against the given client. Idempotent.
pub async fn run(client: &mut Client) -> Result<refinery::Report, MigrateError> {
    let report = embedded::migrations::runner().run_async(client).await?;
    Ok(report)
}

/// Convenience wrapper: apply any pending migrations using a one-shot
/// connection, then tear it down.
///
/// Opens a short-lived NoTls connection from a URL. Refinery requires a
/// non-pooled `tokio_postgres::Client`, so this is the right shape for a
/// one-shot startup migration step in a binary.
pub async fn apply(url: &str) -> Result<refinery::Report, MigrateError> {
    let (mut client, conn) = tokio_postgres::connect(url, NoTls).await?;
    let handle = tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!(error = %e, "migration connection error");
        }
    });
    let report = run(&mut client).await?;
    drop(client);
    handle.abort();
    Ok(report)
}
