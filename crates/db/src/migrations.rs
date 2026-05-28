//! Embedded refinery migrations. SQL files in `crates/db/migrations/`.
//!
//! All migrations run in the current `search_path`; production deployments
//! leave it at `public`, tests redirect into a per-test schema.

use thiserror::Error;
use tokio_postgres::Client;

#[derive(Debug, Error)]
pub enum MigrateError {
    #[error("migration error: {0}")]
    Refinery(#[from] refinery::Error),
}

mod embedded {
    refinery::embed_migrations!("./migrations");
}

/// Run all pending migrations against the given client. Idempotent.
pub async fn run(client: &mut Client) -> Result<refinery::Report, MigrateError> {
    let report = embedded::migrations::runner().run_async(client).await?;
    Ok(report)
}
