//! Shared test fixtures and helpers. Used by integration tests across crates.
//!
//! This is test-support code: `expect`/`panic` on misconfiguration is the
//! correct, loud failure mode, so the correctness lints are relaxed here.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

pub mod pg;

pub use pg::TestDb;

use std::sync::Once;

static TRACING_INIT: Once = Once::new();

/// Initialize a noisy-but-captured tracing subscriber for tests.
/// Safe to call multiple times; only the first call has effect.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let result = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("warn,intellipilot=debug")
                }),
            )
            .try_init();
        drop(result);
    });
}
