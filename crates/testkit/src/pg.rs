//! Per-test isolated Postgres via schema-per-test.
//!
//! Each [`TestDb`] creates a fresh `test_<rand>` schema, runs all migrations
//! into it, and exposes a `deadpool_postgres::Pool` whose connections have
//! `search_path = test_<rand>, public`. On drop the schema is removed.
//!
//! Requires a reachable Postgres. URL comes from `INTELLIPILOT_TEST_DB_URL`,
//! defaulting to the CI/compose connection string.

use deadpool_postgres::{ManagerConfig, Pool, RecyclingMethod, Runtime};
use rand::Rng;
use tokio_postgres::NoTls;

const DEFAULT_URL: &str =
    "postgres://intellipilot:intellipilot_ci@localhost:5432/intellipilot_test";

fn base_url() -> String {
    std::env::var("INTELLIPILOT_TEST_DB_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| DEFAULT_URL.to_owned())
}

fn random_schema() -> String {
    let mut rng = rand::thread_rng();
    let suffix: u64 = rng.r#gen();
    format!("test_{suffix:016x}")
}

/// An isolated test database (one Postgres schema).
pub struct TestDb {
    pub pool: Pool,
    schema: String,
    base_url: String,
}

impl std::fmt::Debug for TestDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestDb")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

impl TestDb {
    /// Spin up a fresh isolated schema with all migrations applied.
    ///
    /// # Panics
    /// Panics if Postgres is unreachable or migrations fail — tests cannot run
    /// without a database, and a clear panic is the right failure mode.
    pub async fn new() -> Self {
        let base = base_url();
        let schema = random_schema();

        // 1. Admin connection (default search_path) to create the schema.
        let (admin, admin_conn) = tokio_postgres::connect(&base, NoTls)
            .await
            .expect("connect to test Postgres (set INTELLIPILOT_TEST_DB_URL)");
        let admin_handle = tokio::spawn(async move {
            drop(admin_conn.await);
        });
        admin
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .await
            .expect("create test schema");
        // Pre-create the (database-global) pg_trgm extension under a
        // transaction-scoped advisory lock so concurrent per-schema migrations
        // don't race on creating it. A *session* lock would be released by the
        // explicit unlock before the implicit transaction commits, leaving a
        // window where another session acquires the lock but its snapshot can't
        // yet see the just-created (uncommitted) extension — it then tries to
        // insert and dies on the catalog's unique index. `pg_advisory_xact_lock`
        // is held until commit, after the extension is visible, so the
        // following `CREATE EXTENSION IF NOT EXISTS` is always a true no-op.
        admin
            .batch_execute(
                "BEGIN; \
                 SELECT pg_advisory_xact_lock(424242); \
                 CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public; \
                 COMMIT;",
            )
            .await
            .expect("ensure pg_trgm");
        drop(admin);
        admin_handle.abort();

        // 2. Migration connection scoped to the new schema.
        let mut cfg: tokio_postgres::Config = base.parse().expect("parse test db url");
        cfg.options(format!("-c search_path={schema},public"));
        let (mut mig_client, mig_conn) = cfg.connect(NoTls).await.expect("connect for migrations");
        let mig_handle = tokio::spawn(async move {
            drop(mig_conn.await);
        });
        intellipilot_db::migrations::run(&mut mig_client)
            .await
            .expect("run migrations");
        drop(mig_client);
        mig_handle.abort();

        // 3. Pool whose connections live in the test schema.
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = deadpool_postgres::Manager::from_config(cfg, NoTls, mgr_config);
        let pool = Pool::builder(mgr)
            .max_size(8)
            .runtime(Runtime::Tokio1)
            .build()
            .expect("build test pool");

        Self {
            pool,
            schema,
            base_url: base,
        }
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Drop runs synchronously; spin a dedicated thread + runtime to issue
        // the cleanup so we don't depend on the test's runtime still living.
        let schema = self.schema.clone();
        let url = self.base_url.clone();
        let cleanup = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                if let Ok((client, conn)) = tokio_postgres::connect(&url, NoTls).await {
                    let handle = tokio::spawn(async move {
                        drop(conn.await);
                    });
                    drop(
                        client
                            .batch_execute(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
                            .await,
                    );
                    drop(client);
                    handle.abort();
                }
            });
        })
        .join();
        drop(cleanup);
    }
}
