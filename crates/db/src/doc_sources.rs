//! Documentation source persistence.
//!
//! Cache bookkeeping (`cache_status`, `head_commit`, `last_synced_at`, …) is
//! updated through the dedicated `mark_*` helpers rather than through
//! [`update`], so a background sync can never collide with a user's edit on
//! the optimistic-concurrency `version` counter.

use intellipilot_core::docs::{CacheStatus, DocSource, DocSourceKind};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;
use crate::backlog::UpdateOutcome;

const COLS: &str = "id, project_id, name, kind, ssh_url, web_url, branch, doc_path, ssh_key_id, \
     read_only, hidden, \"order\", color, emoji, cache_status, cache_error, head_commit, \
     cache_bytes, \
     last_synced_at, last_attempt_at, host_fingerprint, version, created_at, modified_at";

fn row_to_source(r: &Row) -> DocSource {
    DocSource {
        id: r.get("id"),
        project_id: r.get("project_id"),
        name: r.get("name"),
        kind: DocSourceKind::from_str_lossy(r.get("kind")),
        ssh_url: r.get("ssh_url"),
        web_url: r.get("web_url"),
        branch: r.get("branch"),
        doc_path: r.get("doc_path"),
        ssh_key_id: r.get("ssh_key_id"),
        read_only: r.get("read_only"),
        hidden: r.get("hidden"),
        order: r.get("order"),
        color: r.get("color"),
        emoji: r.get("emoji"),
        cache_status: CacheStatus::from_str_lossy(r.get("cache_status")),
        cache_error: r.get("cache_error"),
        head_commit: r.get("head_commit"),
        cache_bytes: r.get("cache_bytes"),
        last_synced_at: r.get("last_synced_at"),
        last_attempt_at: r.get("last_attempt_at"),
        host_fingerprint: r.get("host_fingerprint"),
        version: r.get("version"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

/// The field set for a new source. `doc_path` must already be normalized by
/// [`intellipilot_core::docs::path::normalize`].
#[derive(Debug, Clone)]
pub struct DocSourceNew<'a> {
    pub name: &'a str,
    pub kind: DocSourceKind,
    /// Required for [`DocSourceKind::Git`]; must be `None` for a web source.
    pub ssh_url: Option<&'a str>,
    pub web_url: &'a str,
    /// Required for [`DocSourceKind::Git`]; must be `None` for a web source.
    pub branch: Option<&'a str>,
    pub doc_path: &'a str,
    pub ssh_key_id: Option<Uuid>,
    pub read_only: bool,
    pub color: &'a str,
    pub emoji: &'a str,
    pub created_by: Uuid,
}

/// A partial edit. `None` leaves the field alone; `Some(None)` on a nullable
/// field clears it.
#[derive(Debug, Default, Clone)]
pub struct DocSourcePatch<'a> {
    pub name: Option<&'a str>,
    pub web_url: Option<&'a str>,
    pub branch: Option<&'a str>,
    pub doc_path: Option<&'a str>,
    pub ssh_key_id: Option<Option<Uuid>>,
    pub read_only: Option<bool>,
    pub hidden: Option<bool>,
    pub order: Option<f64>,
    pub color: Option<&'a str>,
    pub emoji: Option<&'a str>,
}

impl DocSourcePatch<'_> {
    /// Does this patch change what the cache holds? Changing the branch means
    /// the cached tree is for the wrong ref; changing the URL or key means it
    /// may be for the wrong repository entirely. Either way the caller must
    /// resync. Note `doc_path` is deliberately absent: it only narrows the
    /// view of an already-correct cache.
    #[must_use]
    pub const fn invalidates_cache(&self) -> bool {
        self.branch.is_some() || self.ssh_key_id.is_some()
    }

    /// Fields that only make sense for a git source. A web source has no
    /// repository, so a patch touching any of these is a client error rather
    /// than something to let the CHECK constraint reject as a 500.
    #[must_use]
    pub const fn touches_git_fields(&self) -> bool {
        self.branch.is_some() || self.doc_path.is_some() || self.ssh_key_id.is_some()
    }
}

pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<DocSource>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {COLS} FROM doc_sources WHERE project_id=$1 ORDER BY \"order\", name"),
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_source).collect())
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<DocSource>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM doc_sources WHERE id=$1 AND project_id=$2"),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_source))
}

/// Count sources in a project, to enforce the per-project cap.
pub async fn count(client: &deadpool_postgres::Client, project_id: Uuid) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM doc_sources WHERE project_id=$1",
            &[&project_id],
        )
        .await?;
    Ok(row.get("n"))
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    new: &DocSourceNew<'_>,
) -> Result<DocSource, DbError> {
    let order = {
        let row = client
            .query_one(
                "SELECT COALESCE(max(\"order\"), 0.0) + 1.0 AS o FROM doc_sources WHERE project_id=$1",
                &[&project_id],
            )
            .await?;
        row.get::<_, f64>("o")
    };
    let row = client
        .query_one(
            &format!(
                "INSERT INTO doc_sources \
                   (project_id, name, kind, ssh_url, web_url, branch, doc_path, \
                    ssh_key_id, read_only, \"order\", color, emoji, created_by) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING {COLS}"
            ),
            &[
                &project_id,
                &new.name,
                &new.kind.as_str(),
                &new.ssh_url,
                &new.web_url,
                &new.branch,
                &new.doc_path,
                &new.ssh_key_id,
                &new.read_only,
                &order,
                &new.color,
                &new.emoji,
                &new.created_by,
            ],
        )
        .await?;
    Ok(row_to_source(&row))
}

pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    expected_version: i32,
    patch: &DocSourcePatch<'_>,
) -> Result<UpdateOutcome<DocSource>, DbError> {
    let (name_set, name) = (patch.name.is_some(), patch.name);
    let (web_set, web) = (patch.web_url.is_some(), patch.web_url);
    let (branch_set, branch) = (patch.branch.is_some(), patch.branch);
    let (jail_set, jail) = (patch.doc_path.is_some(), patch.doc_path);
    let (key_set, key) = (patch.ssh_key_id.is_some(), patch.ssh_key_id.flatten());
    let (ro_set, ro) = (patch.read_only.is_some(), patch.read_only);
    let (hidden_set, hidden) = (patch.hidden.is_some(), patch.hidden);
    let (order_set, order) = (patch.order.is_some(), patch.order);
    let (color_set, color) = (patch.color.is_some(), patch.color);
    let (emoji_set, emoji) = (patch.emoji.is_some(), patch.emoji);
    let row = client
        .query_opt(
            &format!(
                "UPDATE doc_sources SET \
                   name = CASE WHEN $4::bool THEN $5::text ELSE name END, \
                   web_url = CASE WHEN $6::bool THEN $7::text ELSE web_url END, \
                   branch = CASE WHEN $8::bool THEN $9::text ELSE branch END, \
                   doc_path = CASE WHEN $10::bool THEN $11::text ELSE doc_path END, \
                   ssh_key_id = CASE WHEN $12::bool THEN $13::uuid ELSE ssh_key_id END, \
                   read_only = CASE WHEN $14::bool THEN $15::bool ELSE read_only END, \
                   hidden = CASE WHEN $16::bool THEN $17::bool ELSE hidden END, \
                   \"order\" = CASE WHEN $18::bool THEN $19::float8 ELSE \"order\" END, \
                   color = CASE WHEN $20::bool THEN $21::text ELSE color END, \
                   emoji = CASE WHEN $22::bool THEN $23::text ELSE emoji END, \
                   version = version + 1 \
                 WHERE id=$1 AND project_id=$2 AND version=$3 RETURNING {COLS}"
            ),
            &[
                &id,
                &project_id,
                &expected_version,
                &name_set,
                &name,
                &web_set,
                &web,
                &branch_set,
                &branch,
                &jail_set,
                &jail,
                &key_set,
                &key,
                &ro_set,
                &ro,
                &hidden_set,
                &hidden,
                &order_set,
                &order,
                &color_set,
                &color,
                &emoji_set,
                &emoji,
            ],
        )
        .await?;
    if let Some(r) = row {
        return Ok(UpdateOutcome::Updated(row_to_source(&r)));
    }
    // The row exists but the guarded update matched nothing → the version
    // moved under us. No row at all → genuinely missing.
    let exists = client
        .query_opt(
            "SELECT 1 FROM doc_sources WHERE id=$1 AND project_id=$2",
            &[&id, &project_id],
        )
        .await?;
    Ok(exists.map_or(UpdateOutcome::NotFound, |_| UpdateOutcome::Conflict))
}

/// Hard-delete a source. The caller is responsible for removing its cache
/// directory afterwards.
pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM doc_sources WHERE id=$1 AND project_id=$2",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// Claim a source for syncing.
///
/// The claim is refused (returning `false`) when another attempt started
/// within `min_interval_secs`. That single check both rate-limits manual
/// refreshes and stops two workers syncing the same source at once.
pub async fn claim_for_sync(
    client: &deadpool_postgres::Client,
    id: Uuid,
    min_interval_secs: f64,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE doc_sources \
               SET cache_status='syncing', last_attempt_at=now() \
             WHERE id=$1 \
               AND (last_attempt_at IS NULL \
                    OR last_attempt_at < now() - make_interval(secs => $2::double precision))",
            &[&id, &min_interval_secs],
        )
        .await?;
    Ok(n > 0)
}

/// Record a successful clone or fetch.
pub async fn mark_synced(
    client: &deadpool_postgres::Client,
    id: Uuid,
    head_commit: &str,
    cache_bytes: i64,
    host_fingerprint: Option<&str>,
) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE doc_sources SET \
               cache_status='ready', cache_error=NULL, head_commit=$2, cache_bytes=$3, \
               host_fingerprint=COALESCE($4, host_fingerprint), last_synced_at=now() \
             WHERE id=$1",
            &[&id, &head_commit, &cache_bytes, &host_fingerprint],
        )
        .await?;
    Ok(())
}

/// Record a failed attempt.
///
/// A source that was previously `ready` keeps serving its cached tree — the
/// status flips, but `head_commit` and `last_synced_at` are left intact so the
/// UI can say how stale the content it is showing has become.
pub async fn mark_failed(
    client: &deadpool_postgres::Client,
    id: Uuid,
    error: &str,
) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE doc_sources SET cache_status='error', cache_error=$2 WHERE id=$1",
            &[&id, &error],
        )
        .await?;
    Ok(())
}

/// Git sources across every project whose last attempt is older than
/// `cutoff`, oldest first. Drives the background refresher.
///
/// Web sources are excluded in SQL rather than filtered afterwards: they have
/// nothing to fetch, so including them would burn the query's `LIMIT` on rows
/// the refresher can only skip.
pub async fn due_for_sync(
    client: &deadpool_postgres::Client,
    cutoff: OffsetDateTime,
    limit: i64,
) -> Result<Vec<DocSource>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {COLS} FROM doc_sources \
                 WHERE kind = 'git' \
                   AND (last_attempt_at IS NULL OR last_attempt_at < $1) \
                 ORDER BY last_attempt_at NULLS FIRST LIMIT $2"
            ),
            &[&cutoff, &limit],
        )
        .await?;
    Ok(rows.iter().map(row_to_source).collect())
}

/// Reset every source stuck in `syncing` back to a terminal state.
///
/// Called at startup: a process killed mid-fetch would otherwise leave sources
/// claimed forever, since `claim_for_sync` never clears the flag on its own.
pub async fn release_stale_claims(client: &deadpool_postgres::Client) -> Result<u64, DbError> {
    let n = client
        .execute(
            "UPDATE doc_sources \
               SET cache_status = CASE WHEN head_commit IS NULL THEN 'pending' ELSE 'ready' END \
             WHERE cache_status='syncing'",
            &[],
        )
        .await?;
    Ok(n)
}
