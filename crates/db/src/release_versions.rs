//! Release version persistence (versions belong to a release).

use intellipilot_core::release::{ReleaseStatus, ReleaseVersion, ReleaseVersionRef};
use time::{Date, OffsetDateTime};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, release_id, version, status, target_date, released_at, notes, \
     repository_id, git_tag, \"order\", created_at";

fn row_to_version(r: &Row) -> ReleaseVersion {
    ReleaseVersion {
        id: r.get("id"),
        release_id: r.get("release_id"),
        version: r.get("version"),
        status: r
            .get::<_, Option<String>>("status")
            .and_then(|s| ReleaseStatus::parse(&s))
            .unwrap_or(ReleaseStatus::Planned),
        target_date: r.get("target_date"),
        released_at: r.get("released_at"),
        notes: r.get("notes"),
        repository_id: r.get("repository_id"),
        git_tag: r.get("git_tag"),
        order: r.get("order"),
        created_at: r.get("created_at"),
    }
}

fn row_to_ref(r: &Row) -> ReleaseVersionRef {
    ReleaseVersionRef {
        id: r.get("id"),
        release_id: r.get("release_id"),
        release_name: r.get("release_name"),
        release_color: r.get("release_color"),
        version: r.get("version"),
        status: r
            .get::<_, Option<String>>("status")
            .and_then(|s| ReleaseStatus::parse(&s))
            .unwrap_or(ReleaseStatus::Planned),
        target_date: r.get("target_date"),
        order: r.get("order"),
    }
}

/// Writable version fields.
#[derive(Debug, Default)]
pub struct VersionWrite<'a> {
    pub version: &'a str,
    pub status: &'a str,
    pub target_date: Option<Date>,
    pub released_at: Option<OffsetDateTime>,
    pub notes: &'a str,
    pub repository_id: Option<Uuid>,
    pub git_tag: Option<&'a str>,
}

/// List the versions of a release (scoped to a project via the parent release).
pub async fn list_for_release(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    release_id: Uuid,
) -> Result<Vec<ReleaseVersion>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {COLS} FROM release_versions rv \
                 WHERE rv.release_id=$1 \
                   AND EXISTS (SELECT 1 FROM releases r \
                               WHERE r.id=rv.release_id AND r.project_id=$2) \
                 ORDER BY rv.\"order\", rv.created_at"
            ),
            &[&release_id, &project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_version).collect())
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<ReleaseVersion>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {COLS} FROM release_versions rv \
                 WHERE rv.id=$1 \
                   AND EXISTS (SELECT 1 FROM releases r \
                               WHERE r.id=rv.release_id AND r.project_id=$2)"
            ),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_version))
}

pub async fn create(
    client: &deadpool_postgres::Client,
    release_id: Uuid,
    w: &VersionWrite<'_>,
) -> Result<ReleaseVersion, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO release_versions \
                   (release_id, version, status, target_date, released_at, notes, repository_id, \
                    git_tag, \"order\") \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8, \
                   (SELECT COALESCE(MAX(\"order\"),0)+1 FROM release_versions WHERE release_id=$1)) \
                 RETURNING {COLS}"
            ),
            &[
                &release_id,
                &w.version,
                &w.status,
                &w.target_date,
                &w.released_at,
                &w.notes,
                &w.repository_id,
                &w.git_tag,
            ],
        )
        .await?;
    Ok(row_to_version(&row))
}

pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    w: &VersionWrite<'_>,
) -> Result<Option<ReleaseVersion>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE release_versions rv SET version=$3, status=$4, target_date=$5, \
                   released_at=$6, notes=$7, repository_id=$8, git_tag=$9 \
                 WHERE rv.id=$1 \
                   AND EXISTS (SELECT 1 FROM releases r \
                               WHERE r.id=rv.release_id AND r.project_id=$2) \
                 RETURNING {COLS}"
            ),
            &[
                &id,
                &project_id,
                &w.version,
                &w.status,
                &w.target_date,
                &w.released_at,
                &w.notes,
                &w.repository_id,
                &w.git_tag,
            ],
        )
        .await?;
    Ok(row.as_ref().map(row_to_version))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM release_versions rv \
             WHERE rv.id=$1 \
               AND EXISTS (SELECT 1 FROM releases r \
                           WHERE r.id=rv.release_id AND r.project_id=$2)",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// Whether a version exists in this project (for issue.release_version_id).
pub async fn in_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM release_versions rv \
               JOIN releases r ON r.id = rv.release_id \
               WHERE rv.id=$1 AND r.project_id=$2) AS e",
            &[&id, &project_id],
        )
        .await?;
    Ok(row.get("e"))
}

/// Versions of releases linked to any of the given components (drives the
/// issue fix-version picker).
pub async fn for_components(
    client: &deadpool_postgres::Client,
    component_ids: &[Uuid],
) -> Result<Vec<ReleaseVersionRef>, DbError> {
    if component_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = client
        .query(
            "SELECT DISTINCT rv.id, rv.release_id, r.name AS release_name, \
                    r.color AS release_color, rv.version, rv.status, rv.target_date, \
                    rv.\"order\" \
             FROM release_versions rv \
             JOIN releases r ON r.id = rv.release_id \
             JOIN component_releases cr ON cr.release_id = rv.release_id \
             WHERE cr.component_id = ANY($1) ORDER BY r.name, rv.version",
            &[&component_ids],
        )
        .await?;
    Ok(rows.iter().map(row_to_ref).collect())
}

/// All release versions in the project, enriched with their parent release's
/// name and badge color (flat, for pages that resolve many issues' fix
/// versions at once).
pub async fn list_all_for_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<ReleaseVersionRef>, DbError> {
    let rows = client
        .query(
            "SELECT rv.id, rv.release_id, r.name AS release_name, \
                    r.color AS release_color, rv.version, rv.status, rv.target_date, \
                    rv.\"order\" \
             FROM release_versions rv \
             JOIN releases r ON r.id = rv.release_id \
             WHERE r.project_id = $1 ORDER BY r.name, rv.version",
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_ref).collect())
}
