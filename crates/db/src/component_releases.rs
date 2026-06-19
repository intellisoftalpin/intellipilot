//! Component ↔ release link persistence (many-to-many).

use intellipilot_core::release::ComponentReleaseLink;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

fn row_to_link(r: &Row) -> ComponentReleaseLink {
    ComponentReleaseLink {
        component_id: r.get("component_id"),
        release_id: r.get("release_id"),
        release_name: r.get("release_name"),
        created_at: r.get("created_at"),
    }
}

pub async fn list_for_component(
    client: &deadpool_postgres::Client,
    component_id: Uuid,
) -> Result<Vec<ComponentReleaseLink>, DbError> {
    let rows = client
        .query(
            "SELECT cr.component_id, cr.release_id, r.name AS release_name, cr.created_at \
             FROM component_releases cr JOIN releases r ON r.id = cr.release_id \
             WHERE cr.component_id=$1 ORDER BY r.name",
            &[&component_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_link).collect())
}

pub async fn link(
    client: &deadpool_postgres::Client,
    component_id: Uuid,
    release_id: Uuid,
) -> Result<ComponentReleaseLink, DbError> {
    let row = client
        .query_one(
            "WITH ins AS ( \
               INSERT INTO component_releases (component_id, release_id) VALUES ($1,$2) \
               RETURNING component_id, release_id, created_at \
             ) \
             SELECT ins.component_id, ins.release_id, r.name AS release_name, ins.created_at \
             FROM ins JOIN releases r ON r.id = ins.release_id",
            &[&component_id, &release_id],
        )
        .await?;
    Ok(row_to_link(&row))
}

pub async fn unlink(
    client: &deadpool_postgres::Client,
    component_id: Uuid,
    release_id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM component_releases WHERE component_id=$1 AND release_id=$2",
            &[&component_id, &release_id],
        )
        .await?;
    Ok(n > 0)
}
