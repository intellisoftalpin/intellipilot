//! Component↔repository link persistence. Each link pins a branch; a component
//! may link many repositories.

use intellipilot_core::repo::ComponentRepositoryLink;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

fn row_to_link(r: &Row) -> ComponentRepositoryLink {
    ComponentRepositoryLink {
        component_id: r.get("component_id"),
        repository_id: r.get("repository_id"),
        repository_name: r.get("repository_name"),
        ssh_url: r.get("ssh_url"),
        branch: r.get("branch"),
        created_at: r.get("created_at"),
    }
}

/// List a component's linked repositories (with branch + repo display fields).
pub async fn list_for_component(
    client: &deadpool_postgres::Client,
    component_id: Uuid,
) -> Result<Vec<ComponentRepositoryLink>, DbError> {
    let rows = client
        .query(
            "SELECT cr.component_id, cr.repository_id, r.name AS repository_name, \
                    r.ssh_url, cr.branch, cr.created_at \
             FROM component_repositories cr \
               JOIN repositories r ON r.id = cr.repository_id \
             WHERE cr.component_id=$1 ORDER BY r.name",
            &[&component_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_link).collect())
}

/// Link a repository to a component on a branch. Returns a unique-violation
/// `DbError` if the pair is already linked, or a foreign-key violation if the
/// component/repository does not exist.
pub async fn link(
    client: &deadpool_postgres::Client,
    component_id: Uuid,
    repository_id: Uuid,
    branch: &str,
) -> Result<ComponentRepositoryLink, DbError> {
    let row = client
        .query_one(
            "WITH ins AS ( \
               INSERT INTO component_repositories (component_id, repository_id, branch) \
               VALUES ($1,$2,$3) \
               RETURNING component_id, repository_id, branch, created_at \
             ) \
             SELECT ins.component_id, ins.repository_id, r.name AS repository_name, \
                    r.ssh_url, ins.branch, ins.created_at \
             FROM ins JOIN repositories r ON r.id = ins.repository_id",
            &[&component_id, &repository_id, &branch],
        )
        .await?;
    Ok(row_to_link(&row))
}

/// Change the branch of an existing link.
pub async fn update_branch(
    client: &deadpool_postgres::Client,
    component_id: Uuid,
    repository_id: Uuid,
    branch: &str,
) -> Result<Option<ComponentRepositoryLink>, DbError> {
    let row = client
        .query_opt(
            "WITH upd AS ( \
               UPDATE component_repositories SET branch=$3 \
               WHERE component_id=$1 AND repository_id=$2 \
               RETURNING component_id, repository_id, branch, created_at \
             ) \
             SELECT upd.component_id, upd.repository_id, r.name AS repository_name, \
                    r.ssh_url, upd.branch, upd.created_at \
             FROM upd JOIN repositories r ON r.id = upd.repository_id",
            &[&component_id, &repository_id, &branch],
        )
        .await?;
    Ok(row.as_ref().map(row_to_link))
}

pub async fn unlink(
    client: &deadpool_postgres::Client,
    component_id: Uuid,
    repository_id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM component_repositories WHERE component_id=$1 AND repository_id=$2",
            &[&component_id, &repository_id],
        )
        .await?;
    Ok(n > 0)
}
