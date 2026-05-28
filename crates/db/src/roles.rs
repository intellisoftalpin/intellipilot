//! Role persistence.

use intellipilot_core::perms::Permission;
use intellipilot_core::project::Role;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

fn row_to_role(row: &Row) -> Result<Role, DbError> {
    let perms_json: serde_json::Value = row.get("permissions");
    let permissions: Vec<Permission> = serde_json::from_value(perms_json)?;
    Ok(Role {
        id: row.get("id"),
        project_id: row.get("project_id"),
        slug: row.get("slug"),
        name: row.get("name"),
        order: row.get("order"),
        is_admin: row.get("is_admin"),
        permissions,
    })
}

const ROLE_COLS: &str = "id, project_id, slug, name, \"order\", is_admin, permissions";

pub async fn list_for_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<Role>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {ROLE_COLS} FROM roles WHERE project_id = $1 ORDER BY \"order\""),
            &[&project_id],
        )
        .await?;
    rows.iter().map(row_to_role).collect()
}

pub async fn find_in_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    role_id: Uuid,
) -> Result<Option<Role>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {ROLE_COLS} FROM roles WHERE id = $1 AND project_id = $2"),
            &[&role_id, &project_id],
        )
        .await?;
    row.as_ref().map(row_to_role).transpose()
}

pub async fn find_by_slug(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    slug: &str,
) -> Result<Option<Role>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {ROLE_COLS} FROM roles WHERE project_id = $1 AND slug = $2"),
            &[&project_id, &slug],
        )
        .await?;
    row.as_ref().map(row_to_role).transpose()
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    slug: &str,
    name: &str,
    order: i32,
    permissions: &[Permission],
) -> Result<Role, DbError> {
    let perms_json = serde_json::to_value(permissions)?;
    let row = client
        .query_one(
            &format!(
                "INSERT INTO roles (project_id, slug, name, \"order\", is_admin, permissions) \
                 VALUES ($1, $2, $3, $4, false, $5) RETURNING {ROLE_COLS}"
            ),
            &[&project_id, &slug, &name, &order, &perms_json],
        )
        .await?;
    row_to_role(&row)
}

pub async fn update_permissions(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    role_id: Uuid,
    name: Option<&str>,
    permissions: Option<&[Permission]>,
) -> Result<Option<Role>, DbError> {
    let perms_json = match permissions {
        Some(p) => Some(serde_json::to_value(p)?),
        None => None,
    };
    let row = client
        .query_opt(
            &format!(
                "UPDATE roles SET \
                   name = COALESCE($3, name), \
                   permissions = COALESCE($4, permissions) \
                 WHERE id = $1 AND project_id = $2 AND is_admin = false \
                 RETURNING {ROLE_COLS}"
            ),
            &[&role_id, &project_id, &name, &perms_json],
        )
        .await?;
    row.as_ref().map(row_to_role).transpose()
}

/// Delete a non-admin role that has no members. Returns Ok(false) if it
/// doesn't exist or is protected; Err on FK violation (members present).
pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    role_id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM roles WHERE id = $1 AND project_id = $2 AND is_admin = false",
            &[&role_id, &project_id],
        )
        .await?;
    Ok(n > 0)
}
