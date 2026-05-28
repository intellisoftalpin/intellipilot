//! Project persistence, including transactional creation that seeds the
//! default roles and the owner's admin membership.

use intellipilot_core::ordering::APPEND_GAP;
use intellipilot_core::perms::default_roles;
use intellipilot_core::project::{NewProject, Project, ProjectUpdate, Visibility};
use intellipilot_core::taxonomy::default_taxonomies;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const PROJECT_COLS: &str = "id, slug, name, description, owner_id, visibility, \
     kanban_enabled, backlog_enabled, wiki_enabled, epics_enabled, created_at";

fn row_to_project(row: &Row) -> Project {
    let visibility: String = row.get("visibility");
    Project {
        id: row.get("id"),
        slug: row.get("slug"),
        name: row.get("name"),
        description: row.get("description"),
        owner_id: row.get("owner_id"),
        visibility: Visibility::parse(&visibility).unwrap_or(Visibility::Private),
        kanban_enabled: row.get("kanban_enabled"),
        backlog_enabled: row.get("backlog_enabled"),
        wiki_enabled: row.get("wiki_enabled"),
        epics_enabled: row.get("epics_enabled"),
        created_at: row.get("created_at"),
    }
}

/// Create a project, seed the four default roles, and add the owner as admin —
/// all in one transaction.
pub async fn create_with_defaults(
    client: &mut deadpool_postgres::Client,
    new: &NewProject,
) -> Result<Project, DbError> {
    let tx = client.transaction().await?;

    let prow = tx
        .query_one(
            &format!(
                "INSERT INTO projects (slug, name, description, owner_id, visibility) \
                 VALUES ($1, $2, $3, $4, $5) RETURNING {PROJECT_COLS}"
            ),
            &[
                &new.slug,
                &new.name,
                &new.description,
                &new.owner_id,
                &new.visibility.as_str(),
            ],
        )
        .await?;
    let project = row_to_project(&prow);

    let mut admin_role_id: Option<Uuid> = None;
    for role in default_roles() {
        let perms_json = serde_json::to_value(&role.permissions)?;
        let rrow = tx
            .query_one(
                "INSERT INTO roles (project_id, slug, name, \"order\", is_admin, permissions) \
                 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                &[
                    &project.id,
                    &role.slug,
                    &role.name,
                    &role.order,
                    &role.is_admin,
                    &perms_json,
                ],
            )
            .await?;
        if role.is_admin {
            admin_role_id = Some(rrow.get("id"));
        }
    }
    let admin_role_id =
        admin_role_id.ok_or_else(|| DbError::Build("no admin role seeded".into()))?;

    tx.execute(
        "INSERT INTO memberships (project_id, user_id, role_id) VALUES ($1, $2, $3)",
        &[&project.id, &new.owner_id, &admin_role_id],
    )
    .await?;

    // Seed the default taxonomy. Rank items per-kind in declaration order.
    let mut order_by_kind: std::collections::HashMap<&str, f64> = std::collections::HashMap::new();
    for item in default_taxonomies() {
        let kind = item.kind.as_str();
        let order = order_by_kind.entry(kind).or_insert(0.0);
        *order += APPEND_GAP;
        tx.execute(
            "INSERT INTO taxonomy_items \
               (project_id, kind, name, slug, color, \"order\", is_closed, value) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &project.id,
                &kind,
                &item.name,
                &item.slug,
                &item.color,
                &*order,
                &item.is_closed,
                &item.value,
            ],
        )
        .await?;
    }

    tx.commit().await?;
    Ok(project)
}

pub async fn find_by_id(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<Project>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {PROJECT_COLS} FROM projects WHERE id = $1 AND deleted_at IS NULL"),
            &[&id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_project))
}

pub async fn slug_exists(client: &deadpool_postgres::Client, slug: &str) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE slug = $1) AS e",
            &[&slug],
        )
        .await?;
    Ok(row.get("e"))
}

/// Projects the user is a member of.
pub async fn list_for_member(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<Vec<Project>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {} FROM projects p \
                 JOIN memberships m ON m.project_id = p.id \
                 WHERE m.user_id = $1 AND p.deleted_at IS NULL \
                 ORDER BY p.created_at DESC",
                PROJECT_COLS
                    .split(", ")
                    .map(|c| format!("p.{c}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            &[&user_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_project).collect())
}

pub async fn update(
    client: &deadpool_postgres::Client,
    id: Uuid,
    upd: &ProjectUpdate,
) -> Result<Option<Project>, DbError> {
    let visibility = upd.visibility.map(|v| v.as_str().to_owned());
    let row = client
        .query_opt(
            &format!(
                "UPDATE projects SET \
                   name = COALESCE($2, name), \
                   description = COALESCE($3, description), \
                   visibility = COALESCE($4, visibility), \
                   kanban_enabled = COALESCE($5, kanban_enabled), \
                   backlog_enabled = COALESCE($6, backlog_enabled), \
                   wiki_enabled = COALESCE($7, wiki_enabled), \
                   epics_enabled = COALESCE($8, epics_enabled) \
                 WHERE id = $1 AND deleted_at IS NULL \
                 RETURNING {PROJECT_COLS}"
            ),
            &[
                &id,
                &upd.name,
                &upd.description,
                &visibility,
                &upd.kanban_enabled,
                &upd.backlog_enabled,
                &upd.wiki_enabled,
                &upd.epics_enabled,
            ],
        )
        .await?;
    Ok(row.as_ref().map(row_to_project))
}

pub async fn soft_delete(client: &deadpool_postgres::Client, id: Uuid) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE projects SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(n > 0)
}
