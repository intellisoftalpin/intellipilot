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
     issue_prefix, color, icon_image_kind, icon_image_updated_at, \
     kanban_enabled, backlog_enabled, wiki_enabled, epics_enabled, epic_board_settings, \
     created_at";

fn row_to_project(row: &Row) -> Project {
    let visibility: String = row.get("visibility");
    let epic_board = serde_json::from_value(row.get("epic_board_settings")).unwrap_or_default();
    Project {
        id: row.get("id"),
        slug: row.get("slug"),
        name: row.get("name"),
        description: row.get("description"),
        owner_id: row.get("owner_id"),
        visibility: Visibility::parse(&visibility).unwrap_or(Visibility::Private),
        issue_prefix: row.get("issue_prefix"),
        color: row.get("color"),
        icon_image_kind: row.get("icon_image_kind"),
        icon_image_updated_at: row.get("icon_image_updated_at"),
        kanban_enabled: row.get("kanban_enabled"),
        backlog_enabled: row.get("backlog_enabled"),
        wiki_enabled: row.get("wiki_enabled"),
        epics_enabled: row.get("epics_enabled"),
        epic_board,
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
                "INSERT INTO projects \
                   (slug, name, description, owner_id, visibility, issue_prefix, color) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {PROJECT_COLS}"
            ),
            &[
                &new.slug,
                &new.name,
                &new.description,
                &new.owner_id,
                &new.visibility.as_str(),
                &new.issue_prefix,
                &new.color,
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

/// Whether any project already uses this issue prefix (prefixes are globally
/// unique). `exclude` skips a project's own row (for updates).
pub async fn prefix_exists(
    client: &deadpool_postgres::Client,
    prefix: &str,
    exclude: Option<Uuid>,
) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(\
               SELECT 1 FROM projects WHERE issue_prefix = $1 AND ($2::uuid IS NULL OR id <> $2)\
             ) AS e",
            &[&prefix, &exclude],
        )
        .await?;
    Ok(row.get("e"))
}

/// Projects the user is a member of.
/// Every non-deleted project, newest first. For superadmins, who see all
/// projects regardless of membership.
pub async fn list_all(client: &deadpool_postgres::Client) -> Result<Vec<Project>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {PROJECT_COLS} FROM projects \
                 WHERE deleted_at IS NULL ORDER BY created_at DESC"
            ),
            &[],
        )
        .await?;
    Ok(rows.iter().map(row_to_project).collect())
}

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
    let epic_board = upd
        .epic_board
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
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
                   epics_enabled = COALESCE($8, epics_enabled), \
                   epic_board_settings = COALESCE($9::jsonb, epic_board_settings), \
                   issue_prefix = COALESCE($10, issue_prefix), \
                   color = COALESCE($11, color) \
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
                &epic_board,
                &upd.issue_prefix,
                &upd.color,
            ],
        )
        .await?;
    Ok(row.as_ref().map(row_to_project))
}

/// The uploaded icon object (storage key + mime), or `None` when no icon set.
pub async fn icon_object(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Option<(String, String)>, DbError> {
    let row = client
        .query_opt(
            "SELECT icon_image_storage_key, icon_image_mime FROM projects \
             WHERE id = $1 AND icon_image_kind = 'image' AND deleted_at IS NULL",
            &[&project_id],
        )
        .await?;
    Ok(row.and_then(|r| {
        match (
            r.get::<_, Option<String>>("icon_image_storage_key"),
            r.get::<_, Option<String>>("icon_image_mime"),
        ) {
            (Some(k), Some(m)) => Some((k, m)),
            _ => None,
        }
    }))
}

/// Point a project's icon at an uploaded image object.
pub async fn set_icon_image(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    storage_key: &str,
    mime: &str,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE projects SET icon_image_kind = 'image', icon_image_storage_key = $2, \
                 icon_image_mime = $3, icon_image_updated_at = now() \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&project_id, &storage_key, &mime],
        )
        .await?;
    Ok(n > 0)
}

/// Reset a project's icon to the prefix-initials fallback.
pub async fn clear_icon_image(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE projects SET icon_image_kind = 'none', icon_image_storage_key = NULL, \
                 icon_image_mime = NULL, icon_image_updated_at = NULL \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&project_id],
        )
        .await?;
    Ok(n > 0)
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
