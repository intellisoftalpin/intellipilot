//! Membership persistence + the access lookup used for permission checks.

use intellipilot_core::perms::Permission;
use intellipilot_core::project::Membership;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

/// A user's effective access within a project.
#[derive(Debug, Clone)]
pub struct MemberAccess {
    pub membership_id: Uuid,
    pub role_id: Uuid,
    pub role_slug: String,
    pub is_admin: bool,
    pub permissions: Vec<Permission>,
}

impl MemberAccess {
    /// Admins implicitly hold every permission.
    #[must_use]
    pub fn has(&self, perm: Permission) -> bool {
        self.is_admin || self.permissions.contains(&perm)
    }
}

/// Look up the actor's access for a project (None if not a member).
pub async fn access(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<Option<MemberAccess>, DbError> {
    let row = client
        .query_opt(
            "SELECT m.id AS membership_id, r.id AS role_id, r.slug AS role_slug, \
                    r.is_admin, r.permissions \
             FROM memberships m JOIN roles r ON r.id = m.role_id \
             WHERE m.project_id = $1 AND m.user_id = $2",
            &[&project_id, &user_id],
        )
        .await?;
    match row {
        None => Ok(None),
        Some(r) => {
            let perms_json: serde_json::Value = r.get("permissions");
            let permissions: Vec<Permission> = serde_json::from_value(perms_json)?;
            Ok(Some(MemberAccess {
                membership_id: r.get("membership_id"),
                role_id: r.get("role_id"),
                role_slug: r.get("role_slug"),
                is_admin: r.get("is_admin"),
                permissions,
            }))
        }
    }
}

fn row_to_membership(row: &Row) -> Membership {
    Membership {
        id: row.get("id"),
        project_id: row.get("project_id"),
        user_id: row.get("user_id"),
        username: row.get("username"),
        full_name: row.get("full_name"),
        email: row.get("email"),
        role_id: row.get("role_id"),
        role_slug: row.get("role_slug"),
        created_at: row.get("created_at"),
    }
}

pub async fn list_for_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<Membership>, DbError> {
    let rows = client
        .query(
            "SELECT m.id, m.project_id, m.user_id, u.username, u.full_name, u.email, \
                    m.role_id, r.slug AS role_slug, m.created_at \
             FROM memberships m \
             JOIN roles r ON r.id = m.role_id \
             JOIN users u ON u.id = m.user_id \
             WHERE m.project_id = $1 ORDER BY m.created_at",
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_membership).collect())
}

/// Add (or upsert) a membership. Returns the membership id.
pub async fn upsert(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
    invited_by: Option<Uuid>,
) -> Result<Uuid, DbError> {
    let row = client
        .query_one(
            "INSERT INTO memberships (project_id, user_id, role_id, invited_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (project_id, user_id) DO UPDATE SET role_id = EXCLUDED.role_id \
             RETURNING id",
            &[&project_id, &user_id, &role_id, &invited_by],
        )
        .await?;
    Ok(row.get("id"))
}

/// Change a member's role. Returns true if a row was affected.
pub async fn change_role(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE memberships SET role_id = $3 WHERE project_id = $1 AND user_id = $2",
            &[&project_id, &user_id, &role_id],
        )
        .await?;
    Ok(n > 0)
}

/// Remove a member. Returns true if removed.
pub async fn remove(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM memberships WHERE project_id = $1 AND user_id = $2",
            &[&project_id, &user_id],
        )
        .await?;
    Ok(n > 0)
}

/// Count members holding an admin role (to prevent removing the last admin).
pub async fn admin_count(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM memberships m JOIN roles r ON r.id = m.role_id \
             WHERE m.project_id = $1 AND r.is_admin = true",
            &[&project_id],
        )
        .await?;
    Ok(row.get("n"))
}
