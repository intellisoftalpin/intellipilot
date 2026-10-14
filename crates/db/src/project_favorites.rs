//! Per-user favorite projects (V030).
//!
//! The set is small and always written whole: [`replace`] swaps it in one
//! transaction, [`list`] reads it back in starred order. Projects the user can
//! no longer see are filtered out on read, so a lost membership or a
//! soft-deleted project never leaks back through a stale favorite.

use uuid::Uuid;

use crate::DbError;

/// The user's favorite project ids, in the order they were starred. Only
/// projects the user can still see — every live project for a superadmin
/// (`superadmin`), their memberships otherwise.
pub async fn list(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    superadmin: bool,
) -> Result<Vec<Uuid>, DbError> {
    let rows = client
        .query(
            "SELECT f.project_id FROM user_project_favorites f \
             JOIN projects p ON p.id = f.project_id AND p.deleted_at IS NULL \
             WHERE f.user_id = $1 \
               AND ($2 OR EXISTS ( \
                    SELECT 1 FROM memberships m \
                    WHERE m.project_id = f.project_id AND m.user_id = f.user_id)) \
             ORDER BY f.position, f.created_at",
            &[&user_id, &superadmin],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("project_id")).collect())
}

/// How many of `ids` the user can see. The caller compares it with the
/// number it asked about to reject unknown or foreign projects.
pub async fn count_visible(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    superadmin: bool,
    ids: &[Uuid],
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM projects p \
             WHERE p.id = ANY($3) AND p.deleted_at IS NULL \
               AND ($2 OR EXISTS ( \
                    SELECT 1 FROM memberships m \
                    WHERE m.project_id = p.id AND m.user_id = $1))",
            &[&user_id, &superadmin, &ids],
        )
        .await?;
    Ok(row.get("n"))
}

/// Replace the user's favorites with `ids`, in that order.
pub async fn replace(
    client: &mut deadpool_postgres::Client,
    user_id: Uuid,
    ids: &[Uuid],
) -> Result<(), DbError> {
    let tx = client.transaction().await?;
    tx.execute(
        "DELETE FROM user_project_favorites WHERE user_id = $1",
        &[&user_id],
    )
    .await?;
    for (i, id) in ids.iter().enumerate() {
        let position = i16::try_from(i).unwrap_or(i16::MAX);
        tx.execute(
            "INSERT INTO user_project_favorites (user_id, project_id, position) \
             VALUES ($1, $2, $3)",
            &[&user_id, id, &position],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
