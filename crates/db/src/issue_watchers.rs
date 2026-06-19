//! Issue watcher persistence (users subscribed to an issue's notifications).

use uuid::Uuid;

use crate::DbError;

pub async fn list(
    client: &deadpool_postgres::Client,
    issue_id: Uuid,
) -> Result<Vec<Uuid>, DbError> {
    let rows = client
        .query(
            "SELECT user_id FROM issue_watchers WHERE issue_id=$1 ORDER BY user_id",
            &[&issue_id],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("user_id")).collect())
}

/// Add a watcher (idempotent). Returns true if a row was inserted.
pub async fn add(
    client: &deadpool_postgres::Client,
    issue_id: Uuid,
    user_id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "INSERT INTO issue_watchers (issue_id, user_id) VALUES ($1,$2) \
             ON CONFLICT DO NOTHING",
            &[&issue_id, &user_id],
        )
        .await?;
    Ok(n > 0)
}

pub async fn remove(
    client: &deadpool_postgres::Client,
    issue_id: Uuid,
    user_id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM issue_watchers WHERE issue_id=$1 AND user_id=$2",
            &[&issue_id, &user_id],
        )
        .await?;
    Ok(n > 0)
}
