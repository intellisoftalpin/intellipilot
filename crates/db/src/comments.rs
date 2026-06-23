//! Comment persistence (polymorphic over backlog entity kind).

use intellipilot_core::backlog::Comment;
use intellipilot_core::user::UserBrief;
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, target_type, target_id, author_id, body, body_html, edited_at, created_at";

/// The author descriptor, present only when the row was joined to `users`
/// (the list query) and the author still exists.
fn author_from_row(r: &Row) -> Option<UserBrief> {
    let id: Option<Uuid> = r.get("author_id");
    let id = id?;
    // Absent on create/update (RETURNING without the join) → None.
    let username = r.try_get::<_, Option<String>>("username").ok().flatten()?;
    Some(UserBrief {
        id,
        username,
        full_name: r.try_get("full_name").ok().flatten().unwrap_or_default(),
        email: r.try_get("email").ok().flatten().unwrap_or_default(),
        card: crate::users::card_from_row(r),
    })
}

fn row_to_comment(r: &Row) -> Comment {
    Comment {
        id: r.get("id"),
        target_type: r.get("target_type"),
        target_id: r.get("target_id"),
        author_id: r.get("author_id"),
        body: r.get("body"),
        body_html: r.get("body_html"),
        edited_at: r.get("edited_at"),
        created_at: r.get("created_at"),
        author: author_from_row(r),
    }
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    target_type: &str,
    target_id: Uuid,
    author_id: Uuid,
    body: &str,
    body_html: &str,
) -> Result<Comment, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO comments (project_id, target_type, target_id, author_id, body, body_html) \
                 VALUES ($1,$2,$3,$4,$5,$6) RETURNING {COLS}"
            ),
            &[&project_id, &target_type, &target_id, &author_id, &body, &body_html],
        )
        .await?;
    Ok(row_to_comment(&row))
}

pub async fn list(
    client: &deadpool_postgres::Client,
    target_type: &str,
    target_id: Uuid,
) -> Result<Vec<Comment>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT c.id, c.target_type, c.target_id, c.author_id, c.body, c.body_html, \
                        c.edited_at, c.created_at, u.username, u.full_name, u.email{card}{ooo} \
                 FROM comments c \
                 LEFT JOIN users u ON u.id = c.author_id{join} \
                 WHERE c.target_type=$1 AND c.target_id=$2 AND c.deleted_at IS NULL \
                 ORDER BY c.created_at",
                card = crate::users::CARD_COLS,
                ooo = crate::users::OUT_TODAY_COLS,
                join = crate::users::out_today_join("u"),
            ),
            &[&target_type, &target_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_comment).collect())
}

/// Author + creation time of a comment, for edit-window enforcement.
pub async fn meta(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<(Option<Uuid>, OffsetDateTime)>, DbError> {
    let row = client
        .query_opt(
            "SELECT author_id, created_at FROM comments WHERE id=$1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(row.map(|r| (r.get("author_id"), r.get("created_at"))))
}

pub async fn update(
    client: &deadpool_postgres::Client,
    id: Uuid,
    body: &str,
    body_html: &str,
) -> Result<Option<Comment>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE comments SET body=$2, body_html=$3, edited_at=now() \
                 WHERE id=$1 AND deleted_at IS NULL RETURNING {COLS}"
            ),
            &[&id, &body, &body_html],
        )
        .await?;
    Ok(row.as_ref().map(row_to_comment))
}

pub async fn soft_delete(client: &deadpool_postgres::Client, id: Uuid) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE comments SET deleted_at=now() WHERE id=$1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(n > 0)
}
