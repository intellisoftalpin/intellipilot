//! Wiki persistence: pages + immutable revisions. Every save snapshots a
//! revision in the same transaction as the page write.
#![allow(clippy::too_many_arguments)]

use intellipilot_core::wiki::{WikiPage, WikiRevision};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const PAGE_COLS: &str = "id, project_id, slug, title, body, body_html, version, editor_id, \
     created_at, modified_at";

fn row_to_page(r: &Row) -> WikiPage {
    WikiPage {
        id: r.get("id"),
        project_id: r.get("project_id"),
        slug: r.get("slug"),
        title: r.get("title"),
        body: r.get("body"),
        body_html: r.get("body_html"),
        version: r.get("version"),
        editor_id: r.get("editor_id"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

fn row_to_revision(r: &Row, with_body: bool) -> WikiRevision {
    WikiRevision {
        id: r.get("id"),
        page_id: r.get("page_id"),
        rev: r.get("rev"),
        title: r.get("title"),
        body: with_body.then(|| r.get::<_, String>("body")),
        editor_id: r.get("editor_id"),
        created_at: r.get("created_at"),
    }
}

/// Create a page at revision 1 (page row + first revision, transactionally).
pub async fn create(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
    slug: &str,
    title: &str,
    body: &str,
    body_html: &str,
    editor_id: Uuid,
) -> Result<WikiPage, DbError> {
    let tx = client.transaction().await?;
    let prow = tx
        .query_one(
            &format!(
                "INSERT INTO wiki_pages (project_id, slug, title, body, body_html, version, editor_id) \
                 VALUES ($1,$2,$3,$4,$5,1,$6) RETURNING {PAGE_COLS}"
            ),
            &[&project_id, &slug, &title, &body, &body_html, &editor_id],
        )
        .await?;
    let page = row_to_page(&prow);
    tx.execute(
        "INSERT INTO wiki_page_revisions (page_id, rev, title, body, editor_id) \
         VALUES ($1, 1, $2, $3, $4)",
        &[&page.id, &title, &body, &editor_id],
    )
    .await?;
    tx.commit().await?;
    Ok(page)
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<WikiPage>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {PAGE_COLS} FROM wiki_pages WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL"),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_page))
}

pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<WikiPage>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {PAGE_COLS} FROM wiki_pages WHERE project_id=$1 AND deleted_at IS NULL ORDER BY slug"),
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_page).collect())
}

/// Update a page and snapshot a new revision, transactionally. Returns the
/// updated page (or None if not found).
pub async fn update(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    title: &str,
    body: &str,
    body_html: &str,
    editor_id: Uuid,
) -> Result<Option<WikiPage>, DbError> {
    let tx = client.transaction().await?;
    let prow = tx
        .query_opt(
            &format!(
                "UPDATE wiki_pages SET title=$3, body=$4, body_html=$5, editor_id=$6, \
                   version=version+1 \
                 WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL RETURNING {PAGE_COLS}"
            ),
            &[&id, &project_id, &title, &body, &body_html, &editor_id],
        )
        .await?;
    let Some(prow) = prow else {
        tx.rollback().await?;
        return Ok(None);
    };
    let page = row_to_page(&prow);
    tx.execute(
        "INSERT INTO wiki_page_revisions (page_id, rev, title, body, editor_id) \
         VALUES ($1, $2, $3, $4, $5)",
        &[&page.id, &page.version, &title, &body, &editor_id],
    )
    .await?;
    tx.commit().await?;
    Ok(Some(page))
}

pub async fn soft_delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE wiki_pages SET deleted_at=now() WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// List revisions (newest first), without bodies.
pub async fn list_revisions(
    client: &deadpool_postgres::Client,
    page_id: Uuid,
) -> Result<Vec<WikiRevision>, DbError> {
    let rows = client
        .query(
            "SELECT id, page_id, rev, title, editor_id, created_at FROM wiki_page_revisions \
             WHERE page_id=$1 ORDER BY rev DESC",
            &[&page_id],
        )
        .await?;
    Ok(rows.iter().map(|r| row_to_revision(r, false)).collect())
}

/// Fetch a single revision, including its body.
pub async fn get_revision(
    client: &deadpool_postgres::Client,
    page_id: Uuid,
    rev: i32,
) -> Result<Option<WikiRevision>, DbError> {
    let row = client
        .query_opt(
            "SELECT id, page_id, rev, title, body, editor_id, created_at \
             FROM wiki_page_revisions WHERE page_id=$1 AND rev=$2",
            &[&page_id, &rev],
        )
        .await?;
    Ok(row.as_ref().map(|r| row_to_revision(r, true)))
}
