//! Issue relationship persistence (blocks / relates / duplicates).
//!
//! Links are stored once, directed (source → target). For a queried issue we
//! return both outgoing links (it is the source) and incoming links (it is the
//! target), tagging each with a `direction` so the UI can render inverses.

use intellipilot_core::backlog::{IssueLink, LinkType};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

fn row_to_link(r: &Row) -> IssueLink {
    IssueLink {
        id: r.get("id"),
        other_issue_id: r.get("other_id"),
        other_ref: r.get("other_ref"),
        other_subject: r.get("other_subject"),
        link_type: r
            .get::<_, Option<String>>("type")
            .and_then(|s| LinkType::parse(&s))
            .unwrap_or(LinkType::Relates),
        direction: r.get("direction"),
        created_at: r.get("created_at"),
    }
}

/// Outgoing + incoming links for an issue (non-deleted counterparts only).
pub async fn list_for_issue(
    client: &deadpool_postgres::Client,
    issue_id: Uuid,
) -> Result<Vec<IssueLink>, DbError> {
    let rows = client
        .query(
            "SELECT l.id, l.type, l.created_at, 'outgoing' AS direction, \
                    i.id AS other_id, i.ref AS other_ref, i.subject AS other_subject \
             FROM issue_links l JOIN issues i ON i.id = l.target_issue_id \
             WHERE l.source_issue_id = $1 AND i.deleted_at IS NULL \
             UNION ALL \
             SELECT l.id, l.type, l.created_at, 'incoming' AS direction, \
                    i.id AS other_id, i.ref AS other_ref, i.subject AS other_subject \
             FROM issue_links l JOIN issues i ON i.id = l.source_issue_id \
             WHERE l.target_issue_id = $1 AND i.deleted_at IS NULL \
             ORDER BY created_at",
            &[&issue_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_link).collect())
}

/// Create a link and return it as an outgoing view of the source issue.
pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    source_issue_id: Uuid,
    target_issue_id: Uuid,
    link_type: &str,
) -> Result<IssueLink, DbError> {
    let row = client
        .query_one(
            "WITH ins AS ( \
               INSERT INTO issue_links (project_id, source_issue_id, target_issue_id, type) \
               VALUES ($1,$2,$3,$4) RETURNING id, target_issue_id, type, created_at \
             ) \
             SELECT ins.id, ins.type, ins.created_at, 'outgoing' AS direction, \
                    i.id AS other_id, i.ref AS other_ref, i.subject AS other_subject \
             FROM ins JOIN issues i ON i.id = ins.target_issue_id",
            &[&project_id, &source_issue_id, &target_issue_id, &link_type],
        )
        .await?;
    Ok(row_to_link(&row))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM issue_links WHERE id=$1 AND project_id=$2",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}
