//! Cross-project personal work feed queries (`/api/v1/me/issues`).
//!
//! Direct-role listings (assignee/reporter/reviewer/QA) need no visibility
//! guard: being named on an issue IS involvement (same reasoning as the home
//! dashboard). The `mentioned` role is text-derived (`@username` in the
//! description or a comment), so it additionally requires the project to be
//! visible to the user — non-private, or the user is a member or superadmin —
//! to avoid leaking private-project issues via a lucky handle match.

use std::fmt::Write as _;

use intellipilot_core::my_work::{MyIssue, MyIssueRole};
use time::Date;
use tokio_postgres::Row;
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::DbError;

const ISO: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");

fn row_to_issue(row: &Row) -> MyIssue {
    let prefix: String = row.get("issue_prefix");
    let reference: i64 = row.get("ref");
    let due: Option<Date> = row.get("due_date");
    MyIssue {
        id: row.get("id"),
        reference,
        key: format!("{prefix}-{reference}"),
        subject: row.get("subject"),
        project_id: row.get("project_id"),
        project_slug: row.get("project_slug"),
        project_name: row.get("project_name"),
        status: row.get("status"),
        is_closed: row.get("is_closed"),
        issue_type: row.get("issue_type"),
        priority: row.get("priority"),
        assigned_to: row.get("assigned_to"),
        owner_id: row.get("owner_id"),
        reviewer_id: row.get("reviewer_id"),
        qa_assignee_id: row.get("qa_assignee_id"),
        due_date: due.map(|d| d.format(&ISO).unwrap_or_default()),
        created_at: row.get("created_at"),
        modified_at: row.get("modified_at"),
    }
}

/// Escape LIKE metacharacters so the username is matched literally.
fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

const FROM: &str = "FROM issues i \
     JOIN projects p ON p.id = i.project_id \
     LEFT JOIN taxonomy_items st ON st.id = i.status_id \
     LEFT JOIN taxonomy_items ty ON ty.id = i.type_id \
     LEFT JOIN taxonomy_items pr ON pr.id = i.priority_id";

const fn role_condition(role: MyIssueRole) -> &'static str {
    match role {
        MyIssueRole::Assignee => "i.assigned_to = $1",
        MyIssueRole::Reporter => "i.owner_id = $1",
        MyIssueRole::Reviewer => "i.reviewer_id = $1",
        MyIssueRole::Qa => "i.qa_assignee_id = $1",
        // $N for the '@username' ILIKE pattern is appended by the caller.
        MyIssueRole::Mentioned => {
            "(i.description ILIKE $MENTION ESCAPE '\\' \
              OR EXISTS (SELECT 1 FROM comments c \
                         WHERE c.target_type = 'issue' AND c.target_id = i.id \
                           AND c.deleted_at IS NULL \
                           AND c.body ILIKE $MENTION ESCAPE '\\')) \
             AND (p.visibility <> 'private' \
                  OR EXISTS (SELECT 1 FROM memberships m \
                             WHERE m.project_id = i.project_id AND m.user_id = $1) \
                  OR EXISTS (SELECT 1 FROM users su \
                             WHERE su.id = $1 AND su.is_superadmin))"
        }
    }
}

/// List the user's issues for one role, newest-modified first.
///
/// Returns the page plus the total row count for paging. `username` is only
/// consulted for [`MyIssueRole::Mentioned`]; `project_id` optionally narrows
/// the feed to one project.
#[allow(clippy::too_many_arguments)]
pub async fn list(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    username: &str,
    role: MyIssueRole,
    project_id: Option<Uuid>,
    include_closed: bool,
    search: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<MyIssue>, i64), DbError> {
    let mut params: Vec<Box<dyn ToSql + Sync + Send>> = vec![Box::new(user_id)];
    let mut cond = role_condition(role).to_owned();

    if role == MyIssueRole::Mentioned {
        params.push(Box::new(format!("%@{}%", like_escape(username))));
        cond = cond.replace("$MENTION", &format!("${}", params.len()));
    }

    let mut where_sql = format!("i.deleted_at IS NULL AND {cond}");
    if let Some(pid) = project_id {
        params.push(Box::new(pid));
        let _ = write!(where_sql, " AND i.project_id = ${}", params.len());
    }
    if !include_closed {
        where_sql.push_str(" AND st.is_closed IS NOT TRUE");
    }
    if let Some(q) = search {
        params.push(Box::new(format!("%{}%", like_escape(q))));
        let _ = write!(
            where_sql,
            " AND i.subject ILIKE ${} ESCAPE '\\'",
            params.len()
        );
    }

    let refs: Vec<&(dyn ToSql + Sync)> = params
        .iter()
        .map(|p| p.as_ref() as &(dyn ToSql + Sync))
        .collect();

    let count_sql = format!("SELECT count(*)::int8 AS total {FROM} WHERE {where_sql}");
    let total: i64 = client.query_one(&count_sql, &refs).await?.get("total");

    let limit_ph = refs.len().saturating_add(1);
    let offset_ph = refs.len().saturating_add(2);
    let page_sql = format!(
        "SELECT i.id, i.ref, i.subject, i.assigned_to, i.owner_id, i.reviewer_id, \
                i.qa_assignee_id, i.due_date, i.created_at, i.modified_at, \
                p.id AS project_id, p.slug AS project_slug, p.name AS project_name, \
                p.issue_prefix, \
                st.name AS status, COALESCE(st.is_closed, false) AS is_closed, \
                ty.name AS issue_type, pr.name AS priority \
         {FROM} WHERE {where_sql} \
         ORDER BY i.modified_at DESC, i.id DESC \
         LIMIT ${limit_ph} OFFSET ${offset_ph}"
    );
    let mut page_refs = refs;
    page_refs.push(&limit);
    page_refs.push(&offset);
    let rows = client.query(&page_sql, &page_refs).await?;
    Ok((rows.iter().map(row_to_issue).collect(), total))
}
