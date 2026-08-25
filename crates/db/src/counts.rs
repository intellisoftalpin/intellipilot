//! Project rail count queries (see [`intellipilot_core::counts`]).

use intellipilot_core::counts::{CountScopes, ProjectCounts};
use uuid::Uuid;

use crate::DbError;
use crate::backlog::my_role_any_sql;

/// Active-object counts for one project's rail, in a single round trip.
///
/// Only the permitted counts are put in the SELECT list, so an unpermitted
/// section costs nothing — in particular the `my_issues` mention scan is never
/// run for a caller without `issue.view`. `mention_like` is the caller's
/// escaped `%@handle%` pattern; when it is `None` the mention role simply
/// matches nothing.
pub async fn project_counts(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    actor_id: Uuid,
    mention_like: Option<&str>,
    scopes: CountScopes,
) -> Result<ProjectCounts, DbError> {
    if !scopes.any() {
        return Ok(ProjectCounts::default());
    }

    let mut cols: Vec<String> = Vec::with_capacity(4);
    if scopes.issues {
        // Sub-tasks included, to match the issues list.
        cols.push(
            "(SELECT count(*) FROM issues i \
               LEFT JOIN taxonomy_items st ON st.id = i.status_id \
              WHERE i.project_id = $1 AND i.deleted_at IS NULL \
                AND st.is_closed IS NOT TRUE)::int8 AS issues"
                .to_owned(),
        );
        // Top-level only, to match the My Issues board (which, like every
        // board, renders sub-tasks nested inside their parent card rather than
        // as cards of their own). The role predicates are written against a
        // table named `issues`, so this subquery must not alias it.
        cols.push(format!(
            "(SELECT count(*) FROM issues \
               LEFT JOIN taxonomy_items st ON st.id = issues.status_id \
              WHERE issues.project_id = $1 AND issues.deleted_at IS NULL \
                AND issues.parent_id IS NULL \
                AND st.is_closed IS NOT TRUE \
                AND ({}))::int8 AS my_issues",
            my_role_any_sql("$2::uuid", "$3::text")
        ));
    }
    if scopes.epics {
        cols.push(
            "(SELECT count(*) FROM epics e \
               LEFT JOIN taxonomy_items st ON st.id = e.status_id \
              WHERE e.project_id = $1 AND e.deleted_at IS NULL \
                AND st.is_closed IS NOT TRUE)::int8 AS epics"
                .to_owned(),
        );
    }
    if scopes.milestones {
        cols.push(
            "(SELECT count(*) FROM milestones \
              WHERE project_id = $1 AND deleted_at IS NULL \
                AND closed IS NOT TRUE)::int8 AS milestones"
                .to_owned(),
        );
    }

    let sql = format!("SELECT {}", cols.join(", "));
    let pattern = mention_like.map(str::to_owned);
    let row = client
        .query_one(&sql, &[&project_id, &actor_id, &pattern])
        .await?;

    Ok(ProjectCounts {
        my_issues: scopes.issues.then(|| row.get("my_issues")),
        issues: scopes.issues.then(|| row.get("issues")),
        epics: scopes.epics.then(|| row.get("epics")),
        milestones: scopes.milestones.then(|| row.get("milestones")),
    })
}
