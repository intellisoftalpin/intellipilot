//! Milestone persistence + sprint board/stats queries.

use intellipilot_core::milestone::{Milestone, MilestoneStats};
use time::Date;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, name, slug, start_date, end_date, closed, closed_at, \
     \"order\", version, created_at, modified_at";

fn row_to_milestone(r: &Row) -> Milestone {
    Milestone {
        id: r.get("id"),
        project_id: r.get("project_id"),
        name: r.get("name"),
        slug: r.get("slug"),
        start_date: r.get("start_date"),
        end_date: r.get("end_date"),
        closed: r.get("closed"),
        closed_at: r.get("closed_at"),
        order: r.get("order"),
        version: r.get("version"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    name: &str,
    slug: &str,
    start_date: Option<Date>,
    end_date: Option<Date>,
) -> Result<Milestone, DbError> {
    let order = {
        let row = client
            .query_one(
                "SELECT COALESCE(max(\"order\"), 0.0) + 1.0 AS o FROM milestones WHERE project_id = $1",
                &[&project_id],
            )
            .await?;
        row.get::<_, f64>("o")
    };
    let row = client
        .query_one(
            &format!(
                "INSERT INTO milestones (project_id, name, slug, start_date, end_date, \"order\") \
                 VALUES ($1,$2,$3,$4,$5,$6) RETURNING {COLS}"
            ),
            &[&project_id, &name, &slug, &start_date, &end_date, &order],
        )
        .await?;
    Ok(row_to_milestone(&row))
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Milestone>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {COLS} FROM milestones WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL"
            ),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_milestone))
}

pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<Milestone>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {COLS} FROM milestones WHERE project_id=$1 AND deleted_at IS NULL ORDER BY \"order\""),
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_milestone).collect())
}

pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    name: Option<&str>,
    start_date: Option<Date>,
    end_date: Option<Date>,
) -> Result<Option<Milestone>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE milestones SET name=COALESCE($3,name), \
                   start_date=COALESCE($4,start_date), end_date=COALESCE($5,end_date), \
                   version=version+1 \
                 WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL RETURNING {COLS}"
            ),
            &[&id, &project_id, &name, &start_date, &end_date],
        )
        .await?;
    Ok(row.as_ref().map(row_to_milestone))
}

/// Mark a milestone closed (idempotent). Returns the closed milestone.
pub async fn close(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Milestone>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE milestones SET closed=true, \
                   closed_at=COALESCE(closed_at, now()), version=version+1 \
                 WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL RETURNING {COLS}"
            ),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_milestone))
}

pub async fn soft_delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE milestones SET deleted_at=now() WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// Whether a milestone exists in this project (and is not deleted).
pub async fn in_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM milestones WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL) AS e",
            &[&id, &project_id],
        )
        .await?;
    Ok(row.get("e"))
}

/// Whether a milestone is currently closed.
pub async fn is_closed(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let row = client
        .query_opt(
            "SELECT closed FROM milestones WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL",
            &[&id, &project_id],
        )
        .await?;
    Ok(row.is_some_and(|r| r.get::<_, bool>("closed")))
}

/// Sprint stats over the issues assigned to a milestone.
///
/// Size-ordinal totals (via each issue's `size_id` → taxonomy `value`) and
/// issue counts, with "completed" meaning a closed status. `total_tasks` /
/// `completed_tasks` count issues in the sprint (the unified work item).
pub async fn stats(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    milestone_id: Uuid,
) -> Result<MilestoneStats, DbError> {
    let row = client
        .query_one(
            "SELECT \
               COALESCE(sum(pt.value), 0)::float8 AS total_points, \
               COALESCE(sum(CASE WHEN st.is_closed THEN pt.value ELSE 0 END), 0)::float8 \
                 AS done_points, \
               count(*)::int8 AS total_tasks, \
               count(*) FILTER (WHERE st.is_closed)::int8 AS done_tasks \
             FROM issues i \
             LEFT JOIN taxonomy_items pt ON pt.id = i.size_id \
             LEFT JOIN taxonomy_items st ON st.id = i.status_id \
             WHERE i.project_id = $1 AND i.milestone_id = $2 AND i.deleted_at IS NULL",
            &[&project_id, &milestone_id],
        )
        .await?;
    Ok(MilestoneStats {
        total_points: row.get("total_points"),
        completed_points: row.get("done_points"),
        total_tasks: row.get("total_tasks"),
        completed_tasks: row.get("done_tasks"),
    })
}
