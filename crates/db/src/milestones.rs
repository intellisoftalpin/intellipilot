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

/// Sprint stats: point totals (via the US `points_id` → taxonomy value) and
/// task counts, with "completed" meaning a closed status.
pub async fn stats(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    milestone_id: Uuid,
) -> Result<MilestoneStats, DbError> {
    let points_row = client
        .query_one(
            "SELECT \
               COALESCE(sum(pt.value), 0)::float8 AS total, \
               COALESCE(sum(CASE WHEN st.is_closed THEN pt.value ELSE 0 END), 0)::float8 AS done \
             FROM user_stories us \
             LEFT JOIN taxonomy_items pt ON pt.id = us.points_id \
             LEFT JOIN taxonomy_items st ON st.id = us.status_id \
             WHERE us.project_id = $1 AND us.milestone_id = $2 AND us.deleted_at IS NULL",
            &[&project_id, &milestone_id],
        )
        .await?;
    let task_row = client
        .query_one(
            "SELECT \
               count(*)::int8 AS total, \
               count(*) FILTER (WHERE tst.is_closed)::int8 AS done \
             FROM tasks t \
             JOIN user_stories us ON us.id = t.user_story_id \
             LEFT JOIN taxonomy_items tst ON tst.id = t.status_id \
             WHERE us.project_id = $1 AND us.milestone_id = $2 \
               AND us.deleted_at IS NULL AND t.deleted_at IS NULL",
            &[&project_id, &milestone_id],
        )
        .await?;
    Ok(MilestoneStats {
        total_points: points_row.get("total"),
        completed_points: points_row.get("done"),
        total_tasks: task_row.get("total"),
        completed_tasks: task_row.get("done"),
    })
}
