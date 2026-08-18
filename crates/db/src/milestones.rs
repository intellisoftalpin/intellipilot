//! Milestone persistence + sprint board/stats queries.

use intellipilot_core::milestone::{Milestone, MilestoneStats};
use time::Date;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;
use crate::backlog::UpdateOutcome;

const COLS: &str = "id, project_id, name, slug, description, start_date, end_date, \
     actual_end_date, \
     business_release_date, closed, closed_at, \"order\", version, created_at, modified_at";

fn row_to_milestone(r: &Row) -> Milestone {
    Milestone {
        id: r.get("id"),
        project_id: r.get("project_id"),
        name: r.get("name"),
        slug: r.get("slug"),
        description: r.get("description"),
        start_date: r.get("start_date"),
        end_date: r.get("end_date"),
        actual_end_date: r.get("actual_end_date"),
        business_release_date: r.get("business_release_date"),
        closed: r.get("closed"),
        closed_at: r.get("closed_at"),
        order: r.get("order"),
        version: r.get("version"),
        created_at: r.get("created_at"),
        modified_at: r.get("modified_at"),
    }
}

/// A partial milestone edit. `None` leaves the field alone; `Some(None)` on a
/// nullable field clears it. Distinguishing the two is what lets the detail
/// sidebar clear a date rather than only overwrite it.
#[derive(Debug, Default, Clone)]
pub struct MilestonePatch<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub start_date: Option<Option<Date>>,
    pub end_date: Option<Option<Date>>,
    pub actual_end_date: Option<Option<Date>>,
    pub business_release_date: Option<Option<Date>>,
}

/// The field set for a new milestone.
#[derive(Debug, Clone)]
pub struct MilestoneNew<'a> {
    pub name: &'a str,
    pub slug: &'a str,
    pub description: &'a str,
    pub start_date: Option<Date>,
    pub end_date: Option<Date>,
    pub actual_end_date: Option<Date>,
    pub business_release_date: Option<Date>,
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    new: &MilestoneNew<'_>,
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
                "INSERT INTO milestones \
                   (project_id, name, slug, description, start_date, end_date, \
                    actual_end_date, business_release_date, \"order\") \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING {COLS}"
            ),
            &[
                &project_id,
                &new.name,
                &new.slug,
                &new.description,
                &new.start_date,
                &new.end_date,
                &new.actual_end_date,
                &new.business_release_date,
                &order,
            ],
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

/// Apply a partial edit under an optimistic-concurrency guard.
///
/// Every field is set through a `CASE WHEN <present> THEN <value> ELSE <col>`
/// pair so "absent" and "explicit null" stay distinguishable in one statement.
/// Clearing `end_date` also clears `business_release_date`: a business release
/// with no technical release behind it violates the table CHECK, and silently
/// dropping it beats failing the user's save.
pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    expected_version: i32,
    patch: &MilestonePatch<'_>,
) -> Result<UpdateOutcome<Milestone>, DbError> {
    let (name_set, name) = (patch.name.is_some(), patch.name);
    let (desc_set, desc) = (patch.description.is_some(), patch.description);
    let (start_set, start) = (patch.start_date.is_some(), patch.start_date.flatten());
    let (end_set, end) = (patch.end_date.is_some(), patch.end_date.flatten());
    let (actual_set, actual) = (
        patch.actual_end_date.is_some(),
        patch.actual_end_date.flatten(),
    );
    let (biz_set, biz) = (
        patch.business_release_date.is_some(),
        patch.business_release_date.flatten(),
    );
    let row = client
        .query_opt(
            &format!(
                "UPDATE milestones SET \
                   name = CASE WHEN $4::bool THEN $5::text ELSE name END, \
                   description = CASE WHEN $6::bool THEN $7::text ELSE description END, \
                   start_date = CASE WHEN $8::bool THEN $9::date ELSE start_date END, \
                   end_date = CASE WHEN $10::bool THEN $11::date ELSE end_date END, \
                   actual_end_date = CASE \
                     WHEN $12::bool THEN $13::date ELSE actual_end_date END, \
                   business_release_date = CASE \
                     WHEN $14::bool THEN $15::date \
                     WHEN COALESCE( \
                            CASE WHEN $12::bool THEN $13::date \
                                 ELSE actual_end_date END, \
                            CASE WHEN $10::bool THEN $11::date \
                                 ELSE end_date END \
                          ) IS NULL THEN NULL \
                     ELSE business_release_date END, \
                   version = version + 1 \
                 WHERE id=$1 AND project_id=$2 AND version=$3 AND deleted_at IS NULL \
                 RETURNING {COLS}"
            ),
            &[
                &id,
                &project_id,
                &expected_version,
                &name_set,
                &name,
                &desc_set,
                &desc,
                &start_set,
                &start,
                &end_set,
                &end,
                &actual_set,
                &actual,
                &biz_set,
                &biz,
            ],
        )
        .await?;
    match row {
        Some(r) => Ok(UpdateOutcome::Updated(row_to_milestone(&r))),
        None => {
            crate::backlog::classify_miss(client, "milestones", project_id, id, expected_version)
                .await
        }
    }
}

/// Mark a milestone completed (idempotent). Returns the completed milestone.
pub async fn close(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Milestone>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE milestones SET closed=true, \
                   closed_at=COALESCE(closed_at, now()), \
                   actual_end_date=COALESCE(actual_end_date, end_date), \
                   version=version+1 \
                 WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL RETURNING {COLS}"
            ),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_milestone))
}

/// Reopen a completed milestone (idempotent). Clears `closed_at` so a later
/// completion timestamps afresh rather than reporting the first one.
pub async fn reopen(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Milestone>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE milestones SET closed=false, closed_at=NULL, version=version+1 \
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

/// Whether any live epic still belongs to this milestone.
///
/// Deleting a milestone that still composes epics is refused: the epics would
/// silently lose their milestone (FK `ON DELETE SET NULL`) and, through the
/// V019 cascade, so would every issue under them.
pub async fn has_epics(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM epics \
               WHERE milestone_id=$1 AND project_id=$2 AND deleted_at IS NULL) AS e",
            &[&id, &project_id],
        )
        .await?;
    Ok(row.get("e"))
}

/// Sprint stats over the issues in a milestone.
///
/// Since V019 `issues.milestone_id` is maintained by trigger from the issue's
/// epic, so this reads epic-derived membership without joining through epics.
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
