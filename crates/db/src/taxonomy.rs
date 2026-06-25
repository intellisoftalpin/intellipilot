//! Taxonomy persistence: per-project, kind-scoped items with fractional
//! ordering and a renormalization fallback.
#![allow(clippy::option_if_let_else)] // the 3-way if/else-if reads clearer here

use intellipilot_core::ordering::{normalized_ranks, rank_between};
use intellipilot_core::taxonomy::{TaxonomyItem, TaxonomyKind};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str =
    "id, project_id, kind, name, slug, color, emoji, \"order\", is_closed, value, created_at";

fn row_to_item(row: &Row) -> TaxonomyItem {
    let kind: String = row.get("kind");
    TaxonomyItem {
        id: row.get("id"),
        project_id: row.get("project_id"),
        kind: TaxonomyKind::parse(&kind).unwrap_or(TaxonomyKind::Priority),
        name: row.get("name"),
        slug: row.get("slug"),
        color: row.get("color"),
        emoji: row.get("emoji"),
        order: row.get("order"),
        is_closed: row.get("is_closed"),
        value: row.get("value"),
        created_at: row.get("created_at"),
    }
}

pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    kind: TaxonomyKind,
) -> Result<Vec<TaxonomyItem>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {COLS} FROM taxonomy_items \
                 WHERE project_id = $1 AND kind = $2 ORDER BY \"order\""
            ),
            &[&project_id, &kind.as_str()],
        )
        .await?;
    Ok(rows.iter().map(row_to_item).collect())
}

pub async fn find(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    kind: TaxonomyKind,
    id: Uuid,
) -> Result<Option<TaxonomyItem>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {COLS} FROM taxonomy_items WHERE id = $1 AND project_id = $2 AND kind = $3"
            ),
            &[&id, &project_id, &kind.as_str()],
        )
        .await?;
    Ok(row.as_ref().map(row_to_item))
}

/// Highest current rank for a (project, kind), or None if empty.
async fn max_order(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    kind: TaxonomyKind,
) -> Result<Option<f64>, DbError> {
    let row = client
        .query_one(
            "SELECT max(\"order\") AS m FROM taxonomy_items WHERE project_id = $1 AND kind = $2",
            &[&project_id, &kind.as_str()],
        )
        .await?;
    Ok(row.get("m"))
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    kind: TaxonomyKind,
    name: &str,
    slug: &str,
    color: &str,
    emoji: &str,
    is_closed: Option<bool>,
    value: Option<f64>,
) -> Result<TaxonomyItem, DbError> {
    let order = rank_between(max_order(client, project_id, kind).await?, None).unwrap_or(1.0);
    let row = client
        .query_one(
            &format!(
                "INSERT INTO taxonomy_items \
                   (project_id, kind, name, slug, color, emoji, \"order\", is_closed, value) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING {COLS}"
            ),
            &[
                &project_id,
                &kind.as_str(),
                &name,
                &slug,
                &color,
                &emoji,
                &order,
                &is_closed,
                &value,
            ],
        )
        .await?;
    Ok(row_to_item(&row))
}

#[allow(clippy::too_many_arguments)]
pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    kind: TaxonomyKind,
    id: Uuid,
    name: Option<&str>,
    color: Option<&str>,
    emoji: Option<&str>,
    is_closed: Option<bool>,
    value: Option<f64>,
) -> Result<Option<TaxonomyItem>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE taxonomy_items SET \
                   name = COALESCE($4, name), \
                   color = COALESCE($5, color), \
                   emoji = COALESCE($6, emoji), \
                   is_closed = COALESCE($7, is_closed), \
                   value = COALESCE($8, value) \
                 WHERE id = $1 AND project_id = $2 AND kind = $3 \
                 RETURNING {COLS}"
            ),
            &[
                &id,
                &project_id,
                &kind.as_str(),
                &name,
                &color,
                &emoji,
                &is_closed,
                &value,
            ],
        )
        .await?;
    Ok(row.as_ref().map(row_to_item))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    kind: TaxonomyKind,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM taxonomy_items WHERE id = $1 AND project_id = $2 AND kind = $3",
            &[&id, &project_id, &kind.as_str()],
        )
        .await?;
    Ok(n > 0)
}

/// Move `id` to sit between the items currently at `before_id`/`after_id`
/// (either may be None for ends). Uses midpoint insertion, renormalizing the
/// whole (project, kind) set when no midpoint fits.
pub async fn move_item(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
    kind: TaxonomyKind,
    id: Uuid,
    before_id: Option<Uuid>,
    after_id: Option<Uuid>,
) -> Result<bool, DbError> {
    let order_of = |items: &[TaxonomyItem], target: Option<Uuid>| -> Option<f64> {
        target.and_then(|t| items.iter().find(|i| i.id == t).map(|i| i.order))
    };

    let items = list(client, project_id, kind).await?;
    if !items.iter().any(|i| i.id == id) {
        return Ok(false);
    }
    let before = order_of(&items, before_id);
    let after = order_of(&items, after_id);

    if let Some(rank) = rank_between(before, after) {
        let n = client
            .execute(
                "UPDATE taxonomy_items SET \"order\" = $4 \
                 WHERE id = $1 AND project_id = $2 AND kind = $3",
                &[&id, &project_id, &kind.as_str(), &rank],
            )
            .await?;
        return Ok(n > 0);
    }

    // No midpoint fits: renormalize the whole set, placing `id` at the target
    // slot, then assign even ranks.
    renormalize_with_move(client, project_id, kind, &items, id, before_id, after_id).await?;
    Ok(true)
}

async fn renormalize_with_move(
    client: &mut deadpool_postgres::Client,
    project_id: Uuid,
    kind: TaxonomyKind,
    items: &[TaxonomyItem],
    id: Uuid,
    before_id: Option<Uuid>,
    after_id: Option<Uuid>,
) -> Result<(), DbError> {
    // Build the desired order: current order minus `id`, with `id` inserted
    // after `before_id` (or before `after_id`, or at the end).
    let mut ordered: Vec<Uuid> = items.iter().map(|i| i.id).filter(|x| *x != id).collect();
    let pos = if let Some(b) = before_id {
        ordered
            .iter()
            .position(|x| *x == b)
            .map_or(ordered.len(), |p| p.saturating_add(1))
    } else if let Some(a) = after_id {
        ordered.iter().position(|x| *x == a).unwrap_or(0)
    } else {
        ordered.len()
    };
    ordered.insert(pos.min(ordered.len()), id);

    let ranks = normalized_ranks(ordered.len());
    let tx = client.transaction().await?;
    for (oid, rank) in ordered.iter().zip(ranks.iter()) {
        tx.execute(
            "UPDATE taxonomy_items SET \"order\" = $4 \
             WHERE id = $1 AND project_id = $2 AND kind = $3",
            &[oid, &project_id, &kind.as_str(), rank],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
