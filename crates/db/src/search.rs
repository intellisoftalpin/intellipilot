//! Full-text + fuzzy search over the trigger-maintained `search_index`,
//! scoped to the actor's project memberships.

use intellipilot_core::search::SearchHit;
use uuid::Uuid;

use crate::DbError;

/// Run a search for `actor_id`.
///
/// - `q`: user query (parsed with `websearch_to_tsquery`, which never errors).
/// - `project_id`: optional filter to a single project.
/// - `types`: optional entity-type allowlist.
/// - `fuzzy`: enable trigram matching (used for short queries).
///
/// Results are restricted to projects the actor is a member of, so content
/// from other projects is never returned.
pub async fn search(
    client: &deadpool_postgres::Client,
    actor_id: Uuid,
    q: &str,
    project_id: Option<Uuid>,
    types: Option<&[String]>,
    fuzzy: bool,
    limit: i64,
) -> Result<Vec<SearchHit>, DbError> {
    let rows = client
        .query(
            "SELECT s.entity_type, s.entity_id, s.project_id, s.ref, s.title, \
                    ts_headline('english', s.body, query, \
                        'StartSel=<b>,StopSel=</b>,MaxFragments=1,MaxWords=35,MinWords=8') AS snippet, \
                    GREATEST( \
                        ts_rank(s.tsv, query), \
                        CASE WHEN $6 THEN similarity(s.title || ' ' || s.body, $2) ELSE 0 END \
                    )::float4 AS rank \
             FROM search_index s \
             JOIN memberships mem ON mem.project_id = s.project_id AND mem.user_id = $1 \
             CROSS JOIN websearch_to_tsquery('english', $2) query \
             WHERE (s.tsv @@ query \
                    OR ($6 AND similarity(s.title || ' ' || s.body, $2) > 0.15)) \
               AND ($3::uuid IS NULL OR s.project_id = $3) \
               AND ($4::text[] IS NULL OR s.entity_type = ANY($4)) \
             ORDER BY rank DESC, s.updated_at DESC \
             LIMIT $5",
            &[&actor_id, &q, &project_id, &types, &limit, &fuzzy],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| SearchHit {
            entity_type: r.get("entity_type"),
            entity_id: r.get("entity_id"),
            project_id: r.get("project_id"),
            reference: r.get("ref"),
            title: r.get("title"),
            snippet: r.get("snippet"),
            rank: r.get("rank"),
        })
        .collect())
}
