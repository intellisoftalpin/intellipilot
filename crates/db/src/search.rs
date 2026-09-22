//! Search over the trigger-maintained `search_index`: exact work-item keys
//! (`PS-1262`, `PS-E-12`, `1262`) plus full-text and fuzzy matching, limited
//! to what the actor may open.

use intellipilot_core::search::{KeyQuery, SearchHit};
use uuid::Uuid;

use crate::DbError;

/// Who is searching and where. Shared by the key and text lookups.
#[derive(Debug, Clone, Copy)]
pub struct SearchScope<'a> {
    pub actor_id: Uuid,
    /// Platform superadmins see every project, member or not.
    pub is_superadmin: bool,
    /// Hard filter to one project.
    pub project_id: Option<Uuid>,
    /// Rank this project's hits above equal hits elsewhere (the project the
    /// user is in), without hiding the rest.
    pub boost_project_id: Option<Uuid>,
    /// Entity-type allowlist.
    pub types: Option<&'a [String]>,
}

/// Rows the actor may read: superadmin, or a member whose role holds the view
/// permission for that kind of row. Non-members of internal/public projects
/// are excluded — they can see the project but not open its items, so a hit
/// would be a title they cannot follow. Binds `$1` = actor, `$2` = superadmin.
const ACCESS: &str = "\
    JOIN projects p ON p.id = s.project_id AND p.deleted_at IS NULL \
    WHERE ($2::bool OR EXISTS ( \
        SELECT 1 FROM memberships m JOIN roles r ON r.id = m.role_id \
        WHERE m.project_id = s.project_id AND m.user_id = $1 \
          AND (r.is_admin OR r.permissions ? CASE s.entity_type \
                WHEN 'epic' THEN 'epic.view' \
                WHEN 'wiki' THEN 'wiki.view' \
                WHEN 'meeting' THEN 'meeting.view' \
                ELSE 'issue.view' END))) \
      AND ($3::uuid IS NULL OR s.project_id = $3) \
      AND ($4::text[] IS NULL OR s.entity_type = ANY($4))";

/// The rendered key (`PS-1262`, `PS-E-12`) for work items.
const KEY_COL: &str = "\
    CASE WHEN p.issue_prefix IS NULL OR s.ref IS NULL THEN NULL \
         WHEN s.entity_type = 'epic' THEN p.issue_prefix || '-E-' || s.ref \
         WHEN s.entity_type = 'issue' THEN p.issue_prefix || '-' || s.ref \
    END AS key";

/// Rank added to hits in the boosted project. Text ranks are small fractions,
/// so this lifts the current project over most comparable matches elsewhere.
const BOOST: f32 = 0.5;

/// Work items whose key matches `key`, ranked above any text hit: the boosted
/// project first, then issues before epics.
///
/// A typed prefix resolves like the short-link lookup: the live prefix wins,
/// otherwise the project that last gave that prefix up.
pub async fn search_keys(
    client: &deadpool_postgres::Client,
    scope: &SearchScope<'_>,
    key: &KeyQuery,
    limit: i64,
) -> Result<Vec<SearchHit>, DbError> {
    let kinds: Vec<&str> = key.kind.entity_types().to_vec();
    let sql = format!(
        "SELECT s.entity_type, s.entity_id, s.project_id, s.ref, s.title, \
                left(s.body, 400) AS snippet, {KEY_COL}, TRUE AS key_match, \
                (1000 \
                 + CASE WHEN s.project_id = $5 THEN 10 ELSE 0 END \
                 + CASE WHEN s.entity_type = 'issue' THEN 1 ELSE 0 END)::float4 AS rank \
         FROM search_index s {ACCESS} \
           AND s.ref = $6 AND s.entity_type = ANY($7) \
           AND ($8::text IS NULL OR s.project_id = COALESCE( \
                 (SELECT id FROM projects WHERE issue_prefix = $8 AND deleted_at IS NULL), \
                 (SELECT project_id FROM project_prefix_history WHERE prefix = $8))) \
         ORDER BY rank DESC, p.name, s.entity_type \
         LIMIT $9"
    );
    let rows = client
        .query(
            &sql,
            &[
                &scope.actor_id,
                &scope.is_superadmin,
                &scope.project_id,
                &scope.types,
                &scope.boost_project_id,
                &key.number,
                &kinds,
                &key.prefix,
                &limit,
            ],
        )
        .await?;
    Ok(rows.iter().map(row_to_hit).collect())
}

/// Full-text and fuzzy matches for `q`.
///
/// - whole words, stemmed (`english` vector, `websearch_to_tsquery`);
/// - `prefix_query` (see `core::search::prefix_tsquery`) against the unstemmed
///   `simple` vector, so partial and non-English words match;
/// - when `fuzzy`, titles that contain something close to `q`
///   (`word_similarity` ≥ [`FUZZY_THRESHOLD`], typo-tolerant).
pub async fn search_text(
    client: &mut deadpool_postgres::Client,
    scope: &SearchScope<'_>,
    q: &str,
    prefix_query: Option<&str>,
    fuzzy: bool,
    limit: i64,
) -> Result<Vec<SearchHit>, DbError> {
    let sql = format!(
        "SELECT s.entity_type, s.entity_id, s.project_id, s.ref, s.title, \
                CASE WHEN s.tsv @@ qq.en OR qq.simple IS NULL \
                     THEN ts_headline('english', s.body, qq.en, {HEADLINE}) \
                     ELSE ts_headline('simple', s.body, qq.simple, {HEADLINE}) \
                END AS snippet, \
                {KEY_COL}, FALSE AS key_match, \
                (GREATEST( \
                    ts_rank(s.tsv, qq.en), \
                    ts_rank(s.tsv_simple, qq.simple), \
                    CASE WHEN $7 THEN word_similarity($5, s.title) * 0.5 ELSE 0 END \
                 ) + CASE WHEN s.project_id = $6 THEN {BOOST} ELSE 0 END)::float4 AS rank \
         FROM search_index s \
         CROSS JOIN LATERAL (SELECT websearch_to_tsquery('english', $5) AS en, \
                                    to_tsquery('simple', $8) AS simple) qq \
         {ACCESS} \
           AND (s.tsv @@ qq.en \
                OR s.tsv_simple @@ qq.simple \
                OR ($7 AND $5 <% s.title)) \
         ORDER BY rank DESC, s.updated_at DESC \
         LIMIT $9"
    );
    // `<%` reads its cut-off from a setting; scope it to this transaction so
    // the index-backed operator applies our threshold, not the 0.6 default.
    let tx = client.transaction().await?;
    tx.batch_execute(&format!(
        "SET LOCAL pg_trgm.word_similarity_threshold = {FUZZY_THRESHOLD}"
    ))
    .await?;
    let rows = tx
        .query(
            &sql,
            &[
                &scope.actor_id,
                &scope.is_superadmin,
                &scope.project_id,
                &scope.types,
                &q,
                &scope.boost_project_id,
                &fuzzy,
                &prefix_query,
                &limit,
            ],
        )
        .await?;
    tx.commit().await?;
    Ok(rows.iter().map(row_to_hit).collect())
}

/// Minimum `word_similarity` for a fuzzy title hit. The 0.6 default misses a
/// single dropped letter in an 8-letter word (it scores 0.55).
const FUZZY_THRESHOLD: f32 = 0.5;

const HEADLINE: &str = "'StartSel=<b>,StopSel=</b>,MaxFragments=1,MaxWords=35,MinWords=8'";

fn row_to_hit(r: &tokio_postgres::Row) -> SearchHit {
    SearchHit {
        entity_type: r.get("entity_type"),
        entity_id: r.get("entity_id"),
        project_id: r.get("project_id"),
        reference: r.get("ref"),
        key: r.get("key"),
        key_match: r.get("key_match"),
        title: r.get("title"),
        snippet: r.get("snippet"),
        rank: r.get("rank"),
    }
}
