-- ===========================================================================
-- V026: search that finds issue keys, partial words and non-English text.
--
-- The V001 index held one 'english' tsvector plus a trigram index over
-- `title || ' ' || body`. That misses three things users rely on:
--   * partial words typed live in the palette ("deplo" → "deployment") — the
--     english parser stems, and nothing asked for prefix matches;
--   * German/Russian text, which the english stemmer mangles;
--   * fuzzy title matches on items with a real description — similarity()
--     against the whole body collapses toward zero.
--
-- Changes:
--   * `tsv_simple`: an unstemmed ('simple' config) vector, title weight A and
--     body weight B, queried with prefix terms. The english `tsv` stays for
--     stemmed whole-word matching.
--   * A trigram index on `title` alone, for word_similarity (`<%`) fuzzy
--     matching; the combined title||body trigram index is dropped (no longer
--     queried).
--   * An index on (entity_type, ref) for exact key lookups (PS-1262, PS-E-12).
--
-- Key lookups need no new column: `ref` is already indexed per row and the
-- prefix lives on `projects` (plus `project_prefix_history` for old ones).
-- ===========================================================================

ALTER TABLE search_index ADD COLUMN tsv_simple tsvector;

CREATE OR REPLACE FUNCTION search_index_tsv() RETURNS trigger AS $$
BEGIN
    NEW.tsv := setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A')
            || setweight(to_tsvector('english', coalesce(NEW.body, '')), 'B');
    NEW.tsv_simple := setweight(to_tsvector('simple', coalesce(NEW.title, '')), 'A')
                   || setweight(to_tsvector('simple', coalesce(NEW.body, '')), 'B');
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Backfill the new vector without touching updated_at (it breaks rank ties),
-- so the maintenance trigger is bypassed for this one statement.
ALTER TABLE search_index DISABLE TRIGGER search_index_tsv_trg;
UPDATE search_index
SET tsv_simple = setweight(to_tsvector('simple', coalesce(title, '')), 'A')
              || setweight(to_tsvector('simple', coalesce(body, '')), 'B');
ALTER TABLE search_index ENABLE TRIGGER search_index_tsv_trg;

CREATE INDEX search_tsv_simple_idx ON search_index USING GIN (tsv_simple);
CREATE INDEX search_title_trgm_idx ON search_index USING GIN (title gin_trgm_ops);
CREATE INDEX search_ref_idx ON search_index (entity_type, ref) WHERE ref IS NOT NULL;
DROP INDEX IF EXISTS search_trgm_idx;
