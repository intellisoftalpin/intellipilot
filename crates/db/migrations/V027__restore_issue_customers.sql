-- V027: restore customers wiped by the web client's category auto-clear.
--
-- Up to 0.7.1 the issue detail page sent `customer_ids: []` together with any
-- category change away from `customer_request`, silently unlinking every
-- customer. Customers are now valid on any issue, so those links are put back
-- from issue history.
--
-- An issue qualifies only when one history entry records BOTH the category
-- leaving `customer_request` AND the customer set going from non-empty to
-- empty (the auto-clear's exact footprint), and no later entry touches
-- `customer_ids` (so a deliberate change made since is never overridden).
-- Customers deleted since, or not in the issue's project, are skipped; links
-- that already exist are left alone. Each restored issue gets a history entry
-- (no actor) and a version bump so live clients pick the change up.
--
-- Idempotent: the history entry written here is itself a later
-- `customer_ids` change, so a second run finds nothing to do. On a fresh
-- install there is no history and the statement is a no-op.

WITH clears AS (
    SELECT h.target_id                   AS issue_id,
           h.project_id,
           h.diff -> 'customer_ids' -> 0 AS old_ids
    FROM history_entries h
    WHERE h.target_type = 'issue'
      AND h.diff ? 'category'
      AND h.diff ? 'customer_ids'
      AND h.diff -> 'category' ->> 0 = 'customer_request'
      AND (h.diff -> 'category' ->> 1) IS DISTINCT FROM 'customer_request'
      AND jsonb_typeof(h.diff -> 'customer_ids' -> 0) = 'array'
      AND jsonb_array_length(h.diff -> 'customer_ids' -> 0) > 0
      AND h.diff -> 'customer_ids' -> 1 = '[]'::jsonb
      AND NOT EXISTS (
          SELECT 1 FROM history_entries later
          WHERE later.target_type = 'issue'
            AND later.target_id = h.target_id
            AND later.diff ? 'customer_ids'
            AND (later.created_at, later.id) > (h.created_at, h.id)
      )
),
wanted AS (
    SELECT DISTINCT c.issue_id,
           c.project_id,
           CASE WHEN e.t ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                THEN e.t::uuid END AS customer_id
    FROM clears c
    CROSS JOIN LATERAL jsonb_array_elements_text(c.old_ids) AS e(t)
),
restorable AS (
    SELECT w.issue_id, w.customer_id
    FROM wanted w
    JOIN issues i     ON i.id = w.issue_id AND i.project_id = w.project_id
    JOIN customers cu ON cu.id = w.customer_id AND cu.project_id = w.project_id
    WHERE NOT EXISTS (
        SELECT 1 FROM issue_customers x
        WHERE x.issue_id = w.issue_id AND x.customer_id = w.customer_id
    )
),
inserted AS (
    INSERT INTO issue_customers (issue_id, customer_id)
    SELECT issue_id, customer_id FROM restorable
    ON CONFLICT DO NOTHING
    RETURNING issue_id, customer_id
),
touched AS (
    UPDATE issues SET version = version + 1
    WHERE id IN (SELECT issue_id FROM inserted)
    RETURNING id, project_id
)
-- Every sub-select below reads the pre-statement snapshot of issue_customers,
-- so the first element is the set before the restore and the second adds the
-- rows inserted above.
INSERT INTO history_entries (project_id, target_type, target_id, actor_id, diff)
SELECT t.project_id,
       'issue',
       t.id,
       NULL,
       jsonb_build_object('customer_ids', jsonb_build_array(
           COALESCE((SELECT jsonb_agg(x.customer_id ORDER BY x.customer_id)
                     FROM issue_customers x WHERE x.issue_id = t.id), '[]'::jsonb),
           (SELECT jsonb_agg(u.cid ORDER BY u.cid)
            FROM (SELECT x.customer_id AS cid FROM issue_customers x WHERE x.issue_id = t.id
                  UNION
                  SELECT n.customer_id FROM inserted n WHERE n.issue_id = t.id) u)
       ))
FROM touched t;
