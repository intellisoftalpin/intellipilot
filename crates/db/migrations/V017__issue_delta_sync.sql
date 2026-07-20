-- ===========================================================================
-- Delta sync for the issue board.
--
-- Clients cache board data and catch up via
-- `GET /projects/{id}/issues/delta?since=<cursor>`, which selects by
-- `modified_at` — including soft-deleted rows, which act as deletion
-- tombstones. This index backs that query; deliberately NOT partial on
-- `deleted_at IS NULL` so the tombstone scan is covered too.
-- ===========================================================================

CREATE INDEX issues_project_modified_idx ON issues (project_id, modified_at);
