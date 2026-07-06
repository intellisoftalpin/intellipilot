-- ===========================================================================
-- QA assignee + Reviewer on issues.
--
-- Two more single-person accountability fields alongside owner_id (reporter)
-- and assigned_to (assignee), so an issue records who tests it (qa_assignee_id)
-- and who reviews the implementation (reviewer_id). Both are informational and
-- their changes are captured by the existing history_entries wiring.
--
-- Modeled exactly on assigned_to: nullable, single user, FK cleared if the user
-- is deleted. Not indexed (like assigned_to) — they are not filtered on.
-- ===========================================================================

ALTER TABLE issues
    ADD COLUMN qa_assignee_id uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN reviewer_id    uuid REFERENCES users(id) ON DELETE SET NULL;
