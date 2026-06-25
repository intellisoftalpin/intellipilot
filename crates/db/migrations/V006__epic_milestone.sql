-- A milestone is composed of epics: each epic may belong to one milestone.
-- Nullable FK; clearing the milestone detaches its epics. Existing installs
-- keep working unchanged (all epics start with no milestone).
ALTER TABLE epics
    ADD COLUMN milestone_id uuid REFERENCES milestones(id) ON DELETE SET NULL;

CREATE INDEX epics_milestone_idx ON epics (milestone_id) WHERE deleted_at IS NULL;
