-- Phase 6: Milestones / Sprints. User stories gain a milestone link and an
-- optional points reference (a 'point' taxonomy item) used for sprint stats.

CREATE TABLE milestones (
    id          uuid             PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid             NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        text             NOT NULL,
    slug        varchar(100)     NOT NULL,
    start_date  date,
    end_date    date,
    closed      boolean          NOT NULL DEFAULT false,
    closed_at   timestamptz,
    "order"     double precision NOT NULL DEFAULT 1.0,
    version     integer          NOT NULL DEFAULT 1,
    created_at  timestamptz      NOT NULL DEFAULT now(),
    modified_at timestamptz      NOT NULL DEFAULT now(),
    deleted_at  timestamptz,
    UNIQUE (project_id, slug)
);
CREATE INDEX milestones_project_idx ON milestones (project_id) WHERE deleted_at IS NULL;
CREATE TRIGGER milestones_set_modified_at BEFORE UPDATE ON milestones
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

ALTER TABLE user_stories
    ADD COLUMN milestone_id uuid REFERENCES milestones(id) ON DELETE SET NULL;
ALTER TABLE user_stories
    ADD COLUMN points_id uuid REFERENCES taxonomy_items(id) ON DELETE SET NULL;
CREATE INDEX user_stories_milestone_idx ON user_stories (milestone_id) WHERE deleted_at IS NULL;
