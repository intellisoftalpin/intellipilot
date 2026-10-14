-- ===========================================================================
-- Per-user favorite projects.
--
-- A user stars a handful of projects so the clients can list them first: on
-- the projects screen and in the top-bar projects menu. Stored server-side so
-- the set follows the user across devices.
--
-- The cap (4 per user) is enforced in the API, which replaces the whole set at
-- once; `position` keeps the order the user starred them in.
--
-- Purely additive: a new table, nothing existing changes.
-- ===========================================================================

CREATE TABLE user_project_favorites (
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    position   smallint    NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, project_id)
);

COMMENT ON TABLE user_project_favorites IS
    'Projects a user starred, listed first by the clients. At most 4 per user '
    '(enforced by the API).';
