-- ===========================================================================
-- External documentation sources.
--
--   1. `doc_sources` — up to 10 per project, surfaced under the project's
--      Wiki section, in two kinds:
--        * `git` — a repository read out of a cached bare clone; only the
--          subtree at `doc_path` is ever exposed ("the jail").
--        * `web` — a plain URL embedded in a frame. Nothing is fetched,
--          cloned or stored server-side, and it is read-only by construction.
--   2. `doc_user_keys` — one *writable* SSH key per (project, user), so an
--      edit is committed and pushed as the person who made it. Reads use the
--      project's read-only deploy key from `ssh_keys`; writes never do.
--   3. The four new `doc_source.*` permissions, backfilled onto the roles
--      that already hold the equivalent `wiki.*` ones.
--
-- Purely additive: two new tables plus a permission backfill. No existing
-- table is altered, so existing installs are unaffected. The internal wiki
-- keeps working exactly as before — `projects.wiki_enabled` already exists
-- (V001) and only starts being *enforced* in this release.
-- ===========================================================================

-- --- 1. Documentation sources ---------------------------------------------

CREATE TABLE doc_sources (
    id               uuid             PRIMARY KEY DEFAULT uuidv7(),
    project_id       uuid             NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name             varchar(128)     NOT NULL,
    -- `git` (a cloned repository) or `web` (an embedded URL). See the
    -- doc_sources_kind_fields constraint below for what each kind requires.
    kind             varchar(16)      NOT NULL DEFAULT 'git',
    -- Git kinds only; NULL for a web link, which has no repository.
    ssh_url          text,
    -- For a git source: the web base for "open on source" and for links that
    -- escape the jail — required, because it is the only way to redirect a
    -- reader to content we deliberately do not serve. For a web source: the
    -- page itself.
    web_url          text             NOT NULL,
    branch           varchar(255),
    -- The subtree exposed in IntelliPilot, relative to the repository root.
    -- '' means the whole repository. Stored normalized: no leading or
    -- trailing slash, no empty segments, no '.'/'..', no backslashes. The API
    -- normalizes before writing; this CHECK is defense in depth so no code
    -- path — or manual SQL — can plant a path that escapes the jail.
    doc_path         text             NOT NULL DEFAULT '',
    -- Read key. Detached (not cascaded) when the key is deleted, exactly like
    -- `repositories`: the source survives but needs a key before it syncs.
    ssh_key_id       uuid             REFERENCES ssh_keys(id) ON DELETE SET NULL,
    -- Explicitly marks the source as never-editable, independently of who
    -- holds a write key. A source is editable only when this is false AND the
    -- actor holds doc_source.modify AND has a personal write key.
    read_only        boolean          NOT NULL DEFAULT false,
    -- Temporarily withdraw a source from navigation without discarding its
    -- configuration. Hidden sources stay listed in project settings for
    -- whoever can manage them, so the switch is reversible in one click.
    hidden           boolean          NOT NULL DEFAULT false,
    -- Presentation: sidebar order, tile color (hex from the shared palette)
    -- and an optional emoji glyph, matching the taxonomy/release conventions.
    "order"          double precision NOT NULL DEFAULT 1.0,
    color            varchar(16)      NOT NULL DEFAULT '',
    emoji            varchar(16)      NOT NULL DEFAULT '',
    -- Cache state of the bare clone. `cache_bytes` is what the last clone or
    -- fetch actually transferred, used to report against the operator's cap.
    cache_status     varchar(16)      NOT NULL DEFAULT 'pending',
    cache_error      text,
    head_commit      varchar(64),
    cache_bytes      bigint           NOT NULL DEFAULT 0,
    last_synced_at   timestamptz,
    last_attempt_at  timestamptz,
    host_fingerprint text,
    version          integer          NOT NULL DEFAULT 1,
    created_by       uuid             REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz      NOT NULL DEFAULT now(),
    modified_at      timestamptz      NOT NULL DEFAULT now(),
    UNIQUE (project_id, name),
    CONSTRAINT doc_sources_path_normalized CHECK (
        doc_path = ''
        OR (
            doc_path !~ '(^/)|(/$)|(//)'
            AND doc_path !~ '(^|/)[.][.]?(/|$)'
            AND doc_path !~ '\\'
        )
    ),
    CONSTRAINT doc_sources_cache_status CHECK (
        cache_status IN ('pending', 'syncing', 'ready', 'error')
    ),
    -- The two kinds need disjoint field sets, and a web link is read-only
    -- **by construction** rather than by convention: there is no repository
    -- to push to, so the flag can never be cleared for one.
    CONSTRAINT doc_sources_kind_fields CHECK (
        (kind = 'git'
            AND ssh_url IS NOT NULL
            AND branch IS NOT NULL)
        OR (kind = 'web'
            AND ssh_url IS NULL
            AND branch IS NULL
            AND ssh_key_id IS NULL
            AND doc_path = ''
            AND read_only)
    )
);
CREATE INDEX doc_sources_project_idx ON doc_sources (project_id, "order");
CREATE INDEX doc_sources_ssh_key_idx ON doc_sources (ssh_key_id);
-- The background refresher walks every source oldest-attempt-first.
CREATE INDEX doc_sources_sync_idx ON doc_sources (last_attempt_at NULLS FIRST);

CREATE TRIGGER doc_sources_set_modified_at
    BEFORE UPDATE ON doc_sources
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

COMMENT ON COLUMN doc_sources.hidden IS
    'Withdrawn from navigation but fully configured. Nothing is deleted; '
    'clearing the flag restores the source exactly as it was.';

COMMENT ON COLUMN doc_sources.doc_path IS
    'Normalized subtree exposed to readers. Nothing outside it is ever served; '
    'links resolving above it are redirected to web_url.';

-- --- 2. Per-user write keys -----------------------------------------------

CREATE TABLE doc_user_keys (
    id               uuid         PRIMARY KEY DEFAULT uuidv7(),
    project_id       uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id          uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_type         varchar(32)  NOT NULL DEFAULT 'ed25519',
    public_key       text         NOT NULL,
    -- Encrypted at rest (ChaCha20-Poly1305, key from the server pepper) with
    -- the same helper the ssh_keys vault uses. NEVER selected into an API
    -- response — not even for its owner.
    private_key_enc  bytea        NOT NULL,
    fingerprint      text         NOT NULL,
    -- 'generated' = we made the keypair and showed the user its public half;
    -- 'imported'  = the user supplied an existing private key.
    origin           varchar(16)  NOT NULL DEFAULT 'generated',
    created_at       timestamptz  NOT NULL DEFAULT now(),
    UNIQUE (project_id, user_id),
    CONSTRAINT doc_user_keys_origin CHECK (origin IN ('generated', 'imported'))
);
CREATE INDEX doc_user_keys_project_idx ON doc_user_keys (project_id);

COMMENT ON TABLE doc_user_keys IS
    'Per-(project, user) writable SSH key used to commit and push doc edits, '
    'so git history attributes the change to the person who made it.';

-- --- 3. Permission backfill ------------------------------------------------
-- Same shape as V007/V019: append-only, idempotent, and keyed on behaviour
-- rather than on a role slug (projects may have renamed the seeded roles).
--
-- Each new permission maps onto the wiki permission that already expresses
-- the same level of trust, so a role's effective reach does not change:
--
--   doc_source.view   <- wiki.view    (reading docs ≈ reading the wiki)
--   doc_source.modify <- wiki.modify  (editing a doc ≈ editing a page; still
--                                      needs a personal write key at runtime)
--   doc_source.create <- wiki.delete  (registering/removing a whole source is
--   doc_source.delete <- wiki.delete   admin-level, the marker used in V019)

UPDATE roles
SET permissions = permissions || sub.missing
FROM (
    SELECT r.id,
           COALESCE(
               jsonb_agg(p.perm) FILTER (WHERE NOT (r.permissions ? p.perm)),
               '[]'::jsonb
           ) AS missing
    FROM roles r
    CROSS JOIN (VALUES
        ('doc_source.view',   'wiki.view'),
        ('doc_source.modify', 'wiki.modify'),
        ('doc_source.create', 'wiki.delete'),
        ('doc_source.delete', 'wiki.delete')
    ) AS p(perm, implied_by)
    WHERE r.is_admin = true
       OR r.permissions ? p.implied_by
    GROUP BY r.id
) AS sub
WHERE roles.id = sub.id
  AND sub.missing <> '[]'::jsonb;
