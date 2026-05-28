-- Phase 9: Unified full-text search index, kept current by triggers.

-- pg_trgm is "trusted" since PG13, so the database owner can install it.
-- Installed into `public` so it's shared across (test) schemas on search_path.
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

CREATE TABLE search_index (
    entity_type varchar(16) NOT NULL,  -- epic|user_story|task|issue|wiki|comment
    entity_id   uuid        NOT NULL,
    project_id  uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ref         bigint,                -- per-project ref where applicable
    title       text        NOT NULL DEFAULT '',
    body        text        NOT NULL DEFAULT '',
    tsv         tsvector,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_type, entity_id)
);
CREATE INDEX search_tsv_idx ON search_index USING GIN (tsv);
CREATE INDEX search_trgm_idx ON search_index USING GIN ((title || ' ' || body) gin_trgm_ops);
CREATE INDEX search_project_idx ON search_index (project_id);

-- Maintain the weighted tsvector on every write to search_index.
CREATE FUNCTION search_index_tsv() RETURNS trigger AS $$
BEGIN
    NEW.tsv := setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A')
            || setweight(to_tsvector('english', coalesce(NEW.body, '')), 'B');
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER search_index_tsv_trg BEFORE INSERT OR UPDATE ON search_index
    FOR EACH ROW EXECUTE FUNCTION search_index_tsv();

-- Work items (epic/us/task/issue): subject/description + ref. The entity type
-- is passed as a trigger argument.
CREATE FUNCTION sync_search_workitem() RETURNS trigger AS $$
DECLARE etype text := TG_ARGV[0];
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = etype AND entity_id = OLD.id;
        RETURN OLD;
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        DELETE FROM search_index WHERE entity_type = etype AND entity_id = NEW.id;
        RETURN NEW;
    END IF;
    INSERT INTO search_index (entity_type, entity_id, project_id, ref, title, body)
    VALUES (etype, NEW.id, NEW.project_id, NEW.ref, NEW.subject, NEW.description)
    ON CONFLICT (entity_type, entity_id) DO UPDATE
        SET project_id = EXCLUDED.project_id, ref = EXCLUDED.ref,
            title = EXCLUDED.title, body = EXCLUDED.body;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER epics_search AFTER INSERT OR UPDATE OR DELETE ON epics
    FOR EACH ROW EXECUTE FUNCTION sync_search_workitem('epic');
CREATE TRIGGER user_stories_search AFTER INSERT OR UPDATE OR DELETE ON user_stories
    FOR EACH ROW EXECUTE FUNCTION sync_search_workitem('user_story');
CREATE TRIGGER tasks_search AFTER INSERT OR UPDATE OR DELETE ON tasks
    FOR EACH ROW EXECUTE FUNCTION sync_search_workitem('task');
CREATE TRIGGER issues_search AFTER INSERT OR UPDATE OR DELETE ON issues
    FOR EACH ROW EXECUTE FUNCTION sync_search_workitem('issue');

-- Wiki pages: title + body.
CREATE FUNCTION sync_search_wiki() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'wiki' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        DELETE FROM search_index WHERE entity_type = 'wiki' AND entity_id = NEW.id;
        RETURN NEW;
    END IF;
    INSERT INTO search_index (entity_type, entity_id, project_id, ref, title, body)
    VALUES ('wiki', NEW.id, NEW.project_id, NULL, NEW.title, NEW.body)
    ON CONFLICT (entity_type, entity_id) DO UPDATE
        SET project_id = EXCLUDED.project_id, title = EXCLUDED.title, body = EXCLUDED.body;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER wiki_pages_search AFTER INSERT OR UPDATE OR DELETE ON wiki_pages
    FOR EACH ROW EXECUTE FUNCTION sync_search_wiki();

-- Comments: body only.
CREATE FUNCTION sync_search_comment() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'comment' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        DELETE FROM search_index WHERE entity_type = 'comment' AND entity_id = NEW.id;
        RETURN NEW;
    END IF;
    INSERT INTO search_index (entity_type, entity_id, project_id, ref, title, body)
    VALUES ('comment', NEW.id, NEW.project_id, NULL, '', NEW.body)
    ON CONFLICT (entity_type, entity_id) DO UPDATE
        SET project_id = EXCLUDED.project_id, body = EXCLUDED.body;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER comments_search AFTER INSERT OR UPDATE OR DELETE ON comments
    FOR EACH ROW EXECUTE FUNCTION sync_search_comment();
