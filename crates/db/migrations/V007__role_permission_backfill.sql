-- Bring stored role permission vectors in sync with the current catalog.
--
-- Background: roles.permissions is a JSONB snapshot taken at role-creation
-- time. Adding a new Permission variant to the enum does NOT backfill existing
-- rows, so older projects show recently-added permissions (time.*, and the
-- newly-split config-entity permissions) as unchecked even though the holder is
-- effectively granted them (admins via is_admin; project.modify holders via the
-- former coarse gate). This migration reconciles the snapshots.

-- (1) Admin roles implicitly hold every permission (is_admin short-circuits the
--     check). Make the stored vector reflect the full catalog so the settings
--     UI shows them all checked. Overwrite is intentional and idempotent.
UPDATE roles
SET permissions = '[
  "project.view","project.modify","project.delete","project.admin",
  "member.view","member.add","member.remove","member.modify_role",
  "role.view","role.create","role.modify","role.delete",
  "epic.view","epic.create","epic.modify","epic.delete",
  "issue.view","issue.create","issue.modify","issue.delete",
  "milestone.view","milestone.create","milestone.modify","milestone.delete",
  "wiki.view","wiki.create","wiki.modify","wiki.delete",
  "comment.create","comment.moderate","attachment.create","attachment.delete",
  "time.log","time.view_all","time.manage",
  "taxonomy.create","taxonomy.modify","taxonomy.delete",
  "label.create","label.modify","label.delete",
  "component.create","component.modify","component.delete",
  "repository.create","repository.modify","repository.delete",
  "customer.create","customer.modify","customer.delete",
  "release.create","release.modify","release.delete"
]'::jsonb
WHERE is_admin = true;

-- (2) Non-admin roles that could edit the project under the old coarse
--     project.modify gate keep their ability over the now-split config
--     entities. Append only the permissions they don't already have so the
--     migration is safe to reason about and produces no duplicates.
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
        ('taxonomy.create'),('taxonomy.modify'),('taxonomy.delete'),
        ('label.create'),('label.modify'),('label.delete'),
        ('component.create'),('component.modify'),('component.delete'),
        ('repository.create'),('repository.modify'),('repository.delete'),
        ('customer.create'),('customer.modify'),('customer.delete'),
        ('release.create'),('release.modify'),('release.delete')
    ) AS p(perm)
    WHERE r.is_admin = false
      AND r.permissions ? 'project.modify'
    GROUP BY r.id
) AS sub
WHERE roles.id = sub.id
  AND sub.missing <> '[]'::jsonb;
