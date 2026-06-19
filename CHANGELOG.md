# Changelog

All notable changes to the IntelliPilot backend are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to Semantic Versioning.

## [0.4.2] - 2026-06-19

### Security
- Upgraded `git2` 0.19 → 0.21 (libgit2-sys 0.18) to clear RUSTSEC-2026-0183 and
  RUSTSEC-2026-0184 (unsound null-pointer handling in `Remote::list()` /
  `BlameHunk` signatures). No API impact for our usage.

### Fixed
- Container failed to start with `libz.so.1: cannot open shared object file` on
  the distroless runtime: libgit2 dynamically linked the system zlib, which the
  minimal image doesn't ship. Now statically link zlib-ng via git2's
  `zlib-ng-compat` feature (arch-independent; needs `cmake` at build time, which
  the Docker builder and CI already provide).

## [0.4.0] - 2026-06-18

### Added
- **Issue fields overhaul.**
  - **Size** estimation (T-shirt XS–XXL) replaces story points — the `point`
    taxonomy kind was renamed to `size` and reseeded XS–XXL, each carrying a
    numeric ordinal (1–6) the UI uses to scale a size badge.
  - **Category** (fixed enum): `customer_request`, `compliance`, `security`,
    `roadmap`, `technical_debt`, `operational`, `research_discovery`, `other`.
  - **Customer** link (`issues.customer_id`) for customer-requested work, backed
    by a new per-project **customers** registry
    (`/api/v1/projects/{id}/customers`, CRUD: name, company, email, phone, notes).
  - **Start / due dates** with overdue indication.
  - **Resolution** (fixed enum: `fixed`, `wont_do`, `duplicate`,
    `cannot_reproduce`) plus a system-managed `resolved_at` that is set when an
    issue enters a closed status and cleared on reopen.
  - **Issue relationships** (`/api/v1/projects/{id}/issues/{id}/links`):
    `blocks` / `relates` / `duplicates`, with inverse directions rendered.
  - **Watchers** (`/api/v1/projects/{id}/issues/{id}/watchers`).
- **Releases** — a two-level model: a named **release** (e.g. "PSBP") with
  separate **versions** (1.0, 1.1, …). Versions carry a status
  (`planned`/`in_progress`/`released`), target/actual dates, notes, and an
  optional repository + git tag. Releases link to components
  (`/api/v1/projects/{id}/components/{cid}/releases`); an issue's fix-version
  points at a specific version (`release_version_id`) chosen from its
  components' linked releases, or a free-text `release_text` fallback.
  Endpoints under `/api/v1/projects/{id}/releases[/{rid}/versions]` and
  `/release-versions/for-components`.
- **Comment attachments**: the attachment endpoints now accept a `comment`
  target (`/api/v1/projects/{id}/comments/{comment_id}/attachments`); a
  comment's attachments are soft-deleted when the comment is deleted.
- **Git repositories, SSH credential vault, and component linking** — the
  foundation for the upcoming "clone & analyze" feature.
  - **Per-project SSH keys** (`/api/v1/projects/{id}/ssh-keys`): server-generated
    Ed25519 keypairs. The private key is encrypted at rest (ChaCha20-Poly1305,
    keyed by the server pepper) and **never returned**; the public key + SHA256
    fingerprint are exposed so it can be registered as a deploy key. Keys carry a
    name and a read-only/read-write flag, and report how many repositories use
    them. Generation requires a configured server pepper.
  - **Repositories** (`/api/v1/projects/{id}/repositories`): an SSH URL (validated
    as `git@host:path` / `ssh://…`), an optional linked key (existing or created
    inline), an optional default branch, and the captured host-key fingerprint.
    One key can serve many repositories. Deleting a key **detaches** it from its
    repositories (`ON DELETE SET NULL`) rather than deleting them.
  - **Basic git integration** (new `intellipilot-git` crate over libgit2): lists a
    remote's branches over SSH using the in-memory decrypted key (never written to
    disk), captures the host fingerprint (TOFU), bounds concurrency and enforces a
    timeout. Surfaced via `POST …/repositories/branches` (preview an unsaved repo)
    and `GET …/repositories/{id}/branches` (live). Adding/re-keying a repository
    checks reachability best-effort.
  - **Component ↔ repository links**
    (`/api/v1/projects/{id}/components/{cid}/repositories`): a component may link
    many repositories, each pinned to a specific branch (validated against the
    live remote when reachable).
  - SSH key create/delete are recorded in the audit log; per-project caps bound
    growth.

### Changed
- **Priority and severity merged** into a single `priority` taxonomy with the
  scale Low / Medium / High / Critical / Blocker; the `severity` taxonomy kind
  and `issues.severity_id` were removed.
- Story **points → size**: `issues.points_id` renamed to `size_id`; milestone
  "points" totals now sum the size ordinal.
- Components no longer carry the free-text `git_repository` field — repositories
  are now first-class, structured, and linked per branch. (Pre-release schema
  changes folded into the single `V001` migration.)

## [0.3.3] - 2026-06-17

### Fixed
- A failed database migration now logs a single concise line and exits, instead
  of letting the error propagate to `main` where the runtime Debug-prints it —
  refinery's Debug output embeds the full migration SQL, which dumped the entire
  schema into the logs on every restart. The message also hints that a changed
  single-V001 migration requires resetting or reconciling the database.

## [0.3.2] - 2026-06-16

### Added
- LDAP **service-account search-then-bind** mode (`bind_mode = "search"`)
  alongside the existing direct bind. A service account (`service_bind_dn` /
  `service_bind_password`, write-only) searches `user_search_base` (falls back
  to `base_dn`) with `user_search_filter` to find the user's DN, then binds as
  that DN to verify the password. Group membership / superadmin is resolved by a
  reverse `(member=%s)` search under `group_search_base` (configurable via
  `group_search_filter`), merged with the user entry's `memberOf` as a fallback.
  This supports OpenLDAP directories where the login identifier isn't the
  entry's RDN. New `ldap_settings` columns; direct-bind behaviour is unchanged
  when `bind_mode = "direct"` (the default). The LDAP "test" endpoint reuses the
  stored service password when the form leaves it blank.

## [0.3.1] - 2026-06-16

### Added
- White-label branding (superadmin): `PATCH /api/v1/admin/branding` sets a
  custom application name and an optional login-screen message; `PUT` and
  `DELETE /api/v1/admin/branding/icon` upload and reset a custom app icon
  (image validated by magic bytes, ≤1 MB, stored as `bytea`). The public
  `GET /api/v1/branding/icon` serves the icon (404 when none is set), and the
  branding fields (`app_name`, `app_message`, `has_custom_icon`,
  `app_icon_updated_at`) are now included in `GET /api/v1/auth/config` and
  `GET /api/v1/admin/settings`. Branding columns folded into the
  `platform_settings` row; empty values revert to the bundled defaults.

## [0.3.0] - 2026-06-16

### Added
- Outbound notification settings (superadmin): an email channel with two
  mutually-exclusive providers — SMTP (via `lettre`) and Mailgun — plus Matrix
  and Telegram chat channels. Each channel has a "send test" endpoint
  (`/api/v1/admin/notification-settings/test-{mail,matrix,telegram}`). Per-event
  delivery toggles (login, issue created, issue resolved, daily report) are
  stored independently for email and the messenger channels. New
  `notification_settings` table; secrets are write-only (never returned by the
  API; blank-on-update keeps the stored value).
- `password_reset_enabled` in `GET /api/v1/auth/config` now reflects whether an
  email channel is actually configured.

### Fixed
- Admin API timestamps (`PlatformSettingsResponse`, `LdapSettingsResponse`,
  invitation and password-reset responses) are now serialized as RFC3339,
  matching the rest of the API. Previously the `time` crate's default
  (non-ISO-8601) format made clients fail to parse the response.

### Added
- `POST /api/v1/me/password` — self-service password change for the logged-in
  user. Local accounts only (LDAP accounts are rejected with 409); requires the
  current password, enforces strength on the new one, revokes all sessions, and
  clears any pending `must_change_password` flag.
- `GET /api/v1/auth/config` — public endpoint exposing `open_registration` and
  `password_reset_enabled` so unauthenticated UIs can adapt (hide signup when
  registration is closed, hide email reset when no mailer is configured).

### Changed
- Login accepts either an email address or a username as the identifier
  (the `email` field of `LoginRequest` is now resolved against both).

### Security
- Bumped `postgres-protocol` 0.6.11 → 0.6.12 and `tokio-postgres`
  0.7.17 → 0.7.18 to address RUSTSEC-2026-0178, -0179, and -0180
  (denial-of-service advisories in the Postgres driver chain).
