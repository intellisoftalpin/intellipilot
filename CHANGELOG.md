# Changelog

All notable changes to the IntelliPilot backend are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to Semantic Versioning.

## [0.6.18] - 2026-07-29

Account security: admin-driven 2FA recovery, real bans, session visibility and
optional local IP geolocation (migration V018). Frontend companion release is
also 0.6.18 — the two version lines are realigned. (0.6.17 was burned by a
CI failure and never released.)

### Fixed
- **2FA lockout was unrecoverable.** A user who lost every second factor could
  not be helped by anyone: the only disable path (`DELETE /me/totp`) requires
  an authenticated session, which is exactly what the lockout prevents.
  `POST /admin/users/{id}/reset-2fa` clears the TOTP secret, **all passkeys**
  and **all recovery codes**, then revokes the account's sessions. Clearing all
  three matters — `has_active_2fa` counts passkeys as a factor, so a
  TOTP-only reset would have left a passkey-only user just as locked out.
- **Deactivating an LDAP user did not stick.** `find_or_link_ldap_user` runs
  `SET ... is_active = true` on every directory login, silently undoing an
  admin's deactivation at the user's next sign-in. Bans now live in their own
  columns (`banned_at`/`banned_by`/`ban_reason`) that the directory sync never
  writes, and the login path checks them after the link/sync.
- A banned superadmin no longer counts towards the "don't remove the last
  superadmin" guard — previously the last *usable* admin could be demoted,
  deactivated or deleted while a banned one stood in for them.

### Added
- `POST /admin/users/{id}/ban` (with an optional reason) and `.../unban`.
  Banning revokes every session, and is refused for the caller's own account
  (400) or the last usable superadmin (409). Enforced across password login,
  LDAP login, refresh rotation, personal tokens and the superadmin gate.
- `GET`/`DELETE /admin/users/{id}/sessions` — inspect live sessions or sign a
  user out everywhere.
- `GET /admin/users` now returns each account's security posture: `status`
  (active/inactive/banned), `two_factor` (TOTP, passkey and recovery-code
  counts), `active_sessions`, `last_session` (device, address, location),
  `last_seen_at`, `last_login_at` and ban details. Computed with lateral joins
  in one query — no N+1. New `?status=` filter accepts
  `active`/`inactive`/`banned`/`no_2fa`.
- **Local IP geolocation**, off by default and superadmin-only. Resolution
  reads a MaxMind-format database on disk; the only outbound request the
  feature ever makes is fetching that database, so no address is ever sent to
  a third party. Source is DB-IP Lite (no account or licence key), refreshed
  monthly by a background task or on demand via
  `POST /admin/geoip/update`. `POST /admin/geoip/purge` erases collected
  locations, since IP-derived city is personal data. The licence (CC BY 4.0)
  requires the attribution returned in `GET /admin/geoip`.
- Activity tracking: `users.last_seen_at` and `last_login_at`, plus
  `last_seen_at`/`last_ip`/`country_code`/`city` per session. Existing installs
  are backfilled from the audit log by the migration.
- Audit events: `admin_user_2fa_reset`, `admin_user_banned`,
  `admin_user_unbanned`, `admin_sessions_revoked`, `admin_geoip_updated`,
  `admin_geoip_settings_updated`, `admin_geoip_purged`.

### Changed
- Access tokens are stateless with a 15-minute life, so a ban imposed mid-token
  would previously have gone unnoticed until it expired. A new in-process
  presence cache (`crate::presence`) re-checks each user's status at most once
  per 30 seconds and stamps `last_seen_at` in the same statement, bounding ban
  lag without adding a database round trip to every authenticated request.
  Banning invalidates the cache entry, so on the acting node the ban applies to
  the very next request.
- Dependencies: added `maxminddb` (ISC) and `flate2`. `maxminddb`'s `mmap`
  feature is deliberately **not** enabled — `Reader::open_mmap` is an
  `unsafe fn` and this workspace sets `unsafe_code = "forbid"`, so the database
  is read into memory instead (~4 MB country, ~62 MB city, only while the
  feature is switched on).
- Updated `ammonia` 4.1.3 → 4.1.4 for RUSTSEC-2026-0213 (XSS via SVG
  `set`/`animate` attribute values). Pre-existing, unrelated to this release.

## [0.6.11] - 2026-07-19

### Added
- **Short deep links** (migration V016):
  - Boards gain a `key` — a short lowercase slug, unique per project, used as
    the URL segment instead of the board UUID. Auto-derived from the board
    name on create (initials for multi-word names, suffixed on collision;
    existing boards backfilled), editable via `PUT /boards/{board_id}`
    (`409` on duplicate, case-insensitive).
  - `GET /api/v1/projects/by-prefix/{prefix}` resolves a project's issue
    prefix (any letter-case) to the project — private projects invisible to
    the caller stay a plain 404.
  - `GET .../boards/{segment}` accepts a board UUID **or** its key in any
    letter-case.
  - **Rename history**: changing a project prefix or board key records the
    old value, so previously shared short links keep resolving (live values
    always win over history). Superadmin maintenance via
    `GET /api/v1/admin/short-link-history` and
    `POST /api/v1/admin/short-link-history/delete` (single or bulk).
- **`involved` issue filter** — matches issues where the user is assignee,
  QA, or reviewer (never just reporter); `none` matches issues with no
  people set. Available on the issues list and the board data endpoint.
- **`release` issue filter** — matches issues whose fix version belongs to
  the given release; `none` matches issues without a fix version.
- **Work-log date editing** — `PATCH /me/time-entries/{id}` and the admin
  counterpart accept a `date`; moving an entry into a locked month is
  blocked for members (managers bypass, as with other corrections).
- **Multi-level issue hierarchy** — an issue whose parent has its own parent
  is now a valid parent; assignments that would close a cycle are rejected
  with `422`.

## [0.6.10] / [0.6.9]

Version bumps in lockstep with frontend releases.

## [0.6.8] - 2026-07-09

### Fixed
- **`GET /api/v1/projects` now works with app tokens** — previously it only
  accepted a user login token and always returned `401` for an `ipat_…`
  bearer, with no way for a token to discover which project(s) it's scoped
  to. It now returns the projects the app token is scoped to (a human caller
  still sees their memberships, or every project if superadmin).

## [0.6.7] - 2026-07-09

Version bump only (lockstep with the frontend release), no backend changes.

## [0.6.6] - 2026-07-09

Version bump only (lockstep with the frontend release), no backend changes.

## [0.6.5] - 2026-07-09

Version bump only (lockstep with the frontend release), no backend changes.

## [0.6.4] - 2026-07-09

### Added
- **Release badge color** — `Release` now has a `color` (hex) field, settable
  via `POST /releases` and `PATCH /releases/{release_id}`. All versions under
  a release share its color.
- **`GET /api/v1/projects/{project_id}/release-versions`** — flat list of
  every release version in the project, each enriched with its parent
  release's name and color, for surfaces that resolve many issues' fix
  versions at once (issues list, board).

### Fixed
- `POST /release-versions/for-components` (the issue fix-version picker
  endpoint) now actually returns each version's parent release name and
  color — previously it only returned raw `release_versions` columns, so
  `release_name` was always empty despite being part of the response shape.

## [0.4.3] - 2026-06-19

### Added
- **Activity log (superadmin)** — `GET /api/v1/admin/activity` (paginated,
  filterable by `action`) over the universal `audit_log`. New auth events are
  recorded: successful logins (`login_success`, with `via: password|ldap`),
  failed logins (`login_failure`, with a `reason` — `bad_password` /
  `unknown_user` / `account_inactive` / `invalid_credentials` — and the attempted
  `identifier`), first-ever login per user (`login_first`), and the existing
  `password_changed`. The log is universal: new event types need only a new
  `action` string, no schema change.

### Changed
- **LDAP login accepts both a bare username and a `user@domain` UPN** — the user
  search now ORs the configured filter over the local part and the UPN form, so
  it works whether the filter targets `sAMAccountName` or `userPrincipalName`
  (set Default domain to expand a bare name to a UPN).
- **LDAP settings are read-only for an LDAP-authenticated superadmin** — any
  change returns `403 ldap_readonly`; only a superadmin signed in with a local
  password may modify them (prevents tampering and self-lockout by disabling
  LDAP).

### Fixed
- LDAP bind failures are now logged with the real directory error (`WARN`) and
  surfaced in the test dialog with the result code; a rejected bind is reported
  as a "Configuration error", not a misleading "Connection error".

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
