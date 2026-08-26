# Changelog

All notable changes to the IntelliPilot backend are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to Semantic Versioning.

## [0.6.31] - 2026-08-26

Multi-account support for the desktop and mobile apps. Frontend companion
release is also 0.6.31. No migration.

### Added
- `POST /auth/refresh` and `POST /auth/logout` accept an optional
  `{ "refresh_token": ... }` body. **The cookie is read first**, so browser
  clients are entirely unaffected; the body path exists for desktop and mobile,
  which hold several accounts at once and therefore cannot keep one refresh
  cookie per account in a single jar.
  - A body-authenticated caller gets the rotated token back in the response —
    it has no cookie jar to receive it, and the token it sent is now spent.
  - Rotation, reuse detection and family revocation are untouched: a replayed
    body token still revokes the whole family, exactly as over the cookie.

### Notes
- `TokenResponse.refresh_token` was previously populated only when
  `env.is_dev()`. It is now also populated for body-authenticated callers. It
  remains omitted for cookie callers, so the token never becomes readable to
  scripts in a browser.

## [0.6.29] - 2026-08-25

Timesheet-report exclusion for users with no fill obligation (migration V024).
Frontend companion release is also 0.6.29.

### Added
- **`users.exclude_from_time_reports`** — set from *admin → users*
  ("Exclude from timesheet reports"). Built for top managers and freelance
  consultants: people who are on the platform but are not expected to fill a
  timesheet. It is a **reporting** exclusion, never a restriction — the user can
  still log time, edit their entries and see their own timesheet exactly as
  before. Defaulted to false, so every existing install behaves as it did.
  - Hidden from: the per-project team grid, the cross-project superadmin grid,
    the project time-entry list, and that list's CSV/XLSX export.
  - Suppressed: their unfilled-days warning. `missing_days` comes back empty
    for them, which removes the banner from the home dashboard, the project
    overview *and* their own timesheet summary card in one change.
    `working_days` / `complete_days` stay truthful.
  - **Deliberately NOT hidden from**: an issue's own time log — hiding hours
    there would understate the effort actually booked against the issue — and
    the admin cross-project entry list, so a superadmin keeps one view that
    shows every hour. Consequence worth knowing: a project time export will
    not reconcile against per-issue time logs when an excluded user has
    booked hours.
  - Toggling the flag is recorded in the audit log.
- Both team grids report `excluded_members`, surfaced **only to superadmins**
  (the field is omitted, not zeroed, for ordinary project managers, so an
  exclusion cannot be inferred by anyone who did not set it). The grid renders
  it as a quiet, name-free footer note so a deliberately absent row does not
  read as a bug.

### Changed
- `list_for_project` now takes a `ReportScope` (`ProjectWide` | `IssueLevel`).
  Three call sites share that query and two must filter while the third must
  not; an enum makes each site state which it is, where a bool could be
  silently inverted by a later refactor.

## [0.6.26] - 2026-08-25

The My Issues board and project rail count badges. No migration. Frontend
companion release is also 0.6.26.

### Added
- **My Issues board** — a per-project kanban of the caller's own work, laned by
  the relation they have to each issue: watching, assignee, QA, reviewer,
  requestor, mentioned. It is a new `group=my_role` value on the existing
  board-data endpoint, so it reuses the whole board pipeline (per-column counts,
  capped cards, delta sync, live events, drag-to-change-status).
  - An issue appears in **every** lane it qualifies for, the way a
    component-grouped board already duplicates a card across its components. So
    lane totals deliberately do not partition the card set.
  - The `mentioned` lane resolves `@handle` in issue descriptions *and* comment
    bodies through the existing `search_index` trigram index, rather than
    ILIKE-scanning `issues.description` and `comments.body` per row.
- `my_role=<role|any>` filter on `GET /projects/{id}/issues` and the board-data
  endpoint. An unrecognised value is a 422 rather than a silently dropped
  filter, which would widen the response to the whole project.
- `GET /projects/{id}/counts` — active-object totals for the navigation rail
  badges (`my_issues`, `issues`, `epics`, `milestones`). "Active" means not
  closed and not deleted. Each count is gated by its own view permission
  (`issue.view` / `epic.view` / `milestone.view`) and comes back `null`, not
  `0`, when the caller may not see that section.
  - `my_issues` counts **distinct** issues, top-level only, matching what the
    My Issues board actually renders — not the sum of its lane totals.
  - `issues` counts sub-tasks too, matching the issues list, which does not
    filter on `parent_id`.

### Changed
- Project rail order is now Overview → My Issues → Boards → Issues → Epics →
  Milestones → Time tracking → Wiki → Settings, with a count badge on the four
  entity sections.

## [0.6.25] - 2026-08-18

Statuses that count as completed, stacked detail sidebars, and multi-version
kanban badges (migration V023). Frontend companion release is also 0.6.25.

### Added
- `taxonomy_items.counts_as_done`: which statuses epic and milestone progress
  treat as finished work. A task in *In Staging* needs no more work and can
  now fill the progress ring without being closed. Backfilled from
  `is_closed`, so every existing install reports the numbers it did before.
- Detail sidebars stack: milestone → epic → task, each layered over the last,
  each close returning to the one beneath. An entity already open cannot be
  pushed again, which is what stops an epic and its task from re-opening each
  other indefinitely.
- Kanban cards show every fix version an issue ships in, capped at three with
  a `+N` pill; hovering it reveals the full component-to-version table, and
  clicking pins that popup open.
- The milestone's Manage epics dialog is searchable by epic subject and key.

### Changed
- Progress bars are the **only** thing that moved to `counts_as_done`.
  `is_closed` still governs the resolution-required rule, the open-issue
  filters, the dashboard and the board's column logic — the two flags answer
  different questions and are independent, so a project may set them apart.
- The board's release filter now matches **any** of an issue's per-component
  versions rather than the `release_version_id` mirror, which had begun to
  hide issues whose card visibly showed a matching version.
- Tapping an issue inside an epic (or a subtask inside a task) opens it as a
  panel over the current one instead of navigating away to its full page.

## [0.6.24] - 2026-08-17

Per-component fix versions and an issue actions menu (migration V022).
Frontend companion release is also 0.6.24.

### Added
- `issue_component_versions`: the version each affected component ships the
  fix in. A change that lands in different versions of different components
  can finally say so. The version must belong to a release that component is
  linked to, which is what makes the choice meaningful.

### Changed
- `issues.release_version_id` is now a **mirror** of the lowest-ordered
  per-component version, maintained by trigger. Every `?version=` filter,
  export and board group-by keeps reading it unchanged; set versions per
  component instead of writing it directly.
- `set_issue_components` now deletes only the components actually being
  removed rather than clearing and re-inserting the lot. The wholesale clear
  would have pruned every per-component version on any edit that merely
  touched the component list.

### Fixed
- Issues could not be deleted from their detail page — only epics had the
  action. Both now sit in a single actions menu next to the status pill,
  alongside clone, move-to-epic, copy link, and jumps to the time log,
  attachments and links.

## [0.6.23] - 2026-08-17

Milestone dates split into planned and actual, plus fixes to the documentation
setup flow (migration V021). Frontend companion release is also 0.6.23.

### Added
- `milestones.actual_end_date`: when a milestone really finished, alongside the
  planned `end_date` it has always had. The gap between the two is the slip,
  which the timeline draws in its own colour — overrun one way, time saved the
  other. Completing a milestone records the actual end from the plan when it
  is still empty, and never overwrites one already there.

### Changed
- The business release date must now trail whichever technical end really
  happened — `actual_end_date` when set, otherwise `end_date`. Previously the
  rule only ever looked at the plan, so a slipped milestone could announce a
  business release *before* the release it announces. Recording an actual end
  that would break this is refused with a 422 rather than a constraint error.
- Ordering keys off the same effective end date, so a slipped milestone moves
  to where its bar actually sits.

### Fixed
- **The internal wiki editor was unusable.** Both of its text fields built a
  new `TextEditingController` inside `build`, so every keystroke emitted new
  state, rebuilt the widget and reset the caret to the start of the field. The
  editor now owns its controllers and reuses the shared markdown editor, which
  brings a formatting toolbar (bold, headings, lists, links, quotes, code) and
  a live preview beside the source, scrolled in step with it.
- **Registering a git documentation source with a generated key could never
  succeed.** Creation generated the deploy key and probed the remote in the
  same request, so it authenticated with a key that had not been added to the
  git host yet and always failed. The key is now created up front through the
  existing SSH-key endpoint, its public half is shown for copying, and the
  connection is verified separately before the source is registered.

## [0.6.22] - 2026-08-17

External documentation sources: git repositories surfaced under a project's
Wiki section, browsable and editable in place (migration V020). Frontend
companion release is also 0.6.22.

### Added
- `doc_sources`: up to 10 per project, in two kinds.
  - **git** — a repository exposing one subtree (`doc_path`) read from a
    cached bare clone. Registration verifies the remote is reachable and the
    branch exists before storing anything; the clone runs in the background.
  - **web** — a plain URL the client embeds in a sandboxed frame. Nothing is
    fetched, cloned or stored server-side, and it is read-only by
    construction: a CHECK constraint makes `read_only` unclearable for one,
    so there is no state in which it could be edited.
  Every source carries a user-set title (`name`) shown in the sidebar, the
  overview tile, the breadcrumb and above an embedded page.
- `doc_sources.hidden`: withdraw a source from navigation without discarding
  its configuration. Hidden sources are listed only to callers holding
  `doc_source.modify` and read as 404 to everyone else; clearing the flag
  restores them untouched.
- `doc_user_keys`: one writable SSH key per user per project. Edits are
  committed and pushed as that user, so git history attributes a change to the
  person who made it. Keys are generated server-side or imported;
  passphrase-protected keys are refused.
- Endpoints under `/projects/{id}/doc-sources`: CRUD, `POST .../sync`,
  `GET .../tree`, `GET|PUT .../doc?path=`, `GET .../blob?path=`, plus
  `/projects/{id}/doc-keys/me`.
- Four permissions — `doc_source.view` / `.create` / `.modify` / `.delete` —
  backfilled onto the roles holding the equivalent `wiki.*` permission.
- A background refresher re-fetches every source on a configurable interval
  (`INTELLIPILOT_DOCS_SYNC_INTERVAL_SECS`, default 900s). Size caps are
  `INTELLIPILOT_DOCS_MAX_SOURCE_BYTES` (500 MiB) and
  `INTELLIPILOT_DOCS_MAX_FILE_BYTES` (10 MiB).

### Changed
- `projects.wiki_enabled` is now **enforced**. The column has existed since
  V001 but no endpoint consulted it; the internal wiki now answers 404 while it
  is off. Nothing is deleted — pages and revisions return untouched when it is
  switched back on. Defaults to true, so existing installs are unaffected.

### Security
- Documentation content is read from git tree and blob objects rather than
  from a checked-out working directory, so no request path exists to walk out
  of. Client-supplied paths are resolved lexically and **refused** — never
  clamped — when they land above the configured subtree. Symlink and submodule
  entries are skipped rather than followed. SVG blobs are sanitized before
  being served.

## [0.6.21] - 2026-08-17

Milestone rework: epic-only membership, business release dates, and a detail
sidebar (migration V019). Frontend companion release is also 0.6.21.

### Added
- Milestones gain a description and a *business* release date — the commercial
  ship date trailing the technical end date — gated behind the new
  `milestone.business_release.view` / `.modify` permissions.
- `POST /milestones/{id}/reopen` and `GET /milestones/{id}/epics`.

### Changed
- Milestone membership is structural: issues reach a milestone **only** through
  their epic. `issues.milestone_id` is retained and still read by every board
  filter, group-by and export, but it is now written exclusively by two
  triggers. Setting it directly returns 422 `milestone_via_epic_only`.
- Deleting a milestone that still holds epics returns 409
  `milestone_has_epics`.

## [0.6.20] - 2026-07-31

Live change feed extended beyond issues. Frontend companion release is also
0.6.20. No migration, no schema change.

### Added
- The project SSE feed now publishes `epic.created` / `epic.updated` /
  `epic.deleted` (carrying the full entity, like the issue events already did)
  and `comment.created` / `comment.updated` / `comment.deleted` (carrying the
  target and comment ids). Previously only issues and boards broadcast, so an
  open epic — or a comment thread on any entity — could not stay live.

## [0.6.19] - 2026-07-31

Version-only release, kept in lockstep with frontend 0.6.19 (epic / issue
detail UI rework). No API, schema or behaviour changes — no migration.

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
