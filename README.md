# IntelliPilot — Free, Self-Hosted Jira Alternative with Built-In LDAP & Active Directory SSO

> **Open-source project management and issue tracking you run on your own servers — with Active Directory and OpenLDAP single sign-on included for free, not locked behind an "enterprise" tier.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Built with Rust](https://img.shields.io/badge/Backend-Rust-orange.svg)
![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2018-336791.svg)
![Flutter client](https://img.shields.io/badge/Client-Flutter-02569B.svg)
![Self-hosted](https://img.shields.io/badge/Deploy-Self--hosted-success.svg)
![LDAP & Active Directory](https://img.shields.io/badge/Auth-LDAP%20%2B%20Active%20Directory-brightgreen.svg)

**IntelliPilot** is a lightweight, **self-hosted Jira alternative** for agile and
scrum teams: epics, user stories, tasks and issues on a **Kanban board**, sprints
and **milestones**, a project **wiki**, comments, attachments, and fine-grained
**roles and permissions**. It authenticates users against **LDAP and Active
Directory** directories out of the box — both Active-Directory-style direct bind
*and* **OpenLDAP** service-account search-then-bind — so your team gets directory
**single sign-on (SSO)** with no paid plan and no per-seat SSO surcharge.

It is **free and open source (MIT)**, ships a fast Rust + PostgreSQL backend and a
cross-platform [Flutter web/desktop/mobile client](https://github.com/intellisoftalpin/intellipilot),
and is designed to run **on-premise** — including air-gapped networks — via a
single hardened Docker image.

> Website: [intellisoftalpin.com](https://intellisoftalpin.com) · License: [MIT](LICENSE)

---

## Why IntelliPilot — the free LDAP / Active Directory niche

Most free and self-hosted project-management tools make you pay for directory
authentication: LDAP, Active Directory, and SAML/SSO are almost always
"enterprise" upsells. IntelliPilot is built the other way around.

- 🟢 **LDAP & Active Directory SSO for free.** Sign in against your existing
  directory — Microsoft Active Directory *or* OpenLDAP — with group-based
  superadmin mapping. No enterprise tier, no SSO tax, no per-user fee.
- 🟢 **Both bind modes.** *Direct bind* for Active Directory (`user@domain`), and
  *service-account search-then-bind* for OpenLDAP where the login name isn't the
  entry's RDN. Reverse `(member=…)` group search with a `memberOf` fallback.
- 🟢 **Truly self-hosted.** Your data stays on your infrastructure — on-premise,
  private cloud, or air-gapped. No telemetry, no phone-home.
- 🟢 **Free and open source (MIT).** No seat limits, no paywalled features.
- 🟢 **Modern security baseline.** Argon2id, PASETO v4 tokens, TOTP 2FA, and
  FIDO2 / passkeys — included, not gated.

A **free, self-hosted Jira / Taiga / Redmine / OpenProject / YouTrack
alternative** with directory single sign-on that doesn't cost extra is a rare
combination — that's the gap IntelliPilot fills.

---

## Features

- **Agile backlog** — epics, user stories, tasks and issues with fractional-index
  reordering; short references like `PROJ-42`.
- **Kanban board & sprints** — board view, milestones/sprints with scope and stats.
- **Project wiki** — Markdown pages with revisions, diff and restore.
- **Collaboration** — comments, attachments (signed downloads), per-entity history.
- **Roles & permissions** — fine-grained, per-project membership and invitations.
- **Directory SSO** — **LDAP / Active Directory / OpenLDAP** authentication with
  group-to-superadmin mapping (see [the niche above](#why-intellipilot--the-free-ldap--active-directory-niche)).
- **Strong auth** — Argon2id password hashing, PASETO v4 access tokens with
  family-rotated refresh tokens, **TOTP 2FA**, and **FIDO2 / passkeys / WebAuthn**.
- **Notifications** — email (SMTP or Mailgun), **Matrix**, and **Telegram**, with
  per-event delivery toggles.
- **White-label / branding** — override the app name, icon and login message.
- **Privacy & compliance** — GDPR-friendly soft-delete with grace period, data
  export, and an append-only audit log.
- **Self-hosted & hardened** — distroless, non-root, read-only Docker image;
  OpenAPI docs via Swagger UI and Scalar.

---

## Tech stack

- **Language / edition**: Rust 1.88, edition 2024
- **HTTP**: [axum](https://docs.rs/axum) 0.8 + [tower](https://docs.rs/tower) / [tower-http](https://docs.rs/tower-http)
- **Database**: PostgreSQL 18 via [tokio-postgres](https://docs.rs/tokio-postgres) + [deadpool-postgres](https://docs.rs/deadpool-postgres)
- **Migrations**: [refinery](https://docs.rs/refinery) (plain SQL)
- **Auth**: Argon2id passwords, PASETO v4 access tokens with family-rotated
  refresh tokens, TOTP (RFC 6238), FIDO2 / passkeys via
  [webauthn-rs](https://docs.rs/webauthn-rs), and LDAP / Active Directory via
  [ldap3](https://docs.rs/ldap3)
- **Client**: [Flutter](https://github.com/intellisoftalpin/intellipilot) (web, macOS, Linux, Windows, Android, iOS)
- **API docs**: OpenAPI (utoipa) served by Swagger UI and Scalar
- **License**: [MIT](LICENSE)

---

## Repository layout

```
intellipilot/
├─ Cargo.toml              # workspace manifest, pinned deps, lints, profiles
├─ rust-toolchain.toml     # Rust 1.88 pin
├─ rustfmt.toml            # formatting rules
├─ deny.toml               # cargo-deny config
├─ audit.toml              # cargo-audit config
├─ typos.toml              # typo checker config
├─ docker/
│  ├─ Dockerfile           # distroless / nonroot, cargo-chef cached build
│  └─ compose.yaml         # local dev stack (Postgres 18 + API)
├─ .github/workflows/ci.yaml
└─ crates/
   ├─ core/                # pure domain types — no I/O
   ├─ db/                  # tokio-postgres data access + SQL migrations
   ├─ auth/                # Argon2id, PASETO v4, TOTP, WebAuthn primitives
   ├─ storage/             # Storage trait + local-FS impl (sharded)
   ├─ mailer/              # Mailer trait + Noop / Logging / Mailgun impls
   ├─ testkit/             # shared TestDb fixture for integration tests
   └─ api/                 # axum HTTP server, routes, OpenAPI doc
```

The dependency graph is strictly acyclic with `core` at the bottom:

```
api ──► auth, db, storage, mailer, core
db  ──► core
auth, storage, mailer ──► core
testkit ──► core, db
```

---

## Prerequisites

- Rust 1.88 (the toolchain file pins it; [rustup](https://rustup.rs) will
  install it automatically)
- PostgreSQL 18 (for anything beyond `/health` and `/docs` — the binary boots
  without it but only health and docs are mounted)
- Docker + Docker Compose (optional — easiest way to get Postgres + the API
  running together)

For running the test/lint matrix locally you'll also want:

```bash
cargo install cargo-nextest cargo-deny cargo-audit
```

---

## Quick start — Docker Compose

The fastest path to a working stack (Postgres + API) is:

```bash
docker compose -f docker/compose.yaml up --build
```

This brings up Postgres 18 on `127.0.0.1:5432` and the API on
`127.0.0.1:8080`. The API container is read-only, drops all capabilities, and
runs as a non-root user.

Open:

- API base:  http://127.0.0.1:8080
- Live probe: http://127.0.0.1:8080/health/live
- Ready probe: http://127.0.0.1:8080/health/ready
- Swagger UI: http://127.0.0.1:8080/docs
- Scalar reference: http://127.0.0.1:8080/reference
- OpenAPI JSON: http://127.0.0.1:8080/openapi.json

Stop the stack:

```bash
docker compose -f docker/compose.yaml down          # keep data
docker compose -f docker/compose.yaml down -v       # wipe Postgres volume
```

---

## First-time login

Public registration is **closed by default** — the operator bootstraps an
initial superadmin from environment variables, and that superadmin invites
everyone else.

`docker/compose.yaml` defaults to `admin@local` / `admin-dev-password` so a
bare `docker compose up` lands you with a working admin. For
`compose.proxied.yaml` / `compose.full.yaml` you set the credentials in
`docker/.env`:

```env
INTELLIPILOT_BOOTSTRAP_ADMIN_EMAIL=admin@example.com
INTELLIPILOT_BOOTSTRAP_ADMIN_PASSWORD=replace-me-strong-password
```

What the API does on boot:

| State on disk | Outcome |
|---|---|
| No superadmin exists, env vars set | Creates the superadmin from env |
| Env email matches an existing user | Promotes that user (password untouched) |
| At least one superadmin already exists | Env vars are ignored; safe no-op |
| No superadmin exists and env vars are empty | Production refuses to start; development warns and continues |

Once logged in, manage users from the **Admin** menu:

- `/admin/users` — list, create directly, promote/demote, deactivate, delete, issue password reset.
- `/admin/invitations` — invite by email (mailer-less dev mode shows the raw link).
- `/admin/settings` — toggle open registration on/off at runtime.

Direct-created accounts get a `must_change_password` flag set; the user is
prompted to rotate the temporary password on first login.

---

## Local development — cargo

If you'd rather run the binary directly against your own Postgres:

```bash
# 1. Start Postgres 18 (any way you like — Docker, pg_ctl, brew services, …)
docker run --rm -d --name ip-pg -p 5432:5432 \
  -e POSTGRES_USER=intellipilot \
  -e POSTGRES_PASSWORD=intellipilot_dev \
  -e POSTGRES_DB=intellipilot \
  postgres:18-alpine

# 2. Point the binary at it and boot
export INTELLIPILOT_DATABASE_URL='postgres://intellipilot:intellipilot_dev@127.0.0.1:5432/intellipilot?sslmode=disable'
export RUST_LOG='info,intellipilot=debug'

cargo run -p intellipilot-api --bin intellipilot
```

The binary loads a `.env` file from the working directory if one is present
(via [dotenvy](https://docs.rs/dotenvy)). There is no committed `.env.example`
— use the variable table below.

When `INTELLIPILOT_DATABASE_URL` is **unset**, the server still starts but logs
a warning and mounts only the health / OpenAPI surface; identity, projects,
backlog, etc. are gated behind a configured DB.

Hot rebuild loop (optional):

```bash
cargo install cargo-watch
cargo watch -x 'run -p intellipilot-api --bin intellipilot'
```

---

## Configuration

All configuration is via environment variables. Anything safe to default in dev
is defaulted; production refuses to start without the security-sensitive
secrets.

| Variable | Default (dev) | Required in prod | Purpose |
|---|---|---|---|
| `INTELLIPILOT_ENV` | `development` | recommended | `development` enables fault-injection endpoints, `LoggingMailer`, ephemeral keys, and `Secure=false` cookies. `production` enforces real secrets. |
| `INTELLIPILOT_BIND` | `127.0.0.1:8080` | yes (`0.0.0.0:…`) | TCP listen address. |
| `INTELLIPILOT_DATABASE_URL` | unset (only health/docs mount) | yes | Postgres connection string. |
| `INTELLIPILOT_PASETO_SECRET` | ephemeral zero key (warning logged) | **yes** | High-entropy secret; SHA-256 hashed into the 32-byte PASETO v4 local key. Rotating it invalidates all access tokens. |
| `INTELLIPILOT_PASSWORD_PEPPER` | unset | recommended | Optional server-side pepper appended to Argon2id input. |
| `INTELLIPILOT_STORAGE_DIR` | `./data/attachments` | yes (writable path) | Root directory for the `LocalStorage` backend. |
| `INTELLIPILOT_ATTACHMENT_MAX_BYTES` | `26214400` (25 MiB) | no | Per-file upload limit (bytes). Multipart body cap is 32 MiB. |
| `INTELLIPILOT_ATTACHMENT_SECRET` | ephemeral fixed key (warning logged) | **yes** | HMAC key for signing short-lived attachment download URLs. |
| `INTELLIPILOT_RP_ID` | `localhost` | yes (your domain) | WebAuthn relying-party ID. |
| `INTELLIPILOT_RP_ORIGIN` | `http://localhost:8080` | yes (HTTPS origin) | WebAuthn relying-party origin. |
| `INTELLIPILOT_RP_NAME` | `IntelliPilot` | no | Human-readable RP name shown by authenticators. |
| `RUST_LOG` | `info,intellipilot=debug` | no | `tracing-subscriber` filter; logs are JSON. |

The mailer is feature-gated (`mailgun` feature on `intellipilot-mailer`). When
unconfigured, dev uses `LoggingMailer` (tokens appear in tracing output and, for
some flows, in HTTP responses) and prod uses `NoopMailer` (email-dependent
flows return 503).

---

## Database & migrations

SQL migrations live in `crates/db/migrations/V001__init_identity.sql` through
`V009__wiki.sql`. They are applied with [refinery](https://docs.rs/refinery) at
the call site — the `intellipilot-db` crate exposes the runner; integration
tests via `intellipilot-testkit` apply them into per-test schemas.

To apply or inspect migrations against a running Postgres you can either:

- run the test suite (which applies them into isolated schemas), or
- write a small binary that calls `intellipilot_db::Db::migrate()` (the helper
  in the `db` crate). There is intentionally no separate migration CLI yet.

Conventions baked into the schema:

- **IDs**: UUIDv7 everywhere (sortable, native to Postgres 18)
- **Timestamps**: `timestamptz`, UTC
- **Soft-delete + 30-day grace** for GDPR
- **Append-only audit log**
- **Idempotency keys** (table `idempotency_keys`) for mutating endpoints
- **Refresh token family chain** for token-reuse detection
- **Progressive login lockout** with exponential backoff

Migrations are append-only — add `V010__…` rather than editing existing files.

---

## API surface

Routes are constructed in `crates/api/src/router.rs`. The HTTP API is mounted
under `/api/v1` and grouped roughly as:

- `auth/*` — register / login / refresh / logout / password reset
- `me/*` — profile, GDPR export, TOTP, passkey management
- `auth/2fa/verify`, `auth/passkeys/authenticate/*` — second-factor flows
- `projects` + nested `roles`, `members`, `invitations`
- `projects/{id}/taxonomy/{kind}` — per-project status / type / priority lists
- `projects/{id}/epics|userstories|tasks|issues` — backlog CRUD + reorder
- `projects/{id}/{entity}/{id}/comments|history`
- `projects/{id}/resolve/{ref}` — short-link resolver (e.g. `PROJ-42`)
- `projects/{id}/labels|components` — project catalog
- `projects/{id}/milestones` (+ `board`, `stats`, `close`)
- `projects/{id}/{entity}/{id}/attachments` and signed downloads
- `projects/{id}/wiki` with revisions / diff / restore

Always-on:

- `GET /health/live` — liveness (process up)
- `GET /health/ready` — readiness (DB ping, etc.)
- `GET /docs` — Swagger UI
- `GET /reference` — Scalar UI
- `GET /openapi.json` — OpenAPI 3 document

Dev-only (when `INTELLIPILOT_ENV != production`):

- `GET /_fault/panic` — fault-injection endpoint used by integration tests

Errors are returned as [RFC 7807 Problem JSON](https://www.rfc-editor.org/rfc/rfc7807).
Cross-cutting middleware: request ID stamping, security headers, an in-memory
rate limiter (applied only to `/api/v1`, never to health/docs).

---

## Testing

The workspace uses [cargo-nextest](https://nexte.st):

```bash
# Unit + integration tests (will spin up Postgres-backed fixtures via testkit)
cargo nextest run --workspace --locked
```

Tests that need Postgres pick up `DATABASE_URL` (note: `DATABASE_URL`, not
`INTELLIPILOT_DATABASE_URL`) and create an isolated schema per test via
`intellipilot-testkit`. Example for a local Postgres:

```bash
export DATABASE_URL='postgres://intellipilot:intellipilot_dev@127.0.0.1:5432/intellipilot'
cargo nextest run --workspace --locked
```

Phase-scoped integration suites live in `crates/api/tests/phaseN_*.rs`.

Lints / formatting are enforced as errors:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Supply-chain checks (run in CI; useful locally before opening a PR):

```bash
cargo deny check
cargo audit --deny warnings
```

---

## CI

`.github/workflows/ci.yaml` runs on every push and PR to `main`:

| Job | What it does |
|---|---|
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| `test` | `cargo nextest run --workspace --locked --profile ci` against a Postgres 18 service container |
| `deny` | `cargo deny check --all-features` |
| `audit` | `cargo audit --deny warnings` |
| `typos` | source-tree spell check |
| `docker` | builds the production image (no push) |

CI sets `RUSTFLAGS=-D warnings` and `CARGO_INCREMENTAL=0`.

---

## Building the production image

```bash
docker build -f docker/Dockerfile -t intellipilot:dev .
docker run --rm -p 8080:8080 --read-only --tmpfs /tmp \
  -e INTELLIPILOT_DATABASE_URL='postgres://…' \
  -e INTELLIPILOT_PASETO_SECRET='…' \
  -e INTELLIPILOT_ATTACHMENT_SECRET='…' \
  intellipilot:dev
```

The Dockerfile is a 3-stage build using [cargo-chef](https://github.com/LukeMathWalker/cargo-chef)
for dependency caching, stripping symbols, and shipping on
`gcr.io/distroless/cc-debian12:nonroot`. The resulting container has no shell,
no package manager, and runs as user `nonroot`.

---

## Code conventions

These are enforced via workspace lints in the root `Cargo.toml`:

- `unsafe_code = "forbid"` — no `unsafe` anywhere in the workspace
- Clippy `pedantic`, `nursery`, `cargo` — all warn
- Hard-warn on `unwrap_used`, `expect_used`, `panic`, `todo`,
  `unimplemented`, `dbg_macro`, `print_stdout`, `print_stderr`,
  `string_slice`, `arithmetic_side_effects`, `integer_division`,
  `indexing_slicing`

Project-specific patterns:

- New domain types live in `intellipilot-core` first, then DB queries in
  `intellipilot-db`, then HTTP handlers in `intellipilot-api`.
- Use `tokio-postgres` directly — **no sqlx**. The reasoning (unmaintained
  transitive deps `paste` and `rsa`) is documented inline in the root
  `Cargo.toml` next to the DB dependency block.
- Reordering uses fractional indexing (`intellipilot_core::ordering`) — never
  renumber whole lists.
- Mutating endpoints accept client-provided idempotency keys.
- Markdown is rendered with [comrak](https://docs.rs/comrak) and then
  sanitized with [ammonia](https://docs.rs/ammonia); do not bypass the
  sanitizer.
- HTTP errors are RFC 7807 (`crates/api/src/problem.rs`).

---

## FAQ

### Is IntelliPilot a free, open-source Jira alternative?
Yes. IntelliPilot is MIT-licensed, free, and self-hosted. It covers the core of
what teams use Jira for — backlog, Kanban board, sprints/milestones, issues, and
a wiki — without seat limits or paywalled features.

### Does IntelliPilot support Active Directory and OpenLDAP?
Yes — both, and it's included for free. Active Directory works via direct bind
(`user@domain`); OpenLDAP works via a service account that searches for the
user's DN and then binds as it. Superadmin can be granted by directory group
membership.

### Do I have to pay extra for LDAP / SSO?
No. Directory authentication (LDAP / Active Directory / OpenLDAP) is a built-in
feature, not an "enterprise" upsell. There is no SSO tax and no per-seat fee.

### Can I self-host it on-premise or in an air-gapped network?
Yes. IntelliPilot ships as a single hardened Docker image (distroless, non-root,
read-only) plus PostgreSQL. There is no telemetry or phone-home, so it runs fully
offline / on-premise.

### What can I use instead of Jira, Taiga, Redmine, OpenProject or YouTrack?
IntelliPilot is a self-hosted alternative to those tools, with first-class LDAP /
Active Directory single sign-on included at no cost.

### What's the tech stack?
A Rust (axum) + PostgreSQL backend with an OpenAPI-documented REST API, and a
cross-platform Flutter client (web, desktop, mobile).

---

## Keywords

Self-hosted Jira alternative · free open-source project management · issue
tracker · Kanban board · agile / scrum · sprint & backlog management ·
**LDAP authentication** · **Active Directory SSO** · **OpenLDAP** · single
sign-on · on-premise · Rust · PostgreSQL · Flutter · MIT license · Taiga /
Redmine / OpenProject / YouTrack alternative.

---

## License

MIT — see [`LICENSE`](LICENSE). Free for personal and commercial use.

Built by [IntelliSoftAlpin](https://intellisoftalpin.com).
