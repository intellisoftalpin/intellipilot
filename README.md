# IntelliPilot

A multi-tenant project-management platform (epics, user stories, tasks, issues,
milestones, wiki, comments, attachments) built as a Rust workspace.

- **Language / edition**: Rust 1.88, edition 2024
- **HTTP**: [axum](https://docs.rs/axum) 0.8 + [tower](https://docs.rs/tower) / [tower-http](https://docs.rs/tower-http)
- **Database**: PostgreSQL 18 via [tokio-postgres](https://docs.rs/tokio-postgres) + [deadpool-postgres](https://docs.rs/deadpool-postgres)
- **Migrations**: [refinery](https://docs.rs/refinery) (plain SQL, `V001..V009`)
- **Auth**: Argon2id passwords, PASETO v4 access tokens with family-rotated
  refresh tokens, TOTP (RFC 6238), FIDO2 / passkeys via
  [webauthn-rs](https://docs.rs/webauthn-rs)
- **API docs**: OpenAPI (utoipa) served by Swagger UI and Scalar
- **License**: MIT — internal product (`publish = false`)

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

## Delivery phases

Development is organised as numbered phases, each landing as a commit on
`main`. The current state on `main`:

| Phase | Focus |
|---|---|
| 0 | Workspace scaffold, health, OpenAPI, Problem JSON errors |
| 1 | Identity: register / login / sessions / refresh, password policy |
| 2 | 2FA: TOTP, recovery codes, WebAuthn passkeys |
| 3 | Projects, roles, memberships, invitations |
| 4 | Per-project taxonomies (status, type, priority, severity, points) |
| 5 | Backlog: epics, stories, tasks, issues, comments, history, idempotency |
| 6 | Labels & components catalog |
| 7 | Milestones (board + burndown) and attachments |
| 8 | Wiki: pages, revisions, diff, restore |

CI comments reference a future Phase 10 (Hardening) that will add container
vulnerability scanning, SBOM generation on release, and cosign signatures.

---

## License

MIT — see [`LICENSE`](LICENSE).
