# Changelog

All notable changes to the IntelliPilot backend are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to Semantic Versioning.

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
