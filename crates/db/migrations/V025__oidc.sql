-- ===========================================================================
-- OpenID Connect single sign-on.
--
-- A third way in, alongside the local Argon2 password and the LDAP directory
-- bind (V001). Generic OIDC, not tied to any one product: Authentik is the
-- reference configuration, but the same tables serve Keycloak, Entra, Okta or
-- Google without change.
--
-- Five pieces:
--   1. `oidc_providers`      — what to talk to. Several may be configured and
--                              enabled at once; the login screen renders one
--                              button per enabled provider.
--   2. `oidc_identities`     — the binding that actually authenticates a user:
--                              (issuer, subject). Email is NEVER the key. A
--                              user may hold identities from several providers.
--   3. `oidc_auth_requests`  — in-flight browser redirects (state, nonce, PKCE
--                              verifier). Single-use, short-lived.
--   4. `oidc_device_requests`— in-flight device-code flows, for the desktop and
--                              mobile clients. The server brokers the whole
--                              exchange; the client never sees an IdP token.
--   5. Two columns: an admin-armed linking window on `users`, and the
--      "hide local password login" switch on `platform_settings`.
--
-- Purely additive. Every new table starts empty, both new columns are
-- defaulted, and no existing table's semantics change — an install that never
-- configures a provider behaves exactly as it did before this migration ran.
-- Local password login and LDAP are untouched.
-- ===========================================================================

-- --- 1. Providers ----------------------------------------------------------

CREATE TABLE oidc_providers (
    id                     uuid          PRIMARY KEY DEFAULT uuidv7(),
    -- URL-safe key used in the route path (/auth/oidc/{slug}/start). Stable
    -- across renames on purpose: `display_name` is what an admin edits, and a
    -- rename must not break a bookmarked or documented sign-in URL.
    slug                   varchar(64)   NOT NULL UNIQUE,
    -- Button label on the login screen, e.g. "Sign in with Authentik".
    display_name           varchar(128)  NOT NULL,
    -- Master switch. A provider is invisible and unusable until enabled, so a
    -- half-configured one can never lock anybody out.
    enabled                boolean       NOT NULL DEFAULT false,
    -- Issuer URL. Discovery appends /.well-known/openid-configuration; the
    -- value returned in the document's `issuer` field must match this exactly
    -- (that comparison is what makes the ID token's `iss` claim meaningful).
    issuer_url             text          NOT NULL,
    client_id              text          NOT NULL,
    -- Write-only, exactly like ldap_settings.service_bind_password: stored for
    -- the token exchange, never serialized by the API, which exposes only a
    -- `client_secret_set` boolean. Empty for a public client.
    client_secret          text          NOT NULL DEFAULT '',
    -- Space-separated. `openid` is mandatory and is re-added if omitted.
    -- Authentik's `profile` scope already carries username, name and groups.
    scopes                 text          NOT NULL DEFAULT 'openid profile email',
    -- Which claim carries what. Defaults are the standard OIDC names, which
    -- Authentik honours out of the box.
    claim_email            varchar(64)   NOT NULL DEFAULT 'email',
    claim_username         varchar(64)   NOT NULL DEFAULT 'preferred_username',
    claim_display_name     varchar(64)   NOT NULL DEFAULT 'name',
    claim_groups           varchar(64)   NOT NULL DEFAULT 'groups',
    -- Membership grants platform superadmin; absence revokes it, on every
    -- sign-in. Empty disables the mapping entirely, leaving is_superadmin
    -- managed inside IntelliPilot. Mirrors ldap_settings.superadmin_group.
    superadmin_group       text          NOT NULL DEFAULT '',
    -- Create an account on first sign-in for a subject nobody has seen. When
    -- false, only users who already hold a linked identity can sign in.
    allow_jit_provisioning boolean       NOT NULL DEFAULT true,
    -- Refuse to provision or link when the IdP does not assert
    -- `email_verified`. Turning this off means trusting the IdP's word about
    -- an address it may never have checked.
    require_email_verified boolean       NOT NULL DEFAULT true,
    -- Offer this provider to the desktop / mobile clients over the device-code
    -- flow. Requires the IdP to publish a device_authorization_endpoint.
    device_flow_enabled    boolean       NOT NULL DEFAULT true,
    -- Login-screen button order, then display_name for ties.
    sort_order             integer       NOT NULL DEFAULT 0,
    -- Lab / self-signed only, same escape hatch as ldap_settings.
    skip_tls_verify        boolean       NOT NULL DEFAULT false,
    created_at             timestamptz   NOT NULL DEFAULT now(),
    updated_at             timestamptz   NOT NULL DEFAULT now(),
    updated_by             uuid          REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT oidc_providers_slug_shape CHECK (slug ~ '^[a-z0-9][a-z0-9-]*$'),
    CONSTRAINT oidc_providers_issuer_present CHECK (length(trim(issuer_url)) > 0),
    CONSTRAINT oidc_providers_client_id_present CHECK (length(trim(client_id)) > 0)
);

CREATE INDEX oidc_providers_enabled_idx ON oidc_providers (sort_order, display_name)
    WHERE enabled;

CREATE TRIGGER oidc_providers_set_updated_at
    BEFORE UPDATE ON oidc_providers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- --- 2. Identities ---------------------------------------------------------

-- The authenticating fact. A sign-in resolves to a user by (provider,
-- subject) and by nothing else: `subject` is the only claim an IdP guarantees
-- to be stable and unique, whereas an email address can be changed, reassigned
-- or simply asserted without ever having been verified.
CREATE TABLE oidc_identities (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id   uuid        NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
    -- Copied from the discovery document at link time. Kept alongside the
    -- provider row so a later edit of `issuer_url` cannot silently repoint an
    -- existing binding at a different identity source.
    issuer        text        NOT NULL,
    subject       text        NOT NULL,
    -- What the IdP claimed at link time. Informational — shown in the UI so a
    -- user can tell two linked accounts apart. Never used to authenticate.
    email_at_link text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,

    CONSTRAINT oidc_identities_subject_unique UNIQUE (provider_id, subject)
);

CREATE INDEX oidc_identities_user_idx ON oidc_identities (user_id);

COMMENT ON TABLE oidc_identities IS
    'Binding between an IntelliPilot user and an external OIDC subject. '
    'Authentication resolves on (provider_id, subject) only — email is never '
    'an authenticating fact.';

-- --- 3. In-flight browser redirects ---------------------------------------

-- One row per outstanding authorization request. Holds the CSRF `state`, the
-- replay-defeating `nonce` and the PKCE verifier, none of which may ever reach
-- the client. Rows are single-use: the callback deletes the row it redeemed,
-- and `/start` sweeps expired ones, so the table stays small without a job.
CREATE TABLE oidc_auth_requests (
    state         text        PRIMARY KEY,
    provider_id   uuid        NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
    nonce         text        NOT NULL,
    code_verifier text        NOT NULL,
    -- 'login' mints a session; 'link' binds a new identity to link_user_id and
    -- mints nothing.
    purpose       varchar(16) NOT NULL DEFAULT 'login',
    link_user_id  uuid        REFERENCES users(id) ON DELETE CASCADE,
    -- App-relative path to land on afterwards. Validated when stored: it must
    -- begin with a single '/' and carry no scheme or authority, or it is
    -- replaced by '/'. An open redirect here would turn the login flow into a
    -- phishing primitive.
    redirect_to   text        NOT NULL DEFAULT '/',
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,

    CONSTRAINT oidc_auth_requests_purpose CHECK (purpose IN ('login', 'link')),
    CONSTRAINT oidc_auth_requests_link_user CHECK (
        (purpose = 'link' AND link_user_id IS NOT NULL)
        OR (purpose = 'login' AND link_user_id IS NULL)
    )
);

CREATE INDEX oidc_auth_requests_expiry_idx ON oidc_auth_requests (expires_at);

-- --- 4. In-flight device-code flows ---------------------------------------

-- The desktop and mobile clients cannot host a redirect endpoint, so the
-- server brokers RFC 8628 on their behalf: it holds the IdP's `device_code`
-- and hands the client an unrelated opaque `poll_token`. The client therefore
-- never possesses a credential that is valid at the IdP, and the provider's
-- client secret never leaves the server.
CREATE TABLE oidc_device_requests (
    id                        uuid        PRIMARY KEY DEFAULT uuidv7(),
    provider_id               uuid        NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
    -- The IdP-issued device code. Server-side only; never returned to anyone.
    device_code               text        NOT NULL,
    -- Shown to the human, who types it at the IdP's verification page.
    user_code                 text        NOT NULL,
    verification_uri          text        NOT NULL,
    verification_uri_complete text        NOT NULL DEFAULT '',
    -- Minimum seconds the IdP wants between polls. Enforced server-side, so a
    -- misbehaving client cannot hammer the IdP through us.
    interval_secs             integer     NOT NULL DEFAULT 5,
    -- SHA-256 of the opaque token the client polls with, stored hashed for the
    -- same reason refresh tokens are (crates/auth/src/refresh.rs).
    poll_token_hash           text        NOT NULL UNIQUE,
    last_polled_at            timestamptz,
    purpose                   varchar(16) NOT NULL DEFAULT 'login',
    link_user_id              uuid        REFERENCES users(id) ON DELETE CASCADE,
    created_at                timestamptz NOT NULL DEFAULT now(),
    expires_at                timestamptz NOT NULL,
    consumed_at               timestamptz,

    CONSTRAINT oidc_device_requests_purpose CHECK (purpose IN ('login', 'link')),
    CONSTRAINT oidc_device_requests_link_user CHECK (
        (purpose = 'link' AND link_user_id IS NOT NULL)
        OR (purpose = 'login' AND link_user_id IS NULL)
    )
);

CREATE INDEX oidc_device_requests_expiry_idx ON oidc_device_requests (expires_at);

-- --- 5. Account-side columns ----------------------------------------------

-- Admin-armed linking window. Because an SSO sign-in never auto-links by
-- email, a user who already exists (local or LDAP) needs a deliberate act to
-- bind their IdP subject. The self-service route is Profile → Security. This
-- column is the rescue route for someone who *cannot* sign in any more: a
-- superadmin opens a short window, and the next SSO sign-in whose verified
-- email matches this account links to it.
ALTER TABLE users
    ADD COLUMN oidc_link_armed_until timestamptz;

COMMENT ON COLUMN users.oidc_link_armed_until IS
    'While in the future, the next OIDC sign-in presenting this account''s '
    'verified email links its subject to this account instead of being '
    'refused. Cleared on use. Armed only by a superadmin.';

-- The enforcement switch for a deployment that has proven its IdP and wants
-- the password form gone. Default false, so nothing changes on upgrade.
--
-- Deliberately never applies to a superadmin who still holds a local password:
-- that account is the break-glass path back in when an IdP is misconfigured,
-- unreachable or has locked out its own administrators. The same carve-out
-- already exists for LDAP (crates/api/src/auth/handlers.rs).
ALTER TABLE platform_settings
    ADD COLUMN local_password_login_disabled boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN platform_settings.local_password_login_disabled IS
    'Hide local password login and refuse it at the API. Never applies to a '
    'superadmin holding a local password — that is the break-glass account.';
