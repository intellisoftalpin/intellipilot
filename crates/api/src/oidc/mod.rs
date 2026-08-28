//! OpenID Connect single sign-on (V025).
//!
//! Generic OIDC, not tied to one product: Authentik is the reference
//! configuration and test target, but Keycloak, Entra, Okta and Google are the
//! same code path. Everything is driven from the provider's discovery
//! document, so nothing here knows any vendor's endpoint layout.
//!
//! # Why the server brokers both flows
//!
//! Neither flow gives the client an IdP credential. The browser flow redirects
//! through the API, which exchanges the code and mints an IntelliPilot session
//! of its own; the device flow has the API hold the IdP's `device_code` and
//! hand the client an unrelated opaque poll token. So the provider's client
//! secret never leaves the server, the Flutter app needs no per-platform URL
//! scheme registration, and a native client that can point at any IntelliPilot
//! server automatically gets that server's provider configuration.
//!
//! # Division of labour with `openidconnect`
//!
//! The library does the security-critical work: discovery, JWKS retrieval and
//! ID-token verification (signature, issuer, audience, expiry, nonce).
//! Hand-rolling those checks is where OIDC integrations acquire CVEs. The
//! device authorization endpoint, which the library models only as a blocking
//! poll loop, is driven directly over `reqwest` — a mechanical form POST with
//! nothing to get subtly wrong.
//!
//! # What authenticates a user
//!
//! `(issuer, subject)` and nothing else. Email is used in exactly two places,
//! both of which *withhold* access rather than granting it: refusing to
//! provision over an address that already exists, and matching an
//! admin-armed link. See [`resolve`].

pub mod backchannel;
pub mod device;
pub mod flow;
pub mod handlers;
pub mod resolve;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreErrorResponseType,
    CoreGenderClaim, CoreGrantType, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
    CoreRevocableToken, CoreRevocationErrorResponse, CoreSubjectIdentifierType,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AdditionalProviderMetadata, Client, ClientId, ClientSecret,
    DeviceAuthorizationUrl, EmptyExtraTokenFields, EndpointNotSet, IdToken, IdTokenClaims,
    IdTokenFields, IssuerUrl, ProviderMetadata, StandardErrorResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use intellipilot_db::oidc_providers::OidcProvider;

/// How long a fetched discovery document (and its JWKS) is reused.
///
/// Long enough that a busy login page is not re-fetching metadata on every
/// request, short enough that a key rotation at the identity provider heals on
/// its own within a quarter of an hour.
///
/// Deliberately *not* "refetch whenever a signature fails to verify": that
/// would let anyone who can present a garbage token force an outbound request
/// to the provider on demand. A rotation therefore costs up to this long of
/// refused sign-ins, which is the accepted trade for not handing out that
/// lever. An administrator in a hurry can force a refresh by pressing Test on
/// the provider, which invalidates the entry.
const DISCOVERY_TTL: Duration = Duration::from_secs(15 * 60);

/// Cap on how long any single call to an identity provider may take.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

// --------------------------------------------------------------------------
// Type aliases: the library's generics, specialised for what we need
// --------------------------------------------------------------------------

/// Claims the standard set does not model.
///
/// The group claim's *name* is per-provider configuration, so it cannot be a
/// typed field — everything the standard claims do not cover is captured here
/// and looked up by name at resolution time.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ExtraClaims {
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

impl AdditionalClaims for ExtraClaims {}

/// Discovery fields outside the OIDC core set.
///
/// Both are optional because a provider need not offer either. Authentik
/// publishes both; a provider that does not simply cannot serve the device
/// flow, which the admin UI reports rather than failing at sign-in time.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ExtraMetadata {
    #[serde(default)]
    pub device_authorization_endpoint: Option<DeviceAuthorizationUrl>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

impl AdditionalProviderMetadata for ExtraMetadata {}

pub type IpProviderMetadata = ProviderMetadata<
    ExtraMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub type IpIdToken = IdToken<
    ExtraClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub type IpIdTokenClaims = IdTokenClaims<ExtraClaims, CoreGenderClaim>;

pub type IpIdTokenFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub type IpTokenResponse = StandardTokenResponse<IpIdTokenFields, CoreTokenType>;

pub type IpClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
    HasUserInfoUrl = EndpointNotSet,
> = Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    openidconnect::core::CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    IpTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// What can go wrong talking to an identity provider.
///
/// The split matters for the HTTP status the caller returns: `Config` is the
/// operator's mistake (500 / a clear admin-side message), `Unavailable` is the
/// IdP's problem (503, and never a 500 — an unreachable directory is not an
/// internal error), and `Rejected` is the user's or the IdP's answer (401).
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("provider is misconfigured: {0}")]
    Config(String),
    #[error("identity provider unavailable: {0}")]
    Unavailable(String),
    #[error("identity provider rejected the request: {0}")]
    Rejected(String),
    /// The device flow is still waiting on the human. Not a failure.
    #[error("authorization pending")]
    Pending,
    /// The device flow's poll interval was not respected; back off and retry.
    #[error("slow down")]
    SlowDown,
}

// --------------------------------------------------------------------------
// HTTP client
// --------------------------------------------------------------------------

/// Build the HTTP client used for every call to an identity provider.
///
/// Redirects are disabled deliberately: an OIDC client that follows them can
/// be walked from a public discovery URL onto an internal address, which is a
/// textbook SSRF. The `openidconnect` documentation calls this out, and the
/// endpoints we talk to never legitimately redirect.
pub fn http_client(provider: &OidcProvider) -> Result<openidconnect::reqwest::Client, OidcError> {
    let mut builder = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(HTTP_TIMEOUT);
    if provider.skip_tls_verify {
        // Lab / self-signed escape hatch, mirroring ldap_settings.skip_tls_verify.
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
        .build()
        .map_err(|e| OidcError::Config(format!("could not build HTTP client: {e}")))
}

// --------------------------------------------------------------------------
// Discovery cache
// --------------------------------------------------------------------------

struct CachedMetadata {
    metadata: IpProviderMetadata,
    fetched_at: Instant,
}

/// Per-process cache of provider discovery documents, keyed by provider id.
///
/// Lives in `AppState`. Entries carry the issuer URL they were fetched for, so
/// editing a provider's `issuer_url` invalidates its entry rather than serving
/// metadata for the previous identity source.
#[derive(Clone, Default)]
pub struct OidcCache {
    entries: Arc<Mutex<HashMap<(uuid::Uuid, String), CachedMetadata>>>,
}

impl std::fmt::Debug for OidcCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcCache").finish_non_exhaustive()
    }
}

impl OidcCache {
    /// Fetch (or reuse) the provider's discovery document and JWKS.
    pub async fn metadata(&self, provider: &OidcProvider) -> Result<IpProviderMetadata, OidcError> {
        let key = (provider.id, provider.issuer_url.clone());
        {
            let guard = self.entries.lock().await;
            if let Some(hit) = guard.get(&key)
                && hit.fetched_at.elapsed() < DISCOVERY_TTL
            {
                return Ok(hit.metadata.clone());
            }
        }

        let issuer = IssuerUrl::new(provider.issuer_url.clone())
            .map_err(|e| OidcError::Config(format!("invalid issuer URL: {e}")))?;
        let http = http_client(provider)?;
        let metadata = IpProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|e| OidcError::Unavailable(format!("discovery failed: {e}")))?;

        {
            let mut guard = self.entries.lock().await;
            guard.insert(
                key,
                CachedMetadata {
                    metadata: metadata.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }
        Ok(metadata)
    }

    /// Drop a provider's cached metadata — called after an admin edits or
    /// deletes it, so the next sign-in cannot use stale endpoints or keys.
    pub async fn invalidate(&self, provider_id: uuid::Uuid) {
        let mut guard = self.entries.lock().await;
        guard.retain(|(id, _), _| *id != provider_id);
    }
}

/// Build a configured client for this provider from its (cached) metadata.
///
/// An empty stored secret yields a public client, which is what a provider
/// configured for PKCE-only wants.
pub fn client_from_metadata(
    provider: &OidcProvider,
    metadata: IpProviderMetadata,
) -> IpClientReady {
    let secret = (!provider.client_secret.is_empty())
        .then(|| ClientSecret::new(provider.client_secret.clone()));
    IpClient::from_provider_metadata(metadata, ClientId::new(provider.client_id.clone()), secret)
}

/// The client shape [`IpClient::from_provider_metadata`] produces: the
/// authorization endpoint is always present, and the token and user-info
/// endpoints are present only if the provider published them.
pub type IpClientReady = IpClient<
    openidconnect::EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

// --------------------------------------------------------------------------
// Shared helpers
// --------------------------------------------------------------------------

/// The redirect URI this deployment presents for a provider.
///
/// Must match what is registered at the IdP byte for byte, so it is derived
/// from configuration rather than from the incoming request wherever possible:
/// a `Host` header is attacker-controlled, and letting it shape the redirect
/// URI would be a way to steal authorization codes. The admin UI displays the
/// computed value so an operator can paste it into their provider.
#[must_use]
pub fn redirect_uri(public_origin: &str, slug: &str) -> String {
    format!(
        "{}/api/v1/auth/oidc/{slug}/callback",
        public_origin.trim_end_matches('/')
    )
}

/// Sanitise a post-login landing path.
///
/// Only app-relative paths survive. Anything carrying a scheme, an authority
/// (`//evil.example`), or a backslash (which some clients normalise to `/`)
/// falls back to `/`. Without this the login flow would be an open redirect,
/// and an open redirect on an authentication endpoint is a phishing primitive.
#[must_use]
pub fn safe_redirect_to(raw: Option<&str>) -> String {
    let candidate = raw.unwrap_or("/").trim();
    let ok = candidate.starts_with('/')
        && !candidate.starts_with("//")
        && !candidate.contains('\\')
        && !candidate.contains("://")
        && candidate.len() <= 512;
    if ok {
        candidate.to_owned()
    } else {
        "/".to_owned()
    }
}

/// Read a claim that the provider's configuration names, as a string.
#[must_use]
pub fn string_claim(claims: &ExtraClaims, name: &str) -> Option<String> {
    match claims.other.get(name)? {
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// Read the configured group claim as a list of names.
///
/// Accepts both shapes seen in the wild: a JSON array of strings (what
/// Authentik and Keycloak emit) and a single space-separated string.
#[must_use]
pub fn group_claim(claims: &ExtraClaims, name: &str) -> Vec<String> {
    match claims.other.get(name) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        Some(serde_json::Value::String(s)) => s.split_whitespace().map(str::to_owned).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_to_rejects_anything_not_app_relative() {
        assert_eq!(safe_redirect_to(Some("/projects/42")), "/projects/42");
        assert_eq!(safe_redirect_to(None), "/");
        // Protocol-relative: the browser would treat this as another origin.
        assert_eq!(safe_redirect_to(Some("//evil.example/")), "/");
        assert_eq!(safe_redirect_to(Some("https://evil.example")), "/");
        assert_eq!(safe_redirect_to(Some("javascript:alert(1)")), "/");
        assert_eq!(safe_redirect_to(Some("/\\evil.example")), "/");
        assert_eq!(safe_redirect_to(Some("no-leading-slash")), "/");
    }

    #[test]
    fn redirect_uri_is_stable_and_slash_tolerant() {
        assert_eq!(
            redirect_uri("https://pilot.example.com", "authentik"),
            "https://pilot.example.com/api/v1/auth/oidc/authentik/callback"
        );
        assert_eq!(
            redirect_uri("https://pilot.example.com/", "authentik"),
            "https://pilot.example.com/api/v1/auth/oidc/authentik/callback"
        );
    }

    #[test]
    fn group_claim_accepts_array_and_space_separated_forms() {
        let mut claims = ExtraClaims::default();
        claims.other.insert(
            "groups".to_owned(),
            serde_json::json!(["admins", "everyone"]),
        );
        assert_eq!(group_claim(&claims, "groups"), vec!["admins", "everyone"]);

        let mut claims = ExtraClaims::default();
        claims
            .other
            .insert("groups".to_owned(), serde_json::json!("admins everyone"));
        assert_eq!(group_claim(&claims, "groups"), vec!["admins", "everyone"]);

        assert_eq!(
            group_claim(&ExtraClaims::default(), "groups"),
            Vec::<String>::new()
        );
    }
}
