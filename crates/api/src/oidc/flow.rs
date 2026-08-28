//! The browser redirect flow: authorization code with PKCE.
//!
//! Used by the web client. `start` produces the URL to send the browser to and
//! the three secrets that must stay server-side (`state`, `nonce`,
//! `code_verifier`); `exchange` redeems the returned code and hands back
//! *verified* claims.
//!
//! Nothing in this module trusts the query string beyond the code itself: the
//! `state` is matched against a single-use database row before we get here, the
//! `nonce` is checked inside the ID-token verifier, and the PKCE verifier
//! proves the redemption comes from whoever started the flow.

use openidconnect::core::CoreResponseType;
use openidconnect::{
    AccessTokenHash, AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};

use intellipilot_db::oidc_providers::OidcProvider;

use super::{IpIdTokenClaims, OidcCache, OidcError, client_from_metadata, http_client};

/// The URL to redirect to, plus the secrets to store against the `state`.
#[derive(Debug, Clone)]
pub struct StartedFlow {
    pub authorize_url: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
}

/// Build an authorization request.
///
/// PKCE is unconditional. The provider may well be a confidential client with
/// a secret, but PKCE additionally binds the redemption to this specific
/// request, which is what stops a leaked authorization code (browser history,
/// a referrer header, a shared machine) from being replayed by anyone else.
pub async fn start(
    cache: &OidcCache,
    provider: &OidcProvider,
    redirect_uri: &str,
) -> Result<StartedFlow, OidcError> {
    let metadata = cache.metadata(provider).await?;
    let client = client_from_metadata(provider, metadata).set_redirect_uri(
        RedirectUrl::new(redirect_uri.to_owned())
            .map_err(|e| OidcError::Config(format!("invalid redirect URI: {e}")))?,
    );

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    // `openid` is added by the library; the rest come from configuration.
    for scope in provider.scope_list() {
        if scope != "openid" {
            request = request.add_scope(Scope::new(scope));
        }
    }
    let (url, state, nonce) = request.url();

    Ok(StartedFlow {
        authorize_url: url.to_string(),
        state: state.secret().clone(),
        nonce: nonce.secret().clone(),
        code_verifier: verifier.secret().clone(),
    })
}

/// Redeem an authorization code and return verified ID-token claims.
///
/// The verification the library performs here is the whole point of using it:
/// signature against the discovered JWKS, `iss` against the discovery
/// document, `aud` against our client id, expiry, and the `nonce` we generated.
/// The access-token hash is checked too when the provider supplies one, which
/// catches a token substituted between the two halves of the response.
pub async fn exchange(
    cache: &OidcCache,
    provider: &OidcProvider,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
    nonce: &str,
) -> Result<IpIdTokenClaims, OidcError> {
    let metadata = cache.metadata(provider).await?;
    let client = client_from_metadata(provider, metadata).set_redirect_uri(
        RedirectUrl::new(redirect_uri.to_owned())
            .map_err(|e| OidcError::Config(format!("invalid redirect URI: {e}")))?,
    );
    let http = http_client(provider)?;

    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .map_err(|e| OidcError::Config(format!("token endpoint not configured: {e}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(code_verifier.to_owned()))
        .request_async(&http)
        .await
        .map_err(|e| OidcError::Rejected(format!("code exchange failed: {e}")))?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| OidcError::Rejected("provider returned no ID token".to_owned()))?;

    let verifier = client.id_token_verifier();
    let expected_nonce = Nonce::new(nonce.to_owned());
    let claims = id_token
        .claims(&verifier, &expected_nonce)
        .map_err(|e| OidcError::Rejected(format!("ID token verification failed: {e}")))?;

    if let Some(expected) = claims.access_token_hash() {
        let signing_alg = id_token
            .signing_alg()
            .map_err(|e| OidcError::Rejected(format!("unsupported ID token signature: {e}")))?;
        let actual = AccessTokenHash::from_token(
            token_response.access_token(),
            signing_alg,
            id_token
                .signing_key(&verifier)
                .map_err(|e| OidcError::Rejected(format!("could not resolve signing key: {e}")))?,
        )
        .map_err(|e| OidcError::Rejected(format!("access token hash failed: {e}")))?;
        if actual != *expected {
            return Err(OidcError::Rejected("access token hash mismatch".to_owned()));
        }
    }

    Ok(claims.clone())
}
