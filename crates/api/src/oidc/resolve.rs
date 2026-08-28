//! Turning verified ID-token claims into an IntelliPilot user.
//!
//! Every flow — browser redirect, device code, self-service link — funnels
//! through here, so the rules about who may sign in exist in exactly one place.
//!
//! # The rule
//!
//! A sign-in resolves on `(provider, subject)`. If that binding exists, it *is*
//! the answer, regardless of what email the token carries. If it does not:
//!
//!   1. an admin-armed linking window on an account with this *verified* email
//!      binds the subject there (the rescue route for someone who can no longer
//!      sign in);
//!   2. otherwise, an existing account with this email is a hard refusal, not
//!      a link — auto-linking on email is how an IdP that can assert any
//!      address takes over any account;
//!   3. otherwise, JIT provisioning creates a new account, if the provider
//!      allows it.
//!
//! Unlike the LDAP path, nothing here re-enables a deactivated account: see
//! `intellipilot_db::users::find_or_link_ldap_user`, whose `is_active = true`
//! on every login silently undoes a deactivation.

use serde_json::json;
use uuid::Uuid;

use intellipilot_db::oidc_providers::OidcProvider;
use intellipilot_db::{audit, oidc_identities, users};

use super::{ExtraClaims, IpIdTokenClaims, group_claim, string_claim};

/// What a verified token told us about the person signing in.
#[derive(Debug, Clone)]
pub struct IdentityFacts {
    /// The issuer, taken from the *verified* token, not from configuration.
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub username_hint: String,
    pub display_name: String,
    pub groups: Vec<String>,
}

/// Why a resolution was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No email claim, or the provider asserted it is unverified while the
    /// configuration requires verification.
    EmailUnverified,
    /// An account already holds this address. Deliberately not linked: the
    /// user is told to sign in normally and connect from their Security page.
    EmailConflict,
    /// Nobody holds this subject and the provider may not create accounts.
    ProvisioningDisabled,
    /// This subject is already bound to a different account.
    SubjectTaken,
    /// The account exists but may not authenticate.
    Banned,
    Inactive,
    /// The token carried nothing usable as an account identity.
    InsufficientClaims,
    Db,
}

/// Pull the facts we need out of verified claims, honouring the provider's
/// claim-name configuration.
///
/// `issuer` comes from the claims, which the verifier has already checked
/// against the discovery document — so it is the provider's asserted identity,
/// not the possibly-since-edited `issuer_url` column.
#[must_use]
pub fn facts_from_claims(provider: &OidcProvider, claims: &IpIdTokenClaims) -> IdentityFacts {
    let extra: &ExtraClaims = claims.additional_claims();

    // Standard claims first; the configured names are consulted only when the
    // provider puts the value somewhere non-standard.
    let email = claims
        .email()
        .map(|e| e.as_str().to_owned())
        .or_else(|| string_claim(extra, &provider.claim_email))
        .unwrap_or_default();

    let display_name = claims
        .name()
        .and_then(|n| n.get(None).map(|v| v.as_str().to_owned()))
        .or_else(|| string_claim(extra, &provider.claim_display_name))
        .unwrap_or_default();

    let username_hint = claims
        .preferred_username()
        .map(|u| u.as_str().to_owned())
        .or_else(|| string_claim(extra, &provider.claim_username))
        .unwrap_or_else(|| {
            // Local part of the email is the last resort; `free_username`
            // deduplicates whatever it is given.
            email.split('@').next().unwrap_or("user").to_owned()
        });

    IdentityFacts {
        issuer: claims.issuer().as_str().to_owned(),
        subject: claims.subject().as_str().to_owned(),
        email: email.trim().to_lowercase(),
        // Absent means "not asserted", which is not the same as verified.
        email_verified: claims.email_verified().unwrap_or(false),
        username_hint,
        display_name,
        groups: group_claim(extra, &provider.claim_groups),
    }
}

/// Whether the provider's superadmin group is among the token's groups.
///
/// Case-insensitive exact match on a group name. Deliberately not a
/// substring or suffix match: `admins` must not be satisfied by
/// `not-really-admins`.
#[must_use]
pub fn grants_superadmin(provider: &OidcProvider, facts: &IdentityFacts) -> Option<bool> {
    if provider.superadmin_group.trim().is_empty() {
        // Mapping disabled — `is_superadmin` stays managed inside IntelliPilot.
        return None;
    }
    Some(facts.groups.iter().any(|g| {
        g.trim()
            .eq_ignore_ascii_case(provider.superadmin_group.trim())
    }))
}

/// Resolve a sign-in to a user id, provisioning or refusing per the rules above.
pub async fn resolve_login(
    client: &deadpool_postgres::Client,
    provider: &OidcProvider,
    facts: &IdentityFacts,
) -> Result<Uuid, ResolveError> {
    if facts.subject.trim().is_empty() {
        return Err(ResolveError::InsufficientClaims);
    }

    // 1. The authenticating lookup.
    match oidc_identities::find_by_subject(client, provider.id, &facts.subject).await {
        Ok(Some(identity)) => {
            oidc_identities::stamp_login(client, identity.id).await;
            if let Err(e) =
                users::sync_oidc_display_name(client, identity.user_id, &facts.display_name).await
            {
                tracing::warn!(error = %e, "failed to sync display name from provider");
            }
            return Ok(identity.user_id);
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "oidc identity lookup failed");
            return Err(ResolveError::Db);
        }
    }

    // Everything below needs a usable address, either to match an armed link
    // or to seed a new account.
    if facts.email.is_empty() {
        return Err(ResolveError::InsufficientClaims);
    }
    if provider.require_email_verified && !facts.email_verified {
        return Err(ResolveError::EmailUnverified);
    }

    // 2. Admin-armed rescue link.
    match users::find_armed_link_by_email(client, &facts.email).await {
        Ok(Some(user)) => {
            link_subject(client, provider, facts, user.id).await?;
            // One-shot: close the window whether or not the user signs in again.
            if let Err(e) = users::set_oidc_link_arm(client, user.id, None).await {
                tracing::warn!(error = %e, "failed to close oidc link window");
            }
            audit::record(
                client,
                Some(user.id),
                "oidc_identity_linked",
                None,
                None,
                &json!({ "provider": provider.slug, "via": "admin_armed" }),
            )
            .await;
            return Ok(user.id);
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "armed-link lookup failed");
            return Err(ResolveError::Db);
        }
    }

    // 3. An existing account with this address is refused, never linked.
    match users::find_by_email_basic(client, &facts.email).await {
        Ok(Some(_)) => return Err(ResolveError::EmailConflict),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "email collision check failed");
            return Err(ResolveError::Db);
        }
    }

    // 4. Just-in-time provisioning.
    if !provider.allow_jit_provisioning {
        return Err(ResolveError::ProvisioningDisabled);
    }
    // A brand-new account is created with the group mapping already applied, so
    // a first sign-in by a directory admin does not need a second round trip.
    let superadmin = grants_superadmin(provider, facts).unwrap_or(false);
    let user = match users::provision_oidc_user(
        client,
        &facts.email,
        &facts.username_hint,
        &facts.display_name,
        superadmin,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "oidc provisioning failed");
            return Err(ResolveError::Db);
        }
    };
    link_subject(client, provider, facts, user.id).await?;
    audit::record(
        client,
        Some(user.id),
        "oidc_user_provisioned",
        None,
        None,
        &json!({ "provider": provider.slug, "is_superadmin": superadmin }),
    )
    .await;
    Ok(user.id)
}

/// Bind a subject to a user, mapping a duplicate onto [`ResolveError::SubjectTaken`].
pub async fn link_subject(
    client: &deadpool_postgres::Client,
    provider: &OidcProvider,
    facts: &IdentityFacts,
    user_id: Uuid,
) -> Result<(), ResolveError> {
    match oidc_identities::link(
        client,
        user_id,
        provider.id,
        &facts.issuer,
        &facts.subject,
        &facts.email,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(e) if e.is_unique_violation() => Err(ResolveError::SubjectTaken),
        Err(e) => {
            tracing::error!(error = %e, "oidc identity link failed");
            Err(ResolveError::Db)
        }
    }
}

/// Apply the provider's group → superadmin mapping to an existing user.
///
/// Both directions, as configured: membership promotes, absence demotes. The
/// demotion runs through [`users::set_superadmin`], which already refuses to
/// remove the last active superadmin — so a provider that stops emitting the
/// group, or an admin who mistypes its name, cannot lock everyone out of the
/// admin area. Never fails a sign-in: a mapping problem is logged and audited,
/// not turned into a login error.
pub async fn sync_superadmin(
    client: &mut deadpool_postgres::Client,
    provider: &OidcProvider,
    facts: &IdentityFacts,
    user_id: Uuid,
) {
    let Some(desired) = grants_superadmin(provider, facts) else {
        return;
    };
    let current = match users::find_by_id(client, user_id).await {
        Ok(Some(u)) => u.is_superadmin,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, "superadmin sync: user lookup failed");
            return;
        }
    };
    if current == desired {
        return;
    }
    match users::set_superadmin(client, user_id, desired).await {
        Ok(users::AdminUpdateOutcome::Updated) => {
            audit::record(
                client,
                Some(user_id),
                "oidc_superadmin_synced",
                None,
                None,
                &json!({
                    "provider": provider.slug,
                    "group": provider.superadmin_group,
                    "is_superadmin": desired,
                }),
            )
            .await;
        }
        Ok(users::AdminUpdateOutcome::LastSuperadmin) => {
            // The invariant won. Worth an audit entry: from the operator's
            // seat this looks like "the directory says demote and nothing
            // happened", and they need to see why.
            tracing::warn!(
                user_id = %user_id,
                "refused to demote the last superadmin on provider group sync"
            );
            audit::record(
                client,
                Some(user_id),
                "oidc_superadmin_sync_refused",
                None,
                None,
                &json!({ "provider": provider.slug, "reason": "last_superadmin" }),
            )
            .await;
        }
        Ok(users::AdminUpdateOutcome::NotFound) => {}
        Err(e) => tracing::warn!(error = %e, "superadmin sync failed"),
    }
}

/// Whether this account may authenticate at all.
///
/// The same two checks the LDAP path runs, in the same order, and for the same
/// reason: a ban lives in `banned_at` and a deactivation in `is_active`, and
/// neither is implied by the other.
pub async fn check_account_usable(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<(), ResolveError> {
    if users::is_banned(client, user_id).await.unwrap_or(false) {
        return Err(ResolveError::Banned);
    }
    match users::find_by_id(client, user_id).await {
        Ok(Some(u)) if u.is_active => Ok(()),
        Ok(Some(_)) => Err(ResolveError::Inactive),
        Ok(None) => Err(ResolveError::Db),
        Err(e) => {
            tracing::error!(error = %e, "account status check failed");
            Err(ResolveError::Db)
        }
    }
}
