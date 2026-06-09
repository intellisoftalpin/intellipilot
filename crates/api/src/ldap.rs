//! LDAP / directory authentication.
//!
//! Mirrors the reference implementation: a **direct bind** as the logging-in
//! user (over optional StartTLS), then a search of the user's own entry for
//! provisioning attributes and group membership. No service account is used.
//!
//! The authenticator is behind a trait so the login handler is testable with a
//! fake (a live directory can't run in CI).

use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

/// Connection + search configuration, mapped from the stored `ldap_settings`.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub server_url: String,
    pub use_start_tls: bool,
    pub skip_tls_verify: bool,
    pub base_dn: String,
    pub default_domain: String,
    pub bind_dn_format: String,
    pub user_search_filter: String,
    pub superadmin_group: String,
    pub attr_email: String,
    pub attr_display_name: String,
    pub attr_username: String,
    pub connection_timeout_secs: i32,
}

impl From<&intellipilot_db::ldap_settings::LdapSettings> for LdapConfig {
    fn from(s: &intellipilot_db::ldap_settings::LdapSettings) -> Self {
        Self {
            server_url: s.server_url.clone(),
            use_start_tls: s.use_start_tls,
            skip_tls_verify: s.skip_tls_verify,
            base_dn: s.base_dn.clone(),
            default_domain: s.default_domain.clone(),
            bind_dn_format: s.bind_dn_format.clone(),
            user_search_filter: s.user_search_filter.clone(),
            superadmin_group: s.superadmin_group.clone(),
            attr_email: s.attr_email.clone(),
            attr_display_name: s.attr_display_name.clone(),
            attr_username: s.attr_username.clone(),
            connection_timeout_secs: s.connection_timeout_secs,
        }
    }
}

/// What we resolve about a user after a successful bind.
#[derive(Debug, Clone)]
pub struct LdapUser {
    pub email: String,
    pub username: String,
    pub display_name: String,
    pub dn: Option<String>,
    pub is_superadmin: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("directory unavailable: {0}")]
    Unavailable(String),
    #[error("misconfigured: {0}")]
    Config(String),
}

#[async_trait::async_trait]
pub trait LdapAuthenticator: Send + Sync {
    /// Validate `identifier`/`password` against the directory and resolve the
    /// user. `InvalidCredentials` on a failed bind; `Unavailable`/`Config` for
    /// operational problems.
    async fn authenticate(&self, identifier: &str, password: &str) -> Result<LdapUser, LdapError>;
}

/// Real `ldap3`-backed authenticator.
#[derive(Debug)]
pub struct RealLdap {
    cfg: LdapConfig,
}

impl RealLdap {
    #[must_use]
    pub const fn new(cfg: LdapConfig) -> Self {
        Self { cfg }
    }

    /// Form a UPN from a bare login name by appending the default domain.
    fn upn(&self, identifier: &str) -> String {
        if identifier.contains('@') || self.cfg.default_domain.is_empty() {
            identifier.to_owned()
        } else {
            format!("{identifier}@{}", self.cfg.default_domain)
        }
    }

    fn local_part(identifier: &str) -> &str {
        identifier.split('@').next().unwrap_or(identifier)
    }
}

#[async_trait::async_trait]
impl LdapAuthenticator for RealLdap {
    // Several attributes are late-initialized from the optional search and then
    // refined by fallbacks — a single let-binding doesn't fit cleanly.
    #[allow(clippy::useless_let_if_seq)]
    async fn authenticate(&self, identifier: &str, password: &str) -> Result<LdapUser, LdapError> {
        // An empty password yields an unauthenticated (anonymous) bind that
        // many servers accept — always reject it.
        if password.is_empty() {
            return Err(LdapError::InvalidCredentials);
        }
        if self.cfg.server_url.is_empty() {
            return Err(LdapError::Config("server_url is empty".to_owned()));
        }

        let timeout = Duration::from_secs(
            u64::try_from(self.cfg.connection_timeout_secs.max(1)).unwrap_or(10),
        );
        let settings = LdapConnSettings::new()
            .set_starttls(self.cfg.use_start_tls)
            .set_no_tls_verify(self.cfg.skip_tls_verify)
            .set_conn_timeout(timeout);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.cfg.server_url)
            .await
            .map_err(|e| LdapError::Unavailable(e.to_string()))?;
        ldap3::drive!(conn);

        let upn = self.upn(identifier);
        let bind_dn = self.cfg.bind_dn_format.replace("%s", &upn);

        // Direct bind as the user — a failed bind means bad credentials.
        ldap.simple_bind(&bind_dn, password)
            .await
            .map_err(|e| LdapError::Unavailable(e.to_string()))?
            .success()
            .map_err(|_| LdapError::InvalidCredentials)?;

        // Search the user's entry on the authenticated connection for
        // provisioning attributes + groups.
        let local = ldap3::ldap_escape(Self::local_part(identifier)).into_owned();
        let filter = self.cfg.user_search_filter.replace("%s", &local);
        let attrs = vec![
            self.cfg.attr_email.as_str(),
            self.cfg.attr_display_name.as_str(),
            self.cfg.attr_username.as_str(),
            "userPrincipalName",
            "cn",
            "memberOf",
        ];

        let mut email = String::new();
        let mut display_name = String::new();
        let mut username = String::new();
        let mut dn = None;
        let mut groups: Vec<String> = Vec::new();

        if !self.cfg.base_dn.is_empty()
            && let Ok(res) = ldap
                .search(&self.cfg.base_dn, Scope::Subtree, &filter, attrs)
                .await
            && let Ok((entries, _)) = res.success()
            && let Some(entry) = entries.into_iter().next()
        {
            let se = SearchEntry::construct(entry);
            dn = Some(se.dn.clone());
            email = first(&se, &self.cfg.attr_email)
                .or_else(|| first(&se, "userPrincipalName"))
                .unwrap_or_default();
            display_name = first(&se, &self.cfg.attr_display_name)
                .or_else(|| first(&se, "cn"))
                .unwrap_or_default();
            username = first(&se, &self.cfg.attr_username).unwrap_or_default();
            groups = se.attrs.get("memberOf").cloned().unwrap_or_default();
        }
        if let Err(e) = ldap.unbind().await {
            tracing::debug!("ldap unbind failed: {e}");
        }

        // Fallbacks mirroring the reference app when the search returns little.
        if email.is_empty() {
            email = if identifier.contains('@') {
                identifier.to_owned()
            } else {
                upn
            };
        }
        if username.is_empty() {
            username = Self::local_part(identifier).to_owned();
        }
        if display_name.is_empty() {
            display_name.clone_from(&username);
        }

        let is_superadmin = !self.cfg.superadmin_group.is_empty()
            && groups
                .iter()
                .any(|g| group_matches(g, &self.cfg.superadmin_group));

        Ok(LdapUser {
            email,
            username,
            display_name,
            dn,
            is_superadmin,
        })
    }
}

fn first(se: &SearchEntry, attr: &str) -> Option<String> {
    se.attrs
        .get(attr)
        .and_then(|v| v.first())
        .filter(|s| !s.is_empty())
        .cloned()
}

/// Match a `memberOf` DN against a configured group given as either a full DN
/// or a bare CN. Case-insensitive (group names aren't case-sensitive in AD).
fn group_matches(member_of: &str, configured: &str) -> bool {
    let configured = configured.trim();
    if configured.is_empty() {
        return false;
    }
    if member_of.eq_ignore_ascii_case(configured) {
        return true;
    }
    let cn = member_of
        .split(',')
        .next()
        .and_then(|rdn| rdn.split_once('='))
        .map_or(member_of, |(_, v)| v);
    cn.eq_ignore_ascii_case(configured)
}

#[cfg(test)]
mod tests {
    use super::group_matches;

    #[test]
    fn group_matches_cn_and_dn() {
        let dn = "CN=IntelliPilot Admins,OU=Groups,DC=example,DC=com";
        assert!(group_matches(dn, "IntelliPilot Admins"));
        assert!(group_matches(dn, "intellipilot admins"));
        assert!(group_matches(dn, dn));
        assert!(!group_matches(dn, "Other Group"));
        assert!(!group_matches(dn, ""));
    }
}
