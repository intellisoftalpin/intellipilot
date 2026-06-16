//! LDAP / directory authentication.
//!
//! Two bind modes:
//! - **direct** — bind as the logging-in user (`bind_dn_format`), then search
//!   the user's own entry for attributes + `memberOf`. Suits AD where the
//!   identifier maps to a bindable DN/UPN.
//! - **search** — bind as a service account, search for the user's DN, then
//!   bind as that DN to verify the password. Group membership is resolved by a
//!   reverse `(member=<userDN>)` search (with `memberOf` as a fallback). Suits
//!   OpenLDAP where the login identifier isn't the entry's RDN.
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
    /// `search` enables service-account search-then-bind; anything else is
    /// treated as `direct`.
    pub bind_mode: String,
    pub service_bind_dn: String,
    pub service_bind_password: String,
    pub user_search_base: String,
    pub group_search_base: String,
    pub group_search_filter: String,
}

impl LdapConfig {
    fn is_search_mode(&self) -> bool {
        self.bind_mode.eq_ignore_ascii_case("search")
    }

    /// Base DN for the user search — `user_search_base` if set, else `base_dn`.
    fn effective_user_base(&self) -> &str {
        if self.user_search_base.is_empty() {
            &self.base_dn
        } else {
            &self.user_search_base
        }
    }
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
            bind_mode: s.bind_mode.clone(),
            service_bind_dn: s.service_bind_dn.clone(),
            service_bind_password: s.service_bind_password.clone(),
            user_search_base: s.user_search_base.clone(),
            group_search_base: s.group_search_base.clone(),
            group_search_filter: s.group_search_filter.clone(),
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

    /// Search `base` with `filter` and pull provisioning attributes from the
    /// first matching entry. Returns `(email, display_name, username, dn,
    /// memberOf)`; the DN is `None` when nothing matched.
    #[allow(clippy::useless_let_if_seq)]
    async fn fetch_user(
        &self,
        ldap: &mut ldap3::Ldap,
        base: &str,
        filter: &str,
    ) -> (String, String, String, Option<String>, Vec<String>) {
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
        if !base.is_empty()
            && let Ok(res) = ldap.search(base, Scope::Subtree, filter, attrs).await
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
        (email, display_name, username, dn, groups)
    }

    /// Apply reference-app fallbacks for any attribute the search didn't
    /// provide, then decide superadmin from the resolved groups.
    #[allow(clippy::too_many_arguments)]
    fn build_user(
        &self,
        identifier: &str,
        upn: &str,
        email: String,
        display_name: String,
        username: String,
        dn: Option<String>,
        groups: &[String],
    ) -> LdapUser {
        let email = if email.is_empty() {
            if identifier.contains('@') {
                identifier.to_owned()
            } else {
                upn.to_owned()
            }
        } else {
            email
        };
        let username = if username.is_empty() {
            Self::local_part(identifier).to_owned()
        } else {
            username
        };
        let display_name = if display_name.is_empty() {
            username.clone()
        } else {
            display_name
        };
        let is_superadmin = !self.cfg.superadmin_group.is_empty()
            && groups
                .iter()
                .any(|g| group_matches(g, &self.cfg.superadmin_group));
        LdapUser {
            email,
            username,
            display_name,
            dn,
            is_superadmin,
        }
    }

    /// Direct bind as the user, then read their own entry for attributes and
    /// `memberOf`.
    async fn authenticate_direct(
        &self,
        ldap: &mut ldap3::Ldap,
        identifier: &str,
        password: &str,
    ) -> Result<LdapUser, LdapError> {
        let upn = self.upn(identifier);
        let bind_dn = self.cfg.bind_dn_format.replace("%s", &upn);

        // A failed bind means bad credentials.
        ldap.simple_bind(&bind_dn, password)
            .await
            .map_err(|e| LdapError::Unavailable(e.to_string()))?
            .success()
            .map_err(|_| LdapError::InvalidCredentials)?;

        let local = ldap3::ldap_escape(Self::local_part(identifier)).into_owned();
        let filter = self.cfg.user_search_filter.replace("%s", &local);
        let (email, display_name, username, dn, groups) =
            self.fetch_user(ldap, &self.cfg.base_dn, &filter).await;
        if let Err(e) = ldap.unbind().await {
            tracing::debug!("ldap unbind failed: {e}");
        }
        Ok(self.build_user(identifier, &upn, email, display_name, username, dn, &groups))
    }

    /// Service-account search-then-bind: bind as the service account, find the
    /// user's DN, resolve groups, then bind as that DN to verify the password.
    async fn authenticate_search(
        &self,
        ldap: &mut ldap3::Ldap,
        identifier: &str,
        password: &str,
    ) -> Result<LdapUser, LdapError> {
        if self.cfg.service_bind_dn.is_empty() {
            return Err(LdapError::Config("service bind DN is empty".to_owned()));
        }
        // 1) Bind as the service account to run the (privileged) searches.
        ldap.simple_bind(&self.cfg.service_bind_dn, &self.cfg.service_bind_password)
            .await
            .map_err(|e| LdapError::Unavailable(e.to_string()))?
            .success()
            .map_err(|_| LdapError::Config("service account bind failed".to_owned()))?;

        // 2) Find the user entry (filter matches the full identifier, e.g. UPN).
        let escaped = ldap3::ldap_escape(identifier).into_owned();
        let filter = self.cfg.user_search_filter.replace("%s", &escaped);
        let (email, display_name, username, dn, member_of) = self
            .fetch_user(ldap, self.cfg.effective_user_base(), &filter)
            .await;
        let Some(user_dn) = dn.clone() else {
            // No matching entry — report as bad credentials (don't disclose).
            return Err(LdapError::InvalidCredentials);
        };

        // 3) Reverse group search (with memberOf as a fallback), still bound as
        //    the service account.
        let groups = self.resolve_groups(ldap, &user_dn, member_of).await;

        // 4) Verify the password by binding as the discovered DN — done last so
        //    the privileged searches already ran under the service account.
        ldap.simple_bind(&user_dn, password)
            .await
            .map_err(|e| LdapError::Unavailable(e.to_string()))?
            .success()
            .map_err(|_| LdapError::InvalidCredentials)?;
        if let Err(e) = ldap.unbind().await {
            tracing::debug!("ldap unbind failed: {e}");
        }

        let upn = self.upn(identifier);
        Ok(self.build_user(identifier, &upn, email, display_name, username, dn, &groups))
    }

    /// Reverse group-membership search: `(member=<userDN>)` under
    /// `group_search_base`. Results (group DN + CN) are merged with any
    /// `memberOf` already collected so either source satisfies the match.
    async fn resolve_groups(
        &self,
        ldap: &mut ldap3::Ldap,
        user_dn: &str,
        mut groups: Vec<String>,
    ) -> Vec<String> {
        if self.cfg.group_search_base.is_empty() || self.cfg.group_search_filter.is_empty() {
            return groups;
        }
        let escaped = ldap3::ldap_escape(user_dn).into_owned();
        let filter = self.cfg.group_search_filter.replace("%s", &escaped);
        if let Ok(res) = ldap
            .search(
                &self.cfg.group_search_base,
                Scope::Subtree,
                &filter,
                vec!["cn"],
            )
            .await
            && let Ok((entries, _)) = res.success()
        {
            for entry in entries {
                let se = SearchEntry::construct(entry);
                // A group's own DN matches a configured DN; its cn matches a
                // bare CN — push both so `group_matches` succeeds either way.
                groups.push(se.dn.clone());
                if let Some(cn) = first(&se, "cn") {
                    groups.push(cn);
                }
            }
        }
        groups
    }
}

#[async_trait::async_trait]
impl LdapAuthenticator for RealLdap {
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

        if self.cfg.is_search_mode() {
            self.authenticate_search(&mut ldap, identifier, password)
                .await
        } else {
            self.authenticate_direct(&mut ldap, identifier, password)
                .await
        }
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
