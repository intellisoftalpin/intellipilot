//! Minimal git remote integration over SSH, backed by libgit2 (`git2`).
//!
//! The only operation needed today is listing a remote's branches (the basis
//! for the branch picker and for the on-add reachability check). The decrypted
//! private key is supplied **in-memory** (`Cred::ssh_key_from_memory`) so it
//! never touches disk.
//!
//! libgit2 calls are blocking, so the public API wraps them in
//! [`tokio::task::spawn_blocking`], bounds concurrency with a process-wide
//! semaphore, and enforces a hard timeout. This crate is intentionally the
//! single home for git/network concerns, ready to grow a `clone`/`analyze`
//! surface later.

#![allow(clippy::result_large_err)]

use std::cell::RefCell;
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine as _;
use git2::{CertificateCheckStatus, Cred, CredentialType, Direction, RemoteCallbacks};
use thiserror::Error;
use tokio::sync::Semaphore;

/// Cap on concurrent blocking git network operations. User-triggered branch
/// fetches fan out, so this protects the blocking thread pool from abuse.
const MAX_CONCURRENT_GIT_OPS: usize = 4;
/// Hard timeout for a single remote operation.
const GIT_OP_TIMEOUT: Duration = Duration::from_secs(15);

fn semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(MAX_CONCURRENT_GIT_OPS))
}

/// A classified git failure. The API layer maps these onto problem+json.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GitError {
    #[error("authentication failed")]
    AuthFailed,
    #[error("repository not found")]
    NotFound,
    #[error("host unreachable")]
    Unreachable,
    #[error("operation timed out")]
    Timeout,
    #[error("internal git error")]
    Internal,
}

impl GitError {
    /// Stable wire code used in problem+json responses.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthFailed => "git_auth_failed",
            Self::NotFound => "git_not_found",
            Self::Unreachable => "git_unreachable",
            Self::Timeout => "git_timeout",
            Self::Internal => "git_internal",
        }
    }
}

/// Result of inspecting a remote.
#[derive(Debug, Clone, Default)]
pub struct RemoteInfo {
    /// Branch short names (no `refs/heads/` prefix), sorted and de-duplicated.
    pub branches: Vec<String>,
    /// The remote's default branch short name, if advertised.
    pub default_branch: Option<String>,
    /// SHA256 host-key fingerprint (`SHA256:...`) captured on connect, for
    /// display / TOFU verification.
    pub host_fingerprint: Option<String>,
}

fn map_git_err(e: &git2::Error) -> GitError {
    use git2::ErrorClass as Class;
    use git2::ErrorCode as Code;

    if e.code() == Code::Auth {
        return GitError::AuthFailed;
    }
    match e.class() {
        Class::Ssh => GitError::AuthFailed,
        Class::Net => GitError::Unreachable,
        _ => {
            let m = e.message().to_lowercase();
            if m.contains("not found")
                || m.contains("does not exist")
                || m.contains("repository not found")
                || m.contains("access denied")
                || m.contains("err access")
            {
                GitError::NotFound
            } else if m.contains("authentication") || m.contains("auth") || m.contains("publickey")
            {
                GitError::AuthFailed
            } else if m.contains("resolve")
                || m.contains("connect")
                || m.contains("timed out")
                || m.contains("network")
            {
                GitError::Unreachable
            } else {
                GitError::Internal
            }
        }
    }
}

fn strip_head_ref(name: &str) -> String {
    name.strip_prefix("refs/heads/").unwrap_or(name).to_owned()
}

fn list_blocking(ssh_url: &str, private_key_pem: &str) -> Result<RemoteInfo, GitError> {
    let host_fp: RefCell<Option<String>> = RefCell::new(None);

    let mut cb = RemoteCallbacks::new();
    cb.credentials(move |_url, username_from_url, allowed| {
        let user = username_from_url.unwrap_or("git");
        if allowed.contains(CredentialType::SSH_KEY) {
            Cred::ssh_key_from_memory(user, None, private_key_pem, None)
        } else if allowed.contains(CredentialType::USERNAME) {
            Cred::username(user)
        } else {
            Err(git2::Error::from_str("no supported authentication method"))
        }
    });
    cb.certificate_check(|cert, _host| {
        // TOFU: capture the host fingerprint for display; accept the host so a
        // first connection succeeds. Pinning can build on the captured value.
        if let Some(hash) = cert
            .as_hostkey()
            .and_then(git2::cert::CertHostkey::hash_sha256)
        {
            let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);
            *host_fp.borrow_mut() = Some(format!("SHA256:{b64}"));
        }
        Ok(CertificateCheckStatus::CertificateOk)
    });

    let mut remote = git2::Remote::create_detached(ssh_url).map_err(|e| map_git_err(&e))?;
    // `connect_auth` returns a connection guard that disconnects on drop.
    let conn = remote
        .connect_auth(Direction::Fetch, Some(cb), None)
        .map_err(|e| map_git_err(&e))?;

    let default_branch = conn
        .default_branch()
        .ok()
        .and_then(|buf| buf.as_str().ok().map(strip_head_ref));

    let mut branches: Vec<String> = conn
        .list()
        .map_err(|e| map_git_err(&e))?
        .iter()
        .filter_map(|head| {
            head.name()
                .strip_prefix("refs/heads/")
                .map(ToOwned::to_owned)
        })
        .collect();
    drop(conn);

    branches.sort();
    branches.dedup();

    Ok(RemoteInfo {
        branches,
        default_branch,
        host_fingerprint: host_fp.into_inner(),
    })
}

/// List the branches of a remote reachable at `ssh_url`, authenticating with
/// the in-memory OpenSSH `private_key_pem`. Doubles as a reachability /
/// authorization check (success ⇒ reachable and authorized).
pub async fn list_remote_branches(
    ssh_url: String,
    private_key_pem: String,
) -> Result<RemoteInfo, GitError> {
    let _permit = semaphore()
        .acquire()
        .await
        .map_err(|_| GitError::Internal)?;
    let task = tokio::task::spawn_blocking(move || list_blocking(&ssh_url, &private_key_pem));
    match tokio::time::timeout(GIT_OP_TIMEOUT, task).await {
        Ok(Ok(res)) => res,
        Ok(Err(_join)) => Err(GitError::Internal),
        Err(_elapsed) => Err(GitError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn unique_tmp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ip-git-test-{tag}-{}-{n}", std::process::id()))
    }

    /// Seed a repo with two branches (`main`, `develop`) and HEAD on `main`.
    fn seed_repo(path: &std::path::Path) {
        let repo = git2::Repository::init(path).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();
        let tree_id = {
            let mut index = repo.index().unwrap();
            index.write_tree().unwrap()
        };
        let tree = repo.find_tree(tree_id).unwrap();
        let oid = repo
            .commit(Some("refs/heads/main"), &sig, &sig, "init", &tree, &[])
            .unwrap();
        let commit = repo.find_commit(oid).unwrap();
        repo.branch("develop", &commit, false).unwrap();
        repo.set_head("refs/heads/main").unwrap();
    }

    #[tokio::test]
    async fn lists_branches_of_local_repo() {
        let dir = unique_tmp_dir("ok");
        seed_repo(&dir);
        let info = list_remote_branches(dir.to_string_lossy().into_owned(), "unused".to_owned())
            .await
            .expect("local repo lists");
        assert!(info.branches.contains(&"main".to_owned()));
        assert!(info.branches.contains(&"develop".to_owned()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn missing_local_repo_errors() {
        let dir = unique_tmp_dir("missing");
        let err = list_remote_branches(dir.to_string_lossy().into_owned(), "unused".to_owned())
            .await
            .unwrap_err();
        // A non-existent path is not a successful listing.
        assert!(matches!(
            err,
            GitError::NotFound | GitError::Internal | GitError::Unreachable
        ));
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(GitError::AuthFailed.code(), "git_auth_failed");
        assert_eq!(GitError::Timeout.code(), "git_timeout");
    }
}
