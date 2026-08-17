//! Cached bare clones behind external documentation sources.
//!
//! Every source owns one bare repository under the cache root. Reads resolve
//! against git **tree and blob objects**, never against a working directory —
//! there is no checkout, so there is no path on disk for a request to walk
//! out of. Symlink and submodule entries are skipped rather than followed, so
//! a repository cannot use them to point at anything outside itself either.
//!
//! Clone and refresh are the same code path (`init_bare` + a forced fetch of
//! one branch), which keeps a first sync and a thousandth identical.
//!
//! All functions here are blocking; the `spawn_blocking` wrappers, the
//! process-wide concurrency semaphore and the timeouts live at the bottom of
//! the module.

use std::cell::Cell;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::Duration;

use git2::{AutotagOption, FetchOptions, ObjectType, Oid, PushOptions, Repository, Sort, Tree};

use crate::{GitError, auth_callbacks, map_git_err, semaphore};

/// Hard timeout for a clone or fetch. Generous compared with the 15s branch
/// listing: a first clone of a documentation repository transfers real data.
const SYNC_TIMEOUT: Duration = Duration::from_secs(180);
/// Hard timeout for a commit + push.
const PUSH_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard timeout for a purely local read (open + tree walk). Local IO, so this
/// only exists to bound a pathological repository.
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Most entries returned from one tree walk. A documentation repository with
/// more than this is not something the sidebar can usefully render.
const MAX_TREE_ENTRIES: usize = 20_000;
/// Deepest directory nesting walked.
const MAX_TREE_DEPTH: usize = 24;
/// How many commits `last_commit_for` walks before giving up. Bounds the cost
/// on repositories with very long histories; the footer simply goes missing.
const MAX_HISTORY_WALK: usize = 400;

/// git filemodes we refuse to treat as content.
const MODE_SYMLINK: i32 = 0o120_000;
const MODE_GITLINK: i32 = 0o160_000;
/// Filemode used when creating a file that did not exist before.
const MODE_BLOB: i32 = 0o100_644;

/// Outcome of a successful clone or fetch.
#[derive(Debug, Clone)]
pub struct SyncOutcome {
    /// Commit the branch now points at.
    pub head_commit: String,
    /// Bytes received during the transfer. Zero when the fetch was a no-op.
    pub received_bytes: u64,
    pub host_fingerprint: Option<String>,
}

/// One node of a tree walk, with repository-root-relative paths.
#[derive(Debug, Clone)]
pub struct RawEntry {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    /// Blob size in bytes; `0` for directories.
    pub size: u64,
}

/// A blob plus its identity.
#[derive(Debug, Clone)]
pub struct BlobData {
    pub oid: String,
    pub bytes: Vec<u8>,
}

/// Authorship of a commit.
#[derive(Debug, Clone)]
pub struct CommitMeta {
    pub sha: String,
    pub author_name: String,
    pub message: String,
    /// Unix timestamp, seconds.
    pub committed_at: i64,
}

/// What happened to an attempted edit.
#[derive(Debug, Clone)]
pub enum PushOutcome {
    Pushed {
        commit: String,
        blob_oid: String,
    },
    /// The file changed underneath the editor — its blob no longer matches the
    /// OID the client sent as `If-Match`.
    Conflict,
    /// The remote refused the update (protected branch, hook, non-fast-forward
    /// because the branch moved between our fetch and our push). Carries the
    /// host's own message.
    Rejected(String),
}

/// Everything needed to write one file and push it.
#[derive(Debug, Clone)]
pub struct EditRequest {
    pub repo_dir: PathBuf,
    pub ssh_url: String,
    pub branch: String,
    /// Writable key belonging to the person making the edit.
    pub private_key_pem: String,
    /// Repository-root-relative path of the file, already jail-resolved.
    pub repo_path: String,
    pub content: Vec<u8>,
    /// Blob OID the editor started from. `None` creates a new file, which
    /// fails with [`PushOutcome::Conflict`] if one already exists.
    pub expected_blob_oid: Option<String>,
    pub author_name: String,
    pub author_email: String,
    pub message: String,
}

// --- validation ----------------------------------------------------------

/// Branch names are interpolated into refspecs, so they are validated rather
/// than escaped. This is deliberately stricter than git itself: documentation
/// branches are ordinary names.
#[must_use]
pub fn valid_branch_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('-')
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !Path::new(name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("lock"))
        && !name.contains("..")
        && !name.contains("//")
        && !name.contains("@{")
        && name.chars().all(|c| {
            !c.is_control()
                && !c.is_whitespace()
                && !matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\' | '\x7f')
        })
}

fn check_branch(branch: &str) -> Result<(), GitError> {
    if valid_branch_name(branch) {
        Ok(())
    } else {
        Err(GitError::InvalidBranch)
    }
}

// --- blocking implementations --------------------------------------------

/// Open the cache, re-initialising it if it is missing or unusable. A
/// corrupted cache is a recoverable condition: we own the directory entirely,
/// so wiping and re-cloning is always safe.
fn open_or_init(dir: &Path) -> Result<Repository, GitError> {
    if let Ok(repo) = Repository::open_bare(dir) {
        return Ok(repo);
    }
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|_| GitError::Internal)?;
    }
    std::fs::create_dir_all(dir).map_err(|_| GitError::Internal)?;
    Repository::init_bare(dir).map_err(|e| map_git_err(&e))
}

fn sync_blocking(
    dir: &Path,
    ssh_url: &str,
    branch: &str,
    private_key_pem: &str,
    max_bytes: u64,
) -> Result<SyncOutcome, GitError> {
    check_branch(branch)?;
    let repo = open_or_init(dir)?;

    let host_fp: RefCell<Option<String>> = RefCell::new(None);
    let received = Cell::new(0_u64);
    let over_cap = Cell::new(false);

    let mut cb = auth_callbacks(private_key_pem, &host_fp);
    cb.transfer_progress(|stats| {
        let bytes = stats.received_bytes() as u64;
        received.set(bytes);
        if bytes > max_bytes {
            over_cap.set(true);
            // Returning false aborts the transfer mid-stream, so an oversized
            // repository never lands on disk in full.
            return false;
        }
        true
    });

    let mut opts = FetchOptions::new();
    opts.remote_callbacks(cb);
    // Tags can dwarf a documentation repository and we never read them.
    opts.download_tags(AutotagOption::None);

    // Force-update exactly one local branch ref. Anonymous remote: nothing is
    // written to the repository config, so the cache stays disposable.
    let refspec = format!("+refs/heads/{branch}:refs/heads/{branch}");
    let mut remote = repo
        .remote_anonymous(ssh_url)
        .map_err(|e| map_git_err(&e))?;
    let fetch = remote.fetch(&[refspec.as_str()], Some(&mut opts), None);
    drop(remote);
    // Releases the callbacks' borrow of `host_fp` so it can be moved out below.
    drop(opts);
    let host_fingerprint = host_fp.into_inner();

    if let Err(e) = fetch {
        // The abort we triggered ourselves surfaces as a generic error; report
        // the real reason.
        return Err(if over_cap.get() {
            GitError::TooLarge
        } else {
            map_git_err(&e)
        });
    }
    if over_cap.get() {
        return Err(GitError::TooLarge);
    }

    let head = repo
        .find_reference(&format!("refs/heads/{branch}"))
        .map_err(|_| GitError::NotFound)?
        .peel_to_commit()
        .map_err(|e| map_git_err(&e))?
        .id()
        .to_string();

    // A sensible HEAD makes the cache inspectable by hand during support.
    drop(repo.set_head(&format!("refs/heads/{branch}")));

    Ok(SyncOutcome {
        head_commit: head,
        received_bytes: received.get(),
        host_fingerprint,
    })
}

/// Resolve the tree of `branch`, then descend into `jail` if one is set.
/// Returns `None` when the jail path does not exist in the repository — a
/// misconfigured source, reported as such rather than silently showing the
/// whole repository.
fn jail_tree<'r>(
    repo: &'r Repository,
    branch: &str,
    jail: &str,
) -> Result<Option<(Tree<'r>, String)>, GitError> {
    let commit = repo
        .find_reference(&format!("refs/heads/{branch}"))
        .map_err(|_| GitError::NotFound)?
        .peel_to_commit()
        .map_err(|e| map_git_err(&e))?;
    let sha = commit.id().to_string();
    let root = commit.tree().map_err(|e| map_git_err(&e))?;
    if jail.is_empty() {
        return Ok(Some((root, sha)));
    }
    let Ok(entry) = root.get_path(Path::new(jail)) else {
        return Ok(None);
    };
    if entry.kind() != Some(ObjectType::Tree) {
        return Ok(None);
    }
    let obj = entry.to_object(repo).map_err(|e| map_git_err(&e))?;
    let tree = obj.into_tree().map_err(|_| GitError::Internal)?;
    Ok(Some((tree, sha)))
}

/// Recursively collect entries under `tree`. `prefix` is the jail-relative
/// path of `tree` itself.
fn walk(
    repo: &Repository,
    tree: &Tree<'_>,
    prefix: &str,
    depth: usize,
    allowed_ext: &[String],
    out: &mut Vec<RawEntry>,
) -> Result<(), GitError> {
    if depth > MAX_TREE_DEPTH || out.len() >= MAX_TREE_ENTRIES {
        return Ok(());
    }
    for entry in tree {
        if out.len() >= MAX_TREE_ENTRIES {
            break;
        }
        let mode = entry.filemode();
        // Never follow a symlink or descend into a submodule: both are ways
        // for a repository to name something it does not itself contain.
        if mode == MODE_SYMLINK || mode == MODE_GITLINK {
            continue;
        }
        // Non-UTF-8 names are skipped rather than lossily converted: a path
        // we cannot round-trip is a path we cannot safely serve.
        let Ok(name) = entry.name() else { continue };
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        match entry.kind() {
            Some(ObjectType::Tree) => {
                let Ok(obj) = entry.to_object(repo) else {
                    continue;
                };
                let Ok(sub) = obj.into_tree() else { continue };
                let before = out.len();
                out.push(RawEntry {
                    path: path.clone(),
                    name: name.to_owned(),
                    is_dir: true,
                    size: 0,
                });
                walk(repo, &sub, &path, depth.saturating_add(1), allowed_ext, out)?;
                // A directory holding no renderable documents is noise in the
                // sidebar, so drop it again along with its (empty) subtree.
                if out.len() == before.saturating_add(1) {
                    out.truncate(before);
                }
            }
            Some(ObjectType::Blob) => {
                if !has_allowed_ext(name, allowed_ext) {
                    continue;
                }
                let size = entry
                    .to_object(repo)
                    .ok()
                    .and_then(|o| o.peel_to_blob().ok())
                    .map_or(0, |b| b.size() as u64);
                out.push(RawEntry {
                    path,
                    name: name.to_owned(),
                    is_dir: false,
                    size,
                });
            }
            _ => {}
        }
    }
    Ok(())
}

fn has_allowed_ext(name: &str, allowed: &[String]) -> bool {
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    if stem.is_empty() {
        return false;
    }
    let lower = ext.to_ascii_lowercase();
    allowed.contains(&lower)
}

fn read_tree_blocking(
    dir: &Path,
    branch: &str,
    jail: &str,
    allowed_ext: &[String],
) -> Result<Option<(Vec<RawEntry>, String)>, GitError> {
    check_branch(branch)?;
    let repo = Repository::open_bare(dir).map_err(|_| GitError::NotFound)?;
    let Some((tree, sha)) = jail_tree(&repo, branch, jail)? else {
        return Ok(None);
    };
    let mut out = Vec::new();
    walk(&repo, &tree, "", 0, allowed_ext, &mut out)?;
    Ok(Some((out, sha)))
}

fn read_blob_blocking(
    dir: &Path,
    branch: &str,
    repo_path: &str,
    max_bytes: u64,
) -> Result<Option<BlobData>, GitError> {
    check_branch(branch)?;
    let repo = Repository::open_bare(dir).map_err(|_| GitError::NotFound)?;
    let commit = repo
        .find_reference(&format!("refs/heads/{branch}"))
        .map_err(|_| GitError::NotFound)?
        .peel_to_commit()
        .map_err(|e| map_git_err(&e))?;
    let tree = commit.tree().map_err(|e| map_git_err(&e))?;
    let Ok(entry) = tree.get_path(Path::new(repo_path)) else {
        return Ok(None);
    };
    let mode = entry.filemode();
    if mode == MODE_SYMLINK || mode == MODE_GITLINK {
        return Ok(None);
    }
    if entry.kind() != Some(ObjectType::Blob) {
        return Ok(None);
    }
    let obj = entry.to_object(&repo).map_err(|e| map_git_err(&e))?;
    let blob = obj.peel_to_blob().map_err(|e| map_git_err(&e))?;
    if blob.size() as u64 > max_bytes {
        return Err(GitError::TooLarge);
    }
    Ok(Some(BlobData {
        oid: blob.id().to_string(),
        bytes: blob.content().to_vec(),
    }))
}

/// Newest commit that changed `repo_path`, walking at most
/// [`MAX_HISTORY_WALK`] commits.
fn last_commit_blocking(
    dir: &Path,
    branch: &str,
    repo_path: &str,
) -> Result<Option<CommitMeta>, GitError> {
    check_branch(branch)?;
    let repo = Repository::open_bare(dir).map_err(|_| GitError::NotFound)?;
    let head = repo
        .find_reference(&format!("refs/heads/{branch}"))
        .map_err(|_| GitError::NotFound)?
        .peel_to_commit()
        .map_err(|e| map_git_err(&e))?;

    let mut walk = repo.revwalk().map_err(|e| map_git_err(&e))?;
    walk.set_sorting(Sort::TOPOLOGICAL | Sort::TIME)
        .map_err(|e| map_git_err(&e))?;
    walk.push(head.id()).map_err(|e| map_git_err(&e))?;

    let path = Path::new(repo_path);
    let blob_at = |commit: &git2::Commit<'_>| -> Option<Oid> {
        commit.tree().ok()?.get_path(path).ok().map(|e| e.id())
    };

    for (seen, oid) in walk.flatten().enumerate() {
        if seen >= MAX_HISTORY_WALK {
            break;
        }
        let Ok(commit) = repo.find_commit(oid) else {
            continue;
        };
        let here = blob_at(&commit);
        // A commit "touched" the file when its content differs from every
        // parent's. Root commits that contain the file count as touching it.
        let changed = if commit.parent_count() == 0 {
            here.is_some()
        } else {
            (0..commit.parent_count())
                .filter_map(|i| commit.parent(i).ok())
                .all(|p| blob_at(&p) != here)
        };
        if changed {
            return Ok(Some(CommitMeta {
                sha: commit.id().to_string(),
                author_name: commit.author().name().unwrap_or("unknown").to_owned(),
                message: commit
                    .summary()
                    .ok()
                    .flatten()
                    .unwrap_or_default()
                    .to_owned(),
                committed_at: commit.time().seconds(),
            }));
        }
    }
    Ok(None)
}

/// Rebuild the tree chain so `segments` names `blob`, returning the new root
/// tree OID. Every level above the file is rewritten, exactly as a normal
/// commit would.
fn insert_blob(
    repo: &Repository,
    base: Option<&Tree<'_>>,
    segments: &[&str],
    blob: Oid,
    filemode: i32,
) -> Result<Oid, git2::Error> {
    let Some((name, rest)) = segments.split_first() else {
        return Err(git2::Error::from_str("empty path"));
    };
    let mut builder = repo.treebuilder(base)?;
    if rest.is_empty() {
        builder.insert(*name, blob, filemode)?;
    } else {
        // Descend, creating intermediate directories as needed.
        let existing = base
            .and_then(|t| t.get_name(name))
            .filter(|e| e.kind() == Some(ObjectType::Tree))
            .and_then(|e| e.to_object(repo).ok())
            .and_then(|o| o.into_tree().ok());
        let sub = insert_blob(repo, existing.as_ref(), rest, blob, filemode)?;
        builder.insert(*name, sub, 0o040_000)?;
    }
    builder.write()
}

fn edit_blocking(req: &EditRequest) -> Result<PushOutcome, GitError> {
    check_branch(&req.branch)?;
    let repo = Repository::open_bare(&req.repo_dir).map_err(|_| GitError::NotFound)?;

    let refname = format!("refs/heads/{}", req.branch);
    let mut reference = repo
        .find_reference(&refname)
        .map_err(|_| GitError::NotFound)?;
    let parent = reference.peel_to_commit().map_err(|e| map_git_err(&e))?;
    let old_target = parent.id();
    let tree = parent.tree().map_err(|e| map_git_err(&e))?;

    // Optimistic concurrency: the file must still be exactly what the editor
    // loaded. Absent expectation means "create"; an existing file then loses.
    let path = Path::new(&req.repo_path);
    let current = tree.get_path(path).ok();
    if let Some(entry) = current.as_ref() {
        let mode = entry.filemode();
        if mode == MODE_SYMLINK || mode == MODE_GITLINK {
            return Ok(PushOutcome::Conflict);
        }
    }
    let current_oid = current.as_ref().map(|e| e.id().to_string());
    if current_oid != req.expected_blob_oid {
        return Ok(PushOutcome::Conflict);
    }
    // Preserve an executable bit rather than silently normalising it away.
    let filemode = current
        .as_ref()
        .map_or(MODE_BLOB, git2::TreeEntry::filemode);

    let segments: Vec<&str> = req.repo_path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Err(GitError::Internal);
    }

    let blob = repo.blob(&req.content).map_err(|e| map_git_err(&e))?;
    // Writing identical content produces the same OID and therefore the same
    // tree; committing that would be an empty commit.
    if Some(blob.to_string()) == current_oid {
        return Ok(PushOutcome::Pushed {
            commit: old_target.to_string(),
            blob_oid: blob.to_string(),
        });
    }

    let new_tree_oid =
        insert_blob(&repo, Some(&tree), &segments, blob, filemode).map_err(|e| map_git_err(&e))?;
    let new_tree = repo.find_tree(new_tree_oid).map_err(|e| map_git_err(&e))?;

    let sig =
        git2::Signature::now(&req.author_name, &req.author_email).map_err(|e| map_git_err(&e))?;
    // Committed with no ref update, so a failed push leaves nothing dangling
    // that the next reader could see.
    let commit = repo
        .commit(None, &sig, &sig, &req.message, &new_tree, &[&parent])
        .map_err(|e| map_git_err(&e))?;

    reference
        .set_target(commit, "intellipilot doc edit")
        .map_err(|e| map_git_err(&e))?;

    let host_fp: RefCell<Option<String>> = RefCell::new(None);
    let rejection: RefCell<Option<String>> = RefCell::new(None);
    let mut cb = auth_callbacks(&req.private_key_pem, &host_fp);
    cb.push_update_reference(|_refname, status| {
        if let Some(msg) = status {
            *rejection.borrow_mut() = Some(msg.to_owned());
        }
        Ok(())
    });
    let mut opts = PushOptions::new();
    opts.remote_callbacks(cb);

    let refspec = format!("{refname}:{refname}");
    let push = repo
        .remote_anonymous(&req.ssh_url)
        .and_then(|mut r| r.push(&[refspec.as_str()], Some(&mut opts)));
    // Releases the callbacks' borrow of `rejection`.
    drop(opts);
    let rejected = rejection.into_inner();
    match (push, rejected) {
        (Ok(()), None) => Ok(PushOutcome::Pushed {
            commit: commit.to_string(),
            blob_oid: blob.to_string(),
        }),
        // The remote said no: put the cache back where it was so the next
        // reader sees the remote's truth, not our rejected commit.
        (Ok(()), Some(msg)) => {
            rollback(&mut reference, old_target);
            Ok(PushOutcome::Rejected(msg))
        }
        (Err(e), reason) => {
            rollback(&mut reference, old_target);
            let err = map_git_err(&e);
            // A transport-level refusal is still a refusal, not an outage.
            reason.map_or(Err(err), |msg| Ok(PushOutcome::Rejected(msg)))
        }
    }
}

fn rollback(reference: &mut git2::Reference<'_>, old: Oid) {
    drop(reference.set_target(old, "intellipilot doc edit rollback"));
}

/// Delete a source's cache directory. Missing is success — the caller is
/// removing the source either way.
pub fn remove_cache(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

// --- async wrappers -------------------------------------------------------

/// Run a blocking git closure under the shared concurrency semaphore and a
/// hard timeout. `network` decides whether a permit is taken: local reads are
/// fast and must not queue behind clones.
async fn run<T, F>(network: bool, timeout: Duration, f: F) -> Result<T, GitError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, GitError> + Send + 'static,
{
    let _permit = if network {
        Some(
            semaphore()
                .acquire()
                .await
                .map_err(|_| GitError::Internal)?,
        )
    } else {
        None
    };
    let task = tokio::task::spawn_blocking(f);
    match tokio::time::timeout(timeout, task).await {
        Ok(Ok(res)) => res,
        Ok(Err(_join)) => Err(GitError::Internal),
        Err(_elapsed) => Err(GitError::Timeout),
    }
}

/// Clone (first time) or fetch (subsequently) one branch into the cache.
pub async fn sync(
    dir: PathBuf,
    ssh_url: String,
    branch: String,
    private_key_pem: String,
    max_bytes: u64,
) -> Result<SyncOutcome, GitError> {
    run(true, SYNC_TIMEOUT, move || {
        sync_blocking(&dir, &ssh_url, &branch, &private_key_pem, max_bytes)
    })
    .await
}

/// Walk the jail subtree, keeping only files whose extension is in
/// `allowed_ext` (lowercase, without the dot). `Ok(None)` means the jail path
/// does not exist in the repository.
pub async fn read_tree(
    dir: PathBuf,
    branch: String,
    jail: String,
    allowed_ext: Vec<String>,
) -> Result<Option<(Vec<RawEntry>, String)>, GitError> {
    run(false, READ_TIMEOUT, move || {
        read_tree_blocking(&dir, &branch, &jail, &allowed_ext)
    })
    .await
}

/// Read one blob by repository-root-relative path.
pub async fn read_blob(
    dir: PathBuf,
    branch: String,
    repo_path: String,
    max_bytes: u64,
) -> Result<Option<BlobData>, GitError> {
    run(false, READ_TIMEOUT, move || {
        read_blob_blocking(&dir, &branch, &repo_path, max_bytes)
    })
    .await
}

/// Newest commit that touched a path, or `None` if it was not found within the
/// bounded history walk.
pub async fn last_commit_for(
    dir: PathBuf,
    branch: String,
    repo_path: String,
) -> Result<Option<CommitMeta>, GitError> {
    run(false, READ_TIMEOUT, move || {
        last_commit_blocking(&dir, &branch, &repo_path)
    })
    .await
}

/// Write one file, commit it as the requesting user, and push.
pub async fn edit_and_push(req: EditRequest) -> Result<PushOutcome, GitError> {
    run(true, PUSH_TIMEOUT, move || edit_blocking(&req)).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn unique_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ip-docs-{tag}-{}-{n}", std::process::id()))
    }

    /// Build a bare repository containing a small documentation tree:
    ///
    /// ```text
    /// docs/README.md          a document inside the jail
    /// docs/guides/intro.md    a document one level down
    /// docs/img/a.png          a non-document, in a directory holding only those
    /// docs/secret.bin         a non-document beside the documents
    /// docs/escape.md          a SYMLINK naming a file above the jail
    /// secret_outside.md       a document above the jail
    /// ```
    fn seed(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        let repo = Repository::init_bare(dir).unwrap();
        let sig = git2::Signature::now("Seed", "seed@example.com").unwrap();

        let root = {
            let b = |content: &[u8]| repo.blob(content).unwrap();
            let subtree = |entries: &[(&str, Oid, i32)]| {
                let mut t = repo.treebuilder(None).unwrap();
                for (name, oid, mode) in entries {
                    t.insert(*name, *oid, *mode).unwrap();
                }
                t.write().unwrap()
            };

            let guides = subtree(&[(
                "intro.md",
                b(b"# Intro\n\n| a | b |\n|---|---|\n| 1 | 2 |\n"),
                MODE_BLOB,
            )]);
            let img = subtree(&[("a.png", b(b"\x89PNG fake"), MODE_BLOB)]);
            let docs = subtree(&[
                ("README.md", b(b"# Docs\n"), MODE_BLOB),
                ("guides", guides, 0o040_000),
                ("img", img, 0o040_000),
                ("secret.bin", b(b"not a doc"), MODE_BLOB),
                ("escape.md", b(b"../secret_outside.md"), MODE_SYMLINK),
            ]);
            subtree(&[
                ("docs", docs, 0o040_000),
                ("secret_outside.md", b(b"# Secret\n"), MODE_BLOB),
            ])
        };

        let tree = repo.find_tree(root).unwrap();
        repo.commit(Some("refs/heads/main"), &sig, &sig, "seed", &tree, &[])
            .unwrap();
    }

    #[test]
    fn branch_names_are_validated() {
        for good in ["main", "develop", "release/1.2", "feature_x"] {
            assert!(valid_branch_name(good), "{good} should be valid");
        }
        // Anything that could break out of the refspec, or that git itself
        // forbids, is refused.
        for bad in [
            "",
            "-x",
            "/x",
            "x/",
            "a b",
            "a..b",
            "a:b",
            "a~b",
            "a^b",
            "a?b",
            "a*b",
            "a[b",
            "a\\b",
            "a@{b",
            "x.lock",
            "a\nb",
            "main:refs/heads/evil",
        ] {
            assert!(!valid_branch_name(bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn tree_walk_respects_the_jail_and_the_extension_filter() {
        let dir = unique_dir("tree");
        seed(&dir);
        let allowed = vec!["md".to_owned(), "txt".to_owned()];
        let (entries, sha) = read_tree_blocking(&dir, "main", "docs", &allowed)
            .unwrap()
            .unwrap();
        assert_eq!(sha.len(), 40);

        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        // Inside the jail, documents only.
        assert!(paths.contains(&"README.md"));
        assert!(paths.contains(&"guides"));
        assert!(paths.contains(&"guides/intro.md"));
        // Non-documents are invisible...
        assert!(!paths.contains(&"secret.bin"));
        // ...as is a directory holding none of them.
        assert!(!paths.contains(&"img"));
        assert!(!paths.contains(&"img/a.png"));
        // Nothing above the jail is reachable, and the symlink that names it
        // is not listed even though it ends in `.md`.
        assert!(!paths.iter().any(|p| p.contains("secret_outside")));
        assert!(!paths.contains(&"escape.md"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_jail_path_reports_none() {
        let dir = unique_dir("nojail");
        seed(&dir);
        let res = read_tree_blocking(&dir, "main", "does/not/exist", &["md".to_owned()]).unwrap();
        assert!(res.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn blobs_read_by_path_and_symlinks_refused() {
        let dir = unique_dir("blob");
        seed(&dir);
        let doc = read_blob_blocking(&dir, "main", "docs/README.md", 1024)
            .unwrap()
            .unwrap();
        assert_eq!(String::from_utf8(doc.bytes).unwrap(), "# Docs\n");
        assert_eq!(doc.oid.len(), 40);

        // A symlink entry is never dereferenced — it reads as absent.
        assert!(
            read_blob_blocking(&dir, "main", "docs/escape.md", 1024)
                .unwrap()
                .is_none()
        );
        // A directory is not a blob.
        assert!(
            read_blob_blocking(&dir, "main", "docs/guides", 1024)
                .unwrap()
                .is_none()
        );
        assert!(
            read_blob_blocking(&dir, "main", "nope.md", 1024)
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversized_blob_is_refused() {
        let dir = unique_dir("big");
        seed(&dir);
        let err = read_blob_blocking(&dir, "main", "docs/README.md", 2).unwrap_err();
        assert_eq!(err, GitError::TooLarge);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn last_commit_finds_the_seeding_commit() {
        let dir = unique_dir("hist");
        seed(&dir);
        let meta = last_commit_blocking(&dir, "main", "docs/README.md")
            .unwrap()
            .unwrap();
        assert_eq!(meta.author_name, "Seed");
        assert_eq!(meta.message, "seed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn insert_blob_rewrites_nested_trees() {
        let dir = unique_dir("insert");
        seed(&dir);
        {
            let repo = Repository::open_bare(&dir).unwrap();
            let head = repo
                .find_reference("refs/heads/main")
                .unwrap()
                .peel_to_commit()
                .unwrap();
            let tree = head.tree().unwrap();
            let new_blob = repo.blob(b"# Changed\n").unwrap();

            let root = insert_blob(
                &repo,
                Some(&tree),
                &["docs", "guides", "intro.md"],
                new_blob,
                MODE_BLOB,
            )
            .unwrap();
            let updated = repo.find_tree(root).unwrap();
            assert_eq!(
                updated
                    .get_path(Path::new("docs/guides/intro.md"))
                    .unwrap()
                    .id(),
                new_blob
            );
            // Siblings survive the rewrite, at every level.
            assert!(updated.get_path(Path::new("docs/README.md")).is_ok());
            assert!(updated.get_path(Path::new("secret_outside.md")).is_ok());

            // A brand-new nested file creates the intermediate directories.
            let added = repo.blob(b"new\n").unwrap();
            let root2 = insert_blob(
                &repo,
                Some(&tree),
                &["docs", "deep", "new", "file.md"],
                added,
                MODE_BLOB,
            )
            .unwrap();
            let t2 = repo.find_tree(root2).unwrap();
            assert_eq!(
                t2.get_path(Path::new("docs/deep/new/file.md"))
                    .unwrap()
                    .id(),
                added
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extension_filter_ignores_dotfiles_and_case() {
        let allowed = vec!["md".to_owned()];
        assert!(has_allowed_ext("a.md", &allowed));
        assert!(has_allowed_ext("a.MD", &allowed));
        assert!(!has_allowed_ext(".md", &allowed));
        assert!(!has_allowed_ext("md", &allowed));
        assert!(!has_allowed_ext("a.txt", &allowed));
    }
}
