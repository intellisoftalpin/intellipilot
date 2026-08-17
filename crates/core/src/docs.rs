//! External documentation sources surfaced under a project's Wiki section,
//! in two kinds (see [`DocSourceKind`]).
//!
//! For a **git** source, everything a reader sees comes out of a cached bare
//! clone, restricted to the subtree named by [`DocSource::doc_path`] — "the
//! jail". Path normalization and jail resolution live in [`crate::docs::path`]
//! so the API and the git layer share exactly one implementation.
//!
//! A **web** source is just a URL the client embeds. Nothing is fetched,
//! cloned or stored server-side, so none of the jail machinery applies to it —
//! and it is read-only by construction.

pub mod path;

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// What kind of thing a documentation source points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocSourceKind {
    /// A git repository, read from a cached bare clone and jailed to its
    /// `doc_path`. Editable when the caller has a write key.
    Git,
    /// A plain URL, embedded in a frame. Nothing is fetched, cloned or stored
    /// server-side, so it is read-only by construction — there is no
    /// repository to push to.
    Web,
}

impl DocSourceKind {
    /// Wire string, matching the `doc_sources.kind` CHECK constraint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Web => "web",
        }
    }

    /// Parse a stored value. Unknown values degrade to [`Self::Git`], the
    /// column default, rather than failing a whole listing.
    #[must_use]
    pub fn from_str_lossy(s: &str) -> Self {
        if s == "web" { Self::Web } else { Self::Git }
    }

    /// Whether this kind is backed by a cached clone the server syncs.
    #[must_use]
    pub const fn is_git(self) -> bool {
        matches!(self, Self::Git)
    }
}

/// Lifecycle of a source's on-disk cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CacheStatus {
    /// Registered but never successfully cloned.
    Pending,
    /// A clone or fetch is in flight.
    Syncing,
    /// Servable: the cache holds a usable tree.
    Ready,
    /// The last attempt failed. A previously-ready cache is still served —
    /// stale content beats no content when the remote is down.
    Error,
}

impl CacheStatus {
    /// Wire string, matching the `doc_sources.cache_status` CHECK constraint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Syncing => "syncing",
            Self::Ready => "ready",
            Self::Error => "error",
        }
    }

    /// Parse a stored value. Unknown values degrade to [`Self::Pending`]
    /// rather than failing a whole listing.
    #[must_use]
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "syncing" => Self::Syncing,
            "ready" => Self::Ready,
            "error" => Self::Error,
            _ => Self::Pending,
        }
    }
}

/// A registered documentation source. Contains no credential material: only
/// the id of the deploy key it uses.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DocSource {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub kind: DocSourceKind,
    /// Absent for a [`DocSourceKind::Web`] source, which has no repository.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_url: Option<String>,
    /// For a git source, the base URL for browsing the repository on its host
    /// — used by "open on source" and by links resolving above the jail. For
    /// a web source, the page itself.
    pub web_url: String,
    /// Absent for a web source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Subtree exposed to readers, relative to the repository root. Empty
    /// means the whole repository, and is always empty for a web source.
    pub doc_path: String,
    /// Deploy key used for reads. `None` after the key was deleted — the
    /// source then needs a key reassigned before it can sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key_id: Option<Uuid>,
    /// `true` pins the source as never-editable, regardless of who holds a
    /// write key. Always true for a web source, enforced by a CHECK.
    pub read_only: bool,
    /// Withdrawn from navigation without losing its configuration. Hidden
    /// sources are listed only to callers who can manage them, and their
    /// content reads as absent to everyone else.
    pub hidden: bool,
    pub order: f64,
    pub color: String,
    pub emoji: String,
    pub cache_status: CacheStatus,
    /// Human-readable reason the last sync failed, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_error: Option<String>,
    /// Commit currently served from the cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_commit: Option<String>,
    /// Bytes transferred by the last successful clone or fetch.
    pub cache_bytes: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_fingerprint: Option<String>,
    pub version: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified_at: OffsetDateTime,
}

impl DocSource {
    /// The branch to read, for a git source.
    ///
    /// Empty for a web source, which has none. Callers reach this only after
    /// establishing the source is a git one; if that guard were ever missed,
    /// an empty ref fails branch-name validation in the git layer rather than
    /// resolving to something unintended.
    #[must_use]
    pub fn branch_or_empty(&self) -> String {
        self.branch.clone().unwrap_or_default()
    }

    /// The repository URL, for a git source. Empty for a web source — see
    /// [`Self::branch_or_empty`] for why that is safe.
    #[must_use]
    pub fn ssh_url_or_empty(&self) -> String {
        self.ssh_url.clone().unwrap_or_default()
    }
}

/// A user's writable key for one project. The private half never appears
/// here — not even for its owner.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DocUserKey {
    pub id: Uuid,
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub key_type: String,
    /// OpenSSH public key, one-line form. The user registers this with their
    /// git host so pushes authenticate as them.
    pub public_key: String,
    pub fingerprint: String,
    /// `generated` (we made the pair) or `imported` (the user supplied one).
    pub origin: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Kind of a node in the documentation tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocEntryKind {
    Dir,
    /// A renderable document: `.md` / `.markdown` or `.txt`.
    Doc,
}

/// One node of the documentation hierarchy. Paths are relative to the jail
/// root, never to the repository root, so a client cannot learn anything
/// about the layout above `doc_path`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DocEntry {
    /// Jail-relative path, e.g. `guides/getting-started.md`.
    pub path: String,
    /// Display name — the final segment.
    pub name: String,
    pub kind: DocEntryKind,
    /// Byte size of the blob; absent for directories.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    /// Children, for directories. Depth-first, directories before files,
    /// each group sorted case-insensitively.
    ///
    /// `no_recursion` is required: the type refers to itself, and without it
    /// utoipa inlines the schema forever and blows the stack while building
    /// the OpenAPI document. With it, the field is emitted as a `$ref`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(no_recursion)]
    pub children: Vec<Self>,
}

/// The documentation tree of one source, plus the entry document a client
/// should open when no path was requested.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DocTree {
    pub source_id: Uuid,
    /// Commit the tree was read from.
    pub commit: String,
    pub entries: Vec<DocEntry>,
    /// Jail-relative path of the homepage: `README.md`, then `index.md`, then
    /// `home.md` (case-insensitive) at the jail root. `None` when the source
    /// has no obvious entry point and the client should show the tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_path: Option<String>,
}

/// Authorship of the commit that last touched a document.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DocCommitInfo {
    pub sha: String,
    pub author_name: String,
    pub message: String,
    #[serde(with = "time::serde::rfc3339")]
    pub committed_at: OffsetDateTime,
}

/// A document's raw source plus everything the viewer needs around it.
///
/// The body is returned as **markdown source**, not HTML: the Flutter client
/// renders it, which keeps link and image resolution (and therefore the jail)
/// on the client side where the routing context lives.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DocContent {
    pub source_id: Uuid,
    /// Jail-relative path of this document.
    pub path: String,
    pub body: String,
    /// Blob OID, used as the `If-Match` ETag when saving.
    pub blob_oid: String,
    /// Commit the content was read from.
    pub commit: String,
    /// `true` when this document is editable *by the caller*: the source is
    /// not read-only, the caller holds `doc_source.modify`, and they have a
    /// personal write key registered.
    pub can_edit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_commit: Option<DocCommitInfo>,
}
