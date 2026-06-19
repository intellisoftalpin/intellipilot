//! Per-project git integration: the SSH credential vault, repositories, and
//! component↔repository links.
//!
//! These models underpin the future "clone & analyze" feature. The private key
//! of an [`SshKey`] is stored encrypted at rest and is **never** present in
//! these structs — only public, displayable metadata is exposed.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// An SSH key managed within a project (the credential vault). One key may be
/// used by several repositories.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SshKey {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    /// `true` = read-only deploy key; `false` = read/write.
    pub read_only: bool,
    /// Algorithm label, e.g. `ed25519`.
    pub key_type: String,
    /// OpenSSH public key, one-line form. Safe to display / copy as a deploy
    /// key on the git host.
    pub public_key: String,
    /// SHA256 fingerprint (`SHA256:...`).
    pub fingerprint: String,
    /// How many repositories currently reference this key.
    pub used_by_repo_count: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A git repository registered in a project, accessed over SSH.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Repository {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub ssh_url: String,
    /// The SSH key used to access this repo. `None` after its key was deleted —
    /// the repo then needs a key reassigned before it can be reached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key_id: Option<Uuid>,
    /// The repository's default branch, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
    /// SHA256 host-key fingerprint captured on first successful connect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_fingerprint: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A link between a component and a repository, pinned to a specific branch.
/// Many repositories may be linked to the same component.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ComponentRepositoryLink {
    pub component_id: Uuid,
    pub repository_id: Uuid,
    /// Repository name, denormalized for convenient display.
    pub repository_name: String,
    pub ssh_url: String,
    /// The specific branch linked (may differ from the repository default).
    pub branch: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Remote branch discovery result, returned by the branch endpoints.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct RemoteBranches {
    pub branches: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_fingerprint: Option<String>,
}
