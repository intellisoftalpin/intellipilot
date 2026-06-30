//! Atomic permissions and the default per-project role matrix.
//!
//! Permissions are stable strings (stored in `roles.permissions` JSONB and
//! checked at the HTTP boundary). The catalog is forward-looking: it already
//! covers entities introduced in later phases (epics, user stories, tasks,
//! issues, milestones, wiki) so the role model doesn't churn.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// An atomic permission. The serde representation is the stable wire string,
/// e.g. `Permission::ProjectModify` ⇄ `"project.modify"`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // Project
    #[serde(rename = "project.view")]
    ProjectView,
    #[serde(rename = "project.modify")]
    ProjectModify,
    #[serde(rename = "project.delete")]
    ProjectDelete,
    #[serde(rename = "project.admin")]
    ProjectAdmin,
    // Members
    #[serde(rename = "member.view")]
    MemberView,
    #[serde(rename = "member.add")]
    MemberAdd,
    #[serde(rename = "member.remove")]
    MemberRemove,
    #[serde(rename = "member.modify_role")]
    MemberModifyRole,
    // Roles
    #[serde(rename = "role.view")]
    RoleView,
    #[serde(rename = "role.create")]
    RoleCreate,
    #[serde(rename = "role.modify")]
    RoleModify,
    #[serde(rename = "role.delete")]
    RoleDelete,
    // Epics
    #[serde(rename = "epic.view")]
    EpicView,
    #[serde(rename = "epic.create")]
    EpicCreate,
    #[serde(rename = "epic.modify")]
    EpicModify,
    #[serde(rename = "epic.delete")]
    EpicDelete,
    // User stories
    // Issues (the unified work item: Story / Task / Bug / sub-task)
    #[serde(rename = "issue.view")]
    IssueView,
    #[serde(rename = "issue.create")]
    IssueCreate,
    #[serde(rename = "issue.modify")]
    IssueModify,
    #[serde(rename = "issue.delete")]
    IssueDelete,
    // Milestones / sprints
    #[serde(rename = "milestone.view")]
    MilestoneView,
    #[serde(rename = "milestone.create")]
    MilestoneCreate,
    #[serde(rename = "milestone.modify")]
    MilestoneModify,
    #[serde(rename = "milestone.delete")]
    MilestoneDelete,
    // Wiki
    #[serde(rename = "wiki.view")]
    WikiView,
    #[serde(rename = "wiki.create")]
    WikiCreate,
    #[serde(rename = "wiki.modify")]
    WikiModify,
    #[serde(rename = "wiki.delete")]
    WikiDelete,
    // Comments & attachments (cross-entity)
    #[serde(rename = "comment.create")]
    CommentCreate,
    #[serde(rename = "comment.moderate")]
    CommentModerate,
    #[serde(rename = "attachment.create")]
    AttachmentCreate,
    #[serde(rename = "attachment.delete")]
    AttachmentDelete,
    // Time tracking
    /// Log / edit / delete your own worked time in the project.
    #[serde(rename = "time.log")]
    TimeLog,
    /// See the whole team's timesheet in the project.
    #[serde(rename = "time.view_all")]
    TimeViewAll,
    /// Correct other members' entries and lock/unlock project-months.
    #[serde(rename = "time.manage")]
    TimeManage,
    // Taxonomy (issue types, priorities, sizes, statuses, resolutions)
    #[serde(rename = "taxonomy.create")]
    TaxonomyCreate,
    #[serde(rename = "taxonomy.modify")]
    TaxonomyModify,
    #[serde(rename = "taxonomy.delete")]
    TaxonomyDelete,
    // Labels
    #[serde(rename = "label.create")]
    LabelCreate,
    #[serde(rename = "label.modify")]
    LabelModify,
    #[serde(rename = "label.delete")]
    LabelDelete,
    // Components
    #[serde(rename = "component.create")]
    ComponentCreate,
    #[serde(rename = "component.modify")]
    ComponentModify,
    #[serde(rename = "component.delete")]
    ComponentDelete,
    // Repositories (incl. SSH keys and component↔repository links)
    #[serde(rename = "repository.create")]
    RepositoryCreate,
    #[serde(rename = "repository.modify")]
    RepositoryModify,
    #[serde(rename = "repository.delete")]
    RepositoryDelete,
    // Customers
    #[serde(rename = "customer.create")]
    CustomerCreate,
    #[serde(rename = "customer.modify")]
    CustomerModify,
    #[serde(rename = "customer.delete")]
    CustomerDelete,
    // Releases (incl. versions and component↔release links)
    #[serde(rename = "release.create")]
    ReleaseCreate,
    #[serde(rename = "release.modify")]
    ReleaseModify,
    #[serde(rename = "release.delete")]
    ReleaseDelete,
    // Shared boards. Personal boards need only `project.view`; managing boards
    // that are visible to the whole project is gated by these.
    #[serde(rename = "board.shared.create")]
    BoardSharedCreate,
    #[serde(rename = "board.shared.modify")]
    BoardSharedModify,
    #[serde(rename = "board.shared.delete")]
    BoardSharedDelete,
}

impl Permission {
    /// Every permission in catalog order.
    pub const ALL: [Self; 56] = [
        Self::ProjectView,
        Self::ProjectModify,
        Self::ProjectDelete,
        Self::ProjectAdmin,
        Self::MemberView,
        Self::MemberAdd,
        Self::MemberRemove,
        Self::MemberModifyRole,
        Self::RoleView,
        Self::RoleCreate,
        Self::RoleModify,
        Self::RoleDelete,
        Self::EpicView,
        Self::EpicCreate,
        Self::EpicModify,
        Self::EpicDelete,
        Self::IssueView,
        Self::IssueCreate,
        Self::IssueModify,
        Self::IssueDelete,
        Self::MilestoneView,
        Self::MilestoneCreate,
        Self::MilestoneModify,
        Self::MilestoneDelete,
        Self::WikiView,
        Self::WikiCreate,
        Self::WikiModify,
        Self::WikiDelete,
        Self::CommentCreate,
        Self::CommentModerate,
        Self::AttachmentCreate,
        Self::AttachmentDelete,
        Self::TimeLog,
        Self::TimeViewAll,
        Self::TimeManage,
        Self::TaxonomyCreate,
        Self::TaxonomyModify,
        Self::TaxonomyDelete,
        Self::LabelCreate,
        Self::LabelModify,
        Self::LabelDelete,
        Self::ComponentCreate,
        Self::ComponentModify,
        Self::ComponentDelete,
        Self::RepositoryCreate,
        Self::RepositoryModify,
        Self::RepositoryDelete,
        Self::CustomerCreate,
        Self::CustomerModify,
        Self::CustomerDelete,
        Self::ReleaseCreate,
        Self::ReleaseModify,
        Self::ReleaseDelete,
        Self::BoardSharedCreate,
        Self::BoardSharedModify,
        Self::BoardSharedDelete,
    ];

    /// Stable wire string for this permission.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        // Round-trips through serde; kept explicit for cheap, infallible use
        // in queries and checks.
        match self {
            Self::ProjectView => "project.view",
            Self::ProjectModify => "project.modify",
            Self::ProjectDelete => "project.delete",
            Self::ProjectAdmin => "project.admin",
            Self::MemberView => "member.view",
            Self::MemberAdd => "member.add",
            Self::MemberRemove => "member.remove",
            Self::MemberModifyRole => "member.modify_role",
            Self::RoleView => "role.view",
            Self::RoleCreate => "role.create",
            Self::RoleModify => "role.modify",
            Self::RoleDelete => "role.delete",
            Self::EpicView => "epic.view",
            Self::EpicCreate => "epic.create",
            Self::EpicModify => "epic.modify",
            Self::EpicDelete => "epic.delete",
            Self::IssueView => "issue.view",
            Self::IssueCreate => "issue.create",
            Self::IssueModify => "issue.modify",
            Self::IssueDelete => "issue.delete",
            Self::MilestoneView => "milestone.view",
            Self::MilestoneCreate => "milestone.create",
            Self::MilestoneModify => "milestone.modify",
            Self::MilestoneDelete => "milestone.delete",
            Self::WikiView => "wiki.view",
            Self::WikiCreate => "wiki.create",
            Self::WikiModify => "wiki.modify",
            Self::WikiDelete => "wiki.delete",
            Self::CommentCreate => "comment.create",
            Self::CommentModerate => "comment.moderate",
            Self::AttachmentCreate => "attachment.create",
            Self::AttachmentDelete => "attachment.delete",
            Self::TimeLog => "time.log",
            Self::TimeViewAll => "time.view_all",
            Self::TimeManage => "time.manage",
            Self::TaxonomyCreate => "taxonomy.create",
            Self::TaxonomyModify => "taxonomy.modify",
            Self::TaxonomyDelete => "taxonomy.delete",
            Self::LabelCreate => "label.create",
            Self::LabelModify => "label.modify",
            Self::LabelDelete => "label.delete",
            Self::ComponentCreate => "component.create",
            Self::ComponentModify => "component.modify",
            Self::ComponentDelete => "component.delete",
            Self::RepositoryCreate => "repository.create",
            Self::RepositoryModify => "repository.modify",
            Self::RepositoryDelete => "repository.delete",
            Self::CustomerCreate => "customer.create",
            Self::CustomerModify => "customer.modify",
            Self::CustomerDelete => "customer.delete",
            Self::ReleaseCreate => "release.create",
            Self::ReleaseModify => "release.modify",
            Self::ReleaseDelete => "release.delete",
            Self::BoardSharedCreate => "board.shared.create",
            Self::BoardSharedModify => "board.shared.modify",
            Self::BoardSharedDelete => "board.shared.delete",
        }
    }
}

/// A built-in role definition (seeded into every new project).
#[derive(Debug, Clone)]
pub struct DefaultRole {
    pub slug: &'static str,
    pub name: &'static str,
    pub order: i32,
    /// `true` for the owner/admin role: implicitly holds every permission.
    pub is_admin: bool,
    pub permissions: Vec<Permission>,
}

/// All view permissions (the stakeholder baseline).
fn all_view() -> Vec<Permission> {
    Permission::ALL
        .into_iter()
        .filter(|p| p.as_str().rsplit('.').next() == Some("view"))
        .collect()
}

/// View + create/modify on work items + comments/attachments (developer set),
/// without delete or any project/member/role administration.
fn developer_perms() -> Vec<Permission> {
    use Permission::{
        AttachmentCreate, AttachmentDelete, CommentCreate, EpicCreate, EpicModify, IssueCreate,
        IssueModify, MilestoneCreate, MilestoneModify, TimeLog, WikiCreate, WikiModify,
    };
    let mut perms = all_view();
    perms.extend([
        EpicCreate,
        EpicModify,
        IssueCreate,
        IssueModify,
        MilestoneCreate,
        MilestoneModify,
        WikiCreate,
        WikiModify,
        CommentCreate,
        AttachmentCreate,
        AttachmentDelete,
        TimeLog,
    ]);
    perms.sort_unstable();
    perms.dedup();
    perms
}

/// Product owner: developer set + member/role management + project.modify +
/// delete on work items + comment moderation.
fn product_owner_perms() -> Vec<Permission> {
    use Permission::{
        BoardSharedCreate, BoardSharedDelete, BoardSharedModify, CommentModerate, ComponentCreate,
        ComponentDelete, ComponentModify, CustomerCreate, CustomerDelete, CustomerModify,
        EpicDelete, IssueDelete, LabelCreate, LabelDelete, LabelModify, MemberAdd,
        MemberModifyRole, MemberRemove, MemberView, MilestoneDelete, ProjectModify, ReleaseCreate,
        ReleaseDelete, ReleaseModify, RepositoryCreate, RepositoryDelete, RepositoryModify,
        RoleCreate, RoleDelete, RoleModify, RoleView, TaxonomyCreate, TaxonomyDelete,
        TaxonomyModify, TimeViewAll, WikiDelete,
    };
    let mut perms = developer_perms();
    perms.extend([
        ProjectModify,
        BoardSharedCreate,
        BoardSharedModify,
        BoardSharedDelete,
        MemberView,
        MemberAdd,
        MemberRemove,
        MemberModifyRole,
        RoleView,
        RoleCreate,
        RoleModify,
        RoleDelete,
        EpicDelete,
        IssueDelete,
        MilestoneDelete,
        WikiDelete,
        CommentModerate,
        TimeViewAll,
        // Project-configuration entities (previously bundled under
        // project.modify; now split into dedicated permissions).
        TaxonomyCreate,
        TaxonomyModify,
        TaxonomyDelete,
        LabelCreate,
        LabelModify,
        LabelDelete,
        ComponentCreate,
        ComponentModify,
        ComponentDelete,
        RepositoryCreate,
        RepositoryModify,
        RepositoryDelete,
        CustomerCreate,
        CustomerModify,
        CustomerDelete,
        ReleaseCreate,
        ReleaseModify,
        ReleaseDelete,
    ]);
    perms.sort_unstable();
    perms.dedup();
    perms
}

/// The four roles seeded into every new project.
#[must_use]
pub fn default_roles() -> Vec<DefaultRole> {
    vec![
        DefaultRole {
            slug: "admin",
            name: "Administrator",
            order: 1,
            is_admin: true,
            permissions: Permission::ALL.to_vec(),
        },
        DefaultRole {
            slug: "product_owner",
            name: "Product Owner",
            order: 2,
            is_admin: false,
            permissions: product_owner_perms(),
        },
        DefaultRole {
            slug: "dev",
            name: "Developer",
            order: 3,
            is_admin: false,
            permissions: developer_perms(),
        },
        DefaultRole {
            slug: "stakeholder",
            name: "Stakeholder",
            order: 4,
            is_admin: false,
            permissions: all_view(),
        },
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn all_has_no_duplicates_and_matches_count() {
        let mut seen = std::collections::HashSet::new();
        for p in Permission::ALL {
            assert!(
                seen.insert(p.as_str()),
                "duplicate permission {}",
                p.as_str()
            );
        }
        assert_eq!(Permission::ALL.len(), 56);
    }

    #[test]
    fn config_entity_permissions_present() {
        // The project-configuration entities each carry create/modify/delete.
        for group in [
            "taxonomy",
            "label",
            "component",
            "repository",
            "customer",
            "release",
        ] {
            for verb in ["create", "modify", "delete"] {
                let wire = format!("{group}.{verb}");
                assert!(
                    Permission::ALL.iter().any(|p| p.as_str() == wire),
                    "missing permission {wire}"
                );
            }
        }
    }

    #[test]
    fn config_entity_permissions_role_assignment() {
        let roles = default_roles();
        let by_slug = |slug: &str| -> std::collections::HashSet<Permission> {
            roles
                .iter()
                .find(|r| r.slug == slug)
                .map(|r| r.permissions.iter().copied().collect())
                .unwrap()
        };
        let po = by_slug("product_owner");
        let dev = by_slug("dev");
        let config = [
            Permission::TaxonomyCreate,
            Permission::TaxonomyModify,
            Permission::TaxonomyDelete,
            Permission::LabelCreate,
            Permission::LabelModify,
            Permission::LabelDelete,
            Permission::ComponentCreate,
            Permission::ComponentModify,
            Permission::ComponentDelete,
            Permission::RepositoryCreate,
            Permission::RepositoryModify,
            Permission::RepositoryDelete,
            Permission::CustomerCreate,
            Permission::CustomerModify,
            Permission::CustomerDelete,
            Permission::ReleaseCreate,
            Permission::ReleaseModify,
            Permission::ReleaseDelete,
        ];
        for p in config {
            assert!(po.contains(&p), "product_owner should hold {}", p.as_str());
            assert!(
                !dev.contains(&p),
                "dev should NOT hold {} by default",
                p.as_str()
            );
        }
    }

    #[test]
    fn as_str_round_trips_through_serde() {
        for p in Permission::ALL {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", p.as_str()));
            let back: Permission = serde_json::from_str(&json).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn default_role_permission_sets_snapshot() {
        // Stable, reviewable matrix of slug -> sorted permission strings.
        let snapshot: Vec<(String, Vec<String>)> = default_roles()
            .into_iter()
            .map(|r| {
                let mut perms: Vec<String> = r
                    .permissions
                    .iter()
                    .map(|p| p.as_str().to_owned())
                    .collect();
                perms.sort();
                (r.slug.to_owned(), perms)
            })
            .collect();
        insta::assert_json_snapshot!(snapshot);
    }

    #[test]
    fn role_privilege_ordering() {
        // admin ⊇ product_owner ⊇ dev ⊇ stakeholder
        let roles = default_roles();
        let perms: Vec<std::collections::HashSet<Permission>> = roles
            .iter()
            .map(|r| r.permissions.iter().copied().collect())
            .collect();
        assert!(perms[1].is_superset(&perms[2]), "PO ⊇ dev");
        assert!(perms[2].is_superset(&perms[3]), "dev ⊇ stakeholder");
        assert_eq!(perms[0].len(), Permission::ALL.len(), "admin holds all");
    }
}
