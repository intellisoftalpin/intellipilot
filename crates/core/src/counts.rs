//! Project navigation counts: how many *active* objects each rail section
//! holds, for the badge next to its label.
//!
//! "Active" means not closed and not soft-deleted. There is no archive concept
//! in the schema, so closed is the only terminal state:
//!
//!   * issues / epics — their status taxonomy item is not `is_closed`
//!     (a NULL status counts as active);
//!   * milestones — the `closed` flag is false.
//!
//! Every field is `Option` because the sections are gated by *separate*
//! permissions (`issue.view`, `epic.view`, `milestone.view`). `None` means
//! "you may not see this", which the UI renders as no badge at all — a zero
//! and a hidden section must not look alike.

use serde::Serialize;
use utoipa::ToSchema;

/// Active-object counts for one project's navigation rail.
#[derive(Debug, Clone, Copy, Default, Serialize, ToSchema)]
pub struct ProjectCounts {
    /// Distinct active issues the caller holds any role on — the My Issues
    /// board's card count. An issue counts once even when it lands in several
    /// of that board's lanes.
    pub my_issues: Option<i64>,
    /// Active issues in the project, sub-tasks included (matching the issues
    /// list, which does not filter on `parent_id`).
    pub issues: Option<i64>,
    pub epics: Option<i64>,
    pub milestones: Option<i64>,
}

/// Which counts the caller is permitted to see. `my_issues` follows `issues`:
/// both need `issue.view`.
#[derive(Debug, Clone, Copy)]
pub struct CountScopes {
    pub issues: bool,
    pub epics: bool,
    pub milestones: bool,
}

impl CountScopes {
    /// True when at least one count is permitted — otherwise the query can be
    /// skipped entirely.
    #[must_use]
    pub const fn any(self) -> bool {
        self.issues || self.epics || self.milestones
    }
}
