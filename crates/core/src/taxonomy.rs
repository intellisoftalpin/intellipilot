//! Per-project taxonomy: statuses, issue types, priorities, sizes.
//!
//! All kinds share one storage shape (`taxonomy_items`) with kind-specific
//! fields left `None` where not applicable. With the unified backlog there is
//! a single `issue_status` workflow shared by every issue (Story/Task/Bug);
//! the issue *type* is itself a taxonomy (`issue_type`). Estimation uses
//! `size` (T-shirt XS–XXL) whose numeric `value` is an ordinal (1–6) the UI
//! uses to scale the size badge.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// The kind of taxonomy item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaxonomyKind {
    IssueStatus,
    IssueType,
    Priority,
    Size,
}

impl TaxonomyKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IssueStatus => "issue_status",
            Self::IssueType => "issue_type",
            Self::Priority => "priority",
            Self::Size => "size",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "issue_status" => Self::IssueStatus,
            "issue_type" => Self::IssueType,
            "priority" => Self::Priority,
            "size" => Self::Size,
            _ => return None,
        })
    }

    /// Whether this kind carries an `is_closed` flag (the status kind).
    #[must_use]
    pub const fn has_closed(self) -> bool {
        matches!(self, Self::IssueStatus)
    }

    /// Whether this kind carries a `counts_as_done` flag (the status kind).
    ///
    /// Independent of [`Self::has_closed`]: that one answers "is the issue
    /// closed", this one answers "is there work left", and a project may
    /// answer them differently.
    #[must_use]
    pub const fn has_counts_as_done(self) -> bool {
        matches!(self, Self::IssueStatus)
    }

    /// Whether this kind carries an `is_new` flag (the status kind). The "new"
    /// status is the default column a freshly created issue lands in; at most
    /// one status per project may carry it.
    #[must_use]
    pub const fn has_new(self) -> bool {
        matches!(self, Self::IssueStatus)
    }

    /// Whether this kind carries a numeric `value` (size ordinal only).
    #[must_use]
    pub const fn has_value(self) -> bool {
        matches!(self, Self::Size)
    }
}

/// A taxonomy item as returned by the API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TaxonomyItem {
    pub id: Uuid,
    pub project_id: Uuid,
    pub kind: TaxonomyKind,
    pub name: String,
    pub slug: String,
    pub color: String,
    #[serde(default)]
    pub emoji: String,
    pub order: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_closed: Option<bool>,
    /// Whether epic and milestone progress count this status as finished work
    /// (status kind only). Independent of `is_closed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts_as_done: Option<bool>,
    /// The "new" status flag (status kind only): the default column a new issue
    /// lands in. At most one status per project carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_new: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A built-in taxonomy item seeded into every new project.
#[derive(Debug, Clone)]
pub struct DefaultTaxonomyItem {
    pub kind: TaxonomyKind,
    pub name: &'static str,
    pub slug: &'static str,
    pub color: &'static str,
    pub is_closed: Option<bool>,
    pub counts_as_done: Option<bool>,
    pub is_new: Option<bool>,
    pub value: Option<f64>,
}

/// The default taxonomy seeded on project creation.
#[must_use]
pub fn default_taxonomies() -> Vec<DefaultTaxonomyItem> {
    use TaxonomyKind::{IssueStatus, IssueType, Priority, Size};

    // `closed` and `done` are separate arguments on purpose: the seeded
    // statuses happen to agree, but nothing requires them to.
    let status = |kind: TaxonomyKind,
                  name: &'static str,
                  slug: &'static str,
                  color: &'static str,
                  closed: bool,
                  done: bool,
                  is_new: bool| {
        DefaultTaxonomyItem {
            kind,
            name,
            slug,
            color,
            is_closed: Some(closed),
            counts_as_done: Some(done),
            is_new: Some(is_new),
            value: None,
        }
    };
    let plain =
        |kind: TaxonomyKind, name: &'static str, slug: &'static str, color: &'static str| {
            DefaultTaxonomyItem {
                kind,
                name,
                slug,
                color,
                is_closed: None,
                counts_as_done: None,
                is_new: None,
                value: None,
            }
        };
    let size = |name: &'static str, slug: &'static str, color: &'static str, ordinal: f64| {
        DefaultTaxonomyItem {
            kind: Size,
            name,
            slug,
            color,
            is_closed: None,
            counts_as_done: None,
            is_new: None,
            value: Some(ordinal),
        }
    };

    vec![
        // Unified issue statuses (shared by every issue type). "New" is the
        // default landing column for freshly created issues.
        status(IssueStatus, "New", "new", "#999999", false, false, true),
        status(
            IssueStatus,
            "Ready",
            "ready",
            "#ff8a84",
            false,
            false,
            false,
        ),
        status(
            IssueStatus,
            "In progress",
            "in-progress",
            "#ffcc00",
            false,
            false,
            false,
        ),
        status(
            IssueStatus,
            "Ready for test",
            "ready-for-test",
            "#9dce0a",
            false,
            false,
            false,
        ),
        status(IssueStatus, "Done", "done", "#669900", true, true, false),
        status(
            IssueStatus,
            "Archived",
            "archived",
            "#5c3566",
            true,
            true,
            false,
        ),
        // Issue types (the work-item discriminator: Story / Task / Bug / …)
        plain(IssueType, "Story", "story", "#3b7dd8"),
        plain(IssueType, "Task", "task", "#669900"),
        plain(IssueType, "Bug", "bug", "#cc0000"),
        plain(IssueType, "Enhancement", "enhancement", "#9dce0a"),
        plain(IssueType, "Question", "question", "#0079bc"),
        // Priority (merged from the old priority + severity into one scale)
        plain(Priority, "Low", "low", "#999999"),
        plain(Priority, "Medium", "medium", "#ffcc00"),
        plain(Priority, "High", "high", "#ff7518"),
        plain(Priority, "Critical", "critical", "#cc0000"),
        plain(Priority, "Blocker", "blocker", "#5c3566"),
        // Size (T-shirt estimation; `value` is the ordinal used to scale the
        // size badge in the UI)
        size("XS", "xs", "#9dce0a", 1.0),
        size("S", "s", "#669900", 2.0),
        size("M", "m", "#ffcc00", 3.0),
        size("L", "l", "#ff7518", 4.0),
        size("XL", "xl", "#cc0000", 5.0),
        size("XXL", "xxl", "#990000", 6.0),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::type_complexity)]
    use super::*;

    #[test]
    fn kind_round_trips() {
        for s in ["issue_status", "issue_type", "priority", "size"] {
            assert_eq!(TaxonomyKind::parse(s).unwrap().as_str(), s);
        }
        assert!(TaxonomyKind::parse("nope").is_none());
        assert!(TaxonomyKind::parse("severity").is_none());
        assert!(TaxonomyKind::parse("point").is_none());
    }

    #[test]
    fn defaults_snapshot() {
        let rows: Vec<(
            String,
            String,
            String,
            Option<bool>,
            Option<bool>,
            Option<f64>,
        )> = default_taxonomies()
            .into_iter()
            .map(|d| {
                (
                    d.kind.as_str().to_owned(),
                    d.slug.to_owned(),
                    d.color.to_owned(),
                    d.is_closed,
                    d.counts_as_done,
                    d.value,
                )
            })
            .collect();
        insta::assert_json_snapshot!(rows);
    }

    #[test]
    fn statuses_have_closed_flag() {
        for d in default_taxonomies() {
            if d.kind.has_closed() {
                assert!(d.is_closed.is_some(), "{} must set is_closed", d.slug);
            }
            if d.kind.has_counts_as_done() {
                assert!(
                    d.counts_as_done.is_some(),
                    "{} must set counts_as_done",
                    d.slug
                );
            } else {
                assert!(
                    d.counts_as_done.is_none(),
                    "{} must not set counts_as_done",
                    d.slug
                );
            }
            if d.kind.has_value() {
                // every size carries its ordinal value
                assert!(d.value.is_some(), "{} must set value", d.slug);
            }
        }
    }
}
