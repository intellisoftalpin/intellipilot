//! Per-project taxonomy: statuses, issue types, priorities, severities, points.
//!
//! All kinds share one storage shape (`taxonomy_items`) with kind-specific
//! fields left `None` where not applicable. With the unified backlog there is
//! a single `issue_status` workflow shared by every issue (Story/Task/Bug);
//! the issue *type* is itself a taxonomy (`issue_type`).

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
    Severity,
    Point,
}

impl TaxonomyKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IssueStatus => "issue_status",
            Self::IssueType => "issue_type",
            Self::Priority => "priority",
            Self::Severity => "severity",
            Self::Point => "point",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "issue_status" => Self::IssueStatus,
            "issue_type" => Self::IssueType,
            "priority" => Self::Priority,
            "severity" => Self::Severity,
            "point" => Self::Point,
            _ => return None,
        })
    }

    /// Whether this kind carries an `is_closed` flag (the status kind).
    #[must_use]
    pub const fn has_closed(self) -> bool {
        matches!(self, Self::IssueStatus)
    }

    /// Whether this kind carries a numeric `value` (points only).
    #[must_use]
    pub const fn has_value(self) -> bool {
        matches!(self, Self::Point)
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
    pub order: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_closed: Option<bool>,
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
    pub value: Option<f64>,
}

/// The default taxonomy seeded on project creation.
#[must_use]
pub fn default_taxonomies() -> Vec<DefaultTaxonomyItem> {
    use TaxonomyKind::{IssueStatus, IssueType, Point, Priority, Severity};

    let status = |kind: TaxonomyKind,
                  name: &'static str,
                  slug: &'static str,
                  color: &'static str,
                  closed: bool| {
        DefaultTaxonomyItem {
            kind,
            name,
            slug,
            color,
            is_closed: Some(closed),
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
                value: None,
            }
        };
    let point = |name: &'static str, slug: &'static str, value: Option<f64>| DefaultTaxonomyItem {
        kind: Point,
        name,
        slug,
        color: "",
        is_closed: None,
        value,
    };

    vec![
        // Unified issue statuses (shared by every issue type)
        status(IssueStatus, "New", "new", "#999999", false),
        status(IssueStatus, "Ready", "ready", "#ff8a84", false),
        status(IssueStatus, "In progress", "in-progress", "#ffcc00", false),
        status(
            IssueStatus,
            "Ready for test",
            "ready-for-test",
            "#9dce0a",
            false,
        ),
        status(IssueStatus, "Done", "done", "#669900", true),
        status(IssueStatus, "Archived", "archived", "#5c3566", true),
        // Issue types (the work-item discriminator: Story / Task / Bug / …)
        plain(IssueType, "Story", "story", "#3b7dd8"),
        plain(IssueType, "Task", "task", "#669900"),
        plain(IssueType, "Bug", "bug", "#cc0000"),
        plain(IssueType, "Enhancement", "enhancement", "#9dce0a"),
        plain(IssueType, "Question", "question", "#0079bc"),
        // Priorities
        plain(Priority, "Low", "low", "#999999"),
        plain(Priority, "Normal", "normal", "#ffcc00"),
        plain(Priority, "High", "high", "#cc0000"),
        // Severities
        plain(Severity, "Wishlist", "wishlist", "#999999"),
        plain(Severity, "Minor", "minor", "#0079bc"),
        plain(Severity, "Normal", "normal", "#669900"),
        plain(Severity, "Important", "important", "#ffcc00"),
        plain(Severity, "Critical", "critical", "#cc0000"),
        // Points
        point("?", "unset", None),
        point("0", "0", Some(0.0)),
        point("1/2", "half", Some(0.5)),
        point("1", "1", Some(1.0)),
        point("2", "2", Some(2.0)),
        point("3", "3", Some(3.0)),
        point("5", "5", Some(5.0)),
        point("8", "8", Some(8.0)),
        point("13", "13", Some(13.0)),
        point("20", "20", Some(20.0)),
        point("40", "40", Some(40.0)),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::type_complexity)]
    use super::*;

    #[test]
    fn kind_round_trips() {
        for s in [
            "issue_status",
            "issue_type",
            "priority",
            "severity",
            "point",
        ] {
            assert_eq!(TaxonomyKind::parse(s).unwrap().as_str(), s);
        }
        assert!(TaxonomyKind::parse("nope").is_none());
        assert!(TaxonomyKind::parse("us_status").is_none());
        assert!(TaxonomyKind::parse("task_status").is_none());
    }

    #[test]
    fn defaults_snapshot() {
        let rows: Vec<(String, String, String, Option<bool>, Option<f64>)> = default_taxonomies()
            .into_iter()
            .map(|d| {
                (
                    d.kind.as_str().to_owned(),
                    d.slug.to_owned(),
                    d.color.to_owned(),
                    d.is_closed,
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
            if d.kind.has_value() {
                // points carry a value (except the "?" sentinel)
                assert!(d.value.is_some() || d.slug == "unset");
            }
        }
    }
}
