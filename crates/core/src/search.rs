//! Search result type.

use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SearchHit {
    pub entity_type: String,
    pub entity_id: Uuid,
    pub project_id: Uuid,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<i64>,
    /// Rendered key for work items: `PS-1262` for issues, `PS-E-12` for epics.
    /// Absent for wiki pages and comments, or a project without a prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The hit is an exact key match (`PS-1262`, `#1262`, `1262`), not a text
    /// match. Key hits are always ranked ahead of text hits.
    pub key_match: bool,
    pub title: String,
    /// HTML-sanitized snippet (≤ 200 chars), highlights in `<b>`.
    pub snippet: String,
    pub rank: f32,
}

/// Which work-item counter a typed key refers to. Issues and epics number
/// independently, so `PS-12` and `PS-E-12` are different items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Issue,
    Epic,
    /// A bare number (`1262`, `#1262`): either counter may hold it.
    Any,
}

impl KeyKind {
    /// The `search_index.entity_type` values this kind can match.
    #[must_use]
    pub const fn entity_types(self) -> &'static [&'static str] {
        match self {
            Self::Issue => &["issue"],
            Self::Epic => &["epic"],
            Self::Any => &["issue", "epic"],
        }
    }
}

/// A query that reads as a work-item key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyQuery {
    /// Upper-cased project prefix, when one was typed.
    pub prefix: Option<String>,
    pub number: i64,
    pub kind: KeyKind,
}

/// Recognise a work-item key: `PS-1262`, `ps-1262`, `PS1262`, `PS-E-12`,
/// `ps-e12`, `#1262`, or a bare `1262`. Anything else is `None` and is
/// searched as text only.
#[must_use]
pub fn parse_key(q: &str) -> Option<KeyQuery> {
    let q = q.trim();
    let bare = q.strip_prefix('#').unwrap_or(q);
    if let Some(number) = parse_number(bare) {
        return Some(KeyQuery {
            prefix: None,
            number,
            kind: KeyKind::Any,
        });
    }
    let letters = q.bytes().take_while(u8::is_ascii_alphabetic).count();
    if !(2..=3).contains(&letters) {
        return None;
    }
    let (prefix, rest) = q.split_at(letters);
    let rest = rest.strip_prefix('-').unwrap_or(rest);
    let (kind, digits) = rest
        .strip_prefix(['E', 'e'])
        .map_or((KeyKind::Issue, rest), |d| {
            (KeyKind::Epic, d.strip_prefix('-').unwrap_or(d))
        });
    Some(KeyQuery {
        prefix: Some(prefix.to_ascii_uppercase()),
        number: parse_number(digits)?,
        kind,
    })
}

fn parse_number(s: &str) -> Option<i64> {
    if s.is_empty() || s.len() > 18 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| *n > 0)
}

/// Most query words taken into the prefix query; the rest are ignored.
const PREFIX_QUERY_MAX_TERMS: usize = 8;

/// A `to_tsquery('simple', …)` string matching every word of `q`, the last as
/// a prefix (`'deploy' & 'pipel':*`).
///
/// Results thus appear while a word is still being typed. Words are split on anything that is not a letter or
/// digit, so the output never carries tsquery syntax from the user. `None`
/// when `q` has no words.
#[must_use]
pub fn prefix_tsquery(q: &str) -> Option<String> {
    let words: Vec<String> = q
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .take(PREFIX_QUERY_MAX_TERMS)
        .map(str::to_lowercase)
        .collect();
    let (last, init) = words.split_last()?;
    let mut out = String::new();
    for w in init {
        out.push('\'');
        out.push_str(w);
        out.push_str("' & ");
    }
    out.push('\'');
    out.push_str(last);
    out.push_str("':*");
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn key(prefix: Option<&str>, number: i64, kind: KeyKind) -> KeyQuery {
        KeyQuery {
            prefix: prefix.map(str::to_owned),
            number,
            kind,
        }
    }

    #[test]
    fn parses_issue_keys_in_any_case() {
        assert_eq!(
            parse_key("PS-1262"),
            Some(key(Some("PS"), 1262, KeyKind::Issue))
        );
        assert_eq!(
            parse_key("ps-1262"),
            Some(key(Some("PS"), 1262, KeyKind::Issue))
        );
        assert_eq!(
            parse_key(" Ps1262 "),
            Some(key(Some("PS"), 1262, KeyKind::Issue))
        );
        assert_eq!(
            parse_key("ABC-7"),
            Some(key(Some("ABC"), 7, KeyKind::Issue))
        );
    }

    #[test]
    fn parses_epic_keys() {
        assert_eq!(
            parse_key("PS-E-12"),
            Some(key(Some("PS"), 12, KeyKind::Epic))
        );
        assert_eq!(
            parse_key("ps-e-12"),
            Some(key(Some("PS"), 12, KeyKind::Epic))
        );
        assert_eq!(
            parse_key("PS-E12"),
            Some(key(Some("PS"), 12, KeyKind::Epic))
        );
        assert_eq!(
            parse_key("PSE-12"),
            Some(key(Some("PSE"), 12, KeyKind::Issue))
        );
    }

    #[test]
    fn parses_bare_and_hash_numbers() {
        assert_eq!(parse_key("1262"), Some(key(None, 1262, KeyKind::Any)));
        assert_eq!(parse_key("#1262"), Some(key(None, 1262, KeyKind::Any)));
    }

    #[test]
    fn rejects_non_keys() {
        for q in [
            "",
            "deployment",
            "P-1",
            "ABCD-1",
            "PS-",
            "PS-E-",
            "PS-12a",
            "0",
            "#",
            "PS 12",
            "1262 bug",
            "99999999999999999999",
        ] {
            assert_eq!(parse_key(q), None, "{q:?}");
        }
    }

    #[test]
    fn prefix_query_quotes_words_and_prefixes_the_last() {
        assert_eq!(prefix_tsquery("deplo").unwrap(), "'deplo':*");
        assert_eq!(
            prefix_tsquery("Deployment  pipel").unwrap(),
            "'deployment' & 'pipel':*"
        );
        assert_eq!(prefix_tsquery("Überweisung").unwrap(), "'überweisung':*");
        assert_eq!(prefix_tsquery("a & b | !c:*").unwrap(), "'a' & 'b' & 'c':*");
        assert_eq!(prefix_tsquery("(( :*!&| '\""), None);
    }
}
