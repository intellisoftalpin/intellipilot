//! Path normalization and jail resolution for documentation sources.
//!
//! Two rules define the whole feature's containment:
//!
//! 1. A source's configured `doc_path` is stored **normalized** — relative,
//!    slash-separated, no empty segments, no `.` or `..`, no backslashes, no
//!    control characters. [`normalize`] is the only way to produce one, and
//!    the `doc_sources_path_normalized` CHECK constraint re-states the rule in
//!    the database so no code path can plant a bad value.
//!
//! 2. Every path a client asks for is resolved *lexically* against the jail by
//!    [`resolve`] before any git call. `..` is honoured during resolution and
//!    then checked: anything landing outside the jail is rejected, never
//!    clamped. Clamping (silently rewriting `../../etc` to `etc`) would serve
//!    the wrong file instead of refusing — so this module always refuses.
//!
//! Note that content is read from git *tree objects*, not from the
//! filesystem, so even a resolution bug could not reach outside the
//! repository. This module is the layer that keeps it inside the *subtree*.

/// Longest accepted full path, in bytes.
const MAX_PATH_LEN: usize = 1024;
/// Longest accepted single segment, in bytes.
const MAX_SEGMENT_LEN: usize = 255;

/// Why a path was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Contains a NUL or other control character, or a backslash.
    Illegal,
    /// Exceeds the length caps.
    TooLong,
    /// Resolves above the jail root.
    Escapes,
}

impl PathError {
    /// Stable wire code used in problem+json responses.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Illegal => "doc_path_illegal",
            Self::TooLong => "doc_path_too_long",
            Self::Escapes => "doc_path_escapes",
        }
    }
}

/// Reject characters that have no business in a repository path: control
/// characters (including NUL), and backslashes — which some clients and file
/// systems treat as separators, so allowing them would create a second,
/// unchecked separator.
fn has_illegal_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || c == '\\')
}

/// Normalize a user-supplied jail path into stored form.
///
/// Accepts leading/trailing slashes and `.` segments for convenience (users
/// paste `/docs/public/`), but **never** `..` — a configured jail that climbs
/// out of the repository root is a configuration error, not something to
/// resolve.
///
/// Returns the empty string for "the whole repository".
///
/// # Errors
/// [`PathError::Illegal`] for control characters, backslashes or a `..`
/// segment; [`PathError::TooLong`] when a length cap is exceeded.
pub fn normalize(input: &str) -> Result<String, PathError> {
    if has_illegal_chars(input) {
        return Err(PathError::Illegal);
    }
    if input.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong);
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in input.split('/') {
        match seg {
            // Empty segments come from leading, trailing and doubled slashes.
            "" | "." => {}
            ".." => return Err(PathError::Illegal),
            s if s.len() > MAX_SEGMENT_LEN => return Err(PathError::TooLong),
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    if joined.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong);
    }
    Ok(joined)
}

/// Resolve a jail-relative request path, honouring `.` and `..`.
///
/// The result is a normalized jail-relative path (never leading with `/`),
/// suitable for passing to [`in_repo`]. An empty result means the jail root
/// itself.
///
/// # Errors
/// [`PathError::Escapes`] when the path climbs above the jail root — the case
/// this whole module exists to catch.
pub fn resolve(rel: &str) -> Result<String, PathError> {
    if has_illegal_chars(rel) {
        return Err(PathError::Illegal);
    }
    if rel.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong);
    }
    // A leading slash is treated as "relative to the jail root", not as a
    // filesystem absolute path: inside the viewer the jail *is* the root.
    let mut out: Vec<&str> = Vec::new();
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                // Popping past the start means the path leaves the jail.
                if out.pop().is_none() {
                    return Err(PathError::Escapes);
                }
            }
            s if s.len() > MAX_SEGMENT_LEN => return Err(PathError::TooLong),
            s => out.push(s),
        }
    }
    Ok(out.join("/"))
}

/// Join an already-[`resolve`]d jail-relative path onto the source's jail to
/// get the path to look up in the repository tree.
///
/// Both inputs must already be normalized; this only concatenates.
#[must_use]
pub fn in_repo(jail: &str, resolved_rel: &str) -> String {
    match (jail.is_empty(), resolved_rel.is_empty()) {
        (true, _) => resolved_rel.to_owned(),
        (false, true) => jail.to_owned(),
        (false, false) => format!("{jail}/{resolved_rel}"),
    }
}

/// Resolve a link found *inside* a document.
///
/// `from` is the jail-relative path of the document containing the link, and
/// `href` the raw link target. Relative links resolve against the document's
/// directory, exactly as a git host would resolve them; a leading `/` is
/// treated as jail-root-relative.
///
/// # Errors
/// [`PathError::Escapes`] when the link points above the jail. Callers turn
/// that into a redirect to the source's web URL rather than an error.
pub fn resolve_link(from: &str, href: &str) -> Result<String, PathError> {
    if href.starts_with('/') {
        return resolve(href);
    }
    let dir = from.rsplit_once('/').map_or("", |(d, _)| d);
    if dir.is_empty() {
        resolve(href)
    } else {
        resolve(&format!("{dir}/{href}"))
    }
}

/// Extensions rendered as documents. Everything else is invisible in the tree.
const DOC_EXTENSIONS: [&str; 3] = ["md", "markdown", "txt"];

/// Is this filename a renderable document?
#[must_use]
pub fn is_doc(name: &str) -> bool {
    extension(name).is_some_and(|e| DOC_EXTENSIONS.contains(&e.as_str()))
}

/// Image extensions servable through the blob endpoint, with their mime type.
/// SVG is included but is sanitized before it leaves the server.
const IMAGE_TYPES: [(&str, &str); 6] = [
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("svg", "image/svg+xml"),
];

/// Mime type for a servable image, or `None` if the file is not one.
#[must_use]
pub fn image_mime(name: &str) -> Option<&'static str> {
    let ext = extension(name)?;
    IMAGE_TYPES
        .iter()
        .find(|(e, _)| *e == ext)
        .map(|(_, mime)| *mime)
}

/// Is this an SVG, which needs sanitizing before being served?
#[must_use]
pub fn is_svg(name: &str) -> bool {
    extension(name).is_some_and(|e| e == "svg")
}

/// Lowercase extension of the final path segment, without the dot.
fn extension(name: &str) -> Option<String> {
    let file = name.rsplit('/').next()?;
    let (stem, ext) = file.rsplit_once('.')?;
    // A dotfile like `.gitignore` has an empty stem and no real extension.
    if stem.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// Candidate homepage filenames, in preference order. Matched
/// case-insensitively against the entries at the jail root.
pub const ENTRY_CANDIDATES: [&str; 6] = [
    "readme.md",
    "readme.markdown",
    "readme.txt",
    "index.md",
    "index.markdown",
    "home.md",
];

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn normalize_strips_decoration() {
        assert_eq!(normalize("/docs/public/").unwrap(), "docs/public");
        assert_eq!(normalize("docs//public").unwrap(), "docs/public");
        assert_eq!(normalize("./docs/./public").unwrap(), "docs/public");
        assert_eq!(normalize("").unwrap(), "");
        assert_eq!(normalize("/").unwrap(), "");
        assert_eq!(
            normalize("pass/new_version/official-docs/").unwrap(),
            "pass/new_version/official-docs"
        );
    }

    #[test]
    fn normalize_refuses_traversal_and_junk() {
        for bad in [
            "../etc",
            "docs/../..",
            "docs/../../secret",
            "..",
            "docs/..",
            "a\\b",
            "a\0b",
            "a\nb",
        ] {
            assert_eq!(
                normalize(bad).unwrap_err(),
                PathError::Illegal,
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn normalize_enforces_length_caps() {
        assert_eq!(
            normalize(&"a".repeat(MAX_SEGMENT_LEN + 1)).unwrap_err(),
            PathError::TooLong
        );
        assert_eq!(
            normalize(&"a/".repeat(MAX_PATH_LEN)).unwrap_err(),
            PathError::TooLong
        );
    }

    #[test]
    fn resolve_handles_dot_segments() {
        assert_eq!(resolve("guides/./intro.md").unwrap(), "guides/intro.md");
        assert_eq!(
            resolve("guides/sub/../intro.md").unwrap(),
            "guides/intro.md"
        );
        assert_eq!(resolve("/guides/intro.md").unwrap(), "guides/intro.md");
        assert_eq!(resolve("").unwrap(), "");
    }

    /// The central security property: nothing may resolve above the jail, and
    /// an escaping path is *refused*, never silently clamped.
    #[test]
    fn resolve_refuses_every_escape() {
        for bad in [
            "..",
            "../secret.md",
            "../../etc/passwd",
            "guides/../../secret.md",
            "a/b/c/../../../../x",
            "./../x",
        ] {
            assert_eq!(
                resolve(bad).unwrap_err(),
                PathError::Escapes,
                "{bad:?} should escape"
            );
        }
        // Descending and returning to the root is fine — it stays inside.
        assert_eq!(resolve("guides/../intro.md").unwrap(), "intro.md");
    }

    #[test]
    fn resolve_refuses_illegal_characters() {
        for bad in ["a\\b", "a\0b", "a\u{7f}b"] {
            assert_eq!(resolve(bad).unwrap_err(), PathError::Illegal);
        }
    }

    #[test]
    fn in_repo_joins_without_double_slashes() {
        assert_eq!(in_repo("", "intro.md"), "intro.md");
        assert_eq!(in_repo("docs", "intro.md"), "docs/intro.md");
        assert_eq!(in_repo("docs", ""), "docs");
        assert_eq!(in_repo("", ""), "");
    }

    #[test]
    fn links_resolve_against_the_containing_directory() {
        assert_eq!(
            resolve_link("guides/intro.md", "setup.md").unwrap(),
            "guides/setup.md"
        );
        assert_eq!(
            resolve_link("guides/intro.md", "./setup.md").unwrap(),
            "guides/setup.md"
        );
        assert_eq!(
            resolve_link("guides/intro.md", "../api/ref.md").unwrap(),
            "api/ref.md"
        );
        assert_eq!(
            resolve_link("guides/intro.md", "/top.md").unwrap(),
            "top.md"
        );
        assert_eq!(resolve_link("intro.md", "other.md").unwrap(), "other.md");
    }

    /// A link climbing above the jail is an escape the caller turns into a
    /// redirect to the source host — it must not resolve to anything.
    #[test]
    fn links_above_the_jail_escape() {
        assert_eq!(
            resolve_link("intro.md", "../secret.md").unwrap_err(),
            PathError::Escapes
        );
        assert_eq!(
            resolve_link("guides/intro.md", "../../secret.md").unwrap_err(),
            PathError::Escapes
        );
    }

    #[test]
    fn doc_and_image_classification() {
        assert!(is_doc("a.md"));
        assert!(is_doc("a.MD"));
        assert!(is_doc("a.markdown"));
        assert!(is_doc("dir/notes.txt"));
        assert!(!is_doc("a.png"));
        assert!(!is_doc("Makefile"));
        assert!(!is_doc(".gitignore"));

        assert_eq!(image_mime("a.PNG"), Some("image/png"));
        assert_eq!(image_mime("d/b.jpeg"), Some("image/jpeg"));
        assert_eq!(image_mime("c.svg"), Some("image/svg+xml"));
        assert_eq!(image_mime("c.exe"), None);
        assert_eq!(image_mime("c.md"), None);
        assert!(is_svg("x.SVG"));
        assert!(!is_svg("x.png"));
    }
}
