//! Filename sanitization. Guarantees the result is a single safe path
//! component: no separators, no traversal, no control characters.

/// Maximum length of a sanitized filename (bytes).
const MAX_LEN: usize = 200;

/// Reduce an arbitrary client-supplied filename to a safe basename.
///
/// Properties (see tests): the result never contains `/`, `\`, or NUL, is
/// never `.`/`..`, never empty, and is at most [`MAX_LEN`] bytes.
#[must_use]
pub fn sanitize_filename(raw: &str) -> String {
    // Take the last path component under both unix and windows separators.
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);

    let mut out = String::with_capacity(base.len().min(MAX_LEN));
    for ch in base.chars() {
        // Drop control chars, NUL, and path separators; collapse the rest.
        if ch.is_control() || matches!(ch, '/' | '\\' | '\0') {
            continue;
        }
        out.push(ch);
    }

    // Trim leading/trailing dots and whitespace (hidden files, "..", Windows
    // trailing-dot quirks).
    let trimmed = out.trim().trim_matches('.').trim();
    let mut result = trimmed.to_owned();

    if result.len() > MAX_LEN {
        // Truncate on a char boundary.
        let mut end = MAX_LEN;
        while !result.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        result.truncate(end);
        result = result.trim_matches('.').to_owned();
    }

    if result.is_empty() || result == "." || result == ".." {
        return "file".to_owned();
    }
    result
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unreadable_literal,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    #[test]
    fn strips_paths_and_traversal() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("/abs/path/report.pdf"), "report.pdf");
        assert_eq!(
            sanitize_filename(r"C:\Windows\system32\evil.exe"),
            "evil.exe"
        );
        assert_eq!(sanitize_filename(".."), "file");
        assert_eq!(sanitize_filename("..."), "file");
        assert_eq!(sanitize_filename(""), "file");
        assert_eq!(sanitize_filename("a/b/c/"), "file");
    }

    #[test]
    fn drops_control_chars() {
        assert_eq!(sanitize_filename("ev\0il\n.txt"), "evil.txt");
    }

    #[test]
    fn property_never_escapes_a_path() {
        // 1k crafted names: the result must always be a single, safe component.
        let pieces = [
            "..",
            "../",
            "..\\",
            "/",
            "\\",
            "%2e%2e",
            "\0",
            "\n",
            "\t",
            "a",
            "..%2f",
            "....//",
            "con",
            "foo.txt",
            "résumé.pdf",
            " ",
            ".",
            ".hidden",
            "a/b",
            "x\\y",
        ];
        let mut seed = 0x1234_5678_u64;
        for _ in 0..1000 {
            // Cheap LCG to assemble pseudo-random crafted names.
            let mut name = String::new();
            for _ in 0..6 {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let idx = (seed >> 33) as usize % pieces.len();
                name.push_str(pieces[idx]);
            }
            let s = sanitize_filename(&name);
            assert!(!s.contains('/'), "no forward slash: {s:?} from {name:?}");
            assert!(!s.contains('\\'), "no backslash: {s:?} from {name:?}");
            assert!(!s.contains('\0'), "no NUL: {s:?} from {name:?}");
            assert!(s != "." && s != "..", "no dot dirs: {s:?} from {name:?}");
            assert!(!s.is_empty(), "never empty: from {name:?}");
            assert!(!s.starts_with('.'), "no leading dot: {s:?} from {name:?}");
            // A sanitized name must join to a child path, never escaping root.
            let joined = std::path::Path::new("/srv/data").join(&s);
            assert!(
                joined.starts_with("/srv/data/"),
                "stays under root: {joined:?}"
            );
        }
    }
}
