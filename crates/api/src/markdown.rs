//! Markdown rendering with defense-in-depth sanitization.
//!
//! Two layers protect against stored XSS:
//! 1. comrak renders with raw-HTML passthrough **disabled**, so any inline
//!    HTML in the source is escaped rather than emitted.
//! 2. the generated HTML is then run through ammonia's allowlist, which strips
//!    `<script>`, event handlers, `javascript:` URLs, etc.

use std::sync::LazyLock;

use comrak::Options;

static OPTIONS: LazyLock<Options> = LazyLock::new(|| {
    let mut o = Options::default();
    // Common GFM-ish niceties, all safe.
    o.extension.strikethrough = true;
    o.extension.table = true;
    o.extension.autolink = true;
    o.extension.tasklist = true;
    // Critically: never emit raw/inline HTML from the source.
    o.render.unsafe_ = false;
    o.render.escape = true;
    o
});

/// Render untrusted markdown to sanitized HTML safe for storage and display.
#[must_use]
pub fn render(md: &str) -> String {
    let raw = comrak::markdown_to_html(md, &OPTIONS);
    ammonia::clean(&raw)
}

/// Sanitize a raw HTML fragment (e.g. a search snippet) through the ammonia
/// allowlist, then truncate to `max` characters on a char boundary.
#[must_use]
pub fn sanitize_snippet(html: &str, max: usize) -> String {
    let clean = ammonia::clean(html);
    if clean.chars().count() <= max {
        return clean;
    }
    clean.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_basic_markdown() {
        let html = render("# Title\n\nsome **bold** text");
        assert!(html.contains("<h1>"));
        assert!(html.contains("<strong>bold</strong>"));
    }

    #[test]
    fn strips_xss_payloads() {
        // A representative slice of the OWASP XSS filter-evasion cheat sheet.
        let payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "<a href=\"javascript:alert(1)\">click</a>",
            "<svg/onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<a href=\"data:text/html,<script>alert(1)</script>\">x</a>",
            "<math><mtext><script>alert(1)</script></mtext></math>",
            "<input autofocus onfocus=alert(1)>",
            "<marquee onstart=alert(1)>x</marquee>",
            "[click](javascript:alert(1))",
            "<style>body{background:url('javascript:alert(1)')}</style>",
        ];
        // Any dangerous construct must be neutralized: raw HTML is escaped
        // (so `<tag` never appears as a real element) and bad URL schemes are
        // stripped. Note: escaped text like `&lt;img ... onerror=...&gt;` is
        // inert, so we check for *unescaped* tags rather than substrings.
        // Real (unescaped) dangerous tags, and real anchors carrying an
        // executable URL scheme. Escaped raw HTML renders as `&lt;…` text, so
        // it never matches these — and inert text can't execute.
        let forbidden = [
            "<script",
            "<iframe",
            "<svg",
            "<img",
            "<body",
            "<details",
            "<input",
            "<marquee",
            "<math",
            "<style",
            "<object",
            "<embed",
            "<a href=\"javascript",
            "<a href=\"data",
        ];
        for p in payloads {
            let html = render(p).to_lowercase();
            for needle in forbidden {
                assert!(
                    !html.contains(needle),
                    "`{needle}` survived: {p:?} -> {html:?}"
                );
            }
        }
    }
}
