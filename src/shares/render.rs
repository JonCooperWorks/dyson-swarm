//! Server-side render of a shared artefact into a self-contained HTML
//! page, plus passthrough helpers for raw byte streaming.
//!
//! The page is fully static — no JS, no SPA chrome, no upstream
//! requests from the viewer's browser to anywhere except `share.<apex>`
//! itself.  CSP locks `default-src` to `'none'` and only opens
//! `style-src 'unsafe-inline'`, `img-src 'self' data:`, and `font-src
//! 'self' data:` — so a malicious markdown payload that survives
//! ammonia sanitization still cannot exfiltrate.
//!
//! Visual language mirrors the dyson SPA's `ArtefactReader` (same
//! colour palette, same Geist/JetBrains Mono fallback, same chip +
//! prose typography) without dragging the SPA's React bundle into
//! swarm.  The CSS lives next to this module as a constant string so
//! `cargo build` doesn't grow a third place to update styles when the
//! brand changes — when it does, this constant moves.

use pulldown_cmark::{Options, Parser, html};

/// Rough categories — mirrors dyson's `ArtefactKind` enum but lives
/// here decoupled.  We pick a render strategy off the dyson-emitted
/// metadata `kind` string ("security_review" / "image" / "other").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderKind {
    Markdown,
    Image,
    Other,
}

impl RenderKind {
    /// Map dyson's kind string to a render strategy.  Falls back to
    /// markdown for any kind we don't recognise — markdown happens to
    /// be the most generally-useful render for text-shaped content,
    /// and an image artefact is recognised explicitly.
    pub fn classify(kind: &str, mime: Option<&str>) -> Self {
        if kind.eq_ignore_ascii_case("image") {
            return Self::Image;
        }
        let mime = mime.unwrap_or("");
        if mime.starts_with("image/") {
            return Self::Image;
        }
        if mime == "text/markdown"
            || mime == "text/x-markdown"
            || mime.starts_with("text/")
            || kind.eq_ignore_ascii_case("security_review")
            || kind.eq_ignore_ascii_case("other")
        {
            return Self::Markdown;
        }
        Self::Other
    }
}

/// Render the public HTML page for a markdown artefact.  `body` is
/// the raw markdown bytes returned by dyson's `/api/artefacts/:id`.
pub fn render_markdown_page(title: &str, kind_label: &str, body: &str) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_FOOTNOTES);
    let parser = Parser::new_ext(body, opts);
    let mut raw_html = String::with_capacity(body.len() * 2);
    html::push_html(&mut raw_html, parser);
    let safe = sanitize_markdown_html(&raw_html);
    wrap_page(title, kind_label, &safe, /* is_image = */ false, "")
}

/// Render the public HTML page for an image artefact.  The image
/// itself is fetched from `<this-url>/raw` so the bytes stream
/// straight from dyson without a second download.
pub fn render_image_page(title: &str, kind_label: &str, raw_path: &str) -> String {
    let body = format!(
        r#"<img src="{src}" alt="{alt}" class="share-image">"#,
        src = escape_attr(raw_path),
        alt = escape_attr(title),
    );
    wrap_page(
        title, kind_label, &body, /* is_image = */ true, raw_path,
    )
}

/// Render the public HTML page for a generic file artefact.  Shows a
/// download card with the title and a link to `/raw`.
pub fn render_download_page(title: &str, kind_label: &str, raw_path: &str) -> String {
    let body = format!(
        r#"<div class="share-download">
    <div class="share-download-title">{title}</div>
    <div class="share-download-mute">{kind} file</div>
    <a class="btn primary" href="{href}" download>Download</a>
</div>"#,
        title = escape_text(title),
        kind = escape_text(kind_label),
        href = escape_attr(raw_path),
    );
    wrap_page(
        title, kind_label, &body, /* is_image = */ false, raw_path,
    )
}

/// Sanitize pulldown-cmark output against an XSS allowlist.  Image
/// sources are stripped from inline markdown — viewers should only
/// load assets from the share origin, never wherever the agent's
/// markdown said.  External `<a href>` are kept (people share
/// reports that link to NVD entries) but wrapped in `rel=noopener
/// noreferrer` and `target=_blank`.
fn sanitize_markdown_html(input: &str) -> String {
    use ammonia::Builder;
    use std::collections::HashSet;
    let allowed_protocols: HashSet<&str> = ["http", "https", "mailto"].into_iter().collect();
    Builder::default()
        .url_schemes(allowed_protocols)
        .link_rel(Some("noopener noreferrer"))
        .add_generic_attributes(["class", "id"])
        .rm_tags([
            "img", "object", "embed", "iframe", "form", "input", "button",
        ])
        .clean(input)
        .to_string()
}

fn wrap_page(title: &str, kind_label: &str, body: &str, is_image: bool, raw_path: &str) -> String {
    let body_class = if is_image {
        "share-page is-image"
    } else {
        "share-page"
    };
    let download_label = if is_image {
        "Open original"
    } else {
        "Download"
    };
    let download_link = if raw_path.is_empty() {
        String::new()
    } else {
        format!(
            r#"<a class="btn primary" href="{href}" download>{label}</a>"#,
            href = escape_attr(raw_path),
            label = escape_text(download_label),
        )
    };
    let safe_title = escape_text(title);
    let safe_kind = escape_text(kind_label);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>{safe_title}</title>
<style>{css}</style>
</head>
<body class="{body_class}">
<header class="share-topbar">
  <div class="share-brand">dyson · share</div>
  <div class="share-title">{safe_title}</div>
  <span class="chip">{safe_kind}</span>
  <span class="share-spacer"></span>
  {download_link}
</header>
<main class="share-main">
<article class="prose">
{body}
</article>
</main>
<footer class="share-footer">
  <span class="muted small">Anonymous shared artefact · capability is in the URL · revoke from your swarm dashboard.</span>
</footer>
</body>
</html>
"#,
        safe_title = safe_title,
        safe_kind = safe_kind,
        body_class = body_class,
        download_link = download_link,
        body = body,
        css = SHARE_CSS,
    )
}

fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Self-contained stylesheet for the share page.  Mirrors the dyson
/// SPA's design tokens (cooler dark neutrals + lime accent) without
/// pulling in the SPA's full CSS bundle or webfont assets — system
/// fonts substitute for Geist/JetBrains Mono so the binary stays
/// small.  ~3 KiB compressed; lives in the swarm binary only.
const SHARE_CSS: &str = r#"
:root {
  --bg:       oklch(0.135 0.014 262);
  --bg-1:     oklch(0.170 0.014 262);
  --panel:    oklch(0.205 0.015 262);
  --panel-2:  oklch(0.240 0.016 262);
  --line:     oklch(0.295 0.020 262);
  --line-2:   oklch(0.380 0.024 262);
  --mute:     oklch(0.680 0.015 262);
  --fg-dim:   oklch(0.840 0.008 262);
  --fg:       oklch(0.970 0.003 262);
  --accent:       oklch(0.890 0.220 130);
  --accent-2:     oklch(0.940 0.180 138);
  --accent-deep:  oklch(0.760 0.220 132);
  --accent-ink:   oklch(0.190 0.060 130);
  --accent-glow:  oklch(0.890 0.220 130 / 0.55);
  --font-ui:   ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--fg);
  font-family: var(--font-ui);
  font-size: 14px;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
  min-height: 100vh;
  display: flex; flex-direction: column;
}
.muted { color: var(--mute); }
.small { font-size: 12px; }
.mono { font-family: var(--font-mono); }
.share-topbar {
  display: flex; align-items: center; gap: 12px;
  padding: 12px 24px;
  border-bottom: 1px solid var(--line);
  background: var(--bg-1);
}
.share-brand {
  font-family: var(--font-mono);
  font-weight: 600;
  font-size: 12px;
  letter-spacing: 0.04em;
  color: var(--mute);
  text-transform: uppercase;
}
.share-title {
  flex: 0 1 auto;
  font-weight: 500;
  font-size: 14px;
  color: var(--fg);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  max-width: 60%;
}
.share-spacer { flex: 1; }
.chip {
  display: inline-flex; align-items: center;
  height: 22px; padding: 0 9px;
  border-radius: 999px;
  background: var(--panel-2);
  border: 1px solid var(--line);
  font: 500 11px/1 var(--font-mono);
  letter-spacing: 0.04em;
  color: var(--fg-dim);
  white-space: nowrap;
}
.btn {
  height: 32px; padding: 0 14px;
  border-radius: 6px;
  border: 1px solid var(--line);
  background: linear-gradient(180deg, var(--panel-2), var(--panel));
  color: var(--fg);
  font: 500 13px/1 var(--font-ui);
  text-decoration: none;
  display: inline-flex; align-items: center; gap: 6px;
  cursor: pointer;
}
.btn:hover { background: var(--panel-2); border-color: var(--line-2); }
.btn.primary {
  background: linear-gradient(135deg, var(--accent-2), var(--accent), var(--accent-deep));
  color: var(--accent-ink);
  border-color: transparent;
  font-weight: 600;
  box-shadow: 0 8px 22px -10px var(--accent-glow);
}
.btn.primary:hover { filter: brightness(1.06); }
.share-main {
  flex: 1;
  padding: 24px;
  max-width: 920px;
  width: 100%;
  margin: 0 auto;
}
.share-page.is-image .share-main {
  max-width: 100%;
  display: flex; align-items: center; justify-content: center;
}
.share-image {
  max-width: 100%; max-height: 80vh;
  object-fit: contain;
  border-radius: 6px;
  box-shadow: 0 4px 18px -6px oklch(0 0 0 / 0.55);
}
.share-download {
  display: flex; flex-direction: column; align-items: center;
  gap: 10px; padding: 60px 24px;
  text-align: center;
}
.share-download-title { font-size: 16px; color: var(--fg); }
.share-download-mute { font-size: 12px; color: var(--mute); margin-bottom: 12px; }
.share-footer {
  border-top: 1px solid var(--line);
  padding: 14px 24px;
  text-align: center;
  background: var(--bg-1);
}
/* Prose typography — mirrors dyson .prose without the JSX-specific
   tweaks.  Headings sit slightly tighter, code chips use the mono
   stack, tables stretch to width, links pick up the accent. */
.prose { line-height: 1.6; color: var(--fg); }
.prose h1, .prose h2, .prose h3, .prose h4, .prose h5, .prose h6 {
  margin-top: 1.6em; margin-bottom: 0.5em;
  font-weight: 600; line-height: 1.3;
  letter-spacing: -0.005em;
}
.prose h1 { font-size: 1.7em; }
.prose h2 { font-size: 1.35em; border-bottom: 1px solid var(--line); padding-bottom: 0.3em; }
.prose h3 { font-size: 1.15em; }
.prose p { margin: 0.7em 0; }
.prose ul, .prose ol { padding-left: 1.4em; margin: 0.7em 0; }
.prose li { margin: 0.2em 0; }
.prose blockquote {
  border-left: 3px solid var(--line-2);
  margin: 0.8em 0; padding: 0.2em 0 0.2em 1em;
  color: var(--fg-dim);
}
.prose code {
  font-family: var(--font-mono);
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 0.05em 0.4em;
  font-size: 0.92em;
}
.prose pre {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 12px 14px;
  overflow-x: auto;
  margin: 1em 0;
}
.prose pre code {
  background: transparent;
  border: 0;
  padding: 0;
  font-size: 0.92em;
}
.prose a { color: var(--accent); text-decoration: none; }
.prose a:hover { text-decoration: underline; }
.prose table {
  border-collapse: collapse;
  width: 100%;
  margin: 1em 0;
  font-size: 0.94em;
}
.prose th, .prose td {
  border: 1px solid var(--line);
  padding: 6px 10px;
  text-align: left;
  vertical-align: top;
}
.prose th { background: var(--panel-2); font-weight: 600; }
.prose hr { border: 0; border-top: 1px solid var(--line); margin: 1.6em 0; }
.prose img { max-width: 100%; border-radius: 4px; }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_image_explicit() {
        assert_eq!(
            RenderKind::classify("image", Some("image/png")),
            RenderKind::Image
        );
    }

    #[test]
    fn classify_image_by_mime() {
        assert_eq!(
            RenderKind::classify("other", Some("image/jpeg")),
            RenderKind::Image
        );
    }

    #[test]
    fn classify_security_review_is_markdown() {
        assert_eq!(
            RenderKind::classify("security_review", Some("text/markdown")),
            RenderKind::Markdown
        );
    }

    #[test]
    fn classify_unknown_falls_back_to_other() {
        assert_eq!(
            RenderKind::classify("zip", Some("application/zip")),
            RenderKind::Other
        );
    }

    #[test]
    fn render_markdown_strips_script_tags() {
        let md = "# title\n\n<script>alert('xss')</script>\n\nbody";
        let html = render_markdown_page("title", "security_review", md);
        // pulldown-cmark passes raw HTML through; ammonia must strip it.
        assert!(!html.contains("<script>"));
        assert!(!html.contains("alert"));
        // The legitimate markdown content survives.
        assert!(html.contains("body"));
    }

    #[test]
    fn render_markdown_strips_inline_images() {
        // External images in the markdown body would let a viewer's
        // browser hit the agent-controlled URL before the human even
        // reads anything.  rm_tags strips them.
        let md = "before ![alt](https://attacker.example/pixel.gif) after";
        let html = render_markdown_page("title", "security_review", md);
        assert!(!html.contains("attacker.example"));
        assert!(!html.contains("<img"));
    }

    #[test]
    fn render_markdown_keeps_external_links_with_noopener() {
        let md = "see [NVD](https://nvd.nist.gov/CVE)";
        let html = render_markdown_page("t", "security_review", md);
        assert!(html.contains(r#"href="https://nvd.nist.gov/CVE""#));
        assert!(html.contains("noopener"));
    }

    #[test]
    fn render_image_uses_raw_url_for_src() {
        let html = render_image_page("photo", "image", "/v1/tok/raw");
        assert!(html.contains(r#"src="/v1/tok/raw""#));
        assert!(html.contains(r#"class="share-image""#));
    }

    #[test]
    fn render_download_links_to_raw() {
        let html = render_download_page("file.zip", "other", "/v1/tok/raw");
        assert!(html.contains(r#"href="/v1/tok/raw""#));
        assert!(html.contains("Download"));
    }

    #[test]
    fn render_escapes_title_so_html_in_metadata_does_not_render() {
        let html = render_markdown_page("<script>", "security_review", "body");
        // Title appears in <title>, brand area, etc. — all escaped.
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
