pub(super) fn strip_url_query(s: &str) -> String {
    let mut end = s.len();
    if let Some(q) = s.find('?') {
        end = end.min(q);
    }
    if let Some(h) = s.find('#') {
        end = end.min(h);
    }
    s[..end].to_string()
}

// Single-server detail surfaces the full URL so the SPA edit form can
// pre-fill without forcing the operator to re-enter a saved query-string
// credential. List responses strip queries by design.
pub(super) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
