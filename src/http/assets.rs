//! Embedded frontend bundle.
//!
//! `build.rs` walks `src/http/web/dist/` after `npm run build` and emits
//! `web_assets.rs` containing one `(url_path, &[u8], content_type)`
//! entry per file.  This module includes that table and exposes a single
//! `lookup` helper for the static-asset handler.

include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

/// Look up an embedded asset by URL path.  Returns `(bytes, content-type)`
/// or `None`.  `/` resolves to `index.html`.
pub fn lookup(path: &str) -> Option<(&'static [u8], &'static str)> {
    let key = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    for (p, bytes, ct) in ASSETS {
        if *p == key {
            return Some((bytes, ct));
        }
    }
    None
}
