//! Gemini — auth via the `x-goog-api-key` header.  The legacy `?key=`
//! URL form was dropped because Google logs full request URLs server-
//! side, and any redirect would have copied the key into the Referer.
//! We also scrub any inbound `?key=` the client may have sent so we
//! never forward a leaked client key upstream.  Inbound `Authorization`
//! is stripped (it carries the proxy token, not anything the upstream
//! should see).

use axum::http::{HeaderMap, HeaderName, HeaderValue, Uri};

use crate::config::ProviderConfig;
use crate::traits::ProviderAdapter;

const GOOG_API_KEY: HeaderName = HeaderName::from_static("x-goog-api-key");

pub struct GeminiAdapter;

impl ProviderAdapter for GeminiAdapter {
    fn name(&self) -> &'static str {
        "gemini"
    }

    fn upstream_base_url<'a>(&self, config: &'a ProviderConfig) -> &'a str {
        &config.upstream
    }

    fn rewrite_auth(&self, headers: &mut HeaderMap, url: &mut Uri, real_key: &str) {
        headers.remove(axum::http::header::AUTHORIZATION);

        // Strip any inbound `key=` so we don't forward the client's
        // value (or our own, if anything upstream of us re-attached it).
        let path = url.path().to_string();
        let cleaned = strip_key_param(url.query().unwrap_or(""));
        let pq = if cleaned.is_empty() {
            path
        } else {
            format!("{path}?{cleaned}")
        };
        if let Ok(rebuilt) = pq.parse::<axum::http::uri::PathAndQuery>() {
            let mut parts = url.clone().into_parts();
            parts.path_and_query = Some(rebuilt);
            if let Ok(rebuilt_uri) = Uri::from_parts(parts) {
                *url = rebuilt_uri;
            }
        }

        if let Ok(v) = HeaderValue::from_str(real_key) {
            headers.insert(GOOG_API_KEY, v);
        }
    }
}

/// Drop every `key=...` element from a `&`-delimited query string.
/// Returns the rejoined remainder (no leading `&`).
fn strip_key_param(query: &str) -> String {
    let mut out = String::new();
    let mut first = true;
    for part in query.split('&') {
        if part.is_empty() || part == "key" || part.starts_with("key=") {
            continue;
        }
        if !first {
            out.push('&');
        }
        out.push_str(part);
        first = false;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_header_when_no_query() {
        let a = GeminiAdapter;
        let mut headers = HeaderMap::new();
        let mut url: Uri = "/v1beta/models/gemini-pro:generateContent".parse().unwrap();
        a.rewrite_auth(&mut headers, &mut url, "AIza-real");
        assert_eq!(url.query(), None);
        assert_eq!(url.path(), "/v1beta/models/gemini-pro:generateContent");
        assert_eq!(
            headers.get(&GOOG_API_KEY).and_then(|v| v.to_str().ok()),
            Some("AIza-real")
        );
    }

    #[test]
    fn preserves_other_query_params() {
        let a = GeminiAdapter;
        let mut headers = HeaderMap::new();
        let mut url: Uri = "/v1beta/models/gemini-pro:generateContent?alt=sse"
            .parse()
            .unwrap();
        a.rewrite_auth(&mut headers, &mut url, "AIza-real");
        assert_eq!(url.query(), Some("alt=sse"));
        assert_eq!(headers.get(&GOOG_API_KEY).unwrap(), "AIza-real");
    }

    #[test]
    fn strips_inbound_client_key() {
        let a = GeminiAdapter;
        let mut headers = HeaderMap::new();
        let mut url: Uri = "/v1beta?key=client-leaked&alt=sse".parse().unwrap();
        a.rewrite_auth(&mut headers, &mut url, "AIza-real");
        assert_eq!(url.query(), Some("alt=sse"));
        assert_eq!(headers.get(&GOOG_API_KEY).unwrap(), "AIza-real");
    }

    #[test]
    fn strips_solo_inbound_client_key() {
        let a = GeminiAdapter;
        let mut headers = HeaderMap::new();
        let mut url: Uri = "/v1beta?key=client-leaked".parse().unwrap();
        a.rewrite_auth(&mut headers, &mut url, "AIza-real");
        assert_eq!(url.query(), None);
        assert_eq!(headers.get(&GOOG_API_KEY).unwrap(), "AIza-real");
    }

    #[test]
    fn strips_authorization_header() {
        let a = GeminiAdapter;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer client"),
        );
        let mut url: Uri = "/v1beta".parse().unwrap();
        a.rewrite_auth(&mut headers, &mut url, "AIza-real");
        assert!(headers.get(axum::http::header::AUTHORIZATION).is_none());
        assert_eq!(headers.get(&GOOG_API_KEY).unwrap(), "AIza-real");
    }
}
