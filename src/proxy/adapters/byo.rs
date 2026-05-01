//! BYO LLM — user-supplied upstream URL + key.
//!
//! Unlike every other provider, `byo` has no `[providers.byo]` TOML stanza.
//! The user pastes both the upstream URL and the API key into their per-user
//! BYOK row (`byok_byo`), stored as a JSON blob.  The proxy resolver hands
//! the URL back via `ResolvedKey::upstream_override`, which the handler uses
//! instead of `ProviderConfig.upstream`.  This adapter therefore only owns
//! header rewriting (assume OpenAI-compatible Bearer); URL routing happens
//! upstream of it.

use axum::http::{HeaderMap, HeaderValue, Uri};

use crate::config::ProviderConfig;
use crate::traits::ProviderAdapter;

pub struct ByoAdapter;

impl ProviderAdapter for ByoAdapter {
    fn name(&self) -> &'static str {
        "byo"
    }

    /// Returns whatever is in `ProviderConfig.upstream` (typically the
    /// empty string — `byo` is not declared in TOML).  The proxy handler
    /// always overrides this with the user's stored upstream URL via
    /// `ResolvedKey::upstream_override`, so this method's return value is
    /// effectively dead-code; we keep it well-defined for the trait.
    fn upstream_base_url<'a>(&self, config: &'a ProviderConfig) -> &'a str {
        &config.upstream
    }

    fn rewrite_auth(&self, headers: &mut HeaderMap, _url: &mut Uri, real_key: &str) {
        let value = HeaderValue::from_str(&format!("Bearer {real_key}")).expect("bearer header");
        headers.insert(axum::http::header::AUTHORIZATION, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_bearer_with_real_key() {
        let a = ByoAdapter;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer client-token"),
        );
        let mut url: Uri = "/v1/chat/completions".parse().unwrap();
        a.rewrite_auth(&mut headers, &mut url, "byo-real");
        assert_eq!(
            headers.get(axum::http::header::AUTHORIZATION).unwrap(),
            "Bearer byo-real"
        );
    }
}
