//! OpenRouter — same shape as OpenAI: `Authorization: Bearer <key>` swap.

use axum::http::{HeaderMap, HeaderValue, Uri};

use crate::config::ProviderConfig;
use crate::traits::ProviderAdapter;

pub struct OpenRouterAdapter;

impl ProviderAdapter for OpenRouterAdapter {
    fn name(&self) -> &'static str {
        "openrouter"
    }

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
    use crate::config::ProviderConfig;

    fn cfg() -> ProviderConfig {
        ProviderConfig {
            api_key: Some("from-config".into()),
            upstream: "https://openrouter.ai/api".into(),
            anthropic_version: None,
        }
    }

    #[test]
    fn replaces_bearer_with_real_key() {
        let a = OpenRouterAdapter;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer client-token-do-not-forward"),
        );
        let mut url: Uri = "/v1/chat/completions".parse().unwrap();
        a.rewrite_auth(&mut headers, &mut url, "from-config");
        assert_eq!(
            headers.get(axum::http::header::AUTHORIZATION).unwrap(),
            "Bearer from-config"
        );
        assert_eq!(url.path(), "/v1/chat/completions");
    }

    #[test]
    fn upstream_url_is_passthrough() {
        assert_eq!(
            OpenRouterAdapter.upstream_base_url(&cfg()),
            "https://openrouter.ai/api"
        );
    }
}
