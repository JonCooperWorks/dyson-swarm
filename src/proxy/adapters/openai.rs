//! OpenAI — `Authorization: Bearer <key>` swap, identical pattern to
//! OpenRouter but kept distinct so per-provider quirks (org headers,
//! project headers) can be added without disturbing other adapters.

use axum::http::{HeaderMap, HeaderValue, Uri};

use crate::config::ProviderConfig;
use crate::traits::ProviderAdapter;

pub struct OpenAIAdapter;

impl ProviderAdapter for OpenAIAdapter {
    fn name(&self) -> &'static str {
        "openai"
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

    #[test]
    fn replaces_bearer_with_real_key() {
        let a = OpenAIAdapter;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer client-token"),
        );
        let mut url: Uri = "/v1/chat/completions".parse().unwrap();
        a.rewrite_auth(&mut headers, &mut url, "sk-real");
        assert_eq!(
            headers.get(axum::http::header::AUTHORIZATION).unwrap(),
            "Bearer sk-real"
        );
    }
}
