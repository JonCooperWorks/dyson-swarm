//! Groq — OpenAI-compatible Bearer auth at `https://api.groq.com/openai`.
//! Kept distinct from the OpenAI adapter so any future Groq-specific quirk
//! (custom org/team headers, model-suffix routing) lands here without
//! disturbing siblings.

use axum::http::{HeaderMap, HeaderValue, Uri};

use crate::config::ProviderConfig;
use crate::traits::ProviderAdapter;

pub struct GroqAdapter;

impl ProviderAdapter for GroqAdapter {
    fn name(&self) -> &'static str {
        "groq"
    }

    fn upstream_base_url<'a>(&self, config: &'a ProviderConfig) -> &'a str {
        &config.upstream
    }

    fn rewrite_auth(&self, headers: &mut HeaderMap, _url: &mut Uri, real_key: &str) {
        let value =
            HeaderValue::from_str(&format!("Bearer {real_key}")).expect("bearer header");
        headers.insert(axum::http::header::AUTHORIZATION, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_bearer_with_real_key() {
        let a = GroqAdapter;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer client-token"),
        );
        let mut url: Uri = "/openai/v1/chat/completions".parse().unwrap();
        a.rewrite_auth(&mut headers, &mut url, "gsk-real");
        assert_eq!(
            headers.get(axum::http::header::AUTHORIZATION).unwrap(),
            "Bearer gsk-real"
        );
    }
}
