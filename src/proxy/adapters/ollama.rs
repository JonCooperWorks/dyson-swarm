//! Ollama Cloud — OpenAI-compatible Bearer auth at `https://ollama.com`.
//!
//! This slot is for **Ollama Cloud** (the hosted offering), not a local
//! `ollama serve` daemon.  Local Ollama is auth-less; the right way to
//! point swarm at one is the `byo` slot with the daemon's URL —
//! handles work for any operator-private endpoint without forcing the
//! global registry to carry a "no-auth" special case.
//!
//! Cloud Ollama exposes an OpenAI-compatible API under `/v1/...` with
//! Bearer auth, so the adapter shape collapses to the same one
//! `openai`, `groq`, `deepseek`, and `xai` use.

use axum::http::{HeaderMap, HeaderValue, Uri};

use crate::config::ProviderConfig;
use crate::traits::ProviderAdapter;

pub struct OllamaAdapter;

impl ProviderAdapter for OllamaAdapter {
    fn name(&self) -> &'static str {
        "ollama"
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
        let a = OllamaAdapter;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer client-token"),
        );
        let mut url: Uri = "/v1/chat/completions".parse().unwrap();
        a.rewrite_auth(&mut headers, &mut url, "ollama-real");
        assert_eq!(
            headers.get(axum::http::header::AUTHORIZATION).unwrap(),
            "Bearer ollama-real"
        );
    }
}
