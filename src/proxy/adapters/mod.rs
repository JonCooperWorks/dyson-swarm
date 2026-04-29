//! Per-provider adapters. Each implements [`crate::traits::ProviderAdapter`]
//! and is responsible for the upstream's expected auth shape and any
//! URL-level peculiarities (e.g. Gemini's `?key=`).
//!
//! Adapters are stateless. `rewrite_auth` mutates the headers + URL in
//! place; the proxy router passes the live request mutably.

pub mod anthropic;
pub mod byo;
pub mod deepseek;
pub mod gemini;
pub mod groq;
pub mod ollama;
pub mod openai;
pub mod openrouter;
pub mod xai;

use std::collections::HashMap;
use std::sync::Arc;

use crate::traits::ProviderAdapter;

/// Build the canonical adapter map keyed by provider name. The proxy router
/// looks up the adapter by the URL path segment after `/llm/`.
pub fn registry() -> HashMap<&'static str, Arc<dyn ProviderAdapter>> {
    let mut m: HashMap<&'static str, Arc<dyn ProviderAdapter>> = HashMap::new();
    m.insert("openrouter", Arc::new(openrouter::OpenRouterAdapter));
    m.insert("openai", Arc::new(openai::OpenAIAdapter));
    m.insert("anthropic", Arc::new(anthropic::AnthropicAdapter));
    m.insert("gemini", Arc::new(gemini::GeminiAdapter));
    m.insert("ollama", Arc::new(ollama::OllamaAdapter));
    m.insert("groq", Arc::new(groq::GroqAdapter));
    m.insert("deepseek", Arc::new(deepseek::DeepSeekAdapter));
    m.insert("xai", Arc::new(xai::XaiAdapter));
    m.insert("byo", Arc::new(byo::ByoAdapter));
    m
}
