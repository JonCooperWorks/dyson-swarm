//! Outbound HTTP — exactly two clients in this codebase.
//!
//! - InternalHttpClient: operator/system URLs (Cube, OpenRouter, instance
//!   probes, reconfigurer). Pooled, shared.
//! - ExternalHttpClient: admin/user-input URLs. Per-call IP-pinned via
//!   OutboundUrlPolicy. Closes SSRF.
//!
//! Bare `reqwest::Client::new` / `ClientBuilder::build` is forbidden
//! outside this module by clippy.toml.

#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;

use crate::upstream_policy::{
    OutboundUrlError, OutboundUrlPolicy, ValidatedOutboundUrl, pinned_outbound_client_builder,
    validate_outbound_url,
};

const USER_AGENT: &str = concat!("dyson-swarm/", env!("CARGO_PKG_VERSION"));
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const POOL_IDLE: Duration = Duration::from_secs(90);

fn shared_common(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    b.user_agent(USER_AGENT)
        .pool_idle_timeout(Some(POOL_IDLE))
        .redirect(reqwest::redirect::Policy::none())
}

fn shared_defaults(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    shared_common(b).timeout(DEFAULT_TIMEOUT)
}

#[derive(Debug, Clone)]
pub struct InternalHttpClient {
    inner: reqwest::Client,
}

impl InternalHttpClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            inner: shared_defaults(reqwest::Client::builder()).build()?,
        })
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self, reqwest::Error> {
        Self::from_builder(reqwest::Client::builder().timeout(timeout))
    }

    pub fn from_builder(builder: reqwest::ClientBuilder) -> Result<Self, reqwest::Error> {
        Ok(Self {
            inner: shared_common(builder).build()?,
        })
    }

    pub fn raw(&self) -> &reqwest::Client {
        &self.inner
    }

    pub fn get(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.inner.get(url)
    }

    pub fn post(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.inner.post(url)
    }

    pub fn patch(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.inner.patch(url)
    }

    pub fn delete(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        self.inner.delete(url)
    }

    pub fn request(
        &self,
        method: reqwest::Method,
        url: impl reqwest::IntoUrl,
    ) -> reqwest::RequestBuilder {
        self.inner.request(method, url)
    }
}

#[derive(Debug, Clone)]
pub struct ExternalHttpClient {
    policy: Arc<OutboundUrlPolicy>,
}

impl ExternalHttpClient {
    pub fn new(policy: Arc<OutboundUrlPolicy>) -> Self {
        Self { policy }
    }

    /// Validate URL, resolve host, build a pinned client for the resolved
    /// IPs, deny cross-IP redirects. Construct per-fetch.
    pub async fn for_url(&self, url: &str) -> Result<(reqwest::Client, Url), OutboundUrlError> {
        let validated = validate_outbound_url(&self.policy, url).await?;
        self.for_validated(&validated)
    }

    /// Build the same pinned client for a URL that was already validated.
    /// This is used by paths that persist validated socket addresses and must
    /// avoid a second DNS lookup on the request path.
    pub fn for_validated(
        &self,
        validated: &ValidatedOutboundUrl,
    ) -> Result<(reqwest::Client, Url), OutboundUrlError> {
        let client = shared_defaults(pinned_outbound_client_builder(&validated))
            .redirect(redirect_pinned_to(&validated))
            .build()
            .map_err(|e| OutboundUrlError::Build(e.to_string()))?;
        let url = validated.url.clone();
        Ok((client, url))
    }
}

fn redirect_pinned_to(v: &ValidatedOutboundUrl) -> reqwest::redirect::Policy {
    let allowed = v.resolved_addrs.clone();
    reqwest::redirect::Policy::custom(move |attempt| match attempt.url().socket_addrs(|| None) {
        Ok(addrs) if !addrs.is_empty() && addrs.iter().all(|addr| allowed.contains(addr)) => {
            attempt.follow()
        }
        _ => attempt.error("redirect target not in pinned set"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny_all_policy() -> Arc<OutboundUrlPolicy> {
        Arc::new(OutboundUrlPolicy::default())
    }

    #[tokio::test]
    async fn external_rejects_loopback() {
        let client = ExternalHttpClient::new(deny_all_policy());
        assert!(client.for_url("https://127.0.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn external_rejects_metadata_v4() {
        let client = ExternalHttpClient::new(deny_all_policy());
        assert!(client.for_url("https://169.254.169.254/").await.is_err());
    }

    #[tokio::test]
    async fn external_rejects_rfc1918() {
        let client = ExternalHttpClient::new(deny_all_policy());
        assert!(client.for_url("https://10.0.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn external_rejects_non_http_scheme() {
        let client = ExternalHttpClient::new(deny_all_policy());
        assert!(client.for_url("file:///etc/passwd").await.is_err());
    }

    #[test]
    fn internal_builds() {
        InternalHttpClient::new().unwrap();
    }
}
