//! Tiny HTTP client used by the CLI subcommands so they share one code path
//! with the public API. The CLI is a client of the local warden, not a
//! re-implementation of its logic.
//!
//! The bearer is whatever the operator wants to authenticate as.  Stage 5
//! killed the legacy admin_token; CLI users now mint a `user_api_keys`
//! row via the SPA and export it as `WARDEN_API_KEY=...` for the CLI to
//! pick up via [`build_api_client`] in `main.rs`.

use anyhow::{anyhow, Context, Result};
use reqwest::{Client, Method, StatusCode};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct ApiClient {
    base: String,
    bearer: Option<String>,
    http: Client,
}

impl ApiClient {
    pub fn new(base: impl Into<String>, bearer: Option<String>) -> Result<Self> {
        let http = Client::builder()
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            base: normalize_base(base.into()),
            bearer,
            http,
        })
    }

    /// Build a base URL from a `bind` value like `0.0.0.0:8080`. Listens on
    /// `0.0.0.0` are reached via `127.0.0.1`.
    pub fn from_bind(bind: &str, bearer: Option<String>) -> Result<Self> {
        let base = if bind.starts_with("http://") || bind.starts_with("https://") {
            bind.to_owned()
        } else {
            let mut parts = bind.splitn(2, ':');
            let host = parts.next().unwrap_or("127.0.0.1");
            let port = parts.next().unwrap_or("8080");
            let host = match host {
                "0.0.0.0" | "" | "::" => "127.0.0.1",
                other => other,
            };
            format!("http://{host}:{port}")
        };
        Self::new(base, bearer)
    }

    pub async fn send_no_body(&self, method: Method, path: &str) -> Result<()> {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = &self.bearer {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.context("send")?;
        check(resp.status())
    }

    pub async fn send_json<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: &B,
    ) -> Result<()> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .json(body);
        if let Some(t) = &self.bearer {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.context("send")?;
        check(resp.status())
    }
}

fn normalize_base(s: String) -> String {
    s.trim_end_matches('/').to_string()
}

fn check(status: StatusCode) -> Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        Err(anyhow!("HTTP {}", status.as_u16()))
    }
}
