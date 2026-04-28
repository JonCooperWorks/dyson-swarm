//! HTTP implementation of [`crate::instance::DysonReconfigurer`].
//!
//! Pushes swarm-side identity/task/model state into a running dyson
//! sandbox via dyson's `/api/admin/configure` endpoint.  Cube's
//! microVM snapshot/restore freezes the dyson process's `/proc/self/environ`
//! at warmup time (env empty) — without this push, every instance
//! shows `"warmup-placeholder"` as its model and IDENTITY.md is
//! never written.
//!
//! Auth: a per-instance plaintext "configure secret" (32 hex from
//! `Uuid::new_v4().simple()`) is sealed via the system envelope
//! cipher into `system_secrets["instance.<id>.configure"]` on first
//! push and reused on every subsequent push.  Dyson hashes it on
//! first sighting (argon2id, TOFU) into `<dyson_home>/configure_secret_hash`
//! and verifies on every following call.  Belt-and-braces on top of
//! cube's network isolation: even an attacker who reaches the
//! sandbox via cubeproxy can't reconfigure without the plaintext.

use std::sync::Arc;
use std::time::Duration;

use crate::instance::{DysonReconfigurer, ReconfigureBody, configure_secret_name};
use crate::secrets::SystemSecretsService;

/// Header dyson reads to verify the per-instance configure secret.
/// Value is the 32-hex plaintext; dyson runs argon2id over it and
/// compares against the stored hash.
const CONFIGURE_HEADER: &str = "X-Swarm-Configure";

/// Header dyson's CSRF gate insists on for state-changing /api/*
/// methods.  The value isn't read — only the presence is checked
/// (the gate is browser-CORS-shaped, not a token).
const CSRF_HEADER: &str = "X-Dyson-CSRF";

/// HTTP reconfigurer.  Holds the cube-trusted reqwest client + the
/// SystemSecretsService for sealing/recovering the per-instance
/// configure secret.
#[derive(Clone)]
pub struct DysonReconfigurerHttp {
    http: reqwest::Client,
    /// Cube-internal sandbox suffix, e.g. `cube.app:8443`.  Mirrors
    /// `[cube] sandbox_domain` in swarm config.
    sandbox_domain: String,
    /// Where the per-instance configure secret is sealed.
    system_secrets: Arc<SystemSecretsService>,
}

impl DysonReconfigurerHttp {
    /// Construct a reconfigurer.  The HTTP client is built with the
    /// cube root CA trusted (mirrors `dyson_proxy::build_client`)
    /// because cubeproxy presents an mkcert-rooted cert that isn't
    /// in webpki's default bundle.
    pub fn new(
        sandbox_domain: impl Into<String>,
        system_secrets: Arc<SystemSecretsService>,
    ) -> Result<Self, reqwest::Error> {
        let mut b = reqwest::Client::builder().timeout(Duration::from_secs(15));
        if let Ok(path) = std::env::var("SWARM_CUBE_ROOT_CA")
            && !path.is_empty()
        {
            match std::fs::read(&path) {
                Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
                    Ok(cert) => {
                        tracing::info!(path = %path, "reconfigurer: trusting cube root CA");
                        b = b.add_root_certificate(cert);
                    }
                    Err(e) => tracing::error!(path = %path, error = %e, "reconfigurer: parse PEM failed"),
                },
                Err(e) => tracing::error!(path = %path, error = %e, "reconfigurer: read PEM failed"),
            }
        }
        Ok(Self {
            http: b.build()?,
            sandbox_domain: sandbox_domain.into(),
            system_secrets,
        })
    }

    /// Recover or freshly mint the per-instance configure secret.
    /// Generation is a one-shot per instance; subsequent calls
    /// return the same plaintext so dyson's TOFU hash stays valid.
    async fn ensure_secret(&self, instance_id: &str) -> Result<String, String> {
        let name = configure_secret_name(instance_id);
        if let Some(plain) = self.system_secrets.get(&name).await.map_err(|e| e.to_string())? {
            return String::from_utf8(plain)
                .map_err(|_| "non-utf8 configure secret in system_secrets".to_string());
        }
        // First push for this instance — mint, seal, return.
        let s = uuid::Uuid::new_v4().simple().to_string();
        self.system_secrets
            .put(&name, s.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        Ok(s)
    }

    /// Build `https://<port>-<sandbox_id>.<sandbox_domain>/api/admin/configure`.
    /// Mirrors the URL shape `dyson_proxy::forward` uses when
    /// forwarding regular requests (cubeproxy routes by the
    /// leading `<port>-` label of the SNI).
    fn url_for(&self, sandbox_id: &str) -> String {
        let port: u16 = std::env::var("SWARM_CUBE_INTERNAL_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(80);
        format!(
            "https://{port}-{sandbox_id}.{}/api/admin/configure",
            self.sandbox_domain
        )
    }
}

#[async_trait::async_trait]
impl DysonReconfigurer for DysonReconfigurerHttp {
    async fn push(
        &self,
        instance_id: &str,
        sandbox_id: &str,
        body: &ReconfigureBody,
    ) -> Result<(), String> {
        let secret = self.ensure_secret(instance_id).await?;
        let url = self.url_for(sandbox_id);
        let model_count = body.models.len();
        let has_name = body.name.is_some();
        let has_task = body.task.is_some();
        tracing::info!(
            instance = %instance_id,
            sandbox = %sandbox_id,
            url = %url,
            models = model_count,
            has_name,
            has_task,
            "reconfigure: pushing"
        );
        let resp = self
            .http
            .post(&url)
            .header(CONFIGURE_HEADER, &secret)
            .header(CSRF_HEADER, "swarm-internal")
            .json(body)
            .send()
            .await
            .map_err(|e| format!("send: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let resp_body = resp.text().await.unwrap_or_default();
            return Err(format!("dyson /api/admin/configure {status}: {resp_body}"));
        }
        // Drain the response body for diagnostics — dyson returns
        // `{ ok: true, identity_updated: bool, models_updated: bool }`,
        // and `models_updated: false` while we DID send models is the
        // smoking gun for a config_path miss on the dyson side.
        let resp_body = resp.text().await.unwrap_or_default();
        tracing::info!(
            instance = %instance_id,
            response = %resp_body,
            "reconfigure: dyson accepted"
        );
        Ok(())
    }
}

/// Wipe the per-instance configure secret on instance destroy.
/// Best-effort — log on failure, never block destroy on it.  Called
/// from `instance.destroy()` so the sealed plaintext doesn't linger
/// after the sandbox is gone.
pub async fn forget_secret(
    system_secrets: &SystemSecretsService,
    instance_id: &str,
) {
    let name = configure_secret_name(instance_id);
    if let Err(err) = system_secrets.delete(&name).await {
        tracing::warn!(
            error = %err,
            instance = %instance_id,
            "reconfigure: forget_secret failed; sealed plaintext lingers"
        );
    }
}
