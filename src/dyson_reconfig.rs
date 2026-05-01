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
    /// Per-instance mint serialiser.  Without this, two parallel pushes
    /// for the same instance both miss the cached secret, both mint a
    /// fresh UUID, and only the second `put` survives — but the first
    /// one's request body had already been signed with the now-orphaned
    /// secret.  Dyson TOFU-pins whichever plaintext arrived first and
    /// rejects the other forever.  The mutex closes that race.
    ///
    /// Wrapped in `parking_lot::Mutex` rather than `std::sync::Mutex` so
    /// a panic anywhere inside the (short) critical section doesn't
    /// poison the map and turn every future `ensure_secret` into an
    /// `expect`-failure.  The map is GC'd as instances finalise their
    /// first mint and as instances are destroyed (`forget_secret`).
    mint_locks: Arc<parking_lot::Mutex<
        std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>,
    >>,
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
            mint_locks: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Recover or freshly mint the per-instance configure secret.
    /// Generation is a one-shot per instance; subsequent calls
    /// return the same plaintext so dyson's TOFU hash stays valid.
    async fn ensure_secret(&self, instance_id: &str) -> Result<String, String> {
        let name = configure_secret_name(instance_id);
        // Fast path: secret already sealed.
        if let Some(plain) = self.system_secrets.get(&name).await.map_err(|e| e.to_string())? {
            return String::from_utf8(plain)
                .map_err(|_| "non-utf8 configure secret in system_secrets".to_string());
        }
        // Slow path: serialise on the per-instance mint lock so two
        // concurrent first-pushes don't mint two distinct UUIDs.
        // parking_lot::Mutex doesn't poison, so no `.expect` here even
        // if a caller previously panicked while holding the map.
        let lock = {
            let mut map = self.mint_locks.lock();
            map.entry(instance_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;
        // Re-check under the lock — another caller may have minted while
        // we were waiting.
        if let Some(plain) = self.system_secrets.get(&name).await.map_err(|e| e.to_string())? {
            return String::from_utf8(plain)
                .map_err(|_| "non-utf8 configure secret in system_secrets".to_string());
        }
        let s = uuid::Uuid::new_v4().simple().to_string();
        self.system_secrets
            .put(&name, s.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        Ok(s)
    }

    /// Cleanup hook for the destroy path — wipes both the sealed
    /// per-instance configure secret and any leftover mint-lock map
    /// entry.  Idempotent.  Best-effort on the secret delete (logs on
    /// error so a stuck row surfaces in operations); the lock entry
    /// is always removed.
    pub async fn forget_secret(&self, instance_id: &str) {
        // Lock-map GC first — purely in-memory, infallible.
        self.mint_locks.lock().remove(instance_id);
        let name = configure_secret_name(instance_id);
        if let Err(err) = self.system_secrets.delete(&name).await {
            tracing::warn!(
                error = %err,
                instance = %instance_id,
                "reconfigure: forget_secret failed; sealed plaintext lingers"
            );
        }
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

impl DysonReconfigurerHttp {
    /// Diagnostic: GET `/api/admin/skills` on the running dyson and
    /// return the JSON it produces.  Lets an operator inspect which
    /// MCP servers actually loaded — pairs with the matching dyson
    /// route added to debug the silent on_load failure path.
    pub async fn get_skills(
        &self,
        instance_id: &str,
        sandbox_id: &str,
    ) -> Result<serde_json::Value, String> {
        let secret = self.ensure_secret(instance_id).await?;
        let port: u16 = std::env::var("SWARM_CUBE_INTERNAL_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(80);
        let url = format!(
            "https://{port}-{sandbox_id}.{}/api/admin/skills",
            self.sandbox_domain
        );
        let resp = self
            .http
            .get(&url)
            .header(CONFIGURE_HEADER, &secret)
            .header(CSRF_HEADER, "swarm-internal")
            .send()
            .await
            .map_err(|e| format!("send: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("dyson /api/admin/skills {status}: {body}"));
        }
        serde_json::from_str(&body).map_err(|e| format!("parse: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::db::open_in_memory;
    use crate::db::secrets::SqlxSystemSecretStore;
    use crate::envelope::AgeCipherDirectory;
    use crate::traits::SystemSecretStore;

    /// Regression: two parallel first-push pushes for the same instance
    /// must mint exactly one configure-secret plaintext.  Without the
    /// per-instance lock both callers race past the read, both mint
    /// fresh UUIDs, and the put-loser's request body has already been
    /// signed with a now-orphaned secret — dyson TOFU-pins the winner
    /// and rejects the loser permanently.
    #[tokio::test]
    async fn parallel_ensure_secret_returns_one_plaintext() {
        let pool = open_in_memory().await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let store: Arc<dyn SystemSecretStore> =
            Arc::new(SqlxSystemSecretStore::new(pool));
        let system_secrets = Arc::new(SystemSecretsService::new(store, cipher_dir));

        let r = DysonReconfigurerHttp::new("cube.test:8443", system_secrets.clone()).unwrap();
        let r = Arc::new(r);
        let instance_id = "i-test";

        // Fire 16 ensure_secret calls in parallel.  Without the lock we
        // expect 16 distinct UUIDs minted (only the last `put` survives,
        // rendering all other in-flight pushes' signatures orphaned).
        let mut handles = Vec::new();
        for _ in 0..16 {
            let r = r.clone();
            handles.push(tokio::spawn(async move { r.ensure_secret(instance_id).await }));
        }
        let mut secrets = Vec::with_capacity(16);
        for h in handles {
            secrets.push(h.await.unwrap().unwrap());
        }
        // Every caller must see the same sealed plaintext.
        let first = secrets[0].clone();
        for s in &secrets {
            assert_eq!(s, &first, "ensure_secret must not mint twice for one instance");
        }
        // And the sealed value must equal what callers observed.
        let sealed = system_secrets
            .get(&configure_secret_name(instance_id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(String::from_utf8(sealed).unwrap(), first);
    }

    /// GC: after an instance is destroyed, its mint-lock map entry
    /// must be dropped so long-running swarm processes don't grow the
    /// map without bound.  Sister property to the sealed-plaintext
    /// wipe — both pieces of per-instance state should leave with the
    /// instance.
    #[tokio::test]
    async fn forget_secret_drops_mint_lock_entry() {
        let pool = open_in_memory().await.unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
            Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
        let store: Arc<dyn SystemSecretStore> =
            Arc::new(SqlxSystemSecretStore::new(pool));
        let system_secrets = Arc::new(SystemSecretsService::new(store, cipher_dir));

        let r = DysonReconfigurerHttp::new("cube.test:8443", system_secrets.clone()).unwrap();
        let instance_id = "i-gc";

        // Exercise ensure_secret so the lock map entry is created (the
        // first-mint slow path inserts it) and the secret is sealed.
        let _ = r.ensure_secret(instance_id).await.unwrap();
        assert!(
            r.mint_locks.lock().contains_key(instance_id),
            "ensure_secret must seed the per-instance lock entry"
        );

        // forget_secret wipes both halves: the sealed plaintext in
        // system_secrets and the in-memory lock entry.
        r.forget_secret(instance_id).await;
        assert!(
            !r.mint_locks.lock().contains_key(instance_id),
            "forget_secret must remove the per-instance lock entry"
        );
        assert!(
            system_secrets
                .get(&configure_secret_name(instance_id))
                .await
                .unwrap()
                .is_none(),
            "forget_secret must wipe the sealed plaintext"
        );
    }
}
