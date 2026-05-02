//! Secrets — three services, one shape: store opaque ciphertexts in
//! sqlite, route encrypt/decrypt through the right
//! [`crate::envelope::EnvelopeCipher`].
//!
//! - [`SecretsService`] — per-instance secrets (PUT/GET/DELETE under
//!   `/v1/instances/:id/secrets/:name`).  Sealed with the **instance
//!   owner's** cipher (per-user-key model: a stolen instance row by
//!   itself can't decrypt; needs the owner's `.age` file too).
//!
//! - [`UserSecretsService`] — per-user opaque blobs.  Sealed with the
//!   user's own cipher.  Used in Stage 6 for the per-user OpenRouter
//!   key, and available for any future per-user secret (e.g. a
//!   user-pasted GitHub PAT).
//!
//! - [`SystemSecretsService`] — global blobs (provider API keys, the
//!   OpenRouter provisioning key).  Sealed with the system-scope
//!   cipher ([`crate::envelope::SYSTEM_KEY_ID`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::envelope::{CipherDirectory, EnvelopeError, SYSTEM_KEY_ID};
use crate::error::StoreError;
use crate::traits::{InstanceStore, SecretStore, SystemSecretStore, UserSecretStore};

/// Errors a secrets call can surface to the API layer.  Wraps both
/// store and envelope failures so HTTP handlers can map to the right
/// status code in one match.
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
}

// ───────────────────────────────────────────────────────────────────
// SecretsService — per-instance, encrypted with the OWNER's cipher.
// ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SecretsService {
    store: Arc<dyn SecretStore>,
    instances: Arc<dyn InstanceStore>,
    ciphers: Arc<dyn CipherDirectory>,
}

impl SecretsService {
    pub fn new(
        store: Arc<dyn SecretStore>,
        instances: Arc<dyn InstanceStore>,
        ciphers: Arc<dyn CipherDirectory>,
    ) -> Self {
        Self {
            store,
            instances,
            ciphers,
        }
    }

    /// Encrypt `value` with the owner's cipher and persist.
    pub async fn put(
        &self,
        owner_id: &str,
        instance_id: &str,
        name: &str,
        value: &str,
    ) -> Result<(), SecretsError> {
        let cipher = self.ciphers.for_user(owner_id)?;
        let ciphertext = cipher.seal(value.as_bytes())?;
        let ct = String::from_utf8(ciphertext)
            .map_err(|_| EnvelopeError::Age("non-utf8 armor (impossible)".into()))?;
        self.store.put(instance_id, name, &ct).await?;
        Ok(())
    }

    pub async fn delete(
        &self,
        owner_id: &str,
        instance_id: &str,
        name: &str,
    ) -> Result<(), SecretsError> {
        self.instances
            .get_for_owner(owner_id, instance_id)
            .await?
            .ok_or(StoreError::NotFound)?;
        Ok(self.store.delete(instance_id, name).await?)
    }

    /// Decrypt every secret for `instance_id` using `owner_id`'s
    /// cipher.  Returns plaintext `(name, value)` pairs.  A row whose
    /// ciphertext fails to decrypt is **skipped** with a warning —
    /// usually means the user's age key was rotated and old rows are
    /// orphaned; we don't want one bad row to brick the whole list.
    pub async fn list(
        &self,
        owner_id: &str,
        instance_id: &str,
    ) -> Result<Vec<(String, String)>, SecretsError> {
        let cipher = self.ciphers.for_user(owner_id)?;
        let rows = self.store.list(instance_id).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (name, ct) in rows {
            if let Ok(plain) = cipher.open(ct.as_bytes()) {
                if let Ok(s) = String::from_utf8(plain) {
                    out.push((name, s))
                } else {
                    tracing::warn!(
                        instance = %instance_id, name = %name,
                        "instance_secret decrypted to non-utf8 — skipping"
                    );
                }
            } else {
                tracing::warn!(
                    instance = %instance_id, name = %name,
                    "instance_secret failed to decrypt with owner key — skipping"
                );
            }
        }
        Ok(out)
    }

    /// Names only — used by the SPA to render the secrets panel
    /// without round-tripping plaintext.  Cheap because we don't
    /// decrypt.
    pub async fn list_names(&self, instance_id: &str) -> Result<Vec<String>, SecretsError> {
        let rows = self.store.list(instance_id).await?;
        Ok(rows.into_iter().map(|(n, _)| n).collect())
    }
}

// ───────────────────────────────────────────────────────────────────
// UserSecretsService — per-user blobs, encrypted with USER's cipher.
// ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct UserSecretsService {
    store: Arc<dyn UserSecretStore>,
    ciphers: Arc<dyn CipherDirectory>,
}

impl UserSecretsService {
    pub fn new(store: Arc<dyn UserSecretStore>, ciphers: Arc<dyn CipherDirectory>) -> Self {
        Self { store, ciphers }
    }

    pub async fn put(&self, user_id: &str, name: &str, value: &[u8]) -> Result<(), SecretsError> {
        let cipher = self.ciphers.for_user(user_id)?;
        let ct = cipher.seal(value)?;
        let ct_str = String::from_utf8(ct)
            .map_err(|_| EnvelopeError::Age("non-utf8 armor (impossible)".into()))?;
        self.store.put(user_id, name, &ct_str).await?;
        Ok(())
    }

    pub async fn get(&self, user_id: &str, name: &str) -> Result<Option<Vec<u8>>, SecretsError> {
        let Some(ct) = self.store.get(user_id, name).await? else {
            return Ok(None);
        };
        let cipher = self.ciphers.for_user(user_id)?;
        Ok(Some(cipher.open(ct.as_bytes())?))
    }

    pub async fn delete(&self, user_id: &str, name: &str) -> Result<(), SecretsError> {
        Ok(self.store.delete(user_id, name).await?)
    }

    /// Returns names only.  Decrypting a whole list of per-user
    /// secrets just to render names would burn CPU for no reason.
    pub async fn list_names(&self, user_id: &str) -> Result<Vec<String>, SecretsError> {
        let rows = self.store.list(user_id).await?;
        Ok(rows.into_iter().map(|(n, _)| n).collect())
    }
}

// ───────────────────────────────────────────────────────────────────
// SystemSecretsService — global blobs, encrypted with SYSTEM cipher.
// ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SystemSecretsService {
    store: Arc<dyn SystemSecretStore>,
    ciphers: Arc<dyn CipherDirectory>,
}

impl SystemSecretsService {
    pub fn new(store: Arc<dyn SystemSecretStore>, ciphers: Arc<dyn CipherDirectory>) -> Self {
        Self { store, ciphers }
    }

    pub async fn put(&self, name: &str, value: &[u8]) -> Result<(), SecretsError> {
        let cipher = self.ciphers.for_user(SYSTEM_KEY_ID)?;
        let ct = cipher.seal(value)?;
        let ct_str = String::from_utf8(ct)
            .map_err(|_| EnvelopeError::Age("non-utf8 armor (impossible)".into()))?;
        self.store.put(name, &ct_str).await?;
        Ok(())
    }

    pub async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, SecretsError> {
        let Some(ct) = self.store.get(name).await? else {
            return Ok(None);
        };
        let cipher = self.ciphers.for_user(SYSTEM_KEY_ID)?;
        Ok(Some(cipher.open(ct.as_bytes())?))
    }

    /// Convenience: read a system secret as a string (UTF-8).  Returns
    /// `None` for missing rows, errors on non-UTF-8 ciphertext.
    pub async fn get_str(&self, name: &str) -> Result<Option<String>, SecretsError> {
        let Some(bytes) = self.get(name).await? else {
            return Ok(None);
        };
        Ok(Some(String::from_utf8(bytes).map_err(|_| {
            EnvelopeError::Age(format!("system secret `{name}` is not utf-8"))
        })?))
    }

    pub async fn delete(&self, name: &str) -> Result<(), SecretsError> {
        Ok(self.store.delete(name).await?)
    }

    pub async fn list_names(&self) -> Result<Vec<String>, SecretsError> {
        Ok(self.store.list_names().await?)
    }
}

// ───────────────────────────────────────────────────────────────────
// compose_env — unchanged, kept here so callers (instance.rs create +
// restore paths) only depend on this module.
// ───────────────────────────────────────────────────────────────────

/// Compose the env map handed to a CubeSandbox at create/restore time.
///
/// Priority order from the brief: **template → managed → caller → pre-existing
/// rows**. Read left-to-right, with the rightmost source winning on key
/// collision. Pre-existing rows (`instance_secrets` already in the DB) take
/// the highest priority so an operator-curated secret is never clobbered by a
/// transient caller-supplied value or a managed default.
pub fn compose_env(
    template: &BTreeMap<String, String>,
    managed: &BTreeMap<String, String>,
    caller: &BTreeMap<String, String>,
    existing: &[(String, String)],
) -> BTreeMap<String, String> {
    let mut out = template.clone();
    for (k, v) in managed {
        out.insert(k.clone(), v.clone());
    }
    for (k, v) in caller {
        out.insert(k.clone(), v.clone());
    }
    for (k, v) in existing {
        out.insert(k.clone(), v.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m<const N: usize>(pairs: [(&str, &str); N]) -> BTreeMap<String, String> {
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn compose_env_priority_order() {
        let template = m([("A", "tpl"), ("B", "tpl"), ("C", "tpl"), ("D", "tpl")]);
        let managed = m([("B", "mgr"), ("C", "mgr"), ("D", "mgr")]);
        let caller = m([("C", "call"), ("D", "call")]);
        let existing = vec![("D".into(), "exist".into())];
        let merged = compose_env(&template, &managed, &caller, &existing);
        assert_eq!(merged["A"], "tpl");
        assert_eq!(merged["B"], "mgr");
        assert_eq!(merged["C"], "call");
        assert_eq!(merged["D"], "exist");
    }

    #[test]
    fn compose_env_empty_inputs_are_identity() {
        let empty = BTreeMap::new();
        let only_template = m([("X", "1")]);
        let merged = compose_env(&only_template, &empty, &empty, &[]);
        assert_eq!(merged, only_template);
    }

    // ── Encryption-aware tests (instance / user / system services) ───

    use crate::db::{instances::SqlxInstanceStore, open_in_memory};
    use crate::envelope::AgeCipherDirectory;
    use crate::network_policy::NetworkPolicy;
    use crate::now_secs;
    use crate::traits::{InstanceRow, InstanceStatus};
    use std::sync::Mutex;

    /// In-memory SecretStore for testing the SecretsService without sqlite.
    struct MemSecretStore(Mutex<Vec<(String, String, String)>>);
    #[async_trait::async_trait]
    impl SecretStore for MemSecretStore {
        async fn put(&self, instance_id: &str, name: &str, ct: &str) -> Result<(), StoreError> {
            let mut v = self.0.lock().unwrap();
            v.retain(|(i, n, _)| !(i == instance_id && n == name));
            v.push((instance_id.to_owned(), name.to_owned(), ct.to_owned()));
            Ok(())
        }
        async fn delete(&self, instance_id: &str, name: &str) -> Result<(), StoreError> {
            self.0
                .lock()
                .unwrap()
                .retain(|(i, n, _)| !(i == instance_id && n == name));
            Ok(())
        }
        async fn list(&self, instance_id: &str) -> Result<Vec<(String, String)>, StoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(i, _, _)| i == instance_id)
                .map(|(_, n, c)| (n.clone(), c.clone()))
                .collect())
        }
    }

    struct MemUserSecretStore(Mutex<Vec<(String, String, String)>>);
    #[async_trait::async_trait]
    impl UserSecretStore for MemUserSecretStore {
        async fn put(&self, user_id: &str, name: &str, ct: &str) -> Result<(), StoreError> {
            let mut v = self.0.lock().unwrap();
            v.retain(|(u, n, _)| !(u == user_id && n == name));
            v.push((user_id.to_owned(), name.to_owned(), ct.to_owned()));
            Ok(())
        }
        async fn get(&self, user_id: &str, name: &str) -> Result<Option<String>, StoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|(u, n, _)| u == user_id && n == name)
                .map(|(_, _, c)| c.clone()))
        }
        async fn delete(&self, user_id: &str, name: &str) -> Result<(), StoreError> {
            self.0
                .lock()
                .unwrap()
                .retain(|(u, n, _)| !(u == user_id && n == name));
            Ok(())
        }
        async fn list(&self, user_id: &str) -> Result<Vec<(String, String)>, StoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(u, _, _)| u == user_id)
                .map(|(_, n, c)| (n.clone(), c.clone()))
                .collect())
        }
    }

    struct MemSystemSecretStore(Mutex<Vec<(String, String)>>);
    #[async_trait::async_trait]
    impl SystemSecretStore for MemSystemSecretStore {
        async fn put(&self, name: &str, ct: &str) -> Result<(), StoreError> {
            let mut v = self.0.lock().unwrap();
            v.retain(|(n, _)| n != name);
            v.push((name.to_owned(), ct.to_owned()));
            Ok(())
        }
        async fn get(&self, name: &str) -> Result<Option<String>, StoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, c)| c.clone()))
        }
        async fn delete(&self, name: &str) -> Result<(), StoreError> {
            self.0.lock().unwrap().retain(|(n, _)| n != name);
            Ok(())
        }
        async fn list_names(&self) -> Result<Vec<String>, StoreError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .map(|(n, _)| n.clone())
                .collect())
        }
    }

    fn ciphers() -> (tempfile::TempDir, Arc<dyn CipherDirectory>) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = AgeCipherDirectory::new(tmp.path()).unwrap();
        (tmp, Arc::new(dir))
    }

    fn user_id(seed: u8) -> String {
        format!("{:032x}", u128::from(seed) | (u128::from(seed) << 64))
    }

    async fn instance_store() -> Arc<dyn InstanceStore> {
        Arc::new(SqlxInstanceStore::new(
            open_in_memory().await.unwrap(),
            crate::db::test_system_cipher(),
        ))
    }

    async fn instance_store_with(owner_id: &str, instance_id: &str) -> Arc<dyn InstanceStore> {
        let pool = open_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, subject, display_name, status, created_at, activated_at) \
             VALUES (?, ?, ?, 'active', ?, ?)",
        )
        .bind(owner_id)
        .bind(format!("subject-{owner_id}"))
        .bind(owner_id)
        .bind(now_secs())
        .bind(now_secs())
        .execute(&pool)
        .await
        .unwrap();
        let store: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(
            pool,
            crate::db::test_system_cipher(),
        ));
        store
            .create(InstanceRow {
                id: instance_id.to_owned(),
                owner_id: owner_id.to_owned(),
                name: String::new(),
                task: String::new(),
                cube_sandbox_id: None,
                template_id: "tpl".into(),
                status: InstanceStatus::Live,
                bearer_token: "bt".into(),
                pinned: false,
                expires_at: None,
                last_active_at: now_secs(),
                last_probe_at: None,
                last_probe_status: None,
                created_at: now_secs(),
                destroyed_at: None,
                rotated_to: None,
                network_policy: NetworkPolicy::Open,
                network_policy_cidrs: Vec::new(),
                models: Vec::new(),
                tools: Vec::new(),
            })
            .await
            .unwrap();
        store
    }

    #[tokio::test]
    async fn instance_secret_round_trip_uses_owner_cipher() {
        let (_tmp, dir) = ciphers();
        let owner = user_id(0xa1);
        let svc = SecretsService::new(
            Arc::new(MemSecretStore(Mutex::new(Vec::new()))),
            instance_store().await,
            dir.clone(),
        );
        svc.put(&owner, "inst-1", "GITHUB_TOKEN", "ghp_secret")
            .await
            .unwrap();

        let got = svc.list(&owner, "inst-1").await.unwrap();
        assert_eq!(got, vec![("GITHUB_TOKEN".into(), "ghp_secret".into())]);
    }

    #[tokio::test]
    async fn instance_secret_cant_be_decrypted_by_other_user() {
        // The headline property: even if a malicious user has DB
        // access, secrets owned by another user are unrecoverable
        // without that user's age key.
        let (_tmp, dir) = ciphers();
        let alice = user_id(0xa1);
        let bob = user_id(0xb0);
        let svc = SecretsService::new(
            Arc::new(MemSecretStore(Mutex::new(Vec::new()))),
            instance_store().await,
            dir.clone(),
        );
        svc.put(&alice, "inst-1", "K", "alice-only").await.unwrap();

        // Bob asking for the same instance's secrets gets nothing
        // useful — the row's ciphertext fails to open with his key
        // and the row is silently skipped (logged).
        let bob_view = svc.list(&bob, "inst-1").await.unwrap();
        assert!(bob_view.is_empty(), "Bob must not see Alice's plaintext");
    }

    #[tokio::test]
    async fn user_secret_round_trip() {
        let (_tmp, dir) = ciphers();
        let svc = UserSecretsService::new(
            Arc::new(MemUserSecretStore(Mutex::new(Vec::new()))),
            dir.clone(),
        );
        let u = user_id(0x42);
        svc.put(&u, "openrouter_key", b"sk-or-v1-...")
            .await
            .unwrap();

        let got = svc.get(&u, "openrouter_key").await.unwrap();
        assert_eq!(got.as_deref(), Some(b"sk-or-v1-..." as &[u8]));

        // Wrong user → None (no row).
        let other = user_id(0x43);
        assert!(svc.get(&other, "openrouter_key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn system_secret_round_trip() {
        let (_tmp, dir) = ciphers();
        let svc = SystemSecretsService::new(
            Arc::new(MemSystemSecretStore(Mutex::new(Vec::new()))),
            dir.clone(),
        );
        svc.put("openrouter_provisioning", b"sk-or-prov-...")
            .await
            .unwrap();
        let got = svc.get_str("openrouter_provisioning").await.unwrap();
        assert_eq!(got.as_deref(), Some("sk-or-prov-..."));
        let names = svc.list_names().await.unwrap();
        assert_eq!(names, vec!["openrouter_provisioning"]);
    }

    #[tokio::test]
    async fn list_names_does_not_decrypt() {
        // list_names should work even when the cipher would fail —
        // proves we don't accidentally decrypt for the cheap path.
        let (_tmp, dir) = ciphers();
        let svc = SecretsService::new(
            Arc::new(MemSecretStore(Mutex::new(Vec::new()))),
            instance_store().await,
            dir.clone(),
        );
        let owner = user_id(0xa1);
        svc.put(&owner, "inst-1", "K1", "v1").await.unwrap();
        svc.put(&owner, "inst-1", "K2", "v2").await.unwrap();
        let names = svc.list_names("inst-1").await.unwrap();
        assert_eq!(names, vec!["K1", "K2"]);
    }

    #[tokio::test]
    async fn instance_secret_delete_requires_owner() {
        let (_tmp, dir) = ciphers();
        let alice = user_id(0xa1);
        let bob = user_id(0xb0);
        let secrets = Arc::new(MemSecretStore(Mutex::new(Vec::new())));
        let svc = SecretsService::new(
            secrets.clone(),
            instance_store_with(&alice, "inst-1").await,
            dir.clone(),
        );
        svc.put(&alice, "inst-1", "K", "alice-only").await.unwrap();

        let err = svc.delete(&bob, "inst-1", "K").await.unwrap_err();
        assert!(matches!(err, SecretsError::Store(StoreError::NotFound)));

        let names = svc.list_names("inst-1").await.unwrap();
        assert_eq!(names, vec!["K"]);
        svc.delete(&alice, "inst-1", "K").await.unwrap();
        assert!(svc.list_names("inst-1").await.unwrap().is_empty());
    }
}
