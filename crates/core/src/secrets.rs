//! Secrets — two services, one shape: store opaque ciphertexts in
//! sqlite, route encrypt/decrypt through the right
//! [`crate::envelope::EnvelopeCipher`].
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
use crate::traits::{SystemSecretStore, UserSecretStore};

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
// compose_env — kept here so callers (instance.rs create + restore paths)
// only depend on this module.
// ───────────────────────────────────────────────────────────────────

/// Compose the env map handed to a CubeSandbox at create/restore time.
///
/// Priority order: **template → managed → caller**. Read left-to-right, with
/// the rightmost source winning on key collision. External service
/// credentials belong in MCP/user/system secret storage, not in the sandbox
/// environment.
pub fn compose_env(
    template: &BTreeMap<String, String>,
    managed: &BTreeMap<String, String>,
    caller: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut out = template.clone();
    for (k, v) in managed {
        out.insert(k.clone(), v.clone());
    }
    for (k, v) in caller {
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
        let merged = compose_env(&template, &managed, &caller);
        assert_eq!(merged["A"], "tpl");
        assert_eq!(merged["B"], "mgr");
        assert_eq!(merged["C"], "call");
        assert_eq!(merged["D"], "call");
    }

    #[test]
    fn compose_env_empty_inputs_are_identity() {
        let empty = BTreeMap::new();
        let only_template = m([("X", "1")]);
        let merged = compose_env(&only_template, &empty, &empty);
        assert_eq!(merged, only_template);
    }

    // ── Encryption-aware tests (user / system services) ───

    use crate::envelope::AgeCipherDirectory;
    use std::sync::Mutex;

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
}
