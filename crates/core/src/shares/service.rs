//! Application service that wires the share primitives together.
//!
//! Holds the SQLite pool, the per-user secrets service, the shared
//! reqwest client used to talk to dyson, the configured sandbox
//! domain, and an `Arc<ShareMetrics>` for the public read path.  HTTP
//! handlers (`http::shares` for admin CRUD, `http::share_public` for
//! the anonymous read endpoint) do nothing more than parse params,
//! call into here, and translate the result into a status code.
//!
//! Owner-scoping happens at the entry: every method that's
//! user-attributed takes a `user_id` and asserts the matching
//! `instances.owner_id` before doing anything substantive.

use std::sync::Arc;

use sqlx::SqlitePool;

use super::{
    RejectReason, ShareError, ShareMetrics, ShareTtl, build_url, decode_token, ensure_signing_key,
    jti_hex, load_signing_key, new_payload, rotate_signing_key, sign_token, verify_with_key,
};
use crate::artefacts::ArtefactCache;
use crate::db::shares::{self, ShareRow, ShareSpec};
use crate::error::{StoreError, SwarmError};
use crate::instance::InstanceService;
use crate::now_secs;
use crate::secrets::{SecretsError, UserSecretsService};
use crate::traits::InstanceRow;

/// Single application-level error type so handlers map to status
/// codes in one place.  Internal arms are deliberately distinct from
/// `ShareError` (which is the byte-identical 404 hot-path family).
#[derive(Debug, thiserror::Error)]
pub enum ShareServiceError {
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("upstream unavailable: {0}")]
    Upstream(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Secrets(#[from] SecretsError),
}

impl From<SwarmError> for ShareServiceError {
    fn from(e: SwarmError) -> Self {
        match e {
            SwarmError::NotFound => Self::NotFound,
            SwarmError::BadRequest(m) => Self::BadRequest(m),
            SwarmError::Store(s) => Self::Store(s),
            other => Self::Upstream(other.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct ShareService {
    pool: SqlitePool,
    user_secrets: Arc<UserSecretsService>,
    instances: Arc<InstanceService>,
    artefact_cache: ArtefactCache,
    metrics: Arc<ShareMetrics>,
    apex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedShare {
    pub row: ShareRow,
    pub instance: InstanceRow,
}

impl ShareService {
    pub fn new(
        pool: SqlitePool,
        user_secrets: Arc<UserSecretsService>,
        instances: Arc<InstanceService>,
        artefact_cache: ArtefactCache,
        metrics: Arc<ShareMetrics>,
        apex: Option<String>,
    ) -> Self {
        Self {
            pool,
            user_secrets,
            instances,
            artefact_cache,
            metrics,
            apex,
        }
    }

    pub fn metrics(&self) -> &Arc<ShareMetrics> {
        &self.metrics
    }

    pub fn apex(&self) -> Option<&str> {
        self.apex.as_deref()
    }

    /// Mint a new share for an artefact owned by `caller_user_id`.
    /// The artefact must already exist in the swarm-side cache for
    /// the exact `(instance_id, chat_id, artefact_id)` tuple.  The
    /// cache is populated from dyson's authenticated artefact listing,
    /// so this keeps share creation tied to artefacts the caller could
    /// actually see instead of trusting a browser-supplied id.
    pub async fn mint(
        &self,
        caller_user_id: &str,
        instance_id: &str,
        chat_id: &str,
        artefact_id: &str,
        ttl: ShareTtl,
        label: Option<String>,
    ) -> Result<MintedShare, ShareServiceError> {
        // Ownership: 404 if the instance doesn't exist or doesn't
        // belong to caller, no oracle either way.
        self.instances
            .get(caller_user_id, instance_id)
            .await
            .map_err(|e| match e {
                SwarmError::NotFound => ShareServiceError::NotFound,
                other => ShareServiceError::Upstream(other.to_string()),
            })?;
        let cached = self
            .artefact_cache
            .find(instance_id, chat_id, artefact_id)
            .await
            .map_err(|e| ShareServiceError::Upstream(e.to_string()))?;
        match cached {
            Some(row) if row.owner_id == caller_user_id => {}
            _ => return Err(ShareServiceError::NotFound),
        }
        let key = ensure_signing_key(&self.user_secrets, caller_user_id).await?;
        let expires_at = now_secs() + ttl.seconds();
        let payload = new_payload(
            caller_user_id,
            instance_id,
            chat_id,
            artefact_id,
            expires_at,
        );
        let jti = jti_hex(payload.jti);
        let token = sign_token(&payload, &key).map_err(|e| match e {
            ShareError::Malformed => ShareServiceError::Upstream("payload encode failed".into()),
            other => ShareServiceError::Upstream(other.to_string()),
        })?;
        let label_ref = label.as_deref();
        let row = shares::mint(
            &self.pool,
            ShareSpec {
                jti: &jti,
                instance_id,
                chat_id,
                artefact_id,
                created_by: caller_user_id,
                expires_at,
                label: label_ref,
            },
        )
        .await?;
        Ok(MintedShare {
            url: build_url(self.apex.as_deref(), &token),
            jti: row.jti,
            expires_at: row.expires_at,
            label: row.label,
            created_at: row.created_at,
        })
    }

    /// All live shares this user has minted on this instance.
    pub async fn list(
        &self,
        caller_user_id: &str,
        instance_id: &str,
    ) -> Result<Vec<ShareRow>, ShareServiceError> {
        // Ownership probe — same shape as mint().
        self.instances
            .get(caller_user_id, instance_id)
            .await
            .map_err(|e| match e {
                SwarmError::NotFound => ShareServiceError::NotFound,
                other => ShareServiceError::Upstream(other.to_string()),
            })?;
        Ok(shares::list_for_instance(&self.pool, caller_user_id, instance_id).await?)
    }

    /// Idempotent revoke.  Always returns `Ok(())` to the SPA — it
    /// doesn't matter whether the row was found, already-revoked, or
    /// belonged to someone else.  The defensive case here is the
    /// cross-tenant probe: a guessed jti from an admin shouldn't leak
    /// "this jti exists but isn't yours" via differential status.
    pub async fn revoke(&self, caller_user_id: &str, jti: &str) -> Result<(), ShareServiceError> {
        let _ = shares::revoke(&self.pool, jti, caller_user_id).await?;
        Ok(())
    }

    /// Reissue: revoke the old jti and mint a fresh URL with the
    /// requested ttl, against the same artefact.  "Extend" in the UI
    /// is implemented as this — presigned URLs can't be extended in
    /// place without re-signing, and this surfaces the change-of-URL
    /// honestly to the user.
    pub async fn reissue(
        &self,
        caller_user_id: &str,
        jti: &str,
        ttl: ShareTtl,
    ) -> Result<MintedShare, ShareServiceError> {
        let row = shares::find_by_jti(&self.pool, jti)
            .await?
            .ok_or(ShareServiceError::NotFound)?;
        if row.created_by != caller_user_id {
            return Err(ShareServiceError::NotFound);
        }
        // Revoke first so a network blip mid-call leaves the user
        // with at most one valid URL outstanding (the new one) — never
        // none, never both.  shares::mint is independent of the row
        // we revoked, so a partial failure is recoverable: re-call.
        let _ = shares::revoke(&self.pool, jti, caller_user_id).await?;
        self.mint(
            caller_user_id,
            &row.instance_id,
            &row.chat_id,
            &row.artefact_id,
            ttl,
            row.label,
        )
        .await
    }

    /// Panic-button: blow away the user's signing key and mint a fresh
    /// one.  Every share they've ever issued now fails verification at
    /// the HMAC step.  The `artefact_shares` rows survive (audit), but
    /// the URLs are all dead.
    pub async fn rotate_key(&self, caller_user_id: &str) -> Result<(), ShareServiceError> {
        rotate_signing_key(&self.user_secrets, caller_user_id).await?;
        Ok(())
    }

    /// Public read-path verification.  Implements the cheap-reject
    /// hot path: parse → exp → user-key load → HMAC → revocation →
    /// owner-defense.  Increments `share_reject_total{reason=...}`
    /// metrics on every reject; emits no audit row before step 5.
    pub async fn verify(&self, token: &str) -> Result<VerifiedShare, ShareError> {
        // Steps 1-2: parse + version check + exp check.  Pure CPU.
        let (payload, sig) = match decode_token(token) {
            Ok(p) => p,
            Err(e) => {
                self.metrics.record_reject(e.reject_reason());
                return Err(e);
            }
        };
        if payload.exp <= now_secs() {
            self.metrics.record_reject(RejectReason::Expired);
            return Err(ShareError::Expired);
        }
        // Step 3: load the user's signing key.  Missing user → 404.
        let key = match load_signing_key(&self.user_secrets, &payload.user_id).await {
            Ok(k) => k,
            Err(e) => {
                self.metrics.record_reject(e.reject_reason());
                return Err(e);
            }
        };
        // Step 4: HMAC verify.  Pure CPU after the key load.
        if let Err(e) = verify_with_key(&payload, &sig, &key) {
            self.metrics.record_reject(e.reject_reason());
            return Err(e);
        }
        // Step 5: revocation lookup.  By this point the request has
        // proven possession of a valid signature on a real jti, so
        // missed-row / revoked-row map to BadSig (the cheapest 404
        // shape; clients can't tell which from the wire).
        let jti = jti_hex(payload.jti);
        let row = match shares::find_by_jti(&self.pool, &jti).await {
            Ok(Some(r)) if r.revoked_at.is_none() => r,
            Ok(_) => {
                self.metrics.record_reject(RejectReason::BadSig);
                return Err(ShareError::BadSig);
            }
            Err(_) => {
                self.metrics.record_reject(RejectReason::BadSig);
                return Err(ShareError::BadSig);
            }
        };
        // Step 6: instance lookup.  CASCADE means a destroyed instance
        // already removed the share row above; reaching this branch
        // with a missing instance therefore implies a race or a bug —
        // either way 404 is the right answer.
        let instance = match self.instances.get_unscoped(&payload.instance_id).await {
            Ok(i) => i,
            Err(_) => {
                self.metrics.record_reject(RejectReason::BadSig);
                return Err(ShareError::BadSig);
            }
        };
        // Defense: payload.user_id MUST match the instance's owner.
        // Otherwise a leaked signing key from user A could sign URLs
        // pointing into user B's instance.
        if instance.owner_id != payload.user_id {
            self.metrics.record_reject(RejectReason::BadSig);
            return Err(ShareError::BadSig);
        }
        self.metrics.record_accept();
        Ok(VerifiedShare { row, instance })
    }

    /// Append an audit row.  Called only on the verified-and-served
    /// path — bad-sig / expired / unknown-user attempts are not
    /// logged here (they're metric'd above).
    pub async fn record_access(
        &self,
        jti: &str,
        remote_addr: Option<&str>,
        user_agent: Option<&str>,
        status: i32,
    ) {
        if let Err(e) =
            shares::record_access(&self.pool, jti, remote_addr, user_agent, status).await
        {
            tracing::warn!(jti, %e, "share access audit insert failed");
        }
    }

    /// Re-derive the public URL for a still-active share owned by
    /// `caller_user_id`.  The HMAC signature is deterministic
    /// (postcard payload bytes are byte-identical for the same row,
    /// the key is the caller's sealed signing key) — so we can hand
    /// the URL back to the SPA on demand without ever having stored
    /// it.  Revoked / expired rows return `Ok(None)` so the caller
    /// can render a disabled affordance instead of a 4xx.
    pub async fn url_for(
        &self,
        caller_user_id: &str,
        jti: &str,
    ) -> Result<Option<String>, ShareServiceError> {
        let row = shares::find_by_jti(&self.pool, jti)
            .await?
            .ok_or(ShareServiceError::NotFound)?;
        if row.created_by != caller_user_id {
            return Err(ShareServiceError::NotFound);
        }
        if row.revoked_at.is_some() || row.expires_at <= now_secs() {
            return Ok(None);
        }
        // jti string column is hex of payload.jti — reverse to bytes.
        let mut jti_bytes = [0u8; 16];
        if hex::decode_to_slice(&row.jti, &mut jti_bytes).is_err() {
            return Err(ShareServiceError::Upstream("malformed jti".into()));
        }
        let key = ensure_signing_key(&self.user_secrets, caller_user_id).await?;
        let payload = super::SharePayload {
            v: 1,
            user_id: row.created_by.clone(),
            instance_id: row.instance_id.clone(),
            chat_id: row.chat_id.clone(),
            artefact_id: row.artefact_id.clone(),
            exp: row.expires_at,
            jti: jti_bytes,
        };
        let token = sign_token(&payload, &key)
            .map_err(|_| ShareServiceError::Upstream("payload encode failed".into()))?;
        Ok(Some(super::build_url(self.apex.as_deref(), &token)))
    }

    /// Recent accesses for the SPA's audit detail view.
    pub async fn list_accesses(
        &self,
        caller_user_id: &str,
        jti: &str,
        limit: u32,
    ) -> Result<Vec<crate::db::shares::ShareAccessRow>, ShareServiceError> {
        // Ownership: the share must belong to caller before we expose
        // its access log.  Mirrors revoke()'s hidden-existence shape.
        let row = shares::find_by_jti(&self.pool, jti)
            .await?
            .ok_or(ShareServiceError::NotFound)?;
        if row.created_by != caller_user_id {
            return Err(ShareServiceError::NotFound);
        }
        Ok(shares::list_accesses(&self.pool, jti, limit).await?)
    }
}

/// Wire shape returned by mint/reissue.  The plaintext URL is shown
/// to the SPA *once*; the row stores only the hash-of-payload (well,
/// the jti — the URL itself isn't reconstructible without the user's
/// signing key, which never leaves the secrets store unsealed).
#[derive(Debug, Clone, serde::Serialize)]
pub struct MintedShare {
    pub url: String,
    pub jti: String,
    pub expires_at: i64,
    pub label: Option<String>,
    pub created_at: i64,
}
