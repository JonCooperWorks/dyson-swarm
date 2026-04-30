//! Anonymous artefact sharing via per-user-signed URLs.
//!
//! Threat model: the URL itself is the capability.  Possession of a
//! valid `(payload, sig)` pair signed by user X's signing key proves
//! that user X (or someone they've shared the URL with) is permitted
//! to fetch one specific artefact owned by one specific instance, up
//! until `payload.exp`.  Revocation is enforced by an out-of-band
//! check against the `artefact_shares` table.
//!
//! Why per-user keys: the share signing key is sealed in
//! `user_secrets` under name `share_signing_key`, encrypted with the
//! owner user's age cipher.  This means
//!
//! - a stolen DB row is unrecoverable without the owning user's age
//!   key,
//! - a single user rotating their key invalidates every share they
//!   ever issued — the panic-button affordance,
//! - one user's signing key compromise never lets the attacker forge
//!   shares into another user's instance.
//!
//! Hot-path verification is `parse → exp → key-load → HMAC → DB`,
//! ordered so scanner-noise (parse-fail, expired) costs zero DB and
//! zero secret-store I/O.  See `verify_url` for the implementation
//! and `crate::http::share_public::dispatch` for how it wires into
//! the host-based router.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::secrets::{SecretsError, UserSecretsService};

pub mod render;
pub mod service;
pub use service::ShareService;

/// Path prefix under `share.<apex>/...` reserved for v1 payloads.
/// A future v2 (e.g. a different signing scheme) will live under
/// `/v2/...` so old links keep working.
pub const V1_PATH_PREFIX: &str = "/v1/";

/// Name of the user_secret holding the per-user signing key.  Sealed
/// with the user's own age cipher; size is exactly 32 random bytes.
pub const SIGNING_KEY_SECRET_NAME: &str = "share_signing_key";
const SIGNING_KEY_BYTES: usize = 32;

/// The URL payload.  Post-card encoded, then base64url'd, then
/// concatenated with the b64url-encoded HMAC tag separated by `.`.
///
/// `v` is a version byte so future changes to the layout don't have
/// to live alongside v1 in the same parser; `verify_url` rejects
/// anything that isn't a `v=1` envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharePayload {
    pub v: u8,
    pub user_id: String,
    pub instance_id: String,
    pub chat_id: String,
    pub artefact_id: String,
    pub exp: i64,
    pub jti: [u8; 16],
}

/// Lifetime grammar for share mint: 1d, 7d, 30d, or never.  "Never"
/// is encoded as a far-future absolute exp (year ≈ 2126) — well
/// inside i64 seconds, well outside any realistic share lifetime,
/// and still subject to revocation + signing-key rotation.  The
/// owner-facing affordance is the same in both cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareTtl {
    Day,
    Week,
    Month,
    Never,
}

/// 100 years in seconds — the "never" sentinel exp delta.  Picked so
/// `now + delta` lands far in the future without flirting with
/// i64::MAX (which would make off-by-one checks awkward) and stays
/// monotonically larger than any realistic system clock, including
/// container hosts whose clocks have been seen drifting decades.
const NEVER_DELTA_SECS: i64 = 100 * 365 * 24 * 3600;

impl ShareTtl {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "1d" => Some(Self::Day),
            "7d" => Some(Self::Week),
            "30d" => Some(Self::Month),
            "never" => Some(Self::Never),
            _ => None,
        }
    }

    pub fn seconds(self) -> i64 {
        match self {
            Self::Day => 24 * 3600,
            Self::Week => 7 * 24 * 3600,
            Self::Month => 30 * 24 * 3600,
            Self::Never => NEVER_DELTA_SECS,
        }
    }
}

/// Errors during URL parse + verify.  Every public-facing terminal
/// arm in the share handler maps these to a single byte-identical 404
/// — the differentiation is for tracing/metrics only, never sent to
/// the wire.
#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    #[error("malformed share url")]
    Malformed,
    #[error("share has expired")]
    Expired,
    #[error("unknown user signing key")]
    UnknownUser,
    #[error("signature mismatch")]
    BadSig,
    #[error(transparent)]
    Secrets(#[from] SecretsError),
}

/// Hot-path reject reason — used for the
/// `share_reject_total{reason="..."}` Prometheus counter; values
/// stable so dashboards don't break on rename.
#[derive(Debug, Clone, Copy)]
pub enum RejectReason {
    Parse,
    Expired,
    UnknownUser,
    BadSig,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Expired => "expired",
            Self::UnknownUser => "unknown_user",
            Self::BadSig => "bad_sig",
        }
    }
}

impl ShareError {
    pub fn reject_reason(&self) -> RejectReason {
        match self {
            Self::Malformed => RejectReason::Parse,
            Self::Expired => RejectReason::Expired,
            Self::UnknownUser | Self::Secrets(_) => RejectReason::UnknownUser,
            Self::BadSig => RejectReason::BadSig,
        }
    }
}

/// Build the URL token: `<b64url(payload)>.<b64url(sig)>`.
///
/// `key` must be the user's own signing key — the verifier will look
/// it up by `payload.user_id`.  Return value is just the token; the
/// caller composes the full URL (`https://share.<apex>/v1/<token>`).
pub fn sign_token(payload: &SharePayload, key: &[u8]) -> Result<String, ShareError> {
    let payload_bytes = postcard::to_allocvec(payload).map_err(|_| ShareError::Malformed)?;
    let sig = hmac_sha256(key, &payload_bytes);
    let mut token = String::with_capacity(payload_bytes.len() * 2);
    URL_SAFE_NO_PAD.encode_string(&payload_bytes, &mut token);
    token.push('.');
    URL_SAFE_NO_PAD.encode_string(sig, &mut token);
    Ok(token)
}

/// Pure-CPU parse of the URL token into its payload and raw signature
/// bytes.  Does NOT verify the signature — verification needs the
/// signer's key, which the caller looks up by `payload.user_id` after
/// this returns.  Reject reasons:
///
/// - missing/extra `.` separator → `Malformed`
/// - non-base64url → `Malformed`
/// - unknown version byte → `Malformed`
/// - postcard decode failure → `Malformed`
///
/// Length bounds: postcard payloads for plausible ULIDs land at
/// ~80-120 bytes; we cap input length at 1 KiB so a long URL can't
/// drive the decoder into a multi-megabyte allocation.
pub fn decode_token(token: &str) -> Result<(SharePayload, Vec<u8>), ShareError> {
    if token.len() > 1024 {
        return Err(ShareError::Malformed);
    }
    let (payload_b64, sig_b64) = token.split_once('.').ok_or(ShareError::Malformed)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| ShareError::Malformed)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|_| ShareError::Malformed)?;
    let payload: SharePayload =
        postcard::from_bytes(&payload_bytes).map_err(|_| ShareError::Malformed)?;
    if payload.v != 1 {
        return Err(ShareError::Malformed);
    }
    Ok((payload, sig_bytes))
}

/// Verify a parsed `(payload, sig)` against a candidate signing key.
/// Constant-time comparison via the existing `subtle` helper shape.
/// Caller has already checked `payload.exp` against the wall clock
/// before this is called (the cheap-reject ordering).
pub fn verify_with_key(
    payload: &SharePayload,
    sig: &[u8],
    key: &[u8],
) -> Result<(), ShareError> {
    let payload_bytes = postcard::to_allocvec(payload).map_err(|_| ShareError::Malformed)?;
    let expected = hmac_sha256(key, &payload_bytes);
    if !ct_eq(&expected, sig) {
        return Err(ShareError::BadSig);
    }
    Ok(())
}

/// One-shot helper: read the user's signing key from `user_secrets`,
/// returning `UnknownUser` on miss.  Lazy minted on the write path
/// (see `ensure_signing_key`) so the read path can assume the key
/// exists for any user that has ever minted a share.
pub async fn load_signing_key(
    user_secrets: &UserSecretsService,
    user_id: &str,
) -> Result<Vec<u8>, ShareError> {
    match user_secrets.get(user_id, SIGNING_KEY_SECRET_NAME).await? {
        Some(bytes) if bytes.len() == SIGNING_KEY_BYTES => Ok(bytes),
        // Length mismatch is a malformed/legacy row — treat as unknown
        // rather than panicking.  The mint path always writes exactly
        // 32 bytes.
        Some(_) | None => Err(ShareError::UnknownUser),
    }
}

/// Lazy bootstrap.  If the user already has a signing key, return it;
/// otherwise mint 32 fresh bytes, seal them, and return.  Idempotent
/// under racy concurrent calls in practice — the secret_store does an
/// upsert, so the worst-case interleaving is "one of two equal-quality
/// keys wins"; both produce valid signatures only their own owner can
/// verify, but only one ends up sealed at rest.
pub async fn ensure_signing_key(
    user_secrets: &UserSecretsService,
    user_id: &str,
) -> Result<Vec<u8>, SecretsError> {
    if let Some(bytes) = user_secrets.get(user_id, SIGNING_KEY_SECRET_NAME).await?
        && bytes.len() == SIGNING_KEY_BYTES
    {
        return Ok(bytes);
    }
    let mut key = vec![0u8; SIGNING_KEY_BYTES];
    rand::thread_rng().fill_bytes(&mut key);
    user_secrets
        .put(user_id, SIGNING_KEY_SECRET_NAME, &key)
        .await?;
    Ok(key)
}

/// Panic-button rotation.  Deletes the existing key and mints a fresh
/// one, returning the new bytes.  Every share previously signed with
/// the old key now fails verification at the HMAC step — instant
/// global revoke for that user.  `artefact_shares` rows survive so
/// the SPA can still show "this share existed once" in audit views,
/// but they're unverifiable in the wild.
pub async fn rotate_signing_key(
    user_secrets: &UserSecretsService,
    user_id: &str,
) -> Result<Vec<u8>, SecretsError> {
    let _ = user_secrets
        .delete(user_id, SIGNING_KEY_SECRET_NAME)
        .await;
    let mut key = vec![0u8; SIGNING_KEY_BYTES];
    rand::thread_rng().fill_bytes(&mut key);
    user_secrets
        .put(user_id, SIGNING_KEY_SECRET_NAME, &key)
        .await?;
    Ok(key)
}

/// Build a fresh `SharePayload` with a random jti.  The version byte
/// is locked to 1 here so callers can't accidentally mint into a
/// version they didn't intend.
pub fn new_payload(
    user_id: &str,
    instance_id: &str,
    chat_id: &str,
    artefact_id: &str,
    expires_at: i64,
) -> SharePayload {
    let mut jti = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut jti);
    SharePayload {
        v: 1,
        user_id: user_id.to_owned(),
        instance_id: instance_id.to_owned(),
        chat_id: chat_id.to_owned(),
        artefact_id: artefact_id.to_owned(),
        exp: expires_at,
        jti,
    }
}

/// Hex-encode a jti for the row primary key.  Fixed 32-char output.
pub fn jti_hex(jti: [u8; 16]) -> String {
    hex::encode(jti)
}

/// Resolve `share_base_host` from the configured swarm hostname.
/// Returns `Some("share.<apex>")`, or `None` when no hostname is
/// configured (tests).
pub fn share_host(apex: Option<&str>) -> Option<String> {
    apex.map(|h| format!("share.{h}"))
}

/// Build the public URL for a freshly-minted share.  `apex` is the
/// configured swarm hostname (e.g. `swarm.example.com`).  If apex
/// is `None`, returns the `/v1/<token>` path-only form so the
/// SPA in test/local-dev environments can still render the link.
pub fn build_url(apex: Option<&str>, token: &str) -> String {
    match share_host(apex) {
        Some(h) => format!("https://{h}{V1_PATH_PREFIX}{token}"),
        None => format!("{V1_PATH_PREFIX}{token}"),
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length, per RFC 2104");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Counters surfaced through the existing metrics endpoint.  Updated
/// on the public read path before any DB I/O (for parse/expired) and
/// after the user-key load (for unknown-user/bad-sig).  Held as
/// process-local atomics so the increments are lock-free on the hot
/// path.
#[derive(Default)]
pub struct ShareMetrics {
    pub reject_parse: std::sync::atomic::AtomicU64,
    pub reject_expired: std::sync::atomic::AtomicU64,
    pub reject_unknown_user: std::sync::atomic::AtomicU64,
    pub reject_bad_sig: std::sync::atomic::AtomicU64,
    pub accept_total: std::sync::atomic::AtomicU64,
}

impl ShareMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_reject(&self, reason: RejectReason) {
        use std::sync::atomic::Ordering::Relaxed;
        match reason {
            RejectReason::Parse => self.reject_parse.fetch_add(1, Relaxed),
            RejectReason::Expired => self.reject_expired.fetch_add(1, Relaxed),
            RejectReason::UnknownUser => self.reject_unknown_user.fetch_add(1, Relaxed),
            RejectReason::BadSig => self.reject_bad_sig.fetch_add(1, Relaxed),
        };
    }

    pub fn record_accept(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.accept_total.fetch_add(1, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_payload() -> SharePayload {
        SharePayload {
            v: 1,
            user_id: "u".into(),
            instance_id: "i".into(),
            chat_id: "c".into(),
            artefact_id: "a".into(),
            exp: 1_700_000_000,
            jti: [7u8; 16],
        }
    }

    #[test]
    fn encode_decode_roundtrip_preserves_payload() {
        let key = [9u8; 32];
        let payload = fixed_payload();
        let token = sign_token(&payload, &key).unwrap();
        let (back, sig) = decode_token(&token).unwrap();
        assert_eq!(back, payload);
        verify_with_key(&back, &sig, &key).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = [9u8; 32];
        let mut payload = fixed_payload();
        let token = sign_token(&payload, &key).unwrap();
        payload.exp += 1;
        let (decoded, sig) = decode_token(&token).unwrap();
        // The decoded payload still matches the original (the URL
        // hasn't changed); but if a caller tries to verify a forged
        // payload against the real sig, ct_eq fails.
        let _ = decoded;
        let forged_payload_bytes = postcard::to_allocvec(&payload).unwrap();
        let forged_sig = hmac_sha256(&key, &forged_payload_bytes);
        assert_ne!(forged_sig, *sig.as_slice(), "different bytes → different sigs");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let payload = fixed_payload();
        let token = sign_token(&payload, &[1u8; 32]).unwrap();
        let (back, sig) = decode_token(&token).unwrap();
        let err = verify_with_key(&back, &sig, &[2u8; 32]).unwrap_err();
        assert!(matches!(err, ShareError::BadSig));
    }

    #[test]
    fn decode_garbage_does_not_panic() {
        for bad in [
            "",
            ".",
            "no-dot-here",
            "...too.many.dots",
            "@!.&%",                    // invalid base64
            &"a".repeat(2048),          // over the 1KiB cap
            // Valid base64 but not postcard:
            &format!("{}.{}", URL_SAFE_NO_PAD.encode(b"hello"), URL_SAFE_NO_PAD.encode(b"sig")),
        ] {
            let err = decode_token(bad).unwrap_err();
            assert!(matches!(err, ShareError::Malformed), "input {bad:?}");
        }
    }

    #[test]
    fn ttl_parses_known_values() {
        assert_eq!(ShareTtl::parse("1d"), Some(ShareTtl::Day));
        assert_eq!(ShareTtl::parse("7d"), Some(ShareTtl::Week));
        assert_eq!(ShareTtl::parse("30d"), Some(ShareTtl::Month));
        assert_eq!(ShareTtl::parse("never"), Some(ShareTtl::Never));
        assert!(ShareTtl::parse("").is_none());
        assert!(ShareTtl::parse("forever").is_none());
        assert_eq!(ShareTtl::Day.seconds(), 24 * 3600);
        assert_eq!(ShareTtl::Week.seconds(), 7 * 24 * 3600);
        // "never" lands in the next century, but still well below i64::MAX
        // so `now + delta` doesn't overflow.
        assert!(ShareTtl::Never.seconds() > 30 * 24 * 3600);
        assert!(ShareTtl::Never.seconds() < i64::MAX / 2);
    }

    #[test]
    fn share_host_pairs_with_apex() {
        assert_eq!(
            share_host(Some("swarm.example.com")).as_deref(),
            Some("share.swarm.example.com"),
        );
        assert!(share_host(None).is_none());
    }

    #[test]
    fn build_url_full_form_when_apex_known() {
        let url = build_url(Some("swarm.example.com"), "tok");
        assert_eq!(url, "https://share.swarm.example.com/v1/tok");
    }

    #[test]
    fn build_url_path_only_when_apex_missing() {
        assert_eq!(build_url(None, "tok"), "/v1/tok");
    }
}
