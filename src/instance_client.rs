//! Server-to-server fetch into a per-instance dyson agent.
//!
//! Used by `http::share_public` to pull artefact bytes on behalf of
//! anonymous viewers, and conceptually shared with `http::dyson_proxy`
//! (which inlines the same URL-build + bearer-stamp pattern for its
//! request-forwarding loop).  Kept separate from `dyson_proxy` because
//! that module's `forward` is a streaming round-trip with full body
//! passthrough; here we want a clean one-shot GET that returns the
//! upstream `reqwest::Response` for the caller to consume however
//! they like (read-to-bytes for JSON, stream-passthrough for raw
//! artefact bytes).
//!
//! Auth is `Authorization: Bearer <instance.bearer_token>` — the same
//! per-instance secret swarm minted at create time and dyson hashes on
//! first sighting (TOFU + argon2id).

use crate::traits::InstanceRow;

#[derive(Debug, thiserror::Error)]
pub enum InstanceFetchError {
    #[error("instance not yet ready (no cube sandbox id)")]
    NotReady,
    #[error("upstream unreachable: {0}")]
    Unreachable(String),
}

/// Issue an authenticated `GET` against `<instance>/<path>`.  `path`
/// is the dyson-side absolute path beginning with `/api/...`.
///
/// The caller can then `.bytes()` for full-buffered reads (JSON
/// metadata) or `.bytes_stream()` for streaming passthrough (artefact
/// body).  We do not stream-restrict here — the artefact endpoint on
/// dyson sets its own `Content-Type` and we want it preserved on the
/// public share response.
pub async fn fetch_artefact(
    http: &reqwest::Client,
    sandbox_domain: &str,
    instance: &InstanceRow,
    path: &str,
) -> Result<reqwest::Response, InstanceFetchError> {
    let sandbox_id = instance
        .cube_sandbox_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(InstanceFetchError::NotReady)?;
    let port = cube_port();
    let url = format!(
        "https://{port}-{sandbox_id}.{}{path}",
        sandbox_domain.trim_end_matches('/'),
    );
    let bearer = format!("Bearer {}", instance.bearer_token);
    let resp = http
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, bearer)
        .send()
        .await
        .map_err(|e| InstanceFetchError::Unreachable(e.to_string()))?;
    Ok(resp)
}

/// Same `SWARM_CUBE_INTERNAL_PORT` lookup `dyson_proxy` and webhooks
/// already use.  Default 80 — dyson always listens on 80 inside its
/// MicroVM, matching the cube template's `--expose-port 80`.
fn cube_port() -> u16 {
    std::env::var("SWARM_CUBE_INTERNAL_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(80)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::InstanceStatus;

    fn instance(sandbox_id: Option<&str>) -> InstanceRow {
        InstanceRow {
            id: "inst".into(),
            owner_id: "alice".into(),
            name: String::new(),
            task: String::new(),
            cube_sandbox_id: sandbox_id.map(str::to_owned),
            template_id: String::new(),
            status: InstanceStatus::Live,
            bearer_token: "tok".into(),
            pinned: false,
            expires_at: None,
            last_active_at: 0,
            last_probe_at: None,
            last_probe_status: None,
            created_at: 0,
            destroyed_at: None,
            rotated_to: None,
            network_policy: crate::network_policy::NetworkPolicy::Open,
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        }
    }

    #[tokio::test]
    async fn missing_sandbox_id_is_not_ready() {
        let client = reqwest::Client::new();
        let err = fetch_artefact(&client, "cube.test", &instance(None), "/api/foo")
            .await
            .unwrap_err();
        assert!(matches!(err, InstanceFetchError::NotReady));
    }

    #[tokio::test]
    async fn empty_sandbox_id_is_not_ready() {
        let client = reqwest::Client::new();
        let err = fetch_artefact(&client, "cube.test", &instance(Some("")), "/api/foo")
            .await
            .unwrap_err();
        assert!(matches!(err, InstanceFetchError::NotReady));
    }
}
