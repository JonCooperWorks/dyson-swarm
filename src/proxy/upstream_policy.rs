//! Operator policy for user-selected BYO upstream URLs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::ByoConfig;

#[derive(Debug, thiserror::Error)]
pub enum ByoUpstreamError {
    #[error("byo upstreams are disabled")]
    Disabled,
    #[error("upstream is empty")]
    Empty,
    #[error("invalid upstream URL: {0}")]
    InvalidUrl(String),
    #[error("unsupported upstream URL scheme: {0}")]
    UnsupportedScheme(String),
    #[error("upstream URL must not contain userinfo")]
    UserInfo,
    #[error("upstream URL must not contain query or fragment")]
    QueryOrFragment,
    #[error("upstream URL is missing a host")]
    MissingHost,
    #[error("upstream host did not resolve: {0}")]
    Resolve(String),
    #[error("internal BYO upstreams are disabled")]
    InternalNotAllowed,
}

/// Parse and authorize a BYO upstream base URL. BYO is enabled by
/// default because it is a core feature; the conservative default is
/// blocking internal/private addresses unless the operator opts in for
/// local, Tailscale, or DGX-style deployments.
pub async fn validate_byo_upstream(
    policy: &ByoConfig,
    upstream: &str,
) -> Result<reqwest::Url, ByoUpstreamError> {
    if !policy.enabled {
        return Err(ByoUpstreamError::Disabled);
    }
    let trimmed = upstream.trim();
    if trimmed.is_empty() {
        return Err(ByoUpstreamError::Empty);
    }
    let url =
        reqwest::Url::parse(trimmed).map_err(|e| ByoUpstreamError::InvalidUrl(e.to_string()))?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(ByoUpstreamError::UnsupportedScheme(other.to_owned())),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ByoUpstreamError::UserInfo);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ByoUpstreamError::QueryOrFragment);
    }
    let host = url.host_str().ok_or(ByoUpstreamError::MissingHost)?;
    if !policy.allow_internal && resolves_internal(host, url.port_or_known_default()).await? {
        return Err(ByoUpstreamError::InternalNotAllowed);
    }
    Ok(url)
}

async fn resolves_internal(host: &str, port: Option<u16>) -> Result<bool, ByoUpstreamError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(is_internal_ip(ip));
    }
    let port = port.unwrap_or(443);
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ByoUpstreamError::Resolve(e.to_string()))?;
    let mut saw_addr = false;
    for addr in addrs {
        saw_addr = true;
        if is_internal_ip(addr.ip()) {
            return Ok(true);
        }
    }
    if saw_addr {
        Ok(false)
    } else {
        Err(ByoUpstreamError::Resolve("no addresses returned".into()))
    }
}

fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => is_internal_v6(v6),
    }
}

fn is_internal_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || a == 0
        || a == 100 && (64..=127).contains(&b)
        || a >= 224
}

fn is_internal_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || (seg[0] & 0xfe00) == 0xfc00
        || (seg[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_public_http_by_default() {
        let url = validate_byo_upstream(&ByoConfig::default(), "http://8.8.8.8/v1")
            .await
            .expect("public host allowed");
        assert_eq!(url.scheme(), "http");
    }

    #[tokio::test]
    async fn rejects_when_disabled() {
        let policy = ByoConfig {
            enabled: false,
            allow_internal: false,
        };
        let err = validate_byo_upstream(&policy, "http://8.8.8.8")
            .await
            .expect_err("disabled");
        assert!(matches!(err, ByoUpstreamError::Disabled));
    }

    #[tokio::test]
    async fn blocks_internal_literals_by_default() {
        let err = validate_byo_upstream(&ByoConfig::default(), "http://127.0.0.1:11434")
            .await
            .expect_err("blocked");
        assert!(matches!(err, ByoUpstreamError::InternalNotAllowed));

        let err = validate_byo_upstream(&ByoConfig::default(), "http://169.254.169.254")
            .await
            .expect_err("blocked");
        assert!(matches!(err, ByoUpstreamError::InternalNotAllowed));
    }

    #[tokio::test]
    async fn allow_internal_opt_in_accepts_local_targets() {
        let policy = ByoConfig {
            enabled: true,
            allow_internal: true,
        };
        validate_byo_upstream(&policy, "http://127.0.0.1:11434")
            .await
            .expect("internal allowed");
    }

    #[tokio::test]
    async fn rejects_query_fragment_userinfo_and_non_http_schemes() {
        assert!(matches!(
            validate_byo_upstream(&ByoConfig::default(), "file:///etc/passwd")
                .await
                .expect_err("scheme"),
            ByoUpstreamError::UnsupportedScheme(_)
        ));
        assert!(matches!(
            validate_byo_upstream(&ByoConfig::default(), "http://x@8.8.8.8")
                .await
                .expect_err("userinfo"),
            ByoUpstreamError::UserInfo
        ));
        assert!(matches!(
            validate_byo_upstream(&ByoConfig::default(), "http://8.8.8.8?x=1")
                .await
                .expect_err("query"),
            ByoUpstreamError::QueryOrFragment
        ));
    }
}
