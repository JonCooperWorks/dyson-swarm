//! Shared outbound URL SSRF policy for tenant-supplied upstreams.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundUrlPolicy {
    pub enabled: bool,
    pub allow_localhost: bool,
    pub allow_internal: bool,
}

impl Default for OutboundUrlPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_localhost: false,
            allow_internal: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutboundUrlError {
    #[error("upstreams are disabled")]
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
    #[error("upstream cached address is invalid: {0}")]
    CachedAddrInvalid(String),
    #[error("upstream cached addresses are missing")]
    CachedAddrsMissing,
    #[error("internal upstreams are disabled")]
    InternalNotAllowed,
}

#[derive(Debug, Clone)]
pub struct ValidatedOutboundUrl {
    pub url: reqwest::Url,
    pub resolved_addrs: Vec<SocketAddr>,
}

pub async fn validate_outbound_url(
    policy: &OutboundUrlPolicy,
    upstream: &str,
) -> Result<ValidatedOutboundUrl, OutboundUrlError> {
    let url = parse_outbound_url(policy, upstream)?;
    let host = url.host_str().ok_or(OutboundUrlError::MissingHost)?;
    let resolved_addrs = resolve_addrs(host, url.port_or_known_default()).await?;
    validate_resolved_addrs(policy, &url, &resolved_addrs)?;
    Ok(ValidatedOutboundUrl {
        url,
        resolved_addrs,
    })
}

pub fn validate_cached_outbound_url(
    policy: &OutboundUrlPolicy,
    upstream: &str,
    cached_addrs: &[String],
) -> Result<ValidatedOutboundUrl, OutboundUrlError> {
    let url = parse_outbound_url(policy, upstream)?;
    let resolved_addrs = cached_or_literal_addrs(&url, cached_addrs)?;
    validate_resolved_addrs(policy, &url, &resolved_addrs)?;
    Ok(ValidatedOutboundUrl {
        url,
        resolved_addrs,
    })
}

pub fn pinned_outbound_client_builder(validated: &ValidatedOutboundUrl) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    match validated.url.host_str() {
        Some(host) => builder.resolve_to_addrs(host, &validated.resolved_addrs),
        None => builder,
    }
}

fn parse_outbound_url(
    policy: &OutboundUrlPolicy,
    upstream: &str,
) -> Result<reqwest::Url, OutboundUrlError> {
    if !policy.enabled {
        return Err(OutboundUrlError::Disabled);
    }
    let trimmed = upstream.trim();
    if trimmed.is_empty() {
        return Err(OutboundUrlError::Empty);
    }
    let url =
        reqwest::Url::parse(trimmed).map_err(|e| OutboundUrlError::InvalidUrl(e.to_string()))?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(OutboundUrlError::UnsupportedScheme(other.to_owned())),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OutboundUrlError::UserInfo);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(OutboundUrlError::QueryOrFragment);
    }
    url.host_str().ok_or(OutboundUrlError::MissingHost)?;
    Ok(url)
}

fn validate_resolved_addrs(
    policy: &OutboundUrlPolicy,
    url: &reqwest::Url,
    resolved_addrs: &[SocketAddr],
) -> Result<(), OutboundUrlError> {
    if policy.allow_internal {
        return Ok(());
    }
    if policy.allow_localhost && is_localhost_target(url, resolved_addrs) {
        return Ok(());
    }
    if resolved_addrs.iter().any(|addr| is_internal_ip(addr.ip())) {
        return Err(OutboundUrlError::InternalNotAllowed);
    }
    Ok(())
}

fn is_localhost_target(url: &reqwest::Url, resolved_addrs: &[SocketAddr]) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let literal_host = host.trim_start_matches('[').trim_end_matches(']');
    let host_ok = literal_host.eq_ignore_ascii_case("localhost")
        || literal_host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    host_ok
        && !resolved_addrs.is_empty()
        && resolved_addrs.iter().all(|addr| addr.ip().is_loopback())
}

async fn resolve_addrs(host: &str, port: Option<u16>) -> Result<Vec<SocketAddr>, OutboundUrlError> {
    let port = port.unwrap_or(443);
    let literal_host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal_host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs = tokio::net::lookup_host((literal_host, port))
        .await
        .map_err(|e| OutboundUrlError::Resolve(e.to_string()))?;
    let mut out: Vec<SocketAddr> = addrs.collect();
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(OutboundUrlError::Resolve("no addresses returned".into()));
    }
    Ok(out)
}

fn cached_or_literal_addrs(
    url: &reqwest::Url,
    cached_addrs: &[String],
) -> Result<Vec<SocketAddr>, OutboundUrlError> {
    let mut out = Vec::with_capacity(cached_addrs.len());
    for addr in cached_addrs {
        out.push(
            addr.parse::<SocketAddr>()
                .map_err(|e| OutboundUrlError::CachedAddrInvalid(e.to_string()))?,
        );
    }
    if out.is_empty() {
        let host = url.host_str().ok_or(OutboundUrlError::MissingHost)?;
        let ip = host
            .parse::<IpAddr>()
            .map_err(|_| OutboundUrlError::CachedAddrsMissing)?;
        out.push(SocketAddr::new(
            ip,
            url.port_or_known_default().unwrap_or(443),
        ));
    }
    out.sort();
    out.dedup();
    Ok(out)
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
