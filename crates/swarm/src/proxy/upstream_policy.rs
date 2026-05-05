//! Operator policy for user-selected BYO upstream URLs.

pub use dyson_swarm_core::upstream_policy::{
    OutboundUrlError as ByoUpstreamError, ValidatedOutboundUrl as ValidatedByoUpstream,
    pinned_outbound_client_builder as pinned_byo_client_builder,
};
use dyson_swarm_core::upstream_policy::{
    OutboundUrlPolicy, validate_cached_outbound_url, validate_outbound_url,
};

use crate::config::ByoConfig;

fn policy_from_byo(policy: &ByoConfig) -> OutboundUrlPolicy {
    OutboundUrlPolicy {
        enabled: policy.enabled,
        allow_localhost: policy.allow_localhost,
        allow_internal: policy.allow_internal,
    }
}

pub async fn validate_byo_upstream(
    policy: &ByoConfig,
    upstream: &str,
) -> Result<ValidatedByoUpstream, ByoUpstreamError> {
    validate_outbound_url(&policy_from_byo(policy), upstream).await
}

pub fn validate_cached_byo_upstream(
    policy: &ByoConfig,
    upstream: &str,
    cached_addrs: &[String],
) -> Result<ValidatedByoUpstream, ByoUpstreamError> {
    validate_cached_outbound_url(&policy_from_byo(policy), upstream, cached_addrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn allows_public_http_by_default() {
        let url = validate_byo_upstream(&ByoConfig::default(), "http://8.8.8.8/v1")
            .await
            .expect("public host allowed");
        assert_eq!(url.url.scheme(), "http");
        assert_eq!(
            url.resolved_addrs,
            vec!["8.8.8.8:80".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn rejects_when_disabled() {
        let policy = ByoConfig {
            enabled: false,
            allow_localhost: false,
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
            allow_localhost: false,
            allow_internal: true,
        };
        validate_byo_upstream(&policy, "http://127.0.0.1:11434")
            .await
            .expect("internal allowed");
    }

    #[tokio::test]
    async fn allow_localhost_opt_in_accepts_loopback_only() {
        let policy = ByoConfig {
            enabled: true,
            allow_localhost: true,
            allow_internal: false,
        };
        validate_byo_upstream(&policy, "http://localhost:11434")
            .await
            .expect("localhost allowed");
        validate_byo_upstream(&policy, "http://127.0.0.1:11434")
            .await
            .expect("ipv4 loopback allowed");
        validate_byo_upstream(&policy, "http://[::1]:11434")
            .await
            .expect("ipv6 loopback allowed");
    }

    #[tokio::test]
    async fn allow_localhost_does_not_open_other_internal_targets() {
        let policy = ByoConfig {
            enabled: true,
            allow_localhost: true,
            allow_internal: false,
        };
        let err = validate_byo_upstream(&policy, "http://10.0.0.5:11434")
            .await
            .expect_err("rfc1918 still blocked");
        assert!(matches!(err, ByoUpstreamError::InternalNotAllowed));
    }

    #[test]
    fn cached_validation_uses_pinned_addresses_without_dns() {
        let validated = validate_cached_byo_upstream(
            &ByoConfig::default(),
            "http://does-not-resolve.invalid/v1",
            &["8.8.8.8:80".to_owned()],
        )
        .expect("cached public address allowed");

        assert_eq!(validated.url.host_str(), Some("does-not-resolve.invalid"));
        assert_eq!(
            validated.resolved_addrs,
            vec!["8.8.8.8:80".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn cached_validation_rejects_hostname_without_pinned_addresses() {
        let err = validate_cached_byo_upstream(
            &ByoConfig::default(),
            "http://does-not-resolve.invalid/v1",
            &[],
        )
        .expect_err("hostname needs cached addrs");

        assert!(matches!(err, ByoUpstreamError::CachedAddrsMissing));
    }

    #[test]
    fn cached_validation_accepts_legacy_ip_literal_without_pinned_addresses() {
        let validated =
            validate_cached_byo_upstream(&ByoConfig::default(), "http://8.8.8.8/v1", &[])
                .expect("literal IP can be reconstructed without DNS");

        assert_eq!(
            validated.resolved_addrs,
            vec!["8.8.8.8:80".parse::<SocketAddr>().unwrap()]
        );
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
