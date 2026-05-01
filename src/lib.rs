pub mod api_client;
pub mod artefacts;
pub mod auth;
pub mod backup;
pub mod cli;
pub mod config;
pub mod cube_client;
pub mod db;
pub mod dyson_reconfig;
pub mod envelope;
pub mod error;
pub mod http;
pub mod instance;
pub mod instance_client;
pub mod instance_id;
pub mod logging;
pub mod mcp_servers;
pub mod network_policy;
pub mod openrouter;
pub mod policy;
pub mod probe;
pub mod proxy;
pub mod secrets;
pub mod shares;
pub mod snapshot;
pub mod traits;
pub mod ttl;
pub mod webhooks;

/// Wall-clock seconds since the Unix epoch as `i64`. Saturates at 0 on the
/// (unreachable in practice) pre-epoch path so callers don't need to plumb
/// errors for what is effectively a clock query.
pub fn now_secs() -> i64 {
    // Saturate at i64::MAX (year 292277026596) — wrapping into a negative
    // would corrupt every audit row's timestamp.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
