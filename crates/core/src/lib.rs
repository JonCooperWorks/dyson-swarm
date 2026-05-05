pub mod network_policy;

#[cfg(feature = "full")]
pub mod api_client;
#[cfg(feature = "full")]
pub mod artefacts;
#[cfg(feature = "full")]
pub mod backup;
#[cfg(feature = "full")]
pub mod config;
#[cfg(feature = "full")]
pub mod cube_client;
#[cfg(feature = "full")]
pub mod db;
#[cfg(feature = "full")]
pub mod dyson_reconfig;
#[cfg(feature = "full")]
pub mod envelope;
#[cfg(feature = "full")]
pub mod error;
#[cfg(feature = "full")]
pub mod instance;
#[cfg(feature = "full")]
pub mod instance_client;
#[cfg(feature = "full")]
pub mod instance_id;
#[cfg(feature = "full")]
pub mod mcp_servers;
#[cfg(feature = "full")]
pub mod openrouter;
#[cfg(feature = "full")]
pub mod policy;
#[cfg(feature = "full")]
pub mod probe;
#[cfg(feature = "full")]
pub mod secrets;
#[cfg(feature = "full")]
pub mod shares;
#[cfg(feature = "full")]
pub mod snapshot;
#[cfg(feature = "full")]
pub mod state_files;
#[cfg(feature = "full")]
pub mod traits;
#[cfg(feature = "full")]
pub mod ttl;
#[cfg(feature = "full")]
pub mod upstream_policy;
#[cfg(feature = "full")]
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
