pub mod api_client;
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
pub mod logging;
pub mod openrouter;
pub mod policy;
pub mod probe;
pub mod proxy;
pub mod secrets;
pub mod snapshot;
pub mod traits;
pub mod ttl;

/// Wall-clock seconds since the Unix epoch as `i64`. Saturates at 0 on the
/// (unreachable in practice) pre-epoch path so callers don't need to plumb
/// errors for what is effectively a clock query.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
