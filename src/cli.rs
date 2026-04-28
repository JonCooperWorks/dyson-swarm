use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "warden",
    version,
    about = "Orchestrator for Dyson agents in CubeSandbox MicroVMs",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Path to the config TOML.
    #[arg(long, default_value = "/etc/dyson-warden/config.toml", global = true)]
    pub config: PathBuf,

    /// Disable the admin-token check on /v1/* routes. Loud and dangerous;
    /// see startup banner for details.
    #[arg(long = "dangerous-no-auth", default_value_t = false, global = true)]
    pub dangerous_no_auth: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the HTTP server (default action when no subcommand is given).
    Serve,

    /// Per-instance secret material.
    Secrets {
        #[command(subcommand)]
        action: SecretsAction,
    },

    /// Create a new instance from a template.
    New {
        #[arg(long)]
        template: String,
        /// `KEY=VALUE` env entries (repeatable).
        #[arg(long = "env", value_parser = parse_kv)]
        env: Vec<(String, String)>,
        #[arg(long)]
        ttl_seconds: Option<i64>,
    },

    /// Destroy an instance by id.
    Destroy { id: String },

    /// List instances. By default destroyed rows are excluded.
    List {
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = false)]
        include_destroyed: bool,
    },

    /// Take a snapshot of an instance (kind=manual).
    Snapshot { id: String },

    /// Take a snapshot then promote it via the configured backup sink (kind=backup).
    Backup { id: String },

    /// Restore a new instance from a snapshot id.
    Restore {
        /// Source instance id (informational; the snapshot id below decides the bytes).
        instance: String,
        #[arg(long)]
        snapshot: String,
        #[arg(long = "env", value_parser = parse_kv)]
        env: Vec<(String, String)>,
        #[arg(long)]
        ttl_seconds: Option<i64>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SecretsAction {
    /// Set or overwrite a secret on an instance.
    Set {
        instance: String,
        name: String,
        value: String,
    },
    /// Remove a secret from an instance.
    Clear { instance: String, name: String },
    /// Set or overwrite a system-scope secret (provider api keys, etc.).
    /// Bypasses the HTTP API and writes straight to the DB + cipher dir,
    /// so it's runnable on the warden host without an admin bearer.
    SystemSet { name: String, value: String },
    /// Remove a system-scope secret by name.
    SystemClear { name: String },
    /// List all system-scope secret names (values are never printed —
    /// the store layer doesn't expose them and we wouldn't want to
    /// dump api keys to a terminal anyway).
    SystemList,
}

/// Five-line warning emitted when `--dangerous-no-auth` is active.
pub const DANGEROUS_BANNER: &str = "\
=================================================================
WARNING: --dangerous-no-auth is set.
The admin API at /v1/* will accept requests with no bearer token.
Every authenticated response carries X-Warden-Insecure.
Do not run this configuration outside a trusted network.
=================================================================";

pub fn print_dangerous_banner() {
    eprintln!("{DANGEROUS_BANNER}");
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got {s:?}"))?;
    if k.is_empty() {
        return Err("empty key".into());
    }
    Ok((k.to_owned(), v.to_owned()))
}
