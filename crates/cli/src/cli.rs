use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "swarmctl",
    version,
    about = "Orchestrator for Dyson agents in CubeSandbox MicroVMs",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Path to the config TOML.
    #[arg(long, default_value = "/etc/dyson-swarm/config.toml", global = true)]
    pub config: PathBuf,

    /// Disable the admin-token check on /v1/* routes. Loud and dangerous;
    /// see startup banner for details.
    #[arg(long = "dangerous-no-auth", default_value_t = false, global = true)]
    pub dangerous_no_auth: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// Parse argv with secret-from-stdin resolution applied.
    ///
    /// Wraps `<Cli as clap::Parser>::parse()` and post-processes any
    /// subcommand whose value carries a `--stdin` flag.  When `--stdin`
    /// is set, the secret value is read from stdin (until EOF, trailing
    /// newline trimmed) and stamped into the action's `value` field —
    /// keeping the rest of the program unaware of whether the value
    /// came from argv or stdin.
    ///
    /// Inherent methods take precedence over trait methods during method
    /// resolution, so existing callers using `Cli::parse()` get this
    /// version automatically.  Falls through to the clap-provided parser
    /// for any subcommand without a stdin variant.
    pub fn parse() -> Self {
        let mut parsed = <Self as Parser>::parse();
        if let Some(Command::Secrets { ref mut action }) = parsed.command
            && let Err(err) = resolve_stdin_secret(action)
        {
            eprintln!("error: {err}");
            // Same exit shape as clap-provided parse errors (2 = usage).
            std::process::exit(2);
        }
        parsed
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// System-scope secret material.
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

    /// Diagnostic: GET /api/admin/skills on the running dyson and
    /// pretty-print the response.  Surfaces which MCP servers
    /// actually loaded (handshake errors otherwise log silently).
    DysonSkills { id: String },

    /// Mint an opaque user API key directly via the DB + cipher,
    /// bypassing the HTTP admin surface.  Same posture as
    /// `secrets system-set`: meant for the swarm host operator
    /// when no admin bearer is already minted.  Prints the
    /// plaintext token to stdout — capture immediately, never log.
    MintApiKey {
        /// The `users.id` (32-hex) to mint the key under.
        user_id: String,
        /// Optional human-readable label.
        #[arg(long)]
        label: Option<String>,
    },

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

    /// Operator deploy helper: snapshot every live instance to a JSON manifest.
    DeploySnapshotLive {
        /// Manifest path to write atomically.
        #[arg(long)]
        output: PathBuf,
    },

    /// Operator deploy helper: restore live instances in place from a manifest.
    DeployRestoreLive {
        /// Manifest produced by deploy-snapshot-live.
        #[arg(long)]
        manifest: PathBuf,
        /// Optional template override for every restored cube. Omit to use
        /// the template_id captured for each instance in the manifest.
        #[arg(long)]
        template: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SecretsAction {
    /// Set or overwrite a system-scope secret (provider api keys, etc.).
    /// Bypasses the HTTP API and writes straight to the DB + cipher dir,
    /// so it's runnable on the swarm host without an admin bearer.
    ///
    /// Pass `--stdin` to read the secret value from stdin instead of
    /// argv.  Stdin mode avoids leaking the value to /proc/<pid>/cmdline
    /// and auditd's execve records.
    SystemSet {
        name: String,
        /// Secret value.  Omit when `--stdin` is set.
        #[arg(default_value = "")]
        value: String,
        /// Read the secret value from stdin (until EOF; trailing newline
        /// trimmed).  Pass secret via stdin to avoid argv leakage to
        /// /proc/<pid>/cmdline and auditd logs.
        #[arg(long, default_value_t = false)]
        stdin: bool,
    },
    /// Remove a system-scope secret by name.
    SystemClear { name: String },
    /// List all system-scope secret names (values are never printed —
    /// the store layer doesn't expose them and we wouldn't want to
    /// dump api keys to a terminal anyway).
    SystemList,
    /// Print a single system-scope secret value to stdout (no trailing
    /// newline) for an external tool to consume.
    ///
    /// SECURITY POSTURE: this command is the explicit, audited
    /// exception to "system secrets never leave the swarm process."
    /// The vast majority of system secrets (provider api_keys, the OR
    /// provisioning key, etc.) are loaded in-process at startup and
    /// must never be re-emitted.  A handful are needed by external
    /// tools that swarm shells out to — today, only the Cloudflare
    /// API token consumed by acme.sh during the `tls` phase of
    /// bring-up.sh.
    ///
    /// To keep that exception narrow, the handler enforces a
    /// compile-time allowlist (`EXTERNAL_CONSUMER_SECRETS` in this
    /// file).  Names not on the list are rejected before the store is
    /// touched.  Adding a new entry requires editing this file in the
    /// same PR as the new caller — making the security expansion
    /// visible to reviewers instead of being a silent code path.
    SystemGet { name: String },
}

/// Names allowed through `secrets system-get`.  Every entry must
/// correspond to a documented external consumer; review additions as
/// you would a new sudoers entry.
///
/// Current consumers:
/// - `cloudflare.api_token` — read by `bring-up.sh tls` and exported
///   to acme.sh's env as `CF_Token` for DNS-01 issuance of the LE
///   wildcard cert.
pub const EXTERNAL_CONSUMER_SECRETS: &[&str] = &["cloudflare.api_token"];

/// Returns true iff `name` may be exported via `secrets system-get`.
/// Pure function so the allowlist is unit-testable without a DB.
pub fn system_get_allowed(name: &str) -> bool {
    EXTERNAL_CONSUMER_SECRETS.contains(&name)
}

/// Five-line warning emitted when `--dangerous-no-auth` is active.
pub const DANGEROUS_BANNER: &str = "\
=================================================================
WARNING: --dangerous-no-auth is set.
The admin API at /v1/* will accept requests with no bearer token.
Every authenticated response carries X-Swarm-Insecure.
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

/// For each variant that supports `--stdin`, validate that exactly one
/// of {positional value, --stdin} was supplied and, when `--stdin` is
/// active, slurp stdin into the `value` field so downstream code can
/// consume the action without caring how the value arrived.
///
/// Returns a human-readable error string on:
///   - both forms supplied (ambiguous);
///   - neither form supplied (missing value);
///   - stdin read failure (rare; usually a closed pipe).
fn resolve_stdin_secret(action: &mut SecretsAction) -> Result<(), String> {
    match action {
        SecretsAction::SystemSet { value, stdin, name } => resolve_one(value, *stdin, name),
        SecretsAction::SystemClear { .. }
        | SecretsAction::SystemList
        | SecretsAction::SystemGet { .. } => Ok(()),
    }
}

fn resolve_one(value: &mut String, stdin: bool, name: &str) -> Result<(), String> {
    let positional_set = !value.is_empty();
    match (positional_set, stdin) {
        (true, true) => Err(format!(
            "secrets {name}: pass the value either as a positional argument or via --stdin, not both"
        )),
        (false, false) => Err(format!(
            "secrets {name}: missing value (pass as positional argument or use --stdin)"
        )),
        (true, false) => Ok(()),
        (false, true) => {
            let mut buf = String::new();
            std::io::stdin()
                .lock()
                .read_to_string(&mut buf)
                .map_err(|e| format!("secrets {name}: stdin read failed: {e}"))?;
            // Trim a single trailing newline (the common shell pipe
            // shape: `printf '%s' value` is rare in practice, `echo
            // value` and heredocs both append a newline).  Don't trim
            // arbitrary whitespace — secrets can legitimately end in
            // a space.
            if buf.ends_with('\n') {
                buf.pop();
                if buf.ends_with('\r') {
                    buf.pop();
                }
            }
            if buf.is_empty() {
                return Err(format!("secrets {name}: stdin produced an empty value"));
            }
            *value = buf;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_one_rejects_both_sources() {
        let mut v = "abc".to_string();
        let err = resolve_one(&mut v, true, "test").unwrap_err();
        assert!(err.contains("not both"), "got: {err}");
    }

    #[test]
    fn resolve_one_rejects_neither_source() {
        let mut v = String::new();
        let err = resolve_one(&mut v, false, "test").unwrap_err();
        assert!(err.contains("missing value"), "got: {err}");
    }

    #[test]
    fn resolve_one_keeps_positional_value() {
        let mut v = "abc".to_string();
        resolve_one(&mut v, false, "test").unwrap();
        assert_eq!(v, "abc");
    }

    /// `system-get` must refuse any name not on the compile-time
    /// allowlist.  Adding a new entry to the allowlist requires
    /// editing this test in the same diff — making the security
    /// expansion impossible to land silently.
    #[test]
    fn system_get_allowlist_is_exactly_one_entry() {
        // Exactly the documented external-consumer secrets.  If this
        // assertion trips, audit cli.rs::EXTERNAL_CONSUMER_SECRETS:
        // every addition must pair with a real external caller AND
        // an updated docstring on `SystemGet`.
        assert_eq!(EXTERNAL_CONSUMER_SECRETS, &["cloudflare.api_token"]);
    }

    #[test]
    fn system_get_allows_only_listed_names() {
        assert!(system_get_allowed("cloudflare.api_token"));
    }

    #[test]
    fn system_get_rejects_in_process_secrets() {
        // These are the secrets currently sealed by
        // `bring-up.sh secrets-bootstrap` — they load in-process at
        // swarm startup and MUST NOT be exportable via the CLI.
        for name in [
            "provider.openrouter.api_key",
            "provider.anthropic.api_key",
            "provider.openai.api_key",
            "provider.gemini.api_key",
            "openrouter.provisioning_key",
        ] {
            assert!(
                !system_get_allowed(name),
                "{name} is in-process only — must not be allowed via system-get",
            );
        }
    }

    #[test]
    fn system_get_rejects_pathological_names() {
        // Defensive: even though storage is keyed by the literal
        // string, ensure nothing weird sneaks past the allowlist.
        for name in [
            "",
            "cloudflare.api_token ",  // trailing space
            " cloudflare.api_token",  // leading space
            "CLOUDFLARE.API_TOKEN",   // case variant
            "cloudflare.api_token\n", // newline injection
            "../../../etc/passwd",
        ] {
            assert!(!system_get_allowed(name), "must reject: {name:?}");
        }
    }
}
