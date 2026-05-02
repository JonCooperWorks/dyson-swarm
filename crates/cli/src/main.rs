use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use reqwest::Method;
use serde::{Deserialize, Serialize};

use dyson_swarm_cli::{self as cli, Command, SecretsAction};
use dyson_swarm_core::{
    api_client::ApiClient,
    backup::{local::LocalDiskBackupSink, s3::S3BackupSink},
    config, cube_client, db,
    db::{instances::SqlxInstanceStore, secrets::SqlxSecretStore, tokens::SqlxTokenStore},
    instance::{InstanceService, SYSTEM_OWNER},
    snapshot::SnapshotService,
    traits::{
        BackupSink, CubeClient, InstanceStatus, InstanceStore, ListFilter, SecretStore,
        SnapshotStore, TokenStore,
    },
};

fn collect_env() -> BTreeMap<String, String> {
    std::env::vars()
        .filter(|(k, _)| k.starts_with("SWARM_"))
        .collect()
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

#[tokio::main]
async fn main() -> ExitCode {
    // Tighten the process umask before any FS I/O.  Files we create
    // afterwards (sqlite db, age key files via OpenOptions, future
    // secret-bearing writes that forget to chmod) end up at owner-only
    // by default instead of inheriting the (potentially 022) shell
    // umask.  Closes the create-then-chmod race window on path-based
    // secret material.  Unix-only — Windows has no umask concept and
    // libc isn't a runtime dep there (cfg-guarded in Cargo.toml).
    #[cfg(unix)]
    {
        // SAFETY: umask(2) is a process-wide setter that only flips
        // a kernel-side bitmask; it has no other observable side
        // effect and is safe to call from any thread, including
        // before tokio's runtime spins up worker threads.
        unsafe {
            libc::umask(0o077);
        }
    }
    let args = cli::Cli::parse();
    if args.dangerous_no_auth {
        if !env_flag("SWARM_DEV_MODE") && !env_flag("SWARM_DANGEROUS_NO_AUTH_OK") {
            eprintln!(
                "error: --dangerous-no-auth requires SWARM_DEV_MODE=1 or SWARM_DANGEROUS_NO_AUTH_OK=1"
            );
            return ExitCode::from(2);
        }
        cli::print_dangerous_banner();
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let cfg = match config::Config::load(&args.config, &collect_env(), args.dangerous_no_auth) {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(error = %err, config = %args.config.display(), "config load failed");
            return ExitCode::from(2);
        }
    };

    let Some(command) = args.command else {
        eprintln!("error: missing subcommand");
        return ExitCode::from(2);
    };

    match command {
        Command::Secrets { action } => run_secrets(&cfg, args.dangerous_no_auth, action).await,
        Command::New {
            template,
            env,
            ttl_seconds,
        } => run_new(&cfg, args.dangerous_no_auth, template, env, ttl_seconds).await,
        Command::Destroy { id } => run_destroy(&cfg, args.dangerous_no_auth, id).await,
        Command::List {
            status,
            include_destroyed,
        } => run_list(&cfg, args.dangerous_no_auth, status, include_destroyed).await,
        Command::Snapshot { id } => {
            run_simple_post(
                &cfg,
                args.dangerous_no_auth,
                &format!("/v1/instances/{id}/snapshot"),
            )
            .await
        }
        Command::Backup { id } => {
            run_simple_post(
                &cfg,
                args.dangerous_no_auth,
                &format!("/v1/instances/{id}/backup"),
            )
            .await
        }
        Command::Restore {
            instance,
            snapshot,
            env,
            ttl_seconds,
        } => {
            run_restore(
                &cfg,
                args.dangerous_no_auth,
                instance,
                snapshot,
                env,
                ttl_seconds,
            )
            .await
        }
        Command::DeploySnapshotLive { output } => run_deploy_snapshot_live(&cfg, output).await,
        Command::DeployRestoreLive { manifest, template } => {
            run_deploy_restore_live(&cfg, manifest, template).await
        }
        Command::DysonSkills { id } => run_dyson_skills(&cfg, id).await,
        Command::MintApiKey { user_id, label } => run_mint_api_key(&cfg, user_id, label).await,
    }
}

/// Mint an opaque user api-key without going through the HTTP admin
/// surface.  Mirrors `secrets system-set` in posture: direct DB +
/// cipher access on the swarm host, suitable for first-time setup
/// or unblocking debug flows when no admin bearer is already
/// minted.  Prints plaintext to stdout (capture immediately).
async fn run_mint_api_key(
    cfg: &config::Config,
    user_id: String,
    label: Option<String>,
) -> ExitCode {
    if !env_flag("SWARM_MINT_API_KEY_OK") {
        eprintln!("error: mint-api-key requires SWARM_MINT_API_KEY_OK=1");
        return ExitCode::from(2);
    }

    let pool = match dyson_swarm_core::db::open(&cfg.db_path).await {
        Ok(p) => p,
        Err(err) => {
            eprintln!("db open: {err}");
            return ExitCode::from(2);
        }
    };
    let cipher_dir = match dyson_swarm_core::envelope::AgeCipherDirectory::new(
        cfg.keys_dir.clone().unwrap_or_default(),
    ) {
        Ok(d) => std::sync::Arc::new(d)
            as std::sync::Arc<dyn dyson_swarm_core::envelope::CipherDirectory>,
        Err(err) => {
            eprintln!("keys_dir open: {err}");
            return ExitCode::from(2);
        }
    };
    let users = dyson_swarm_core::db::users::SqlxUserStore::new(pool, cipher_dir);
    use dyson_swarm_core::traits::UserStore;
    match users.mint_api_key(&user_id, label.as_deref()).await {
        Ok(token) => {
            println!("{token}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("mint_api_key: {err}");
            ExitCode::from(2)
        }
    }
}

/// Diagnostic: probe `/api/admin/skills` on a running dyson.  Reads
/// the instance's sandbox_id from the swarm DB, builds a
/// reconfigurer (same one the regular configure path uses), and
/// pretty-prints the JSON response.  Best-run on the swarm host —
/// the cube root CA + sandbox_domain in /etc/dyson-swarm/config.toml
/// are required to reach cubeproxy.
async fn run_dyson_skills(cfg: &config::Config, id: String) -> ExitCode {
    use dyson_swarm_core::dyson_reconfig::DysonReconfigurerHttp;
    let pool = match dyson_swarm_core::db::open(&cfg.db_path).await {
        Ok(p) => p,
        Err(err) => {
            eprintln!("db open: {err}");
            return ExitCode::from(2);
        }
    };
    let cipher_dir =
        match dyson_swarm_core::envelope::AgeCipherDirectory::new(cfg.resolved_keys_dir()) {
            Ok(d) => std::sync::Arc::new(d)
                as std::sync::Arc<dyn dyson_swarm_core::envelope::CipherDirectory>,
            Err(err) => {
                eprintln!("keys_dir open: {err}");
                return ExitCode::from(2);
            }
        };
    let system_cipher = match cipher_dir.system() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("system envelope init: {err}");
            return ExitCode::from(2);
        }
    };
    if let Err(err) =
        dyson_swarm_core::db::runtime_migrations::migrate(&pool, system_cipher.as_ref()).await
    {
        eprintln!("runtime data migration: {err}");
        return ExitCode::from(2);
    }
    let instances_store: std::sync::Arc<dyn dyson_swarm_core::traits::InstanceStore> =
        std::sync::Arc::new(dyson_swarm_core::db::instances::SqlxInstanceStore::new(
            pool.clone(),
            system_cipher,
        ));
    let row = match instances_store.get(&id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            eprintln!("instance not found: {id}");
            return ExitCode::from(2);
        }
        Err(err) => {
            eprintln!("instance lookup: {err}");
            return ExitCode::from(2);
        }
    };
    let sandbox_id = match row.cube_sandbox_id.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => s.to_owned(),
        None => {
            eprintln!("instance has no cube_sandbox_id");
            return ExitCode::from(2);
        }
    };
    let system_secrets_store: std::sync::Arc<dyn dyson_swarm_core::traits::SystemSecretStore> =
        std::sync::Arc::new(dyson_swarm_core::db::secrets::SqlxSystemSecretStore::new(
            pool,
        ));
    let system_secrets = std::sync::Arc::new(dyson_swarm_core::secrets::SystemSecretsService::new(
        system_secrets_store,
        cipher_dir,
    ));
    let reconfigurer =
        match DysonReconfigurerHttp::new(cfg.cube.sandbox_domain.clone(), system_secrets) {
            Ok(r) => r,
            Err(err) => {
                eprintln!("reconfigurer init: {err}");
                return ExitCode::from(2);
            }
        };
    match reconfigurer.get_skills(&id, &sandbox_id).await {
        Ok(v) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string())
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("get_skills: {err}");
            ExitCode::from(2)
        }
    }
}

struct OpsServices {
    instances: Arc<dyn InstanceStore>,
    snapshots: Arc<SnapshotService>,
}

async fn build_ops_services(cfg: &config::Config) -> Result<OpsServices, String> {
    let pool = db::open(&cfg.db_path)
        .await
        .map_err(|e| format!("db open {}: {e:#}", cfg.db_path.display()))?;
    let cube = Arc::new(
        cube_client::HttpCubeClient::new(&cfg.cube).map_err(|e| format!("cube client: {e:#}"))?,
    ) as Arc<dyn CubeClient>;
    let cipher_dir: Arc<dyn dyson_swarm_core::envelope::CipherDirectory> = Arc::new(
        dyson_swarm_core::envelope::AgeCipherDirectory::new(cfg.resolved_keys_dir())
            .map_err(|e| format!("envelope key directory init: {e:#}"))?,
    );
    let system_cipher = cipher_dir
        .system()
        .map_err(|e| format!("system envelope init: {e:#}"))?;
    let report = db::runtime_migrations::migrate(&pool, system_cipher.as_ref())
        .await
        .map_err(|e| format!("runtime data migration: {e:#}"))?;
    if report.applied {
        eprintln!(
            "ok: runtime data migrations sealed {} proxy token(s), {} instance bearer(s)",
            report.proxy_tokens_sealed, report.instance_bearers_sealed
        );
    }
    let instances: Arc<dyn InstanceStore> =
        Arc::new(SqlxInstanceStore::new(pool.clone(), system_cipher.clone()));
    let secrets: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
    let tokens: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone(), system_cipher));
    let snapshots_store: Arc<dyn SnapshotStore> =
        Arc::new(db::snapshots::SqliteSnapshotStore::new(pool.clone()));

    let system_secrets_store: Arc<dyn dyson_swarm_core::traits::SystemSecretStore> = Arc::new(
        dyson_swarm_core::db::secrets::SqlxSystemSecretStore::new(pool.clone()),
    );
    let user_secrets_store: Arc<dyn dyson_swarm_core::traits::UserSecretStore> = Arc::new(
        dyson_swarm_core::db::secrets::SqlxUserSecretStore::new(pool.clone()),
    );
    let system_secrets_svc = Arc::new(dyson_swarm_core::secrets::SystemSecretsService::new(
        system_secrets_store,
        cipher_dir.clone(),
    ));
    let user_secrets_svc = Arc::new(dyson_swarm_core::secrets::UserSecretsService::new(
        user_secrets_store,
        cipher_dir,
    ));

    let proxy_base = match cfg.cube_facing_addr.as_deref().filter(|a| !a.is_empty()) {
        Some(addr) => format!("http://{addr}/llm"),
        None => match cfg.hostname.as_deref().filter(|h| !h.is_empty()) {
            Some(host) => format!("https://{host}/llm"),
            None => format!("http://{}/llm", cfg.bind),
        },
    };
    let llm_cidr: Option<String> = cfg
        .cube_facing_addr
        .as_deref()
        .and_then(|addr| addr.split(':').next())
        .filter(|host| !host.is_empty())
        .filter(|host| host.parse::<std::net::Ipv4Addr>().is_ok())
        .map(|host| format!("{host}/32"));

    let mut instance_svc =
        InstanceService::new(cube.clone(), instances.clone(), secrets, tokens, proxy_base)
            .with_llm_cidr(llm_cidr)
            .with_mcp_secrets(user_secrets_svc);
    if let Ok(r) = dyson_swarm_core::dyson_reconfig::DysonReconfigurerHttp::new(
        cfg.cube.sandbox_domain.clone(),
        system_secrets_svc,
    ) {
        instance_svc = instance_svc.with_reconfigurer(Arc::new(r));
    }
    let instance_svc = Arc::new(instance_svc);

    let backup_sink: Arc<dyn BackupSink> = match cfg.backup.sink {
        config::BackupSinkKind::Local => Arc::new(LocalDiskBackupSink::new(cube.clone())),
        config::BackupSinkKind::S3 => {
            let s3cfg = cfg
                .backup
                .s3
                .as_ref()
                .ok_or_else(|| "s3 backup sink selected but [backup.s3] missing".to_string())?;
            Arc::new(
                S3BackupSink::new(s3cfg, cfg.backup.local_cache_dir.clone(), cube.clone())
                    .map_err(|e| format!("s3 backup sink: {e:#}"))?,
            )
        }
    };
    let snapshots = Arc::new(SnapshotService::new(
        cube,
        instances.clone(),
        snapshots_store,
        backup_sink,
        instance_svc,
    ));

    Ok(OpsServices {
        instances,
        snapshots,
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct DeployRecoveryManifest {
    version: u32,
    created_at: i64,
    entries: Vec<DeployRecoveryEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeployRecoveryEntry {
    instance_id: String,
    name: String,
    snapshot_id: String,
    template_id: String,
    sandbox_id: String,
}

async fn run_deploy_snapshot_live(cfg: &config::Config, output: PathBuf) -> ExitCode {
    let services = match build_ops_services(cfg).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let live = match services
        .instances
        .list(
            SYSTEM_OWNER,
            ListFilter {
                status: Some(InstanceStatus::Live),
                include_destroyed: false,
            },
        )
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!("error: list live instances: {err:#}");
            return ExitCode::FAILURE;
        }
    };

    let mut entries = Vec::new();
    for row in live {
        let Some(sandbox_id) = row
            .cube_sandbox_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
        else {
            eprintln!(
                "error: live instance {} has no cube_sandbox_id; refusing destructive cube install",
                row.id
            );
            return ExitCode::FAILURE;
        };
        match services.snapshots.snapshot(SYSTEM_OWNER, &row.id).await {
            Ok(snap) => {
                println!("snapshot {} ({}) -> {}", row.id, row.name.trim(), snap.id);
                entries.push(DeployRecoveryEntry {
                    instance_id: row.id,
                    name: row.name,
                    snapshot_id: snap.id,
                    template_id: row.template_id,
                    sandbox_id,
                });
            }
            Err(err) => {
                eprintln!("error: snapshot {} failed: {err:#}", row.id);
                return ExitCode::FAILURE;
            }
        }
    }

    let manifest = DeployRecoveryManifest {
        version: 1,
        created_at: dyson_swarm_core::now_secs(),
        entries,
    };
    if let Err(err) = write_manifest_atomic(&output, &manifest) {
        eprintln!("error: write manifest {}: {err}", output.display());
        return ExitCode::FAILURE;
    }
    println!(
        "wrote deploy recovery manifest {} ({} entr{})",
        output.display(),
        manifest.entries.len(),
        if manifest.entries.len() == 1 {
            "y"
        } else {
            "ies"
        }
    );
    ExitCode::SUCCESS
}

async fn run_deploy_restore_live(
    cfg: &config::Config,
    manifest_path: PathBuf,
    template_override: Option<String>,
) -> ExitCode {
    let manifest: DeployRecoveryManifest = match std::fs::read(&manifest_path)
        .map_err(|e| format!("read {}: {e}", manifest_path.display()))
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| format!("parse json: {e}")))
    {
        Ok(m) => m,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    if manifest.version != 1 {
        eprintln!("error: unsupported manifest version {}", manifest.version);
        return ExitCode::from(2);
    }
    if manifest.entries.is_empty() {
        println!("deploy recovery manifest is empty; nothing to restore");
        return ExitCode::SUCCESS;
    }

    let services = match build_ops_services(cfg).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = Vec::new();
    for entry in &manifest.entries {
        let target_template = template_override
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| entry.template_id.clone());
        println!(
            "restore {} ({}) from {} using template {}",
            entry.instance_id, entry.name, entry.snapshot_id, target_template
        );
        match services
            .snapshots
            .restore_in_place(
                SYSTEM_OWNER,
                &entry.instance_id,
                &entry.snapshot_id,
                Some(target_template),
            )
            .await
        {
            Ok(row) => {
                let sandbox = row.cube_sandbox_id.as_deref().unwrap_or("");
                println!("restored {} -> {}", row.id, sandbox);
            }
            Err(err) => {
                eprintln!("error: restore {} failed: {err:#}", entry.instance_id);
                failed.push(entry.instance_id.clone());
            }
        }
    }

    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        eprintln!("error: {} instance restore(s) failed", failed.len());
        ExitCode::FAILURE
    }
}

fn write_manifest_atomic(
    path: &std::path::Path,
    manifest: &DeployRecoveryManifest,
) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("create parent dir: {e}"))?;
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "manifest path must have a UTF-8 file name".to_string())?;
    let tmp = path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|e| format!("encode json: {e}"))?;
    std::fs::write(&tmp, bytes).map_err(|e| format!("write tmp: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename tmp: {e}"))?;
    Ok(())
}

fn build_api_client(cfg: &config::Config, dangerous_no_auth: bool) -> Option<ApiClient> {
    // Stage 5 retired the admin_token; CLI subcommands now read a
    // user api-key from `SWARM_API_KEY` (mint one via the SPA admin
    // panel and export).  `--dangerous-no-auth` skips entirely.
    let token = if dangerous_no_auth {
        None
    } else {
        std::env::var("SWARM_API_KEY").ok()
    };
    match ApiClient::from_bind(&cfg.bind, token) {
        Ok(c) => Some(c),
        Err(err) => {
            eprintln!("error: {err:#}");
            None
        }
    }
}

async fn run_secrets(
    cfg: &config::Config,
    dangerous_no_auth: bool,
    action: SecretsAction,
) -> ExitCode {
    // System-scope variants bypass HTTP and operate on the DB + key
    // dir directly.  This is intentional: provider api_keys are a
    // bootstrap concern (the swarm HTTP server may not be running
    // yet, and there's no admin user to mint a bearer for in a fresh
    // deployment) and the operator running this CLI on the swarm
    // host already has filesystem access to both pieces.
    if let SecretsAction::SystemSet { .. }
    | SecretsAction::SystemClear { .. }
    | SecretsAction::SystemList
    | SecretsAction::SystemGet { .. } = action
    {
        return run_system_secret(cfg, action).await;
    }

    let Some(client) = build_api_client(cfg, dangerous_no_auth) else {
        return ExitCode::FAILURE;
    };
    let result = match action {
        SecretsAction::Set {
            instance,
            name,
            value,
            stdin: _,
        } => {
            let path = format!("/v1/instances/{instance}/secrets/{name}");
            client
                .send_json(Method::PUT, &path, &serde_json::json!({"value": value}))
                .await
        }
        SecretsAction::Clear { instance, name } => {
            let path = format!("/v1/instances/{instance}/secrets/{name}");
            client.send_no_body(Method::DELETE, &path).await
        }
        // The Set/Clear/List/Get system variants returned above.
        SecretsAction::SystemSet { .. }
        | SecretsAction::SystemClear { .. }
        | SecretsAction::SystemList
        | SecretsAction::SystemGet { .. } => unreachable!(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// System-secret CLI handler.  Opens the sqlite DB + envelope key dir
/// directly and pipes through [`SystemSecretsService`].  No HTTP, no
/// admin bearer.
async fn run_system_secret(cfg: &config::Config, action: SecretsAction) -> ExitCode {
    let pool = match db::open(&cfg.db_path).await {
        Ok(p) => p,
        Err(err) => {
            eprintln!("error: db open failed: {err:#}");
            return ExitCode::FAILURE;
        }
    };
    let cipher_dir: Arc<dyn dyson_swarm_core::envelope::CipherDirectory> =
        match dyson_swarm_core::envelope::AgeCipherDirectory::new(cfg.resolved_keys_dir()) {
            Ok(d) => Arc::new(d),
            Err(err) => {
                eprintln!("error: envelope key dir init failed: {err:#}");
                return ExitCode::FAILURE;
            }
        };
    let store: Arc<dyn dyson_swarm_core::traits::SystemSecretStore> = Arc::new(
        dyson_swarm_core::db::secrets::SqlxSystemSecretStore::new(pool.clone()),
    );
    let svc = dyson_swarm_core::secrets::SystemSecretsService::new(store, cipher_dir);

    match action {
        SecretsAction::SystemSet {
            name,
            value,
            stdin: _,
        } => match svc.put(&name, value.as_bytes()).await {
            Ok(()) => {
                eprintln!("ok: system secret {name} stored");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err:#}");
                ExitCode::FAILURE
            }
        },
        SecretsAction::SystemClear { name } => match svc.delete(&name).await {
            Ok(()) => {
                eprintln!("ok: system secret {name} cleared");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err:#}");
                ExitCode::FAILURE
            }
        },
        SecretsAction::SystemList => match svc.list_names().await {
            Ok(names) => {
                for n in names {
                    println!("{n}");
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err:#}");
                ExitCode::FAILURE
            }
        },
        SecretsAction::SystemGet { name } => {
            // Allowlist gate runs BEFORE we touch the store — a
            // rejected name leaves no audit trail beyond this stderr
            // line, no envelope decryption, no DB read.
            if !cli::system_get_allowed(&name) {
                eprintln!(
                    "error: system-get refused: '{name}' is not in cli::EXTERNAL_CONSUMER_SECRETS.\n\
                     If you legitimately need an external tool to consume this secret,\n\
                     add it to that list in dyson-swarm/crates/cli/src/cli.rs and document the consumer\n\
                     in the SystemGet docstring.  Provider api_keys and the OR provisioning\n\
                     key load in-process at startup and must NOT be added."
                );
                return ExitCode::FAILURE;
            }
            match svc.get_str(&name).await {
                Ok(Some(value)) => {
                    use std::io::Write;
                    // Write raw bytes with no trailing newline so
                    // `$(swarmctl secrets system-get ...)` captures exactly
                    // the stored value.  Flush explicitly — the process
                    // is about to exit and stdout is fully buffered when
                    // attached to a pipe.
                    let mut out = std::io::stdout().lock();
                    if let Err(err) = out.write_all(value.as_bytes()).and_then(|_| out.flush()) {
                        eprintln!("error: write failed: {err:#}");
                        return ExitCode::FAILURE;
                    }
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    eprintln!("error: system secret '{name}' not set");
                    ExitCode::FAILURE
                }
                Err(err) => {
                    eprintln!("error: {err:#}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => unreachable!(),
    }
}

async fn run_new(
    cfg: &config::Config,
    dangerous_no_auth: bool,
    template: String,
    env: Vec<(String, String)>,
    ttl_seconds: Option<i64>,
) -> ExitCode {
    let Some(client) = build_api_client(cfg, dangerous_no_auth) else {
        return ExitCode::FAILURE;
    };
    let env: BTreeMap<String, String> = env.into_iter().collect();
    let body = serde_json::json!({
        "template_id": template,
        "env": env,
        "ttl_seconds": ttl_seconds,
    });
    match client.send_json(Method::POST, "/v1/instances", &body).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_destroy(cfg: &config::Config, dangerous_no_auth: bool, id: String) -> ExitCode {
    let Some(client) = build_api_client(cfg, dangerous_no_auth) else {
        return ExitCode::FAILURE;
    };
    let path = format!("/v1/instances/{id}");
    match client.send_no_body(Method::DELETE, &path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_list(
    cfg: &config::Config,
    dangerous_no_auth: bool,
    status: Option<String>,
    include_destroyed: bool,
) -> ExitCode {
    let Some(client) = build_api_client(cfg, dangerous_no_auth) else {
        return ExitCode::FAILURE;
    };
    let mut path = String::from("/v1/instances?");
    if let Some(s) = status {
        let _ = write!(path, "status={s}&");
    }
    if include_destroyed {
        path.push_str("include_destroyed=true");
    }
    match client.send_no_body(Method::GET, &path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_simple_post(cfg: &config::Config, dangerous_no_auth: bool, path: &str) -> ExitCode {
    let Some(client) = build_api_client(cfg, dangerous_no_auth) else {
        return ExitCode::FAILURE;
    };
    match client
        .send_json(Method::POST, path, &serde_json::json!({}))
        .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_restore(
    cfg: &config::Config,
    dangerous_no_auth: bool,
    instance: String,
    snapshot: String,
    env: Vec<(String, String)>,
    ttl_seconds: Option<i64>,
) -> ExitCode {
    let Some(client) = build_api_client(cfg, dangerous_no_auth) else {
        return ExitCode::FAILURE;
    };
    let env: BTreeMap<String, String> = env.into_iter().collect();
    let body = serde_json::json!({
        "snapshot_id": snapshot,
        "env": env,
        "ttl_seconds": ttl_seconds,
    });
    let path = format!("/v1/instances/{instance}/restore");
    match client.send_json(Method::POST, &path, &body).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
