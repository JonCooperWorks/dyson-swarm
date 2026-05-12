use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Method;
use serde::{Deserialize, Serialize};

use dyson_swarm_cli::{self as cli, Command, SecretsAction};
use dyson_swarm_core::{
    api_client::ApiClient,
    backup::{local::LocalDiskBackupSink, s3::S3BackupSink},
    config, cube_client, db,
    db::{instances::SqlxInstanceStore, tokens::SqlxTokenStore},
    http::InternalHttpClient,
    instance::{InstanceService, SYSTEM_OWNER},
    snapshot::SnapshotService,
    traits::{
        BackupSink, CubeClient, InstanceRow, InstanceStatus, InstanceStore, ListFilter,
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
        Command::DeployRecreateLive {
            progress,
            template,
            include_current_template,
            dry_run,
            no_verify_conversations,
        } => {
            run_deploy_recreate_live(
                &cfg,
                progress,
                template,
                include_current_template,
                dry_run,
                !no_verify_conversations,
            )
            .await
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
    let root_ca_path = dyson_swarm_core::dyson_reconfig::cube_root_ca_path_from_env();
    let reconfigurer = match DysonReconfigurerHttp::new_with_root_ca_path(
        cfg.cube.sandbox_domain.clone(),
        system_secrets,
        root_ca_path.as_deref(),
    ) {
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
    instance_svc: Arc<InstanceService>,
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
        cipher_dir.clone(),
    ));
    let state_files = Arc::new(dyson_swarm_core::state_files::StateFileService::new(
        pool.clone(),
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
        InstanceService::new(cube.clone(), instances.clone(), tokens, proxy_base)
            .with_llm_cidr(llm_cidr)
            .with_mcp_upstream_policy(dyson_swarm_core::upstream_policy::OutboundUrlPolicy {
                enabled: cfg.byo.enabled,
                allow_localhost: cfg.byo.allow_localhost,
                allow_internal: cfg.byo.allow_internal,
            })
            .with_state_files(state_files)
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
                .ok_or_else(|| "s3 backup sink selected but [backup.s3] missing".to_owned())?;
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
        instance_svc.clone(),
    ));

    Ok(OpsServices {
        instances,
        instance_svc,
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

    let mut failed_restores = Vec::new();
    let mut failed_deletes = Vec::new();
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
                if let Err(err) = services
                    .snapshots
                    .delete(SYSTEM_OWNER, &entry.snapshot_id)
                    .await
                {
                    eprintln!(
                        "error: delete restored snapshot {} for {} failed: {err:#}",
                        entry.snapshot_id, entry.instance_id
                    );
                    failed_deletes.push(format!("{} ({})", entry.instance_id, entry.snapshot_id));
                } else {
                    println!("deleted restored snapshot {}", entry.snapshot_id);
                }
            }
            Err(err) => {
                eprintln!("error: restore {} failed: {err:#}", entry.instance_id);
                failed_restores.push(entry.instance_id.clone());
            }
        }
    }

    if failed_restores.is_empty() && failed_deletes.is_empty() {
        ExitCode::SUCCESS
    } else {
        if !failed_restores.is_empty() {
            eprintln!(
                "error: {} instance restore(s) failed: {}",
                failed_restores.len(),
                failed_restores.join(", ")
            );
        }
        if !failed_deletes.is_empty() {
            eprintln!(
                "error: {} restored snapshot cleanup(s) failed: {}",
                failed_deletes.len(),
                failed_deletes.join(", ")
            );
        }
        ExitCode::FAILURE
    }
}

#[derive(Debug, Serialize)]
struct DeployRecreateProgressEvent {
    version: u32,
    ts: i64,
    status: String,
    instance_id: String,
    name: String,
    old_sandbox_id: Option<String>,
    new_sandbox_id: Option<String>,
    old_template_id: String,
    target_template_id: String,
    duration_ms: Option<u64>,
    healthz_ok: Option<bool>,
    conversations_ok: Option<bool>,
    conversation_count: Option<usize>,
    error: Option<String>,
}

#[derive(Debug)]
struct DeployRecreateVerification {
    healthz_ok: bool,
    conversations_ok: Option<bool>,
    conversation_count: Option<usize>,
}

async fn run_deploy_recreate_live(
    cfg: &config::Config,
    progress: PathBuf,
    template_override: Option<String>,
    include_current_template: bool,
    dry_run: bool,
    verify_conversations: bool,
) -> ExitCode {
    let target_template = match deploy_target_template(cfg, template_override) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    if let Err(err) = ensure_progress_log_parent(&progress) {
        eprintln!("error: progress log {}: {err}", progress.display());
        return ExitCode::FAILURE;
    }

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
    if live.is_empty() {
        println!("no live instances to recreate");
        return ExitCode::SUCCESS;
    }

    let mut ok = 0usize;
    let mut skipped = 0usize;
    let mut failed = Vec::new();
    let mut durations = Vec::new();
    for row in live {
        let old_sandbox_id = row.cube_sandbox_id.clone();
        if old_sandbox_id.as_deref().is_none_or(str::is_empty) {
            let err =
                "live row has no cube_sandbox_id; recreate requires a current cube".to_owned();
            if append_recreate_progress(
                &progress,
                DeployRecreateProgressEvent {
                    version: 1,
                    ts: dyson_swarm_core::now_secs(),
                    status: "fail".into(),
                    instance_id: row.id.clone(),
                    name: row.name.clone(),
                    old_sandbox_id,
                    new_sandbox_id: None,
                    old_template_id: row.template_id.clone(),
                    target_template_id: target_template.clone(),
                    duration_ms: None,
                    healthz_ok: None,
                    conversations_ok: None,
                    conversation_count: None,
                    error: Some(err.clone()),
                },
            )
            .is_err()
            {
                eprintln!("error: failed writing progress log {}", progress.display());
                return ExitCode::FAILURE;
            }
            eprintln!("error: recreate {} failed: {err}", row.id);
            failed.push(row.id);
            continue;
        }

        if row.template_id == target_template && !include_current_template {
            if append_recreate_progress(
                &progress,
                DeployRecreateProgressEvent {
                    version: 1,
                    ts: dyson_swarm_core::now_secs(),
                    status: "skip".into(),
                    instance_id: row.id.clone(),
                    name: row.name.clone(),
                    old_sandbox_id,
                    new_sandbox_id: None,
                    old_template_id: row.template_id.clone(),
                    target_template_id: target_template.clone(),
                    duration_ms: None,
                    healthz_ok: None,
                    conversations_ok: None,
                    conversation_count: None,
                    error: Some("already on target template".into()),
                },
            )
            .is_err()
            {
                eprintln!("error: failed writing progress log {}", progress.display());
                return ExitCode::FAILURE;
            }
            skipped += 1;
            continue;
        }

        if append_recreate_progress(
            &progress,
            DeployRecreateProgressEvent {
                version: 1,
                ts: dyson_swarm_core::now_secs(),
                status: "start".into(),
                instance_id: row.id.clone(),
                name: row.name.clone(),
                old_sandbox_id: old_sandbox_id.clone(),
                new_sandbox_id: None,
                old_template_id: row.template_id.clone(),
                target_template_id: target_template.clone(),
                duration_ms: None,
                healthz_ok: None,
                conversations_ok: None,
                conversation_count: None,
                error: None,
            },
        )
        .is_err()
        {
            eprintln!("error: failed writing progress log {}", progress.display());
            return ExitCode::FAILURE;
        }

        if dry_run {
            if append_recreate_progress(
                &progress,
                DeployRecreateProgressEvent {
                    version: 1,
                    ts: dyson_swarm_core::now_secs(),
                    status: "skip".into(),
                    instance_id: row.id.clone(),
                    name: row.name.clone(),
                    old_sandbox_id,
                    new_sandbox_id: None,
                    old_template_id: row.template_id.clone(),
                    target_template_id: target_template.clone(),
                    duration_ms: None,
                    healthz_ok: None,
                    conversations_ok: None,
                    conversation_count: None,
                    error: Some("dry run".into()),
                },
            )
            .is_err()
            {
                eprintln!("error: failed writing progress log {}", progress.display());
                return ExitCode::FAILURE;
            }
            skipped += 1;
            continue;
        }

        println!(
            "recreate {} ({}) from {} to template {}",
            row.id,
            row.name.trim(),
            old_sandbox_id.as_deref().unwrap_or(""),
            target_template
        );
        let started = Instant::now();
        let recreate_owner_id = deploy_recreate_owner_id(&row).to_owned();
        match services
            .instance_svc
            .recreate_in_place(&recreate_owner_id, &row.id, &target_template, None)
            .await
        {
            Ok(new_row) => {
                let duration_ms = elapsed_ms(started);
                match verify_recreated_instance(
                    cfg,
                    &new_row,
                    &target_template,
                    old_sandbox_id.as_deref(),
                    verify_conversations,
                )
                .await
                {
                    Ok(verification) => {
                        let new_sandbox = new_row.cube_sandbox_id.clone();
                        if append_recreate_progress(
                            &progress,
                            DeployRecreateProgressEvent {
                                version: 1,
                                ts: dyson_swarm_core::now_secs(),
                                status: "ok".into(),
                                instance_id: new_row.id.clone(),
                                name: new_row.name.clone(),
                                old_sandbox_id,
                                new_sandbox_id: new_sandbox.clone(),
                                old_template_id: row.template_id.clone(),
                                target_template_id: target_template.clone(),
                                duration_ms: Some(duration_ms),
                                healthz_ok: Some(verification.healthz_ok),
                                conversations_ok: verification.conversations_ok,
                                conversation_count: verification.conversation_count,
                                error: None,
                            },
                        )
                        .is_err()
                        {
                            eprintln!("error: failed writing progress log {}", progress.display());
                            return ExitCode::FAILURE;
                        }
                        println!(
                            "recreated {} -> {} ({} ms)",
                            new_row.id,
                            new_sandbox.as_deref().unwrap_or(""),
                            duration_ms
                        );
                        ok += 1;
                        durations.push(duration_ms);
                    }
                    Err(err) => {
                        let new_sandbox = new_row.cube_sandbox_id.clone();
                        if append_recreate_progress(
                            &progress,
                            DeployRecreateProgressEvent {
                                version: 1,
                                ts: dyson_swarm_core::now_secs(),
                                status: "fail".into(),
                                instance_id: new_row.id.clone(),
                                name: new_row.name.clone(),
                                old_sandbox_id,
                                new_sandbox_id: new_sandbox,
                                old_template_id: row.template_id.clone(),
                                target_template_id: target_template.clone(),
                                duration_ms: Some(duration_ms),
                                healthz_ok: None,
                                conversations_ok: None,
                                conversation_count: None,
                                error: Some(err.clone()),
                            },
                        )
                        .is_err()
                        {
                            eprintln!("error: failed writing progress log {}", progress.display());
                            return ExitCode::FAILURE;
                        }
                        eprintln!("error: recreate {} verification failed: {err}", new_row.id);
                        failed.push(new_row.id);
                    }
                }
            }
            Err(err) => {
                let duration_ms = elapsed_ms(started);
                let msg = format!("{err:#}");
                if append_recreate_progress(
                    &progress,
                    DeployRecreateProgressEvent {
                        version: 1,
                        ts: dyson_swarm_core::now_secs(),
                        status: "fail".into(),
                        instance_id: row.id.clone(),
                        name: row.name.clone(),
                        old_sandbox_id,
                        new_sandbox_id: None,
                        old_template_id: row.template_id.clone(),
                        target_template_id: target_template.clone(),
                        duration_ms: Some(duration_ms),
                        healthz_ok: None,
                        conversations_ok: None,
                        conversation_count: None,
                        error: Some(msg.clone()),
                    },
                )
                .is_err()
                {
                    eprintln!("error: failed writing progress log {}", progress.display());
                    return ExitCode::FAILURE;
                }
                eprintln!("error: recreate {} failed: {msg}", row.id);
                failed.push(row.id);
            }
        }
    }

    if let Some(summary) = duration_summary(&durations) {
        println!(
            "deploy-recreate-live summary: ok={ok} skipped={skipped} failed={} {summary}",
            failed.len()
        );
    } else {
        println!(
            "deploy-recreate-live summary: ok={ok} skipped={skipped} failed={}",
            failed.len()
        );
    }
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        eprintln!("error: failed instance(s): {}", failed.join(", "));
        ExitCode::FAILURE
    }
}

fn deploy_recreate_owner_id(row: &InstanceRow) -> &str {
    row.owner_id.as_str()
}

fn deploy_target_template(
    cfg: &config::Config,
    template_override: Option<String>,
) -> Result<String, String> {
    template_override
        .or_else(|| cfg.default_template_id.clone())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "target template is required (pass --template or set default_template_id)".into()
        })
}

fn ensure_progress_log_parent(path: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("create parent dir: {e}"))?;
    }
    Ok(())
}

fn append_recreate_progress(
    path: &std::path::Path,
    event: DeployRecreateProgressEvent,
) -> Result<(), String> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open progress log: {e}"))?;
    serde_json::to_writer(&mut file, &event).map_err(|e| format!("encode progress event: {e}"))?;
    file.write_all(b"\n")
        .map_err(|e| format!("write progress event: {e}"))?;
    Ok(())
}

async fn verify_recreated_instance(
    cfg: &config::Config,
    row: &InstanceRow,
    target_template: &str,
    old_sandbox_id: Option<&str>,
    verify_conversations: bool,
) -> Result<DeployRecreateVerification, String> {
    if row.status != InstanceStatus::Live {
        return Err(format!(
            "row status is {}, expected live",
            row.status.as_str()
        ));
    }
    if row.template_id != target_template {
        return Err(format!(
            "row template_id is {}, expected {target_template}",
            row.template_id
        ));
    }
    let new_sandbox_id = row
        .cube_sandbox_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "row has no cube_sandbox_id after recreate".to_owned())?;
    if old_sandbox_id == Some(new_sandbox_id) {
        return Err(format!(
            "cube_sandbox_id did not change from {new_sandbox_id}"
        ));
    }

    let hostname = cfg
        .hostname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "server.hostname is not configured; cannot verify public instance".to_owned()
        })?;
    let hostname = hostname
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let base = format!("https://{}.{}", row.id, hostname);
    let client = InternalHttpClient::with_timeout(Duration::from_secs(
        cfg.health_probe_timeout_seconds.max(1),
    ))
    .map_err(|e| format!("verification client: {e}"))?;

    let health_url = format!("{base}/healthz");
    let health_resp = client
        .get(&health_url)
        .bearer_auth(&row.bearer_token)
        .send()
        .await
        .map_err(|e| format!("healthz send {health_url}: {e}"))?;
    if !health_resp.status().is_success() {
        let status = health_resp.status();
        let body = bounded_body(health_resp).await;
        return Err(format!("healthz {status}: {body}"));
    }

    let mut conversation_count = None;
    let mut conversations_ok = None;
    if verify_conversations {
        let conversations_url = format!("{base}/api/conversations");
        let conversations_resp = client
            .get(&conversations_url)
            .bearer_auth(&row.bearer_token)
            .send()
            .await
            .map_err(|e| format!("conversations send {conversations_url}: {e}"))?;
        if !conversations_resp.status().is_success() {
            let status = conversations_resp.status();
            let body = bounded_body(conversations_resp).await;
            return Err(format!("conversations {status}: {body}"));
        }
        let value: serde_json::Value = conversations_resp
            .json()
            .await
            .map_err(|e| format!("conversations parse: {e}"))?;
        let count = value
            .as_array()
            .map(Vec::len)
            .or_else(|| {
                value
                    .get("conversations")
                    .and_then(serde_json::Value::as_array)
                    .map(Vec::len)
            })
            .ok_or_else(|| "conversations response was not an array".to_owned())?;
        conversation_count = Some(count);
        conversations_ok = Some(true);
    }

    Ok(DeployRecreateVerification {
        healthz_ok: true,
        conversations_ok,
        conversation_count,
    })
}

async fn bounded_body(resp: reqwest::Response) -> String {
    let body = resp.text().await.unwrap_or_default();
    body.chars().take(500).collect()
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn duration_summary(durations: &[u64]) -> Option<String> {
    if durations.is_empty() {
        return None;
    }
    let mut sorted = durations.to_vec();
    sorted.sort_unstable();
    let min = sorted[0];
    let median = sorted[sorted.len() / 2];
    let max = sorted[sorted.len() - 1];
    Some(format!("duration_ms=min:{min} median:{median} max:{max}"))
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
        .ok_or_else(|| "manifest path must have a UTF-8 file name".to_owned())?;
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
    _dangerous_no_auth: bool,
    action: SecretsAction,
) -> ExitCode {
    // System-scope variants bypass HTTP and operate on the DB + key
    // dir directly.  This is intentional: provider api_keys are a
    // bootstrap concern (the swarm HTTP server may not be running
    // yet, and there's no admin user to mint a bearer for in a fresh
    // deployment) and the operator running this CLI on the swarm
    // host already has filesystem access to both pieces.
    run_system_secret(cfg, action).await
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

#[cfg(test)]
mod tests {
    use super::*;

    fn row_with_owner(owner_id: &str) -> InstanceRow {
        InstanceRow {
            id: "inst-1".into(),
            owner_id: owner_id.into(),
            name: "agent".into(),
            task: "task".into(),
            cube_sandbox_id: Some("cube-1".into()),
            state_generation: "gen-1".into(),
            template_id: "tpl-old".into(),
            status: InstanceStatus::Live,
            bearer_token: "bearer".into(),
            pinned: false,
            expires_at: None,
            last_active_at: 0,
            last_probe_at: None,
            last_probe_status: None,
            created_at: 0,
            destroyed_at: None,
            rotated_to: None,
            network_policy: dyson_swarm_core::network_policy::NetworkPolicy::Open,
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        }
    }

    #[test]
    fn deploy_recreate_uses_instance_owner_not_system_owner() {
        let row = row_with_owner("user-123");

        assert_eq!(deploy_recreate_owner_id(&row), "user-123");
        assert_ne!(deploy_recreate_owner_id(&row), SYSTEM_OWNER);
    }
}
