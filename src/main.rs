use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;

use dyson_swarm::{
    api_client::ApiClient,
    auth::AuthState,
    backup::{local::LocalDiskBackupSink, s3::S3BackupSink},
    cli::{self, Command, SecretsAction},
    config, cube_client, db,
    db::{instances::SqlxInstanceStore, secrets::SqlxSecretStore, tokens::SqlxTokenStore},
    http,
    instance::InstanceService,
    logging,
    probe::{self, HttpHealthProber},
    proxy::{self, policy_check::InstancePolicy, ProxyService},
    secrets::SecretsService,
    snapshot::SnapshotService,
    auth::{bearer::BearerAuthenticator, chain::ChainAuthenticator, oidc, Authenticator, UserAuthState},
    traits::{
        AuditStore, BackupSink, CubeClient, HealthProber, InstanceStore, PolicyStore, SecretStore,
        SnapshotStore, TokenStore, UserStore,
    },
    ttl,
};

fn collect_env() -> BTreeMap<String, String> {
    std::env::vars()
        .filter(|(k, _)| k.starts_with("SWARM_"))
        .collect()
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
        cli::print_dangerous_banner();
    }
    logging::init();

    let cfg = match config::Config::load(&args.config, &collect_env(), args.dangerous_no_auth) {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(error = %err, config = %args.config.display(), "config load failed");
            return ExitCode::from(2);
        }
    };

    match args.command.unwrap_or(Command::Serve) {
        Command::Serve => run_server(cfg, args.dangerous_no_auth).await,
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
            run_simple_post(&cfg, args.dangerous_no_auth, &format!("/v1/instances/{id}/snapshot"))
                .await
        }
        Command::Backup { id } => {
            run_simple_post(&cfg, args.dangerous_no_auth, &format!("/v1/instances/{id}/backup"))
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
    let pool = match dyson_swarm::db::open(&cfg.db_path).await {
        Ok(p) => p,
        Err(err) => {
            eprintln!("db open: {err}");
            return ExitCode::from(2);
        }
    };
    let cipher_dir = match dyson_swarm::envelope::AgeCipherDirectory::new(
        cfg.keys_dir.clone().unwrap_or_default(),
    ) {
        Ok(d) => std::sync::Arc::new(d) as std::sync::Arc<dyn dyson_swarm::envelope::CipherDirectory>,
        Err(err) => {
            eprintln!("keys_dir open: {err}");
            return ExitCode::from(2);
        }
    };
    let users = dyson_swarm::db::users::SqlxUserStore::new(pool, cipher_dir);
    use dyson_swarm::traits::UserStore;
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
    use dyson_swarm::dyson_reconfig::DysonReconfigurerHttp;
    let pool = match dyson_swarm::db::open(&cfg.db_path).await {
        Ok(p) => p,
        Err(err) => {
            eprintln!("db open: {err}");
            return ExitCode::from(2);
        }
    };
    let instances_store: std::sync::Arc<dyn dyson_swarm::traits::InstanceStore> = std::sync::Arc::new(
        dyson_swarm::db::instances::SqlxInstanceStore::new(pool.clone()),
    );
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
    let cipher_dir = match dyson_swarm::envelope::AgeCipherDirectory::new(cfg.keys_dir.clone().unwrap_or_default()) {
        Ok(d) => std::sync::Arc::new(d) as std::sync::Arc<dyn dyson_swarm::envelope::CipherDirectory>,
        Err(err) => {
            eprintln!("keys_dir open: {err}");
            return ExitCode::from(2);
        }
    };
    let system_secrets_store: std::sync::Arc<dyn dyson_swarm::traits::SystemSecretStore> =
        std::sync::Arc::new(dyson_swarm::db::secrets::SqlxSystemSecretStore::new(pool));
    let system_secrets = std::sync::Arc::new(
        dyson_swarm::secrets::SystemSecretsService::new(system_secrets_store, cipher_dir),
    );
    let reconfigurer = match DysonReconfigurerHttp::new(cfg.cube.sandbox_domain.clone(), system_secrets) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("reconfigurer init: {err}");
            return ExitCode::from(2);
        }
    };
    match reconfigurer.get_skills(&id, &sandbox_id).await {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()));
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("get_skills: {err}");
            ExitCode::from(2)
        }
    }
}

async fn run_server(cfg: config::Config, dangerous_no_auth: bool) -> ExitCode {
    let pool = match db::open(&cfg.db_path).await {
        Ok(p) => p,
        Err(err) => {
            tracing::error!(error = %err, db = %cfg.db_path.display(), "db open failed");
            return ExitCode::from(2);
        }
    };

    let cube = match cube_client::HttpCubeClient::new(&cfg.cube) {
        Ok(c) => Arc::new(c) as Arc<dyn CubeClient>,
        Err(err) => {
            tracing::error!(error = %err, "cube client init failed");
            return ExitCode::from(2);
        }
    };
    let instances_store: Arc<dyn InstanceStore> = Arc::new(SqlxInstanceStore::new(pool.clone()));
    let secrets_store: Arc<dyn SecretStore> = Arc::new(SqlxSecretStore::new(pool.clone()));
    let user_secrets_store: Arc<dyn dyson_swarm::traits::UserSecretStore> =
        Arc::new(dyson_swarm::db::secrets::SqlxUserSecretStore::new(pool.clone()));
    let system_secrets_store: Arc<dyn dyson_swarm::traits::SystemSecretStore> =
        Arc::new(dyson_swarm::db::secrets::SqlxSystemSecretStore::new(pool.clone()));
    let tokens_store: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));

    // Per-user envelope encryption directory.  Lazy-creates an age
    // identity per user inside `keys_dir` on first secret seal/open.
    let cipher_dir: Arc<dyn dyson_swarm::envelope::CipherDirectory> =
        match dyson_swarm::envelope::AgeCipherDirectory::new(cfg.resolved_keys_dir()) {
            Ok(d) => Arc::new(d),
            Err(err) => {
                tracing::error!(error = %err, "envelope key directory init failed");
                return ExitCode::from(2);
            }
        };
    let snapshots_store: Arc<dyn SnapshotStore> =
        Arc::new(db::snapshots::SqliteSnapshotStore::new(pool.clone()));
    let policies_store: Arc<dyn PolicyStore> =
        Arc::new(db::policies::SqlitePolicyStore::new(pool.clone()));
    let audit_store: Arc<dyn AuditStore> =
        Arc::new(db::audit::SqliteAuditStore::new(pool.clone()));
    let users_store: Arc<dyn UserStore> =
        Arc::new(db::users::SqlxUserStore::new(pool.clone(), cipher_dir.clone()));

    // Dyson agents inside cube sandboxes can't reach swarm's bind
    // (which is loopback 127.0.0.1:8080 by design — Caddy is the only
    // public-facing listener).  Cube's default outbound policy also
    // blocks RFC1918 + CGNAT (`100.64.0.0/10`, the tailnet range), so
    // even a non-loopback bind on the host's tailnet IP would be
    // unreachable.  When `hostname` is set, route the agent's /llm
    // calls back through Caddy at the public hostname instead — public
    // DNS, public TLS (Let's Encrypt or whatever Caddy issued), works
    // through the same internet path the cube already trusts.
    //
    // Local-dev callers without a hostname keep the loopback URL, since
    // the agent runs on the same machine in that path.
    // Prefer the explicit cube-facing address when set: the cube can't
    // hairpin through the host's own public IP (which is what
    // `https://{hostname}/llm` resolves to in production), so a deploy
    // points this at the host's cube-dev gateway IP instead.  See the
    // doc on `Config::cube_facing_addr` for the full failure mode.
    let proxy_base = match cfg.cube_facing_addr.as_deref().filter(|a| !a.is_empty()) {
        Some(addr) => format!("http://{addr}/llm"),
        None => match cfg.hostname.as_deref().filter(|h| !h.is_empty()) {
            Some(host) => format!("https://{host}/llm"),
            None => format!("http://{}/llm", cfg.bind),
        },
    };
    tracing::info!(proxy_base = %proxy_base, "agent /llm proxy URL");

    // Derive the swarm-proxy CIDR for the per-instance network
    // policy resolver.  Only the IP-form of `cube_facing_addr`
    // produces a CIDR — a hostname-form address would need DNS
    // resolution, which we DO support for user-supplied entries but
    // not for the swarm's own bootstrap (the resolver is only
    // available after InstanceService is built; we'd be chasing our
    // tail).  Operators who want Airgap/Allowlist must set
    // `cube_facing_addr` to an IPv4 (the live deploy already does:
    // 192.168.0.1).  None ⇒ Airgap/Allowlist hires return
    // BadRequest; Open/Denylist still work.
    let llm_cidr: Option<String> = cfg
        .cube_facing_addr
        .as_deref()
        .and_then(|addr| addr.split(':').next())
        .filter(|host| !host.is_empty())
        .filter(|host| host.parse::<std::net::Ipv4Addr>().is_ok())
        .map(|host| format!("{host}/32"));
    if let Some(cidr) = &llm_cidr {
        tracing::info!(llm_cidr = %cidr, "network-policy: LLM CIDR for Airgap/Allowlist");
    } else {
        tracing::warn!(
            "network-policy: no IPv4 cube_facing_addr — Airgap and Allowlist hires will return 400 \
             until cfg.cube_facing_addr is set to an IPv4 address (e.g. \"192.168.0.1:8080\")"
        );
    }

    let mut instance_svc = InstanceService::new(
        cube.clone(),
        instances_store.clone(),
        secrets_store.clone(),
        tokens_store.clone(),
        proxy_base,
    )
    .with_llm_cidr(llm_cidr);
    let secrets_svc = Arc::new(SecretsService::new(secrets_store, cipher_dir.clone()));
    let user_secrets_svc = Arc::new(dyson_swarm::secrets::UserSecretsService::new(
        user_secrets_store,
        cipher_dir.clone(),
    ));
    let system_secrets_svc = Arc::new(dyson_swarm::secrets::SystemSecretsService::new(
        system_secrets_store,
        cipher_dir.clone(),
    ));

    // Stage 8: dyson runtime reconfigurer.  Pushes
    // {name, task, models} into the sandbox's
    // /api/admin/configure after create/restore/edit.  Only set
    // when swarm has both a hostname (so dyson is reachable at
    // all) and a sandbox_domain (cubeproxy is the dispatch
    // target).  We thread it into InstanceService so create()
    // and restore() both push automatically.
    let reconfigurer: Option<Arc<dyn dyson_swarm::instance::DysonReconfigurer>> =
        match dyson_swarm::dyson_reconfig::DysonReconfigurerHttp::new(
            cfg.cube.sandbox_domain.clone(),
            system_secrets_svc.clone(),
        ) {
            Ok(r) => Some(Arc::new(r)),
            Err(err) => {
                tracing::warn!(error = %err, "reconfigurer init failed; warmup-placeholder will persist");
                None
            }
        };
    if let Some(r) = &reconfigurer {
        instance_svc = instance_svc.with_reconfigurer(r.clone());
    }
    // MCP server records are sealed under the user's own cipher so a
    // stolen sqlite row leaks nothing without their age key — same
    // posture as the OpenRouter BYOK path.
    instance_svc = instance_svc.with_mcp_secrets(user_secrets_svc.clone());
    let instance_svc = Arc::new(instance_svc);

    // Name push sweep.  Every swarm restart re-pushes the per-instance
    // `name` (from the swarm-side row) into the running dyson's
    // IDENTITY.md via /api/admin/configure.  Catches up any dysons
    // whose name fell out of sync with the row — typically because
    // the row was renamed while offline, or the instance predates the
    // SPA's /api/agent endpoint.  Idempotent.
    {
        let svc = instance_svc.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            match svc.push_names_all().await {
                Ok((visited, succeeded)) => {
                    tracing::info!(visited, succeeded, "push-names: startup sweep complete");
                }
                Err(err) => tracing::warn!(error = %err, "push-names: startup sweep aborted"),
            }
        });
    }

    // Image-generation rewire sweep.  Every swarm restart re-pushes
    // the current image-gen defaults to every Live instance so a
    // bumped model id (or a fresh OpenRouter image provider entry)
    // rolls out without operator-side intervention.  Idempotent —
    // dysons that already have the right values get the same JSON
    // written back.  Spawned so the HTTP server doesn't wait on
    // possibly-cold cubeproxy timeouts.
    {
        let svc = instance_svc.clone();
        tokio::spawn(async move {
            // Brief delay so the cubeproxy / SQL pool / token store
            // all have time to settle past their first
            // dyson_proxy::dispatch resolutions.  Push timing isn't
            // load-bearing — the loop is best-effort with retries
            // through `push_with_retry` inside the per-row push call.
            tokio::time::sleep(Duration::from_secs(3)).await;
            match svc.rewire_image_generation_all().await {
                Ok((visited, succeeded)) => {
                    tracing::info!(
                        visited,
                        succeeded,
                        "rewire-image-gen: startup sweep complete"
                    );
                }
                Err(err) => tracing::warn!(
                    error = %err,
                    "rewire-image-gen: startup sweep aborted"
                ),
            }
        });
    }

    let backup_sink: Arc<dyn BackupSink> = match cfg.backup.sink {
        config::BackupSinkKind::Local => Arc::new(LocalDiskBackupSink::new(cube.clone())),
        config::BackupSinkKind::S3 => {
            let s3cfg = cfg
                .backup
                .s3
                .as_ref()
                .expect("validated by Config::load");
            match S3BackupSink::new(s3cfg, cfg.backup.local_cache_dir.clone(), cube.clone()) {
                Ok(s) => Arc::new(s),
                Err(err) => {
                    tracing::error!(error = %err, "s3 backup sink init failed");
                    return ExitCode::from(2);
                }
            }
        }
    };
    let snapshot_svc = Arc::new(SnapshotService::new(
        cube,
        instances_store.clone(),
        snapshots_store,
        backup_sink,
        instance_svc.clone(),
    ));

    // Binary rotation sweep.  Opt-in: every Live instance whose cube
    // template is older than `default_template_id` is snapshot+
    // restored onto the current default and the source destroyed.
    // This closes the gap left by config-only rewires (the image-gen
    // sweep above) when the fix lives in the dyson binary — config
    // pushes can't add a new ConfigureBody field, can't change tool
    // registration logic, can't fix the no-skills-block boot bug.
    //
    // Sequenced AFTER the image-gen sweep with a longer settle delay:
    // config push is cheap; if the lighter work fixes the dyson
    // there's no reason to bear the snapshot+restore cost.  ≥30s lets
    // the cubeproxy upstream routing fully warm so the new restore's
    // configure-push doesn't race a cold nginx and lose to 502s.
    //
    // Always run the rotate-binary sweep on startup.  The sequence
    // serialises one instance at a time through `rotate_in_place`
    // (snapshot + new cube + swap + destroy) so the host never carries
    // 2× cube memory at once.  The Phase 0 quiesce gate inside
    // `rotate_in_place` waits for each dyson to go naturally idle
    // before snapshotting, so users mid-conversation aren't forced
    // into a 503 — they pause, we swap silently, they resume on the
    // new cube under the same subdomain.  Skipped only when
    // `default_template_id` is unset (single-tenant test mode).
    {
        let target_template = cfg
            .default_template_id
            .clone()
            .filter(|s| !s.trim().is_empty());
        if let Some(target) = target_template {
            let isvc = instance_svc.clone();
            let ssvc = snapshot_svc.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                match isvc.rotate_binary_all(&ssvc, &target).await {
                    Ok(report) => {
                        tracing::info!(
                            visited = report.visited,
                            rotated = report.rotated,
                            failed = report.failed.len(),
                            target_template = %target,
                            "rotate-binary: startup sweep complete"
                        );
                        for (id, err) in &report.failed {
                            tracing::warn!(
                                instance = %id,
                                error = %err,
                                "rotate-binary: row left for next sweep"
                            );
                        }
                    }
                    Err(err) => tracing::warn!(
                        error = %err,
                        "rotate-binary: startup sweep aborted"
                    ),
                }
            });
        } else {
            tracing::debug!(
                "rotate-binary: default_template_id unset — startup sweep skipped"
            );
        }
    }

    let auth = if dangerous_no_auth {
        AuthState::dangerous_no_auth()
    } else if let Some(roles) = cfg.oidc.as_ref().and_then(|o| o.roles.clone()) {
        AuthState::enforced(roles)
    } else {
        tracing::warn!(
            "no [oidc.roles] in config — admin endpoints will return 404 \
             for everyone.  Set oidc.roles.{{claim,admin}} or pass \
             --dangerous-no-auth for local dev."
        );
        // No `[oidc.roles]` configured: build an enforced AuthState with
        // `roles: None`.  `require_admin_role` 404s every caller in that
        // shape, which is the same denial response a real role-miss
        // produces — admin's 404-not-403 contract holds without a
        // sentinel role-pair.  An earlier version of this branch stamped
        // `OidcRoles { claim: "".into(), admin: "".into() }` to keep the
        // layer ordering uniform; that placeholder is unnecessary and
        // muddied the "is admin enabled" check, so it's gone.
        AuthState {
            roles: None,
            dangerous_no_auth: false,
        }
    };

    let prober: Arc<dyn HealthProber> = match HttpHealthProber::new(
        Duration::from_secs(cfg.health_probe_timeout_seconds),
        cfg.hostname.clone(),
    ) {
        Ok(p) => Arc::new(p),
        Err(err) => {
            tracing::error!(error = %err, "health prober init failed");
            return ExitCode::from(2);
        }
    };
    let _probe_loop = probe::spawn_loop(
        prober.clone(),
        instances_store.clone(),
        Duration::from_secs(cfg.health_probe_interval_seconds),
    );
    let _ttl_loop = ttl::spawn_loop(
        instances_store.clone(),
        instance_svc.clone(),
        ttl::DEFAULT_INTERVAL,
    );

    let default_policy = InstancePolicy {
        allowed_providers: cfg.default_policy.allowed_providers.clone(),
        allowed_models: cfg.default_policy.allowed_models.clone(),
        daily_token_budget: cfg.default_policy.daily_token_budget,
        monthly_usd_budget: cfg.default_policy.monthly_usd_budget,
        rps_limit: cfg.default_policy.rps_limit,
    };
    // Stage 6: OpenRouter Provisioning client + per-user key resolver.
    // Optional — when [openrouter] isn't configured (or the key file
    // is missing) the proxy falls back to the global
    // `[providers.openrouter].api_key`.  Constructed up front so both
    // the proxy and the admin endpoints share one resolver.
    let or_provisioning: Option<Arc<dyn dyson_swarm::openrouter::Provisioning>> =
        match resolve_or_provisioning_async(&cfg, system_secrets_svc.as_ref()).await {
            Ok(Some(client)) => Some(Arc::new(client) as Arc<dyn dyson_swarm::openrouter::Provisioning>),
            Ok(None) => None,
            Err(err) => {
                tracing::error!(error = %err, "openrouter provisioning init failed");
                return ExitCode::from(2);
            }
        };
    let user_or_keys = or_provisioning.as_ref().map(|prov| {
        Arc::new(dyson_swarm::openrouter::UserOrKeyResolver::new(
            users_store.clone(),
            user_secrets_svc.clone(),
            prov.clone(),
        ))
    });

    // Stage 3: provider api_keys live in `system_secrets` under the
    // name `provider.<name>.api_key`.  Overlay them onto the TOML
    // [providers.*] config at startup; the system_secrets value wins
    // when set, the TOML value remains as a fallback for un-migrated
    // deployments.  Read once at startup — rotating an api key
    // requires a swarm restart, which is fine for v1.
    let providers_resolved = match overlay_provider_keys(
        cfg.providers.clone(),
        system_secrets_svc.as_ref(),
    )
    .await
    {
        Ok(p) => p,
        Err(err) => {
            tracing::error!(error = %err, "system_secrets overlay failed");
            return ExitCode::from(2);
        }
    };

    let providers_for_app = Arc::new(providers_resolved.clone());
    let mut proxy = match ProxyService::new(
        tokens_store.clone(),
        instances_store.clone(),
        policies_store,
        audit_store,
        providers_resolved,
        default_policy,
    ) {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(error = %err, "proxy service init failed");
            return ExitCode::from(2);
        }
    };
    if let Some(resolver) = &user_or_keys {
        proxy = proxy.with_user_or_keys(resolver.clone());
    }
    proxy = proxy.with_user_secrets(user_secrets_svc.clone());
    let proxy_svc = Arc::new(proxy);
    let llm_router = proxy::http::router(proxy_svc);

    // MCP-server proxy: bearer-protected JSON-RPC pass-through that lives
    // alongside `/llm/*`, plus a small set of user-session routes for
    // listing servers and starting OAuth flows.  Public origin is built
    // from the swarm hostname (used as the OAuth redirect_uri the
    // upstream provider sees); when no hostname is configured the
    // OAuth-start handler returns 503 with a clear message.
    let mcp_public_origin = cfg
        .hostname
        .as_deref()
        .map(|h| format!("https://{}", h.trim_end_matches('/')));
    let mcp_svc = match dyson_swarm::proxy::mcp::McpService::new(
        tokens_store.clone(),
        instances_store.clone(),
        user_secrets_svc.clone(),
        mcp_public_origin,
    ) {
        Ok(s) => Arc::new(s.with_instance_svc(instance_svc.clone())),
        Err(err) => {
            tracing::error!(error = %err, "mcp service init failed");
            return ExitCode::from(2);
        }
    };
    let mcp_router = dyson_swarm::proxy::mcp::router(mcp_svc.clone());
    let mcp_user_router = dyson_swarm::proxy::mcp::user_router(mcp_svc);
    let llm_router = llm_router.merge(mcp_router);

    // Authenticator chain: bearer first (cheap, in-DB lookup), then OIDC if
    // configured. Bearer claims everything that doesn't look like a JWT;
    // OIDC handles the JWT shape and is the primary path in production.
    let mut auth_links: Vec<Arc<dyn Authenticator>> =
        vec![Arc::new(BearerAuthenticator::new(users_store.clone()))];
    if let Some(oidc_cfg) = &cfg.oidc {
        let runtime_cfg = oidc::OidcConfig {
            issuer: oidc_cfg.issuer.clone(),
            audience: oidc_cfg.audience.clone(),
            jwks_url: oidc_cfg.jwks_url.clone(),
            jwks_ttl: Duration::from_secs(oidc_cfg.jwks_ttl_seconds),
        };
        match oidc::OidcAuthenticator::new(runtime_cfg) {
            Ok(o) => auth_links.push(Arc::new(o)),
            Err(err) => {
                tracing::error!(error = %err, "oidc authenticator init failed");
                return ExitCode::from(2);
            }
        }
    } else {
        tracing::warn!("no [oidc] section in config — only opaque bearer auth available");
    }
    let user_auth = UserAuthState::new(
        Arc::new(ChainAuthenticator::new(auth_links)),
        users_store.clone(),
    );

    // Per-instance webhook ("tasks") plumbing.  Stores reuse the same
    // sqlite pool every other table sits on; the dispatcher uses the
    // shared cube-trusted reqwest client so it can reach a sandbox at
    // `<port>-<sandbox_id>.<sandbox_domain>` over cubeproxy's
    // mkcert-rooted TLS (same path `dyson_proxy::forward` takes).
    let webhook_store: Arc<dyn dyson_swarm::traits::WebhookStore> =
        Arc::new(dyson_swarm::db::webhooks::SqlxWebhookStore::new(pool.clone()));
    let delivery_store: Arc<dyn dyson_swarm::traits::DeliveryStore> =
        Arc::new(dyson_swarm::db::webhooks::SqlxDeliveryStore::new(pool.clone()));
    let webhook_dispatcher: Arc<dyn dyson_swarm::webhooks::WebhookDispatcher> = {
        let http_client = match http::dyson_proxy::build_client() {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(error = %err, "webhook dispatcher http client init failed");
                return ExitCode::from(2);
            }
        };
        Arc::new(dyson_swarm::webhooks::HttpWebhookDispatcher::new(
            http_client,
            cfg.cube.sandbox_domain.clone(),
        ))
    };
    let webhooks_svc = Arc::new(dyson_swarm::webhooks::WebhookService::new(
        webhook_store,
        delivery_store,
        secrets_svc.clone(),
        instance_svc.clone(),
        webhook_dispatcher,
    ));

    // Anonymous artefact-share service — wires the SQLite pool, the
    // user-secrets handle (per-user signing keys are sealed under the
    // user's age cipher), and the apex hostname through one place.
    // The Prometheus-shaped metrics live as process-local atomics
    // inside an Arc<ShareMetrics>.
    let shares_svc = Arc::new(dyson_swarm::shares::ShareService::new(
        pool.clone(),
        user_secrets_svc.clone(),
        instance_svc.clone(),
        dyson_swarm::shares::ShareMetrics::new(),
        cfg.hostname.clone(),
    ));

    let app_state = http::AppState {
        secrets: secrets_svc,
        user_secrets: user_secrets_svc,
        system_secrets: system_secrets_svc,
        ciphers: cipher_dir.clone(),
        instances: instance_svc,
        snapshots: snapshot_svc,
        prober,
        tokens: tokens_store,
        users: users_store,
        sandbox_domain: cfg.cube.sandbox_domain.clone(),
        hostname: cfg.hostname.clone(),
        auth_config: Arc::new(http::auth_config::AuthConfig::from_toml(
            cfg.oidc.as_ref(),
            cfg.default_template_id.clone(),
            cfg.default_models.clone(),
            cfg.cube_profiles.clone(),
        )),
        dyson_http: http::dyson_proxy::build_client().expect("dyson http client init"),
        models_upstream: cfg
            .providers
            .get("openrouter")
            .map(|p| p.upstream.clone()),
        models_cache: http::models::ModelsCache::new(),
        openrouter_provisioning: or_provisioning,
        user_or_keys,
        providers: providers_for_app,
        webhooks: webhooks_svc,
        shares: shares_svc,
    };
    let app = http::router(app_state, auth, user_auth, llm_router, mcp_user_router);

    let listener = match tokio::net::TcpListener::bind(&cfg.bind).await {
        Ok(l) => l,
        Err(err) => {
            tracing::error!(error = %err, bind = %cfg.bind, "bind failed");
            return ExitCode::from(2);
        }
    };
    tracing::info!(bind = %cfg.bind, db = %cfg.db_path.display(), "swarm started");

    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = wait_for_shutdown().await;
        });
    if let Err(err) = server.await {
        tracing::error!(error = %err, "server exited with error");
        return ExitCode::FAILURE;
    }

    tracing::info!("swarm stopped");
    ExitCode::SUCCESS
}

/// Stage 3: overlay `system_secrets[provider.<name>.api_key]` onto the
/// TOML `[providers.*]` config.  The system_secret takes precedence
/// when set; the TOML value remains a fallback for deployments that
/// haven't migrated yet.
///
/// Naming convention is fixed: `provider.<name>.api_key` (e.g.
/// `provider.openrouter.api_key`).  Operators set these via
/// `swarm secrets system-set provider.openrouter.api_key <value>`.
async fn overlay_provider_keys(
    mut providers: config::Providers,
    secrets: &dyson_swarm::secrets::SystemSecretsService,
) -> Result<config::Providers, String> {
    let names: Vec<String> = providers.names().map(str::to_string).collect();
    for name in names {
        let Some(cfg) = providers.get_mut(&name) else { continue };
        let key = format!("provider.{name}.api_key");
        match secrets.get_str(&key).await {
            Ok(Some(value)) => {
                tracing::info!(
                    provider = %name,
                    "stage 3: provider api_key sourced from system_secrets"
                );
                cfg.api_key = Some(value);
            }
            Ok(None) => {
                // No system_secret set; TOML value (if any) wins.  We
                // don't warn here — many deployments will be mid-
                // migration with TOML still authoritative.
            }
            Err(err) => return Err(format!("system_secrets[{key}]: {err}")),
        }
    }
    Ok(providers)
}

/// Stage 3 sibling: the OpenRouter Provisioning key.  Same secret-
/// store-first pattern as `overlay_provider_keys`, but for the secret
/// swarm uses to mint per-user OR bearers via /api/v1/keys.
///
/// Lookup name: `openrouter.provisioning_key`.  Operators set it via
/// `swarm secrets system-set --stdin openrouter.provisioning_key`.
/// Returns the resolved plaintext (or None if neither system_secrets
/// nor a hand-edited `[openrouter] provisioning_key = "..."` block
/// carries one).
async fn resolve_or_provisioning_secret(
    cfg: &config::Config,
    secrets: &dyson_swarm::secrets::SystemSecretsService,
) -> Result<Option<String>, String> {
    if let Some(value) = secrets
        .get_str("openrouter.provisioning_key")
        .await
        .map_err(|e| format!("system_secrets[openrouter.provisioning_key]: {e}"))?
        .filter(|v| !v.trim().is_empty())
    {
        tracing::info!("stage 3: openrouter provisioning key sourced from system_secrets");
        return Ok(Some(value.trim().to_owned()));
    }
    let Some(or_cfg) = &cfg.openrouter else { return Ok(None); };
    match or_cfg.provisioning_key.as_deref() {
        Some(k) if !k.trim().is_empty() => Ok(Some(k.trim().to_owned())),
        _ => Ok(None),
    }
}

/// Async resolver that prefers `system_secrets[openrouter.provisioning_key]`
/// then falls back to `[openrouter]` config.  Builds the Provisioning
/// client when a key is found, returns Ok(None) when the operator
/// hasn't enabled Stage 6.
async fn resolve_or_provisioning_async(
    cfg: &config::Config,
    secrets: &dyson_swarm::secrets::SystemSecretsService,
) -> Result<Option<dyson_swarm::openrouter::OpenRouterProvisioning>, String> {
    let Some(key) = resolve_or_provisioning_secret(cfg, secrets).await? else {
        return Ok(None);
    };
    let upstream = cfg
        .openrouter
        .as_ref()
        .and_then(|o| o.upstream.clone())
        .or_else(|| cfg.providers.get("openrouter").map(|p| p.upstream.clone()))
        .unwrap_or_else(|| "https://openrouter.ai/api".to_string());
    dyson_swarm::openrouter::OpenRouterProvisioning::new(upstream, key)
        .map(Some)
        .map_err(|e| format!("openrouter client build: {e}"))
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
    | SecretsAction::SystemList = action
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
        // The Set/Clear/List system variants returned above.
        SecretsAction::SystemSet { .. }
        | SecretsAction::SystemClear { .. }
        | SecretsAction::SystemList => unreachable!(),
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
    let cipher_dir: Arc<dyn dyson_swarm::envelope::CipherDirectory> =
        match dyson_swarm::envelope::AgeCipherDirectory::new(cfg.resolved_keys_dir()) {
            Ok(d) => Arc::new(d),
            Err(err) => {
                eprintln!("error: envelope key dir init failed: {err:#}");
                return ExitCode::FAILURE;
            }
        };
    let store: Arc<dyn dyson_swarm::traits::SystemSecretStore> = Arc::new(
        dyson_swarm::db::secrets::SqlxSystemSecretStore::new(pool.clone()),
    );
    let svc = dyson_swarm::secrets::SystemSecretsService::new(store, cipher_dir);

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

async fn wait_for_shutdown() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    Ok(())
}
