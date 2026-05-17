use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use dyson_swarm::{
    auth::AuthState,
    auth::{
        Authenticator, UserAuthState, bearer::BearerAuthenticator, chain::ChainAuthenticator, oidc,
    },
    backup::{local::LocalDiskBackupSink, s3::S3BackupSink},
    config, cube_client, db, http,
    instance::InstanceService,
    logging,
    probe::{self, HttpHealthProber},
    proxy::{self, ProxyService, policy_check::InstancePolicy},
    sandbox_backend::CubeSandboxBackend,
    snapshot::SnapshotService,
    traits::{
        AdminAuditStore, AuditStore, BackupSink, CubeClient, HealthProber, InstanceStore,
        McpAuditStore, PolicyStore, SandboxBackend, SessionStore, SnapshotStore, TokenStore,
        UserStore,
    },
    ttl,
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

fn startup_rotation_target(enabled: bool, default_template_id: Option<&str>) -> Option<String> {
    if !enabled {
        return None;
    }
    default_template_id
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
}

#[derive(Debug, Parser)]
#[command(
    name = "swarm",
    version,
    about = "HTTP orchestration server for Dyson agents in CubeSandbox MicroVMs",
    disable_help_subcommand = true
)]
struct ServerArgs {
    /// Path to the config TOML.
    #[arg(long, default_value = "/etc/dyson-swarm/config.toml")]
    config: PathBuf,

    /// Disable the auth check on /v1/* routes. Loud and dangerous.
    #[arg(long = "dangerous-no-auth", default_value_t = false)]
    dangerous_no_auth: bool,
}

const DANGEROUS_BANNER: &str = "\
=================================================================
WARNING: --dangerous-no-auth is set.
The admin API at /v1/* will accept requests with no bearer token.
Every authenticated response carries X-Swarm-Insecure.
Do not run this configuration outside a trusted network.
=================================================================";

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
    let args = ServerArgs::parse();
    if args.dangerous_no_auth {
        if !env_flag("SWARM_DEV_MODE") && !env_flag("SWARM_DANGEROUS_NO_AUTH_OK") {
            eprintln!(
                "error: --dangerous-no-auth requires SWARM_DEV_MODE=1 or SWARM_DANGEROUS_NO_AUTH_OK=1"
            );
            return ExitCode::from(2);
        }
        eprintln!("{DANGEROUS_BANNER}");
    }
    logging::init();

    let cfg = match config::Config::load(&args.config, &collect_env(), args.dangerous_no_auth) {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(error = %err, config = %args.config.display(), "config load failed");
            return ExitCode::from(2);
        }
    };

    run_server(cfg, args.dangerous_no_auth).await
}

async fn run_server(cfg: config::Config, dangerous_no_auth: bool) -> ExitCode {
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
    let token_cipher = match cipher_dir.system() {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(error = %err, "token envelope init failed");
            return ExitCode::from(2);
        }
    };
    let database = match db::open_configured(&cfg, cipher_dir.clone(), token_cipher.clone()).await {
        Ok(db) => db,
        Err(err) => {
            tracing::error!(
                error = %err,
                backend = %cfg.database_backend,
                db = %cfg.db_path.display(),
                "db open failed"
            );
            return ExitCode::from(2);
        }
    };
    let stores = database.stores.clone();

    let cube = match cube_client::HttpCubeClient::new(&cfg.cube) {
        Ok(c) => Arc::new(c) as Arc<dyn CubeClient>,
        Err(err) => {
            tracing::error!(error = %err, "cube client init failed");
            return ExitCode::from(2);
        }
    };
    let sandbox_backend: Arc<dyn SandboxBackend> = Arc::new(CubeSandboxBackend::new(cube.clone()));
    let user_secrets_store = stores.user_secrets.clone();
    let system_secrets_store = stores.system_secrets.clone();
    if cipher_dir.is_sealed_mode() {
        tracing::warn!("KMS sealed mode enabled; runtime secret data migrations skipped");
    } else {
        match stores.runtime_migrator.migrate(token_cipher.as_ref()).await {
            Ok(report) => {
                if report.applied {
                    tracing::info!(
                        proxy_tokens = report.proxy_tokens_sealed,
                        instance_bearers = report.instance_bearers_sealed,
                        proxy_token_lookups = report.proxy_token_lookups_backfilled,
                        "runtime data migrations complete"
                    );
                }
            }
            Err(err) => {
                tracing::error!(error = %err, "runtime data migration failed");
                return ExitCode::from(2);
            }
        }
    }
    let instances_store: Arc<dyn InstanceStore> = stores.instances.clone();
    let tokens_store: Arc<dyn TokenStore> = stores.tokens.clone();
    let snapshots_store: Arc<dyn SnapshotStore> = stores.snapshots.clone();
    let policies_store: Arc<dyn PolicyStore> = stores.policies.clone();
    let audit_store: Arc<dyn AuditStore> = stores.audit.clone();
    let mcp_audit_store: Arc<dyn McpAuditStore> = stores.mcp_audit.clone();
    let llm_tool_calls_store: Arc<dyn dyson_swarm::traits::LlmToolCallStore> =
        stores.llm_tool_calls.clone();
    let admin_audit_store: Arc<dyn AdminAuditStore> = stores.admin_audit.clone();
    let users_store: Arc<dyn UserStore> = stores.users.clone();
    let sessions_store: Arc<dyn SessionStore> = stores.sessions.clone();
    let state_files = std::sync::Arc::new(dyson_swarm::state_files::StateFileService::new(
        stores.state_files.clone(),
        cipher_dir.clone(),
    ));
    let outbound_policy = Arc::new(dyson_swarm_core::upstream_policy::OutboundUrlPolicy {
        enabled: cfg.byo.enabled,
        allow_localhost: cfg.byo.allow_localhost,
        allow_internal: cfg.byo.allow_internal,
    });
    let external_http = Arc::new(dyson_swarm_core::http::ExternalHttpClient::new(
        outbound_policy.clone(),
    ));
    let skill_marketplace_store = stores.skill_marketplace_sources.clone();
    let skill_marketplace = Arc::new(
        dyson_swarm::skill_marketplace::SkillMarketplaceService::new_with_external_client(
            skill_marketplace_store,
            (*external_http).clone(),
        ),
    );

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

    let mut instance_svc = InstanceService::with_backend(
        sandbox_backend.clone(),
        instances_store.clone(),
        tokens_store.clone(),
        proxy_base,
    )
    .with_llm_cidr(llm_cidr)
    .with_network_config(cfg.network.clone())
    .with_mcp_upstream_policy(dyson_swarm::upstream_policy::OutboundUrlPolicy {
        enabled: cfg.byo.enabled,
        allow_localhost: cfg.byo.allow_localhost,
        allow_internal: cfg.byo.allow_internal,
    });
    let egress_sync: Arc<dyn dyson_swarm::egress_policy_sync::EgressPolicySync> =
        Arc::new(dyson_swarm::egress_policy_sync::SystemdEgressPolicySync::new());
    instance_svc = instance_svc.with_egress_policy_sync(egress_sync.clone());
    let user_secrets_svc = Arc::new(dyson_swarm::secrets::UserSecretsService::new(
        user_secrets_store,
        cipher_dir.clone(),
    ));
    let agent_secrets_svc = Arc::new(dyson_swarm::agent_secrets::AgentSecretsService::new(
        stores.agent_secrets.clone(),
        cipher_dir.clone(),
        stores.secret_access_audit.clone(),
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
    instance_svc = instance_svc.with_channels(stores.channels.clone());
    instance_svc = instance_svc.with_agent_secrets(stores.agent_secrets.clone());
    instance_svc = instance_svc.with_state_files(state_files.clone());
    let instance_svc = Arc::new(instance_svc);
    if let Err(err) = instance_svc
        .warn_live_internal_network_policies_if_disabled()
        .await
    {
        tracing::warn!(
            error = %err,
            "network-policy: startup Open policy warning scan failed"
        );
    }

    // Runtime config sync sweep. Every swarm restart re-pushes the
    // current desired config to every Live instance: models, tools,
    // runtime tokens, state sync, image generation, and MCP servers.
    // Idempotent; spawned so the HTTP server doesn't wait on
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
            match svc.sync_runtime_config_all().await {
                Ok((visited, succeeded)) => {
                    tracing::info!(
                        visited,
                        succeeded,
                        "runtime-config-sync: startup sweep complete"
                    );
                }
                Err(err) => tracing::warn!(
                    error = %err,
                    "runtime-config-sync: startup sweep aborted"
                ),
            }
        });
    }

    let backup_sink: Arc<dyn BackupSink> = match cfg.backup.sink {
        config::BackupSinkKind::Local => {
            Arc::new(LocalDiskBackupSink::with_backend(sandbox_backend.clone()))
        }
        config::BackupSinkKind::S3 => {
            let s3cfg = cfg.backup.s3.as_ref().expect("validated by Config::load");
            match S3BackupSink::with_backend(
                s3cfg,
                cfg.backup.local_cache_dir.clone(),
                sandbox_backend.clone(),
            ) {
                Ok(s) => Arc::new(s),
                Err(err) => {
                    tracing::error!(error = %err, "s3 backup sink init failed");
                    return ExitCode::from(2);
                }
            }
        }
    };
    let snapshot_svc = Arc::new(SnapshotService::with_backend(
        sandbox_backend,
        instances_store.clone(),
        snapshots_store,
        backup_sink,
        instance_svc.clone(),
    ));

    // Binary rotation sweep.  Opt-in: every Live instance whose cube
    // template is older than `default_template_id` is snapshot+
    // restored onto the current default and the source destroyed.
    // This is intentionally not tied to ordinary restarts/deploys:
    // the durable mirror only covers swarm-managed state, while
    // running dysons may also hold local workspace state inside the
    // cube.  Operators can still turn this on for a deliberate binary
    // migration, but deploys must not silently replace live sandboxes.
    {
        let target_template = startup_rotation_target(
            cfg.rotate_binary_on_startup,
            cfg.default_template_id.as_deref(),
        );
        if let Some(target) = target_template {
            let isvc = instance_svc.clone();
            let ssvc = snapshot_svc.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                tracing::info!(
                    target_template = %target,
                    "rotate-binary: startup sweep starting (background)"
                );
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
        } else if cfg.rotate_binary_on_startup {
            tracing::debug!("rotate-binary: default_template_id unset — startup sweep skipped");
        } else {
            tracing::info!("rotate-binary: startup sweep disabled by config");
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
    // Optional — when it is absent, OpenRouter proxy calls require a
    // user BYOK row and otherwise fail closed. Constructed up front so
    // both the proxy and the admin endpoints share one resolver.
    let or_provisioning: Option<Arc<dyn dyson_swarm::openrouter::Provisioning>> =
        match resolve_or_provisioning_async(&cfg, system_secrets_svc.as_ref()).await {
            Ok(Some(client)) => {
                Some(Arc::new(client) as Arc<dyn dyson_swarm::openrouter::Provisioning>)
            }
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
    let providers_resolved =
        match overlay_provider_keys(cfg.providers.clone(), system_secrets_svc.as_ref()).await {
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
    proxy = proxy.with_byo_config(cfg.byo.clone());
    proxy = proxy.with_tool_call_audit(llm_tool_calls_store.clone(), cipher_dir.clone());
    if cfg.byo.allow_internal {
        tracing::warn!(
            "BYO internal upstreams enabled; tenants can point byo at private/local hosts"
        );
    } else if !cfg.byo.enabled {
        tracing::warn!("BYO upstreams disabled by operator config");
    }
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
    let (mcp_runtime_socket, mcp_docker_runtime, docker_catalog, allow_user_docker_json) =
        match cfg.mcp_runtime.as_ref() {
            Some(runtime) => (
                Some(runtime.socket_path.clone()),
                runtime.runtime.as_str().to_owned(),
                runtime.docker_catalog.clone(),
                runtime.allow_user_docker_json,
            ),
            None => (None, "runsc".to_owned(), Vec::new(), false),
        };
    let mcp_catalog_store = stores.mcp_docker_catalog.clone();
    if let Err(err) = mcp_catalog_store.seed_config(&docker_catalog).await {
        tracing::error!(error = %err, "mcp docker catalog seed failed");
        return ExitCode::from(2);
    }
    let mcp_svc = match dyson_swarm::proxy::mcp::McpService::new(
        tokens_store.clone(),
        instances_store.clone(),
        user_secrets_svc.clone(),
        mcp_public_origin,
    ) {
        Ok(s) => Arc::new(
            s.with_instance_svc(instance_svc.clone())
                .with_runtime_socket(mcp_runtime_socket.clone())
                .with_docker_runtime(mcp_docker_runtime)
                .with_docker_catalog(docker_catalog, allow_user_docker_json)
                .with_docker_catalog_store(mcp_catalog_store)
                .with_mcp_audit(mcp_audit_store)
                .with_mcp_upstream_policy(dyson_swarm::upstream_policy::OutboundUrlPolicy {
                    enabled: cfg.byo.enabled,
                    allow_localhost: cfg.byo.allow_localhost,
                    allow_internal: cfg.byo.allow_internal,
                }),
        ),
        Err(err) => {
            tracing::error!(error = %err, "mcp service init failed");
            return ExitCode::from(2);
        }
    };
    {
        let svc = mcp_svc.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            const ATTEMPTS: usize = 6;
            for attempt in 1..=ATTEMPTS {
                match dyson_swarm::proxy::mcp::restart_active_runtime_servers(svc.clone()).await {
                    Ok(report) => {
                        tracing::info!(
                            attempt,
                            visited = report.visited_instances,
                            runtime_servers = report.runtime_servers,
                            restarted = report.restarted,
                            failed = report.failed,
                            "mcp-runtime: startup restart sweep complete"
                        );
                        if report.failed == 0 {
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            attempt,
                            error = %err,
                            "mcp-runtime: startup restart sweep aborted"
                        );
                    }
                }
                if attempt < ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        });
    }
    let mcp_router = dyson_swarm::proxy::mcp::router(mcp_svc.clone());
    let mcp_user_router = dyson_swarm::proxy::mcp::user_router(mcp_svc.clone());
    let mcp_admin_router = dyson_swarm::proxy::mcp::admin_router(mcp_svc);
    let telegram_api_base = std::env::var("SWARM_TELEGRAM_API_BASE")
        .unwrap_or_else(|_| "https://api.telegram.org".to_owned());
    let telegram_proxy_svc = match dyson_swarm::proxy::telegram::TelegramProxyService::new(
        tokens_store.clone(),
        instances_store.clone(),
        stores.channels.clone(),
        user_secrets_svc.clone(),
        telegram_api_base.clone(),
    ) {
        Ok(svc) => Arc::new(svc),
        Err(err) => {
            tracing::error!(error = %err, "telegram proxy init failed");
            return ExitCode::from(2);
        }
    };
    let telegram_router = dyson_swarm::proxy::telegram::router(telegram_proxy_svc);
    let llm_router = llm_router.merge(mcp_router).merge(telegram_router);

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
    )
    .with_sessions(sessions_store.clone());

    // Per-instance webhook ("tasks") plumbing.  The dispatcher uses the
    // shared cube-trusted reqwest client so it can reach a sandbox at
    // `<port>-<sandbox_id>.<sandbox_domain>` over cubeproxy's
    // mkcert-rooted TLS (same path `dyson_proxy::forward` takes).
    let webhook_store: Arc<dyn dyson_swarm::traits::WebhookStore> = stores.webhooks.clone();
    let delivery_store: Arc<dyn dyson_swarm::traits::DeliveryStore> = stores.deliveries.clone();
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
        user_secrets_svc.clone(),
        instance_svc.clone(),
        webhook_dispatcher,
        cipher_dir.clone(),
    ));
    let public_origin = cfg
        .hostname
        .as_deref()
        .map(|h| format!("https://{}", h.trim_end_matches('/')));
    let telegram_api: Arc<dyn dyson_swarm::channels::TelegramApi> =
        match dyson_swarm::channels::ReqwestTelegramApi::new(telegram_api_base) {
            Ok(api) => Arc::new(api),
            Err(err) => {
                tracing::error!(error = %err, "telegram api client init failed");
                return ExitCode::from(2);
            }
        };
    let channels_svc = Arc::new(dyson_swarm::channels::ChannelsService::new(
        stores.channels.clone(),
        instances_store.clone(),
        user_secrets_svc.clone(),
        telegram_api,
        public_origin,
    ));

    // Swarm-side artefact store. Metadata and sealed bytes live in the
    // swarm DB so shared artefacts outlive their cube and any one host.
    let artefact_cache = std::sync::Arc::new(dyson_swarm::artefacts::ArtefactCacheService::new(
        stores.artefacts.clone(),
        cipher_dir.clone(),
    ));
    // Anonymous artefact-share service — wires the share store, the
    // user-secrets handle (per-user signing keys are sealed under the
    // user's age cipher), the artefact cache used to verify mint
    // requests, and the apex hostname through one place.
    let shares_svc = Arc::new(dyson_swarm::shares::ShareService::new(
        stores.shares.clone(),
        user_secrets_svc.clone(),
        instance_svc.clone(),
        artefact_cache.clone(),
        dyson_swarm::shares::ShareMetrics::new(),
        cfg.hostname.clone(),
    ));
    let dyson_http =
        match startup_result(http::dyson_proxy::build_client(), "dyson http client init") {
            Ok(client) => client,
            Err(err) => {
                tracing::error!(error = %err, "startup failed");
                return ExitCode::FAILURE;
            }
        };

    let app_state = http::AppState {
        user_secrets: user_secrets_svc,
        agent_secrets: agent_secrets_svc,
        system_secrets: system_secrets_svc,
        ciphers: cipher_dir.clone(),
        instances: instance_svc,
        snapshots: snapshot_svc,
        prober,
        tokens: tokens_store,
        users: users_store,
        sessions: sessions_store,
        admin_audit: admin_audit_store,
        secret_access_audit: stores.secret_access_audit.clone(),
        llm_tool_calls: llm_tool_calls_store,
        egress_sync,
        sandbox_domain: cfg.cube.sandbox_domain.clone(),
        hostname: cfg.hostname.clone(),
        auth_config: Arc::new(http::auth_config::AuthConfig::from_toml(
            cfg.oidc.as_ref(),
            cfg.default_template_id.clone(),
            cfg.default_models.clone(),
            cfg.cube_profiles.clone(),
            cfg.network.clone(),
        )),
        dyson_http,
        models_upstream: cfg.providers.get("openrouter").map(|p| p.upstream.clone()),
        models_cache: http::models::ModelsCache::new(),
        openrouter_provisioning: or_provisioning,
        user_or_keys,
        providers: providers_for_app,
        byo: Arc::new(cfg.byo.clone()),
        external_http,
        webhooks: webhooks_svc,
        channels: channels_svc,
        shares: shares_svc,
        artefact_cache,
        state_files,
        skill_marketplace,
        agent_skill_publications: stores.agent_skill_publications.clone(),
        mcp_runtime_socket,
    };
    let app = http::router(
        app_state,
        auth,
        user_auth,
        llm_router,
        mcp_user_router,
        mcp_admin_router,
    );

    let listener = match tokio::net::TcpListener::bind(&cfg.bind).await {
        Ok(l) => l,
        Err(err) => {
            tracing::error!(error = %err, bind = %cfg.bind, "bind failed");
            return ExitCode::from(2);
        }
    };
    tracing::info!(
        bind = %cfg.bind,
        backend = %cfg.database_backend,
        db = %cfg.db_path.display(),
        "swarm started"
    );

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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
/// `swarmctl secrets system-set provider.openrouter.api_key <value>`.
async fn overlay_provider_keys(
    mut providers: config::Providers,
    secrets: &dyson_swarm::secrets::SystemSecretsService,
) -> Result<config::Providers, String> {
    let names: Vec<String> = providers.names().map(str::to_owned).collect();
    for name in names {
        let Some(cfg) = providers.get_mut(&name) else {
            continue;
        };
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
/// `swarmctl secrets system-set --stdin openrouter.provisioning_key`.
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
    let Some(or_cfg) = &cfg.openrouter else {
        return Ok(None);
    };
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
        .unwrap_or_else(|| "https://openrouter.ai/api".to_owned());
    dyson_swarm::openrouter::OpenRouterProvisioning::new(upstream, key)
        .map(Some)
        .map_err(|e| format!("openrouter client build: {e}"))
}

fn startup_result<T, E: std::fmt::Display>(
    result: Result<T, E>,
    context: &'static str,
) -> Result<T, String> {
    result.map_err(|err| format!("{context}: {err}"))
}

async fn wait_for_shutdown() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{startup_result, startup_rotation_target};

    #[test]
    fn regression_dyson_http_client_init_error_is_returned() {
        let err =
            startup_result::<(), _>(Err("builder failed"), "dyson http client init").unwrap_err();
        assert_eq!(err, "dyson http client init: builder failed");
    }

    #[test]
    fn startup_result_returns_success_value() {
        let value = startup_result::<_, &str>(Ok(42), "dyson http client init").unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn startup_rotation_requires_explicit_enable() {
        assert_eq!(startup_rotation_target(false, Some("tpl-new")), None);
    }

    #[test]
    fn startup_rotation_uses_trimmed_default_template_when_enabled() {
        assert_eq!(
            startup_rotation_target(true, Some(" tpl-new ")),
            Some("tpl-new".to_string())
        );
    }

    #[test]
    fn startup_rotation_skips_empty_default_template() {
        assert_eq!(startup_rotation_target(true, Some("   ")), None);
        assert_eq!(startup_rotation_target(true, None), None);
    }
}
