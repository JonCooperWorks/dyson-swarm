use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use reqwest::Method;

use dyson_warden::{
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
        .filter(|(k, _)| k.starts_with("WARDEN_"))
        .collect()
}

#[tokio::main]
async fn main() -> ExitCode {
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
    let user_secrets_store: Arc<dyn dyson_warden::traits::UserSecretStore> =
        Arc::new(dyson_warden::db::secrets::SqlxUserSecretStore::new(pool.clone()));
    let system_secrets_store: Arc<dyn dyson_warden::traits::SystemSecretStore> =
        Arc::new(dyson_warden::db::secrets::SqlxSystemSecretStore::new(pool.clone()));
    let tokens_store: Arc<dyn TokenStore> = Arc::new(SqlxTokenStore::new(pool.clone()));

    // Per-user envelope encryption directory.  Lazy-creates an age
    // identity per user inside `keys_dir` on first secret seal/open.
    let cipher_dir: Arc<dyn dyson_warden::envelope::CipherDirectory> =
        match dyson_warden::envelope::AgeCipherDirectory::new(cfg.resolved_keys_dir()) {
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
    let users_store: Arc<dyn UserStore> = Arc::new(db::users::SqlxUserStore::new(pool.clone()));

    let proxy_base = format!("http://{}/llm", cfg.bind);
    let instance_svc = Arc::new(InstanceService::new(
        cube.clone(),
        instances_store.clone(),
        secrets_store.clone(),
        tokens_store.clone(),
        proxy_base,
        cfg.default_ttl_seconds,
    ));
    let secrets_svc = Arc::new(SecretsService::new(secrets_store, cipher_dir.clone()));
    let user_secrets_svc = Arc::new(dyson_warden::secrets::UserSecretsService::new(
        user_secrets_store,
        cipher_dir.clone(),
    ));
    let system_secrets_svc = Arc::new(dyson_warden::secrets::SystemSecretsService::new(
        system_secrets_store,
        cipher_dir.clone(),
    ));

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

    let auth = if dangerous_no_auth {
        AuthState::dangerous_no_auth()
    } else {
        match cfg.oidc.as_ref().and_then(|o| o.roles.clone()) {
            Some(roles) => AuthState::enforced(roles),
            None => {
                tracing::warn!(
                    "no [oidc.roles] in config — admin endpoints will return 403 \
                     for everyone.  Set oidc.roles.{{claim,admin}} or pass \
                     --dangerous-no-auth for local dev."
                );
                AuthState::enforced(crate::config::OidcRoles {
                    // Sentinel that no real JWT carries → all admin
                    // requests denied.  Using a placeholder rather
                    // than a different code path keeps the layer
                    // ordering uniform.
                    claim: String::new(),
                    admin: String::new(),
                })
            }
        }
    };

    let prober: Arc<dyn HealthProber> = match HttpHealthProber::new(
        Duration::from_secs(cfg.health_probe_timeout_seconds),
        cfg.cube.sandbox_domain.clone(),
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
    let proxy_svc = match ProxyService::new(
        tokens_store.clone(),
        instances_store.clone(),
        policies_store,
        audit_store,
        cfg.providers.clone(),
        default_policy,
    ) {
        Ok(s) => Arc::new(s),
        Err(err) => {
            tracing::error!(error = %err, "proxy service init failed");
            return ExitCode::from(2);
        }
    };
    let llm_router = proxy::http::router(proxy_svc);

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
        )),
        dyson_http: http::dyson_proxy::build_client().expect("dyson http client init"),
    };
    let app = http::router(app_state, auth, user_auth, llm_router);

    let listener = match tokio::net::TcpListener::bind(&cfg.bind).await {
        Ok(l) => l,
        Err(err) => {
            tracing::error!(error = %err, bind = %cfg.bind, "bind failed");
            return ExitCode::from(2);
        }
    };
    tracing::info!(bind = %cfg.bind, db = %cfg.db_path.display(), "warden started");

    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = wait_for_shutdown().await;
        });
    if let Err(err) = server.await {
        tracing::error!(error = %err, "server exited with error");
        return ExitCode::FAILURE;
    }

    tracing::info!("warden stopped");
    ExitCode::SUCCESS
}

fn build_api_client(cfg: &config::Config, dangerous_no_auth: bool) -> Option<ApiClient> {
    // Stage 5 retired the admin_token; CLI subcommands now read a
    // user api-key from `WARDEN_API_KEY` (mint one via the SPA admin
    // panel and export).  `--dangerous-no-auth` skips entirely.
    let token = if dangerous_no_auth {
        None
    } else {
        std::env::var("WARDEN_API_KEY").ok()
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
    let Some(client) = build_api_client(cfg, dangerous_no_auth) else {
        return ExitCode::FAILURE;
    };
    let result = match action {
        SecretsAction::Set {
            instance,
            name,
            value,
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
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
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
        path.push_str(&format!("status={s}&"));
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
