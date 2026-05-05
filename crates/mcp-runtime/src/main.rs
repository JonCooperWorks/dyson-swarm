use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use clap::Parser;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

const DOCKER_INSTANCE_LABEL: &str = "dyson.mcp.instance";
const DOCKER_SERVER_LABEL: &str = "dyson.mcp.server";
const DEFAULT_SECRET_ROOT: &str = "/run/dyson-mcp-runtime/secrets";
const CONTAINER_SECRET_DIR: &str = "/run/secrets";
const SECRET_ENTRYPOINT_CONTAINER_PATH: &str = "/run/dyson-mcp-runtime-secret-entrypoint";
const SECRET_ENTRYPOINT_SHELL: &str = "/bin/sh";

#[derive(Debug, Parser)]
#[command(name = "dyson-mcp-runtime")]
struct Args {
    /// Unix socket swarm uses to ask the helper to proxy one JSON-RPC message.
    #[arg(long, default_value = "/run/dyson-mcp-runtime/runtime.sock")]
    socket: PathBuf,
    /// Idle stdio sessions are stopped after this many seconds. 0 disables idle reaping.
    #[arg(long, default_value_t = 0)]
    idle_seconds: u64,
    /// Runtime directory used for per-session Docker secret file mounts.
    #[arg(long, default_value = DEFAULT_SECRET_ROOT)]
    secrets_dir: PathBuf,
}

#[derive(Debug)]
struct ForwardRequest {
    instance_id: String,
    server_name: String,
    transport: TransportSpec,
    request_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
enum TransportSpec {
    DockerStdio {
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
    HttpStreamable {
        url: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        auth_bearer_env: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum RuntimeRequest {
    Forward {
        instance_id: String,
        server_name: String,
        transport: TransportSpec,
        request_json: String,
    },
    StopServer {
        instance_id: String,
        server_name: String,
    },
    StopInstance {
        instance_id: String,
    },
    RestartServer {
        instance_id: String,
        server_name: String,
        transport: TransportSpec,
    },
}

#[derive(Debug, Serialize)]
struct ForwardResponse {
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<&'static str>,
    body: String,
}

struct Runtime {
    sessions: Mutex<HashMap<String, Arc<RuntimeSession>>>,
    spawn_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    idle_after: Duration,
    docker: Arc<dyn DockerController>,
    secret_root: PathBuf,
}

struct RuntimeSession {
    session: Arc<dyn McpSession + Send + Sync>,
    last_used: Arc<Mutex<Instant>>,
}

#[async_trait]
trait McpSession {
    async fn send(
        &self,
        request_json: String,
        id_key: Option<String>,
    ) -> Result<Option<String>, String>;
    async fn shutdown(&self);
    fn fingerprint(&self) -> &str;
}

#[async_trait]
trait DockerController: Send + Sync {
    fn command(&self) -> &str;
    async fn cleanup_server(&self, instance_id: &str, server_name: &str) -> Result<usize, String>;
    async fn cleanup_instance(&self, instance_id: &str) -> Result<usize, String>;
}

#[derive(Debug)]
struct CliDockerController {
    command: String,
}

#[async_trait]
impl DockerController for CliDockerController {
    fn command(&self) -> &str {
        &self.command
    }

    async fn cleanup_server(&self, instance_id: &str, server_name: &str) -> Result<usize, String> {
        self.cleanup_by_labels(&[
            (DOCKER_INSTANCE_LABEL, instance_id),
            (DOCKER_SERVER_LABEL, server_name),
        ])
        .await
    }

    async fn cleanup_instance(&self, instance_id: &str) -> Result<usize, String> {
        self.cleanup_by_labels(&[(DOCKER_INSTANCE_LABEL, instance_id)])
            .await
    }
}

impl CliDockerController {
    async fn cleanup_by_labels(&self, labels: &[(&str, &str)]) -> Result<usize, String> {
        let mut ps = Command::new(&self.command);
        ps.args(["ps", "-aq"]);
        for (key, value) in labels {
            ps.arg("--filter").arg(format!("label={key}={value}"));
        }
        let output = tokio::time::timeout(Duration::from_secs(10), ps.output())
            .await
            .map_err(|_| "docker ps timed out".to_string())?
            .map_err(|e| format!("docker ps: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "docker ps failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let ids: Vec<&str> = std::str::from_utf8(&output.stdout)
            .map_err(|e| format!("docker ps utf8: {e}"))?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }

        let mut rm = Command::new(&self.command);
        rm.args(["rm", "-f"]).args(ids.iter().copied());
        let output = tokio::time::timeout(Duration::from_secs(20), rm.output())
            .await
            .map_err(|_| "docker rm timed out".to_string())?
            .map_err(|e| format!("docker rm: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "docker rm failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(ids.len())
    }
}

struct DockerStdioSession {
    fingerprint: String,
    stdin: Arc<Mutex<ChildStdin>>,
    send_lock: Mutex<()>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>,
    child: Arc<Mutex<Child>>,
    reader: JoinHandle<()>,
    secret_dir: Option<PathBuf>,
}

struct HttpStreamableSession {
    fingerprint: String,
    url: String,
    headers: BTreeMap<String, String>,
    auth_bearer_env: Option<String>,
    client: reqwest::Client,
    session_id: Mutex<Option<String>>,
    protocol_version: Mutex<Option<String>>,
    send_lock: Mutex<()>,
}

impl Runtime {
    #[cfg(test)]
    fn new(idle_after: Duration) -> Arc<Self> {
        Self::with_docker_and_secrets(
            idle_after,
            Arc::new(CliDockerController {
                command: "docker".to_string(),
            }),
            PathBuf::from(DEFAULT_SECRET_ROOT),
        )
    }

    #[cfg(test)]
    fn with_docker(idle_after: Duration, docker: Arc<dyn DockerController>) -> Arc<Self> {
        Self::with_docker_and_secrets(idle_after, docker, PathBuf::from(DEFAULT_SECRET_ROOT))
    }

    fn with_docker_and_secrets(
        idle_after: Duration,
        docker: Arc<dyn DockerController>,
        secret_root: PathBuf,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            spawn_locks: Mutex::new(HashMap::new()),
            idle_after,
            docker,
            secret_root,
        })
    }

    async fn forward(&self, req: ForwardRequest) -> ForwardResponse {
        if let Err(e) = validate_transport(&req.transport) {
            return err(400, &e);
        }
        let value: serde_json::Value = match serde_json::from_str(&req.request_json) {
            Ok(v) => v,
            Err(e) => return err(400, &format!("invalid JSON-RPC body: {e}")),
        };
        let method = value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let id_key = value.get("id").map(|id| id.to_string());
        let session_key = session_key(&req.instance_id, &req.server_name);

        if method == "initialize" {
            self.stop_session(&session_key).await;
        }
        let session = match self.get_or_spawn(&session_key, &req).await {
            Ok(s) => s,
            Err(e) => return err(502, &e),
        };
        *session.last_used.lock().await = Instant::now();

        let response = session.session.send(req.request_json, id_key).await;
        match response {
            Ok(Some(body)) => ForwardResponse {
                status: 200,
                content_type: Some("application/json"),
                body,
            },
            Ok(None) => ForwardResponse {
                status: 202,
                content_type: None,
                body: String::new(),
            },
            Err(e) => err(502, &e),
        }
    }

    async fn get_or_spawn(
        &self,
        key: &str,
        req: &ForwardRequest,
    ) -> Result<Arc<RuntimeSession>, String> {
        let wanted = session_fingerprint(&req.transport);
        if let Some(existing) = self.sessions.lock().await.get(key).cloned() {
            if existing.session.fingerprint() == wanted {
                return Ok(existing);
            }
        }
        let spawn_lock = {
            let mut locks = self.spawn_locks.lock().await;
            locks
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = spawn_lock.lock().await;
        let stale = {
            let mut sessions = self.sessions.lock().await;
            if let Some(existing) = sessions.get(key).cloned() {
                if existing.session.fingerprint() == wanted {
                    return Ok(existing);
                }
                sessions.remove(key)
            } else {
                None
            }
        };
        if let Some(session) = stale {
            session.session.shutdown().await;
            if matches!(req.transport, TransportSpec::DockerStdio { .. })
                && let Err(err) = self
                    .docker
                    .cleanup_server(&req.instance_id, &req.server_name)
                    .await
            {
                tracing::warn!(
                    error = %err,
                    instance = %req.instance_id,
                    server = %req.server_name,
                    "mcp runtime: stale docker cleanup failed"
                );
            }
        }
        let session = Arc::new(RuntimeSession {
            session: spawn_session(req, wanted, Arc::clone(&self.docker), &self.secret_root)?,
            last_used: Arc::new(Mutex::new(Instant::now())),
        });
        self.sessions
            .lock()
            .await
            .insert(key.to_string(), Arc::clone(&session));
        Ok(session)
    }

    async fn stop_session(&self, key: &str) -> bool {
        let Some(session) = self.sessions.lock().await.remove(key) else {
            return false;
        };
        session.session.shutdown().await;
        true
    }

    async fn stop_server(&self, instance_id: &str, server_name: &str) -> RuntimeStopResult {
        let stopped_sessions = usize::from(
            self.stop_session(&session_key(instance_id, server_name))
                .await,
        );
        let removed_containers = match self.docker.cleanup_server(instance_id, server_name).await {
            Ok(n) => n,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    instance = %instance_id,
                    server = %server_name,
                    "mcp runtime: docker server cleanup failed"
                );
                0
            }
        };
        RuntimeStopResult {
            stopped_sessions,
            removed_containers,
        }
    }

    async fn stop_instance(&self, instance_id: &str) -> RuntimeStopResult {
        let prefix = format!("{instance_id}:");
        let keys: Vec<String> = self
            .sessions
            .lock()
            .await
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect();
        let mut stopped_sessions = 0usize;
        for key in keys {
            stopped_sessions += usize::from(self.stop_session(&key).await);
        }
        let removed_containers = match self.docker.cleanup_instance(instance_id).await {
            Ok(n) => n,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    instance = %instance_id,
                    "mcp runtime: docker instance cleanup failed"
                );
                0
            }
        };
        RuntimeStopResult {
            stopped_sessions,
            removed_containers,
        }
    }

    async fn restart_server(
        &self,
        instance_id: String,
        server_name: String,
        transport: TransportSpec,
    ) -> ForwardResponse {
        if let Err(e) = validate_transport(&transport) {
            return err(400, &e);
        }

        let key = session_key(&instance_id, &server_name);
        let stopped_sessions = usize::from(self.stop_session(&key).await);
        let removed_containers = if matches!(transport, TransportSpec::DockerStdio { .. }) {
            match self.docker.cleanup_server(&instance_id, &server_name).await {
                Ok(n) => n,
                Err(cleanup_err) => {
                    tracing::warn!(
                        error = %cleanup_err,
                        instance = %instance_id,
                        server = %server_name,
                        "mcp runtime: docker restart cleanup failed"
                    );
                    return err(502, &format!("docker cleanup failed: {cleanup_err}"));
                }
            }
        } else {
            0
        };

        let req = ForwardRequest {
            instance_id,
            server_name,
            transport,
            request_json: String::new(),
        };
        match self.get_or_spawn(&key, &req).await {
            Ok(session) => {
                *session.last_used.lock().await = Instant::now();
                restart_response(RuntimeRestartResult {
                    stopped_sessions,
                    removed_containers,
                })
            }
            Err(e) => err(502, &e),
        }
    }

    async fn reap_idle(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let snapshot: Vec<(String, Arc<RuntimeSession>)> = self
                .sessions
                .lock()
                .await
                .iter()
                .map(|(k, v)| (k.clone(), Arc::clone(v)))
                .collect();
            for (key, session) in snapshot {
                if session.last_used.lock().await.elapsed() >= self.idle_after {
                    tracing::debug!(session = %key, "reaping idle MCP runtime session");
                    if let Some((instance_id, server_name)) = key.split_once(':') {
                        self.stop_server(instance_id, server_name).await;
                    } else {
                        self.stop_session(&key).await;
                    }
                }
            }
        }
    }
}

fn spawn_session(
    req: &ForwardRequest,
    fingerprint: String,
    docker: Arc<dyn DockerController>,
    secret_root: &Path,
) -> Result<Arc<dyn McpSession + Send + Sync>, String> {
    match &req.transport {
        TransportSpec::DockerStdio { args, env } => Ok(Arc::new(DockerStdioSession::spawn(
            docker,
            args,
            env,
            &req.instance_id,
            &req.server_name,
            fingerprint,
            secret_root,
        )?)),
        TransportSpec::HttpStreamable {
            url,
            headers,
            auth_bearer_env,
        } => Ok(Arc::new(HttpStreamableSession::new(
            url.clone(),
            headers.clone(),
            auth_bearer_env.clone(),
            fingerprint,
        )?)),
    }
}

fn session_key(instance_id: &str, server_name: &str) -> String {
    format!("{instance_id}:{server_name}")
}

#[derive(Debug, Serialize)]
struct RuntimeStopResult {
    stopped_sessions: usize,
    removed_containers: usize,
}

#[derive(Debug, Serialize)]
struct RuntimeRestartResult {
    stopped_sessions: usize,
    removed_containers: usize,
}

impl DockerStdioSession {
    fn spawn(
        docker: Arc<dyn DockerController>,
        user_args: &[String],
        env: &HashMap<String, String>,
        instance_id: &str,
        server_name: &str,
        fingerprint: String,
        secret_root: &Path,
    ) -> Result<Self, String> {
        let launch = docker_run_launch(
            user_args,
            env,
            instance_id,
            server_name,
            secret_root,
            docker.command(),
        )?;
        let mut child = Command::new(docker.command())
            .args(&launch.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                cleanup_secret_dir_sync(launch.secret_dir.as_deref());
                format!("spawn docker: {e}")
            })?;
        let Some(stdin) = child.stdin.take() else {
            cleanup_secret_dir_sync(launch.secret_dir.as_deref());
            return Err("docker child stdin was not piped".into());
        };
        let Some(stdout) = child.stdout.take() else {
            cleanup_secret_dir_sync(launch.secret_dir.as_deref());
            return Err("docker child stdout was not piped".into());
        };
        let pending: Arc<Mutex<HashMap<String, oneshot::Sender<String>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_reader = Arc::clone(&pending);
        let server_name = server_name.to_string();
        let reader = tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                    tracing::debug!(server = %server_name, "ignoring non-JSON MCP stdout line");
                    continue;
                };
                let Some(id) = value.get("id") else {
                    continue;
                };
                if let Some(tx) = pending_reader.lock().await.remove(&id.to_string()) {
                    let _ = tx.send(line);
                }
            }
            tracing::debug!(server = %server_name, "MCP runtime stdout closed");
            pending_reader.lock().await.clear();
        });
        Ok(Self {
            fingerprint,
            stdin: Arc::new(Mutex::new(stdin)),
            send_lock: Mutex::new(()),
            pending,
            child: Arc::new(Mutex::new(child)),
            reader,
            secret_dir: launch.secret_dir,
        })
    }
}

#[async_trait]
impl McpSession for DockerStdioSession {
    async fn send(
        &self,
        request_json: String,
        id_key: Option<String>,
    ) -> Result<Option<String>, String> {
        let _guard = self.send_lock.lock().await;
        let pending_id = id_key.clone();
        let rx = if let Some(id) = id_key {
            let (tx, rx) = oneshot::channel();
            self.pending.lock().await.insert(id, tx);
            Some(rx)
        } else {
            None
        };
        {
            let mut stdin = self.stdin.lock().await;
            if let Err(e) = stdin.write_all(request_json.as_bytes()).await {
                remove_pending(&self.pending, pending_id.as_deref()).await;
                return Err(format!("write stdin: {e}"));
            }
            if let Err(e) = stdin.write_all(b"\n").await {
                remove_pending(&self.pending, pending_id.as_deref()).await;
                return Err(format!("write newline: {e}"));
            }
            if let Err(e) = stdin.flush().await {
                remove_pending(&self.pending, pending_id.as_deref()).await;
                return Err(format!("flush stdin: {e}"));
            }
        }
        let Some(rx) = rx else {
            return Ok(None);
        };
        match tokio::time::timeout(Duration::from_secs(120), rx).await {
            Ok(Ok(body)) => Ok(Some(body)),
            Ok(Err(_)) => Err("MCP server exited before responding".to_string()),
            Err(_) => {
                remove_pending(&self.pending, pending_id.as_deref()).await;
                Err("MCP server response timed out".to_string())
            }
        }
    }

    async fn shutdown(&self) {
        self.reader.abort();
        let _ = self.child.lock().await.start_kill();
        if let Some(secret_dir) = &self.secret_dir
            && let Err(e) = tokio::fs::remove_dir_all(secret_dir).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                error = %e,
                path = %secret_dir.display(),
                "mcp runtime: failed to remove docker secret dir"
            );
        }
    }

    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl HttpStreamableSession {
    fn new(
        url: String,
        headers: BTreeMap<String, String>,
        auth_bearer_env: Option<String>,
        fingerprint: String,
    ) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("build HTTP client: {e}"))?;
        Ok(Self {
            fingerprint,
            url,
            headers,
            auth_bearer_env,
            client,
            session_id: Mutex::new(None),
            protocol_version: Mutex::new(None),
            send_lock: Mutex::new(()),
        })
    }
}

#[async_trait]
impl McpSession for HttpStreamableSession {
    async fn send(
        &self,
        request_json: String,
        id_key: Option<String>,
    ) -> Result<Option<String>, String> {
        let _guard = self.send_lock.lock().await;
        let request_value: serde_json::Value = serde_json::from_str(&request_json)
            .map_err(|e| format!("invalid JSON-RPC body: {e}"))?;
        let method = request_value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let mut req = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream");
        for (name, value) in &self.headers {
            req = req.header(name.as_str(), value.as_str());
        }
        if let Some(var) = &self.auth_bearer_env {
            if var.trim().is_empty() {
                return Err("auth_bearer_env must not be empty".into());
            }
            let token =
                std::env::var(var).map_err(|_| format!("bearer token env `{var}` is not set"))?;
            req = req.bearer_auth(token);
        }
        if let Some(session_id) = self.session_id.lock().await.clone() {
            req = req.header("Mcp-Session-Id", session_id);
        }
        if let Some(protocol_version) = self.protocol_version.lock().await.clone() {
            req = req.header("MCP-Protocol-Version", protocol_version);
        }

        let resp = tokio::time::timeout(Duration::from_secs(120), req.body(request_json).send())
            .await
            .map_err(|_| "HTTP MCP server response timed out".to_string())?
            .map_err(|e| {
                format!(
                    "send: {}",
                    dyson_swarm_core::mcp_servers::redact_reqwest_err(&e, &self.url)
                )
            })?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let bytes = tokio::time::timeout(Duration::from_secs(120), resp.bytes())
            .await
            .map_err(|_| "HTTP MCP server body timed out".to_string())?
            .map_err(|e| format!("read body: {e}"))?;

        if status == reqwest::StatusCode::ACCEPTED && bytes.is_empty() {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        if bytes.is_empty() {
            return if id_key.is_some() {
                Err("HTTP MCP server returned an empty response".into())
            } else {
                Ok(None)
            };
        }

        let response_value = if content_type.starts_with("text/event-stream") {
            parse_sse_jsonrpc_response(&bytes, id_key.as_deref())?
        } else {
            parse_jsonrpc_response(&bytes, id_key.as_deref())?
        };

        if method == "initialize" {
            if let Some(session_id) = headers
                .get("Mcp-Session-Id")
                .or_else(|| headers.get("mcp-session-id"))
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
            {
                *self.session_id.lock().await = Some(session_id);
            }
            if let Some(protocol_version) = response_value
                .get("result")
                .and_then(|r| r.get("protocolVersion"))
                .and_then(serde_json::Value::as_str)
            {
                *self.protocol_version.lock().await = Some(protocol_version.to_string());
            }
        }

        serde_json::to_string(&response_value)
            .map(Some)
            .map_err(|e| format!("encode JSON-RPC response: {e}"))
    }

    async fn shutdown(&self) {
        let Some(session_id) = self.session_id.lock().await.take() else {
            return;
        };
        let mut req = self
            .client
            .delete(&self.url)
            .header("Mcp-Session-Id", session_id);
        if let Some(protocol_version) = self.protocol_version.lock().await.clone() {
            req = req.header("MCP-Protocol-Version", protocol_version);
        }
        for (name, value) in &self.headers {
            req = req.header(name.as_str(), value.as_str());
        }
        if let Some(var) = &self.auth_bearer_env
            && let Ok(token) = std::env::var(var)
        {
            req = req.bearer_auth(token);
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), req.send()).await;
    }

    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

fn validate_transport(transport: &TransportSpec) -> Result<(), String> {
    match transport {
        TransportSpec::DockerStdio { args, .. } => {
            dyson_swarm_core::mcp_servers::validate_docker_stdio_args(args)
        }
        TransportSpec::HttpStreamable {
            url,
            auth_bearer_env,
            ..
        } => {
            validate_http_streamable_url(url)?;
            if matches!(auth_bearer_env, Some(v) if v.trim().is_empty()) {
                return Err("auth_bearer_env must not be empty".into());
            }
            Ok(())
        }
    }
}

fn validate_http_streamable_url(raw: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(raw).map_err(|e| format!("invalid HttpStreamable url: {e}"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if url_is_loopback(&url) => Ok(()),
        "http" => Err(
            "HttpStreamable transport requires https unless the URL uses loopback or a unix socket"
                .into(),
        ),
        "unix" | "http+unix" => Ok(()),
        scheme => Err(format!(
            "HttpStreamable transport requires http or https URL, got `{scheme}`"
        )),
    }
}

fn url_is_loopback(url: &reqwest::Url) -> bool {
    url.host_str()
        .map(|host| {
            host.parse::<IpAddr>()
                .map(|addr| addr.is_loopback())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn session_fingerprint(transport: &TransportSpec) -> String {
    match transport {
        TransportSpec::DockerStdio { args, env } => {
            let env: BTreeMap<&String, &String> = env.iter().collect();
            serde_json::json!({
                "kind": "DockerStdio",
                "args": args,
                "env": env,
            })
        }
        TransportSpec::HttpStreamable {
            url,
            headers,
            auth_bearer_env,
        } => serde_json::json!({
            "kind": "HttpStreamable",
            "url": url,
            "headers": headers,
            "auth_bearer_env": auth_bearer_env,
        }),
    }
    .to_string()
}

fn parse_jsonrpc_response(bytes: &[u8], id_key: Option<&str>) -> Result<serde_json::Value, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("parse json: {e}"))?;
    if response_matches_id(&value, id_key) {
        Ok(value)
    } else {
        Err("JSON-RPC response id did not match request".into())
    }
}

fn parse_sse_jsonrpc_response(
    bytes: &[u8],
    id_key: Option<&str>,
) -> Result<serde_json::Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("sse utf8: {e}"))?;
    let mut buf = String::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            if let Some(value) = take_matching_sse_event(&mut buf, id_key)? {
                return Ok(value);
            }
            buf.clear();
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(rest.trim_start());
        }
    }
    if let Some(value) = take_matching_sse_event(&mut buf, id_key)? {
        return Ok(value);
    }
    Err("no matching JSON-RPC response in SSE stream".into())
}

fn take_matching_sse_event(
    buf: &mut String,
    id_key: Option<&str>,
) -> Result<Option<serde_json::Value>, String> {
    if buf.is_empty() {
        return Ok(None);
    }
    let payload = std::mem::take(buf);
    let value = serde_json::from_str::<serde_json::Value>(payload.trim())
        .map_err(|e| format!("parse sse json: {e}"))?;
    if response_matches_id(&value, id_key) {
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

fn response_matches_id(value: &serde_json::Value, id_key: Option<&str>) -> bool {
    if value.get("jsonrpc").is_none()
        || !(value.get("result").is_some() || value.get("error").is_some())
    {
        return false;
    }
    match id_key {
        Some(id) => value.get("id").map(serde_json::Value::to_string).as_deref() == Some(id),
        None => true,
    }
}

async fn remove_pending(
    pending: &Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>,
    id: Option<&str>,
) {
    if let Some(id) = id {
        pending.lock().await.remove(id);
    }
}

#[cfg(test)]
fn docker_run_args(user_args: &[String], instance_id: &str, server_name: &str) -> Vec<String> {
    docker_run_launch(
        user_args,
        &HashMap::new(),
        instance_id,
        server_name,
        Path::new("/tmp/dyson-mcp-runtime-test-secrets"),
        "docker",
    )
    .expect("docker args should build")
    .args
}

struct DockerLaunch {
    args: Vec<String>,
    secret_dir: Option<PathBuf>,
}

struct DockerImageDefaults {
    entrypoint: Vec<String>,
    cmd: Vec<String>,
}

struct DockerUserArgs {
    options: Vec<String>,
    entrypoint: Option<String>,
    image: String,
    command: Vec<String>,
}

fn docker_run_launch(
    user_args: &[String],
    env: &HashMap<String, String>,
    instance_id: &str,
    server_name: &str,
    secret_root: &Path,
    docker_command: &str,
) -> Result<DockerLaunch, String> {
    let mut secrets = BTreeMap::new();
    for (name, value) in env {
        if is_env_name(name) {
            secrets.insert(name.clone(), value.clone());
        }
    }
    let mut user_args = sanitized_docker_user_args(user_args, &mut secrets);
    let secret_dir = if secrets.is_empty() {
        None
    } else {
        let dir = create_docker_secret_dir(secret_root, instance_id, server_name)?;
        if let Err(e) = write_docker_secret_files(&dir, &secrets) {
            cleanup_secret_dir_sync(Some(&dir));
            return Err(e);
        }
        match inject_secret_wrapper(user_args, &secrets, &dir, docker_command) {
            Ok(args) => {
                user_args = args;
                Some(dir)
            }
            Err(e) => {
                cleanup_secret_dir_sync(Some(&dir));
                return Err(e);
            }
        }
    };

    let mut out = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-i".to_string(),
        "--cap-drop=ALL".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "--network".to_string(),
        "bridge".to_string(),
        "--memory=512m".to_string(),
        "--cpus=1".to_string(),
        "--pids-limit=256".to_string(),
        "--label".to_string(),
        format!("{DOCKER_INSTANCE_LABEL}={instance_id}"),
        "--label".to_string(),
        format!("{DOCKER_SERVER_LABEL}={server_name}"),
    ];
    out.extend(user_args);
    Ok(DockerLaunch {
        args: out,
        secret_dir,
    })
}

fn sanitized_docker_user_args(
    user_args: &[String],
    secrets: &mut BTreeMap<String, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 1usize;
    while i < user_args.len() {
        let arg = &user_args[i];
        if arg == "--network" || arg == "--net" {
            i += 2;
            continue;
        }
        if arg.starts_with("--network=") || arg.starts_with("--net=") {
            i += 1;
            continue;
        }
        if arg == "-e" || arg == "--env" {
            if let Some(value) = user_args.get(i + 1) {
                if let Some(name) = capture_secret_env_arg(value, secrets) {
                    if !secrets.contains_key(&name) {
                        out.push(arg.clone());
                        out.push(value.clone());
                    }
                } else {
                    out.push(arg.clone());
                    out.push(value.clone());
                }
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("--env=") {
            if let Some(name) = capture_secret_env_arg(value, secrets) {
                if !secrets.contains_key(&name) {
                    out.push(format!("--env={value}"));
                }
            } else {
                out.push(format!("--env={value}"));
            }
            i += 1;
            continue;
        }
        if let Some(value) = arg.strip_prefix("-e")
            && !value.is_empty()
        {
            if let Some(name) = capture_secret_env_arg(value, secrets) {
                if !secrets.contains_key(&name) {
                    out.push(format!("-e{value}"));
                }
            } else {
                out.push(format!("-e{value}"));
            }
            i += 1;
            continue;
        }
        out.push(arg.clone());
        i += 1;
    }
    out
}

fn capture_secret_env_arg(arg: &str, secrets: &mut BTreeMap<String, String>) -> Option<String> {
    let Some((name, value)) = arg.split_once('=') else {
        if is_env_name(arg) {
            return Some(arg.to_string());
        }
        return None;
    };
    if !is_env_name(name) {
        return None;
    }
    secrets.insert(name.to_string(), value.to_string());
    Some(name.to_string())
}

fn inject_secret_wrapper(
    user_args: Vec<String>,
    secrets: &BTreeMap<String, String>,
    secret_dir: &Path,
    docker_command: &str,
) -> Result<Vec<String>, String> {
    let split = split_docker_user_args(&user_args)?;
    let wrapper_path = secret_dir.join("entrypoint.sh");
    write_file_with_mode(&wrapper_path, secret_entrypoint_script().as_bytes(), 0o555)
        .map_err(|e| format!("write docker secret entrypoint: {e}"))?;

    let mut options = split.options;
    options.push("--mount".into());
    options.push(format!(
        "type=bind,src={},dst={SECRET_ENTRYPOINT_CONTAINER_PATH},readonly",
        wrapper_path.display()
    ));
    for name in secrets.keys() {
        let container_path = format!("{CONTAINER_SECRET_DIR}/{name}");
        options.push("--mount".into());
        options.push(format!(
            "type=bind,src={},dst={container_path},readonly",
            secret_dir.join(name).display()
        ));
        options.push("--env".into());
        options.push(format!("{name}_FILE={container_path}"));
    }
    options.push("--entrypoint".into());
    options.push(SECRET_ENTRYPOINT_SHELL.into());

    let wrapped_command = wrapped_image_command(
        docker_command,
        &split.image,
        split.entrypoint.as_deref(),
        &split.command,
    )?;
    options.push(split.image);
    options.push(SECRET_ENTRYPOINT_CONTAINER_PATH.into());
    options.extend(wrapped_command);
    Ok(options)
}

fn split_docker_user_args(user_args: &[String]) -> Result<DockerUserArgs, String> {
    let mut options = Vec::new();
    let mut entrypoint = None;
    let mut i = 0usize;
    while i < user_args.len() {
        let arg = &user_args[i];
        if arg == "--" {
            let Some(image) = user_args.get(i + 1) else {
                return Err("docker run args must include an image".into());
            };
            return Ok(DockerUserArgs {
                options,
                entrypoint,
                image: image.clone(),
                command: user_args[i + 2..].to_vec(),
            });
        }
        if arg == "--entrypoint" {
            let Some(value) = user_args.get(i + 1) else {
                return Err("docker run --entrypoint requires a value".into());
            };
            entrypoint = Some(value.clone());
            i += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--entrypoint=") {
            entrypoint = Some(value.to_string());
            i += 1;
            continue;
        }
        if !arg.starts_with('-') {
            return Ok(DockerUserArgs {
                options,
                entrypoint,
                image: arg.clone(),
                command: user_args[i + 1..].to_vec(),
            });
        }
        options.push(arg.clone());
        if docker_run_option_takes_value(arg)
            && !arg.contains('=')
            && let Some(value) = user_args.get(i + 1)
        {
            options.push(value.clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    Err("docker run args must include an image".into())
}

fn docker_run_option_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "-a" | "--add-host"
            | "--annotation"
            | "--attach"
            | "--blkio-weight"
            | "-c"
            | "--cap-add"
            | "--cap-drop"
            | "--cgroup-parent"
            | "--cidfile"
            | "--cpu-period"
            | "--cpu-quota"
            | "--cpu-rt-period"
            | "--cpu-rt-runtime"
            | "--cpu-shares"
            | "--cpus"
            | "--cpuset-cpus"
            | "--cpuset-mems"
            | "--device"
            | "--device-cgroup-rule"
            | "--device-read-bps"
            | "--device-read-iops"
            | "--device-write-bps"
            | "--device-write-iops"
            | "--dns"
            | "--dns-option"
            | "--dns-search"
            | "--domainname"
            | "-e"
            | "--env"
            | "--env-file"
            | "--expose"
            | "--group-add"
            | "--health-cmd"
            | "--health-interval"
            | "--health-retries"
            | "--health-start-interval"
            | "--health-start-period"
            | "--health-timeout"
            | "-h"
            | "--hostname"
            | "--ip"
            | "--ip6"
            | "--isolation"
            | "-l"
            | "--label"
            | "--link"
            | "--link-local-ip"
            | "--log-driver"
            | "--log-opt"
            | "-m"
            | "--memory"
            | "--memory-reservation"
            | "--memory-swap"
            | "--memory-swappiness"
            | "--mount"
            | "--name"
            | "--network"
            | "--network-alias"
            | "--oom-score-adj"
            | "-p"
            | "--pid"
            | "--pids-limit"
            | "--platform"
            | "--publish"
            | "--pull"
            | "--restart"
            | "--runtime"
            | "--security-opt"
            | "--shm-size"
            | "--stop-signal"
            | "--stop-timeout"
            | "--storage-opt"
            | "--sysctl"
            | "--tmpfs"
            | "--ulimit"
            | "-u"
            | "--user"
            | "--userns"
            | "-v"
            | "--volume"
            | "--volumes-from"
            | "-w"
            | "--workdir"
    )
}

fn wrapped_image_command(
    docker_command: &str,
    image: &str,
    entrypoint_override: Option<&str>,
    command: &[String],
) -> Result<Vec<String>, String> {
    let defaults = if entrypoint_override.is_none() || command.is_empty() {
        inspect_docker_image_defaults(docker_command, image)?
    } else {
        None
    }
    .unwrap_or_else(|| DockerImageDefaults {
        entrypoint: Vec::new(),
        cmd: Vec::new(),
    });

    let mut out = Vec::new();
    if let Some(entrypoint) = entrypoint_override {
        out.push(entrypoint.to_string());
        if command.is_empty() {
            out.extend(defaults.cmd);
        } else {
            out.extend(command.iter().cloned());
        }
    } else if !defaults.entrypoint.is_empty() {
        out.extend(defaults.entrypoint);
        if command.is_empty() {
            out.extend(defaults.cmd);
        } else {
            out.extend(command.iter().cloned());
        }
    } else if !command.is_empty() {
        out.extend(command.iter().cloned());
    } else {
        out.extend(defaults.cmd);
    }

    if out.is_empty() {
        return Err(format!(
            "docker secret wrapper could not determine startup command for image `{image}`"
        ));
    }
    Ok(out)
}

fn inspect_docker_image_defaults(
    docker_command: &str,
    image: &str,
) -> Result<Option<DockerImageDefaults>, String> {
    match inspect_docker_image_defaults_once(docker_command, image)? {
        Some(defaults) => Ok(Some(defaults)),
        None => {
            let pull = StdCommand::new(docker_command)
                .args(["pull", image])
                .output()
                .map_err(|e| format!("docker pull {image}: {e}"))?;
            if !pull.status.success() {
                return Ok(None);
            }
            inspect_docker_image_defaults_once(docker_command, image)
        }
    }
}

fn inspect_docker_image_defaults_once(
    docker_command: &str,
    image: &str,
) -> Result<Option<DockerImageDefaults>, String> {
    let output = StdCommand::new(docker_command)
        .args([
            "image",
            "inspect",
            image,
            "--format",
            "{{json .Config.Entrypoint}}\n{{json .Config.Cmd}}",
        ])
        .output()
        .map_err(|e| format!("docker image inspect {image}: {e}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|e| format!("docker image inspect {image} produced non-utf8 output: {e}"))?;
    let mut lines = text.lines();
    let entrypoint = parse_docker_json_string_list(lines.next().unwrap_or(""))?;
    let cmd = parse_docker_json_string_list(lines.next().unwrap_or(""))?;
    Ok(Some(DockerImageDefaults { entrypoint, cmd }))
}

fn parse_docker_json_string_list(raw: &str) -> Result<Vec<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "null" || raw == "<no value>" {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<String>>(raw)
        .map_err(|e| format!("parse docker image defaults: {e}"))
}

fn create_docker_secret_dir(
    secret_root: &Path,
    instance_id: &str,
    server_name: &str,
) -> Result<PathBuf, String> {
    create_private_dir(secret_root)
        .map_err(|e| format!("create docker secret root `{}`: {e}", secret_root.display()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock before unix epoch: {e}"))?
        .as_nanos();
    let dir = secret_root.join(format!(
        "{}-{}-{nonce}",
        safe_path_component(instance_id),
        safe_path_component(server_name)
    ));
    create_private_dir(&dir)
        .map_err(|e| format!("create docker secret dir `{}`: {e}", dir.display()))?;
    Ok(dir)
}

fn write_docker_secret_files(
    secret_dir: &Path,
    secrets: &BTreeMap<String, String>,
) -> Result<(), String> {
    for (name, value) in secrets {
        write_file_with_mode(&secret_dir.join(name), value.as_bytes(), 0o444)
            .map_err(|e| format!("write docker secret `{name}`: {e}"))?;
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_file_with_mode(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn safe_path_component(value: &str) -> String {
    let out: String = value
        .chars()
        .map(|c| {
            if c == '_' || c == '-' || c == '.' || c.is_ascii_alphanumeric() {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() { "_".into() } else { out }
}

fn secret_entrypoint_script() -> &'static str {
    r#"#!/bin/sh
set -eu

for secret in /run/secrets/*; do
  [ -f "$secret" ] || continue
  name=${secret##*/}
  case "$name" in
    ""|*[!A-Za-z0-9_]*|[0-9]*) continue ;;
  esac
  value=$(cat "$secret")
  export "$name=$value"
  export "${name}_FILE=$secret"
done

exec "$@"
"#
}

fn cleanup_secret_dir_sync(secret_dir: Option<&Path>) {
    if let Some(secret_dir) = secret_dir
        && let Err(e) = fs::remove_dir_all(secret_dir)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            error = %e,
            path = %secret_dir.display(),
            "mcp runtime: failed to remove docker secret dir"
        );
    }
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn err(status: u16, msg: &str) -> ForwardResponse {
    let body = serde_json::json!({ "error": msg }).to_string();
    ForwardResponse {
        status,
        content_type: Some("application/json"),
        body,
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    if let Some(parent) = args.socket.parent()
        && let Err(e) = tokio::fs::create_dir_all(parent).await
    {
        tracing::error!(error = %e, path = %parent.display(), "failed to create socket dir");
        return std::process::ExitCode::from(2);
    }
    let _ = tokio::fs::remove_file(&args.socket).await;
    let listener = match UnixListener::bind(&args.socket) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, socket = %args.socket.display(), "failed to bind socket");
            return std::process::ExitCode::from(2);
        }
    };
    #[cfg(unix)]
    if let Err(e) = set_socket_mode(&args.socket) {
        tracing::warn!(error = %e, socket = %args.socket.display(), "failed to chmod socket");
    }
    let runtime = Runtime::with_docker_and_secrets(
        Duration::from_secs(args.idle_seconds),
        Arc::new(CliDockerController {
            command: "docker".to_string(),
        }),
        args.secrets_dir.clone(),
    );
    if args.idle_seconds > 0 {
        tokio::spawn(Arc::clone(&runtime).reap_idle());
    }
    tracing::info!(socket = %args.socket.display(), "dyson MCP runtime listening");
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let rt = Arc::clone(&runtime);
                tokio::spawn(async move {
                    handle_connection(rt, stream).await;
                });
            }
            Err(e) => tracing::warn!(error = %e, "runtime accept failed"),
        }
    }
}

async fn handle_connection(runtime: Arc<Runtime>, stream: UnixStream) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let response = match reader.read_line(&mut line).await {
        Ok(0) => err(400, "empty request"),
        Ok(_) => match serde_json::from_str::<RuntimeRequest>(&line) {
            Ok(RuntimeRequest::Forward {
                instance_id,
                server_name,
                transport,
                request_json,
            }) => {
                runtime
                    .forward(ForwardRequest {
                        instance_id,
                        server_name,
                        transport,
                        request_json,
                    })
                    .await
            }
            Ok(RuntimeRequest::StopServer {
                instance_id,
                server_name,
            }) => stop_response(runtime.stop_server(&instance_id, &server_name).await),
            Ok(RuntimeRequest::StopInstance { instance_id }) => {
                stop_response(runtime.stop_instance(&instance_id).await)
            }
            Ok(RuntimeRequest::RestartServer {
                instance_id,
                server_name,
                transport,
            }) => {
                runtime
                    .restart_server(instance_id, server_name, transport)
                    .await
            }
            Err(e) => err(400, &format!("invalid request: {e}")),
        },
        Err(e) => err(400, &format!("read request: {e}")),
    };
    let mut stream = reader.into_inner();
    if let Ok(bytes) = serde_json::to_vec(&response) {
        let _ = stream.write_all(&bytes).await;
        let _ = stream.write_all(b"\n").await;
        let _ = stream.flush().await;
    }
}

fn stop_response(result: RuntimeStopResult) -> ForwardResponse {
    match serde_json::to_string(&serde_json::json!({
        "ok": true,
        "stopped_sessions": result.stopped_sessions,
        "removed_containers": result.removed_containers,
    })) {
        Ok(body) => ForwardResponse {
            status: 200,
            content_type: Some("application/json"),
            body,
        },
        Err(e) => err(500, &format!("encode stop response: {e}")),
    }
}

fn restart_response(result: RuntimeRestartResult) -> ForwardResponse {
    match serde_json::to_string(&serde_json::json!({
        "ok": true,
        "stopped_sessions": result.stopped_sessions,
        "removed_containers": result.removed_containers,
    })) {
        Ok(body) => ForwardResponse {
            status: 200,
            content_type: Some("application/json"),
            body,
        },
        Err(e) => err(500, &format!("encode restart response: {e}")),
    }
}

#[cfg(unix)]
fn set_socket_mode(path: &PathBuf) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dyson-mcp-runtime-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[derive(Default)]
    struct MockDocker {
        server_cleanups: Mutex<Vec<(String, String)>>,
        instance_cleanups: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DockerController for MockDocker {
        fn command(&self) -> &'static str {
            "docker"
        }

        async fn cleanup_server(
            &self,
            instance_id: &str,
            server_name: &str,
        ) -> Result<usize, String> {
            self.server_cleanups
                .lock()
                .await
                .push((instance_id.to_string(), server_name.to_string()));
            Ok(3)
        }

        async fn cleanup_instance(&self, instance_id: &str) -> Result<usize, String> {
            self.instance_cleanups
                .lock()
                .await
                .push(instance_id.to_string());
            Ok(5)
        }
    }

    struct StubSession {
        fingerprint: String,
        shutdowns: Arc<Mutex<usize>>,
    }

    #[async_trait]
    impl McpSession for StubSession {
        async fn send(
            &self,
            _request_json: String,
            _id_key: Option<String>,
        ) -> Result<Option<String>, String> {
            Ok(None)
        }

        async fn shutdown(&self) {
            *self.shutdowns.lock().await += 1;
        }

        fn fingerprint(&self) -> &str {
            &self.fingerprint
        }
    }

    async fn insert_stub_session(
        runtime: &Runtime,
        instance_id: &str,
        server_name: &str,
        shutdowns: Arc<Mutex<usize>>,
    ) {
        runtime.sessions.lock().await.insert(
            session_key(instance_id, server_name),
            Arc::new(RuntimeSession {
                session: Arc::new(StubSession {
                    fingerprint: "stub".into(),
                    shutdowns,
                }),
                last_used: Arc::new(Mutex::new(Instant::now())),
            }),
        );
    }

    #[tokio::test]
    #[ignore = "requires Docker and pulls python:3.12-alpine"]
    async fn forwards_to_tiny_echo_mcp_container() {
        let runtime = Runtime::new(Duration::from_secs(30));
        let script = r#"
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "echo", "version": "0.1.0"},
        }
    elif method == "tools/list":
        result = {"tools": [{"name": "echo", "description": "echo input"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
"#;
        let args = vec![
            "run".to_string(),
            "-i".to_string(),
            "--rm".to_string(),
            "python:3.12-alpine".to_string(),
            "python".to_string(),
            "-u".to_string(),
            "-c".to_string(),
            script.to_string(),
        ];
        let init = ForwardRequest {
            instance_id: "itest".into(),
            server_name: "echo".into(),
            transport: TransportSpec::DockerStdio {
                args: args.clone(),
                env: HashMap::new(),
            },
            request_json: serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            })
            .to_string(),
        };
        let init_resp = runtime.forward(init).await;
        assert_eq!(init_resp.status, 200, "{}", init_resp.body);

        let list = ForwardRequest {
            instance_id: "itest".into(),
            server_name: "echo".into(),
            transport: TransportSpec::DockerStdio {
                args,
                env: HashMap::new(),
            },
            request_json: serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            })
            .to_string(),
        };
        let list_resp = runtime.forward(list).await;
        assert_eq!(list_resp.status, 200, "{}", list_resp.body);
        let body: serde_json::Value = serde_json::from_str(&list_resp.body).unwrap();
        assert_eq!(body["result"]["tools"][0]["name"], "echo");

        runtime.stop_session("itest:echo").await;
    }

    #[tokio::test]
    async fn stop_server_removes_session_and_cleans_docker_labels() {
        let docker = Arc::new(MockDocker::default());
        let runtime = Runtime::with_docker(Duration::from_secs(30), docker.clone());
        let shutdowns = Arc::new(Mutex::new(0usize));
        insert_stub_session(&runtime, "i-1", "brave", shutdowns.clone()).await;

        let result = runtime.stop_server("i-1", "brave").await;

        assert_eq!(result.stopped_sessions, 1);
        assert_eq!(result.removed_containers, 3);
        assert_eq!(*shutdowns.lock().await, 1);
        assert!(runtime.sessions.lock().await.is_empty());
        assert_eq!(
            docker.server_cleanups.lock().await.as_slice(),
            &[("i-1".to_string(), "brave".to_string())]
        );
    }

    #[tokio::test]
    async fn stop_instance_removes_matching_sessions_and_cleans_instance_label() {
        let docker = Arc::new(MockDocker::default());
        let runtime = Runtime::with_docker(Duration::from_secs(30), docker.clone());
        let shutdowns = Arc::new(Mutex::new(0usize));
        insert_stub_session(&runtime, "i-1", "brave", shutdowns.clone()).await;
        insert_stub_session(&runtime, "i-1", "github", shutdowns.clone()).await;
        insert_stub_session(&runtime, "i-2", "brave", shutdowns.clone()).await;

        let result = runtime.stop_instance("i-1").await;

        assert_eq!(result.stopped_sessions, 2);
        assert_eq!(result.removed_containers, 5);
        assert_eq!(*shutdowns.lock().await, 2);
        assert_eq!(runtime.sessions.lock().await.len(), 1);
        assert_eq!(
            docker.instance_cleanups.lock().await.as_slice(),
            &["i-1".to_string()]
        );
    }

    #[tokio::test]
    async fn restart_server_replaces_existing_runtime_session() {
        let docker = Arc::new(MockDocker::default());
        let runtime = Runtime::with_docker(Duration::from_secs(30), docker);
        let shutdowns = Arc::new(Mutex::new(0usize));
        insert_stub_session(&runtime, "i-1", "remote", shutdowns.clone()).await;

        let resp = runtime
            .restart_server(
                "i-1".into(),
                "remote".into(),
                TransportSpec::HttpStreamable {
                    url: "https://mcp.example.test/mcp".into(),
                    headers: BTreeMap::new(),
                    auth_bearer_env: None,
                },
            )
            .await;

        assert_eq!(resp.status, 200, "{}", resp.body);
        assert_eq!(*shutdowns.lock().await, 1);
        let sessions = runtime.sessions.lock().await;
        assert_eq!(sessions.len(), 1);
        assert_ne!(
            sessions
                .get("i-1:remote")
                .expect("session exists")
                .session
                .fingerprint(),
            "stub"
        );
    }

    #[test]
    fn runtime_request_deserializes_tagged_docker_forward() {
        let req: RuntimeRequest = serde_json::from_value(serde_json::json!({
            "op": "forward",
            "instance_id": "i-1",
            "server_name": "echo",
            "transport": {
                "kind": "DockerStdio",
                "args": ["run", "example/mcp"],
                "env": {"B": "2"}
            },
            "request_json": serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string()
        }))
        .unwrap();

        let RuntimeRequest::Forward { transport, .. } = req else {
            panic!("expected forward request");
        };
        assert_eq!(
            transport,
            TransportSpec::DockerStdio {
                args: vec!["run".into(), "example/mcp".into()],
                env: HashMap::from([("B".into(), "2".into())]),
            }
        );
    }

    #[test]
    fn runtime_request_deserializes_tagged_docker_restart() {
        let req: RuntimeRequest = serde_json::from_value(serde_json::json!({
            "op": "restart_server",
            "instance_id": "i-1",
            "server_name": "echo",
            "transport": {
                "kind": "DockerStdio",
                "args": ["run", "example/mcp"],
                "env": {"A": "1"}
            }
        }))
        .unwrap();

        let RuntimeRequest::RestartServer { transport, .. } = req else {
            panic!("expected restart_server request");
        };
        assert_eq!(
            transport,
            TransportSpec::DockerStdio {
                args: vec!["run".into(), "example/mcp".into()],
                env: HashMap::from([("A".into(), "1".into())]),
            }
        );
    }

    #[test]
    fn transport_spec_deserializes_tagged_http() {
        let req: RuntimeRequest = serde_json::from_value(serde_json::json!({
            "op": "forward",
            "instance_id": "i-1",
            "server_name": "remote",
            "transport": {
                "kind": "HttpStreamable",
                "url": "https://mcp.example.test/mcp",
                "headers": {"X-Cluster": "prod"},
                "auth_bearer_env": "MCP_TOKEN"
            },
            "request_json": serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize"}).to_string()
        }))
        .unwrap();

        let RuntimeRequest::Forward { transport, .. } = req else {
            panic!("expected forward request");
        };
        assert_eq!(
            transport,
            TransportSpec::HttpStreamable {
                url: "https://mcp.example.test/mcp".into(),
                headers: BTreeMap::from([("X-Cluster".into(), "prod".into())]),
                auth_bearer_env: Some("MCP_TOKEN".into()),
            }
        );
    }

    #[test]
    fn fingerprint_is_stable_across_env_and_header_ordering() {
        let left = TransportSpec::DockerStdio {
            args: vec!["run".into(), "example/mcp".into()],
            env: HashMap::from([("B".into(), "2".into()), ("A".into(), "1".into())]),
        };
        let right = TransportSpec::DockerStdio {
            args: vec!["run".into(), "example/mcp".into()],
            env: HashMap::from([("A".into(), "1".into()), ("B".into(), "2".into())]),
        };
        assert_eq!(session_fingerprint(&left), session_fingerprint(&right));

        let http_left = TransportSpec::HttpStreamable {
            url: "https://mcp.example.test/mcp".into(),
            headers: BTreeMap::from([("Z".into(), "z".into()), ("A".into(), "a".into())]),
            auth_bearer_env: None,
        };
        let http_right = TransportSpec::HttpStreamable {
            url: "https://mcp.example.test/mcp".into(),
            headers: BTreeMap::from([("A".into(), "a".into()), ("Z".into(), "z".into())]),
            auth_bearer_env: None,
        };
        assert_eq!(
            session_fingerprint(&http_left),
            session_fingerprint(&http_right)
        );
    }

    #[test]
    fn http_streamable_guard_rejects_plaintext_remote_hosts() {
        let err = validate_http_streamable_url("http://example.com/mcp").unwrap_err();
        assert!(err.contains("requires https"));
        validate_http_streamable_url("https://example.com/mcp").unwrap();
        validate_http_streamable_url("http://127.0.0.1:9000/mcp").unwrap();
    }

    #[test]
    fn http_streamable_sse_parser_picks_matching_response() {
        let sse = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n";
        let value = parse_sse_jsonrpc_response(sse, Some("2")).unwrap();
        assert_eq!(value["id"], 2);
        assert!(value["result"]["tools"].is_array());
    }

    #[test]
    fn docker_run_args_forces_bridge_network_and_strips_user_network_flags() {
        let args = vec![
            "run".to_string(),
            "--network=bridge".to_string(),
            "--net".to_string(),
            "bridge".to_string(),
            "example/mcp".to_string(),
        ];
        let out = docker_run_args(&args, "i-1", "stdio");
        assert!(out.windows(2).any(|w| w == ["--network", "bridge"]));
        assert_eq!(
            out.iter().filter(|arg| arg.as_str() == "--network").count(),
            1
        );
        assert!(!out.iter().any(|arg| arg == "--network=bridge"));
        assert!(!out.iter().any(|arg| arg == "--net"));
        assert!(out.iter().any(|arg| arg == "example/mcp"));
    }

    #[test]
    fn docker_run_args_mounts_env_values_as_secret_files() {
        let args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "-e".to_string(),
            "MASSIVE_API_KEY=secret-one".to_string(),
            "--env=OTHER_TOKEN=secret-two".to_string(),
            "-eTHIRD_TOKEN=secret-three".to_string(),
            "--entrypoint".to_string(),
            "python".to_string(),
            "example/mcp".to_string(),
            "./entrypoint.py".to_string(),
        ];
        let secret_root = test_secret_root("docker-env-files");
        let launch = docker_run_launch(
            &args,
            &HashMap::from([("ENV_MAP_TOKEN".to_string(), "secret-four".to_string())]),
            "i-1",
            "stdio",
            &secret_root,
            "docker",
        )
        .unwrap();
        let secret_dir = launch.secret_dir.as_ref().expect("secret dir");
        let joined = launch.args.join(" ");

        for value in ["secret-one", "secret-two", "secret-three", "secret-four"] {
            assert!(!joined.contains(value));
        }
        assert!(
            launch
                .args
                .windows(2)
                .any(|w| { w == ["--entrypoint", SECRET_ENTRYPOINT_SHELL] })
        );
        for name in [
            "ENV_MAP_TOKEN",
            "MASSIVE_API_KEY",
            "OTHER_TOKEN",
            "THIRD_TOKEN",
        ] {
            let expected_file_env = format!("{name}_FILE={CONTAINER_SECRET_DIR}/{name}");
            assert!(
                launch
                    .args
                    .windows(2)
                    .any(|w| w[0] == "--env" && w[1] == expected_file_env)
            );
            assert!(
                launch
                    .args
                    .iter()
                    .any(|arg| { arg.contains(&format!("dst={CONTAINER_SECRET_DIR}/{name}")) })
            );
        }
        assert_eq!(
            std::fs::read_to_string(secret_dir.join("MASSIVE_API_KEY")).unwrap(),
            "secret-one"
        );
        assert_eq!(
            std::fs::read_to_string(secret_dir.join("ENV_MAP_TOKEN")).unwrap(),
            "secret-four"
        );
        let image_index = launch
            .args
            .iter()
            .position(|arg| arg == "example/mcp")
            .expect("image arg");
        assert_eq!(
            &launch.args[image_index + 1..],
            [
                SECRET_ENTRYPOINT_CONTAINER_PATH,
                "python",
                "./entrypoint.py"
            ]
        );

        cleanup_secret_dir_sync(launch.secret_dir.as_deref());
        let _ = std::fs::remove_dir_all(secret_root);
    }

    #[tokio::test]
    async fn http_streamable_session_round_trips_json_responses() {
        use axum::extract::State;
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::IntoResponse;
        use axum::routing::post;
        use axum::{Json, Router};

        #[derive(Clone)]
        struct MockState {
            seen_sessions: Arc<Mutex<Vec<Option<String>>>>,
        }

        async fn handler(
            State(state): State<MockState>,
            headers: HeaderMap,
            Json(body): Json<serde_json::Value>,
        ) -> impl IntoResponse {
            let seen = headers
                .get("Mcp-Session-Id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            state.seen_sessions.lock().await.push(seen);
            match body.get("method").and_then(serde_json::Value::as_str) {
                Some("initialize") => (
                    StatusCode::OK,
                    [("Mcp-Session-Id", "sid-test")],
                    Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": body["id"].clone(),
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "mock", "version": "0.1.0"}
                        }
                    })),
                )
                    .into_response(),
                Some("tools/list") => Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": body["id"].clone(),
                    "result": {"tools": [{"name": "remote_echo"}]}
                }))
                .into_response(),
                _ => StatusCode::ACCEPTED.into_response(),
            }
        }

        let state = MockState {
            seen_sessions: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route("/mcp", post(handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let transport = TransportSpec::HttpStreamable {
            url: format!("http://{addr}/mcp"),
            headers: BTreeMap::new(),
            auth_bearer_env: None,
        };
        validate_transport(&transport).unwrap();
        let session = HttpStreamableSession::new(
            format!("http://{addr}/mcp"),
            BTreeMap::new(),
            None,
            session_fingerprint(&transport),
        )
        .unwrap();

        let init = session
            .send(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {}
                })
                .to_string(),
                Some("1".into()),
            )
            .await
            .unwrap()
            .unwrap();
        let init_body: serde_json::Value = serde_json::from_str(&init).unwrap();
        assert_eq!(init_body["result"]["serverInfo"]["name"], "mock");

        let list = session
            .send(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {}
                })
                .to_string(),
                Some("2".into()),
            )
            .await
            .unwrap()
            .unwrap();
        let list_body: serde_json::Value = serde_json::from_str(&list).unwrap();
        assert_eq!(list_body["result"]["tools"][0]["name"], "remote_echo");

        let seen = state.seen_sessions.lock().await.clone();
        assert_eq!(seen, vec![None, Some("sid-test".into())]);
        session.shutdown().await;
        server.abort();
    }
}
