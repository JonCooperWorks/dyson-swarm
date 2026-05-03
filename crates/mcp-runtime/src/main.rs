use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

#[derive(Debug, Parser)]
#[command(name = "dyson-mcp-runtime")]
struct Args {
    /// Unix socket swarm uses to ask the helper to proxy one JSON-RPC message.
    #[arg(long, default_value = "/run/dyson-mcp-runtime/runtime.sock")]
    socket: PathBuf,
    /// Idle stdio sessions are stopped after this many seconds.
    #[arg(long, default_value_t = 600)]
    idle_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct ForwardRequest {
    instance_id: String,
    server_name: String,
    command: String,
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    request_json: String,
}

#[derive(Debug, Serialize)]
struct ForwardResponse {
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<&'static str>,
    body: String,
}

struct Runtime {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    spawn_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    idle_after: Duration,
}

struct Session {
    fingerprint: String,
    stdin: Arc<Mutex<ChildStdin>>,
    send_lock: Mutex<()>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>,
    child: Arc<Mutex<Child>>,
    reader: JoinHandle<()>,
    last_used: Arc<Mutex<Instant>>,
}

impl Runtime {
    fn new(idle_after: Duration) -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            spawn_locks: Mutex::new(HashMap::new()),
            idle_after,
        })
    }

    async fn forward(&self, req: ForwardRequest) -> ForwardResponse {
        if req.command != "docker" {
            return err(400, "only `command: \"docker\"` is supported");
        }
        if let Err(e) = dyson_swarm_core::mcp_servers::validate_docker_stdio_args(&req.args) {
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
        let session_key = format!("{}:{}", req.instance_id, req.server_name);

        if method == "initialize" {
            self.stop_session(&session_key).await;
        }
        let session = match self.get_or_spawn(&session_key, &req).await {
            Ok(s) => s,
            Err(e) => return err(502, &e),
        };
        *session.last_used.lock().await = Instant::now();

        let response = session.send(req.request_json, id_key).await;
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

    async fn get_or_spawn(&self, key: &str, req: &ForwardRequest) -> Result<Arc<Session>, String> {
        let wanted = session_fingerprint(req);
        if let Some(existing) = self.sessions.lock().await.get(key).cloned() {
            if existing.fingerprint == wanted {
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
                if existing.fingerprint == wanted {
                    return Ok(existing);
                }
                sessions.remove(key)
            } else {
                None
            }
        };
        if let Some(session) = stale {
            session.reader.abort();
            let _ = session.child.lock().await.start_kill();
        }
        let session = Arc::new(Session::spawn(req, wanted).await?);
        self.sessions
            .lock()
            .await
            .insert(key.to_string(), Arc::clone(&session));
        Ok(session)
    }

    async fn stop_session(&self, key: &str) {
        let Some(session) = self.sessions.lock().await.remove(key) else {
            return;
        };
        session.reader.abort();
        let _ = session.child.lock().await.start_kill();
    }

    async fn reap_idle(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let snapshot: Vec<(String, Arc<Session>)> = self
                .sessions
                .lock()
                .await
                .iter()
                .map(|(k, v)| (k.clone(), Arc::clone(v)))
                .collect();
            for (key, session) in snapshot {
                if session.last_used.lock().await.elapsed() >= self.idle_after {
                    tracing::debug!(session = %key, "reaping idle MCP runtime session");
                    self.stop_session(&key).await;
                }
            }
        }
    }
}

impl Session {
    async fn spawn(req: &ForwardRequest, fingerprint: String) -> Result<Self, String> {
        let args = docker_run_args(&req.args, &req.instance_id, &req.server_name);
        let mut child = Command::new("docker")
            .args(args)
            .envs(&req.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn docker: {e}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or("docker child stdin was not piped")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("docker child stdout was not piped")?;
        let pending: Arc<Mutex<HashMap<String, oneshot::Sender<String>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_reader = Arc::clone(&pending);
        let server_name = req.server_name.clone();
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
            last_used: Arc::new(Mutex::new(Instant::now())),
        })
    }

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
}

fn session_fingerprint(req: &ForwardRequest) -> String {
    let env: BTreeMap<&String, &String> = req.env.iter().collect();
    serde_json::json!({
        "command": &req.command,
        "args": &req.args,
        "env": env,
    })
    .to_string()
}

async fn remove_pending(
    pending: &Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>,
    id: Option<&str>,
) {
    if let Some(id) = id {
        pending.lock().await.remove(id);
    }
}

fn docker_run_args(user_args: &[String], instance_id: &str, server_name: &str) -> Vec<String> {
    let mut out = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-i".to_string(),
        "--cap-drop=ALL".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "--memory=512m".to_string(),
        "--cpus=1".to_string(),
        "--pids-limit=256".to_string(),
        "--label".to_string(),
        format!("dyson.mcp.instance={instance_id}"),
        "--label".to_string(),
        format!("dyson.mcp.server={server_name}"),
    ];
    out.extend(user_args.iter().skip(1).cloned());
    out
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
    let runtime = Runtime::new(Duration::from_secs(args.idle_seconds));
    tokio::spawn(Arc::clone(&runtime).reap_idle());
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
        Ok(_) => match serde_json::from_str::<ForwardRequest>(&line) {
            Ok(req) => runtime.forward(req).await,
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

#[cfg(unix)]
fn set_socket_mode(path: &PathBuf) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            command: "docker".into(),
            args: args.clone(),
            env: HashMap::new(),
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
            command: "docker".into(),
            args,
            env: HashMap::new(),
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
}
