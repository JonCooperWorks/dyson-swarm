use super::*;
use crate::db::sqlite::instances::SqlxInstanceStore;
use crate::db::sqlite::open_in_memory;
use crate::db::sqlite::secrets::SqlxUserSecretStore;
use crate::db::sqlite::tokens::SqlxTokenStore;
use crate::envelope::AgeCipherDirectory;
use crate::envelope::{EnvelopeCipher, EnvelopeError};
use crate::traits::{InstanceRow, InstanceStatus, InstanceStore, TokenStore};
use axum::body::Bytes;
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicU32, Ordering};

#[test]
fn strip_url_query_drops_query_and_fragment() {
    assert_eq!(
        strip_url_query("https://mcp.alphavantage.co/mcp?apikey=AABBCC"),
        "https://mcp.alphavantage.co/mcp"
    );
    assert_eq!(
        strip_url_query("https://example.com/path#frag"),
        "https://example.com/path"
    );
    assert_eq!(
        strip_url_query("https://example.com/path?k=v#frag"),
        "https://example.com/path"
    );
}

#[test]
fn strip_url_query_passes_through_clean_url() {
    let clean = "https://mcp.context7.com/mcp";
    assert_eq!(strip_url_query(clean), clean);
}

#[test]
fn safe_local_return_path_allows_only_local_absolute_paths() {
    for good in ["/", "/instances/i-1/mcp", "/path?x=1", "/path#fragment"] {
        assert_eq!(safe_local_return_path(good), Some(good));
    }
    for bad in [
        "",
        " ",
        " /path",
        "/path ",
        "//evil.example/path",
        "https://evil.example/path",
        "http://evil.example/path",
        "\\\\evil.example\\path",
        "/\\evil.example\\path",
        "/path\\evil",
        "relative/path",
    ] {
        assert_eq!(safe_local_return_path(bad), None, "{bad:?}");
    }
}

#[test]
fn peek_jsonrpc_extracts_method_id_params() {
    let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"foo"}}"#;
    let (m, id, p) = peek_jsonrpc(body).expect("parses");
    assert_eq!(m, "tools/call");
    assert_eq!(id, serde_json::json!(7));
    assert_eq!(p["name"], "foo");
}

#[test]
fn peek_jsonrpc_returns_none_for_batches_and_garbage() {
    // Batched JSON-RPC: array root.  Pass through unfiltered.
    assert!(peek_jsonrpc(b"[]").is_none());
    // Non-JSON.
    assert!(peek_jsonrpc(b"not json").is_none());
    // Object without method (a JSON-RPC response, not request).
    assert!(peek_jsonrpc(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).is_none());
}

#[test]
fn filter_tools_list_keeps_only_allowed() {
    let body = br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[
        {"name":"a","description":"x"},
        {"name":"b"},
        {"name":"c","description":"z"}
    ]}}"#;
    let allowed = vec!["a".to_string(), "c".to_string()];
    let out = filter_tools_list_body(body, &allowed).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["a", "c"]);
}

#[test]
fn filter_tools_list_empties_when_nothing_allowed() {
    let body = br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}]}}"#;
    let out = filter_tools_list_body(body, &[]).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(v["result"]["tools"].as_array().unwrap().is_empty());
}

#[test]
fn filter_tools_list_errors_on_unexpected_shape() {
    // No result.tools — caller should fall back to passing the
    // upstream body through unchanged rather than rewriting it.
    let body = br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601}}"#;
    assert!(filter_tools_list_body(body, &["a".into()]).is_err());
}

#[tokio::test]
async fn call_runtime_round_trips_fake_helper() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("runtime.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(req["op"], "forward");
        assert_eq!(req["instance_id"], "i-1");
        assert_eq!(req["server_name"], "echo");
        assert_eq!(req["transport"]["kind"], "DockerStdio");
        assert_eq!(req["transport"]["runtime"], "runsc");
        assert!(req.get("command").is_none());
        assert!(req["transport"].get("command").is_none());
        let resp = serde_json::json!({
            "status": 200,
            "content_type": "application/json",
            "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}"
        });
        let mut stream = reader.into_inner();
        stream
            .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
            .await
            .unwrap();
        stream.write_all(b"\n").await.unwrap();
    });

    let args = vec!["run".to_string(), "example/mcp".to_string()];
    let env = std::collections::HashMap::new();
    let req = RuntimeRequest::forward_docker(
        "i-1",
        "echo",
        "runsc",
        args.clone(),
        &env,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    );
    let resp = call_runtime(&socket, &req).await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("\"ok\":true"));
    server.await.unwrap();
}

#[tokio::test]
async fn stop_runtime_server_sends_runtime_cleanup_op() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("runtime.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(req["op"], "stop_server");
        assert_eq!(req["instance_id"], "i-1");
        assert_eq!(req["server_name"], "brave");
        let resp = serde_json::json!({
            "status": 200,
            "content_type": "application/json",
            "body": "{\"ok\":true,\"stopped_sessions\":1,\"removed_containers\":1}"
        });
        let mut stream = reader.into_inner();
        stream
            .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
            .await
            .unwrap();
        stream.write_all(b"\n").await.unwrap();
    });

    stop_runtime_server(Some(&socket), "i-1", "brave")
        .await
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn restart_runtime_server_sends_runtime_restart_op() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("runtime.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(req["op"], "restart_server");
        assert_eq!(req["instance_id"], "i-1");
        assert_eq!(req["server_name"], "brave");
        assert_eq!(req["transport"]["kind"], "DockerStdio");
        assert_eq!(req["transport"]["runtime"], "runsc");
        assert!(req["transport"].get("command").is_none());
        let resp = serde_json::json!({
            "status": 200,
            "content_type": "application/json",
            "body": "{\"ok\":true,\"stopped_sessions\":1,\"removed_containers\":1}"
        });
        let mut stream = reader.into_inner();
        stream
            .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
            .await
            .unwrap();
        stream.write_all(b"\n").await.unwrap();
    });

    let entry = McpServerEntry {
        url: "docker://example/mcp".into(),
        auth: McpAuthSpec::None,
        headers: std::collections::HashMap::new(),
        runtime: Some(McpRuntimeSpec::DockerStdio {
            command: "docker".into(),
            args: vec!["run".into(), "example/mcp".into()],
            env: std::collections::HashMap::new(),
        }),
        docker_catalog: None,
        raw_vscode_config: None,
        oauth_tokens: None,
        tools_catalog: None,
        last_check_error: None,
        enabled_tools: None,
    };
    restart_runtime_server(Some(&socket), "runsc", "i-1", "brave", &entry)
        .await
        .unwrap();
    server.await.unwrap();
}

#[test]
fn runtime_request_strips_user_runtime_before_helper() {
    let entry = McpServerEntry {
        url: "docker://example/mcp".into(),
        auth: McpAuthSpec::None,
        headers: std::collections::HashMap::new(),
        runtime: Some(McpRuntimeSpec::DockerStdio {
            command: "docker".into(),
            args: vec![
                "run".into(),
                "--runtime".into(),
                "runc".into(),
                "--runtime=crun".into(),
                "example/mcp".into(),
            ],
            env: std::collections::HashMap::new(),
        }),
        docker_catalog: None,
        raw_vscode_config: None,
        oauth_tokens: None,
        tools_catalog: None,
        last_check_error: None,
        enabled_tools: None,
    };
    let req = runtime_forward_request_for_entry(
        "runsc",
        "i-1",
        "stdio",
        &entry,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    )
    .unwrap();
    let value = serde_json::to_value(req).unwrap();
    assert_eq!(value["transport"]["runtime"], "runsc");
    assert_eq!(
        value["transport"]["args"],
        serde_json::json!(["run", "example/mcp"])
    );
}

#[test]
fn parse_sse_jsonrpc_picks_first_response_event() {
    // Two events: a server-side "ping" (no jsonrpc.result/error)
    // followed by the actual response.  Parser must skip the first.
    let sse = b"event: ping\ndata: {\"hello\":1}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n";
    let v = parse_sse_jsonrpc(sse).unwrap();
    assert_eq!(v["id"], 2);
    assert!(v["result"]["tools"].is_array());
}

#[test]
fn parse_sse_jsonrpc_handles_multi_line_data() {
    // SSE allows multiple `data:` lines per event; they concatenate
    // with newlines.  Make sure the parser glues them correctly.
    let sse = b"data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":2,\"result\":{}}\n\n";
    let v = parse_sse_jsonrpc(sse).unwrap();
    assert_eq!(v["id"], 2);
}

#[test]
fn strip_url_query_handles_fragment_before_query() {
    // RFC violators that put `#` before `?` — strip at the earliest
    // delimiter so we never accidentally render past it.
    assert_eq!(
        strip_url_query("https://example.com/path#frag?secret=x"),
        "https://example.com/path"
    );
}

async fn seeded_user_secrets() -> (tempfile::TempDir, Arc<UserSecretsService>) {
    let pool = open_in_memory().await.unwrap();
    // Seed a user row so the FK on user_secrets resolves.
    sqlx::query("INSERT INTO users (id, subject, status, created_at) VALUES (?, ?, 'active', ?)")
        .bind("u1")
        .bind("u1")
        .bind(0i64)
        .execute(&pool)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dir: Arc<dyn crate::envelope::CipherDirectory> =
        Arc::new(AgeCipherDirectory::new(tmp.path()).unwrap());
    let store: Arc<dyn crate::traits::UserSecretStore> = Arc::new(SqlxUserSecretStore::new(pool));
    (tmp, Arc::new(UserSecretsService::new(store, dir)))
}

#[tokio::test]
async fn oauth_flow_cache_round_trip() {
    let (_tmp, _svc) = seeded_user_secrets().await;
    let cache = OAuthFlowCache::new();
    cache.insert(
        "s".into(),
        PendingFlow {
            owner_id: "u1".into(),
            instance_id: "i".into(),
            server_name: "srv".into(),
            pkce_verifier: "v".into(),
            redirect_uri: "https://swarm/mcp/oauth/callback".into(),
            token_url: "https://up/token".into(),
            client_id: "c".into(),
            client_secret: None,
            expires_at: i64::MAX,
            return_to: None,
        },
    );
    let f = cache.take("s").unwrap();
    assert_eq!(f.client_id, "c");
    assert!(cache.take("s").is_none());
}

#[test]
fn html_escape_handles_specials() {
    assert_eq!(html_escape("<a>\"&"), "&lt;a&gt;&quot;&amp;");
}

#[test]
fn hop_by_hop_filters_known_set() {
    assert!(is_hop_by_hop("Connection"));
    assert!(is_hop_by_hop("transfer-encoding"));
    assert!(!is_hop_by_hop("content-type"));
}

#[derive(Debug)]
struct TestCipher;

impl EnvelopeCipher for TestCipher {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let mut out = b"sealed:".to_vec();
        out.extend_from_slice(plaintext);
        Ok(out)
    }

    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        ciphertext
            .strip_prefix(b"sealed:")
            .map(|s| s.to_vec())
            .ok_or(EnvelopeError::Corrupt)
    }
}

fn system_cipher() -> Arc<dyn EnvelopeCipher> {
    Arc::new(TestCipher)
}

const MCP_TEST_OWNER: &str = "00000000000000000000000000000002";
const MCP_TEST_INSTANCE: &str = "i-mcp-audit";
const MCP_TEST_SERVER: &str = "linear";

fn test_caller(user_id: &str) -> CallerIdentity {
    CallerIdentity {
        user_id: user_id.to_owned(),
        identity: crate::auth::UserIdentity {
            subject: user_id.to_owned(),
            email: None,
            display_name: None,
            source: crate::auth::AuthSource::Bearer,
            claims: serde_json::Value::Null,
        },
    }
}

async fn create_test_mcp_audit_table(pool: &SqlitePool) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS mcp_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT NOT NULL,
            instance_id TEXT NOT NULL,
            server_name TEXT NOT NULL,
            tool TEXT,
            status INTEGER NOT NULL,
            duration_ms INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn spawn_mcp_upstream() -> (String, Arc<AtomicU32>) {
    async fn handler(
        axum::extract::State(calls): axum::extract::State<Arc<AtomicU32>>,
        _body: Bytes,
    ) -> Response<Body> {
        calls.fetch_add(1, Ordering::SeqCst);
        Response::builder()
            .status(StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}"#,
            ))
            .unwrap()
    }

    let calls = Arc::new(AtomicU32::new(0));
    let app = axum::Router::new()
        .route("/", axum::routing::post(handler))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/"), calls)
}

async fn build_mcp_proxy_fixture(
    pool: SqlitePool,
    upstream_url: String,
) -> (Arc<McpService>, String, tempfile::TempDir) {
    let entry = McpServerEntry {
        url: upstream_url,
        auth: McpAuthSpec::None,
        headers: std::collections::HashMap::new(),
        runtime: None,
        docker_catalog: None,
        raw_vscode_config: None,
        oauth_tokens: None,
        tools_catalog: None,
        last_check_error: None,
        enabled_tools: None,
    };
    build_mcp_proxy_fixture_for_entry(pool, entry, None).await
}

async fn build_mcp_proxy_fixture_for_entry(
    pool: SqlitePool,
    entry: McpServerEntry,
    runtime_socket_path: Option<std::path::PathBuf>,
) -> (Arc<McpService>, String, tempfile::TempDir) {
    sqlx::query(
        "INSERT OR IGNORE INTO users (id, subject, status, created_at) \
         VALUES (?, ?, 'active', 0)",
    )
    .bind(MCP_TEST_OWNER)
    .bind("subject-mcp-audit")
    .execute(&pool)
    .await
    .unwrap();

    let instances = Arc::new(SqlxInstanceStore::new(pool.clone(), system_cipher()));
    instances
        .create(InstanceRow {
            id: MCP_TEST_INSTANCE.into(),
            owner_id: MCP_TEST_OWNER.into(),
            name: String::new(),
            task: String::new(),
            cube_sandbox_id: Some("sb-mcp".into()),
            state_generation: String::new(),
            template_id: "template".into(),
            status: InstanceStatus::Live,
            bearer_token: "instance-bearer".into(),
            pinned: false,
            expires_at: None,
            last_active_at: 0,
            last_probe_at: None,
            last_probe_status: None,
            created_at: 0,
            destroyed_at: None,
            rotated_to: None,
            network_policy: crate::network_policy::NetworkPolicy::Open,
            network_policy_cidrs: Vec::new(),
            models: Vec::new(),
            tools: Vec::new(),
        })
        .await
        .unwrap();

    let tokens = Arc::new(SqlxTokenStore::new(pool.clone(), system_cipher()));
    let token = tokens.mint(MCP_TEST_INSTANCE, "*").await.unwrap();

    let keys_tmp = tempfile::tempdir().unwrap();
    let cipher_dir: Arc<dyn crate::envelope::CipherDirectory> =
        Arc::new(AgeCipherDirectory::new(keys_tmp.path()).unwrap());
    let user_secret_store: Arc<dyn crate::traits::UserSecretStore> =
        Arc::new(SqlxUserSecretStore::new(pool.clone()));
    let user_secrets = Arc::new(UserSecretsService::new(user_secret_store, cipher_dir));
    mcp_servers::put(
        &user_secrets,
        MCP_TEST_OWNER,
        MCP_TEST_INSTANCE,
        MCP_TEST_SERVER,
        &entry,
    )
    .await
    .unwrap();

    let svc = McpService::new(tokens, instances, user_secrets, None)
        .unwrap()
        .with_runtime_socket(runtime_socket_path)
        .with_mcp_audit(Arc::new(
            crate::db::sqlite::audit::SqliteMcpAuditStore::new(pool.clone()),
        ))
        .with_mcp_upstream_policy(crate::upstream_policy::OutboundUrlPolicy {
            enabled: true,
            allow_localhost: true,
            allow_internal: true,
        });
    (Arc::new(svc), token, keys_tmp)
}

async fn spawn_mcp_proxy(svc: Arc<McpService>) -> String {
    let app = router(svc);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn tools_call_forward_writes_mcp_audit_row() {
    let pool = open_in_memory().await.unwrap();
    create_test_mcp_audit_table(&pool).await;
    let (upstream_url, _calls) = spawn_mcp_upstream().await;
    let (svc, token, _keys) = build_mcp_proxy_fixture(pool.clone(), upstream_url).await;
    let base = spawn_mcp_proxy(svc).await;

    let client = dyson_swarm_core::http::InternalHttpClient::new().unwrap();
    let resp = client
        .post(format!("{base}/mcp/{MCP_TEST_INSTANCE}/{MCP_TEST_SERVER}"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {}}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let row = sqlx::query(
        "SELECT owner_id, server_name, tool, status, ts \
         FROM mcp_audit ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .unwrap()
    .expect("MCP tools/call forward must write an mcp_audit row");
    let owner_id: String = sqlx::Row::try_get(&row, "owner_id").unwrap();
    let server_name: String = sqlx::Row::try_get(&row, "server_name").unwrap();
    let tool: String = sqlx::Row::try_get(&row, "tool").unwrap();
    let status: i64 = sqlx::Row::try_get(&row, "status").unwrap();
    let ts: i64 = sqlx::Row::try_get(&row, "ts").unwrap();
    assert_eq!(owner_id, MCP_TEST_OWNER, "mcp_audit owner_id mismatch");
    assert_eq!(
        server_name, MCP_TEST_SERVER,
        "mcp_audit server_name mismatch"
    );
    assert_eq!(tool, "search", "mcp_audit tool name mismatch");
    assert_eq!(status, 200, "mcp_audit status mismatch");
    assert!(ts > 0, "mcp_audit timestamp must be populated");
}

#[tokio::test]
async fn tools_call_forward_is_rate_limited_per_owner_and_server() {
    let pool = open_in_memory().await.unwrap();
    create_test_mcp_audit_table(&pool).await;
    let (upstream_url, calls) = spawn_mcp_upstream().await;
    let (svc, token, _keys) = build_mcp_proxy_fixture(pool, upstream_url).await;
    let base = spawn_mcp_proxy(svc).await;
    let client = dyson_swarm_core::http::InternalHttpClient::new().unwrap();

    let mut saw_429 = false;
    for _ in 0..64 {
        let resp = client
            .post(format!("{base}/mcp/{MCP_TEST_INSTANCE}/{MCP_TEST_SERVER}"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search", "arguments": {}}
            }))
            .send()
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }

    assert!(
        saw_429,
        "MCP tools/call forward must rate-limit per owner/server before line-speed upstream drain"
    );
    assert!(
        calls.load(Ordering::SeqCst) < 64,
        "MCP rate limit must refuse excess calls before forwarding upstream"
    );
}

#[tokio::test]
async fn forward_rejects_non_live_instances_before_forwarding() {
    for blocked_status in [
        InstanceStatus::Paused,
        InstanceStatus::Configuring,
        InstanceStatus::Destroyed,
    ] {
        let pool = open_in_memory().await.unwrap();
        create_test_mcp_audit_table(&pool).await;
        let (upstream_url, calls) = spawn_mcp_upstream().await;
        let (svc, token, _keys) = build_mcp_proxy_fixture(pool, upstream_url).await;
        svc.instances
            .update_status(MCP_TEST_INSTANCE, blocked_status)
            .await
            .unwrap();
        let base = spawn_mcp_proxy(svc).await;

        let client = dyson_swarm_core::http::InternalHttpClient::new().unwrap();
        let resp = client
            .post(format!("{base}/mcp/{MCP_TEST_INSTANCE}/{MCP_TEST_SERVER}"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search", "arguments": {}}
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{blocked_status:?}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "non-live instances must be rejected before forwarding"
        );
    }
}

#[tokio::test]
async fn forward_rejects_oversized_request_body_before_forwarding() {
    let pool = open_in_memory().await.unwrap();
    create_test_mcp_audit_table(&pool).await;
    let (upstream_url, calls) = spawn_mcp_upstream().await;
    let (svc, token, _keys) = build_mcp_proxy_fixture(pool, upstream_url).await;
    let base = spawn_mcp_proxy(svc).await;

    let client = dyson_swarm_core::http::InternalHttpClient::new().unwrap();
    let resp = client
        .post(format!("{base}/mcp/{MCP_TEST_INSTANCE}/{MCP_TEST_SERVER}"))
        .bearer_auth(token)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(vec![b' '; MAX_RUNTIME_BODY_BYTES + 1])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "oversized request bodies must not be forwarded"
    );
}

#[tokio::test]
async fn docker_catalog_put_rejects_cross_owner_before_management_mutation() {
    let pool = open_in_memory().await.unwrap();
    let runtime_tmp = tempfile::tempdir().unwrap();
    let entry = McpServerEntry {
        url: "https://example.test/mcp".into(),
        auth: McpAuthSpec::None,
        headers: std::collections::HashMap::new(),
        runtime: None,
        docker_catalog: None,
        raw_vscode_config: None,
        oauth_tokens: None,
        tools_catalog: None,
        last_check_error: None,
        enabled_tools: None,
    };
    let (svc, _token, _keys) = build_mcp_proxy_fixture_for_entry(
        pool,
        entry,
        Some(runtime_tmp.path().join("runtime.sock")),
    )
    .await;
    let svc = match Arc::try_unwrap(svc) {
        Ok(svc) => svc.with_docker_catalog(
            vec![mcp_servers::McpDockerCatalogServer {
                id: "github".into(),
                label: "GitHub".into(),
                description: None,
                template: serde_json::json!({
                    "mcpServers": {
                        "github": {
                            "command": "docker",
                            "args": ["run", "--rm", "-i", "ghcr.io/example/github-mcp"]
                        }
                    }
                })
                .to_string(),
                placeholders: Vec::new(),
            }],
            false,
        ),
        Err(_) => panic!("fixture service should have one strong ref"),
    };

    let resp = put_docker_catalog_server(
        State(Arc::new(svc)),
        Path((MCP_TEST_INSTANCE.to_owned(), "github".to_owned())),
        axum::Extension(test_caller("00000000000000000000000000000003")),
        Json(PutDockerCatalogBody {
            placeholders: std::collections::BTreeMap::new(),
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("no such instance")
    );
}

fn spawn_oversized_runtime_helper() -> (tempfile::TempDir, std::path::PathBuf) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    const OVERSIZED_BODY_BYTES: usize = 32 * 1024 * 1024;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("runtime.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut request = String::new();
        reader.read_line(&mut request).await.unwrap();
        let mut stream = reader.into_inner();
        stream
            .write_all(
                br#"{"status":200,"content_type":"application/json","body":"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"payload\":\""#,
            )
            .await
            .unwrap();
        let chunk = vec![b'a'; 1024 * 1024];
        for _ in 0..(OVERSIZED_BODY_BYTES / chunk.len()) {
            stream.write_all(&chunk).await.unwrap();
        }
        stream.write_all(br#"\"}}"}"#).await.unwrap();
        stream.write_all(b"\n").await.unwrap();
        stream.flush().await.unwrap();
    });
    (tmp, socket)
}

#[tokio::test]
async fn runtime_forward_rejects_oversized_single_line_response() {
    let pool = open_in_memory().await.unwrap();
    create_test_mcp_audit_table(&pool).await;
    let (_runtime_tmp, socket) = spawn_oversized_runtime_helper();
    let entry = McpServerEntry {
        url: "docker://example/mcp".into(),
        auth: McpAuthSpec::None,
        headers: std::collections::HashMap::new(),
        runtime: Some(McpRuntimeSpec::DockerStdio {
            command: "docker".into(),
            args: vec!["run".into(), "example/mcp".into()],
            env: std::collections::HashMap::new(),
        }),
        docker_catalog: None,
        raw_vscode_config: None,
        oauth_tokens: None,
        tools_catalog: None,
        last_check_error: None,
        enabled_tools: None,
    };
    let (svc, token, _keys) = build_mcp_proxy_fixture_for_entry(pool, entry, Some(socket)).await;
    let base = spawn_mcp_proxy(svc).await;

    let client = dyson_swarm_core::http::InternalHttpClient::new().unwrap();
    let resp = client
        .post(format!("{base}/mcp/{MCP_TEST_INSTANCE}/{MCP_TEST_SERVER}"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {}}
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.bytes().await.unwrap();

    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "oversized MCP runtime response must be refused with 502"
    );
    assert!(
        body.len() < 1024 * 1024,
        "oversized MCP runtime response must not be forwarded as a full client body"
    );
}
