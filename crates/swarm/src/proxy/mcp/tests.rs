use super::*;
use crate::db::open_in_memory;
use crate::db::secrets::SqlxUserSecretStore;
use crate::envelope::AgeCipherDirectory;

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
        &args,
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
    restart_runtime_server(Some(&socket), "i-1", "brave", &entry)
        .await
        .unwrap();
    server.await.unwrap();
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
