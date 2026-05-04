use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use tokio::sync::Mutex;

#[derive(Debug, Parser)]
#[command(name = "smoke-mcp-mock")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: String,
}

#[derive(Clone)]
struct AppState {
    session_id: Arc<Mutex<Option<String>>>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let listener = match tokio::net::TcpListener::bind(&args.bind).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, bind = %args.bind, "bind failed");
            return std::process::ExitCode::from(2);
        }
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::error!(error = %err, "local_addr failed");
            return std::process::ExitCode::from(2);
        }
    };
    let app = Router::new()
        .route("/mcp", post(handle_mcp))
        .with_state(AppState {
            session_id: Arc::new(Mutex::new(None)),
        });
    tracing::info!(%addr, "smoke MCP mock listening");
    println!("{addr}");
    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(error = %err, "serve failed");
        return std::process::ExitCode::from(2);
    }
    std::process::ExitCode::SUCCESS
}

async fn handle_mcp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let incoming_session = headers
        .get("Mcp-Session-Id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let method = body
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    match method {
        "initialize" => {
            let session_id = format!(
                "smoke-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            );
            *state.session_id.lock().await = Some(session_id.clone());
            tracing::info!(method, mcp_session_id = %session_id, "mock initialize");
            (
                StatusCode::OK,
                [("Mcp-Session-Id", session_id)],
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": body.get("id").cloned().unwrap_or(serde_json::Value::Null),
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "smoke-mcp-mock", "version": "0.1.0"}
                    }
                })),
            )
                .into_response()
        }
        "tools/list" => {
            let expected = state.session_id.lock().await.clone();
            tracing::info!(
                method,
                mcp_session_id = incoming_session.as_deref().unwrap_or(""),
                reused = incoming_session.is_some() && incoming_session == expected,
                "mock tools/list"
            );
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": body.get("id").cloned().unwrap_or(serde_json::Value::Null),
                "result": {
                    "tools": [
                        {"name": "smoke_tool", "description": "runtime smoke tool"}
                    ]
                }
            }))
            .into_response()
        }
        "notifications/initialized" => StatusCode::ACCEPTED.into_response(),
        _ => Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": body.get("id").cloned().unwrap_or(serde_json::Value::Null),
            "result": {}
        }))
        .into_response(),
    }
}
