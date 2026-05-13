//! Per-instance LLM tool-call audit routes.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::convert::Infallible;

use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path, State};
use axum::http::{Response, StatusCode, Uri, header};
use axum::routing::get;
use axum::{Json, Router};
use futures::Stream;
use serde::Serialize;

use crate::auth::CallerIdentity;
use crate::http::AppState;
use crate::traits::{LlmToolCallFilters, LlmToolCallRow, LlmToolCallStatusFilter};

const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 500;
const SEARCH_SCAN_LIMIT: usize = 10_000;
const STREAM_BOOTSTRAP_LIMIT: u32 = 50;
const STREAM_POLL_LIMIT: usize = 500;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/instances/:id/audit/tool-calls", get(list_tool_calls))
        .route(
            "/v1/instances/:id/audit/tool-calls/export",
            get(export_tool_calls),
        )
        .route(
            "/v1/instances/:id/audit/tool-calls/facets",
            get(tool_call_facets),
        )
        .route(
            "/v1/instances/:id/audit/tool-calls/stream",
            get(stream_tool_calls),
        )
        .with_state(state)
}

#[derive(Debug, Serialize, Clone)]
pub struct ToolCallView {
    pub id: i64,
    pub llm_audit_id: Option<i64>,
    pub instance_id: String,
    pub tool_use_id: String,
    pub tool_name: String,
    pub mcp_server: Option<String>,
    pub input: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub is_error: Option<bool>,
    pub called_at: i64,
    pub resulted_at: Option<i64>,
    pub mcp_audit_id: Option<i64>,
    pub mcp_status: Option<i64>,
    pub mcp_duration_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ToolCallListResponse {
    pub items: Vec<ToolCallView>,
    pub next_cursor: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ToolCallFacetResponse {
    pub tools: Vec<String>,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone)]
struct Query {
    tool: Option<String>,
    status: LlmToolCallStatusFilter,
    server: Option<String>,
    q: Option<String>,
    before: Option<i64>,
    limit: u32,
}

impl Query {
    fn filters(&self) -> LlmToolCallFilters<'_> {
        LlmToolCallFilters {
            tool: self.tool.as_deref(),
            status: self.status,
            server: self.server.as_deref(),
        }
    }
}

async fn list_tool_calls(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(instance_id): Path<String>,
    uri: Uri,
) -> Result<Json<ToolCallListResponse>, StatusCode> {
    ensure_instance_owner(&state, &caller.user_id, &instance_id).await?;
    let query = parse_query(uri.query().unwrap_or(""))?;
    if query_has_text(&query) {
        let (items, next_cursor) =
            search_tool_calls(&state, &caller.user_id, &instance_id, &query).await?;
        return Ok(Json(ToolCallListResponse { items, next_cursor }));
    }
    let rows = state
        .llm_tool_calls
        .list(
            &caller.user_id,
            &instance_id,
            query.filters(),
            query.before,
            query.limit,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut items = rows_to_views(&state, &caller.user_id, rows, query.q.as_deref())?;
    if items.len() > query.limit as usize {
        items.truncate(query.limit as usize);
    }
    let next_cursor = items.last().map(|r| r.id);
    Ok(Json(ToolCallListResponse { items, next_cursor }))
}

async fn search_tool_calls(
    state: &AppState,
    owner_id: &str,
    instance_id: &str,
    query: &Query,
) -> Result<(Vec<ToolCallView>, Option<i64>), StatusCode> {
    let mut before = query.before;
    let mut scanned = 0usize;
    let mut items = Vec::new();
    loop {
        let rows = state
            .llm_tool_calls
            .list(owner_id, instance_id, query.filters(), before, MAX_LIMIT)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if rows.is_empty() {
            break;
        }
        before = rows.last().map(|r| r.id);
        scanned += rows.len();
        let views = rows_to_views(state, owner_id, rows, query.q.as_deref())?;
        items.extend(views);
        if items.len() >= query.limit as usize || scanned >= SEARCH_SCAN_LIMIT {
            break;
        }
    }
    if items.len() > query.limit as usize {
        items.truncate(query.limit as usize);
    }
    let next_cursor = items.last().map(|r| r.id);
    Ok((items, next_cursor))
}

async fn tool_call_facets(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(instance_id): Path<String>,
) -> Result<Json<ToolCallFacetResponse>, StatusCode> {
    ensure_instance_owner(&state, &caller.user_id, &instance_id).await?;
    let mut before = None;
    let mut scanned = 0usize;
    let mut tools = BTreeSet::new();
    let mut servers = BTreeSet::new();
    loop {
        let rows = state
            .llm_tool_calls
            .list(
                &caller.user_id,
                &instance_id,
                LlmToolCallFilters::default(),
                before,
                MAX_LIMIT,
            )
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if rows.is_empty() {
            break;
        }
        before = rows.last().map(|r| r.id);
        scanned += rows.len();
        for row in rows {
            tools.insert(row.tool_name);
            if let Some(server) = row.mcp_server {
                servers.insert(server);
            }
        }
        if scanned >= SEARCH_SCAN_LIMIT {
            break;
        }
    }
    Ok(Json(ToolCallFacetResponse {
        tools: tools.into_iter().collect(),
        servers: servers.into_iter().collect(),
    }))
}

async fn export_tool_calls(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(instance_id): Path<String>,
    uri: Uri,
) -> Result<Response<Body>, StatusCode> {
    ensure_instance_owner(&state, &caller.user_id, &instance_id).await?;
    let mut query = parse_query(uri.query().unwrap_or(""))?;
    query.limit = MAX_LIMIT;
    let mut before = query.before;
    let mut lines = String::new();
    let mut emitted = 0usize;
    loop {
        let rows = state
            .llm_tool_calls
            .list(
                &caller.user_id,
                &instance_id,
                query.filters(),
                before,
                MAX_LIMIT,
            )
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if rows.is_empty() {
            break;
        }
        before = rows.last().map(|r| r.id);
        let views = rows_to_views(&state, &caller.user_id, rows, query.q.as_deref())?;
        for view in views {
            if emitted >= 10_000 {
                break;
            }
            let line =
                serde_json::to_string(&view).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            lines.push_str(&line);
            lines.push('\n');
            emitted += 1;
        }
        if emitted >= 10_000 {
            break;
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"tool-calls.ndjson\"",
        )
        .body(Body::from(lines))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn stream_tool_calls(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Path(instance_id): Path<String>,
    uri: Uri,
) -> Result<Response<Body>, StatusCode> {
    ensure_instance_owner(&state, &caller.user_id, &instance_id).await?;
    let query = parse_query(uri.query().unwrap_or(""))?;
    let rows = state
        .llm_tool_calls
        .list(
            &caller.user_id,
            &instance_id,
            query.filters(),
            None,
            STREAM_BOOTSTRAP_LIMIT,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut initial = rows_to_views(&state, &caller.user_id, rows, query.q.as_deref())?;
    initial.reverse();
    let cursor = initial.iter().map(|r| r.id).max().unwrap_or(0);
    let stream = tool_call_sse_stream(state, caller.user_id, instance_id, query, initial, cursor);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn tool_call_sse_stream(
    state: AppState,
    owner_id: String,
    instance_id: String,
    query: Query,
    initial: Vec<ToolCallView>,
    cursor: i64,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    struct SseState {
        state: AppState,
        owner_id: String,
        instance_id: String,
        query: Query,
        queue: VecDeque<String>,
        cursor: i64,
        ticks: u32,
        interval: tokio::time::Interval,
    }

    let queue = initial
        .into_iter()
        .filter_map(|view| sse_tool_call_event(&view).ok())
        .collect::<VecDeque<_>>();
    let state = SseState {
        state,
        owner_id,
        instance_id,
        query,
        queue,
        cursor,
        ticks: 0,
        interval: tokio::time::interval(std::time::Duration::from_secs(1)),
    };

    futures::stream::unfold(state, |mut s| async move {
        loop {
            if let Some(next) = s.queue.pop_front() {
                return Some((Ok(Bytes::from(next)), s));
            }
            s.interval.tick().await;
            s.ticks = s.ticks.saturating_add(1);
            match s
                .state
                .llm_tool_calls
                .stream_after(&s.owner_id, &s.instance_id, s.cursor)
                .await
            {
                Ok(rows) => {
                    for row in rows.into_iter().take(STREAM_POLL_LIMIT) {
                        s.cursor = s.cursor.max(row.id);
                        match row_to_view(&s.state, &s.owner_id, row) {
                            Ok(Some(view))
                                if view_matches_plain_filters(&view, &s.query)
                                    && query_matches(&view, s.query.q.as_deref()) =>
                            {
                                if let Ok(event) = sse_tool_call_event(&view) {
                                    s.queue.push_back(event);
                                }
                            }
                            Ok(_) => {}
                            Err(err) => {
                                tracing::warn!(error = %err, "tool-call stream decrypt failed");
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "tool-call stream poll failed");
                }
            }
            if s.ticks >= 15 {
                s.ticks = 0;
                return Some((Ok(Bytes::from_static(b": heartbeat\n\n")), s));
            }
        }
    })
}

fn sse_tool_call_event(view: &ToolCallView) -> Result<String, serde_json::Error> {
    let data = serde_json::to_string(view)?;
    Ok(format!("event: tool_call\ndata: {data}\n\n"))
}

async fn ensure_instance_owner(
    state: &AppState,
    owner_id: &str,
    instance_id: &str,
) -> Result<(), StatusCode> {
    state
        .instances
        .get(owner_id, instance_id)
        .await
        .map(|_| ())
        .map_err(|err| match err {
            crate::error::SwarmError::NotFound => StatusCode::NOT_FOUND,
            crate::error::SwarmError::BadRequest(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })
}

fn rows_to_views(
    state: &AppState,
    owner_id: &str,
    rows: Vec<LlmToolCallRow>,
    q: Option<&str>,
) -> Result<Vec<ToolCallView>, StatusCode> {
    let mut out = Vec::new();
    for row in rows {
        if let Some(view) =
            row_to_view(state, owner_id, row).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            && query_matches(&view, q)
        {
            out.push(view);
        }
    }
    Ok(out)
}

fn row_to_view(
    state: &AppState,
    owner_id: &str,
    row: LlmToolCallRow,
) -> Result<Option<ToolCallView>, String> {
    if row.owner_id != owner_id {
        return Ok(None);
    }
    Ok(Some(ToolCallView {
        id: row.id,
        llm_audit_id: row.llm_audit_id,
        instance_id: row.instance_id,
        tool_use_id: row.tool_use_id,
        tool_name: row.tool_name,
        mcp_server: row.mcp_server,
        input: unseal_json(state, owner_id, row.input_sealed)?,
        result: unseal_json(state, owner_id, row.result_sealed)?,
        is_error: row.is_error,
        called_at: row.called_at,
        resulted_at: row.resulted_at,
        mcp_audit_id: row.mcp_audit_id,
        mcp_status: row.mcp_status,
        mcp_duration_ms: row.mcp_duration_ms,
    }))
}

fn unseal_json(
    state: &AppState,
    owner_id: &str,
    ciphertext: Option<Vec<u8>>,
) -> Result<Option<serde_json::Value>, String> {
    let Some(ciphertext) = ciphertext else {
        return Ok(None);
    };
    let cipher = state
        .ciphers
        .for_user(owner_id)
        .map_err(|e| format!("load cipher: {e}"))?;
    let plain = cipher
        .open(&ciphertext)
        .map_err(|e| format!("open payload: {e}"))?;
    serde_json::from_slice::<serde_json::Value>(&plain)
        .map(Some)
        .map_err(|e| format!("decode payload json: {e}"))
}

fn query_matches(view: &ToolCallView, q: Option<&str>) -> bool {
    let Some(q) = q.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    let needle = q.to_ascii_lowercase();
    payload_contains(view.input.as_ref(), &needle)
        || payload_contains(view.result.as_ref(), &needle)
}

fn view_matches_plain_filters(view: &ToolCallView, query: &Query) -> bool {
    if query
        .tool
        .as_ref()
        .is_some_and(|tool| tool != &view.tool_name)
    {
        return false;
    }
    if query
        .server
        .as_ref()
        .is_some_and(|server| view.mcp_server.as_ref() != Some(server))
    {
        return false;
    }
    match query.status {
        LlmToolCallStatusFilter::All => true,
        LlmToolCallStatusFilter::Ok => view.is_error == Some(false),
        LlmToolCallStatusFilter::Err => view.is_error == Some(true),
    }
}

fn payload_contains(v: Option<&serde_json::Value>, needle: &str) -> bool {
    v.and_then(|v| serde_json::to_string(v).ok())
        .is_some_and(|s| s.to_ascii_lowercase().contains(needle))
}

fn query_has_text(query: &Query) -> bool {
    query.q.as_deref().is_some_and(|q| !q.trim().is_empty())
}

fn parse_query(qs: &str) -> Result<Query, StatusCode> {
    let params = parse_query_map(qs);
    let status = match params.get("status").map(String::as_str) {
        Some("ok") => LlmToolCallStatusFilter::Ok,
        Some("err") => LlmToolCallStatusFilter::Err,
        Some("all") | None | Some("") => LlmToolCallStatusFilter::All,
        Some(_) => return Err(StatusCode::BAD_REQUEST),
    };
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_LIMIT);
    Ok(Query {
        tool: clean_param(params.get("tool")),
        status,
        server: clean_param(params.get("server")).filter(|s| s != "all"),
        q: clean_param(params.get("q")),
        before: params.get("before").and_then(|s| s.parse::<i64>().ok()),
        limit,
    })
}

fn clean_param(v: Option<&String>) -> Option<String> {
    v.map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn parse_query_map(qs: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in qs.split('&').filter(|p| !p.is_empty()) {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        out.insert(qs_decode(k), qs_decode(v));
    }
    out
}

fn qs_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
}
