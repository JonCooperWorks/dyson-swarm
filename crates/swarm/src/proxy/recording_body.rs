//! Streaming response wrapper that tees bytes through to the client
//! while extracting `usage` info and stamping the audit row on Drop.
//!
//! The proxy inserts an `llm_audit` row up-front with `completed=false`
//! and `output_tokens=None`, then wraps the upstream response body in
//! [`RecordingBody`].  As bytes flow through:
//!
//! - We forward each chunk verbatim to the caller (byte-for-byte
//!   passthrough — no buffering of the whole response).
//! - We watch for `usage` blocks (SSE `data:` lines or trailing JSON)
//!   to extract `output_tokens` for accurate budget accounting.
//! - We track total bytes and short-circuit at `MAX_RESPONSE_BYTES`,
//!   recording a `truncated` flag in the audit row.
//!
//! On `Drop` we spawn a `tokio` task to write the final completion
//! state — `Drop` is sync, so the actual `update_completion` call has
//! to be deferred onto the runtime.  This is fire-and-forget; if the
//! task fails (e.g. runtime shutdown) the row stays `completed=false`
//! and shows up in the forensic-trail bucket.

use std::collections::BTreeMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use futures::{FutureExt as _, Stream};
use serde_json::Value as JsonValue;

use crate::envelope::{CipherDirectory, KmsContext, KmsScope, SecretAccessReason, seal_context};
use crate::traits::{AuditStore, LlmToolCallEntry, LlmToolCallStore};

/// Hard cap on a single response body.  64 MiB is well above any
/// realistic LLM completion (4M tokens × 4 bytes ≈ 16 MiB) and well
/// below anything that would spike the swarm's memory under streaming
/// — but it also closes a denial-of-service vector where a hostile
/// upstream (or man-in-the-middle) sends an unbounded body.
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const TOOL_PAYLOAD_CAP: usize = 64 * 1024;

#[derive(Clone)]
pub struct ToolCallAuditContext {
    pub provider: String,
    pub owner_id: String,
    pub instance_id: String,
    pub llm_audit_id: i64,
    pub store: Arc<dyn LlmToolCallStore>,
    pub ciphers: Arc<dyn CipherDirectory>,
}

/// Shared state between the streaming body and the Drop handler.
/// Atomics so the Drop handler can read finalized state without a
/// lock (the inner stream owns this Arc; Drop fires when the last
/// clone goes out of scope).
struct RecordingState {
    audit: Arc<dyn AuditStore>,
    audit_id: i64,
    output_tokens: AtomicU64,
    /// Sentinel: u64::MAX means "no output_tokens observed yet" so we
    /// can distinguish "tokens=0" from "tokens=None".  Cleaner than a
    /// second flag.
    output_tokens_seen: AtomicBool,
    truncated: AtomicBool,
    /// SSE / JSON parser state.  Using a parking_lot mutex since
    /// `parse_chunk` mutates the buffer; the lock is held for a few
    /// microseconds per chunk.
    parser: parking_lot::Mutex<UsageParser>,
    tool_audit: Option<ToolCallAuditContext>,
    tool_parser: parking_lot::Mutex<ToolCallStreamParser>,
}

impl Drop for RecordingState {
    fn drop(&mut self) {
        let finalized = if self.tool_audit.is_some() {
            self.tool_parser.get_mut().finish()
        } else {
            Vec::new()
        };
        if !finalized.is_empty() {
            record_tool_calls(self.tool_audit.clone(), finalized);
        }
        let audit = self.audit.clone();
        let audit_id = self.audit_id;
        let output_tokens = if self.output_tokens_seen.load(Ordering::Relaxed) {
            // u64::try_from is safe: we only `store` from i64 sources.
            i64::try_from(self.output_tokens.load(Ordering::Relaxed)).ok()
        } else {
            None
        };
        let truncated = self.truncated.load(Ordering::Relaxed);
        // `tokio::spawn` from a sync Drop: works as long as we're
        // inside a tokio runtime.  The handler always runs from one
        // (axum -> tokio).  Outside a runtime (some tests) the task
        // is silently dropped — acceptable here since tests don't
        // assert on completion-write timing.
        let handle = tokio::runtime::Handle::try_current().ok();
        if let Some(h) = handle {
            spawn_audit_future(&h, audit_id, async move {
                if let Err(e) = audit.update_completion(audit_id, output_tokens).await {
                    tracing::warn!(
                        audit_id,
                        truncated,
                        error = %e,
                        "audit completion update failed",
                    );
                } else if truncated {
                    tracing::warn!(
                        audit_id,
                        "response body truncated at cap; audit row marked completed",
                    );
                }
            });
        }
    }
}

/// Stream adapter that tees bytes through and harvests `usage` info.
/// Generic over the inner stream so this works with `reqwest::Response::bytes_stream`
/// or any other `Stream<Item = Result<Bytes, E>>`.
pub struct RecordingBody<S, E> {
    inner: S,
    state: Arc<RecordingState>,
    bytes_seen: u64,
    finished: bool,
    _e: std::marker::PhantomData<E>,
}

impl<S, E> RecordingBody<S, E>
where
    S: Stream<Item = Result<Bytes, E>>,
{
    pub fn new(inner: S, audit: Arc<dyn AuditStore>, audit_id: i64) -> Self {
        Self {
            inner,
            state: Arc::new(RecordingState {
                audit,
                audit_id,
                output_tokens: AtomicU64::new(0),
                output_tokens_seen: AtomicBool::new(false),
                truncated: AtomicBool::new(false),
                parser: parking_lot::Mutex::new(UsageParser::default()),
                tool_audit: None,
                tool_parser: parking_lot::Mutex::new(ToolCallStreamParser::new("openai")),
            }),
            bytes_seen: 0,
            finished: false,
            _e: std::marker::PhantomData,
        }
    }

    pub fn new_with_tool_audit(
        inner: S,
        audit: Arc<dyn AuditStore>,
        audit_id: i64,
        tool_audit: ToolCallAuditContext,
    ) -> Self {
        let provider = tool_audit.provider.clone();
        Self {
            inner,
            state: Arc::new(RecordingState {
                audit,
                audit_id,
                output_tokens: AtomicU64::new(0),
                output_tokens_seen: AtomicBool::new(false),
                truncated: AtomicBool::new(false),
                parser: parking_lot::Mutex::new(UsageParser::default()),
                tool_audit: Some(tool_audit),
                tool_parser: parking_lot::Mutex::new(ToolCallStreamParser::new(&provider)),
            }),
            bytes_seen: 0,
            finished: false,
            _e: std::marker::PhantomData,
        }
    }
}

// `Unpin` bound on `S` — every `bytes_stream()` we wrap is already
// Unpin (reqwest, futures::stream::iter, …), and requiring it here
// lets us reach through `Pin<&mut Self>` with `get_mut()` without
// hand-rolling pin projection.  `E` ends up inside a `PhantomData<E>`
// on the struct, which propagates auto-traits — Unpin too.
impl<S, E> Stream for RecordingBody<S, E>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display + Unpin,
{
    type Item = Result<Bytes, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.finished = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                tracing::warn!(
                    bytes_seen = this.bytes_seen,
                    error = %e,
                    "llm proxy upstream stream failed"
                );
                this.finished = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(Some(Ok(chunk))) => {
                let new_total = this.bytes_seen.saturating_add(chunk.len() as u64);
                if new_total > MAX_RESPONSE_BYTES {
                    // Cap exceeded.  Trim the chunk to the cap, mark
                    // truncated, end the stream after this delivery.
                    let allowed_u64 = MAX_RESPONSE_BYTES.saturating_sub(this.bytes_seen);
                    let allowed = usize::try_from(allowed_u64).unwrap_or(usize::MAX);
                    let trimmed = chunk.slice(..allowed.min(chunk.len()));
                    this.bytes_seen = MAX_RESPONSE_BYTES;
                    this.state.truncated.store(true, Ordering::Relaxed);
                    this.finished = true;
                    if !trimmed.is_empty() {
                        Self::observe(&this.state, &trimmed);
                        return Poll::Ready(Some(Ok(trimmed)));
                    }
                    return Poll::Ready(None);
                }
                this.bytes_seen = new_total;
                Self::observe(&this.state, &chunk);
                Poll::Ready(Some(Ok(chunk)))
            }
        }
    }
}

impl<S, E> RecordingBody<S, E> {
    fn observe(state: &Arc<RecordingState>, chunk: &Bytes) {
        let mut parser = state.parser.lock();
        if let Some(tokens) = parser.feed(chunk) {
            // Safe-cast guard: i64 → u64.  Negative or absurd values
            // (shouldn't happen for token counts) become 0.
            let tokens_u = u64::try_from(tokens).unwrap_or(0);
            state.output_tokens.store(tokens_u, Ordering::Relaxed);
            state.output_tokens_seen.store(true, Ordering::Relaxed);
        }
        drop(parser);
        let finalized = if state.tool_audit.is_some() {
            state.tool_parser.lock().feed(chunk)
        } else {
            Vec::new()
        };
        if !finalized.is_empty() {
            record_tool_calls(state.tool_audit.clone(), finalized);
        }
    }
}

fn record_tool_calls(ctx: Option<ToolCallAuditContext>, calls: Vec<ToolCallEvent>) {
    let Some(ctx) = ctx else {
        return;
    };
    let audit_id = ctx.llm_audit_id;
    let handle = tokio::runtime::Handle::try_current().ok();
    if let Some(h) = handle {
        spawn_audit_future(&h, audit_id, async move {
            for call in calls {
                if let Err(err) = insert_tool_call(&ctx, call).await {
                    tracing::warn!(error = %err, "llm tool-call audit insert failed");
                }
            }
        });
    }
}

fn spawn_audit_future<F>(handle: &tokio::runtime::Handle, audit_id: i64, future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    handle.spawn(async move {
        if AssertUnwindSafe(future).catch_unwind().await.is_err() {
            tracing::error!(audit_id, "spawned audit task panicked");
        }
    });
}

async fn insert_tool_call(ctx: &ToolCallAuditContext, call: ToolCallEvent) -> Result<(), String> {
    let context = KmsContext::user_scoped(
        KmsScope::LlmToolCall,
        ctx.owner_id.clone(),
        Some(ctx.instance_id.clone()),
        Some(format!("input:{}", call.tool_use_id)),
    );
    let input_sealed = seal_context(
        ctx.ciphers.as_ref(),
        &context,
        &capped_json_bytes(&call.input),
        SecretAccessReason::LlmProviderProxy,
    )
    .map_err(|e| format!("seal tool input: {e}"))?;
    let (mcp_server, mcp_tool_name) = parse_mcp_tool_name(&call.tool_name);
    let called_at = crate::now_secs();
    let id = ctx
        .store
        .insert_call(&LlmToolCallEntry {
            llm_audit_id: Some(ctx.llm_audit_id),
            owner_id: ctx.owner_id.clone(),
            instance_id: ctx.instance_id.clone(),
            tool_use_id: call.tool_use_id,
            tool_name: call.tool_name,
            mcp_server: mcp_server.clone(),
            input_sealed: Some(input_sealed),
            called_at,
        })
        .await
        .map_err(|e| e.to_string())?;
    if let (Some(server), Some(tool)) = (mcp_server, mcp_tool_name) {
        retry_link_mcp(ctx.clone(), id, server, tool, called_at);
    }
    Ok(())
}

fn retry_link_mcp(
    ctx: ToolCallAuditContext,
    tool_call_id: i64,
    server: String,
    tool: String,
    called_at: i64,
) {
    let handle = tokio::runtime::Handle::try_current().ok();
    if let Some(h) = handle {
        h.spawn(async move {
            for attempt in 0..3 {
                match ctx
                    .store
                    .link_mcp_audit(
                        tool_call_id,
                        &ctx.owner_id,
                        &ctx.instance_id,
                        &server,
                        &tool,
                        called_at,
                    )
                    .await
                {
                    Ok(true) => return,
                    Ok(false) => {}
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            tool_call_id,
                            server = %server,
                            tool = %tool,
                            "llm tool-call mcp audit link failed",
                        );
                    }
                }
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        });
    }
}

pub(crate) fn parse_mcp_tool_name(tool_name: &str) -> (Option<String>, Option<String>) {
    let Some(rest) = tool_name.strip_prefix("mcp__") else {
        return (None, None);
    };
    let Some((server, tool)) = rest.split_once("__") else {
        return (None, None);
    };
    if server.is_empty() || tool.is_empty() {
        return (None, None);
    }
    (Some(server.to_owned()), Some(tool.to_owned()))
}

pub(crate) fn capped_json_bytes(value: &JsonValue) -> Vec<u8> {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    if bytes.len() <= TOOL_PAYLOAD_CAP {
        return bytes;
    }
    let prefix = String::from_utf8_lossy(&bytes[..TOOL_PAYLOAD_CAP]).into_owned();
    serde_json::to_vec(&serde_json::json!({
        "_truncated": true,
        "prefix_utf8": prefix,
    }))
    .unwrap_or_else(|_| br#"{"_truncated":true}"#.to_vec())
}

/// Best-effort parser for `usage.output_tokens` in SSE-or-plain-JSON
/// responses.  We accumulate up to a small buffer (8 KiB) of *the most
/// recent* bytes — for SSE, that catches the final `usage` event in the
/// trailing chunks; for non-streaming JSON, the `usage` block is at the
/// end of the body.
///
/// On a parse miss this returns `None` and the audit row stays
/// `output_tokens=None` — the daily-tokens query (Agent 1's update)
/// handles `None` as 0 so the budget is conservatively under-counted
/// rather than over-counted.
#[derive(Default)]
struct UsageParser {
    /// Tail buffer.  Capped so we don't DoS our own RAM on a hostile
    /// upstream that streams gigabytes without a `usage` block.
    tail: Vec<u8>,
}

const TAIL_CAP: usize = 8 * 1024;

impl UsageParser {
    fn feed(&mut self, chunk: &[u8]) -> Option<i64> {
        // Append, then trim to TAIL_CAP from the right.
        self.tail.extend_from_slice(chunk);
        if self.tail.len() > TAIL_CAP {
            let drop_n = self.tail.len() - TAIL_CAP;
            self.tail.drain(..drop_n);
        }
        // Two scan strategies:
        // 1. SSE: lines starting with `data:` containing JSON; pick
        //    the last one that has a `usage.output_tokens` field.
        // 2. Plain JSON: the entire tail might be the response body
        //    (or its tail).  Try parsing as JSON.
        find_output_tokens_sse(&self.tail).or_else(|| find_output_tokens_json(&self.tail))
    }
}

fn find_output_tokens_sse(buf: &[u8]) -> Option<i64> {
    // Walk backwards through `data: …` lines, stopping at the first
    // one that decodes to JSON with `usage.output_tokens`.  SSE events
    // are separated by `\n\n`; lines start with `data:`.  We don't try
    // to be RFC-perfect — the parser is best-effort and any miss just
    // leaves output_tokens=None.
    let s = std::str::from_utf8(buf).ok()?;
    let mut last_tokens = None;
    for line in s.lines() {
        let line = line.trim_start();
        if let Some(payload) = line.strip_prefix("data:") {
            let payload = payload.trim();
            if payload == "[DONE]" || payload.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                if let Some(t) = extract_output_tokens(&v) {
                    last_tokens = Some(t);
                }
            }
        }
    }
    last_tokens
}

fn find_output_tokens_json(buf: &[u8]) -> Option<i64> {
    // Try to parse the buffer as a complete JSON object.  Most
    // non-streaming responses fit comfortably under TAIL_CAP; bigger
    // ones get their tail clipped — which means JSON parse fails and
    // we return None.  Acceptable: budget under-counts, never over-
    // counts.
    let v: serde_json::Value = serde_json::from_slice(buf).ok()?;
    extract_output_tokens(&v)
}

/// Pull `usage.output_tokens` from a JSON payload.  Handles OpenAI
/// (`completion_tokens`), Anthropic (`output_tokens`), and Google /
/// Gemini (`candidatesTokenCount`) flavours.  Returns the first one
/// that looks like a non-negative integer.
fn extract_output_tokens(v: &serde_json::Value) -> Option<i64> {
    let usage = v.get("usage").or_else(|| v.get("usageMetadata"))?;
    for key in &[
        "output_tokens",        // Anthropic
        "completion_tokens",    // OpenAI / OR
        "candidatesTokenCount", // Gemini
    ] {
        if let Some(n) = usage.get(*key).and_then(serde_json::Value::as_i64) {
            return Some(n);
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
struct ToolCallEvent {
    tool_use_id: String,
    tool_name: String,
    input: JsonValue,
}

#[derive(Default)]
struct ToolCallStreamParser {
    provider: String,
    sse_buffer: String,
    anthropic: AnthropicToolParser,
    openai: OpenAiToolParser,
}

impl ToolCallStreamParser {
    fn new(provider: &str) -> Self {
        Self {
            provider: provider.to_ascii_lowercase(),
            sse_buffer: String::new(),
            anthropic: AnthropicToolParser::default(),
            openai: OpenAiToolParser::default(),
        }
    }

    fn feed(&mut self, chunk: &[u8]) -> Vec<ToolCallEvent> {
        let Ok(text) = std::str::from_utf8(chunk) else {
            return Vec::new();
        };
        self.sse_buffer.push_str(text);
        let mut out = Vec::new();
        while let Some(idx) = self.sse_buffer.find("\n\n") {
            let event = self.sse_buffer[..idx].to_owned();
            self.sse_buffer.drain(..idx + 2);
            for payload in sse_json_payloads(&event) {
                out.extend(self.process_payload(&payload));
            }
        }
        out
    }

    fn finish(&mut self) -> Vec<ToolCallEvent> {
        let mut out = Vec::new();
        if !self.sse_buffer.trim().is_empty() {
            let event = std::mem::take(&mut self.sse_buffer);
            for payload in sse_json_payloads(&event) {
                out.extend(self.process_payload(&payload));
            }
        }
        if self.provider == "anthropic" {
            out
        } else {
            out.extend(self.openai.finish_all());
            out
        }
    }

    fn process_payload(&mut self, payload: &JsonValue) -> Vec<ToolCallEvent> {
        if self.provider == "anthropic" {
            self.anthropic.process(payload)
        } else {
            self.openai.process(payload)
        }
    }
}

fn sse_json_payloads(event: &str) -> Vec<JsonValue> {
    let mut payload = String::new();
    for line in event.lines() {
        let line = line.trim_start();
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data == "[DONE]" || data.is_empty() {
                continue;
            }
            if !payload.is_empty() {
                payload.push('\n');
            }
            payload.push_str(data);
        }
    }
    if payload.is_empty() {
        return Vec::new();
    }
    serde_json::from_str::<JsonValue>(&payload)
        .map(|v| vec![v])
        .unwrap_or_default()
}

#[derive(Default)]
struct AnthropicToolParser {
    blocks: BTreeMap<i64, AnthropicToolBlock>,
}

#[derive(Default)]
struct AnthropicToolBlock {
    id: String,
    name: String,
    initial_input: Option<JsonValue>,
    partial_json: String,
}

impl AnthropicToolParser {
    fn process(&mut self, payload: &JsonValue) -> Vec<ToolCallEvent> {
        match payload.get("type").and_then(JsonValue::as_str) {
            Some("content_block_start") => {
                self.start_block(payload);
                Vec::new()
            }
            Some("content_block_delta") => {
                self.delta(payload);
                Vec::new()
            }
            Some("content_block_stop") => self.stop(payload).into_iter().collect(),
            _ => Vec::new(),
        }
    }

    fn start_block(&mut self, payload: &JsonValue) {
        let Some(block) = payload.get("content_block") else {
            return;
        };
        if block.get("type").and_then(JsonValue::as_str) != Some("tool_use") {
            return;
        }
        let Some(index) = payload.get("index").and_then(JsonValue::as_i64) else {
            return;
        };
        let Some(id) = block.get("id").and_then(JsonValue::as_str) else {
            return;
        };
        let Some(name) = block.get("name").and_then(JsonValue::as_str) else {
            return;
        };
        self.blocks.insert(
            index,
            AnthropicToolBlock {
                id: id.to_owned(),
                name: name.to_owned(),
                initial_input: block.get("input").cloned(),
                partial_json: String::new(),
            },
        );
    }

    fn delta(&mut self, payload: &JsonValue) {
        let Some(index) = payload.get("index").and_then(JsonValue::as_i64) else {
            return;
        };
        let Some(block) = self.blocks.get_mut(&index) else {
            return;
        };
        let Some(delta) = payload.get("delta") else {
            return;
        };
        if delta.get("type").and_then(JsonValue::as_str) == Some("input_json_delta")
            && let Some(partial) = delta.get("partial_json").and_then(JsonValue::as_str)
        {
            block.partial_json.push_str(partial);
        }
    }

    fn stop(&mut self, payload: &JsonValue) -> Option<ToolCallEvent> {
        let index = payload.get("index").and_then(JsonValue::as_i64)?;
        let block = self.blocks.remove(&index)?;
        let input = if block.partial_json.trim().is_empty() {
            block.initial_input.unwrap_or_else(|| serde_json::json!({}))
        } else {
            match serde_json::from_str::<JsonValue>(&block.partial_json) {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        tool_use_id = %block.id,
                        "anthropic tool_use input_json_delta was malformed; skipping audit row",
                    );
                    return None;
                }
            }
        };
        Some(ToolCallEvent {
            tool_use_id: block.id,
            tool_name: block.name,
            input,
        })
    }
}

#[derive(Default)]
struct OpenAiToolParser {
    calls: BTreeMap<(i64, i64), OpenAiToolCall>,
}

#[derive(Default)]
struct OpenAiToolCall {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

impl OpenAiToolParser {
    fn process(&mut self, payload: &JsonValue) -> Vec<ToolCallEvent> {
        let mut finished = false;
        let Some(choices) = payload.get("choices").and_then(JsonValue::as_array) else {
            return Vec::new();
        };
        for choice in choices {
            let choice_index = choice.get("index").and_then(JsonValue::as_i64).unwrap_or(0);
            if choice
                .get("finish_reason")
                .and_then(JsonValue::as_str)
                .is_some_and(|r| r == "tool_calls")
            {
                finished = true;
            }
            let Some(tool_calls) = choice
                .get("delta")
                .and_then(|d| d.get("tool_calls"))
                .and_then(JsonValue::as_array)
            else {
                continue;
            };
            for call in tool_calls {
                let tool_index = call.get("index").and_then(JsonValue::as_i64).unwrap_or(0);
                let slot = self.calls.entry((choice_index, tool_index)).or_default();
                if let Some(id) = call.get("id").and_then(JsonValue::as_str) {
                    slot.id = Some(id.to_owned());
                }
                if let Some(function) = call.get("function") {
                    if let Some(name) = function.get("name").and_then(JsonValue::as_str) {
                        slot.name = Some(name.to_owned());
                    }
                    if let Some(args) = function.get("arguments").and_then(JsonValue::as_str) {
                        slot.arguments.push_str(args);
                    }
                }
            }
        }
        if finished {
            self.finish_all()
        } else {
            Vec::new()
        }
    }

    fn finish_all(&mut self) -> Vec<ToolCallEvent> {
        let calls = std::mem::take(&mut self.calls);
        let mut out = Vec::new();
        for (_, call) in calls {
            let (Some(id), Some(name)) = (call.id, call.name) else {
                continue;
            };
            let raw = if call.arguments.trim().is_empty() {
                "{}"
            } else {
                call.arguments.trim()
            };
            match serde_json::from_str::<JsonValue>(raw) {
                Ok(input) => out.push(ToolCallEvent {
                    tool_use_id: id,
                    tool_name: name,
                    input,
                }),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        tool_use_id = %id,
                        "openai tool_call arguments were malformed; skipping audit row",
                    );
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    use crate::error::StoreError;
    use crate::traits::{AuditEntry, AuditStore};

    use futures::StreamExt as _;

    #[derive(Default)]
    struct StubAudit {
        completions: Mutex<Vec<(i64, Option<i64>)>>,
    }

    #[async_trait]
    impl AuditStore for StubAudit {
        async fn insert(&self, _: &AuditEntry) -> Result<i64, StoreError> {
            Ok(1)
        }
        async fn daily_tokens(&self, _: &str, _: i64) -> Result<u64, StoreError> {
            Ok(0)
        }
        async fn update_completion(
            &self,
            audit_id: i64,
            output_tokens: Option<i64>,
        ) -> Result<(), StoreError> {
            self.completions
                .lock()
                .unwrap()
                .push((audit_id, output_tokens));
            Ok(())
        }
    }

    struct PanickingAudit {
        notify: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }

    #[async_trait]
    impl AuditStore for PanickingAudit {
        async fn insert(&self, _: &AuditEntry) -> Result<i64, StoreError> {
            Ok(1)
        }
        async fn daily_tokens(&self, _: &str, _: i64) -> Result<u64, StoreError> {
            Ok(0)
        }
        async fn update_completion(&self, _: i64, _: Option<i64>) -> Result<(), StoreError> {
            if let Some(tx) = self.notify.lock().unwrap().take() {
                let _ = tx.send(());
            }
            panic!("intentional audit panic");
        }
    }

    #[test]
    fn extract_openai_completion_tokens() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"usage": {"prompt_tokens": 10, "completion_tokens": 42}}"#)
                .unwrap();
        assert_eq!(extract_output_tokens(&v), Some(42));
    }

    #[test]
    fn extract_anthropic_output_tokens() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"usage": {"input_tokens": 10, "output_tokens": 17}}"#)
                .unwrap();
        assert_eq!(extract_output_tokens(&v), Some(17));
    }

    #[test]
    fn extract_gemini_candidates_token_count() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"usageMetadata": {"candidatesTokenCount": 99}}"#).unwrap();
        assert_eq!(extract_output_tokens(&v), Some(99));
    }

    #[test]
    fn parser_picks_up_sse_final_event() {
        let mut p = UsageParser::default();
        let r = p.feed(b"data: {\"hello\":\"world\"}\n\n");
        assert_eq!(r, None);
        let r = p.feed(b"data: {\"usage\":{\"output_tokens\":7}}\n\n");
        assert_eq!(r, Some(7));
    }

    #[test]
    fn parser_picks_up_plain_json() {
        let mut p = UsageParser::default();
        let body = br#"{"id":"x","usage":{"completion_tokens":11}}"#;
        let r = p.feed(body);
        assert_eq!(r, Some(11));
    }

    #[test]
    fn anthropic_parser_records_one_tool_use() {
        let mut p = ToolCallStreamParser::new("anthropic");
        let out = p.feed(
            br#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ec"}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"ho hi\"}"}}

data: {"type":"content_block_stop","index":0}

"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tool_use_id, "toolu_1");
        assert_eq!(out[0].tool_name, "bash");
        assert_eq!(out[0].input, serde_json::json!({"cmd":"echo hi"}));
    }

    #[test]
    fn anthropic_parser_records_two_tool_uses_and_ignores_text_blocks() {
        let mut p = ToolCallStreamParser::new("anthropic");
        let out = p.feed(
            br#"data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":"thinking"}}

data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}

data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"pwd\"}"}}

data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_2","name":"mcp__github__create_issue","input":{}}}

data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"title\":\"bug\"}"}}

data: {"type":"content_block_stop","index":1}

data: {"type":"content_block_stop","index":2}

"#,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].tool_use_id, "toolu_1");
        assert_eq!(out[1].tool_name, "mcp__github__create_issue");
    }

    #[test]
    fn anthropic_parser_skips_malformed_partial_json() {
        let mut p = ToolCallStreamParser::new("anthropic");
        let out = p.feed(
            br#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_bad","name":"bash","input":{}}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":"}}

data: {"type":"content_block_stop","index":0}

"#,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn openai_parser_records_one_tool_call() {
        let mut p = ToolCallStreamParser::new("openai");
        let out = p.feed(
            br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"pw"}}]}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"d\"}"}}]},"finish_reason":"tool_calls"}]}

"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tool_use_id, "call_1");
        assert_eq!(out[0].tool_name, "bash");
        assert_eq!(out[0].input, serde_json::json!({"cmd":"pwd"}));
    }

    #[test]
    fn openai_parser_records_multiple_tool_calls() {
        let mut p = ToolCallStreamParser::new("openrouter");
        let out = p.feed(
            br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"bash","arguments":"{\"cmd\":\"pwd\"}"}},{"index":1,"id":"call_2","function":{"name":"edit_file","arguments":"{\"path\":\"a\"}"}}]},"finish_reason":"tool_calls"}]}

"#,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].tool_use_id, "call_1");
        assert_eq!(out[1].tool_name, "edit_file");
    }

    #[test]
    fn openai_parser_finalizes_on_stream_close() {
        let mut p = ToolCallStreamParser::new("openai");
        let out = p.feed(
            br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"bash","arguments":"{\"cmd\":\"pwd\"}"}}]}}]}

"#,
        );
        assert!(out.is_empty());
        let out = p.finish();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].input, serde_json::json!({"cmd":"pwd"}));
    }

    #[test]
    fn tool_payload_cap_marks_truncated_json() {
        let v = serde_json::json!({"blob":"x".repeat(TOOL_PAYLOAD_CAP + 100)});
        let capped = capped_json_bytes(&v);
        let decoded: serde_json::Value = serde_json::from_slice(&capped).unwrap();
        assert_eq!(decoded["_truncated"], true);
        assert!(decoded["prefix_utf8"].as_str().unwrap().len() <= TOOL_PAYLOAD_CAP);
    }

    #[tokio::test]
    async fn drop_finalizes_completion_with_tokens() {
        let stub = Arc::new(StubAudit::default());
        let audit: Arc<dyn AuditStore> = stub.clone();
        let chunks = vec![
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: {\"hello\":1}\n\n")),
            Ok(Bytes::from_static(
                b"data: {\"usage\":{\"output_tokens\":5}}\n\n",
            )),
            Ok(Bytes::from_static(b"data: [DONE]\n\n")),
        ];
        let s = futures::stream::iter(chunks);
        let body = RecordingBody::new(s, audit, 42);
        // Drain the stream
        let collected: Vec<_> = body.collect().await;
        assert_eq!(collected.len(), 3);
        // Drop fires here; give the runtime a tick to run the
        // tokio::spawn'd update.  This is racy in principle but
        // a short yield is enough on the in-process runtime.
        // Drop fires here; yield repeatedly to let the spawned
        // completion task run.  No `tokio::time::sleep` because the
        // crate's tokio feature set deliberately omits "time".
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if !stub.completions.lock().unwrap().is_empty() {
                break;
            }
        }
        let calls = stub.completions.lock().unwrap();
        assert_eq!(calls.as_slice(), &[(42, Some(5))]);
    }

    #[tokio::test]
    async fn drop_finalizes_with_none_when_no_usage_seen() {
        let stub = Arc::new(StubAudit::default());
        let audit: Arc<dyn AuditStore> = stub.clone();
        let chunks = vec![Ok::<Bytes, std::io::Error>(Bytes::from_static(
            b"random bytes",
        ))];
        let s = futures::stream::iter(chunks);
        let body = RecordingBody::new(s, audit, 7);
        let _: Vec<_> = body.collect().await;
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if !stub.completions.lock().unwrap().is_empty() {
                break;
            }
        }
        let calls = stub.completions.lock().unwrap();
        assert_eq!(calls.as_slice(), &[(7, None)]);
    }

    #[tokio::test]
    async fn drop_spawned_audit_panic_is_caught_and_runtime_continues() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let audit: Arc<dyn AuditStore> = Arc::new(PanickingAudit {
            notify: Mutex::new(Some(tx)),
        });
        let chunks = vec![Ok::<Bytes, std::io::Error>(Bytes::from_static(
            b"random bytes",
        ))];
        let body = RecordingBody::new(futures::stream::iter(chunks), audit, 13);

        let _: Vec<_> = body.collect().await;
        rx.await.unwrap();
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }

        let stub = Arc::new(StubAudit::default());
        let audit: Arc<dyn AuditStore> = stub.clone();
        let chunks = vec![Ok::<Bytes, std::io::Error>(Bytes::from_static(
            br#"{"usage":{"completion_tokens":3}}"#,
        ))];
        let body = RecordingBody::new(futures::stream::iter(chunks), audit, 14);
        let _: Vec<_> = body.collect().await;
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if !stub.completions.lock().unwrap().is_empty() {
                break;
            }
        }

        let calls = stub.completions.lock().unwrap();
        assert_eq!(calls.as_slice(), &[(14, Some(3))]);
    }

    #[tokio::test]
    async fn truncates_at_cap() {
        let stub = Arc::new(StubAudit::default());
        let audit: Arc<dyn AuditStore> = stub.clone();
        // Two huge chunks past the cap to verify the trimming.
        let big = Bytes::from(vec![
            0u8;
            usize::try_from(MAX_RESPONSE_BYTES).unwrap() + 1024
        ]);
        let chunks = vec![Ok::<Bytes, std::io::Error>(big)];
        let s = futures::stream::iter(chunks);
        let body = RecordingBody::new(s, audit, 9);
        let collected: Vec<Result<Bytes, std::io::Error>> = body.collect().await;
        // First chunk trimmed to the cap.
        let total: u64 = collected
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|b| b.len() as u64)
            .sum();
        assert_eq!(total, MAX_RESPONSE_BYTES);
    }
}
