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

use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::task::{Context, Poll};

use axum::body::Bytes;
use futures::Stream;

use crate::traits::AuditStore;

/// Hard cap on a single response body.  64 MiB is well above any
/// realistic LLM completion (4M tokens × 4 bytes ≈ 16 MiB) and well
/// below anything that would spike the swarm's memory under streaming
/// — but it also closes a denial-of-service vector where a hostile
/// upstream (or man-in-the-middle) sends an unbounded body.
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

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
}

impl Drop for RecordingState {
    fn drop(&mut self) {
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
            h.spawn(async move {
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
    E: Unpin,
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
    }
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
