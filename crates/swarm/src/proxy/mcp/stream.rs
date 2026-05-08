/// Minimal SSE parser scoped to our use case: scan `data:` lines and
/// return the first one that looks like a JSON-RPC response (carries
/// `jsonrpc` and either `result` or `error`).  Multi-line `data:`
/// continuations are concatenated per the SSE spec.
pub(super) fn parse_sse_jsonrpc(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("sse utf8: {e}"))?;
    let mut buf = String::new();
    let flush = |buf: &mut String| -> Option<serde_json::Value> {
        if buf.is_empty() {
            return None;
        }
        let payload = std::mem::take(buf);
        let value = serde_json::from_str::<serde_json::Value>(payload.trim()).ok()?;
        if value.get("jsonrpc").is_some()
            && (value.get("result").is_some() || value.get("error").is_some())
        {
            Some(value)
        } else {
            None
        }
    };
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            // Blank line ⇒ event boundary.
            if let Some(v) = flush(&mut buf) {
                return Ok(v);
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
        // Any other field (id:, event:, retry:) is ignored.
    }
    if let Some(v) = flush(&mut buf) {
        return Ok(v);
    }
    Err("no JSON-RPC response in SSE stream".into())
}

pub(super) fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}
