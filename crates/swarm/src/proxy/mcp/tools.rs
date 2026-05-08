use std::collections::HashSet;

/// Peek at a JSON-RPC envelope to extract `(method, id, params)`.
/// Returns `None` for batches, parse failures, or non-object roots —
/// the proxy passes those through untouched.  We deliberately don't
/// validate the JSON-RPC envelope strictly; this is a *gate*, not
/// validation.  The upstream MCP server will catch malformed bodies.
pub(super) fn peek_jsonrpc(bytes: &[u8]) -> Option<(String, serde_json::Value, serde_json::Value)> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = value.as_object()?;
    let method = obj.get("method")?.as_str()?.to_owned();
    let id = obj.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let params = obj
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Some((method, id, params))
}

/// Filter the `result.tools[]` array of a `tools/list` JSON response
/// down to names in `allowed`.  Returns the re-serialised body.  A
/// parse failure or unexpected shape returns Err so the caller can
/// fall back to passing the upstream body through.
pub(super) fn filter_tools_list_body(bytes: &[u8], allowed: &[String]) -> Result<Vec<u8>, String> {
    let mut value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("parse: {e}"))?;
    let allowed_set: HashSet<&str> = allowed.iter().map(String::as_str).collect();
    let Some(tools) = value
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(|t| t.as_array_mut())
    else {
        return Err("response shape mismatch (no result.tools)".into());
    };
    tools.retain(|t| {
        t.get("name")
            .and_then(|n| n.as_str())
            .map(|n| allowed_set.contains(n))
            .unwrap_or(false)
    });
    serde_json::to_vec(&value).map_err(|e| format!("re-serialise: {e}"))
}
