export function toolCallQuery(filters = {}) {
  const params = new URLSearchParams();
  if (filters.tool) params.set('tool', filters.tool);
  if (filters.status === 'ok' || filters.status === 'err') params.set('status', filters.status);
  else params.set('status', 'all');
  if (filters.server) params.set('server', filters.server);
  if (filters.q) params.set('q', filters.q);
  if (filters.before != null) params.set('before', String(filters.before));
  if (filters.limit) params.set('limit', String(filters.limit));
  const qs = params.toString();
  return qs ? `?${qs}` : '';
}

export function listToolCalls(client, instanceId, filters = {}) {
  return client._json(
    `/v1/instances/${encodeURIComponent(instanceId)}/audit/tool-calls${toolCallQuery(filters)}`,
    { headers: { Accept: 'application/json' } },
  );
}

export function listToolCallFacets(client, instanceId) {
  return client._json(
    `/v1/instances/${encodeURIComponent(instanceId)}/audit/tool-calls/facets`,
    { headers: { Accept: 'application/json' } },
  );
}

export async function exportToolCallsNdjson(client, instanceId, filters = {}) {
  const url = `/v1/instances/${encodeURIComponent(instanceId)}/audit/tool-calls/export${toolCallQuery(filters)}`;
  const r = await client._authedFetch(url, { headers: { Accept: 'application/x-ndjson' } });
  if (!r.ok) throw new Error(`GET ${url} failed: ${r.status}`);
  return r.blob();
}

export function streamToolCalls(client, instanceId, filters = {}, onEvent, onError) {
  const controller = new AbortController();
  const url = `/v1/instances/${encodeURIComponent(instanceId)}/audit/tool-calls/stream${toolCallQuery(filters)}`;
  (async () => {
    try {
      const r = await client._authedFetch(url, {
        headers: { Accept: 'text/event-stream' },
        signal: controller.signal,
      });
      if (!r.ok) throw new Error(`GET ${url} failed: ${r.status}`);
      if (!r.body) return;
      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buffer.indexOf('\n\n')) >= 0) {
          const frame = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          const event = parseSseFrame(frame);
          if (event?.event === 'tool_call' && event.data) {
            onEvent(JSON.parse(event.data));
          }
        }
      }
    } catch (err) {
      if (!controller.signal.aborted && onError) onError(err);
    }
  })();
  return () => controller.abort();
}

function parseSseFrame(frame) {
  const out = { event: 'message', data: '' };
  for (const line of frame.split(/\r?\n/)) {
    if (!line || line.startsWith(':')) continue;
    if (line.startsWith('event:')) out.event = line.slice(6).trim();
    else if (line.startsWith('data:')) {
      if (out.data) out.data += '\n';
      out.data += line.slice(5).trimStart();
    }
  }
  return out;
}
