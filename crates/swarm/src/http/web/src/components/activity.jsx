import React from 'react';
import { useApi } from '../hooks/useApi.jsx';
import { exportToolCallsNdjson, listToolCallFacets, listToolCalls, streamToolCalls } from '../api/audit.js';
import { fmtTime } from '../utils/format.js';

const PAGE_LIMIT = 100;
const MEMORY_CAP = 1000;
const RESULT_REFRESH_MS = 1500;

export function ActivityPage({ instanceId, embedded = false }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState(null);
  const [facets, setFacets] = React.useState({ tools: [], servers: [] });
  const [hasSeenRows, setHasSeenRows] = React.useState(false);
  const [selected, setSelected] = React.useState(null);
  const [err, setErr] = React.useState('');
  const [filters, setFilters] = React.useState({ tool: '', status: '', server: '', q: '' });
  const [debounced, setDebounced] = React.useState(filters);
  const [live, setLive] = React.useState(true);
  const [paused, setPaused] = React.useState(false);
  const pausedBuffer = React.useRef([]);
  const toolListId = React.useId();
  const statusListId = React.useId();
  const serverListId = React.useId();

  const mergeIncomingRows = React.useCallback((incoming) => {
    const clean = (Array.isArray(incoming) ? incoming : [incoming]).filter(Boolean);
    if (clean.length === 0) return;
    setHasSeenRows(true);
    if (paused) {
      pausedBuffer.current = mergeRows([...clean, ...pausedBuffer.current]);
      return;
    }
    setRows(prev => mergeRows([...clean, ...(prev || [])]));
  }, [paused]);

  React.useEffect(() => {
    const id = setTimeout(() => setDebounced(filters), 250);
    return () => clearTimeout(id);
  }, [filters]);

  React.useEffect(() => {
    let cancelled = false;
    setErr('');
    listToolCalls(client, instanceId, { ...debounced, limit: PAGE_LIMIT })
      .then(page => {
        if (!cancelled) {
          const items = Array.isArray(page?.items) ? page.items : [];
          if (items.length > 0) setHasSeenRows(true);
          setRows(items);
        }
      })
      .catch(e => {
        if (!cancelled) {
          setRows([]);
          setErr(e?.detail || e?.message || 'activity load failed');
        }
      });
    return () => { cancelled = true; };
  }, [client, instanceId, debounced]);

  React.useEffect(() => {
    let cancelled = false;
    listToolCallFacets(client, instanceId)
      .then(next => {
        if (!cancelled) {
          setFacets({
            tools: Array.isArray(next?.tools) ? next.tools : [],
            servers: Array.isArray(next?.servers) ? next.servers : [],
          });
        }
      })
      .catch(() => {
        if (!cancelled) setFacets({ tools: [], servers: [] });
      });
    return () => { cancelled = true; };
  }, [client, instanceId]);

  React.useEffect(() => {
    if (!live) return undefined;
    return streamToolCalls(
      client,
      instanceId,
      { ...debounced, limit: 50 },
      row => mergeIncomingRows(row),
      e => setErr(e?.message || 'activity stream failed'),
    );
  }, [client, instanceId, debounced, live, mergeIncomingRows]);

  React.useEffect(() => {
    if (!live) return undefined;
    let cancelled = false;
    const id = setInterval(() => {
      listToolCalls(client, instanceId, { ...debounced, limit: PAGE_LIMIT })
        .then(page => {
          if (!cancelled) mergeIncomingRows(page?.items || []);
        })
        .catch(e => {
          if (!cancelled) setErr(e?.detail || e?.message || 'activity refresh failed');
        });
    }, RESULT_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [client, instanceId, debounced, live, mergeIncomingRows]);

  React.useEffect(() => {
    if (paused || pausedBuffer.current.length === 0) return;
    const buffered = pausedBuffer.current;
    pausedBuffer.current = [];
    setRows(prev => mergeRows([...buffered, ...(prev || [])]));
  }, [paused]);

  React.useEffect(() => {
    if (!selected || !Array.isArray(rows)) return;
    const updated = rows.find(row => row.id === selected.id);
    if (updated && updated !== selected) setSelected(updated);
  }, [rows, selected]);

  const toolOptions = mergeOptions(facets.tools, unique(rows, 'tool_name'));
  const serverOptions = mergeOptions(facets.servers, unique(rows, 'mcp_server'));
  const hasRows = Array.isArray(rows) && rows.length > 0;
  const hasAnyRows = hasRows || hasSeenRows || toolOptions.length > 0 || serverOptions.length > 0;
  const visibleRows = (rows || []).slice(0, 250);
  const Shell = embedded ? 'div' : 'main';

  const setFilter = (key, value) => setFilters(f => ({ ...f, [key]: value }));
  const doExport = async () => {
    setErr('');
    try {
      const blob = await exportToolCallsNdjson(client, instanceId, debounced);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `tool-calls-${instanceId}.ndjson`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
    } catch (e) {
      setErr(e?.message || 'export failed');
    }
  };

  return (
    <Shell className={embedded ? 'instance-subpage' : 'page page-edit'}>
      <header className={embedded ? 'subpage-header' : 'page-header'}>
        <h1 className={embedded ? 'subpage-title' : 'page-title'}>activity</h1>
      </header>

      <section className="panel activity-panel">
        <div className="panel-header">
          <div className="panel-title">tool calls</div>
          <div className="panel-actions">
            <button
              type="button"
              className={`btn btn-ghost btn-sm ${live ? 'activity-live-on' : ''}`}
              onClick={() => setLive(v => !v)}
            >
              live ●
            </button>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setPaused(v => !v)}>
              {paused ? 'resume' : 'pause'}
            </button>
            <button type="button" className="btn btn-ghost btn-sm" onClick={doExport} disabled={!hasRows}>
              export
            </button>
          </div>
        </div>

        {err ? <div className="error">{err}</div> : null}

        {rows === null ? (
          <p className="muted small">loading…</p>
        ) : !hasAnyRows ? (
          <p className="muted small">no tool calls yet — the agent hasn't called any tools on this instance.</p>
        ) : (
          <>
            <div className="activity-filters">
              <input
                type="search"
                list={toolListId}
                value={filters.tool}
                onChange={e => setFilter('tool', e.target.value)}
                placeholder="any tool"
                aria-label="tool filter"
              />
              <datalist id={toolListId}>
                {toolOptions.map(t => <option key={t} value={t}/>)}
              </datalist>
              <input
                type="search"
                list={statusListId}
                value={filters.status}
                onChange={e => setFilter('status', e.target.value)}
                placeholder="any status"
                aria-label="status filter"
              />
              <datalist id={statusListId}>
                <option value="ok"/>
                <option value="err"/>
              </datalist>
              <input
                type="search"
                list={serverListId}
                value={filters.server}
                onChange={e => setFilter('server', e.target.value)}
                placeholder="any mcp server"
                aria-label="mcp server filter"
              />
              <datalist id={serverListId}>
                {serverOptions.map(s => <option key={s} value={s}/>)}
              </datalist>
              <input
                type="search"
                value={filters.q}
                onChange={e => setFilter('q', e.target.value)}
                placeholder="search payloads"
                aria-label="search tool payloads"
              />
            </div>
            {!hasRows ? (
              <p className="muted small">no tool calls match these filters.</p>
            ) : (
              <div className="activity-list" role="list">
                {visibleRows.map(row => (
                  <button
                    type="button"
                    key={row.id}
                    className={`activity-row ${row.is_error ? 'activity-row-error' : ''}`}
                    onClick={() => setSelected(row)}
                    role="listitem"
                  >
                    <span className="activity-time">{fmtClock(row.called_at)}</span>
                    <code className="activity-tool">{row.tool_name}</code>
                    <span className="activity-duration">{duration(row)}</span>
                    <span className="activity-status">{row.is_error ? '✗' : row.resulted_at ? '✓' : '…'}</span>
                    <span className="activity-preview">{preview(row.input)}</span>
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </section>

      {selected ? <ActivityDrawer row={selected} onClose={() => setSelected(null)}/> : null}
    </Shell>
  );
}

function ActivityDrawer({ row, onClose }) {
  const json = JSON.stringify(row, null, 2);
  const copy = () => navigator.clipboard?.writeText(json).catch(() => {});
  return (
    <aside className="activity-drawer" role="dialog" aria-label="tool call detail">
      <div className="activity-drawer-head">
        <h2>{row.tool_name}</h2>
        <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>close</button>
      </div>
      <dl className="audit-meta">
        <dt>tool_use_id</dt><dd><code>{row.tool_use_id}</code></dd>
        <dt>called_at</dt><dd>{fmtTime(row.called_at, { style: 'locale' })}</dd>
        <dt>resulted_at</dt><dd>{row.resulted_at ? `${fmtTime(row.resulted_at, { style: 'locale' })} (${duration(row)})` : '…'}</dd>
        {row.mcp_server ? <><dt>mcp_server</dt><dd><code>{row.mcp_server}</code></dd></> : null}
      </dl>
      <h3>input</h3>
      <pre className="audit-body">{JSON.stringify(row.input, null, 2)}</pre>
      <h3>result</h3>
      <pre className="audit-body">{row.result ? JSON.stringify(row.result, null, 2) : '…'}</pre>
      {row.mcp_audit_id ? (
        <>
          <h3>mcp transport</h3>
          <pre className="audit-body">{JSON.stringify({
            mcp_audit_id: row.mcp_audit_id,
            status: row.mcp_status,
            duration_ms: row.mcp_duration_ms,
          }, null, 2)}</pre>
        </>
      ) : null}
      <button type="button" className="btn btn-sm" onClick={copy}>copy as JSON</button>
    </aside>
  );
}

function mergeRows(rows) {
  const seen = new Set();
  const out = [];
  for (const row of rows) {
    if (!row || seen.has(row.id)) continue;
    seen.add(row.id);
    out.push(row);
    if (out.length >= MEMORY_CAP) break;
  }
  return out;
}

function unique(rows, key) {
  return [...new Set((rows || []).map(r => r?.[key]).filter(Boolean))].sort();
}

function mergeOptions(...sets) {
  return [...new Set(sets.flat().filter(Boolean))].sort();
}

function preview(v) {
  if (v == null) return '';
  return JSON.stringify(v).replace(/\s+/g, ' ').slice(0, 80);
}

function duration(row) {
  if (!row.resulted_at) return '…';
  return `${Math.max(0, row.resulted_at - row.called_at)}s`;
}

function fmtClock(ts) {
  const d = new Date(ts * 1000);
  return d.toISOString().slice(11, 23);
}
