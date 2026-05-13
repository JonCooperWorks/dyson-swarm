import React from 'react';
import { useApi } from '../hooks/useApi.jsx';
import { exportToolCallsNdjson, listToolCallFacets, listToolCalls, streamToolCalls } from '../api/audit.js';
import { fmtTime } from '../utils/format.js';

const PAGE_LIMIT = 100;
const MEMORY_CAP = 1000;
const RESULT_REFRESH_MS = 1500;
const DENSITY_KEY = 'dyson.activity.density';
const EMPTY_FILTERS = { tool: '', status: '', server: '', q: '' };

export function ActivityPage({ instanceId, embedded = false }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState(null);
  const rowsRef = React.useRef(null);
  const [facets, setFacets] = React.useState({ tools: [], servers: [] });
  const [hasSeenRows, setHasSeenRows] = React.useState(false);
  const [selected, setSelected] = React.useState(null);
  const [activeIndex, setActiveIndex] = React.useState(0);
  const [err, setErr] = React.useState('');
  const [filters, setFilters] = React.useState(EMPTY_FILTERS);
  const [debounced, setDebounced] = React.useState(filters);
  const [paused, setPaused] = React.useState(false);
  const pausedRef = React.useRef(false);
  const pausedBuffer = React.useRef([]);
  const [bufferedCount, setBufferedCount] = React.useState(0);
  const [newAwayCount, setNewAwayCount] = React.useState(0);
  const [openFilter, setOpenFilter] = React.useState(null);
  const [density, setDensity] = React.useState(readDensity);
  const listRef = React.useRef(null);
  const activityRef = React.useRef(null);
  const atTopRef = React.useRef(true);

  const noteNewRows = React.useCallback((count) => {
    if (!count) return;
    const list = listRef.current;
    if (!list || list.scrollTop <= 50) {
      if (list) list.scrollTop = 0;
      setNewAwayCount(0);
      return;
    }
    setNewAwayCount(n => n + count);
  }, []);

  const mergeIncomingRows = React.useCallback((incoming) => {
    const clean = (Array.isArray(incoming) ? incoming : [incoming]).filter(Boolean);
    if (clean.length === 0) return;
    setHasSeenRows(true);
    if (pausedRef.current) {
      pausedBuffer.current = mergeRows([...clean, ...pausedBuffer.current]);
      setBufferedCount(pausedBuffer.current.length);
      return;
    }

    const prevRows = rowsRef.current || [];
    const prevIds = new Set(prevRows.map(row => row.id));
    const freshCount = clean.filter(row => !prevIds.has(row.id)).length;
    setRows(prev => mergeRows([...clean, ...(prev || [])]));
    noteNewRows(freshCount);
  }, [noteNewRows]);

  React.useEffect(() => {
    rowsRef.current = rows;
  }, [rows]);

  React.useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  React.useEffect(() => {
    const id = setTimeout(() => setDebounced(filters), 250);
    return () => clearTimeout(id);
  }, [filters]);

  React.useEffect(() => {
    let cancelled = false;
    setErr('');
    setNewAwayCount(0);
    listToolCalls(client, instanceId, { ...debounced, limit: PAGE_LIMIT })
      .then(page => {
        if (!cancelled) {
          const items = Array.isArray(page?.items) ? page.items : [];
          if (items.length > 0) setHasSeenRows(true);
          setRows(items);
          setActiveIndex(i => clampIndex(i, items.length));
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

  React.useEffect(() => streamToolCalls(
    client,
    instanceId,
    { ...debounced, limit: 50 },
    row => mergeIncomingRows(row),
    e => setErr(e?.message || 'activity stream failed'),
  ), [client, instanceId, debounced, mergeIncomingRows]);

  React.useEffect(() => {
    let cancelled = false;
    const id = setInterval(() => {
      if (pausedRef.current) return;
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
  }, [client, instanceId, debounced, mergeIncomingRows]);

  React.useEffect(() => {
    if (!selected || !Array.isArray(rows)) return;
    const updated = rows.find(row => row.id === selected.id);
    if (updated && updated !== selected) setSelected(updated);
  }, [rows, selected]);

  React.useEffect(() => {
    const count = (rows || []).length;
    if (count === 0) {
      setActiveIndex(0);
      return;
    }
    setActiveIndex(i => clampIndex(i, count));
  }, [rows]);

  React.useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key !== 'Escape') return;
      setSelected(null);
      setOpenFilter(null);
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, []);

  const toolOptions = mergeOptions(facets.tools, unique(rows, 'tool_name'));
  const serverOptions = mergeOptions(facets.servers, unique(rows, 'mcp_server'));
  const hasRows = Array.isArray(rows) && rows.length > 0;
  const hasAnyRows = hasRows || hasSeenRows || toolOptions.length > 0 || serverOptions.length > 0;
  const hasActiveFilters = Object.values(filters).some(Boolean);
  const visibleRows = (rows || []).slice(0, 250);
  const Shell = embedded ? 'div' : 'main';

  const setFilter = (key, value) => {
    setFilters(f => ({ ...f, [key]: value }));
    setOpenFilter(null);
  };
  const clearFilter = (key) => setFilter(key, '');
  const clearAllFilters = () => {
    setFilters(EMPTY_FILTERS);
    setOpenFilter(null);
  };
  const setSearch = (value) => setFilters(f => ({ ...f, q: value }));
  const toggleDensity = () => {
    setDensity(current => {
      const next = current === 'compact' ? 'comfortable' : 'compact';
      writeDensity(next);
      return next;
    });
  };
  const resumePaused = () => {
    const buffered = pausedBuffer.current;
    pausedBuffer.current = [];
    setBufferedCount(0);
    setPaused(false);
    if (buffered.length > 0) {
      setRows(prev => mergeRows([...buffered, ...(prev || [])]));
      setHasSeenRows(true);
      requestAnimationFrameSafe(() => {
        if (listRef.current) listRef.current.scrollTop = 0;
      });
      setNewAwayCount(0);
    }
  };
  const togglePaused = () => {
    if (paused) {
      resumePaused();
    } else {
      setPaused(true);
    }
  };
  const jumpToTop = () => {
    if (listRef.current) listRef.current.scrollTop = 0;
    atTopRef.current = true;
    setNewAwayCount(0);
  };
  const onListScroll = () => {
    atTopRef.current = (listRef.current?.scrollTop || 0) <= 50;
    if (atTopRef.current) setNewAwayCount(0);
  };
  const selectRow = (row, index) => {
    setActiveIndex(index);
    setSelected(row);
  };
  const onActivityKeyDown = (event) => {
    if (isTextInput(event.target) || isPopoverTarget(event.target)) return;
    if (event.key === 'j') {
      event.preventDefault();
      setActiveIndex(i => clampIndex(i + 1, visibleRows.length));
    } else if (event.key === 'k') {
      event.preventDefault();
      setActiveIndex(i => clampIndex(i - 1, visibleRows.length));
    } else if (event.key === 'Enter') {
      const row = visibleRows[activeIndex];
      if (row) {
        event.preventDefault();
        setSelected(row);
      }
    } else if (event.key === 'Escape') {
      event.preventDefault();
      setSelected(null);
      setOpenFilter(null);
    }
  };
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

      <section
        className="panel activity-panel"
        role="region"
        aria-label="tool-call activity"
        tabIndex={0}
        ref={activityRef}
        onKeyDown={onActivityKeyDown}
      >
        <div className="panel-header">
          <div className="panel-title">tool calls</div>
        </div>

        {err ? <div className="error">{err}</div> : null}

        {rows === null ? (
          <p className="muted small">loading…</p>
        ) : (
          <>
            {(hasAnyRows || hasActiveFilters) ? (
              <div className="activity-toolbar">
                <div className="activity-filter-strip" aria-label="activity filters">
                  <FilterChip
                    label="tool"
                    value={filters.tool}
                    options={toolOptions}
                    open={openFilter === 'tool'}
                    onOpen={() => setOpenFilter(openFilter === 'tool' ? null : 'tool')}
                    onSelect={value => setFilter('tool', value)}
                    onClear={() => clearFilter('tool')}
                  />
                  <FilterChip
                    label="status"
                    value={filters.status}
                    options={['ok', 'err']}
                    open={openFilter === 'status'}
                    onOpen={() => setOpenFilter(openFilter === 'status' ? null : 'status')}
                    onSelect={value => setFilter('status', value)}
                    onClear={() => clearFilter('status')}
                  />
                  <FilterChip
                    label="server"
                    value={filters.server}
                    options={serverOptions}
                    open={openFilter === 'server'}
                    onOpen={() => setOpenFilter(openFilter === 'server' ? null : 'server')}
                    onSelect={value => setFilter('server', value)}
                    onClear={() => clearFilter('server')}
                  />
                  <input
                    className="activity-search-input"
                    type="search"
                    value={filters.q}
                    onChange={e => setSearch(e.target.value)}
                    placeholder="search payloads"
                    aria-label="search tool payloads"
                  />
                  {filters.q ? (
                    <button type="button" className="activity-chip-clear activity-search-clear" onClick={() => setSearch('')} aria-label="clear payload search">
                      x
                    </button>
                  ) : null}
                  <button type="button" className="activity-density-toggle" onClick={toggleDensity}>
                    density: {density}
                  </button>
                  <button
                    type="button"
                    className={`activity-live-button ${paused ? 'activity-live-paused' : 'activity-live-on'}`}
                    onClick={togglePaused}
                  >
                    {paused ? `paused${bufferedCount ? ` · ${bufferedCount} new` : ''}` : 'live'}
                  </button>
                  <button type="button" className="btn btn-ghost btn-sm" onClick={doExport} disabled={!hasRows}>
                    export
                  </button>
                </div>
              </div>
            ) : null}

            {!hasRows ? (
              hasActiveFilters ? (
                <div className="activity-empty-filtered">
                  <p className="muted small">no calls match these filters — clear filters</p>
                  <button type="button" className="btn btn-ghost btn-sm" onClick={clearAllFilters}>clear filters</button>
                </div>
              ) : (
                <p className="muted small">no tool calls yet — the agent hasn't called any tools on this instance.</p>
              )
            ) : (
              <>
                {newAwayCount > 0 ? (
                  <button type="button" className="activity-new-pill" onClick={jumpToTop}>↑ {newAwayCount} new</button>
                ) : null}
                <div
                  className={`activity-list activity-density-${density}`}
                  role="list"
                  ref={listRef}
                  onScroll={onListScroll}
                >
                  {visibleRows.map((row, index) => (
                    <ActivityRow
                      key={row.id}
                      row={row}
                      active={index === activeIndex}
                      selected={selected?.id === row.id}
                      onClick={() => selectRow(row, index)}
                    />
                  ))}
                </div>
              </>
            )}
          </>
        )}
      </section>

      {selected ? <ActivityDrawer row={selected} onClose={() => setSelected(null)}/> : null}
    </Shell>
  );
}

function FilterChip({ label, value, options, open, onOpen, onSelect, onClear }) {
  const active = Boolean(value);
  const shown = active ? value : 'all';
  const allOptions = [''].concat(options || []);
  return (
    <div className="activity-filter-chip-wrap">
      <div className={`activity-filter-chip ${active ? 'activity-filter-chip-active' : ''}`}>
        <button type="button" className="activity-filter-chip-main" onClick={onOpen}>
          <span>{label}: {shown}</span>
          <span aria-hidden="true">▼</span>
        </button>
        {active ? (
          <button type="button" className="activity-chip-clear" onClick={onClear} aria-label={`clear ${label} filter`}>
            x
          </button>
        ) : null}
      </div>
      {open ? (
        <div className="activity-filter-popover" role="listbox" aria-label={`${label} options`}>
          {allOptions.map(option => {
            const optionLabel = option || 'all';
            return (
              <button
                type="button"
                role="option"
                aria-selected={option === value}
                key={optionLabel}
                className={option === value ? 'selected' : ''}
                onClick={() => onSelect(option)}
              >
                {optionLabel}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function ActivityRow({ row, active, selected, onClick }) {
  const state = rowState(row);
  const durationInfo = duration(row);
  return (
    <button
      type="button"
      className={[
        'activity-row',
        row.is_error ? 'activity-row-error' : '',
        state === 'pending' ? 'activity-row-pending' : '',
        state === 'stale' ? 'activity-row-stale' : '',
        active ? 'activity-row-active' : '',
        selected ? 'activity-row-selected' : '',
      ].filter(Boolean).join(' ')}
      onClick={onClick}
      role="listitem"
      aria-current={active ? 'true' : undefined}
    >
      <span className="activity-time" title={new Date(row.called_at * 1000).toISOString()}>{fmtClock(row.called_at)}</span>
      <code className="activity-tool">{row.tool_name}</code>
      <span className="activity-duration" title={durationInfo.title}>
        {state === 'pending' || state === 'stale' ? (
          <span
            className={`activity-duration-dot ${state === 'stale' ? 'activity-duration-stale' : 'activity-duration-pending'}`}
            title={state === 'stale' ? 'no result yet' : 'waiting for result'}
            aria-label={`${row.tool_use_id} ${state === 'stale' ? 'has no result yet' : 'is waiting for a tool result'}`}
          />
        ) : durationInfo.label}
      </span>
      <span className="activity-status">{row.is_error ? '✗' : row.resulted_at ? '✓' : '…'}</span>
      <span className="activity-preview">{preview(row.input)}</span>
    </button>
  );
}

function ActivityDrawer({ row, onClose }) {
  const json = JSON.stringify(row, null, 2);
  const transport = row.mcp_audit_id ? {
    mcp_audit_id: row.mcp_audit_id,
    status: row.mcp_status,
    duration_ms: row.mcp_duration_ms,
  } : null;

  React.useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  return (
    <aside className="activity-drawer" role="dialog" aria-label="tool call detail">
      <div className="activity-drawer-head">
        <div>
          <h2>{row.tool_name}</h2>
          <code>{row.tool_use_id}</code>
        </div>
        <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>close</button>
      </div>
      <dl className="audit-meta">
        <dt>called_at</dt><dd>{fmtTime(row.called_at, { style: 'locale' })}</dd>
        <dt>resulted_at</dt><dd>{row.resulted_at ? `${fmtTime(row.resulted_at, { style: 'locale' })} (${duration(row).label})` : '…'}</dd>
        {row.mcp_server ? <><dt>mcp_server</dt><dd><code>{row.mcp_server}</code></dd></> : null}
      </dl>
      <button type="button" className="btn btn-sm activity-copy-json" onClick={() => copyText(json)}>copy as JSON</button>
      <AuditPre title="input" value={row.input}/>
      <AuditPre title="result" value={row.result}/>
      {transport ? <AuditPre title="mcp transport" value={transport} className="activity-drawer-transport"/> : null}
    </aside>
  );
}

function AuditPre({ title, value, className = '' }) {
  const text = value == null ? '…' : JSON.stringify(value, null, 2);
  return (
    <section className={`activity-pre-block ${className}`.trim()}>
      <div className="activity-pre-head">
        <h3>{title}</h3>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => copyText(text)}>copy</button>
      </div>
      <pre className="audit-body">{text}</pre>
    </section>
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
  if (!row.resulted_at) return { label: '…', title: 'no result yet' };
  const seconds = Math.max(0, row.resulted_at - row.called_at);
  if (seconds < 1) return { label: `${Math.round(seconds * 1000)}ms`, title: `${Math.round(seconds * 1_000_000)}us` };
  if (seconds < 60) return { label: `${seconds.toFixed(1)}s`, title: `${Math.round(seconds * 1_000_000)}us` };
  const whole = Math.round(seconds);
  const minutes = Math.floor(whole / 60);
  const rest = String(whole % 60).padStart(2, '0');
  return { label: `${minutes}:${rest}`, title: `${Math.round(seconds * 1_000_000)}us` };
}

function rowState(row) {
  if (row.resulted_at) return row.is_error ? 'error' : 'paired';
  const age = Date.now() / 1000 - row.called_at;
  return age > 30 ? 'stale' : 'pending';
}

function fmtClock(ts) {
  return new Date(ts * 1000).toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function clampIndex(index, count) {
  if (count <= 0) return 0;
  return Math.min(Math.max(index, 0), count - 1);
}

function isTextInput(target) {
  const tag = target?.tagName?.toLowerCase();
  return tag === 'input' || tag === 'textarea' || target?.isContentEditable;
}

function isPopoverTarget(target) {
  return Boolean(target?.closest?.('.activity-filter-popover') || target?.closest?.('.activity-filter-chip'));
}

function copyText(text) {
  return navigator.clipboard?.writeText(text).catch(() => {});
}

function readDensity() {
  try {
    return window.localStorage.getItem(DENSITY_KEY) === 'compact' ? 'compact' : 'comfortable';
  } catch {
    return 'comfortable';
  }
}

function writeDensity(value) {
  try {
    window.localStorage.setItem(DENSITY_KEY, value);
  } catch {
    // Local storage is a convenience only; losing it should not break Activity.
  }
}

function requestAnimationFrameSafe(fn) {
  if (typeof requestAnimationFrame === 'function') {
    requestAnimationFrame(fn);
  } else {
    setTimeout(fn, 0);
  }
}
