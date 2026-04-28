/* swarm — Instances view (list + detail + create modal).
 *
 * Two-pane layout: left rail lists every instance the caller owns,
 * the right pane shows whichever id the URL hash names.  Hash routing
 * keeps deep-links stable across IdP redirects (the OIDC return URL
 * is always `/`, so the hash is the only thing the IdP doesn't
 * mangle).
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import {
  upsertInstance, removeInstance, selectInstance, setLoadError, setInstances,
} from '../store/app.js';

export function InstancesView({ view }) {
  const selectedId = view.name === 'instance' ? view.id : null;
  React.useEffect(() => {
    selectInstance(selectedId);
  }, [selectedId]);

  return (
    <div className="instances-pane">
      <InstanceList selectedId={selectedId}/>
      <InstanceDetail id={selectedId}/>
    </div>
  );
}

// ─── List ─────────────────────────────────────────────────────────

function InstanceList({ selectedId }) {
  const { client } = useApi();
  const { byId, order } = useAppState(s => s.instances);
  const [creating, setCreating] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);

  const refresh = React.useCallback(async () => {
    setRefreshing(true);
    try {
      const list = await client.listInstances();
      setInstances(Array.isArray(list) ? list : []);
    } catch (err) {
      setLoadError(err?.message || 'list failed');
    } finally {
      setRefreshing(false);
    }
  }, [client]);

  // Light polling so a TTL sweeper that destroys an instance under us
  // surfaces in the UI without a manual refresh.  30s is long enough
  // not to hammer the API but short enough to feel live.
  React.useEffect(() => {
    const id = setInterval(() => {
      if (!document.hidden) refresh();
    }, 30_000);
    return () => clearInterval(id);
  }, [refresh]);

  return (
    <aside className="left-rail">
      <div className="rail-header">
        <div className="rail-title">your instances</div>
        <div className="rail-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={refreshing} title="refresh">
            {refreshing ? '…' : '↻'}
          </button>
          <button className="btn btn-sm" onClick={() => setCreating(true)}>new</button>
        </div>
      </div>
      <ul className="rail-list">
        {order.length === 0 ? (
          <li className="rail-empty muted small">no instances. click "new" to spin one up.</li>
        ) : order.map(id => {
          const row = byId[id];
          const label = row.name && row.name.trim() ? row.name : `(unnamed) ${shortId(id)}`;
          return (
            <li key={id} className={`rail-row ${selectedId === id ? 'selected' : ''}`}>
              <a href={`#/i/${encodeURIComponent(id)}`}>
                <div className="rail-row-name">{label}</div>
                <div className="rail-row-id muted small">{shortId(id)}</div>
                <div className="rail-row-meta">
                  <StatusBadge status={row.status}/>
                  <span className="muted small">{row.template_id}</span>
                </div>
              </a>
            </li>
          );
        })}
      </ul>
      {creating ? <CreateModal onClose={() => setCreating(false)} onCreated={refresh}/> : null}
    </aside>
  );
}

function StatusBadge({ status }) {
  const cls = status === 'live' ? 'ok'
            : status === 'creating' ? 'warn'
            : status === 'destroyed' ? 'faint'
            : 'warn';
  return <span className={`badge badge-${cls}`}>{status}</span>;
}

// ─── Create modal — onboarding-shaped ──────────────────────────────
//
// Each Dyson is an employee.  The form reads top-down like an offer
// letter: who they are, what they do, then the boring infrastructure
// bits (template, ttl) collapsed under "advanced".

function CreateModal({ onClose, onCreated }) {
  const { client, auth } = useApi();
  const [name, setName] = React.useState('');
  const [task, setTask] = React.useState('');
  // Model ids the agent can pick from.  One labelled suggestion
  // group ("default", from operator-curated `default_models` in
  // /etc/dyson-swarm/config.toml via /auth/config) plus free-form
  // text input for anything else (any OpenRouter id, comma- and
  // space-tolerant).  First selected model becomes SWARM_MODEL
  // (legacy single-pick env); the full list is passed as
  // SWARM_MODELS (csv) for agents that support failover/rotation.
  const defaultModels = auth?.config?.default_models || [];
  const [models, setModels] = React.useState(
    defaultModels.length ? [defaultModels[0]] : []
  );
  // Operator-configured default from `default_template_id` in
  // /etc/dyson-swarm/config.toml, surfaced via /auth/config.  Fall
  // back to a placeholder string only when the deployment hasn't
  // configured one — submit is gated on `templateId.trim()` so the
  // user sees the field empty and is forced to fill it in.
  const [templateId, setTemplateId] = React.useState(
    auth?.config?.default_template_id || ''
  );
  const [ttlSeconds, setTtlSeconds] = React.useState('');
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  // Two-phase flow: 'form' (fill in) → 'provisioning' (POSTed; waiting
  // on the server, which now also pre-warms Caddy's on_demand TLS
  // before returning so the user's first "open ↗" click works).
  const [phase, setPhase] = React.useState('form');

  const submit = async (e) => {
    e.preventDefault();
    if (!templateId.trim() || models.length === 0) return;
    setSubmitting(true);
    setError(null);
    try {
      const req = {
        template_id: templateId.trim(),
        env: {
          // First-pick stays under the legacy single-model env so
          // Dyson agents that read SWARM_MODEL keep working.
          SWARM_MODEL: models[0],
          // Full ordered list — Dyson agents that support multiple
          // models (failover, A/B) split this on commas.
          SWARM_MODELS: models.join(','),
        },
      };
      if (name.trim()) req.name = name.trim();
      if (task.trim()) req.task = task.trim();
      const ttl = ttlSeconds.trim() ? Number(ttlSeconds) : null;
      if (Number.isFinite(ttl) && ttl > 0) req.ttl_seconds = ttl;

      setPhase('provisioning');
      // Server blocks until the sandbox is Live AND Caddy's TLS cert
      // is provisioned (pre-warmed inside instance.create()), so by
      // the time this resolves the new dyson is fully reachable.
      const result = await client.createInstance(req);
      onCreated && onCreated();

      if (result?.id) {
        window.location.hash = `#/i/${encodeURIComponent(result.id)}`;
      }
      onClose && onClose();
      return;
    } catch (err) {
      setError(err?.detail || err?.message || 'create failed');
      setPhase('form');
    } finally {
      setSubmitting(false);
    }
  };

  if (phase === 'provisioning') {
    return (
      <ModalShell onClose={null} title="provisioning">
        <p className="muted small">getting your dyson ready…</p>
        <div className="progress-bar"><div className="progress-bar-indeterminate"/></div>
        <p className="muted small" style={{ marginTop: 12 }}>
          By the time this closes, your dyson is live and reachable.
        </p>
      </ModalShell>
    );
  }

  return (
    <ModalShell onClose={onClose} title="hire a new dyson">
      <form onSubmit={submit} className="form">
        <label className="field">
          <span>name</span>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="PR reviewer for foo/bar"
            autoFocus
          />
        </label>
        <label className="field">
          <span>task</span>
          <textarea
            className="textarea"
            value={task}
            onChange={e => setTask(e.target.value)}
            placeholder="What this employee does, in prose. Example:\n\nWatch for new PRs in github.com/foo/bar. Comment with style-guide violations and link to the relevant section. Don't approve or merge."
            rows={6}
          />
          <span className="hint muted small">
            The agent reads this on first boot as <code>SWARM_TASK</code>.
            You can edit it later, but changes don't propagate to a
            running employee.
          </span>
        </label>
        <ModelMultiPicker
          defaultModels={defaultModels}
          selected={models}
          onChange={setModels}
        />
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => setShowAdvanced(s => !s)}
        >
          {showAdvanced ? '▾ advanced' : '▸ advanced'}
        </button>
        {showAdvanced ? (
          <>
            <label className="field">
              <span>template id</span>
              <input
                value={templateId}
                onChange={e => setTemplateId(e.target.value)}
                placeholder="dyson-default"
                required
              />
            </label>
            <label className="field">
              <span>ttl (seconds, optional)</span>
              <input
                value={ttlSeconds}
                onChange={e => setTtlSeconds(e.target.value)}
                placeholder="86400"
                inputMode="numeric"
              />
            </label>
          </>
        ) : null}
        {error ? <div className="error">{error}</div> : null}
        <div className="modal-actions">
          <button
            type="submit"
            className="btn btn-primary"
            disabled={submitting || models.length === 0}
            title={models.length === 0 ? 'pick at least one model' : ''}
          >
            {submitting ? 'hiring…' : 'hire'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClose}>cancel</button>
        </div>
      </form>
    </ModalShell>
  );
}

// Multi-select with two labelled suggestion sources: the swarm's
// operator-curated `default_models` ("default") and the configured
// upstream provider's full catalogue ("openrouter") fetched via
// /v1/models — never directly from openrouter.ai.  Free-form text
// input accepts any other id with Enter, comma, or space (when the
// input contains "/"); selected models render as removable chips
// above the input, ordered (first = primary).
function ModelMultiPicker({ defaultModels, selected, onChange }) {
  const { client } = useApi();
  const [input, setInput] = React.useState('');
  const [upstreamModels, setUpstreamModels] = React.useState(null); // null=loading, [] on err
  const [upstreamError, setUpstreamError] = React.useState(null);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const body = await client.listProviderModels();
        const ids = Array.isArray(body?.models) ? body.models.filter(Boolean) : [];
        if (!cancelled) setUpstreamModels(ids);
      } catch (e) {
        if (!cancelled) {
          setUpstreamModels([]);
          setUpstreamError(
            e?.status === 503
              ? 'no upstream provider configured'
              : (e?.message || 'fetch failed'),
          );
        }
      }
    })();
    return () => { cancelled = true; };
  }, [client]);

  const add = (id) => {
    const v = id.trim();
    if (!v) return;
    if (selected.includes(v)) return;
    onChange([...selected, v]);
  };
  const remove = (id) => onChange(selected.filter(m => m !== id));
  const onKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ',' || (e.key === ' ' && input.includes('/'))) {
      e.preventDefault();
      add(input);
      setInput('');
    } else if (e.key === 'Backspace' && !input && selected.length) {
      remove(selected[selected.length - 1]);
    }
  };

  const filter = input.trim().toLowerCase();
  const matches = (id) =>
    !selected.includes(id) && (!filter || id.toLowerCase().includes(filter));
  const defaultMatches = defaultModels.filter(matches);
  const upstreamMatches = (upstreamModels || []).filter(matches).slice(0, 12);

  return (
    <div className="field">
      <span>models</span>
      <div className="chip-input">
        {selected.map((m, i) => (
          <span key={m} className={`chip ${i === 0 ? 'chip-primary' : ''}`}>
            <code className="mono-sm">{m}</code>
            <button
              type="button"
              className="chip-x"
              aria-label={`remove ${m}`}
              onClick={() => remove(m)}
            >×</button>
          </span>
        ))}
        <input
          className="chip-input-text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder={selected.length === 0 ? 'pick at least one model' : 'add another…'}
        />
      </div>
      <div className="model-suggestions">
        {defaultMatches.length > 0 ? (
          <div className="model-suggestion-group">
            <div className="model-suggestion-label">default</div>
            <div className="model-suggestion-chips">
              {defaultMatches.map(id => (
                <button
                  key={id}
                  type="button"
                  className="chip chip-add"
                  onClick={() => add(id)}
                >+ <code className="mono-sm">{id}</code></button>
              ))}
            </div>
          </div>
        ) : null}
        <div className="model-suggestion-group">
          <div className="model-suggestion-label">
            openrouter
            {upstreamModels === null ? <span className="muted small"> · loading…</span>
             : upstreamError ? <span className="muted small"> · {upstreamError}</span>
             : null}
          </div>
          <div className="model-suggestion-chips">
            {upstreamMatches.map(id => (
              <button
                key={id}
                type="button"
                className="chip chip-add"
                onClick={() => add(id)}
              >+ <code className="mono-sm">{id}</code></button>
            ))}
            {upstreamModels !== null && upstreamMatches.length === 0 && filter ? (
              <span className="muted small">no openrouter matches for "{filter}" — press Enter to add it as a custom id</span>
            ) : null}
          </div>
        </div>
      </div>
      <span className="hint muted small">
        First chip is the primary; agents that support multiple models
        try the rest in order.  Type any model id and press Enter to
        add a custom one.
      </span>
    </div>
  );
}

function ModalShell({ title, onClose, children }) {
  // ESC closes.  Click on the scrim closes; click on the panel doesn't.
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose && onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} role="dialog" aria-label={title}>
        <header className="modal-header">{title}</header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

function KvField({ label, value }) {
  const [copied, setCopied] = React.useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value || '');
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch { /* ignore */ }
  };
  return (
    <div className="kv">
      <div className="kv-label">{label}</div>
      <div className="kv-value">
        <code>{value}</code>
        <button className="btn btn-ghost btn-sm" onClick={copy}>
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
    </div>
  );
}

// ─── Detail ───────────────────────────────────────────────────────

function InstanceDetail({ id }) {
  const { client } = useApi();
  const row = useAppState(s => (id ? s.instances.byId[id] : null));
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);
  // Hoisted above the conditional returns so the hook order is stable
  // across renders — otherwise React's useState slot count differs
  // between the "no id / no row" early-return paths and the full
  // render, which throws "rendered fewer hooks than expected" and
  // leaves the pane blank.
  const [editing, setEditing] = React.useState(false);

  // Pull fresh detail when selection changes (the list view's row is a
  // strict subset of the InstanceView shape, so re-fetching catches
  // probe times and other detail-only fields).
  React.useEffect(() => {
    if (!id) return;
    let cancelled = false;
    client.getInstance(id).then(detail => {
      if (!cancelled && detail) upsertInstance(detail);
    }).catch(e => {
      if (!cancelled) setErr(e?.message || 'fetch failed');
    });
    return () => { cancelled = true; };
  }, [client, id]);

  // Background TLS warm-up for `<id>.<hostname>` whenever the detail
  // page first appears for an instance.  Caddy fronts each Dyson with
  // on_demand TLS, so the very first request to a fresh subdomain
  // triggers a Let's Encrypt round-trip (~5–15s) — without warming
  // the user's first "open ↗" click races the ACME flow and shows
  // about:blank.
  //
  // Two complementary mechanisms:
  //   1. `<link rel="preconnect">` injected into <head> — a strong
  //      hint that tells modern browsers to do TCP + TLS handshake
  //      against the origin in the background, before any nav.
  //   2. A no-cors fetch — actually consummates the request even on
  //      browsers that ignore the preconnect hint.  no-cors means we
  //      don't read the body; the TLS handshake is the whole point.
  //
  // Both fire-and-forget; failures are expected (cold cert, network
  // blip) and never surfaced to the user.
  const openUrl = row?.open_url;
  React.useEffect(() => {
    if (!openUrl) return;
    let origin;
    try { origin = new URL(openUrl).origin; } catch { return; }

    const link = document.createElement('link');
    link.rel = 'preconnect';
    link.href = origin;
    link.crossOrigin = 'use-credentials';
    document.head.appendChild(link);

    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 20_000);
    fetch(openUrl, { mode: 'no-cors', credentials: 'include', signal: ctrl.signal })
      .catch(() => { /* expected for cold cert / network blips */ })
      .finally(() => clearTimeout(t));

    return () => {
      clearTimeout(t);
      ctrl.abort();
      link.remove();
    };
  }, [openUrl]);

  if (!id) return <EmptyDetail/>;
  if (!row) return <main className="detail-pane"><p className="muted">loading…</p></main>;

  const probe = async () => {
    setBusy(true); setErr(null);
    try {
      const result = await client.probeInstance(id);
      // probe returns { result: "healthy" | ... }; refetch row to pick
      // up the updated last_probe_at / last_probe_status the handler
      // wrote inline.
      const next = await client.getInstance(id);
      if (next) upsertInstance(next);
      return result;
    } catch (e) {
      setErr(e?.message || 'probe failed');
    } finally {
      setBusy(false);
    }
  };

  const destroy = async () => {
    if (!confirm(`destroy instance ${id}? this is permanent.`)) return;
    setBusy(true); setErr(null);
    try {
      await client.destroyInstance(id);
      removeInstance(id);
      window.location.hash = '#/';
    } catch (e) {
      setErr(e?.message || 'destroy failed');
      setBusy(false);
    }
  };

  const displayName = row.name && row.name.trim() ? row.name : '(unnamed)';
  // open_url is computed by the backend from `[server] hostname` + the
  // instance id.  Null when swarm has no hostname configured (the
  // host-based proxy is a no-op in that case) — that's the only case
  // we hard-disable the link, since there's literally nowhere to go.
  //
  // For status≠live or no sandbox yet we still ship the href: the user
  // explicitly wants a plain `target="_blank"` to navigate.  Without an
  // href the browser opens about:blank in the new tab, which is worse
  // than landing on a 502 / "still warming up" page they can refresh.
  const canOpen = !!row.open_url;
  const isWarmingUp = canOpen && (row.status !== 'live' || !row.cube_sandbox_id);

  return (
    <main className="detail-pane">
      <header className="detail-header">
        <div className="employee-card">
          <h2 className="employee-name">{displayName}</h2>
          <div className="detail-sub muted small">
            <code className="mono-sm">{row.id}</code> ·{' '}
            <StatusBadge status={row.status}/>{' '}
            {row.pinned ? <span className="badge badge-info">pinned</span> : null}
            {' · '}template <code>{row.template_id}</code>
          </div>
          <div className="employee-task">
            {row.task && row.task.trim() ? (
              <p className="task-prose">{row.task}</p>
            ) : (
              <p className="muted small">
                no task description — click <em>edit</em> to write one.
              </p>
            )}
          </div>
        </div>
        <div className="detail-actions">
          <a
            className={`btn btn-primary ${canOpen ? '' : 'btn-disabled'}`}
            href={canOpen ? row.open_url : undefined}
            target="_blank"
            rel="noopener noreferrer"
            aria-disabled={!canOpen}
            onClick={(e) => { if (!canOpen) e.preventDefault(); }}
            title={
              !canOpen
                ? 'swarm hostname is not configured — set [server] hostname in config.toml'
                : isWarmingUp
                  ? 'sandbox is still warming up — opening anyway'
                  : 'open this dyson in a new tab'
            }
          >
            open ↗
          </a>
          <button className="btn btn-ghost" onClick={() => setEditing(true)} disabled={busy}>edit</button>
          <button className="btn btn-ghost" onClick={probe} disabled={busy}>probe</button>
          <button className="btn btn-danger" onClick={destroy} disabled={busy || row.status === 'destroyed'}>
            destroy
          </button>
        </div>
      </header>

      <section className="panel">
        <div className="panel-title">runtime</div>
        <KvRow label="cube sandbox id" value={row.cube_sandbox_id || '—'}/>
        <KvRow label="created" value={fmtTime(row.created_at)}/>
        <KvRow label="last active" value={fmtTime(row.last_active_at)}/>
        <KvRow label="expires" value={row.expires_at ? fmtTime(row.expires_at) : 'never'}/>
        <KvRow label="last probe" value={
          row.last_probe_at
            ? `${fmtTime(row.last_probe_at)} · ${probeLabel(row.last_probe_status)}`
            : 'never'
        }/>
        {row.destroyed_at ? <KvRow label="destroyed" value={fmtTime(row.destroyed_at)}/> : null}
      </section>

      {err ? <div className="error">{err}</div> : null}

      <SnapshotsPanel instanceId={id} disabled={row.status === 'destroyed'}/>
      <SecretsPanel instanceId={id}/>

      {editing ? (
        <EditEmployeeModal
          instance={row}
          onClose={() => setEditing(false)}
          onSaved={(updated) => {
            upsertInstance(updated);
            setEditing(false);
          }}
        />
      ) : null}
    </main>
  );
}

// ─── Edit name + task ─────────────────────────────────────────────

function EditEmployeeModal({ instance, onClose, onSaved }) {
  const { client, auth } = useApi();
  const [name, setName] = React.useState(instance.name || '');
  const [task, setTask] = React.useState(instance.task || '');
  // Models picker reuses the same component as the create form,
  // sourced from operator-curated `default_models` plus the live
  // /v1/models upstream catalogue.  Pre-fills with the current
  // primary model when available; the agent will also accept any
  // other model id the user types.
  const initialModels = (instance.models && instance.models.length)
    ? instance.models
    : (instance.model ? [instance.model] : []);
  const [models, setModels] = React.useState(initialModels);
  const defaultModels = auth?.config?.default_models || [];
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true); setError(null);
    try {
      const payload = { name, task };
      // Only include models if the user actually picked any —
      // backend treats missing/empty as "leave unchanged".
      if (models.length > 0) payload.models = models;
      const updated = await client.updateInstance(instance.id, payload);
      onSaved && onSaved(updated);
    } catch (err) {
      setError(err?.detail || err?.message || 'save failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ModalShell onClose={onClose} title="edit employee">
      <form onSubmit={submit} className="form">
        <label className="field">
          <span>name</span>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="PR reviewer for foo/bar"
            autoFocus
          />
        </label>
        <label className="field">
          <span>task</span>
          <textarea
            className="textarea"
            value={task}
            onChange={e => setTask(e.target.value)}
            rows={6}
          />
          <span className="hint muted small">
            Saving rewrites the dyson's IDENTITY.md (mission section)
            via /api/admin/configure — the agent picks it up on the
            next turn (no restart).
          </span>
        </label>
        <ModelMultiPicker
          defaultModels={defaultModels}
          selected={models}
          onChange={setModels}
        />
        {error ? <div className="error">{error}</div> : null}
        <div className="modal-actions">
          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'saving…' : 'save'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClose}>cancel</button>
        </div>
      </form>
    </ModalShell>
  );
}

function EmptyDetail() {
  return (
    <main className="detail-pane detail-empty">
      <div className="muted">select an instance, or click "new" to create one.</div>
    </main>
  );
}

function KvRow({ label, value }) {
  return (
    <div className="kvrow">
      <div className="kvrow-label">{label}</div>
      <div className="kvrow-value"><code>{value}</code></div>
    </div>
  );
}

// ─── Snapshots panel ─────────────────────────────────────────────

function SnapshotsPanel({ instanceId, disabled }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);

  const refresh = React.useCallback(async () => {
    try {
      const list = await client.listSnapshotsForInstance(instanceId);
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.message || 'list snapshots failed');
    }
  }, [client, instanceId]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const take = async (mode) => {
    setBusy(true); setErr(null);
    try {
      const fn = mode === 'backup' ? client.backupInstance : client.snapshotInstance;
      await fn.call(client, instanceId);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || `${mode} failed`);
    } finally {
      setBusy(false);
    }
  };

  const restore = async (snapshotId) => {
    if (!confirm('Restoring forks a brand-new instance from this snapshot. Continue?')) return;
    setBusy(true); setErr(null);
    try {
      const created = await client.restoreInstance({
        instance_id: instanceId,
        snapshot_id: snapshotId,
      });
      // Restore returns a CreatedInstance (new id, bearer, proxy_token).
      // The bearer/proxy tokens are sensitive but already shown at create
      // time; for restore we just navigate to the new detail page.
      if (created?.id) {
        window.location.hash = `#/i/${encodeURIComponent(created.id)}`;
      }
    } catch (e) {
      setErr(e?.detail || e?.message || 'restore failed');
    } finally {
      setBusy(false);
    }
  };

  const pull = async (snapshotId) => {
    setBusy(true); setErr(null);
    try {
      await client.pullSnapshot(snapshotId);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'pull failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">snapshots</div>
        <div className="panel-actions">
          <button className="btn btn-sm" onClick={() => take('snapshot')} disabled={busy || disabled}>
            snapshot
          </button>
          <button className="btn btn-sm" onClick={() => take('backup')} disabled={busy || disabled}
                  title="snapshot then promote to the configured backup sink">
            backup
          </button>
        </div>
      </div>
      {err ? <div className="error">{err}</div> : null}
      {rows === null ? (
        <p className="muted small">loading…</p>
      ) : rows.length === 0 ? (
        <p className="muted small">no snapshots yet.</p>
      ) : (
        <table className="rows">
          <thead><tr>
            <th>id</th><th>kind</th><th>created</th><th>remote</th><th></th>
          </tr></thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id}>
                <td><code className="mono-sm">{r.id}</code></td>
                <td><span className="badge badge-faint">{r.kind}</span></td>
                <td className="muted">{fmtTime(r.created_at)}</td>
                <td>
                  {r.remote_uri ? (
                    <span className="badge badge-info" title={r.remote_uri}>S3</span>
                  ) : <span className="muted small">local</span>}
                </td>
                <td className="row-actions">
                  {r.remote_uri ? (
                    <button className="btn btn-ghost btn-sm" onClick={() => pull(r.id)} disabled={busy}>
                      pull
                    </button>
                  ) : null}
                  <button className="btn btn-ghost btn-sm" onClick={() => restore(r.id)} disabled={busy}>
                    restore
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

// ─── Secrets panel ───────────────────────────────────────────────

function SecretsPanel({ instanceId }) {
  const { client } = useApi();
  const [names, setNames] = React.useState(null);
  const [adding, setAdding] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  const refresh = React.useCallback(async () => {
    try {
      const list = await client.listSecretNames(instanceId);
      setNames(Array.isArray(list) ? list.map(r => r.name).sort() : []);
    } catch (e) {
      setErr(e?.message || 'list secrets failed');
    }
  }, [client, instanceId]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const remove = async (name) => {
    if (!confirm(`delete secret ${name}?`)) return;
    setBusy(true); setErr(null);
    try {
      await client.deleteSecret(instanceId, name);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">secrets</div>
        <div className="panel-actions">
          <button className="btn btn-sm" onClick={() => setAdding(true)} disabled={busy}>
            add
          </button>
        </div>
      </div>
      {err ? <div className="error">{err}</div> : null}
      <p className="muted small">
        Values are write-only — set here, read by the agent at runtime.  The
        web UI lists names so existing secrets can be replaced or removed.
      </p>
      {names === null ? (
        <p className="muted small">loading…</p>
      ) : names.length === 0 ? (
        <p className="muted small">no secrets set.</p>
      ) : (
        <ul className="secret-list">
          {names.map(name => (
            <li key={name}>
              <code className="mono-sm">{name}</code>
              <button className="btn btn-ghost btn-sm" onClick={() => remove(name)} disabled={busy}>
                delete
              </button>
            </li>
          ))}
        </ul>
      )}
      {adding ? (
        <AddSecretModal
          instanceId={instanceId}
          onClose={() => setAdding(false)}
          onAdded={() => { setAdding(false); refresh(); }}
        />
      ) : null}
    </section>
  );
}

function AddSecretModal({ instanceId, onClose, onAdded }) {
  const { client } = useApi();
  const [name, setName] = React.useState('');
  const [value, setValue] = React.useState('');
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  const submit = async (e) => {
    e.preventDefault();
    if (!name.trim() || !value) return;
    setSubmitting(true); setError(null);
    try {
      await client.putSecret(instanceId, name.trim(), value);
      onAdded && onAdded();
    } catch (err) {
      setError(err?.detail || err?.message || 'put failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ModalShell onClose={onClose} title="add secret">
      <form onSubmit={submit} className="form">
        <label className="field">
          <span>name</span>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="ANTHROPIC_API_KEY"
            autoFocus
            required
          />
        </label>
        <label className="field">
          <span>value</span>
          <input
            type="password"
            value={value}
            onChange={e => setValue(e.target.value)}
            required
          />
        </label>
        {error ? <div className="error">{error}</div> : null}
        <div className="modal-actions">
          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'saving…' : 'save'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClose}>cancel</button>
        </div>
      </form>
    </ModalShell>
  );
}

function fmtTime(secs) {
  if (!secs) return '—';
  try { return new Date(secs * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z'); }
  catch { return String(secs); }
}

// Trim a UUID for display.  Full id is still on the detail page, but
// list rows + breadcrumbs read better with the first 8 chars.
function shortId(id) {
  if (!id) return '';
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}

function probeLabel(p) {
  if (!p) return 'unknown';
  if (typeof p === 'string') return p;
  if (typeof p === 'object') {
    // ProbeResult is `{ kind: "Healthy" | "Degraded" | "Unreachable" }`
    // depending on serde shape; cover both.
    return p.kind || JSON.stringify(p);
  }
  return String(p);
}
