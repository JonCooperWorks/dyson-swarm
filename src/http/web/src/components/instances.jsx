/* warden — Instances view (list + detail + create modal).
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
          return (
            <li key={id} className={`rail-row ${selectedId === id ? 'selected' : ''}`}>
              <a href={`#/i/${encodeURIComponent(id)}`}>
                <div className="rail-row-id">{id}</div>
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

// ─── Create modal ─────────────────────────────────────────────────

function CreateModal({ onClose, onCreated }) {
  const { client } = useApi();
  const [templateId, setTemplateId] = React.useState('');
  const [ttlSeconds, setTtlSeconds] = React.useState('');
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [created, setCreated] = React.useState(null);

  const submit = async (e) => {
    e.preventDefault();
    if (!templateId.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const req = { template_id: templateId.trim(), env: {} };
      const ttl = ttlSeconds.trim() ? Number(ttlSeconds) : null;
      if (Number.isFinite(ttl) && ttl > 0) req.ttl_seconds = ttl;
      const result = await client.createInstance(req);
      setCreated(result);
      onCreated && onCreated();
    } catch (err) {
      setError(err?.detail || err?.message || 'create failed');
    } finally {
      setSubmitting(false);
    }
  };

  if (created) {
    return (
      <ModalShell onClose={onClose} title="instance created">
        <p className="small">
          Save the proxy token now — it won't be shown again.
        </p>
        <KvField label="id" value={created.id}/>
        <KvField label="url" value={created.url}/>
        <KvField label="bearer token" value={created.bearer_token}/>
        <KvField label="proxy token" value={created.proxy_token}/>
        <div className="modal-actions">
          <a className="btn" href={`#/i/${encodeURIComponent(created.id)}`} onClick={onClose}>
            open detail →
          </a>
          <button className="btn btn-ghost" onClick={onClose}>close</button>
        </div>
      </ModalShell>
    );
  }

  return (
    <ModalShell onClose={onClose} title="new instance">
      <form onSubmit={submit} className="form">
        <label className="field">
          <span>template id</span>
          <input
            value={templateId}
            onChange={e => setTemplateId(e.target.value)}
            placeholder="dyson-default"
            autoFocus
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
        {error ? <div className="error">{error}</div> : null}
        <div className="modal-actions">
          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'creating…' : 'create'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClose}>cancel</button>
        </div>
      </form>
    </ModalShell>
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

  return (
    <main className="detail-pane">
      <header className="detail-header">
        <div>
          <h2 className="detail-id">{row.id}</h2>
          <div className="detail-sub muted small">
            template <code>{row.template_id}</code> ·{' '}
            <StatusBadge status={row.status}/>{' '}
            {row.pinned ? <span className="badge badge-info">pinned</span> : null}
          </div>
        </div>
        <div className="detail-actions">
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

      <section className="panel placeholder">
        <div className="panel-title">snapshots</div>
        <p className="muted small">phase 4 — snapshot/backup/restore actions land here.</p>
      </section>

      <section className="panel placeholder">
        <div className="panel-title">secrets</div>
        <p className="muted small">phase 4 — per-instance secret editor lands here.</p>
      </section>
    </main>
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

function fmtTime(secs) {
  if (!secs) return '—';
  try { return new Date(secs * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z'); }
  catch { return String(secs); }
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
