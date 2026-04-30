/* swarm — Tasks (webhooks) views.
 *
 * Five pages, all reachable from the instance detail header's
 * `tasks <badge>` button:
 *
 *   #/i/<id>/tasks                       → TasksListPage   (roster)
 *   #/i/<id>/tasks/new                   → TaskFormPage    (create)
 *   #/i/<id>/tasks/<name>                → TaskFormPage    (edit + recent log)
 *   #/i/<id>/tasks/audit                 → AuditListPage   (cross-task log)
 *   #/i/<id>/tasks/audit/<delivery_id>   → AuditDetailPage (body view)
 *
 * The form pages reuse the same `.page-edit` width and `.page-form`
 * layout the hire/edit flow uses so the tasks UI fits the rest of
 * the app on both desktop and mobile.
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import {
  setWebhooksFor, upsertWebhook, removeWebhook,
} from '../store/app.js';

const SCHEMES = [
  {
    value: 'hmac_sha256',
    label: 'HMAC-SHA256',
    hint: 'Caller signs the body with the shared secret. Standard for GitHub/Stripe-style webhooks.',
  },
  {
    value: 'bearer',
    label: 'Bearer token',
    hint: 'Caller sends Authorization: Bearer <secret>. No replay protection — use only inside trusted networks.',
  },
  {
    value: 'none',
    label: 'Dangerous: no auth',
    hint: 'Anyone with the URL can fire this webhook. Avoid unless the agent itself rejects irrelevant payloads.',
  },
];

function schemeLabel(s) {
  return SCHEMES.find(x => x.value === s)?.label || s;
}

function fmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts * 1000).toLocaleString(); } catch { return String(ts); }
}

function shortId(id) {
  return (id || '').slice(0, 8);
}

// ─── List page ────────────────────────────────────────────────────

export function TasksListPage({ instanceId }) {
  const { client } = useApi();
  const slot = useAppState(s => s.webhooks.byInstance[instanceId]);
  const rows = slot?.rows || [];
  const [refreshing, setRefreshing] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const backHref = `#/i/${encodeURIComponent(instanceId)}`;
  const newHref = `#/i/${encodeURIComponent(instanceId)}/tasks/new`;
  const auditHref = `#/i/${encodeURIComponent(instanceId)}/tasks/audit`;

  const refresh = React.useCallback(async () => {
    setRefreshing(true); setErr(null);
    try {
      const list = await client.listWebhooks(instanceId);
      setWebhooksFor(instanceId, list || []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'list failed');
    } finally {
      setRefreshing(false);
    }
  }, [client, instanceId]);

  React.useEffect(() => { refresh(); }, [refresh]);

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') window.location.hash = backHref; };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [backHref]);

  const toggle = async (row) => {
    try {
      const updated = await client.setWebhookEnabled(instanceId, row.name, !row.enabled);
      upsertWebhook(instanceId, updated);
    } catch (e) {
      setErr(e?.detail || e?.message || 'toggle failed');
    }
  };

  const remove = async (row) => {
    if (!window.confirm(`Delete task "${row.name}"? The webhook URL will stop accepting requests immediately.`)) {
      return;
    }
    try {
      await client.deleteWebhook(instanceId, row.name);
      removeWebhook(instanceId, row.name);
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete failed');
    }
  };

  return (
    <main className="page page-edit">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">tasks</h1>
        <p className="page-sub muted">
          Webhook-triggered jobs for this dyson.  Each task exposes a URL;
          when called and signature-verified, the payload kicks off a
          fresh agent conversation seeded with the task brief.
        </p>
      </header>

      {err ? <div className="error">{err}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <div className="panel-title">tasks</div>
          <div className="panel-actions">
            <button
              className="btn btn-ghost btn-sm"
              onClick={refresh}
              disabled={refreshing}
              title="refresh"
            >
              {refreshing ? '…' : '↻'}
            </button>
            <a className="btn btn-ghost btn-sm" href={auditHref} title="cross-task delivery audit log">audit</a>
            <a className="btn btn-sm" href={newHref}>+ new</a>
          </div>
        </div>
        {rows.length === 0 ? (
          <p className="muted small">
            no tasks yet — click <em>+ new</em> to expose a webhook URL.
          </p>
        ) : (
          <ul className="tasks-list">
            {rows.map(row => (
              <TaskRow
                key={row.name}
                row={row}
                instanceId={instanceId}
                onToggle={() => toggle(row)}
                onDelete={() => remove(row)}
              />
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}

function TaskRow({ row, instanceId, onToggle, onDelete }) {
  const editHref = `#/i/${encodeURIComponent(instanceId)}/tasks/${encodeURIComponent(row.name)}`;
  const fullUrl = (typeof window !== 'undefined')
    ? `${window.location.origin}${row.path}`
    : row.path;
  const [copied, setCopied] = React.useState(false);
  const copy = async (e) => {
    e.preventDefault();
    try {
      await navigator.clipboard.writeText(fullUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 1100);
    } catch { /* ignore */ }
  };
  return (
    <li className={`tasks-row ${row.enabled ? '' : 'disabled'}`}>
      <div className="tasks-row-head">
        <a className="tasks-row-name" href={editHref}>{row.name}</a>
        <span className={`badge ${row.enabled ? 'badge-ok' : 'badge-faint'}`}>
          {row.enabled ? 'enabled' : 'disabled'}
        </span>
        <span className="badge badge-warn small">{schemeLabel(row.auth_scheme)}</span>
      </div>
      {row.description ? (
        <div className="tasks-row-desc muted small">{row.description}</div>
      ) : (
        <div className="tasks-row-desc muted small"><em>no instructions</em></div>
      )}
      <div className="tasks-row-url">
        <code className="mono-sm" title={fullUrl}>{fullUrl}</code>
        <button type="button" className="btn btn-ghost btn-sm" onClick={copy}>
          {copied ? 'copied!' : 'copy url'}
        </button>
      </div>
      <div className="tasks-row-actions">
        <button type="button" className="btn btn-ghost btn-sm" onClick={onToggle}>
          {row.enabled ? 'disable' : 'enable'}
        </button>
        <a className="btn btn-ghost btn-sm" href={editHref}>edit</a>
        <button type="button" className="btn btn-danger btn-sm" onClick={onDelete}>delete</button>
      </div>
    </li>
  );
}

// ─── Form page (new + edit) ───────────────────────────────────────

export function TaskFormPage({ instanceId, taskName }) {
  const editing = !!taskName;
  const backHref = `#/i/${encodeURIComponent(instanceId)}/tasks`;

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') window.location.hash = backHref; };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [backHref]);

  return (
    <main className="page page-edit">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">{editing ? 'edit task' : 'new task'}</h1>
        <p className="page-sub muted">
          {editing
            ? 'Update the brief, rotate the signing key, or disable the URL.'
            : 'Expose a webhook URL on this dyson.  When called and verified, the payload kicks off a fresh conversation.'}
        </p>
      </header>
      <TaskForm instanceId={instanceId} taskName={taskName}/>
    </main>
  );
}

function TaskForm({ instanceId, taskName }) {
  const { client } = useApi();
  const editing = !!taskName;
  const backHref = `#/i/${encodeURIComponent(instanceId)}/tasks`;

  // Loaded row when editing.  null until fetched; undefined-on-empty is
  // ambiguous so we use the explicit `loaded` flag.
  const [loaded, setLoaded] = React.useState(!editing);
  const [name, setName] = React.useState(taskName || '');
  const [description, setDescription] = React.useState('');
  const [scheme, setScheme] = React.useState('hmac_sha256');
  const [secret, setSecret] = React.useState('');
  const [hasSecret, setHasSecret] = React.useState(false);
  const [enabled, setEnabled] = React.useState(true);
  const [danger, setDanger] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [origScheme, setOrigScheme] = React.useState('hmac_sha256');

  React.useEffect(() => {
    if (!editing) return;
    let cancelled = false;
    client.getWebhook(instanceId, taskName).then(row => {
      if (cancelled || !row) return;
      setName(row.name);
      setDescription(row.description || '');
      setScheme(row.auth_scheme);
      setOrigScheme(row.auth_scheme);
      setHasSecret(!!row.has_secret);
      setEnabled(!!row.enabled);
      setLoaded(true);
    }).catch(e => {
      if (!cancelled) setErr(e?.detail || e?.message || 'load failed');
    });
    return () => { cancelled = true; };
  }, [client, editing, instanceId, taskName]);

  const schemeChanged = editing && scheme !== origScheme;
  const needsSecret = scheme !== 'none';
  const requireSecretOnSave = needsSecret && (!editing || schemeChanged || !hasSecret);

  const submit = async (e) => {
    e.preventDefault();
    if (submitting) return;
    setErr(null);
    if (scheme === 'none' && !danger) {
      setErr('Confirm "I understand this URL accepts any payload" to use no-auth.');
      return;
    }
    if (requireSecretOnSave && !secret) {
      setErr('A signing secret is required for this scheme.');
      return;
    }
    setSubmitting(true);
    try {
      if (editing) {
        const body = { description, auth_scheme: scheme, enabled };
        if (secret) body.secret = secret;
        const updated = await client.updateWebhook(instanceId, taskName, body);
        upsertWebhook(instanceId, updated);
      } else {
        const body = { name, description, auth_scheme: scheme, enabled };
        if (secret) body.secret = secret;
        const created = await client.createWebhook(instanceId, body);
        upsertWebhook(instanceId, created);
      }
      window.location.hash = backHref;
    } catch (e) {
      setErr(e?.detail || e?.message || 'save failed');
    } finally {
      setSubmitting(false);
    }
  };

  if (editing && !loaded) {
    return <div className="muted">loading…</div>;
  }

  const fullUrl = editing && typeof window !== 'undefined'
    ? `${window.location.origin}/webhooks/${encodeURIComponent(instanceId)}/${encodeURIComponent(taskName)}`
    : null;

  return (
    <div className="edit-stack">
      <form id="task-form" onSubmit={submit} className="form page-form">
        <section className="page-section">
          <h2 className="section-title">identity</h2>
          <label className="field">
            <span>name</span>
            <input
              value={name}
              onChange={e => setName(e.target.value.toLowerCase())}
              placeholder="github-deploy"
              disabled={editing || submitting}
              maxLength={64}
              autoFocus={!editing}
              pattern="[a-z0-9_-]+"
              title="lowercase letters, digits, hyphens or underscores; max 64"
            />
            <small className="muted">
              URL-safe slug.  Lowercase ASCII letters, digits, hyphens, underscores.
              {editing ? ' (immutable on edit)' : ''}
            </small>
          </label>
          {fullUrl ? (
            <label className="field">
              <span>url</span>
              <UrlField value={fullUrl}/>
            </label>
          ) : null}
          <label className="field">
            <span>instructions</span>
            <textarea
              className="textarea"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Triage GitHub issues opened in foo/bar — read the body, label spam, ping me on real reports."
              rows={5}
              disabled={submitting}
            />
            <small className="muted">
              Prepended to every fired webhook's prompt.  Tell the agent what to do
              with the payload that arrives.
            </small>
          </label>
        </section>

        <section className="page-section">
          <h2 className="section-title">signature</h2>
          <div className="task-scheme-grid">
            {SCHEMES.map(s => (
              <label key={s.value} className={`task-scheme ${scheme === s.value ? 'selected' : ''} ${s.value === 'none' ? 'danger' : ''}`}>
                <input
                  type="radio"
                  name="auth-scheme"
                  value={s.value}
                  checked={scheme === s.value}
                  onChange={() => { setScheme(s.value); setDanger(false); }}
                  disabled={submitting}
                />
                <div className="task-scheme-body">
                  <div className="task-scheme-label">{s.label}</div>
                  <div className="task-scheme-hint muted small">{s.hint}</div>
                </div>
              </label>
            ))}
          </div>
          {needsSecret ? (
            <label className="field">
              <span>{requireSecretOnSave ? 'secret' : 'rotate secret'}</span>
              <input
                type="password"
                value={secret}
                onChange={e => setSecret(e.target.value)}
                placeholder={requireSecretOnSave ? 'paste a strong random string' : 'leave blank to keep existing'}
                disabled={submitting}
                autoComplete="off"
              />
              <small className="muted">
                {scheme === 'hmac_sha256'
                  ? 'Used as the HMAC key. Caller signs the body and sends the hex digest as X-Swarm-Signature: sha256=<hex>.'
                  : 'Sent verbatim by the caller as Authorization: Bearer <secret>. Constant-time compared on receipt.'}
              </small>
            </label>
          ) : (
            <label className="field check">
              <input
                type="checkbox"
                checked={danger}
                onChange={e => setDanger(e.target.checked)}
                disabled={submitting}
              />
              <span>
                I understand this URL accepts any payload, signed or not.
              </span>
            </label>
          )}
        </section>

        <section className="page-section">
          <h2 className="section-title">availability</h2>
          <label className="field check">
            <input
              type="checkbox"
              checked={enabled}
              onChange={e => setEnabled(e.target.checked)}
              disabled={submitting}
            />
            <span>accept incoming webhook calls</span>
          </label>
          <small className="muted">
            When unchecked, the public URL returns 404.  The row stays
            so the configuration sticks; flip back on to resume.
          </small>
        </section>

        {err ? <div className="error">{err}</div> : null}
      </form>

      {editing ? <DeliveriesPanel instanceId={instanceId} taskName={taskName}/> : null}

      <div className="edit-action-bar">
        <button
          type="submit"
          form="task-form"
          className="btn btn-primary btn-lg"
          disabled={submitting}
        >
          {submitting ? 'saving…' : (editing ? 'save' : 'create task')}
        </button>
        <a className="btn btn-ghost" href={backHref}>cancel</a>
      </div>
    </div>
  );
}

function UrlField({ value }) {
  const [copied, setCopied] = React.useState(false);
  const copy = async (e) => {
    e.preventDefault();
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1100);
    } catch { /* ignore */ }
  };
  return (
    <div className="task-url-field">
      <input value={value} readOnly className="mono-sm"/>
      <button type="button" className="btn btn-ghost btn-sm" onClick={copy}>
        {copied ? 'copied!' : 'copy'}
      </button>
    </div>
  );
}

function DeliveriesPanel({ instanceId, taskName }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState(null);

  const refresh = React.useCallback(async () => {
    try {
      const list = await client.listWebhookDeliveries(instanceId, taskName, { limit: 50 });
      setRows(Array.isArray(list) ? list : []);
      setErr(null);
    } catch (e) {
      setErr(e?.detail || e?.message || 'load failed');
    } finally {
      setLoading(false);
    }
  }, [client, instanceId, taskName]);

  React.useEffect(() => {
    refresh();
    const id = setInterval(() => { if (!document.hidden) refresh(); }, 30_000);
    return () => clearInterval(id);
  }, [refresh]);

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">recent deliveries</div>
        <div className="panel-actions">
          <button type="button" className="btn btn-ghost btn-sm" onClick={refresh} title="refresh">
            ↻
          </button>
        </div>
      </div>
      {err ? <div className="error">{err}</div> : null}
      {loading ? (
        <p className="muted small">loading…</p>
      ) : rows.length === 0 ? (
        <p className="muted small">no deliveries yet — fire the webhook to see it here.</p>
      ) : (
        <ul className="deliveries-list">
          {rows.map(d => (
            <li key={d.id} className={`deliveries-row ${d.signature_ok ? '' : 'sig-bad'}`}>
              <div className="deliveries-row-head">
                <span className={`badge ${d.status_code < 400 ? 'badge-ok' : 'badge-warn'}`}>
                  {d.status_code}
                </span>
                <span className="muted small">{fmtTime(d.fired_at)}</span>
                <span className="muted small">{d.latency_ms}ms</span>
                {!d.signature_ok ? <span className="badge badge-warn small">bad signature</span> : null}
                {d.request_id ? <code className="mono-sm muted">{shortId(d.request_id)}</code> : null}
              </div>
              {d.error ? <div className="deliveries-row-err small">{d.error}</div> : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// ─── Audit list + detail ──────────────────────────────────────────
//
// `AuditListPage` is the cross-task delivery log: every fire across
// every task on the instance, newest first, with body-substring search
// and cursor pagination.  Detail pages link from here.

const AUDIT_PAGE_SIZE = 50;

export function AuditListPage({ instanceId }) {
  const { client } = useApi();
  const backHref = `#/i/${encodeURIComponent(instanceId)}/tasks`;
  // Pages are tracked as a stack of `before` cursors so the user can
  // page forward by appending the oldest fired_at, and backward by
  // popping.  The first page has cursor=null (= unbounded).
  const [cursors, setCursors] = React.useState([null]);
  const [rows, setRows] = React.useState(null);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState(null);
  // The form input is committed to `committedQ` on submit so each
  // keystroke doesn't re-fire the query.  Submitting also resets the
  // cursor stack — search invalidates the existing pagination.
  const [qInput, setQInput] = React.useState('');
  const [committedQ, setCommittedQ] = React.useState('');
  const [webhookFilter, setWebhookFilter] = React.useState('');
  const slot = useAppState(s => s.webhooks.byInstance[instanceId]);
  const taskNames = React.useMemo(
    () => (slot?.rows || []).map(r => r.name),
    [slot],
  );

  React.useEffect(() => {
    // Pull the task roster on mount so the webhook filter dropdown is
    // populated before the user opens it.  Cached in the store so it
    // doesn't blink on subsequent visits.
    let cancelled = false;
    if (!slot) {
      client.listWebhooks(instanceId)
        .then(list => { if (!cancelled) setWebhooksFor(instanceId, list || []); })
        .catch(() => { /* surfaced on the tasks list page */ });
    }
    return () => { cancelled = true; };
  }, [client, instanceId, slot]);

  const cursor = cursors[cursors.length - 1];
  const refresh = React.useCallback(async () => {
    setLoading(true); setErr(null);
    try {
      const list = await client.listInstanceDeliveries(instanceId, {
        limit: AUDIT_PAGE_SIZE,
        before: cursor ?? undefined,
        q: committedQ || undefined,
        webhook: webhookFilter || undefined,
      });
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'load failed');
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, [client, instanceId, cursor, committedQ, webhookFilter]);

  React.useEffect(() => { refresh(); }, [refresh]);

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') window.location.hash = backHref; };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [backHref]);

  const submitSearch = (e) => {
    e.preventDefault();
    setCursors([null]);
    setCommittedQ(qInput.trim());
  };

  const clearSearch = () => {
    setQInput('');
    setCommittedQ('');
    setWebhookFilter('');
    setCursors([null]);
  };

  const nextPage = () => {
    if (!rows || rows.length < AUDIT_PAGE_SIZE) return;
    const last = rows[rows.length - 1];
    setCursors([...cursors, last.fired_at]);
  };
  const prevPage = () => {
    if (cursors.length <= 1) return;
    setCursors(cursors.slice(0, -1));
  };

  const onPage = cursors.length;
  const canPrev = cursors.length > 1;
  const canNext = !!rows && rows.length >= AUDIT_PAGE_SIZE;

  return (
    <main className="page page-edit">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">audit</h1>
        <p className="page-sub muted">
          Every webhook fire on this dyson, newest first.  Click a row
          to read the request body the agent saw.
        </p>
      </header>

      <section className="panel">
        <div className="panel-header">
          <div className="panel-title">deliveries</div>
          <div className="panel-actions">
            <button
              className="btn btn-ghost btn-sm"
              onClick={refresh}
              disabled={loading}
              title="refresh"
            >
              {loading ? '…' : '↻'}
            </button>
          </div>
        </div>

        <form className="audit-filters" onSubmit={submitSearch}>
          <input
            type="search"
            className="audit-search"
            placeholder="search bodies + errors…"
            value={qInput}
            onChange={e => setQInput(e.target.value)}
            maxLength={256}
          />
          <select
            className="audit-task-filter"
            value={webhookFilter}
            onChange={e => { setWebhookFilter(e.target.value); setCursors([null]); }}
            title="filter by task"
          >
            <option value="">all tasks</option>
            {taskNames.map(n => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          <button type="submit" className="btn btn-sm">search</button>
          {(committedQ || webhookFilter) ? (
            <button type="button" className="btn btn-ghost btn-sm" onClick={clearSearch}>
              clear
            </button>
          ) : null}
        </form>

        {err ? <div className="error">{err}</div> : null}

        {rows === null ? (
          <p className="muted small">loading…</p>
        ) : rows.length === 0 ? (
          <AuditEmpty
            filtered={!!(committedQ || webhookFilter)}
            onClear={clearSearch}
          />
        ) : (
          <table className="rows audit-table">
            <thead><tr>
              <th>when</th>
              <th>task</th>
              <th>status</th>
              <th>latency</th>
              <th>size</th>
              <th>request id</th>
            </tr></thead>
            <tbody>
              {rows.map(d => {
                const detailHref = `#/i/${encodeURIComponent(instanceId)}/tasks/audit/${encodeURIComponent(d.id)}`;
                return (
                  <tr key={d.id} className={d.signature_ok ? '' : 'sig-bad'}>
                    <td className="muted small">
                      <a className="audit-row-link" href={detailHref}>{fmtTime(d.fired_at)}</a>
                    </td>
                    <td><code className="mono-sm">{d.webhook_name}</code></td>
                    <td>
                      <span className={`badge ${d.status_code < 400 ? 'badge-ok' : 'badge-warn'}`}>
                        {d.status_code}
                      </span>
                      {!d.signature_ok ? (
                        <span className="badge badge-warn small" style={{ marginLeft: 6 }}>bad sig</span>
                      ) : null}
                    </td>
                    <td className="muted small">{d.latency_ms}ms</td>
                    <td className="muted small">{fmtBytes(d.body_size)}</td>
                    <td className="muted small">
                      {d.request_id ? <code className="mono-sm">{shortId(d.request_id)}</code> : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        <div className="audit-pager">
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={prevPage}
            disabled={!canPrev || loading}
          >
            ← newer
          </button>
          <span className="muted small">page {onPage}</span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={nextPage}
            disabled={!canNext || loading}
          >
            older →
          </button>
        </div>
      </section>
    </main>
  );
}

export function AuditDetailPage({ instanceId, deliveryId }) {
  const { client } = useApi();
  const backHref = `#/i/${encodeURIComponent(instanceId)}/tasks/audit`;
  const [row, setRow] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    let cancelled = false;
    setLoading(true); setErr(null);
    client.getDelivery(instanceId, deliveryId)
      .then(r => { if (!cancelled) { setRow(r); setLoading(false); } })
      .catch(e => {
        if (!cancelled) {
          setErr(e?.detail || e?.message || 'load failed');
          setLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, [client, instanceId, deliveryId]);

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') window.location.hash = backHref; };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [backHref]);

  return (
    <main className="page page-edit">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">delivery</h1>
        <p className="page-sub muted">
          Exact request bytes the agent saw on this fire.
        </p>
      </header>

      {err ? <div className="error">{err}</div> : null}

      {loading ? (
        <p className="muted">loading…</p>
      ) : !row ? (
        <p className="muted">delivery not found.</p>
      ) : (
        <>
          <section className="panel">
            <div className="panel-title">metadata</div>
            <dl className="audit-meta">
              <dt>id</dt><dd><code className="mono-sm">{row.id}</code></dd>
              <dt>task</dt>
              <dd>
                <code className="mono-sm">{row.webhook_name}</code>{' '}
                <a
                  className="muted small"
                  href={`#/i/${encodeURIComponent(instanceId)}/tasks/${encodeURIComponent(row.webhook_name)}`}
                >
                  open task
                </a>
              </dd>
              <dt>fired</dt><dd>{fmtTime(row.fired_at)}</dd>
              <dt>status</dt>
              <dd>
                <span className={`badge ${row.status_code < 400 ? 'badge-ok' : 'badge-warn'}`}>
                  {row.status_code}
                </span>{' '}
                {row.signature_ok
                  ? <span className="badge badge-ok small">signature ok</span>
                  : <span className="badge badge-warn small">signature failed</span>}
              </dd>
              <dt>latency</dt><dd>{row.latency_ms}ms</dd>
              <dt>request id</dt>
              <dd>{row.request_id ? <code className="mono-sm">{row.request_id}</code> : '—'}</dd>
              <dt>content-type</dt>
              <dd>{row.content_type ? <code className="mono-sm">{row.content_type}</code> : '—'}</dd>
              <dt>body size</dt><dd>{fmtBytes(row.body_size)}</dd>
              {row.error ? (<><dt>error</dt><dd className="deliveries-row-err small">{row.error}</dd></>) : null}
            </dl>
          </section>

          <DeliveryBodyPanel row={row}/>
        </>
      )}
    </main>
  );
}

function DeliveryBodyPanel({ row }) {
  const [copied, setCopied] = React.useState(false);
  const text = row.body_text;
  const hasBody = text != null || row.body_b64 != null;

  const copy = async () => {
    if (text == null) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1100);
    } catch { /* ignore */ }
  };

  // For JSON content, pretty-print on demand.  We don't pre-format
  // because (a) the operator may want the exact bytes the signature
  // was computed over, (b) JSON.parse silently strips whitespace and
  // re-orders nothing, but a stringify+parse round-trip changes
  // separators which is enough to confuse a "why does my HMAC fail"
  // debug session.
  const pretty = React.useMemo(() => {
    if (text == null) return null;
    if (!(row.content_type || '').toLowerCase().includes('json')) return null;
    try {
      const parsed = JSON.parse(text);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return null;
    }
  }, [text, row.content_type]);
  const [showPretty, setShowPretty] = React.useState(false);

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">body</div>
        <div className="panel-actions">
          {pretty ? (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => setShowPretty(p => !p)}
            >
              {showPretty ? 'raw' : 'pretty'}
            </button>
          ) : null}
          {text != null ? (
            <button type="button" className="btn btn-ghost btn-sm" onClick={copy}>
              {copied ? 'copied!' : 'copy'}
            </button>
          ) : null}
        </div>
      </div>
      {!hasBody ? (
        <p className="muted small">no body recorded.</p>
      ) : text != null ? (
        <pre className="audit-body">{showPretty && pretty ? pretty : text}</pre>
      ) : (
        <>
          <p className="muted small">
            non-utf8 payload — base64-encoded:
          </p>
          <pre className="audit-body">{row.body_b64}</pre>
        </>
      )}
    </section>
  );
}

function fmtBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(2)} MiB`;
}

function AuditEmpty({ filtered, onClear }) {
  return (
    <div className="audit-empty">
      <div className="audit-empty-glyph" aria-hidden="true">∅</div>
      <div className="audit-empty-title">
        {filtered ? 'no deliveries match' : 'no deliveries yet'}
      </div>
      <div className="audit-empty-body muted small">
        {filtered ? (
          <>Try a different search term, or pick a different task.</>
        ) : (
          <>
            Each successful or failed webhook fire records a row here.
            POST to a task URL to see one show up.
          </>
        )}
      </div>
      {filtered ? (
        <button type="button" className="btn btn-ghost btn-sm" onClick={onClear}>
          clear filters
        </button>
      ) : null}
    </div>
  );
}
