/* swarm — Tasks (webhooks) views.
 *
 * Three pages, all reachable from the instance detail header's
 * `tasks <badge>` button:
 *
 *   #/i/<id>/tasks            → TasksListPage  (table, toggle, copy URL)
 *   #/i/<id>/tasks/new        → TaskFormPage   (create)
 *   #/i/<id>/tasks/<name>     → TaskFormPage   (edit + delivery log)
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
        <div className="tasks-row-desc muted small"><em>no description</em></div>
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
            <span>description</span>
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
            <span>enabled — accept incoming webhook calls</span>
          </label>
          <small className="muted">
            Disabled tasks return 404 at the public URL.  The row stays
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
    <section className="panel deliveries-panel">
      <div className="panel-title">
        recent deliveries
        <button type="button" className="btn btn-ghost btn-sm" onClick={refresh}>↻</button>
      </div>
      {err ? <div className="error">{err}</div> : null}
      {loading ? (
        <div className="muted small">loading…</div>
      ) : rows.length === 0 ? (
        <div className="muted small">no deliveries yet — fire the webhook to see it here.</div>
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
