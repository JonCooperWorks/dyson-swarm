/* swarm — Tasks (webhooks) views.
 *
 * Five pages, all reachable from the agent detail header's
 * `webhooks <badge>` button. Routes remain /tasks for backward
 * compatibility; user-facing copy calls them webhooks.
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
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import {
  setWebhooksFor, upsertWebhook, removeWebhook,
} from '../store/app.js';
import { EmptyState, Pager } from './ui.jsx';
import { fmtBytes, fmtTime, shortId } from '../utils/format.js';
import { WEBHOOK_PRESETS } from './webhookPresets.js';

const SCHEMES = [
  {
    value: 'hmac_sha256',
    label: 'HMAC-SHA256',
    hint: 'Caller signs the body with the shared secret and sends it in the configured signature header.',
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

const TASK_SLUG_RE = /^[a-z0-9_-]{1,64}$/;
const TASK_URL_PLACEHOLDER = 'webhook-name';
const DEFAULT_SIGNATURE_HEADER = 'x-swarm-signature';
const TASK_MARKDOWN_PLUGINS = [remarkGfm, remarkBreaks];
const TASK_MARKDOWN_COMPONENTS = {
  a: ({ node, ...props }) => (
    <a {...props} target="_blank" rel="noopener noreferrer"/>
  ),
};

function nullableText(value) {
  const s = String(value ?? '').trim();
  return s ? s : null;
}

function b64Text(value) {
  if (typeof TextEncoder !== 'undefined') {
    const bytes = new TextEncoder().encode(value);
    let raw = '';
    bytes.forEach(b => { raw += String.fromCharCode(b); });
    return btoa(raw);
  }
  return btoa(value);
}

function b64DecodeText(value) {
  try {
    const raw = atob(value || '');
    if (typeof TextDecoder !== 'undefined') {
      const bytes = Uint8Array.from(raw, ch => ch.charCodeAt(0));
      return new TextDecoder().decode(bytes);
    }
    return raw;
  } catch {
    return '';
  }
}

function textToHex(value) {
  if (typeof TextEncoder !== 'undefined') {
    return Array.from(new TextEncoder().encode(value || ''))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  return Array.from(value || '')
    .map(ch => ch.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
}

function parseRecordedDelivery(raw) {
  const normalised = String(raw || '').replace(/\r\n/g, '\n');
  const sep = normalised.indexOf('\n\n');
  const headerText = sep >= 0 ? normalised.slice(0, sep) : normalised;
  const body = sep >= 0 ? normalised.slice(sep + 2) : '';
  const headers = {};
  headerText.split('\n').forEach(line => {
    const idx = line.indexOf(':');
    if (idx <= 0) return;
    headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  });
  return { headers, body_b64: b64Text(body) };
}

function schemeLabel(s) {
  return SCHEMES.find(x => x.value === s)?.label || s;
}

function schemeBadgeClass(s) {
  if (s === 'none') return 'badge-warn';
  if (s === 'hmac_sha256') return 'badge-ok';
  return 'badge-info';
}

function validTaskSlug(name) {
  const slug = (name || '').trim();
  return TASK_SLUG_RE.test(slug);
}

function webhookUrlFor(instanceId, name, { showPlaceholder = false } = {}) {
  const slug = (name || '').trim();
  const hasValidSlug = validTaskSlug(slug);
  if (!hasValidSlug && !showPlaceholder) return null;
  if (typeof window === 'undefined') return null;
  const urlSlug = hasValidSlug ? encodeURIComponent(slug) : TASK_URL_PLACEHOLDER;
  return `${window.location.origin}/webhooks/${encodeURIComponent(instanceId)}/${urlSlug}`;
}

// ─── List page ────────────────────────────────────────────────────

export function TasksListPage({ instanceId, embedded = false }) {
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
    if (!window.confirm(`Delete webhook "${row.name}"? The URL will stop accepting requests immediately.`)) {
      return;
    }
    try {
      await client.deleteWebhook(instanceId, row.name);
      removeWebhook(instanceId, row.name);
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete failed');
    }
  };

  const Shell = embedded ? 'div' : 'main';
  return (
    <Shell className={embedded ? 'instance-subpage' : 'page page-edit'}>
      <header className={embedded ? 'subpage-header' : 'page-header'}>
        {embedded ? null : <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>}
        <h1 className={embedded ? 'subpage-title' : 'page-title'}>webhooks</h1>
        <p className="page-sub muted">
          One URL per provider. When a signed request arrives, swarm
          records the delivery and posts it into that webhook's stable chat
          using the webhook instructions.
        </p>
      </header>

      {err ? <div className="error">{err}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <div className="panel-title">webhook receivers</div>
          <div className="panel-actions">
            <button
              className="btn btn-ghost btn-sm"
              onClick={refresh}
              disabled={refreshing}
              title="refresh"
            >
              {refreshing ? '…' : '↻'}
            </button>
            <a className="btn btn-ghost btn-sm" href={auditHref} title="delivery audit log">audit</a>
            <a className="btn btn-sm" href={newHref}>new webhook</a>
          </div>
        </div>
        {rows.length === 0 ? (
          <TasksEmpty newHref={newHref} auditHref={auditHref}/>
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
    </Shell>
  );
}

function TasksEmpty({ newHref, auditHref }) {
  return (
    <EmptyState
      glyph="↯"
      title="no webhooks yet"
      actions={(
        <>
        <a className="btn btn-primary btn-sm" href={newHref}>new webhook</a>
        <a className="btn btn-ghost btn-sm" href={auditHref}>audit</a>
        </>
      )}
    >
      Create one provider URL, then watch every delivery in audit.
    </EmptyState>
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
        <span className={`badge ${schemeBadgeClass(row.auth_scheme)} small`}>
          {schemeLabel(row.auth_scheme)}
        </span>
      </div>
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

export function TaskFormPage({ instanceId, taskName, embedded = false }) {
  const editing = !!taskName;
  const backHref = `#/i/${encodeURIComponent(instanceId)}/tasks`;

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') window.location.hash = backHref; };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [backHref]);

  const Shell = embedded ? 'div' : 'main';
  return (
    <Shell className={embedded ? 'instance-subpage' : 'page page-edit'}>
      <header className={embedded ? 'subpage-header' : 'page-header'}>
        <a className="btn btn-ghost btn-sm" href={backHref}>← webhooks</a>
        <h1 className={embedded ? 'subpage-title' : 'page-title'}>{editing ? 'edit webhook' : 'new webhook'}</h1>
        <p className="page-sub muted">
          {editing
            ? 'Update the instructions, rotate the shared secret, or disable the URL.'
            : 'Create a provider-facing URL. When called and verified, the payload is posted into a stable chat for that webhook.'}
        </p>
      </header>
      <TaskForm instanceId={instanceId} taskName={taskName}/>
    </Shell>
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
  const [signatureHeader, setSignatureHeader] = React.useState(DEFAULT_SIGNATURE_HEADER);
  const [verifierMode, setVerifierMode] = React.useState('legacy_hmac');
  const [signatureAlgo, setSignatureAlgo] = React.useState('sha256');
  const [signatureEncoding, setSignatureEncoding] = React.useState('hex');
  const [signaturePrefix, setSignaturePrefix] = React.useState('sha256=');
  const [signatureSeparator, setSignatureSeparator] = React.useState('');
  const [signatureValueSplit, setSignatureValueSplit] = React.useState('=');
  const [timestampHeader, setTimestampHeader] = React.useState('');
  const [timestampSkewSecs, setTimestampSkewSecs] = React.useState('300');
  const [payloadTemplate, setPayloadTemplate] = React.useState('{{body}}');
  const [idempotencyHeader, setIdempotencyHeader] = React.useState('');
  const [secret, setSecret] = React.useState('');
  const [hasSecret, setHasSecret] = React.useState(false);
  const [enabled, setEnabled] = React.useState(true);
  const [danger, setDanger] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [origScheme, setOrigScheme] = React.useState('hmac_sha256');
  const [recordedDelivery, setRecordedDelivery] = React.useState('');
  const [verifyResult, setVerifyResult] = React.useState(null);
  const [verifying, setVerifying] = React.useState(false);

  React.useEffect(() => {
    if (!editing) return;
    let cancelled = false;
    client.getWebhook(instanceId, taskName).then(row => {
      if (cancelled || !row) return;
      setName(row.name);
      setDescription(row.description || '');
      setScheme(row.auth_scheme);
      setOrigScheme(row.auth_scheme);
      setSignatureHeader(row.signature_header || DEFAULT_SIGNATURE_HEADER);
      setVerifierMode(row.verifier_mode || 'legacy_hmac');
      setSignatureAlgo(row.signature_algo || 'sha256');
      setSignatureEncoding(row.signature_encoding || 'hex');
      setSignaturePrefix(row.signature_prefix || '');
      setSignatureSeparator(row.signature_separator || '');
      setSignatureValueSplit(row.signature_value_split || '');
      setTimestampHeader(row.timestamp_header || '');
      setTimestampSkewSecs(String(row.timestamp_skew_secs ?? 300));
      setPayloadTemplate(row.payload_template || '{{body}}');
      setIdempotencyHeader(row.idempotency_header || '');
      setHasSecret(!!row.has_secret);
      setEnabled(!!row.enabled);
      setLoaded(true);
    }).catch(e => {
      if (!cancelled) setErr(e?.detail || e?.message || 'load failed');
    });
    return () => { cancelled = true; };
  }, [client, editing, instanceId, taskName]);

  const schemeChanged = editing && scheme !== origScheme;
  const usesHmac = scheme === 'hmac_sha256' || verifierMode === 'hmac_v2';
  const needsSecret = scheme !== 'none' && verifierMode !== 'none' && verifierMode !== 'bearer_v2';
  const requireSecretOnSave = needsSecret && (!editing || schemeChanged || !hasSecret);

  const applyPreset = (preset) => {
    setScheme(preset.auth_scheme);
    setSignatureHeader(preset.signature_header);
    setVerifierMode(preset.verifier_mode);
    setSignatureAlgo(preset.signature_algo || 'sha256');
    setSignatureEncoding(preset.signature_encoding || 'hex');
    setSignaturePrefix(preset.signature_prefix || '');
    setSignatureSeparator(preset.signature_separator || '');
    setSignatureValueSplit(preset.signature_value_split || '');
    setTimestampHeader(preset.timestamp_header || '');
    setTimestampSkewSecs(String(preset.timestamp_skew_secs ?? 300));
    setPayloadTemplate(preset.payload_template || '{{body}}');
    setIdempotencyHeader(preset.idempotency_header || '');
    setDanger(false);
    setVerifyResult(null);
  };

  const verifierBody = () => ({
    verifier_mode: verifierMode,
    signature_algo: nullableText(signatureAlgo),
    signature_encoding: nullableText(signatureEncoding),
    signature_prefix: nullableText(signaturePrefix),
    signature_separator: nullableText(signatureSeparator),
    signature_value_split: nullableText(signatureValueSplit),
    timestamp_header: nullableText(timestampHeader),
    timestamp_skew_secs: timestampSkewSecs === '' ? null : Number(timestampSkewSecs),
    payload_template: nullableText(payloadTemplate),
    idempotency_header: nullableText(idempotencyHeader),
  });

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
        const body = { description, auth_scheme: scheme, enabled, ...verifierBody() };
        if (usesHmac) body.signature_header = signatureHeader.trim() || DEFAULT_SIGNATURE_HEADER;
        if (secret) body.secret = secret;
        const updated = await client.updateWebhook(instanceId, taskName, body);
        upsertWebhook(instanceId, updated);
      } else {
        const body = { name, description, auth_scheme: scheme, enabled, ...verifierBody() };
        if (usesHmac) body.signature_header = signatureHeader.trim() || DEFAULT_SIGNATURE_HEADER;
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

  const verifyRecorded = async () => {
    if (!editing || verifying) return;
    setVerifying(true);
    setVerifyResult(null);
    setErr(null);
    try {
      const result = await client.verifyWebhookDelivery(
        instanceId,
        taskName,
        parseRecordedDelivery(recordedDelivery),
      );
      setVerifyResult(result);
    } catch (e) {
      setVerifyResult({ type: 'request_failed', reason: e?.detail || e?.message || 'verify failed' });
    } finally {
      setVerifying(false);
    }
  };

  if (editing && !loaded) {
    return <div className="muted">loading…</div>;
  }

  const activeSlug = editing ? taskName : name;
  const urlReady = validTaskSlug(activeSlug);
  const fullUrl = webhookUrlFor(instanceId, activeSlug, { showPlaceholder: true });

  return (
    <div className="edit-stack">
      <form id="task-form" onSubmit={submit} className="form page-form">
        <section className="page-section">
          <h2 className="section-title">provider URL</h2>
          {fullUrl ? (
            <label className={`field task-provider-url ${urlReady ? '' : 'pending'}`}>
              <span>provider URL</span>
              <UrlField value={fullUrl} disabled={!urlReady}/>
              <small className="muted">
                {urlReady
                  ? 'Copy this into the provider. Configure the provider with the shared secret below.'
                  : 'Enter a URL-safe webhook name below to unlock copy.'}
              </small>
            </label>
          ) : null}
          <label className="field">
            <span>name</span>
            <input
              aria-label="name"
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
              This becomes the final segment of the provider URL. Lowercase ASCII letters, digits, hyphens, underscores.
              {editing ? ' (immutable on edit)' : ''}
            </small>
          </label>
        </section>

        <section className="page-section">
          <h2 className="section-title">verification</h2>
          <div className="task-preset-strip" aria-label="webhook verifier presets">
            {WEBHOOK_PRESETS.map(preset => (
              <button
                key={preset.label}
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => applyPreset(preset)}
                disabled={submitting}
              >
                {preset.label}
              </button>
            ))}
          </div>
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
              <span>{requireSecretOnSave ? 'shared secret' : 'rotate shared secret'}</span>
              <input
                type="password"
                value={secret}
                onChange={e => setSecret(e.target.value)}
                placeholder={requireSecretOnSave ? 'paste or generate a strong random string' : 'leave blank to keep existing'}
                disabled={submitting}
                autoComplete="off"
              />
              <small className="muted">
                {scheme === 'hmac_sha256'
                  ? `Use the same secret in the provider. It signs the body and sends ${signatureHeader || DEFAULT_SIGNATURE_HEADER}: sha256=<hex>.`
                  : 'Use the same secret in the provider as Authorization: Bearer <secret>.'}
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
          {usesHmac ? (
            <label className="field">
              <span>signature header</span>
              <input
                aria-label="signature header"
                value={signatureHeader}
                onChange={e => setSignatureHeader(e.target.value.toLowerCase())}
                placeholder={DEFAULT_SIGNATURE_HEADER}
                disabled={submitting}
                autoComplete="off"
              />
              <small className="muted">
                Use the provider's header name, for example x-hub-signature-256 or x-swarm-signature.
              </small>
            </label>
          ) : null}
          <div className="task-verifier-grid">
            <label className="field">
              <span>verifier mode</span>
              <select
                aria-label="verifier mode"
                value={verifierMode}
                onChange={e => setVerifierMode(e.target.value)}
                disabled={submitting}
              >
                <option value="legacy_hmac">legacy_hmac</option>
                <option value="legacy_bearer">legacy_bearer</option>
                <option value="none">none</option>
                <option value="hmac_v2">hmac_v2</option>
                <option value="bearer_v2">bearer_v2</option>
              </select>
            </label>
            <label className="field">
              <span>algorithm</span>
              <select
                aria-label="signature algorithm"
                value={signatureAlgo}
                onChange={e => setSignatureAlgo(e.target.value)}
                disabled={submitting}
              >
                <option value="sha256">sha256</option>
                <option value="sha1">sha1</option>
                <option value="sha512">sha512</option>
              </select>
            </label>
            <label className="field">
              <span>encoding</span>
              <select
                aria-label="signature encoding"
                value={signatureEncoding}
                onChange={e => setSignatureEncoding(e.target.value)}
                disabled={submitting}
              >
                <option value="hex">hex</option>
                <option value="base64">base64</option>
              </select>
            </label>
            <label className="field">
              <span>signature prefix</span>
              <input
                aria-label="signature prefix"
                value={signaturePrefix}
                onChange={e => setSignaturePrefix(e.target.value)}
                placeholder="sha256="
                disabled={submitting}
                autoComplete="off"
              />
            </label>
            <label className="field">
              <span>signature separator</span>
              <input
                aria-label="signature separator"
                value={signatureSeparator}
                onChange={e => setSignatureSeparator(e.target.value)}
                placeholder="space or comma for multi-sig headers"
                disabled={submitting}
                autoComplete="off"
              />
            </label>
            <label className="field">
              <span>value split</span>
              <input
                aria-label="signature value split"
                value={signatureValueSplit}
                onChange={e => setSignatureValueSplit(e.target.value)}
                placeholder="= or ,"
                disabled={submitting}
                autoComplete="off"
              />
            </label>
            <label className="field">
              <span>timestamp header</span>
              <input
                aria-label="timestamp header"
                value={timestampHeader}
                onChange={e => setTimestampHeader(e.target.value.toLowerCase())}
                placeholder="webhook-timestamp"
                disabled={submitting}
                autoComplete="off"
              />
            </label>
            <label className="field">
              <span>timestamp skew seconds</span>
              <input
                aria-label="timestamp skew seconds"
                type="number"
                min="0"
                value={timestampSkewSecs}
                onChange={e => setTimestampSkewSecs(e.target.value)}
                disabled={submitting}
              />
            </label>
            <label className="field">
              <span>idempotency header</span>
              <input
                aria-label="idempotency header"
                value={idempotencyHeader}
                onChange={e => setIdempotencyHeader(e.target.value.toLowerCase())}
                placeholder="webhook-id"
                disabled={submitting}
                autoComplete="off"
              />
            </label>
          </div>
          <label className="field">
            <span>payload template</span>
            <input
              aria-label="payload template"
              value={payloadTemplate}
              onChange={e => setPayloadTemplate(e.target.value)}
              placeholder="{{body}}"
              disabled={submitting}
              autoComplete="off"
            />
            <small className="muted">
              Placeholders: {'{{body}}'}, {'{{timestamp}}'}, {'{{id}}'}, {'{{version}}'}.
            </small>
          </label>
          {editing ? (
            <section className="task-verify-widget" aria-label="verify recorded delivery">
              <label className="field">
                <span>Paste a recorded delivery (headers + body)</span>
                <textarea
                  aria-label="recorded delivery"
                  className="textarea"
                  value={recordedDelivery}
                  onChange={e => setRecordedDelivery(e.target.value)}
                  rows={5}
                  placeholder={'webhook-id: msg_123\nwebhook-timestamp: 1700000000\n\n{"event":"ping"}'}
                  disabled={verifying}
                />
              </label>
              <div className="panel-actions">
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={verifyRecorded}
                  disabled={verifying || !recordedDelivery.trim()}
                >
                  {verifying ? 'verifying…' : 'verify'}
                </button>
              </div>
              {verifyResult ? (
                <VerifyResult result={verifyResult}/>
              ) : null}
            </section>
          ) : null}
        </section>

        <section className="page-section">
          <h2 className="section-title">agent instructions</h2>
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
              Prepended to every webhook delivery. Tell the agent what to do with each payload.
            </small>
          </label>
          {description.trim() ? (
            <section className="task-instructions-preview" aria-label="instructions preview">
              <div className="muted small">preview</div>
              <TaskMarkdown markdown={description}/>
            </section>
          ) : null}
        </section>

        <section className="page-section">
          <h2 className="section-title">status</h2>
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
            When unchecked, the provider URL returns 404. The row stays
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
          {submitting ? 'saving…' : (editing ? 'save' : 'create webhook')}
        </button>
        <a className="btn btn-ghost" href={backHref}>cancel</a>
      </div>
    </div>
  );
}

const TaskMarkdown = React.memo(function TaskMarkdown({ markdown }) {
  return (
    <div className="task-prose">
      <ReactMarkdown
        remarkPlugins={TASK_MARKDOWN_PLUGINS}
        components={TASK_MARKDOWN_COMPONENTS}
      >
        {markdown}
      </ReactMarkdown>
    </div>
  );
});

function VerifyResult({ result }) {
  if (result?.ok) {
    const rendered = b64DecodeText(result.rendered_payload_b64 || '');
    return (
      <div className="success small">
        <div>matched {result.matched_version || 'signature'}</div>
        {rendered ? <pre className="audit-body">{rendered}</pre> : null}
      </div>
    );
  }
  const reason = result?.type || result?.reason || 'verify failed';
  return <div className="error small">{reason}</div>;
}

function UrlField({ value, disabled = false }) {
  const [copied, setCopied] = React.useState(false);
  const copy = async (e) => {
    e.preventDefault();
    if (disabled) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1100);
    } catch { /* ignore */ }
  };
  return (
    <div className="task-url-field">
      <input aria-label="url" value={value} readOnly className="mono-sm" aria-invalid={disabled ? 'true' : undefined}/>
      <button type="button" className="btn btn-ghost btn-sm" onClick={copy} disabled={disabled}>
        {disabled ? 'name first' : (copied ? 'copied!' : 'copy')}
      </button>
    </div>
  );
}

function DeliveriesPanel({ instanceId, taskName }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState(null);
  const [inspectRow, setInspectRow] = React.useState(null);
  const [hexMode, setHexMode] = React.useState(false);

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

  const inspect = async (delivery) => {
    setErr(null);
    setHexMode(false);
    try {
      const row = await client.getDelivery(instanceId, delivery.id);
      setInspectRow(row);
    } catch (e) {
      setErr(e?.detail || e?.message || 'inspect failed');
    }
  };

  const replay = async (delivery) => {
    setErr(null);
    try {
      await client.replayWebhookDelivery(instanceId, taskName, delivery.id);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'replay failed');
    }
  };

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
        <EmptyState title="no deliveries yet">
          Fire this webhook URL to see each delivery recorded here.
        </EmptyState>
      ) : (
        <ul className="deliveries-list">
          {rows.map(d => (
            <li key={d.id} className={`deliveries-row ${d.signature_ok ? '' : 'sig-bad'}`}>
              <div className="deliveries-row-head">
                <span className={`badge ${d.status_code < 400 ? 'badge-ok' : 'badge-warn'}`}>
                  {d.status_code}
                </span>
                <span className="muted small">{fmtTime(d.fired_at, { style: 'locale' })}</span>
                <span className="muted small">{d.latency_ms}ms</span>
                {!d.signature_ok ? <span className="badge badge-warn small">bad signature</span> : null}
                {d.request_id ? <code className="mono-sm muted">{shortId(d.request_id)}</code> : null}
              </div>
              {d.error ? <div className="deliveries-row-err small">{d.error}</div> : null}
              <div className="deliveries-row-actions">
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => inspect(d)}>
                  Inspect
                </button>
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => replay(d)}>
                  Replay
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
      {inspectRow ? (
        <section className="panel task-inspect-modal" role="dialog" aria-label="delivery inspect">
          <div className="panel-header">
            <div className="panel-title">request bytes</div>
            <div className="panel-actions">
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setHexMode(h => !h)}
              >
                {hexMode ? 'view as text' : 'view as hex'}
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setInspectRow(null)}
              >
                close
              </button>
            </div>
          </div>
          {inspectRow.request_headers ? (
            <pre className="audit-body">{JSON.stringify(inspectRow.request_headers, null, 2)}</pre>
          ) : null}
          <pre className="audit-body">
            {hexMode
              ? textToHex(inspectRow.body_text ?? b64DecodeText(inspectRow.body_b64 || ''))
              : (inspectRow.body_text ?? b64DecodeText(inspectRow.body_b64 || ''))}
          </pre>
        </section>
      ) : null}
    </section>
  );
}

// ─── Audit list + detail ──────────────────────────────────────────
//
// `AuditListPage` is the cross-task delivery log: every fire across
// every task on the instance, newest first, with task filtering and
// cursor pagination. Detail pages link from here.

const AUDIT_PAGE_SIZE = 50;

export function AuditListPage({ instanceId, embedded = false }) {
  const { client } = useApi();
  const backHref = `#/i/${encodeURIComponent(instanceId)}/tasks`;
  // Pages are tracked as a stack of `before` cursors so the user can
  // page forward by appending the oldest fired_at, and backward by
  // popping.  The first page has cursor=null (= unbounded).
  const [cursors, setCursors] = React.useState([null]);
  const [rows, setRows] = React.useState(null);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState(null);
  const [webhookFilter, setWebhookFilter] = React.useState('');
  const slot = useAppState(s => s.webhooks.byInstance[instanceId]);
  const taskNames = React.useMemo(
    () => (slot?.rows || []).map(r => r.name),
    [slot],
  );
  const filterNames = React.useMemo(() => {
    const names = new Set(taskNames);
    (rows || []).forEach(r => {
      if (r?.webhook_name) names.add(r.webhook_name);
    });
    return Array.from(names).sort((a, b) => a.localeCompare(b));
  }, [taskNames, rows]);

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
        webhook: webhookFilter || undefined,
      });
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'load failed');
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, [client, instanceId, cursor, webhookFilter]);

  React.useEffect(() => { refresh(); }, [refresh]);

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') window.location.hash = backHref; };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [backHref]);

  const clearFilter = () => {
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

  const Shell = embedded ? 'div' : 'main';
  return (
    <Shell className={embedded ? 'instance-subpage' : 'page page-edit'}>
      <header className={embedded ? 'subpage-header' : 'page-header'}>
        <a className="btn btn-ghost btn-sm" href={backHref}>← webhooks</a>
        <h1 className={embedded ? 'subpage-title' : 'page-title'}>audit</h1>
        <p className="page-sub muted">
          Every webhook delivery on this agent, newest first. Click a row
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

        <div className="audit-filters">
          <select
            className="audit-task-filter"
            value={webhookFilter}
            onChange={e => { setWebhookFilter(e.target.value); setCursors([null]); }}
            title="filter by webhook"
          >
            <option value="">all webhooks</option>
            {filterNames.map(n => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          {webhookFilter ? (
            <button type="button" className="btn btn-ghost btn-sm" onClick={clearFilter}>
              clear
            </button>
          ) : null}
        </div>

        {err ? <div className="error">{err}</div> : null}

        {rows === null ? (
          <p className="muted small">loading…</p>
        ) : rows.length === 0 ? (
          <AuditEmpty
            filtered={!!webhookFilter}
            onClear={clearFilter}
          />
        ) : (
          <table className="rows audit-table">
            <thead><tr>
              <th>when</th>
              <th>webhook</th>
              <th>status</th>
              <th>latency</th>
              <th>size</th>
              <th>request id</th>
            </tr></thead>
            <tbody>
              {rows.map(d => {
                const detailHref = `#/i/${encodeURIComponent(instanceId)}/tasks/audit/${encodeURIComponent(d.id)}`;
                const deletedTask = !!slot && d.webhook_name && !taskNames.includes(d.webhook_name);
                return (
                  <tr key={d.id} className={d.signature_ok ? '' : 'sig-bad'}>
                    <td data-label="when" className="muted small">
                      <a className="audit-row-link" href={detailHref}>{fmtTime(d.fired_at, { style: 'locale' })}</a>
                    </td>
                    <td data-label="webhook">
                      <code className="mono-sm">{d.webhook_name}</code>
                      {deletedTask ? (
                        <span className="badge badge-faint small audit-deleted-task">deleted</span>
                      ) : null}
                    </td>
                    <td data-label="status">
                      <span className={`badge ${d.status_code < 400 ? 'badge-ok' : 'badge-warn'}`}>
                        {d.status_code}
                      </span>
                      {!d.signature_ok ? (
                        <span className="badge badge-warn small audit-status-badge">bad sig</span>
                      ) : null}
                    </td>
                    <td data-label="latency" className="muted small">{d.latency_ms}ms</td>
                    <td data-label="size" className="muted small">{fmtBytes(d.body_size)}</td>
                    <td data-label="request id" className="muted small">
                      {d.request_id ? <code className="mono-sm">{shortId(d.request_id)}</code> : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        <Pager
          className="audit-pager"
          label={`page ${onPage}`}
          canPrev={canPrev}
          canNext={canNext}
          onPrev={prevPage}
          onNext={nextPage}
          disabled={loading}
          prevLabel="← newer"
          nextLabel="older →"
        />
      </section>
    </Shell>
  );
}

export function AuditDetailPage({ instanceId, deliveryId, embedded = false }) {
  const { client } = useApi();
  const slot = useAppState(s => s.webhooks.byInstance[instanceId]);
  const taskNames = React.useMemo(
    () => (slot?.rows || []).map(r => r.name),
    [slot],
  );
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
    let cancelled = false;
    if (!slot) {
      client.listWebhooks(instanceId)
        .then(list => { if (!cancelled) setWebhooksFor(instanceId, list || []); })
        .catch(() => { /* detail still renders even if the roster cannot load */ });
    }
    return () => { cancelled = true; };
  }, [client, instanceId, slot]);

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') window.location.hash = backHref; };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [backHref]);

  const Shell = embedded ? 'div' : 'main';
  return (
    <Shell className={embedded ? 'instance-subpage' : 'page page-edit'}>
      <header className={embedded ? 'subpage-header' : 'page-header'}>
        <a className="btn btn-ghost btn-sm" href={backHref}>← audit</a>
        <h1 className={embedded ? 'subpage-title' : 'page-title'}>delivery</h1>
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
              <dt>webhook</dt>
              <dd>
                <code className="mono-sm">{row.webhook_name}</code>{' '}
                {slot && taskNames.includes(row.webhook_name) ? (
                  <a
                    className="muted small"
                    href={`#/i/${encodeURIComponent(instanceId)}/tasks/${encodeURIComponent(row.webhook_name)}`}
                  >
                    open webhook
                  </a>
                ) : slot ? (
                  <span className="badge badge-faint small">deleted</span>
                ) : null}
              </dd>
              <dt>fired</dt><dd>{fmtTime(row.fired_at, { style: 'locale' })}</dd>
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
    </Shell>
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

function AuditEmpty({ filtered, onClear }) {
  return (
    <EmptyState
      title={filtered ? 'no deliveries match' : 'no deliveries yet'}
      actions={filtered ? (
        <button type="button" className="btn btn-ghost btn-sm" onClick={onClear}>
          clear filters
        </button>
      ) : null}
    >
      {filtered
        ? 'Pick a different webhook, or clear the filter.'
        : 'Each successful or failed webhook delivery records a row here. POST to a webhook URL to see one show up.'}
    </EmptyState>
  );
}
