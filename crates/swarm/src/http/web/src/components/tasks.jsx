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
const CUSTOM_TAB_ID = 'custom';
const DEFAULT_PRESET = WEBHOOK_PRESETS[0];
const VERIFICATION_TABS = [...WEBHOOK_PRESETS, {
  id: CUSTOM_TAB_ID,
  label: 'Custom',
  docs_url: '',
}];
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

function nullableExactText(value) {
  const s = String(value ?? '');
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
  try {
    const parsed = JSON.parse(normalised);
    if (parsed && typeof parsed === 'object' && parsed.headers) {
      return {
        headers: parsed.headers || {},
        body_b64: parsed.body_b64 || b64Text(parsed.body || ''),
      };
    }
  } catch { /* raw HTTP-ish format below */ }
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

function randomBase64Url(bytes = 32) {
  const buf = new Uint8Array(bytes);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < buf.length; i += 1) buf[i] = Math.floor(Math.random() * 256);
  }
  let raw = '';
  buf.forEach(b => { raw += String.fromCharCode(b); });
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function humanVerifyReason(result) {
  const type = result?.type || result?.reason || 'verify failed';
  switch (type) {
    case 'all_signatures_mismatched':
      return 'All signatures did not match the shared secret and signed payload.';
    case 'missing_signature':
      return 'The configured signature header was missing.';
    case 'missing_timestamp':
      return 'The timestamp header was missing.';
    case 'timestamp_out_of_skew':
      return 'The timestamp was outside the allowed clock skew.';
    case 'missing_header':
      return `Missing required header${result?.name ? `: ${result.name}` : ''}.`;
    case 'malformed_signature':
      return `The signature header could not be decoded${result?.reason ? `: ${result.reason}` : ''}.`;
    case 'unknown_version':
      return `The signature version is not configured${result?.version ? `: ${result.version}` : ''}.`;
    default:
      return String(type).replaceAll('_', ' ');
  }
}

function hexPreview(text, limit = 48) {
  const hex = textToHex(text);
  return hex.length > limit ? `${hex.slice(0, limit)}…` : hex;
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
  const [selectedTab, setSelectedTab] = React.useState(DEFAULT_PRESET.id);
  const [scheme, setScheme] = React.useState(DEFAULT_PRESET.auth_scheme);
  const [signatureHeader, setSignatureHeader] = React.useState(DEFAULT_PRESET.signature_header);
  const [verifierMode, setVerifierMode] = React.useState(DEFAULT_PRESET.verifier_mode);
  const [signatureAlgo, setSignatureAlgo] = React.useState(DEFAULT_PRESET.signature_algo);
  const [signatureEncoding, setSignatureEncoding] = React.useState(DEFAULT_PRESET.signature_encoding);
  const [signaturePrefix, setSignaturePrefix] = React.useState(DEFAULT_PRESET.signature_prefix);
  const [signatureSeparator, setSignatureSeparator] = React.useState(DEFAULT_PRESET.signature_separator);
  const [signatureValueSplit, setSignatureValueSplit] = React.useState(DEFAULT_PRESET.signature_value_split);
  const [timestampHeader, setTimestampHeader] = React.useState(DEFAULT_PRESET.timestamp_header);
  const [timestampSkewSecs, setTimestampSkewSecs] = React.useState(String(DEFAULT_PRESET.timestamp_skew_secs));
  const [payloadTemplate, setPayloadTemplate] = React.useState(DEFAULT_PRESET.payload_template);
  const [idempotencyHeader, setIdempotencyHeader] = React.useState(DEFAULT_PRESET.idempotency_header);
  const [bearerPathToken, setBearerPathToken] = React.useState('');
  const [secret, setSecret] = React.useState('');
  const [hasSecret, setHasSecret] = React.useState(false);
  const [secretEditing, setSecretEditing] = React.useState(!editing);
  const [secretRevealed, setSecretRevealed] = React.useState(false);
  const [enabled, setEnabled] = React.useState(true);
  const [danger, setDanger] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [toast, setToast] = React.useState(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [origScheme, setOrigScheme] = React.useState('hmac_sha256');
  const [recordedDelivery, setRecordedDelivery] = React.useState('');
  const [verifyResult, setVerifyResult] = React.useState(null);
  const [verifying, setVerifying] = React.useState(false);
  const [providerPath, setProviderPath] = React.useState(null);

  React.useEffect(() => {
    if (!editing) return;
    let cancelled = false;
    client.getWebhook(instanceId, taskName).then(row => {
      if (cancelled || !row) return;
      setName(row.name);
      setDescription(row.description || '');
      setSelectedTab(row.preset_id && WEBHOOK_PRESETS.some(p => p.id === row.preset_id)
        ? row.preset_id
        : CUSTOM_TAB_ID);
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
      setBearerPathToken(row.bearer_path_token || '');
      setHasSecret(!!row.has_secret);
      setSecret('');
      setSecretEditing(!row.has_secret);
      setProviderPath(row.path || null);
      setEnabled(!!row.enabled);
      setLoaded(true);
    }).catch(e => {
      if (!cancelled) setErr(e?.detail || e?.message || 'load failed');
    });
    return () => { cancelled = true; };
  }, [client, editing, instanceId, taskName]);

  const selectedPreset = WEBHOOK_PRESETS.find(p => p.id === selectedTab) || null;
  const isVendorTab = !!selectedPreset;
  const schemeChanged = editing && scheme !== origScheme;
  const usesHmac = isVendorTab || scheme === 'hmac_sha256' || verifierMode === 'hmac_v2';
  const needsSecret = isVendorTab || (scheme !== 'none' && verifierMode !== 'none' && verifierMode !== 'bearer_v2');
  const requireSecretOnSave = needsSecret && (!editing || schemeChanged || !hasSecret || secretEditing);
  const secretTooShort = needsSecret && secretEditing && secret.length > 0 && secret.length < 16;

  const applyPreset = (preset) => {
    setSelectedTab(preset.id);
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

  const selectCustom = () => {
    setSelectedTab(CUSTOM_TAB_ID);
    if (scheme === 'hmac_sha256') {
      setVerifierMode('hmac_v2');
    }
    setVerifyResult(null);
  };

  const selectScheme = (value) => {
    setSelectedTab(CUSTOM_TAB_ID);
    setScheme(value);
    setDanger(false);
    if (value === 'hmac_sha256') {
      setVerifierMode('hmac_v2');
      setSignatureHeader(signatureHeader || DEFAULT_PRESET.signature_header);
      setSignatureAlgo(signatureAlgo || DEFAULT_PRESET.signature_algo);
      setSignatureEncoding(signatureEncoding || DEFAULT_PRESET.signature_encoding);
      setPayloadTemplate(payloadTemplate || DEFAULT_PRESET.payload_template);
    } else if (value === 'bearer') {
      setVerifierMode('bearer_v2');
      if (!bearerPathToken) setBearerPathToken(`whp_${randomBase64Url(24)}`);
    } else {
      setVerifierMode('none');
    }
  };

  const verifierBody = () => ({
    verifier_mode: verifierMode,
    signature_algo: nullableText(signatureAlgo),
    signature_encoding: nullableText(signatureEncoding),
    signature_prefix: nullableText(signaturePrefix),
    signature_separator: nullableExactText(signatureSeparator),
    signature_value_split: nullableText(signatureValueSplit),
    timestamp_header: nullableText(timestampHeader),
    timestamp_skew_secs: timestampSkewSecs === '' ? null : Number(timestampSkewSecs),
    payload_template: nullableText(payloadTemplate),
    idempotency_header: nullableText(idempotencyHeader),
    bearer_path_token: verifierMode === 'bearer_v2' ? nullableText(bearerPathToken) : null,
  });

  const saveDisabledReason = (() => {
    if (submitting) return null;
    if (requireSecretOnSave && !secret) return 'save disabled: secret is empty';
    if (secretTooShort) return 'secret is too short — vendors require ≥ 16 chars';
    if (scheme === 'none' && !danger) return 'save disabled: confirm no-auth risk';
    if (!editing && !validTaskSlug(name)) return 'save disabled: enter a valid webhook name';
    return null;
  })();

  const submit = async (e) => {
    e.preventDefault();
    if (submitting) return;
    setErr(null);
    if (saveDisabledReason) {
      setErr(saveDisabledReason);
      return;
    }
    setSubmitting(true);
    try {
      const preset_id = isVendorTab ? selectedPreset.id : null;
      if (editing) {
        const body = { description, preset_id, auth_scheme: scheme, enabled, ...verifierBody() };
        if (usesHmac) body.signature_header = signatureHeader.trim() || DEFAULT_SIGNATURE_HEADER;
        if (secretEditing && secret) body.secret = secret;
        const updated = await client.updateWebhook(instanceId, taskName, body);
        upsertWebhook(instanceId, updated);
      } else {
        const body = { name, description, preset_id, auth_scheme: scheme, enabled, ...verifierBody() };
        if (usesHmac) body.signature_header = signatureHeader.trim() || DEFAULT_SIGNATURE_HEADER;
        if (secretEditing && secret) body.secret = secret;
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

  const verifyLastFailed = async () => {
    if (!editing || verifying) return;
    setVerifying(true);
    setVerifyResult(null);
    setErr(null);
    try {
      const result = await client.verifyWebhookDelivery(
        instanceId,
        taskName,
        null,
        { fromLastFailed: true },
      );
      setVerifyResult(result);
    } catch (e) {
      setVerifyResult({ type: 'request_failed', reason: e?.detail || e?.message || 'verify failed' });
    } finally {
      setVerifying(false);
    }
  };

  const generateSecret = async () => {
    const next = randomBase64Url(32);
    setSecret(next);
    setSecretEditing(true);
    setSecretRevealed(false);
    try {
      await navigator.clipboard?.writeText(next);
      setToast('Generated and copied. Save before closing.');
    } catch {
      setToast('Generated. Save before closing.');
    }
  };

  const rotateBearerPath = () => {
    setBearerPathToken(`whp_${randomBase64Url(24)}`);
  };

  if (editing && !loaded) {
    return <div className="muted">loading…</div>;
  }

  const activeSlug = editing ? taskName : name;
  const urlReady = validTaskSlug(activeSlug);
  const fullUrl = editing && providerPath && typeof window !== 'undefined'
    ? `${window.location.origin}${providerPath}`
    : webhookUrlFor(instanceId, activeSlug, { showPlaceholder: true });

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
                  ? 'Copy this into the provider. Configure the provider with the verifier below.'
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
          <VerificationTabs
            selectedTab={selectedTab}
            onSelect={(id) => {
              const preset = WEBHOOK_PRESETS.find(p => p.id === id);
              if (preset) applyPreset(preset);
              else selectCustom();
            }}
            disabled={submitting}
          />
          {selectedPreset ? (
            <>
              <VendorSummary preset={selectedPreset}/>
              <SecretControl
                secret={secret}
                setSecret={setSecret}
                hasSecret={hasSecret}
                editing={secretEditing}
                setEditing={setSecretEditing}
                revealed={secretRevealed}
                setRevealed={setSecretRevealed}
                onGenerate={generateSecret}
                disabled={submitting}
                error={secretTooShort ? 'secret is too short — vendors require ≥ 16 chars' : null}
              />
            </>
          ) : (
            <CustomVerificationFields
              scheme={scheme}
              selectScheme={selectScheme}
              verifierMode={verifierMode}
              setVerifierMode={setVerifierMode}
              signatureHeader={signatureHeader}
              setSignatureHeader={setSignatureHeader}
              signatureAlgo={signatureAlgo}
              setSignatureAlgo={setSignatureAlgo}
              signatureEncoding={signatureEncoding}
              setSignatureEncoding={setSignatureEncoding}
              signaturePrefix={signaturePrefix}
              setSignaturePrefix={setSignaturePrefix}
              signatureSeparator={signatureSeparator}
              setSignatureSeparator={setSignatureSeparator}
              signatureValueSplit={signatureValueSplit}
              setSignatureValueSplit={setSignatureValueSplit}
              timestampHeader={timestampHeader}
              setTimestampHeader={setTimestampHeader}
              timestampSkewSecs={timestampSkewSecs}
              setTimestampSkewSecs={setTimestampSkewSecs}
              payloadTemplate={payloadTemplate}
              setPayloadTemplate={setPayloadTemplate}
              idempotencyHeader={idempotencyHeader}
              setIdempotencyHeader={setIdempotencyHeader}
              bearerPathToken={bearerPathToken}
              setBearerPathToken={setBearerPathToken}
              rotateBearerPath={rotateBearerPath}
              secretProps={{
                secret,
                setSecret,
                hasSecret,
                editing: secretEditing,
                setEditing: setSecretEditing,
                revealed: secretRevealed,
                setRevealed: setSecretRevealed,
                onGenerate: generateSecret,
                disabled: submitting,
                error: secretTooShort ? 'secret is too short — vendors require ≥ 16 chars' : null,
              }}
              danger={danger}
              setDanger={setDanger}
              disabled={submitting}
            />
          )}
          {toast ? <div className="success small">{toast}</div> : null}
          <VerifyWidget
            editing={editing}
            selectedLabel={selectedPreset?.label || 'custom provider'}
            recordedDelivery={recordedDelivery}
            setRecordedDelivery={setRecordedDelivery}
            verifyRecorded={verifyRecorded}
            verifyLastFailed={verifyLastFailed}
            verifyResult={verifyResult}
            verifying={verifying}
          />
          <ProviderUrlBlock
            value={fullUrl}
            disabled={!urlReady}
            vendorLabel={selectedPreset?.label || 'provider'}
            docsUrl={selectedPreset?.docs_url || ''}
          />
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
          disabled={submitting || !!saveDisabledReason}
        >
          {submitting ? 'saving…' : (editing ? 'save' : 'create webhook')}
        </button>
        {saveDisabledReason ? <span className="muted small">{saveDisabledReason}</span> : null}
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

function VerificationTabs({ selectedTab, onSelect, disabled }) {
  const refs = React.useRef([]);
  const onKeyDown = (e, idx) => {
    if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(e.key)) return;
    e.preventDefault();
    let next = idx;
    if (e.key === 'ArrowRight') next = (idx + 1) % VERIFICATION_TABS.length;
    if (e.key === 'ArrowLeft') next = (idx - 1 + VERIFICATION_TABS.length) % VERIFICATION_TABS.length;
    if (e.key === 'Home') next = 0;
    if (e.key === 'End') next = VERIFICATION_TABS.length - 1;
    refs.current[next]?.focus();
    onSelect(VERIFICATION_TABS[next].id);
  };
  return (
    <div className="task-verification-tabs" role="tablist" aria-label="verification presets">
      {VERIFICATION_TABS.map((tab, idx) => (
        <button
          key={tab.id}
          ref={el => { refs.current[idx] = el; }}
          type="button"
          role="tab"
          aria-selected={selectedTab === tab.id}
          tabIndex={selectedTab === tab.id ? 0 : -1}
          className={`task-verification-tab ${selectedTab === tab.id ? 'selected' : ''} ${tab.id === CUSTOM_TAB_ID ? 'custom' : ''}`}
          onClick={() => onSelect(tab.id)}
          onKeyDown={e => onKeyDown(e, idx)}
          disabled={disabled}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

function VendorSummary({ preset }) {
  const rows = [
    ['Algorithm', preset.signature_algo || 'sha256', 'Hash algorithm used by this vendor.'],
    ['Encoding', preset.signature_encoding || 'hex', 'How the binary HMAC is encoded in the header.'],
    ['Signature header', preset.signature_header, 'Header that carries one or more signatures.'],
    ['Payload signed', preset.payload_template, 'Exact byte template verified before dispatch.'],
  ];
  if (preset.timestamp_header) {
    rows.push([
      'Timestamp header',
      `${preset.timestamp_header} (${preset.timestamp_skew_secs || 300}s skew)`,
      'Header used for replay-window checks.',
    ]);
  }
  if (preset.idempotency_header) {
    rows.push(['Idempotency', preset.idempotency_header, 'Header used to dedupe replayed deliveries.']);
  }
  rows.push(['Docs', preset.docs_url, 'Vendor verification documentation.']);
  return (
    <section className="task-vendor-summary" aria-label={`${preset.label} verification summary`}>
      {rows.map(([label, value, title]) => (
        <div key={label} className="task-summary-row" title={title}>
          <dt>{label}</dt>
          <dd>
            {label === 'Docs' ? (
              <a href={value} target="_blank" rel="noopener noreferrer">{value}</a>
            ) : (
              <code>{value}</code>
            )}
          </dd>
        </div>
      ))}
    </section>
  );
}

function SecretControl({
  secret,
  setSecret,
  hasSecret,
  editing,
  setEditing,
  revealed,
  setRevealed,
  onGenerate,
  disabled,
  error,
}) {
  if (hasSecret && !editing) {
    return (
      <div className="field task-secret-stored">
        <span>shared secret</span>
        <div className="task-secret-stored-row">
          <code>••••••••</code>
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setEditing(true)}>
            Replace
          </button>
        </div>
        <small className="muted">The existing secret is stored server-side and is never sent back to this page.</small>
      </div>
    );
  }
  return (
    <label className="field">
      <span>shared secret</span>
      <div className="task-secret-row">
        <input
          aria-label="shared secret"
          className="task-verification-input"
          type={revealed ? 'text' : 'password'}
          value={secret}
          onChange={e => setSecret(e.target.value)}
          placeholder="paste or generate a strong random string"
          disabled={disabled}
          autoComplete="off"
        />
        <button type="button" className="btn btn-ghost btn-sm" onClick={onGenerate} disabled={disabled}>
          Generate
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => setRevealed(!revealed)}
          disabled={disabled}
        >
          {revealed ? 'Hide' : 'Reveal'}
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => navigator.clipboard?.writeText(secret)}
          disabled={!secret}
        >
          Copy
        </button>
      </div>
      {error ? <small className="error small">{error}</small> : (
        <small className="muted">Use the same secret in the vendor dashboard.</small>
      )}
    </label>
  );
}

function CustomVerificationFields({
  scheme,
  selectScheme,
  verifierMode,
  setVerifierMode,
  signatureHeader,
  setSignatureHeader,
  signatureAlgo,
  setSignatureAlgo,
  signatureEncoding,
  setSignatureEncoding,
  signaturePrefix,
  setSignaturePrefix,
  signatureSeparator,
  setSignatureSeparator,
  signatureValueSplit,
  setSignatureValueSplit,
  timestampHeader,
  setTimestampHeader,
  timestampSkewSecs,
  setTimestampSkewSecs,
  payloadTemplate,
  setPayloadTemplate,
  idempotencyHeader,
  setIdempotencyHeader,
  bearerPathToken,
  setBearerPathToken,
  rotateBearerPath,
  secretProps,
  danger,
  setDanger,
  disabled,
}) {
  return (
    <>
      <div className="task-scheme-grid">
        {SCHEMES.map(s => (
          <label key={s.value} className={`task-scheme ${scheme === s.value ? 'selected' : ''} ${s.value === 'none' ? 'danger' : ''}`}>
            <input
              type="radio"
              name="auth-scheme"
              value={s.value}
              checked={scheme === s.value}
              onChange={() => selectScheme(s.value)}
              disabled={disabled}
            />
            <div className="task-scheme-body">
              <div className="task-scheme-label">{s.label}</div>
              <div className="task-scheme-hint muted small">{s.hint}</div>
            </div>
          </label>
        ))}
      </div>
      {scheme === 'hmac_sha256' ? (
        <>
          <SecretControl {...secretProps}/>
          <label className="field">
            <span>signature header</span>
            <input
              aria-label="signature header"
              className="task-verification-input"
              value={signatureHeader}
              onChange={e => setSignatureHeader(e.target.value.toLowerCase())}
              placeholder={DEFAULT_SIGNATURE_HEADER}
              disabled={disabled}
              autoComplete="off"
            />
          </label>
          <div className="task-verifier-grid">
            <label className="field">
              <span>verifier mode</span>
              <select
                aria-label="verifier mode"
                className="task-verification-input"
                value={verifierMode}
                onChange={e => setVerifierMode(e.target.value)}
                disabled={disabled}
              >
                <option value="legacy_hmac">legacy_hmac</option>
                <option value="hmac_v2">hmac_v2</option>
              </select>
            </label>
            <label className="field">
              <span>algorithm</span>
              <select
                aria-label="signature algorithm"
                className="task-verification-input"
                value={signatureAlgo}
                onChange={e => setSignatureAlgo(e.target.value)}
                disabled={disabled}
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
                className="task-verification-input"
                value={signatureEncoding}
                onChange={e => setSignatureEncoding(e.target.value)}
                disabled={disabled}
              >
                <option value="hex">hex</option>
                <option value="base64">base64</option>
              </select>
            </label>
            <TextInput label="signature prefix" value={signaturePrefix} setValue={setSignaturePrefix} disabled={disabled}/>
            <TextInput label="signature separator" value={signatureSeparator} setValue={setSignatureSeparator} disabled={disabled}/>
            <TextInput label="signature value split" value={signatureValueSplit} setValue={setSignatureValueSplit} disabled={disabled}/>
            <TextInput label="timestamp header" value={timestampHeader} setValue={(v) => setTimestampHeader(v.toLowerCase())} disabled={disabled}/>
            <label className="field">
              <span>timestamp skew seconds</span>
              <input
                aria-label="timestamp skew seconds"
                className="task-verification-input"
                type="number"
                min="0"
                value={timestampSkewSecs}
                onChange={e => setTimestampSkewSecs(e.target.value)}
                disabled={disabled}
              />
            </label>
            <TextInput label="idempotency header" value={idempotencyHeader} setValue={(v) => setIdempotencyHeader(v.toLowerCase())} disabled={disabled}/>
          </div>
          <label className="field">
            <span>payload template</span>
            <input
              aria-label="payload template"
              className="task-verification-input"
              value={payloadTemplate}
              onChange={e => setPayloadTemplate(e.target.value)}
              placeholder="{{body}}"
              disabled={disabled}
              autoComplete="off"
            />
            <small className="muted">
              Placeholders: {'{{body}}'}, {'{{timestamp}}'}, {'{{id}}'}, {'{{version}}'}.
            </small>
          </label>
        </>
      ) : null}
      {scheme === 'bearer' ? (
        <label className="field">
          <span>path token</span>
          <div className="task-secret-row">
            <input
              aria-label="path token"
              className="task-verification-input"
              value={bearerPathToken}
              onChange={e => setBearerPathToken(e.target.value)}
              disabled={disabled}
              autoComplete="off"
            />
            <button type="button" className="btn btn-ghost btn-sm" onClick={rotateBearerPath}>
              Rotate
            </button>
          </div>
          <small className="muted">Caller sends Authorization: Bearer &lt;secret&gt;. No replay protection.</small>
        </label>
      ) : null}
      {scheme === 'none' ? (
        <label className="field check task-no-auth-warning">
          <input
            type="checkbox"
            checked={danger}
            onChange={e => setDanger(e.target.checked)}
            disabled={disabled}
          />
          <span>I understand this URL accepts any payload, signed or not.</span>
        </label>
      ) : null}
    </>
  );
}

function TextInput({ label, value, setValue, disabled }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        aria-label={label}
        className="task-verification-input"
        value={value}
        onChange={e => setValue(e.target.value)}
        disabled={disabled}
        autoComplete="off"
      />
    </label>
  );
}

function VerifyWidget({
  editing,
  selectedLabel,
  recordedDelivery,
  setRecordedDelivery,
  verifyRecorded,
  verifyLastFailed,
  verifyResult,
  verifying,
}) {
  if (!editing) {
    return (
      <section className="task-verify-widget" aria-label="verify recorded delivery">
        <div className="muted small">Save the webhook before testing recorded deliveries.</div>
      </section>
    );
  }
  return (
    <section className="task-verify-widget" aria-label="verify recorded delivery">
      <label className="field task-verify-input-cell">
        <span>{`Paste a recorded delivery — copy from ${selectedLabel}'s dashboard recent deliveries`}</span>
        <textarea
          aria-label="recorded delivery"
          className="textarea task-verification-input"
          value={recordedDelivery}
          onChange={e => setRecordedDelivery(e.target.value)}
          rows={7}
          placeholder={'webhook-id: msg_123\nwebhook-timestamp: 1700000000\n\n{"event":"ping"}'}
          disabled={verifying}
        />
      </label>
      <div className="task-verify-result-cell">
        <div className="panel-actions">
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={verifyRecorded}
            disabled={verifying || !recordedDelivery.trim()}
          >
            {verifying ? 'verifying…' : 'verify'}
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={verifyLastFailed}
            disabled={verifying}
          >
            Use last failed delivery
          </button>
        </div>
        {verifyResult ? <VerifyResult result={verifyResult}/> : (
          <div className="muted small">Result appears here without writing a delivery row.</div>
        )}
      </div>
    </section>
  );
}

function ProviderUrlBlock({ value, disabled, vendorLabel, docsUrl }) {
  return (
    <div className={`task-provider-url-block ${disabled ? 'pending' : ''}`}>
      <div className="muted small">Provider URL</div>
      <UrlField value={value} disabled={disabled} label="provider url" copyLabel="copy provider url" disabledLabel="enter name"/>
      <small className="muted">
        {docsUrl ? (
          <>Set this in {vendorLabel}'s dashboard at <a href={docsUrl} target="_blank" rel="noopener noreferrer">{docsUrl}</a>.</>
        ) : (
          'Set this in the provider dashboard.'
        )}
      </small>
    </div>
  );
}

function VerifyResult({ result }) {
  if (result?.ok) {
    const rendered = b64DecodeText(result.rendered_payload_b64 || '');
    return (
      <div className="success small">
        <div>✓ matched {result.matched_version || 'signature'}</div>
        {rendered ? <pre className="audit-body">{hexPreview(rendered)}</pre> : null}
      </div>
    );
  }
  return (
    <div className="error small">
      <div>✕ {humanVerifyReason(result)}</div>
      {result?.type ? <code>{result.type}</code> : null}
    </div>
  );
}

function UrlField({
  value,
  disabled = false,
  label = 'url',
  copyLabel = 'copy',
  disabledLabel = 'name first',
}) {
  const [copied, setCopied] = React.useState(false);
  const copy = async (e) => {
    e.preventDefault();
    if (disabled) return;
    try {
      await navigator.clipboard.writeText(value || '');
      setCopied(true);
      setTimeout(() => setCopied(false), 1100);
    } catch { /* ignore */ }
  };
  return (
    <div className="task-url-field">
      <input aria-label={label} value={value || ''} readOnly className="mono-sm" aria-invalid={disabled ? 'true' : undefined}/>
      <button type="button" className="btn btn-ghost btn-sm" onClick={copy} disabled={disabled}>
        {disabled ? disabledLabel : (copied ? 'copied!' : copyLabel)}
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
