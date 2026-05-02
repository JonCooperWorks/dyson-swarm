/* swarm — Provider Keys (BYOK) view.
 *
 * Lets the signed-in user manage their per-provider API keys.  The
 * server validates a key against the provider before persisting, so
 * a 422 here means the upstream rejected the value — usually a typo
 * or a revoked key.  Plaintext is never returned: cards only show
 * whether a key is set, never the value itself.
 *
 * Cards collapse to a single "header strip" by default and expand
 * inline with controls when clicked — accordion-style, only one
 * open at a time.  When the user has exactly one configured
 * provider (BYOK or platform-fallback), that card auto-opens on
 * mount so the most-likely-relevant one is one click away.
 *
 * `byo` is special: the user supplies BOTH an upstream URL and a
 * key, letting them point swarm at any OpenAI-compatible endpoint.
 * For everything else the upstream is fixed by the operator's TOML.
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';

/// Cosmetic metadata: a single-line subtitle shown under each
/// provider name.  Keeps the page from looking like a bare list of
/// strings.  Order in `PROVIDER_ORDER` is the *fallback* ordering;
/// `sortProviders` floats configured providers to the top so the
/// user's active credentials are always glanceable.
const PROVIDER_META = {
  anthropic:  { label: 'Anthropic',    blurb: 'Claude — api.anthropic.com'             },
  openai:     { label: 'OpenAI',       blurb: 'GPT-4o, o1 — api.openai.com'            },
  openrouter: { label: 'OpenRouter',   blurb: 'Aggregator — openrouter.ai'             },
  gemini:     { label: 'Gemini',       blurb: 'Google — generativelanguage api'        },
  groq:       { label: 'Groq',         blurb: 'Fast inference — api.groq.com'          },
  deepseek:   { label: 'DeepSeek',     blurb: 'DeepSeek — api.deepseek.com'            },
  xai:        { label: 'xAI',          blurb: 'Grok — api.x.ai'                        },
  ollama:     { label: 'Ollama Cloud', blurb: 'Hosted Ollama — ollama.com'             },
  byo:        { label: 'Custom (BYO)', blurb: 'Any OpenAI-compatible endpoint' },
};

const PROVIDER_ORDER = [
  'anthropic', 'openai', 'openrouter', 'gemini',
  'groq', 'deepseek', 'xai', 'ollama', 'byo',
];

/// Treats a provider as "configured" when the user has either
/// pasted a BYOK key or has an OR-minted key on file.  Platform
/// keys are no longer a real fallback for non-OR providers (BYOK-
/// or-503) so they don't count.
function isConfigured(p) {
  return p.has_byok || p.has_or_minted;
}

/// Sort: BYOK first (your own key), then OR-minted (per-user but
/// billed via the operator's OR Provisioning account), then
/// everything else.  Stable within each bucket — declaration order
/// from `PROVIDER_ORDER`.
function sortProviders(rows) {
  const baseIdx = (n) => {
    const i = PROVIDER_ORDER.indexOf(n);
    return i === -1 ? PROVIDER_ORDER.length : i;
  };
  const bucket = (p) => {
    if (p.has_byok) return 0;
    if (p.has_or_minted) return 1;
    return 2;
  };
  return [...rows].sort((a, b) => {
    const ba = bucket(a);
    const bb = bucket(b);
    if (ba !== bb) return ba - bb;
    return baseIdx(a.name) - baseIdx(b.name);
  });
}

export function ByokView() {
  const { client } = useApi();
  const [providers, setProviders] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [openName, setOpenName] = React.useState(null); // accordion: only one card open at a time
  const [editing, setEditing] = React.useState(null);   // {name} or null — modal state

  const refresh = React.useCallback(async () => {
    setErr(null);
    try {
      const list = await client.listProviders();
      const sorted = sortProviders(Array.isArray(list) ? list : []);
      setProviders(sorted);
      // Auto-open the single configured card on first load.  If the
      // user has already chosen something to look at, leave them be.
      setOpenName(prev => {
        if (prev !== null) return prev;
        const configured = sorted.filter(isConfigured);
        return configured.length === 1 ? configured[0].name : null;
      });
    } catch (e) {
      setErr(e?.detail || e?.message || 'list providers failed');
    }
  }, [client]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const onToggle = React.useCallback((name) => {
    setOpenName(prev => (prev === name ? null : name));
  }, []);

  const onDelete = React.useCallback(async (name) => {
    const meta = PROVIDER_META[name];
    if (!confirm(`Remove your ${meta?.label || name} key?`)) return;
    setBusy(true); setErr(null);
    try {
      await client.deleteByok(name);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete failed');
    } finally {
      setBusy(false);
    }
  }, [client, refresh]);

  return (
    <main className="page">
      <header className="page-header">
        <h1 className="page-title">provider keys</h1>
        <p className="page-sub muted">
          Bring your own key. Pasted keys are validated against the
          provider, encrypted under your account, and used for every
          call you make through the proxy. OpenRouter is the only
          platform-managed default — every other provider is
          BYOK-only, so the operator never absorbs your spend.
        </p>
      </header>

      {err ? <div className="error">{err}</div> : null}

      {providers === null ? (
        <p className="muted small">loading…</p>
      ) : (
        <section className="byok-list">
          {providers.map(p => (
            <ProviderRow
              key={p.name}
              provider={p}
              open={openName === p.name}
              busy={busy}
              onToggle={() => onToggle(p.name)}
              onEdit={() => setEditing({ name: p.name })}
              onDelete={() => onDelete(p.name)}
            />
          ))}
        </section>
      )}

      {editing ? (
        <ByokEditor
          provider={providers?.find(p => p.name === editing.name)}
          onClose={() => setEditing(null)}
          onSaved={async () => { setEditing(null); await refresh(); }}
        />
      ) : null}
    </main>
  );
}

function ProviderRow({ provider, open, busy, onToggle, onEdit, onDelete }) {
  const { name, has_byok, has_or_minted, supports_byo } = provider;
  const meta = PROVIDER_META[name] || { label: name, blurb: '' };

  let badge;
  if (has_byok) {
    badge = <span className="badge badge-ok">your key</span>;
  } else if (has_or_minted) {
    badge = <span className="badge badge-ok">minted for you</span>;
  } else if (supports_byo) {
    badge = <span className="badge badge-faint">no endpoint</span>;
  } else if (name === 'openrouter') {
    // OR has no per-user key yet — first /llm/openrouter call mints
    // one (when the operator has Provisioning wired up).
    badge = <span className="badge badge-faint">no key yet</span>;
  } else {
    // Every other provider is BYOK-or-503: the user must paste a
    // key for it to work at all.  Use the warn colour so the
    // status reads as "action needed", not just "info".
    badge = <span className="badge badge-warn">BYOK required</span>;
  }

  const accent = has_byok || has_or_minted;
  const primaryLabel = has_byok
    ? 'rotate key'
    : has_or_minted
      ? 'use my own key'
      : (supports_byo ? 'configure endpoint' : 'add your key');

  // Header is a button so keyboard users can toggle with Space/Enter.
  return (
    <article className={`byok-row ${open ? 'open' : ''} ${accent ? 'has-byok' : ''}`}>
      <button
        type="button"
        className="byok-row-head"
        onClick={onToggle}
        aria-expanded={open}
      >
        <span className="byok-row-chev" aria-hidden="true">{open ? '▾' : '▸'}</span>
        <span className="byok-row-id">
          <span className="byok-row-name">{meta.label}</span>
          <span className="byok-row-blurb">{meta.blurb}</span>
        </span>
        <span className="byok-row-badge">{badge}</span>
      </button>
      {open ? (
        <div className="byok-row-body">
          <p className="byok-row-explain muted small">
            {explainStatus(provider)}
          </p>
          <div className="byok-row-actions">
            <button
              className="btn btn-primary btn-sm"
              onClick={onEdit}
              disabled={busy}
            >
              {primaryLabel}
            </button>
            {has_byok ? (
              <button
                className="btn btn-ghost btn-sm btn-danger"
                onClick={onDelete}
                disabled={busy}
              >
                remove
              </button>
            ) : null}
          </div>
        </div>
      ) : null}
    </article>
  );
}

/// Single sentence of context shown when a card is open — turns the
/// status badge into a real explanation.
function explainStatus(p) {
  if (p.has_byok) {
    return p.name === 'byo'
      ? 'Your custom endpoint is active. Every /llm/byo/… call uses your URL and key.'
      : 'Your key is active. Every call to this provider uses it.';
  }
  if (p.has_or_minted) {
    // OR-specific: a key was minted for the user via the operator's
    // Provisioning account.  Calls work; billing flows through the
    // operator (capped per-user).  Adding a BYOK overrides this.
    return 'Swarm minted an OpenRouter key for you (billed through the operator, capped per-user). Calls work as-is. Add your own key to override and bill yourself directly.';
  }
  if (p.name === 'openrouter') {
    // No BYOK, no minted key.  First /llm/openrouter call will mint
    // a key when the operator has the Provisioning client wired up.
    return 'No key on file yet. Your first OpenRouter call will mint one automatically when the operator has the Provisioning API enabled. Add your own key to skip the mint and bill yourself.';
  }
  if (p.name === 'byo') {
    return 'Set an upstream URL + key to point swarm at any OpenAI-compatible endpoint.';
  }
  // Every other provider is BYOK-or-503: no platform fallback.
  return 'BYOK only — the operator does not backstop spend on this provider. Calls 503 until you paste a key. Your spend, your account.';
}

function ByokEditor({ provider, onClose, onSaved }) {
  const { client } = useApi();
  const name = provider?.name || '';
  const meta = PROVIDER_META[name] || { label: name, blurb: '' };
  const isByo = name === 'byo';
  const [key, setKey] = React.useState('');
  const [upstream, setUpstream] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);

  // Esc closes the modal — match the platform's modal UX.
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const onSubmit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const body = isByo
        ? { key: key.trim(), upstream: upstream.trim() }
        : { key: key.trim() };
      await client.putByok(name, body);
      await onSaved();
    } catch (e2) {
      if (e2?.status === 422) {
        setErr('Provider rejected the key — double-check the value.');
      } else if (e2?.status === 502) {
        setErr("Couldn't reach the provider to validate. Try again.");
      } else if (e2?.status === 400) {
        setErr(e2?.detail || 'Invalid input.');
      } else {
        setErr(e2?.detail || e2?.message || 'save failed');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <header className="modal-header">
          {provider?.has_byok ? 'rotate' : 'add'} {meta.label.toLowerCase()} key
        </header>
        <div className="modal-body">
          <form className="form" onSubmit={onSubmit}>
            {isByo ? (
              <label className="field">
                <span>upstream URL</span>
                <input
                  type="url"
                  required
                  autoFocus
                  placeholder="https://my-llm.example/v1"
                  value={upstream}
                  onChange={e => setUpstream(e.target.value)}
                  disabled={busy}
                />
                <span className="byok-help muted small">
                  Any OpenAI-compatible base URL. Swarm will probe
                  <code className="byok-inline-code">/v1/models</code>
                  with the key below before saving.
                </span>
              </label>
            ) : null}
            <label className="field">
              <span>API key</span>
              <textarea
                className="byok-key-input"
                required
                rows={3}
                autoFocus={!isByo}
                spellCheck={false}
                placeholder={`paste your ${meta.label} key`}
                value={key}
                onChange={e => setKey(e.target.value)}
                disabled={busy}
              />
              <span className="byok-help muted small">
                Encrypted with your account key. Visible to swarm
                only when forwarding upstream calls.
              </span>
            </label>
            {err ? <div className="error">{err}</div> : null}
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-ghost"
                onClick={onClose}
                disabled={busy}
              >
                cancel
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={busy || !key.trim() || (isByo && !upstream.trim())}
              >
                {busy ? 'validating…' : 'validate & save'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
