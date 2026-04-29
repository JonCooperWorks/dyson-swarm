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
/// strings.  Order in `PROVIDER_ORDER` controls how cards render.
const PROVIDER_META = {
  anthropic:  { label: 'Anthropic',     blurb: 'Claude — claude.ai/api'           },
  openai:     { label: 'OpenAI',        blurb: 'GPT-4o, o1 — api.openai.com'      },
  openrouter: { label: 'OpenRouter',    blurb: 'Aggregator — openrouter.ai'       },
  gemini:     { label: 'Gemini',        blurb: 'Google — generativelanguage api'  },
  groq:       { label: 'Groq',          blurb: 'Fast inference — api.groq.com'    },
  deepseek:   { label: 'DeepSeek',      blurb: 'DeepSeek — api.deepseek.com'      },
  xai:        { label: 'xAI',           blurb: 'Grok — api.x.ai'                  },
  ollama:     { label: 'Ollama',        blurb: 'Local — no key required'          },
  byo:        { label: 'Custom (BYO)',  blurb: 'Any OpenAI-compatible endpoint'   },
};

const PROVIDER_ORDER = [
  'anthropic', 'openai', 'openrouter', 'gemini',
  'groq', 'deepseek', 'xai', 'ollama', 'byo',
];

function sortProviders(rows) {
  const idx = (n) => {
    const i = PROVIDER_ORDER.indexOf(n);
    return i === -1 ? PROVIDER_ORDER.length : i;
  };
  return [...rows].sort((a, b) => idx(a.name) - idx(b.name));
}

/// Treats a provider as "configured" when the user has either
/// pasted a BYOK key or the operator has wired a platform key.
/// `ollama` is local + auth-less so we count it as configured too.
function isConfigured(p) {
  return p.has_byok || p.has_platform || p.name === 'ollama';
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
          call you make through the proxy. Without a personal key,
          calls fall back to the operator's platform key — when one
          is configured.
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
  const { name, has_byok, has_platform, supports_byo } = provider;
  const meta = PROVIDER_META[name] || { label: name, blurb: '' };
  const isOllama = name === 'ollama';

  let badge;
  if (has_byok) {
    badge = <span className="badge badge-ok">your key</span>;
  } else if (has_platform) {
    badge = <span className="badge badge-info">platform key</span>;
  } else if (supports_byo) {
    badge = <span className="badge badge-faint">no endpoint</span>;
  } else if (isOllama) {
    badge = <span className="badge badge-faint">local · no auth</span>;
  } else {
    badge = <span className="badge badge-faint">not configured</span>;
  }

  // Header is a button so keyboard users can toggle with Space/Enter.
  return (
    <article className={`byok-row ${open ? 'open' : ''} ${has_byok ? 'has-byok' : ''}`}>
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
            {isOllama ? (
              <span className="muted small">
                Ollama runs locally and needs no API key. Calls flow
                through <code>/llm/ollama/…</code>.
              </span>
            ) : (
              <>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={onEdit}
                  disabled={busy}
                >
                  {has_byok ? 'rotate key' : (supports_byo ? 'configure endpoint' : 'add your key')}
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
              </>
            )}
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
      : 'Your key is active. Calls to this provider use it; the platform key (if any) is bypassed.';
  }
  if (p.has_platform) {
    return 'Calls fall through to the operator\'s platform key. Add your own to take over billing for this provider.';
  }
  if (p.name === 'byo') {
    return 'Set an upstream URL + key to point swarm at any OpenAI-compatible endpoint.';
  }
  if (p.name === 'ollama') {
    return 'Ollama is auth-less and pointed at a local daemon by the operator.';
  }
  return 'Not available on this deployment until you add a key — there\'s no platform fallback.';
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
