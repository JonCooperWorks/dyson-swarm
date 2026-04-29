/* swarm — Provider Keys (BYOK) view.
 *
 * Lets the signed-in user manage their per-provider API keys.  The
 * server validates a key against the provider before persisting, so
 * a 422 here means the upstream rejected the value — usually a typo
 * or a revoked key.  Plaintext is never returned: the table only
 * shows whether a key is set, never the value itself.
 *
 * `byo` is special: the user supplies BOTH an upstream URL and a
 * key, letting them point swarm at any OpenAI-compatible endpoint.
 * For everything else the upstream is fixed by the operator's TOML.
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';

export function ByokView() {
  const { client } = useApi();
  const [providers, setProviders] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [editing, setEditing] = React.useState(null); // {name} or null

  const refresh = React.useCallback(async () => {
    setErr(null);
    try {
      const list = await client.listProviders();
      setProviders(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.message || 'list providers failed');
    }
  }, [client]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const onDelete = async (name) => {
    if (!confirm(`Remove your ${name} key?`)) return;
    try {
      await client.deleteByok(name);
      await refresh();
    } catch (e) {
      setErr(e?.message || 'delete failed');
    }
  };

  return (
    <main className="admin-pane">
      <header className="admin-header">
        <h2>provider keys</h2>
        <p className="muted small">
          BYOK — bring your own key.  Pasted keys are validated against the
          provider, encrypted under your account key, and used for every
          call you make through the proxy.  When you have no key set, the
          proxy falls back to the platform key (if your operator has one
          configured).
        </p>
      </header>
      {err ? <div className="error">{err}</div> : null}
      {providers === null ? (
        <p className="muted small">loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>provider</th>
              <th>status</th>
              <th>actions</th>
            </tr>
          </thead>
          <tbody>
            {providers.map(p => (
              <ProviderRow
                key={p.name}
                provider={p}
                onEdit={() => setEditing({ name: p.name })}
                onDelete={() => onDelete(p.name)}
              />
            ))}
          </tbody>
        </table>
      )}
      {editing ? (
        <ByokEditor
          providerName={editing.name}
          onClose={() => setEditing(null)}
          onSaved={async () => { setEditing(null); await refresh(); }}
        />
      ) : null}
    </main>
  );
}

function ProviderRow({ provider, onEdit, onDelete }) {
  const { name, has_byok, has_platform, supports_byo } = provider;
  let badge;
  if (has_byok) {
    badge = <span className="status-pill status-pill-ok">BYOK set</span>;
  } else if (supports_byo) {
    badge = <span className="status-pill status-pill-muted">no endpoint configured</span>;
  } else if (has_platform) {
    badge = <span className="status-pill status-pill-info">using platform key</span>;
  } else {
    badge = <span className="status-pill status-pill-muted">not configured</span>;
  }
  return (
    <tr>
      <td><code>{name}</code></td>
      <td>{badge}</td>
      <td>
        <button className="btn btn-sm" onClick={onEdit}>
          {has_byok ? 'update' : (supports_byo ? 'configure' : 'add key')}
        </button>
        {has_byok ? (
          <button className="btn btn-sm btn-danger" onClick={onDelete}>delete</button>
        ) : null}
      </td>
    </tr>
  );
}

function ByokEditor({ providerName, onClose, onSaved }) {
  const { client } = useApi();
  const isByo = providerName === 'byo';
  const [key, setKey] = React.useState('');
  const [upstream, setUpstream] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);

  const onSubmit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const body = isByo ? { key, upstream } : { key };
      await client.putByok(providerName, body);
      await onSaved();
    } catch (e) {
      if (e?.status === 422) {
        setErr('Provider rejected the key — double-check the value.');
      } else if (e?.status === 502) {
        setErr('Could not reach the provider to validate the key. Try again.');
      } else {
        setErr(e?.message || 'save failed');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <form className="modal" onClick={e => e.stopPropagation()} onSubmit={onSubmit}>
        <h3>{isByo ? 'configure custom endpoint' : `${providerName} key`}</h3>
        {isByo ? (
          <label>
            <span>upstream URL</span>
            <input
              type="url"
              required
              placeholder="https://my-llm.example/v1"
              value={upstream}
              onChange={e => setUpstream(e.target.value)}
            />
          </label>
        ) : null}
        <label>
          <span>API key</span>
          <textarea
            required
            rows={3}
            placeholder="paste your key"
            value={key}
            onChange={e => setKey(e.target.value)}
          />
        </label>
        {err ? <div className="error">{err}</div> : null}
        <div className="modal-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose} disabled={busy}>
            cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy || !key.trim()}>
            {busy ? 'validating…' : 'validate & save'}
          </button>
        </div>
      </form>
    </div>
  );
}
