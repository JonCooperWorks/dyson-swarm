/* warden — Admin view (users + proxy-token revocation).
 *
 * Admin routes (/v1/admin/*) sit behind the admin-bearer middleware,
 * not the user-OIDC chain.  The SPA's normal token won't reach them,
 * so the Admin view prompts for the operator's admin token, stashes
 * it in sessionStorage (per-tab; clears on close), and builds a
 * dedicated WardenClient instance bound to it.
 *
 * Why not auto-elevate from OIDC: warden's threat model treats the
 * admin token as an out-of-band ops credential, separate from any
 * user identity.  Mixing the two would mean every OIDC user with the
 * UI loaded becomes an "admin candidate", which is exactly the
 * privilege coupling we want to avoid.
 *
 * The token is stored unobfuscated in sessionStorage — same XSS
 * exposure as the OIDC token, accepted under the same trust model.
 */

import React from 'react';
import { WardenClient } from '../api/client.js';

const TOKEN_KEY = 'warden:admin-token';

function readAdminToken() {
  try { return sessionStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
}
function writeAdminToken(t) {
  if (!t) sessionStorage.removeItem(TOKEN_KEY);
  else sessionStorage.setItem(TOKEN_KEY, t);
}

export function AdminView() {
  const [token, setToken] = React.useState(readAdminToken());

  if (!token) return <AdminTokenPrompt onSubmit={(t) => { writeAdminToken(t); setToken(t); }}/>;

  // Admin client — same class, different bearer source.  Built once
  // per token change so a "forget" + re-enter cycle gets a fresh
  // closure rather than a stale getToken pointing at the old value.
  const client = React.useMemo(() => new WardenClient({ getToken: () => token }), [token]);
  const forget = () => { writeAdminToken(''); setToken(''); };

  return (
    <main className="admin-pane">
      <header className="admin-header">
        <h2>admin</h2>
        <div className="admin-actions">
          <button className="btn btn-ghost" onClick={forget}>forget admin token</button>
        </div>
      </header>
      <UsersPanel client={client}/>
      <ProxyTokensPanel client={client}/>
    </main>
  );
}

function AdminTokenPrompt({ onSubmit }) {
  const [v, setV] = React.useState('');
  const submit = (e) => {
    e.preventDefault();
    if (!v.trim()) return;
    onSubmit(v.trim());
  };
  return (
    <main className="splash">
      <h1>admin</h1>
      <p className="muted">
        Admin routes are gated by an out-of-band token.  Paste the value of
        <code>admin_token</code> from the warden config to continue.
      </p>
      <form onSubmit={submit} className="form" style={{ width: 'min(420px, 90vw)' }}>
        <label className="field">
          <span>admin token</span>
          <input
            type="password"
            value={v}
            onChange={e => setV(e.target.value)}
            autoFocus
            required
          />
        </label>
        <div className="modal-actions">
          <button type="submit" className="btn btn-primary">use this token</button>
        </div>
      </form>
      <p className="muted small">
        Stored in sessionStorage; cleared on tab close or via "forget admin
        token" once you're in.
      </p>
    </main>
  );
}

// ─── Users panel ─────────────────────────────────────────────────

function UsersPanel({ client }) {
  const [rows, setRows] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [mintedFor, setMintedFor] = React.useState(null);
  const [mintedToken, setMintedToken] = React.useState(null);

  const refresh = React.useCallback(async () => {
    setErr(null);
    try {
      const list = await client.adminListUsers();
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.status === 401 ? 'admin token rejected' : (e?.message || 'list users failed'));
    }
  }, [client]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const setStatus = async (id, mode) => {
    setBusy(true); setErr(null);
    try {
      const fn = mode === 'activate' ? client.adminActivateUser : client.adminSuspendUser;
      await fn.call(client, id);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || `${mode} failed`);
    } finally {
      setBusy(false);
    }
  };

  const mint = async (id) => {
    const label = prompt('label for this api key (optional):') || null;
    setBusy(true); setErr(null);
    try {
      const r = await client.adminMintApiKey(id, label);
      // Backend returns { token, label, created_at } or similar.
      // Surface it once — it's not retrievable later.
      const tok = (r && (r.token || r.api_key)) || null;
      if (tok) {
        setMintedFor(id);
        setMintedToken(tok);
      }
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'mint failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">users</div>
        <div className="panel-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh}>refresh</button>
        </div>
      </div>
      {err ? <div className="error">{err}</div> : null}
      {rows === null ? (
        <p className="muted small">loading…</p>
      ) : rows.length === 0 ? (
        <p className="muted small">no users.</p>
      ) : (
        <table className="rows">
          <thead><tr>
            <th>id</th><th>subject</th><th>email</th><th>status</th><th>created</th><th></th>
          </tr></thead>
          <tbody>
            {rows.map(u => (
              <tr key={u.id}>
                <td><code className="mono-sm">{u.id}</code></td>
                <td><code className="mono-sm">{u.subject}</code></td>
                <td className="muted small">{u.email || '—'}</td>
                <td><UserStatusBadge status={u.status}/></td>
                <td className="muted small">{fmtTime(u.created_at)}</td>
                <td className="row-actions">
                  {u.status !== 'active' ? (
                    <button className="btn btn-ghost btn-sm" onClick={() => setStatus(u.id, 'activate')} disabled={busy}>
                      activate
                    </button>
                  ) : (
                    <button className="btn btn-ghost btn-sm" onClick={() => setStatus(u.id, 'suspend')} disabled={busy}>
                      suspend
                    </button>
                  )}
                  <button className="btn btn-ghost btn-sm" onClick={() => mint(u.id)} disabled={busy}>
                    mint key
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {mintedToken ? (
        <MintedKeyBanner
          forUser={mintedFor}
          token={mintedToken}
          onDismiss={() => { setMintedFor(null); setMintedToken(null); }}
        />
      ) : null}
    </section>
  );
}

function UserStatusBadge({ status }) {
  const cls = status === 'active' ? 'ok'
            : status === 'suspended' ? 'warn'
            : 'faint'; // inactive
  return <span className={`badge badge-${cls}`}>{status}</span>;
}

function MintedKeyBanner({ forUser, token, onDismiss }) {
  const [copied, setCopied] = React.useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* ignore */ }
  };
  return (
    <div className="banner banner-info">
      <div>
        api key for <code className="mono-sm">{forUser}</code> minted —
        save it now, it won't be shown again:
      </div>
      <code className="mono-sm" style={{ display: 'block', marginTop: 4, wordBreak: 'break-all' }}>
        {token}
      </code>
      <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
        <button className="btn btn-sm" onClick={copy}>{copied ? 'copied' : 'copy'}</button>
        <button className="btn btn-ghost btn-sm" onClick={onDismiss}>dismiss</button>
      </div>
    </div>
  );
}

// ─── Proxy tokens panel (revoke-by-paste) ──────────────────────

function ProxyTokensPanel({ client }) {
  const [token, setToken] = React.useState('');
  const [submitting, setSubmitting] = React.useState(false);
  const [outcome, setOutcome] = React.useState(null);

  const submit = async (e) => {
    e.preventDefault();
    if (!token.trim()) return;
    setSubmitting(true); setOutcome(null);
    try {
      await client.adminRevokeProxyToken(token.trim());
      setOutcome({ ok: true, msg: `revoked.` });
      setToken('');
    } catch (err) {
      const msg = err?.status === 404 ? 'no such token' : (err?.detail || err?.message || 'revoke failed');
      setOutcome({ ok: false, msg });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">proxy tokens</div>
      </div>
      <p className="muted small">
        Emergency revoke for a leaked per-instance LLM proxy token.
        Subsequent <code>/llm/*</code> calls bearing this token return 401.
      </p>
      <form onSubmit={submit} className="form">
        <label className="field">
          <span>proxy token</span>
          <input
            type="password"
            value={token}
            onChange={e => setToken(e.target.value)}
            placeholder="paste the leaked token"
          />
        </label>
        <div className="modal-actions">
          <button type="submit" className="btn btn-danger" disabled={submitting || !token.trim()}>
            {submitting ? 'revoking…' : 'revoke'}
          </button>
        </div>
      </form>
      {outcome ? (
        <div className={outcome.ok ? 'banner banner-info' : 'error'}>{outcome.msg}</div>
      ) : null}
    </section>
  );
}

function fmtTime(secs) {
  if (!secs) return '—';
  try { return new Date(secs * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z'); }
  catch { return String(secs); }
}
