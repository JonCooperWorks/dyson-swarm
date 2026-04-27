/* warden — Admin view (users + proxy-token revocation).
 *
 * Admin routes (/v1/admin/*) sit behind the same OIDC chain as
 * everything else, with an extra middleware that requires the
 * caller's JWT to carry the configured admin permission/role.  The
 * SPA's normal access token is therefore sufficient — no separate
 * credential, no token prompt.  Users without the admin permission
 * see a "not authorized" splash instead of the panels (driven by a
 * probe of /v1/admin/users; backend is the source of truth).
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';

export function AdminView() {
  const { client } = useApi();
  const [authz, setAuthz] = React.useState({ state: 'probing' }); // probing | ok | denied | error

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await client.adminListUsers();
        if (!cancelled) setAuthz({ state: 'ok' });
      } catch (e) {
        if (cancelled) return;
        if (e?.status === 401) setAuthz({ state: 'denied', reason: 'unauthenticated' });
        else if (e?.status === 403) setAuthz({ state: 'denied', reason: 'forbidden' });
        else setAuthz({ state: 'error', message: e?.message || 'admin probe failed' });
      }
    })();
    return () => { cancelled = true; };
  }, [client]);

  if (authz.state === 'probing') {
    return <main className="admin-pane"><p className="muted small">checking access…</p></main>;
  }
  if (authz.state === 'denied') {
    return <NotAuthorized reason={authz.reason}/>;
  }
  if (authz.state === 'error') {
    return (
      <main className="admin-pane">
        <div className="error">{authz.message}</div>
      </main>
    );
  }

  return (
    <main className="admin-pane">
      <header className="admin-header">
        <h2>admin</h2>
      </header>
      <UsersPanel client={client}/>
      <ProxyTokensPanel client={client}/>
    </main>
  );
}

function NotAuthorized({ reason }) {
  return (
    <main className="splash">
      <h1>admin</h1>
      <p className="muted">
        {reason === 'forbidden'
          ? 'Your account is signed in but does not have the admin permission. Ask your operator to assign it in the IdP.'
          : 'Sign in is required to view admin tools.'}
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
      setErr(e?.message || 'list users failed');
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

  const setOrLimit = async (id, currentLimit) => {
    const next = prompt(
      `OpenRouter USD spend cap for this user (current: $${currentLimit}):`,
      String(currentLimit ?? 10),
    );
    if (next == null) return;
    const parsed = Number(next);
    if (!Number.isFinite(parsed) || parsed < 0) {
      setErr(`invalid limit "${next}" — must be a non-negative number`);
      return;
    }
    setBusy(true); setErr(null);
    try {
      await client.adminSetOpenRouterLimit(id, parsed);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'set limit failed');
    } finally {
      setBusy(false);
    }
  };

  const forceMintOr = async (id) => {
    if (!confirm(
      'Force-mint a new OpenRouter key for this user? The current key (if any) is revoked upstream and the plaintext is shown only once.',
    )) return;
    setBusy(true); setErr(null);
    try {
      const r = await client.adminForceMintOpenRouterKey(id);
      const tok = r?.token || null;
      if (tok) {
        setMintedFor(`${id} · openrouter`);
        setMintedToken(tok);
      }
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'or mint failed');
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
            <th>id</th><th>subject</th><th>email</th><th>status</th>
            <th>OR key</th><th>OR limit</th>
            <th>created</th><th></th>
          </tr></thead>
          <tbody>
            {rows.map(u => (
              <tr key={u.id}>
                <td><code className="mono-sm">{u.id}</code></td>
                <td><code className="mono-sm">{u.subject}</code></td>
                <td className="muted small">{u.email || '—'}</td>
                <td><UserStatusBadge status={u.status}/></td>
                <td>
                  {u.openrouter_key_present ? (
                    <span className="badge badge-ok">present</span>
                  ) : (
                    <span className="badge badge-faint">none</span>
                  )}
                </td>
                <td className="muted small">${(u.openrouter_key_limit_usd ?? 0).toFixed(2)}</td>
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
                    mint api key
                  </button>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => setOrLimit(u.id, u.openrouter_key_limit_usd)}
                    disabled={busy}
                    title="set the user's OpenRouter USD spend cap"
                  >
                    OR limit
                  </button>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => forceMintOr(u.id)}
                    disabled={busy}
                    title="rotate (or first-time mint) the user's OpenRouter key"
                  >
                    {u.openrouter_key_present ? 'rotate OR' : 'mint OR'}
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
