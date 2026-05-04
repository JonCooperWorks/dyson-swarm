/* swarm — Admin view (users + proxy-token revocation).
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
      <DockerCatalogPanel client={client}/>
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

// ─── Docker MCP catalog panel ───────────────────────────────────

function DockerCatalogPanel({ client }) {
  const [rows, setRows] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [editing, setEditing] = React.useState(null);

  const refresh = React.useCallback(async () => {
    setErr(null);
    try {
      const body = await client.adminListMcpDockerCatalog();
      setRows(Array.isArray(body?.servers) ? body.servers : []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'list Docker MCP presets failed');
    }
  }, [client]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const save = async (preset) => {
    setBusy(true); setErr(null);
    try {
      await client.adminPutMcpDockerCatalogServer(preset.id, {
        label: preset.label,
        description: preset.description,
        template: preset.template,
        credentials: preset.credentials,
      });
      setEditing(null);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'save Docker MCP preset failed');
    } finally {
      setBusy(false);
    }
  };

  const remove = async (row) => {
    if (!confirm(`delete Docker MCP preset ${row.id}?`)) return;
    setBusy(true); setErr(null);
    try {
      await client.adminDeleteMcpDockerCatalogServer(row.id);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete Docker MCP preset failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">docker mcp presets</div>
        <div className="panel-actions">
          <button
            className="btn btn-sm"
            onClick={() => setEditing({ mode: 'new', row: emptyDockerCatalogPreset() })}
            disabled={busy}
          >
            add preset
          </button>
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={busy}>
            refresh
          </button>
        </div>
      </div>
      {err ? <div className="error">{err}</div> : null}
      {rows === null ? (
        <p className="muted small">loading...</p>
      ) : rows.length === 0 ? (
        <p className="muted small">no Docker MCP presets.</p>
      ) : (
        <table className="rows">
          <thead><tr>
            <th>id</th><th>label</th><th>source</th><th>placeholders</th><th>updated</th><th></th>
          </tr></thead>
          <tbody>
            {rows.map(row => (
              <tr key={row.id}>
                <td data-label="id"><code className="mono-sm">{row.id}</code></td>
                <td data-label="label">
                  <div>{row.label || row.id}</div>
                  {row.description ? <div className="muted small">{row.description}</div> : null}
                </td>
                <td data-label="source">
                  <span className={`badge badge-${row.source === 'config' ? 'info' : 'ok'}`}>
                    {row.source || 'admin'}
                  </span>
                </td>
                <td data-label="placeholders" className="muted small">
                  {(row.credentials || []).length}
                </td>
                <td data-label="updated" className="muted small">{fmtTime(row.updated_at)}</td>
                <td className="row-actions">
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => setEditing({ mode: 'edit', row })}
                    disabled={busy}
                  >
                    edit
                  </button>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => remove(row)}
                    disabled={busy}
                  >
                    delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {editing ? (
        <DockerCatalogModal
          mode={editing.mode}
          initial={editing.row}
          busy={busy}
          onCancel={() => setEditing(null)}
          onSave={save}
        />
      ) : null}
    </section>
  );
}

function emptyDockerCatalogPreset() {
  return {
    id: '',
    label: '',
    description: '',
    template: JSON.stringify({
      servers: {
        example: {
          type: 'stdio',
          command: 'docker',
          args: ['run', '--rm', '-i', 'ghcr.io/example/mcp:latest'],
        },
      },
    }, null, 2),
    credentials: [],
  };
}

function normalizeCredential(field = {}) {
  return {
    id: field.id || '',
    label: field.label || '',
    description: field.description || '',
    required: field.required !== false,
    secret: field.secret !== false,
    placeholder: field.placeholder || '',
  };
}

function DockerCatalogModal({ mode, initial, busy, onCancel, onSave }) {
  const isEdit = mode === 'edit';
  const [id, setId] = React.useState(initial?.id || '');
  const [label, setLabel] = React.useState(initial?.label || '');
  const [description, setDescription] = React.useState(initial?.description || '');
  const [template, setTemplate] = React.useState(initial?.template || '');
  const [credentials, setCredentials] = React.useState(
    () => (initial?.credentials || []).map(normalizeCredential),
  );
  const [err, setErr] = React.useState(null);

  const updateCredential = (index, patch) => {
    setCredentials(curr => curr.map((field, i) => (i === index ? { ...field, ...patch } : field)));
  };
  const removeCredential = (index) => {
    setCredentials(curr => curr.filter((_, i) => i !== index));
  };
  const addCredential = () => {
    setCredentials(curr => [
      ...curr,
      {
        id: '',
        label: '',
        description: '',
        required: true,
        secret: true,
        placeholder: '',
      },
    ]);
  };

  const submit = (e) => {
    e.preventDefault();
    setErr(null);
    const preset = {
      id: id.trim(),
      label: label.trim(),
      description: description.trim() || null,
      template,
      credentials: credentials.map(field => ({
        id: field.id.trim(),
        label: field.label.trim() || field.id.trim(),
        description: field.description.trim() || null,
        required: Boolean(field.required),
        secret: Boolean(field.secret),
        placeholder: field.placeholder.trim() || null,
      })),
    };
    const validation = validateCatalogPreset(preset);
    if (validation) {
      setErr(validation);
      return;
    }
    onSave(preset);
  };

  return (
    <div className="modal-scrim" onClick={onCancel}>
      <div className="modal admin-catalog-modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span>{isEdit ? `edit ${initial.id}` : 'add Docker MCP preset'}</span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={onCancel}
            disabled={busy}
            aria-label="close"
          >
            x
          </button>
        </div>
        <form className="form modal-body" onSubmit={submit}>
          {err ? <div className="error">{err}</div> : null}
          <label className="field">
            <span>id</span>
            <input
              value={id}
              onChange={e => setId(e.target.value)}
              placeholder="github"
              disabled={busy || isEdit}
              autoComplete="off"
              autoFocus={!isEdit}
            />
          </label>
          <label className="field">
            <span>label</span>
            <input
              value={label}
              onChange={e => setLabel(e.target.value)}
              placeholder="GitHub"
              disabled={busy}
              autoComplete="off"
            />
          </label>
          <label className="field">
            <span>description</span>
            <input
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Docker-backed GitHub MCP server"
              disabled={busy}
              autoComplete="off"
            />
          </label>
          <label className="field">
            <span>JSON template</span>
            <textarea
              className="mcp-json-textarea admin-catalog-template"
              value={template}
              onChange={e => setTemplate(e.target.value)}
              spellCheck={false}
              disabled={busy}
              aria-label="Docker MCP JSON template"
            />
          </label>
          <div className="admin-catalog-placeholders">
            <div className="panel-header">
              <div className="panel-title">placeholders</div>
              <div className="panel-actions">
                <button type="button" className="btn btn-ghost btn-sm" onClick={addCredential} disabled={busy}>
                  add placeholder
                </button>
              </div>
            </div>
            {credentials.length === 0 ? (
              <p className="muted small">no placeholders.</p>
            ) : (
              <div className="admin-catalog-credential-list">
                {credentials.map((field, index) => (
                  <div className="admin-catalog-credential-row" key={index}>
                    <label className="field">
                      <span>id</span>
                      <input
                        value={field.id}
                        onChange={e => updateCredential(index, { id: e.target.value })}
                        placeholder="github_token"
                        disabled={busy}
                        autoComplete="off"
                        aria-label={`placeholder ${index + 1} id`}
                      />
                    </label>
                    <label className="field">
                      <span>label</span>
                      <input
                        value={field.label}
                        onChange={e => updateCredential(index, { label: e.target.value })}
                        placeholder="GitHub token"
                        disabled={busy}
                        autoComplete="off"
                        aria-label={`placeholder ${index + 1} label`}
                      />
                    </label>
                    <label className="field">
                      <span>description</span>
                      <input
                        value={field.description}
                        onChange={e => updateCredential(index, { description: e.target.value })}
                        placeholder="Personal access token"
                        disabled={busy}
                        autoComplete="off"
                        aria-label={`placeholder ${index + 1} description`}
                      />
                    </label>
                    <label className="field">
                      <span>placeholder</span>
                      <input
                        value={field.placeholder}
                        onChange={e => updateCredential(index, { placeholder: e.target.value })}
                        placeholder="ghp_..."
                        disabled={busy}
                        autoComplete="off"
                        aria-label={`placeholder ${index + 1} input placeholder`}
                      />
                    </label>
                    <div className="admin-catalog-flags">
                      <label className="field check">
                        <input
                          type="checkbox"
                          checked={field.required}
                          onChange={e => updateCredential(index, { required: e.target.checked })}
                          disabled={busy}
                        />
                        <span>required</span>
                      </label>
                      <label className="field check">
                        <input
                          type="checkbox"
                          checked={field.secret}
                          onChange={e => updateCredential(index, { secret: e.target.checked })}
                          disabled={busy}
                        />
                        <span>secret</span>
                      </label>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => removeCredential(index)}
                        disabled={busy}
                      >
                        remove
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="modal-actions">
            <button type="button" className="btn btn-ghost" onClick={onCancel} disabled={busy}>
              cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'saving...' : 'save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function validateCatalogPreset(preset) {
  if (!/^[A-Za-z0-9_-]+$/.test(preset.id)) return 'id must match [A-Za-z0-9_-]+';
  if (!preset.label) return 'label is required';
  if (!preset.template.trim()) return 'JSON template is required';
  try {
    JSON.parse(preset.template);
  } catch (e) {
    return e?.message || 'JSON template is not valid JSON';
  }
  const seen = new Set();
  for (const field of preset.credentials) {
    if (!/^[A-Za-z0-9_-]+$/.test(field.id)) return 'placeholder ids must match [A-Za-z0-9_-]+';
    if (seen.has(field.id)) return `placeholder ${field.id} is duplicated`;
    seen.add(field.id);
    if (!field.label) return `placeholder ${field.id} needs a label`;
  }
  return null;
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
                <td data-label="id"><code className="mono-sm">{u.id}</code></td>
                <td data-label="subject"><code className="mono-sm">{u.subject}</code></td>
                <td data-label="email" className="muted small">{u.email || '—'}</td>
                <td data-label="status"><UserStatusBadge status={u.status}/></td>
                <td data-label="OR key">
                  {u.openrouter_key_present ? (
                    <span className="badge badge-ok">present</span>
                  ) : (
                    <span className="badge badge-faint">none</span>
                  )}
                </td>
                <td data-label="OR limit" className="muted small">${(u.openrouter_key_limit_usd ?? 0).toFixed(2)}</td>
                <td data-label="created" className="muted small">{fmtTime(u.created_at)}</td>
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
