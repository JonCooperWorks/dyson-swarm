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

const DOCKER_CATALOG_TEMPLATE_PLACEHOLDER = JSON.stringify({
  servers: {
    example: {
      type: 'stdio',
      command: 'docker',
      args: ['run', '--rm', '-i', 'ghcr.io/example/mcp:latest'],
    },
  },
}, null, 2);

const CREDENTIAL_TOKEN_RE = /{{\s*credentials?\.([A-Za-z0-9_-]+)\s*}}/g;
const SAFE_PLACEHOLDER_NAME_RE = /^[A-Za-z0-9_-]+$/;

export function AdminView({ view = { name: 'admin' } }) {
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

  if (view.name === 'admin-mcp-catalog-new') {
    return <DockerCatalogEditorPage client={client} mode="new"/>;
  }
  if (view.name === 'admin-mcp-catalog-edit') {
    return <DockerCatalogEditorPage client={client} mode="edit" catalogId={view.catalogId}/>;
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
          <a className={`btn btn-sm ${busy ? 'disabled' : ''}`} href="#/admin/mcp-catalog/new">
            add preset
          </a>
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
                  <a
                    className={`btn btn-ghost btn-sm ${busy ? 'disabled' : ''}`}
                    href={`#/admin/mcp-catalog/${encodeURIComponent(row.id)}`}
                  >
                    edit
                  </a>
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
    </section>
  );
}

function emptyDockerCatalogPreset() {
  return {
    id: '',
    label: '',
    description: '',
    template: '',
    credentials: [],
  };
}

function DockerCatalogEditorPage({ client, mode, catalogId }) {
  const isEdit = mode === 'edit';
  const [initial, setInitial] = React.useState(isEdit ? null : emptyDockerCatalogPreset());
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);

  React.useEffect(() => {
    let cancelled = false;
    if (!isEdit) {
      setInitial(emptyDockerCatalogPreset());
      return () => { cancelled = true; };
    }
    (async () => {
      setErr(null);
      try {
        const body = await client.adminListMcpDockerCatalog();
        const row = (body?.servers || []).find(server => server.id === catalogId);
        if (!cancelled) {
          setInitial(row || null);
          if (!row) setErr(`No Docker MCP preset named ${catalogId}.`);
        }
      } catch (e) {
        if (!cancelled) setErr(e?.detail || e?.message || 'load Docker MCP preset failed');
      }
    })();
    return () => { cancelled = true; };
  }, [client, catalogId, isEdit]);

  const save = async (preset) => {
    setBusy(true); setErr(null);
    try {
      await client.adminPutMcpDockerCatalogServer(preset.id, {
        label: preset.label,
        description: preset.description,
        template: preset.template,
        credentials: preset.credentials,
      });
      window.location.hash = '#/admin';
    } catch (e) {
      setErr(e?.detail || e?.message || 'save Docker MCP preset failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="admin-pane admin-catalog-page">
      <header className="admin-header">
        <div>
          <h2>{isEdit ? `edit ${catalogId}` : 'add Docker MCP preset'}</h2>
          <p className="muted small admin-catalog-page-subtitle">
            Configure the read-only MCP JSON template and the credential placeholders users may fill.
          </p>
        </div>
        <a className="btn btn-ghost btn-sm" href="#/admin">back</a>
      </header>
      {err ? <div className="error">{err}</div> : null}
      {!initial && isEdit && !err ? (
        <p className="muted small">loading...</p>
      ) : initial ? (
        <DockerCatalogForm
          mode={mode}
          initial={initial}
          busy={busy}
          onCancel={() => { window.location.hash = '#/admin'; }}
          onSave={save}
        />
      ) : null}
    </main>
  );
}

function DockerCatalogForm({ mode, initial, busy, onCancel, onSave }) {
  const isEdit = mode === 'edit';
  const templateRef = React.useRef(null);
  const [id, setId] = React.useState(initial?.id || '');
  const [label, setLabel] = React.useState(initial?.label || '');
  const [description, setDescription] = React.useState(initial?.description || '');
  const [template, setTemplate] = React.useState(initial?.template || '');
  const [placeholderName, setPlaceholderName] = React.useState('');
  const [err, setErr] = React.useState(null);

  const placeholders = React.useMemo(() => extractCredentialPlaceholders(template), [template]);
  const trimmedPlaceholderName = placeholderName.trim();
  const canInsertPlaceholder = SAFE_PLACEHOLDER_NAME_RE.test(trimmedPlaceholderName);

  const insertPlaceholder = () => {
    if (!canInsertPlaceholder) {
      setErr('placeholder name must match [A-Za-z0-9_-]+');
      return;
    }
    setErr(null);
    const token = `{{credential.${trimmedPlaceholderName}}}`;
    const textarea = templateRef.current;
    const start = textarea?.selectionStart ?? template.length;
    const end = textarea?.selectionEnd ?? template.length;
    const next = `${template.slice(0, start)}${token}${template.slice(end)}`;
    setTemplate(next);
    setPlaceholderName('');
    const schedule = window.requestAnimationFrame || ((fn) => setTimeout(fn, 0));
    schedule(() => {
      textarea?.focus();
      const pos = start + token.length;
      textarea?.setSelectionRange(pos, pos);
    });
  };

  const submit = (e) => {
    e.preventDefault();
    setErr(null);
    const credentials = credentialSpecsFromTemplate(template);
    const preset = {
      id: id.trim(),
      label: label.trim(),
      description: description.trim() || null,
      template,
      credentials,
    };
    const validation = validateCatalogPreset(preset);
    if (validation) {
      setErr(validation);
      return;
    }
    onSave(preset);
  };

  return (
    <section className="panel admin-catalog-form-panel">
      <form className="form admin-catalog-form" onSubmit={submit}>
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
            <textarea
              className="textarea admin-catalog-description"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Docker-backed GitHub MCP server"
              disabled={busy}
              rows={4}
              autoComplete="off"
            />
          </label>
          <div className="admin-catalog-payload">
            <label className="field admin-catalog-template-field">
              <span>JSON template</span>
              <textarea
                ref={templateRef}
                className="mcp-json-textarea admin-catalog-template"
                value={template}
                placeholder={DOCKER_CATALOG_TEMPLATE_PLACEHOLDER}
                onChange={e => setTemplate(e.target.value)}
                spellCheck={false}
                disabled={busy}
                aria-label="Docker MCP JSON template"
              />
            </label>
            <div className="admin-catalog-token-workbench">
              <div className="mcp-card-head">
                <div className="mcp-card-title">
                  <code className="mcp-card-name">payload placeholders</code>
                  <span className="mcp-auth-pill mcp-auth-docker">docker</span>
                </div>
              </div>
              <div className="mcp-card-body">
                <label className="field admin-catalog-placeholder-name">
                  <span>placeholder name</span>
                  <input
                    value={placeholderName}
                    onChange={e => setPlaceholderName(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        insertPlaceholder();
                      }
                    }}
                    placeholder="github_token"
                    disabled={busy}
                    autoComplete="off"
                    aria-label="placeholder name"
                  />
                </label>
                <button
                  type="button"
                  className="btn btn-primary admin-catalog-insert-token"
                  onClick={insertPlaceholder}
                  disabled={busy || !canInsertPlaceholder}
                >
                  insert token
                </button>
                {placeholders.length === 0 ? (
                  <div className="admin-catalog-placeholder-empty">
                    <p className="muted small">no payload placeholders</p>
                  </div>
                ) : (
                  <div className="admin-catalog-credential-list" aria-label="payload placeholders">
                    {placeholders.map(name => (
                      <div className="admin-catalog-credential-row" key={name}>
                        <div className="admin-catalog-credential-row-head">
                          <div className="admin-catalog-credential-title">
                            <span className="muted small">credential field</span>
                            <code className="mono-sm">{name}</code>
                          </div>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            onClick={() => setPlaceholderName(name)}
                            disabled={busy}
                          >
                            reuse
                          </button>
                        </div>
                        <code className="admin-catalog-token">{`{{credential.${name}}}`}</code>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
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
    </section>
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
    if (!SAFE_PLACEHOLDER_NAME_RE.test(field.id)) return 'placeholder ids must match [A-Za-z0-9_-]+';
    if (seen.has(field.id)) return `placeholder ${field.id} is duplicated`;
    seen.add(field.id);
  }
  return null;
}

function extractCredentialPlaceholders(template) {
  const seen = new Set();
  const names = [];
  for (const match of template.matchAll(CREDENTIAL_TOKEN_RE)) {
    const name = match[1];
    if (!seen.has(name)) {
      seen.add(name);
      names.push(name);
    }
  }
  return names;
}

function credentialSpecsFromTemplate(template) {
  return extractCredentialPlaceholders(template).map(name => ({
    id: name,
    label: name,
    description: null,
    required: true,
    secret: true,
    placeholder: null,
  }));
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
