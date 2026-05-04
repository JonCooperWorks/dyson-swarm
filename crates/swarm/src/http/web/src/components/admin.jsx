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

const PLACEHOLDER_TOKEN_RE = /{{\s*placeholders?\.([A-Za-z0-9_-]+)\s*}}/g;
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
      setErr(e?.detail || e?.message || 'list Docker MCP templates failed');
    }
  }, [client]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const remove = async (row) => {
    if (!confirm(`delete Docker MCP template ${row.id}?`)) return;
    setBusy(true); setErr(null);
    try {
      await client.adminDeleteMcpDockerCatalogServer(row.id);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete Docker MCP template failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">docker mcp templates</div>
        <div className="panel-actions">
          <a className={`btn btn-sm ${busy ? 'disabled' : ''}`} href="#/admin/mcp-catalog/new">
            add template
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
        <p className="muted small">no Docker MCP templates.</p>
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
          if (!row) setErr(`No Docker MCP template named ${catalogId}.`);
        }
      } catch (e) {
        if (!cancelled) setErr(e?.detail || e?.message || 'load Docker MCP template failed');
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
      setErr(e?.detail || e?.message || 'save Docker MCP template failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="admin-pane admin-catalog-page">
      <header className="admin-header">
        <div>
          <h2>{isEdit ? `edit ${catalogId}` : 'add Docker MCP template'}</h2>
          <p className="muted small admin-catalog-page-subtitle">
            Configure the MCP JSON template and the placeholders users may fill.
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
  const pathListId = React.useId();
  const [id, setId] = React.useState(initial?.id || '');
  const [label, setLabel] = React.useState(initial?.label || '');
  const [description, setDescription] = React.useState(initial?.description || '');
  const [template, setTemplate] = React.useState(initial?.template || '');
  const [payloadPath, setPayloadPath] = React.useState('');
  const [placeholderName, setPlaceholderName] = React.useState('');
  const [friendlyName, setFriendlyName] = React.useState('');
  const [placeholderLabels, setPlaceholderLabels] = React.useState(
    () => Object.fromEntries((initial?.credentials || []).map(field => [field.id, field.label || field.id])),
  );
  const [err, setErr] = React.useState(null);

  const payloadPaths = React.useMemo(() => listPayloadValuePaths(template), [template]);
  const bindings = React.useMemo(() => listPlaceholderBindings(template), [template]);
  const trimmedPayloadPath = payloadPath.trim();
  const trimmedPlaceholderName = placeholderName.trim();
  const canBindPlaceholder = Boolean(trimmedPayloadPath) && SAFE_PLACEHOLDER_NAME_RE.test(trimmedPlaceholderName);
  const selectedPayloadTarget = React.useMemo(
    () => describePayloadPathTarget(template, trimmedPayloadPath),
    [template, trimmedPayloadPath],
  );
  const replacementToken = SAFE_PLACEHOLDER_NAME_RE.test(trimmedPlaceholderName)
    ? `{{placeholder.${trimmedPlaceholderName}}}`
    : '';

  const bindPlaceholder = () => {
    if (!trimmedPayloadPath) {
      setErr('payload path is required');
      return;
    }
    if (!SAFE_PLACEHOLDER_NAME_RE.test(trimmedPlaceholderName)) {
      setErr('placeholder name must match [A-Za-z0-9_-]+');
      return;
    }
    try {
      const payload = JSON.parse(template);
      const path = parsePayloadPath(trimmedPayloadPath);
      setJsonPathValue(payload, path, `{{placeholder.${trimmedPlaceholderName}}}`);
      setTemplate(JSON.stringify(payload, null, 2));
      setPlaceholderLabels(curr => ({
        ...curr,
        [trimmedPlaceholderName]: friendlyName.trim() || trimmedPlaceholderName,
      }));
      setPlaceholderName('');
      setFriendlyName('');
      setErr(null);
    } catch (e) {
      setErr(e?.message || 'could not bind placeholder');
    }
  };

  const submit = (e) => {
    e.preventDefault();
    setErr(null);
    const credentials = placeholderSpecsFromTemplate(template, placeholderLabels);
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
                  <code className="mcp-card-name">template placeholders</code>
                  <span className="mcp-auth-pill mcp-auth-docker">docker</span>
                </div>
              </div>
              <div className="mcp-card-body">
                <div className="admin-catalog-saved-placeholders">
                  <div className="admin-catalog-saved-placeholders-title">saved placeholders</div>
                  {bindings.length === 0 ? (
                    <div className="admin-catalog-placeholder-empty">
                      <p className="muted small">no template placeholders</p>
                    </div>
                  ) : (
                    <div className="admin-catalog-placeholder-list" aria-label="template placeholders">
                      {bindings.map(binding => (
                        <div className="admin-catalog-placeholder-row" key={`${binding.id}:${binding.path || ''}`}>
                          <div className="admin-catalog-placeholder-row-head">
                            <div className="admin-catalog-placeholder-title">
                              <span className="muted small">placeholder</span>
                              <code className="mono-sm">{binding.id}</code>
                            </div>
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              onClick={() => {
                                setPayloadPath(binding.path || '');
                                setPlaceholderName(binding.id);
                                setFriendlyName(placeholderLabels[binding.id] || binding.id);
                              }}
                              disabled={busy}
                            >
                              reuse
                            </button>
                          </div>
                          {binding.path ? (
                            <code className="admin-catalog-token">{binding.path}</code>
                          ) : null}
                          <code className="admin-catalog-token">{placeholderLabels[binding.id] || binding.id}</code>
                          <code className="admin-catalog-token">{binding.token}</code>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <label className="field admin-catalog-placeholder-name">
                  <span>payload path</span>
                  <input
                    list={pathListId}
                    value={payloadPath}
                    onChange={e => setPayloadPath(e.target.value)}
                    placeholder="servers.github.env.GITHUB_TOKEN"
                    disabled={busy}
                    autoComplete="off"
                    aria-label="payload path"
                  />
                  <datalist id={pathListId}>
                    {payloadPaths.map(path => (
                      <option key={path.path} value={path.path}>{path.preview}</option>
                    ))}
                  </datalist>
                </label>
                {selectedPayloadTarget ? (
                  <div className={`admin-catalog-target-card ${selectedPayloadTarget.ok ? 'admin-catalog-target-ok' : 'admin-catalog-target-error'}`}>
                    <div className="admin-catalog-target-kicker">
                      {selectedPayloadTarget.ok ? 'selected JSON value' : 'path needs attention'}
                    </div>
                    <code className="admin-catalog-target-path">{trimmedPayloadPath}</code>
                    {selectedPayloadTarget.ok ? (
                      <>
                        <div className="admin-catalog-target-flow">
                          <div>
                            <span>current value</span>
                            <code>{selectedPayloadTarget.preview}</code>
                          </div>
                          <div>
                            <span>will become</span>
                            <code>{replacementToken || '{{placeholder.name}}'}</code>
                          </div>
                        </div>
                        <p className="muted small admin-catalog-target-note">
                          This value is where the user's input will go.
                        </p>
                      </>
                    ) : (
                      <p className="muted small admin-catalog-target-note">{selectedPayloadTarget.error}</p>
                    )}
                  </div>
                ) : null}
                <label className="field admin-catalog-placeholder-name">
                  <span>placeholder name</span>
                  <input
                    value={placeholderName}
                    onChange={e => setPlaceholderName(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        bindPlaceholder();
                      }
                    }}
                    placeholder="github_token"
                    disabled={busy}
                    autoComplete="off"
                    aria-label="placeholder name"
                  />
                </label>
                <label className="field admin-catalog-placeholder-name">
                  <span>friendly name</span>
                  <input
                    value={friendlyName}
                    onChange={e => setFriendlyName(e.target.value)}
                    placeholder="Brave API key"
                    disabled={busy}
                    autoComplete="off"
                    aria-label="friendly name"
                  />
                </label>
                <button
                  type="button"
                  className="btn btn-primary admin-catalog-bind-placeholder"
                  onClick={bindPlaceholder}
                  disabled={busy || !canBindPlaceholder}
                >
                  bind placeholder
                </button>
                {payloadPaths.length > 0 ? (
                  <div className="admin-catalog-path-list" aria-label="payload paths">
                    {payloadPaths.slice(0, 12).map(path => (
                      <button
                        key={path.path}
                        type="button"
                        className={`admin-catalog-path-option ${path.path === trimmedPayloadPath ? 'admin-catalog-path-option-active' : ''}`}
                        onClick={() => setPayloadPath(path.path)}
                        disabled={busy}
                      >
                        <code>{path.path}</code>
                        <span>{path.preview}</span>
                      </button>
                    ))}
                  </div>
                ) : null}
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

function extractTemplatePlaceholders(template) {
  const seen = new Set();
  const names = [];
  for (const match of template.matchAll(PLACEHOLDER_TOKEN_RE)) {
    const name = match[1];
    if (!seen.has(name)) {
      seen.add(name);
      names.push(name);
    }
  }
  return names;
}

function listPlaceholderBindings(template) {
  try {
    const payload = JSON.parse(template);
    const seen = new Set();
    const bindings = [];
    walkJsonLeaves(payload, [], (value, path) => {
      if (typeof value !== 'string') return;
      for (const match of value.matchAll(PLACEHOLDER_TOKEN_RE)) {
        const id = match[1];
        const displayPath = formatPayloadPath(path);
        const key = `${displayPath}:${id}:${match[0]}`;
        if (seen.has(key)) continue;
        seen.add(key);
        bindings.push({ id, path: displayPath, token: match[0] });
      }
    });
    return bindings;
  } catch {
    return extractTemplatePlaceholders(template).map(id => ({
      id,
      path: '',
      token: `{{placeholder.${id}}}`,
    }));
  }
}

function listPayloadValuePaths(template) {
  try {
    const payload = JSON.parse(template);
    const paths = [];
    walkJsonLeaves(payload, [], (value, path) => {
      if (path.length === 0) return;
      paths.push({
        path: formatPayloadPath(path),
        preview: previewJsonValue(value),
      });
    });
    return paths;
  } catch {
    return [];
  }
}

function describePayloadPathTarget(template, pathText) {
  if (!pathText) return null;
  try {
    const payload = JSON.parse(template);
    const path = parsePayloadPath(pathText);
    const value = getJsonPathValue(payload, path);
    return {
      ok: true,
      preview: previewJsonValue(value),
    };
  } catch (e) {
    return {
      ok: false,
      error: e?.message || 'payload path could not be found',
    };
  }
}

function walkJsonLeaves(value, path, visit) {
  if (Array.isArray(value)) {
    if (value.length === 0) visit(value, path);
    value.forEach((item, index) => walkJsonLeaves(item, [...path, index], visit));
    return;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length === 0) visit(value, path);
    entries.forEach(([key, child]) => walkJsonLeaves(child, [...path, key], visit));
    return;
  }
  visit(value, path);
}

function previewJsonValue(value) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value);
  if (raw == null) return 'null';
  return raw.length > 42 ? `${raw.slice(0, 39)}...` : raw;
}

function formatPayloadPath(path) {
  return path.map((part, index) => {
    if (typeof part === 'number') return `[${part}]`;
    if (/^[A-Za-z0-9_-]+$/.test(part)) return index === 0 ? part : `.${part}`;
    return `[${JSON.stringify(part)}]`;
  }).join('');
}

function parsePayloadPath(path) {
  const segments = [];
  let token = '';
  for (let i = 0; i < path.length; i += 1) {
    const char = path[i];
    if (char === '.') {
      if (token) {
        segments.push(token);
        token = '';
      }
      continue;
    }
    if (char !== '[') {
      token += char;
      continue;
    }
    if (token) {
      segments.push(token);
      token = '';
    }
    const end = path.indexOf(']', i);
    if (end === -1) throw new Error('payload path has an unclosed bracket');
    const raw = path.slice(i + 1, end).trim();
    if (!raw) throw new Error('payload path has an empty bracket segment');
    if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
      const json = raw.startsWith("'")
        ? `"${raw.slice(1, -1).replaceAll('"', '\\"')}"`
        : raw;
      segments.push(JSON.parse(json));
    } else if (/^\d+$/.test(raw)) {
      segments.push(Number(raw));
    } else {
      segments.push(raw);
    }
    i = end;
  }
  if (token) segments.push(token);
  if (segments.length === 0) throw new Error('payload path is required');
  return segments;
}

function setJsonPathValue(root, path, value) {
  let cursor = root;
  for (let i = 0; i < path.length - 1; i += 1) {
    const key = path[i];
    if (cursor == null || typeof cursor !== 'object') {
      throw new Error(`payload path ${formatPayloadPath(path.slice(0, i + 1))} is not an object`);
    }
    if (cursor[key] == null) {
      cursor[key] = typeof path[i + 1] === 'number' ? [] : {};
    }
    cursor = cursor[key];
  }
  const last = path[path.length - 1];
  if (cursor == null || typeof cursor !== 'object') {
    throw new Error(`payload path ${formatPayloadPath(path)} cannot be set`);
  }
  cursor[last] = value;
}

function getJsonPathValue(root, path) {
  let cursor = root;
  for (let i = 0; i < path.length; i += 1) {
    const key = path[i];
    if (cursor == null || typeof cursor !== 'object' || !(key in cursor)) {
      throw new Error(`payload path ${formatPayloadPath(path.slice(0, i + 1))} was not found`);
    }
    cursor = cursor[key];
  }
  return cursor;
}

function placeholderSpecsFromTemplate(template, labels = {}) {
  return extractTemplatePlaceholders(template).map(name => ({
    id: name,
    label: labels[name] || name,
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
