/* swarm — Admin view (users + proxy-token revocation).
 *
 * Admin routes (/v1/admin/*) sit behind the same OIDC chain as
 * everything else, with an extra middleware that requires the
 * caller's JWT to carry the configured admin permission/role.  The
 * SPA's normal access token is therefore sufficient — no separate
 * token prompt.  Users without the admin permission
 * see a "not authorized" splash instead of the panels (driven by a
 * probe of /v1/admin/users; backend is the source of truth).
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';
import { JsonEditor } from './json-editor.jsx';
import { MarkdownBody } from './markdown.jsx';

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

const ADMIN_SECTIONS = [
  {
    key: 'mcp-catalog',
    href: '#/admin/mcp-catalog',
    label: 'MCP catalog',
    summary: 'Docker MCP templates',
  },
  {
    key: 'skill-marketplaces',
    href: '#/admin/skill-marketplaces',
    label: 'Skill marketplaces',
    summary: 'Skill source indexes',
  },
  {
    key: 'users',
    href: '#/admin/users',
    label: 'Users',
    summary: 'Accounts and limits',
  },
  {
    key: 'proxy-tokens',
    href: '#/admin/proxy-tokens',
    label: 'Proxy tokens',
    summary: 'Emergency revocation',
  },
  {
    key: 'kms-audit',
    href: '#/admin/kms-audit',
    label: 'KMS audit',
    summary: 'Secret access events',
  },
];

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
  if (view.name === 'admin-skill-marketplace-new') {
    return <SkillMarketplaceSourceEditorPage client={client} mode="new"/>;
  }
  if (view.name === 'admin-skill-marketplace-edit') {
    return <SkillMarketplaceSourceEditorPage client={client} mode="edit" marketplaceId={view.marketplaceId}/>;
  }
  if (view.name === 'admin-mcp-catalog') {
    return (
      <AdminSectionPage active="mcp-catalog">
        <DockerCatalogPanel client={client}/>
      </AdminSectionPage>
    );
  }
  if (view.name === 'admin-skill-marketplaces') {
    return (
      <AdminSectionPage active="skill-marketplaces">
        <SkillMarketplaceSourcesPanel client={client}/>
      </AdminSectionPage>
    );
  }
  if (view.name === 'admin-users') {
    return (
      <AdminSectionPage active="users">
        <UsersPanel client={client}/>
      </AdminSectionPage>
    );
  }
  if (view.name === 'admin-proxy-tokens') {
    return (
      <AdminSectionPage active="proxy-tokens">
        <ProxyTokensPanel client={client}/>
      </AdminSectionPage>
    );
  }
  if (view.name === 'admin-kms-audit') {
    return (
      <AdminSectionPage active="kms-audit">
        <KmsAuditPanel client={client}/>
      </AdminSectionPage>
    );
  }

  return <AdminLandingPage client={client}/>;
}

function AdminLandingPage({ client }) {
  const overview = useAdminOverview(client);
  return (
    <main className="admin-pane admin-overview-page">
      <AdminPageHeader title="admin" subtitle="Operator controls"/>
      <nav className="admin-section-links" aria-label="admin sections">
        {ADMIN_SECTIONS.map(section => (
          <AdminSectionCard
            key={section.key}
            section={section}
            overview={overview}
          />
        ))}
      </nav>
    </main>
  );
}

function AdminSectionPage({ active, children }) {
  const section = ADMIN_SECTIONS.find(s => s.key === active);
  return (
    <main className={`admin-pane admin-section-page admin-section-page-${active}`}>
      <AdminPageHeader title={section?.label || 'admin'} subtitle={section?.summary}>
        <a className="btn btn-ghost btn-sm" href="#/admin">overview</a>
      </AdminPageHeader>
      <AdminSectionTabs active={active}/>
      {children}
    </main>
  );
}

function AdminPageHeader({ title, subtitle, children }) {
  return (
    <header className="admin-header">
      <div>
        <h2>{title}</h2>
        {subtitle ? <p className="muted small admin-header-subtitle">{subtitle}</p> : null}
      </div>
      {children ? <div className="admin-header-actions">{children}</div> : null}
    </header>
  );
}

function AdminSectionTabs({ active }) {
  return (
    <nav className="admin-section-tabs" aria-label="admin sections">
      {ADMIN_SECTIONS.map(section => (
        <a
          key={section.key}
          className={section.key === active ? 'active' : ''}
          href={section.href}
        >
          {section.label}
        </a>
      ))}
    </nav>
  );
}

function AdminSectionCard({ section, overview }) {
  const metrics = overviewMetrics(section.key, overview);
  return (
    <a className="admin-section-link" href={section.href}>
      <span className="admin-section-link-main">
        <span className="admin-section-link-title">{section.label}</span>
        <span className="admin-section-link-summary">{section.summary}</span>
      </span>
      <span className="admin-section-link-metrics" aria-label={`${section.label} summary`}>
        {metrics.map(item => (
          <span className="admin-section-link-metric" key={item.label}>
            <strong>{item.value}</strong>
            <span>{item.label}</span>
          </span>
        ))}
      </span>
    </a>
  );
}

function useAdminOverview(client) {
  const [overview, setOverview] = React.useState({ state: 'loading' });

  React.useEffect(() => {
    let cancelled = false;
    const load = async () => {
      const [users, docker, marketplaces, catalog] = await Promise.all([
        callOverview(() => client.adminListUsers()),
        callOverview(() => client.adminListMcpDockerCatalog?.()),
        callOverview(() => client.adminListSkillMarketplaces?.()),
        callOverview(() => client.listMarketplaceSkills?.()),
      ]);
      if (cancelled) return;

      const userRows = Array.isArray(users.value) ? users.value : [];
      const dockerRows = Array.isArray(docker.value?.servers) ? docker.value.servers : [];
      const marketplaceRows = Array.isArray(marketplaces.value?.sources) ? marketplaces.value.sources : [];
      const skillSources = Array.isArray(catalog.value?.sources) ? catalog.value.sources : [];
      const virtualCatalogs = skillSources.filter(isVirtualAgentSource);

      setOverview({
        state: 'ready',
        users: {
          total: userRows.length,
          active: userRows.filter(u => u.status === 'active').length,
          suspended: userRows.filter(u => u.status === 'suspended').length,
        },
        docker: {
          total: dockerRows.length,
          pending: dockerRows.filter(row => row.status === 'pending').length,
          admin: dockerRows.filter(row => (row.source || 'admin') === 'admin').length,
        },
        marketplaces: {
          total: marketplaceRows.length,
          enabled: marketplaceRows.filter(row => row.enabled !== false).length,
          virtual: virtualCatalogs.length,
        },
      });
    };
    load();
    return () => { cancelled = true; };
  }, [client]);

  return overview;
}

async function callOverview(fn) {
  if (typeof fn !== 'function') return { ok: false, value: null };
  try {
    return { ok: true, value: await fn() };
  } catch (error) {
    return { ok: false, value: null, error };
  }
}

function overviewMetrics(key, overview) {
  if (overview.state !== 'ready') {
    return [{ label: 'status', value: '...' }];
  }
  switch (key) {
    case 'mcp-catalog':
      return [
        { label: 'templates', value: overview.docker.total },
        { label: 'pending', value: overview.docker.pending },
      ];
    case 'skill-marketplaces':
      return [
        { label: 'sources', value: overview.marketplaces.total },
        { label: 'agent catalogs', value: overview.marketplaces.virtual },
      ];
    case 'users':
      return [
        { label: 'users', value: overview.users.total },
        { label: 'active', value: overview.users.active },
      ];
    case 'proxy-tokens':
      return [{ label: 'mode', value: 'revoke' }];
    case 'kms-audit':
      return [{ label: 'events', value: 'paged' }];
    default:
      return [];
  }
}

function AdminStatsRow({ items }) {
  const visible = (items || []).filter(item => item && item.value !== undefined && item.value !== null);
  if (visible.length === 0) return null;
  return (
    <div className="admin-stats-row">
      {visible.map(item => (
        <div className="admin-stat" key={item.label}>
          <span className="admin-stat-value">{item.value}</span>
          <span className="admin-stat-label">{item.label}</span>
        </div>
      ))}
    </div>
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
      {rows !== null ? (
        <AdminStatsRow items={[
          { label: 'templates', value: rows.length },
          { label: 'pending', value: rows.filter(row => row.status === 'pending').length },
          { label: 'admin managed', value: rows.filter(row => (row.source || 'admin') === 'admin').length },
        ]}/>
      ) : null}
      {rows === null ? (
        <p className="muted small">loading...</p>
      ) : rows.length === 0 ? (
        <p className="muted small">no Docker MCP templates.</p>
      ) : (
        <table className="rows">
          <thead><tr>
            <th>id</th><th>label</th><th>status</th><th>source</th><th>placeholders</th><th>updated</th><th></th>
          </tr></thead>
          <tbody>
            {rows.map(row => (
              <tr key={row.id}>
                <td data-label="id"><code className="mono-sm">{row.id}</code></td>
                <td data-label="label">
                  <div>{row.label || row.id}</div>
                  {row.description ? (
                    <MarkdownBody markdown={row.description} className="md-body md-body-compact mcp-description-markdown"/>
                  ) : null}
                </td>
                <td data-label="status">
                  <span className={`badge badge-${row.status === 'pending' ? 'warn' : 'ok'}`}>
                    {row.status || 'active'}
                  </span>
                  {row.requested_by_user_id ? (
                    <div className="muted small">
                      requested by <code className="mono-sm">{row.requested_by_user_id}</code>
                    </div>
                  ) : null}
                </td>
                <td data-label="source">
                  <span className={`badge badge-${row.source === 'config' ? 'info' : 'ok'}`}>
                    {row.source || 'admin'}
                  </span>
                </td>
                <td data-label="placeholders" className="muted small">
                  {(row.placeholders || []).length}
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

// ─── Skill marketplace sources panel ─────────────────────────────

const SKILL_MARKETPLACE_ID_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function SkillMarketplaceSourcesPanel({ client }) {
  const [rows, setRows] = React.useState(null);
  const [virtualRows, setVirtualRows] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [catalogErr, setCatalogErr] = React.useState(null);

  const available = Boolean(
    client.adminListSkillMarketplaces
      && client.adminPutSkillMarketplaceSource
      && client.adminDeleteSkillMarketplaceSource,
  );

  const refresh = React.useCallback(async () => {
    if (!available) return;
    setErr(null);
    setCatalogErr(null);
    try {
      const catalogPromise = typeof client.listMarketplaceSkills === 'function'
        ? client.listMarketplaceSkills().catch(e => ({ __error: e }))
        : Promise.resolve(null);
      const body = await client.adminListSkillMarketplaces();
      setRows(Array.isArray(body?.sources) ? body.sources : []);
      const catalogBody = await catalogPromise;
      if (catalogBody?.__error) {
        setCatalogErr(catalogBody.__error?.detail || catalogBody.__error?.message || 'list agent skill catalogs failed');
        setVirtualRows([]);
      } else {
        setVirtualRows(buildVirtualAgentCatalogRows(catalogBody));
      }
    } catch (e) {
      setErr(e?.detail || e?.message || 'list skill marketplaces failed');
    }
  }, [available, client]);

  React.useEffect(() => { refresh(); }, [refresh]);

  if (!available) return null;

  const remove = async (row) => {
    if (!confirm(`delete skill marketplace ${row.id}?`)) return;
    setBusy(true); setErr(null);
    try {
      await client.adminDeleteSkillMarketplaceSource(row.id);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete skill marketplace failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel admin-skill-marketplaces-panel">
      <div className="panel-header">
        <div className="panel-title">skill marketplaces</div>
        <div className="panel-actions">
          <a className={`btn btn-sm ${busy ? 'disabled' : ''}`} href="#/admin/skill-marketplaces/new">
            add marketplace
          </a>
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={busy}>
            refresh
          </button>
        </div>
      </div>
      {err ? <div className="error">{err}</div> : null}
      {rows !== null || virtualRows !== null ? (
        <AdminStatsRow items={[
          { label: 'configured sources', value: rows ? rows.length : '...' },
          { label: 'enabled', value: rows ? rows.filter(row => row.enabled !== false).length : '...' },
          { label: 'agent catalogs', value: virtualRows ? virtualRows.length : '...' },
        ]}/>
      ) : null}
      <div className="admin-marketplace-sections">
        <section className="admin-marketplace-section">
          <div className="admin-marketplace-section-head">
            <div>
              <h3>configured marketplace sources</h3>
              <p className="muted small">Inline and HTTPS marketplace indexes stored in Swarm.</p>
            </div>
          </div>
          {rows === null ? (
            <p className="muted small">loading...</p>
          ) : rows.length === 0 ? (
            <div className="admin-marketplace-empty">
              <div>
                <h4>No configured marketplace sources yet</h4>
                <p className="muted small">Add an inline or HTTPS source when operators need a shared editable catalog.</p>
              </div>
              <a className="btn btn-primary btn-sm" href="#/admin/skill-marketplaces/new">add marketplace</a>
            </div>
          ) : (
            <table className="rows">
              <thead><tr>
                <th>id</th><th>type</th><th>status</th><th>location</th><th>last fetch</th><th></th>
              </tr></thead>
              <tbody>
                {rows.map(row => (
                  <tr key={row.id}>
                    <td data-label="id"><code className="mono-sm">{row.id}</code></td>
                    <td data-label="type">{row.source_type}</td>
                    <td data-label="status">
                      <span className={`badge badge-${row.enabled === false ? 'faint' : 'ok'}`}>
                        {row.enabled === false ? 'disabled' : 'enabled'}
                      </span>
                      {row.last_error ? (
                        <div className="error small">{row.last_error}</div>
                      ) : null}
                    </td>
                    <td data-label="location">
                      <code className="mono-sm">{row.location}</code>
                    </td>
                    <td data-label="last fetch" className="muted small">{fmtTime(row.last_fetch_at)}</td>
                    <td className="row-actions">
                      <a
                        className="btn btn-ghost btn-sm"
                        href={`#/admin/skill-marketplaces/${encodeURIComponent(row.id)}`}
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

        <section className="admin-marketplace-section virtual-catalogs">
          <div className="admin-marketplace-section-head">
            <div>
              <h3>agent skill catalogs</h3>
              <p className="muted small">Read-only virtual catalogs discovered from live agent inventory.</p>
            </div>
          </div>
          {catalogErr ? <div className="error">{catalogErr}</div> : null}
          {virtualRows === null ? (
            <p className="muted small">loading...</p>
          ) : virtualRows.length === 0 ? (
            <p className="muted small admin-marketplace-empty-line">No live agent skill catalogs found</p>
          ) : (
            <table className="rows virtual-catalog-table">
              <thead><tr>
                <th>catalog</th><th>marketplace id</th><th>live instance</th><th>skills</th><th>status</th><th></th>
              </tr></thead>
              <tbody>
                {virtualRows.map(row => (
                  <tr key={row.id} className="virtual-catalog-row">
                    <td data-label="catalog">
                      <div className="virtual-catalog-name">{row.name}</div>
                    </td>
                    <td data-label="marketplace id">
                      <code className="mono-sm">{row.id}</code>
                    </td>
                    <td data-label="live instance">
                      <div className="virtual-catalog-instance">
                        <span>{row.instanceName}</span>
                        <code className="mono-sm">{row.instanceId}</code>
                      </div>
                    </td>
                    <td data-label="skills">
                      <span className="badge badge-info">{row.skillCount}</span>
                    </td>
                    <td data-label="status">
                      <span className="badge badge-info">virtual</span>
                      <div className="muted small">from agent inventory</div>
                    </td>
                    <td className="row-actions virtual-catalog-actions">
                      <a className="btn btn-ghost btn-sm" href={row.browseHref}>browse</a>
                      <a className="btn btn-ghost btn-sm" href={row.agentHref}>agent skills</a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </section>
  );
}

function buildVirtualAgentCatalogRows(catalog) {
  const sources = Array.isArray(catalog?.sources) ? catalog.sources : [];
  const skills = Array.isArray(catalog?.skills) ? catalog.skills : [];
  const sourceById = new Map(sources.map(source => [source.id, source]));
  const ids = new Set(
    sources
      .filter(isVirtualAgentSource)
      .map(source => source.id)
      .filter(Boolean),
  );
  for (const skill of skills) {
    if (isVirtualAgentMarketplaceId(skill.marketplace_id)) ids.add(skill.marketplace_id);
  }
  return [...ids].map(id => {
    const source = sourceById.get(id) || { id };
    const catalogSkills = skills.filter(skill => skill.marketplace_id === id);
    const firstSkill = catalogSkills[0] || {};
    const author = catalogSkills.map(skill => skill.author).find(Boolean) || {};
    const instanceId = author.instance_id || instanceIdFromAgentSource(source) || id.replace(/^agent-/, '');
    const instanceName = author.name || instanceId;
    const name = firstSkill.marketplace_name || `${instanceName} skills`;
    return {
      id,
      name,
      instanceId,
      instanceName,
      skillCount: catalogSkills.length,
      browseHref: `#/skills?source=${encodeURIComponent(id)}`,
      agentHref: author.href || `#/i/${encodeURIComponent(instanceId)}/skills`,
    };
  }).sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

function isVirtualAgentSource(source) {
  return source?.source_type === 'agent' || isVirtualAgentMarketplaceId(source?.id);
}

function isVirtualAgentMarketplaceId(id) {
  return String(id || '').startsWith('agent-');
}

function instanceIdFromAgentSource(source) {
  const match = String(source?.location || '').match(/^swarm:\/\/instances\/([^/]+)\/skills$/);
  return match ? match[1] : '';
}

function emptySkillMarketplaceSource() {
  return {
    id: '',
    source_type: 'inline',
    location: '',
    enabled: true,
  };
}

function SkillMarketplaceSourceEditorPage({ client, mode, marketplaceId }) {
  const isEdit = mode === 'edit';
  const [initial, setInitial] = React.useState(isEdit ? null : emptySkillMarketplaceSource());
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);

  React.useEffect(() => {
    let cancelled = false;
    if (!isEdit) {
      setInitial(emptySkillMarketplaceSource());
      return () => { cancelled = true; };
    }
    setInitial(null);
    (async () => {
      setErr(null);
      try {
        const body = await client.adminListSkillMarketplaces();
        const row = (body?.sources || []).find(source => source.id === marketplaceId);
        if (!cancelled) {
          setInitial(row ? {
            id: row.id,
            source_type: row.source_type || 'http',
            location: row.location || '',
            enabled: row.enabled !== false,
          } : null);
          if (!row) setErr(`No skill marketplace named ${marketplaceId}.`);
        }
      } catch (e) {
        if (!cancelled) setErr(e?.detail || e?.message || 'load skill marketplace failed');
      }
    })();
    return () => { cancelled = true; };
  }, [client, isEdit, marketplaceId]);

  const save = async (source) => {
    setBusy(true); setErr(null);
    try {
      await client.adminPutSkillMarketplaceSource(source.id, {
        source_type: source.source_type,
        location: source.location,
        enabled: source.enabled,
      });
      window.location.hash = '#/admin/skill-marketplaces';
    } catch (e) {
      setErr(e?.detail || e?.message || 'save skill marketplace failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="admin-pane admin-catalog-page admin-catalog-page-wide">
      <header className="admin-header">
        <div>
          <h2>{isEdit ? `edit ${marketplaceId}` : 'add skill marketplace'}</h2>
          <p className="muted small admin-catalog-page-subtitle">
            Connect a marketplace index that Swarm can publish to Dyson agents.
          </p>
        </div>
        <a className="btn btn-ghost btn-sm" href="#/admin">back</a>
      </header>
      {err ? <div className="error">{err}</div> : null}
      {!initial && isEdit && !err ? (
        <p className="muted small">loading...</p>
      ) : initial ? (
        <SkillMarketplaceSourceForm
          key={`${mode}:${initial.id || 'new'}`}
          mode={mode}
          initial={initial}
          busy={busy}
          onCancel={() => { window.location.hash = '#/admin/skill-marketplaces'; }}
          onSave={save}
        />
      ) : null}
    </main>
  );
}

function SkillMarketplaceSourceForm({ mode, initial, busy, onCancel, onSave }) {
  const isEdit = mode === 'edit';
  const [form, setForm] = React.useState(initial || emptySkillMarketplaceSource());
  const [err, setErr] = React.useState(null);
  const editorRef = React.useRef(null);

  const submit = (e) => {
    e.preventDefault();
    const id = form.id.trim();
    const sourceType = form.source_type === 'http' ? 'http' : 'inline';
    const location = form.location.trim();
    if (!SKILL_MARKETPLACE_ID_RE.test(id)) {
      setErr('marketplace id must be lowercase words separated by hyphens');
      return;
    }
    if (!location) {
      setErr(sourceType === 'http' ? 'marketplace url is required' : 'marketplace index JSON is required');
      return;
    }
    if (sourceType === 'inline') {
      const parsed = editorRef.current?.parse();
      if (!parsed?.ok) {
        setErr(parsed?.error || 'invalid JSON');
        return;
      }
    } else {
      try {
        const parsed = new URL(location);
        if (parsed.protocol !== 'https:') {
          setErr('marketplace url must use https');
          return;
        }
      } catch {
        setErr('marketplace url is invalid');
        return;
      }
    }
    if (form.source_type !== sourceType) {
      setForm(curr => ({ ...curr, source_type: sourceType }));
    }
    setErr(null);
    onSave({
      id,
      source_type: sourceType,
      location,
      enabled: form.enabled !== false,
    });
  };

  return (
    <section className="panel admin-catalog-form-panel admin-skill-marketplace-form-panel">
      <form className="form admin-catalog-form" onSubmit={submit}>
        {err ? <div className="error">{err}</div> : null}
        <p className="muted small admin-catalog-page-subtitle">
          Inline pastes the index directly. HTTP fetches it from a URL Swarm can reach.
        </p>
        <label className="field">
          <span>id</span>
          <input
            value={form.id}
            onChange={e => setForm(curr => ({ ...curr, id: e.target.value }))}
            placeholder="team-skills"
            disabled={busy || isEdit}
            autoComplete="off"
            autoFocus={!isEdit}
          />
        </label>
        <label className="field">
          <span>type</span>
          <select
            value={form.source_type}
            onChange={e => setForm(curr => ({ ...curr, source_type: e.target.value }))}
            disabled={busy}
          >
            <option value="inline">inline</option>
            <option value="http">http</option>
          </select>
        </label>
        {form.source_type === 'http' ? (
          <label className="field">
            <span>url</span>
            <input
              value={form.location}
              onChange={e => setForm(curr => ({ ...curr, location: e.target.value }))}
              placeholder="https://example.com/marketplace.json"
              disabled={busy}
              autoComplete="off"
            />
          </label>
        ) : (
          <label className="field">
            <span>index json</span>
            <JsonEditor
              ref={editorRef}
              value={form.location}
              onChange={next => setForm(curr => ({ ...curr, location: next }))}
              rows={16}
              placeholder='{ "schema_version": 1, "marketplace": { "id": "team-skills", "name": "Team skills" }, "skills": [] }'
              disabled={busy}
              ariaLabel="marketplace index JSON"
              validate={parsed => {
                const skills = Array.isArray(parsed?.skills) ? parsed.skills : null;
                if (!skills) return { ok: false, message: 'missing skills[] array' };
                return { ok: true, message: `valid (${skills.length} skill${skills.length === 1 ? '' : 's'})` };
              }}
            />
          </label>
        )}
        <label className="field check">
          <input
            type="checkbox"
            checked={form.enabled !== false}
            onChange={e => setForm(curr => ({ ...curr, enabled: e.target.checked }))}
            disabled={busy}
          />
          <span>enabled</span>
        </label>
        <div className="form-actions">
          <button className="btn btn-primary" type="submit" disabled={busy}>
            save
          </button>
          <button className="btn btn-ghost" type="button" onClick={onCancel} disabled={busy}>
            cancel
          </button>
        </div>
      </form>
    </section>
  );
}

function emptyDockerCatalogPreset() {
  return {
    id: '',
    label: '',
    description: '',
    template: '',
    placeholders: [],
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
        placeholders: preset.placeholders,
      });
      window.location.hash = '#/admin/mcp-catalog';
    } catch (e) {
      setErr(e?.detail || e?.message || 'save Docker MCP template failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="admin-pane admin-catalog-page admin-catalog-page-wide">
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
          key={`${mode}:${initial.id || 'new'}`}
          mode={mode}
          initial={initial}
          busy={busy}
          onCancel={() => { window.location.hash = '#/admin/mcp-catalog'; }}
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
    () => Object.fromEntries((initial?.placeholders || []).map(field => [field.id, field.label || field.id])),
  );
  const [err, setErr] = React.useState(null);
  const templateEditorRef = React.useRef(null);

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

  const removePlaceholder = (binding) => {
    try {
      setTemplate(removePlaceholderBinding(template, binding));
      setPlaceholderLabels(curr => {
        const next = { ...curr };
        delete next[binding.id];
        return next;
      });
      if (placeholderName === binding.id) {
        setPlaceholderName('');
        setFriendlyName('');
      }
      if (payloadPath === binding.path) setPayloadPath('');
      setErr(null);
    } catch (e) {
      setErr(e?.message || 'could not remove placeholder');
    }
  };

  const submit = (e) => {
    e.preventDefault();
    setErr(null);
    const parsedTemplate = templateEditorRef.current?.parse();
    if (!parsedTemplate?.ok) {
      setErr(parsedTemplate?.error || 'JSON template is not valid JSON');
      return;
    }
    const placeholders = placeholderSpecsFromTemplate(template, placeholderLabels);
    const preset = {
      id: id.trim(),
      label: label.trim(),
      description: description.trim() || null,
      template,
      placeholders,
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
              <div className="admin-catalog-template">
                <JsonEditor
                  ref={templateEditorRef}
                  value={template}
                  onChange={setTemplate}
                  rows={20}
                  placeholder={DOCKER_CATALOG_TEMPLATE_PLACEHOLDER}
                  disabled={busy}
                  ariaLabel="Docker MCP JSON template"
                  validate={parsed => {
                    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
                      return { ok: false, message: 'template must be a JSON object' };
                    }
                    const placeholders = listPlaceholderBindings(JSON.stringify(parsed));
                    return placeholders.length === 0
                      ? { ok: true, message: 'valid JSON (no placeholders bound)' }
                      : { ok: true, message: `valid JSON (${placeholders.length} placeholder${placeholders.length === 1 ? '' : 's'})` };
                  }}
                />
              </div>
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
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm btn-danger"
                              onClick={() => removePlaceholder(binding)}
                              disabled={busy}
                            >
                              delete
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
  for (const field of preset.placeholders) {
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

function removePlaceholderBinding(template, binding) {
  const token = binding?.token || `{{placeholder.${binding?.id || ''}}}`;
  if (!binding?.path) {
    return template.replaceAll(token, '');
  }
  const payload = JSON.parse(template);
  const path = parsePayloadPath(binding.path);
  const current = getJsonPathValue(payload, path);
  if (typeof current !== 'string') {
    throw new Error('placeholder path is no longer a string value');
  }
  setJsonPathValue(payload, path, current.replaceAll(token, ''));
  return JSON.stringify(payload, null, 2);
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
      {rows !== null ? (
        <AdminStatsRow items={[
          { label: 'users', value: rows.length },
          { label: 'active', value: rows.filter(u => u.status === 'active').length },
          { label: 'suspended', value: rows.filter(u => u.status === 'suspended').length },
          { label: 'OpenRouter keys', value: rows.filter(u => u.openrouter_key_present).length },
        ]}/>
      ) : null}
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

function KmsAuditPanel({ client }) {
  const [filters, setFilters] = React.useState({
    scope: '',
    reason: '',
    operation: '',
    result: '',
    owner_id: '',
    instance_id: '',
    secret_name: '',
  });
  const [offset, setOffset] = React.useState(0);
  const [page, setPage] = React.useState({ state: 'loading', items: [], next_offset: null });
  const limit = 50;

  React.useEffect(() => {
    let cancelled = false;
    setPage(prev => ({ ...prev, state: 'loading' }));
    client.adminListKmsAudit({ ...filters, limit, offset })
      .then(body => {
        if (cancelled) return;
        setPage({
          state: 'ready',
          items: body?.items || [],
          next_offset: body?.next_offset ?? null,
        });
      })
      .catch(error => {
        if (cancelled) return;
        setPage({ state: 'error', items: [], next_offset: null, message: error?.detail || error?.message || 'failed to load audit events' });
      });
    return () => { cancelled = true; };
  }, [client, filters, offset]);

  const updateFilter = (key, value) => {
    setOffset(0);
    setFilters(f => ({ ...f, [key]: value }));
  };

  return (
    <section className="panel admin-kms-audit-panel">
      <div className="panel-header">
        <div className="panel-title">KMS audit events</div>
        <div className="panel-actions">
          <button className="btn btn-sm" type="button" onClick={() => setOffset(0)}>refresh</button>
        </div>
      </div>
      <div className="admin-kms-audit-filters">
        <select value={filters.scope} onChange={e => updateFilter('scope', e.target.value)} aria-label="scope">
          <option value="">all scopes</option>
          <option value="system_secret">system_secret</option>
          <option value="system_configure">system_configure</option>
          <option value="user_secret">user_secret</option>
          <option value="user_api_key">user_api_key</option>
          <option value="user_profile">user_profile</option>
          <option value="runtime_token">runtime_token</option>
          <option value="state_file">state_file</option>
          <option value="artefact">artefact</option>
          <option value="webhook_delivery">webhook_delivery</option>
          <option value="llm_tool_call">llm_tool_call</option>
        </select>
        <select value={filters.operation} onChange={e => updateFilter('operation', e.target.value)} aria-label="operation">
          <option value="">all operations</option>
          <option value="encrypt">encrypt</option>
          <option value="decrypt">decrypt</option>
          <option value="rewrap">rewrap</option>
          <option value="rotate">rotate</option>
          <option value="delete">delete</option>
        </select>
        <select value={filters.result} onChange={e => updateFilter('result', e.target.value)} aria-label="result">
          <option value="">all results</option>
          <option value="success">success</option>
          <option value="failure">failure</option>
        </select>
        <select value={filters.reason} onChange={e => updateFilter('reason', e.target.value)} aria-label="reason">
          <option value="">all reasons</option>
          {[
            'LlmProviderProxy',
            'McpProxyForward',
            'McpOAuthRefresh',
            'RuntimeConfigurePush',
            'SystemSecretBootstrap',
            'OperatorCli',
            'StateReplay',
            'ArtefactRead',
            'Migration',
            'Test',
          ].map(reason => <option key={reason} value={reason}>{reason}</option>)}
        </select>
        <input value={filters.owner_id} onChange={e => updateFilter('owner_id', e.target.value)} placeholder="owner_id"/>
        <input value={filters.instance_id} onChange={e => updateFilter('instance_id', e.target.value)} placeholder="instance_id"/>
        <input value={filters.secret_name} onChange={e => updateFilter('secret_name', e.target.value)} placeholder="secret_name"/>
      </div>
      {page.state === 'loading' ? <p className="muted small">loading audit events...</p> : null}
      {page.state === 'error' ? <div className="error">{page.message}</div> : null}
      {page.state === 'ready' && page.items.length === 0 ? (
        <p className="muted small">no audit events</p>
      ) : null}
      {page.items.length > 0 ? (
        <div className="table-scroll">
          <table className="rows admin-kms-audit-table">
            <thead>
              <tr>
                <th>timestamp</th>
                <th>actor</th>
                <th>reason</th>
                <th>operation</th>
                <th>scope</th>
                <th>owner</th>
                <th>instance</th>
                <th>secret</th>
                <th>key</th>
                <th>result</th>
                <th>error</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((row, idx) => (
                <tr key={`${row.timestamp}-${idx}`}>
                  <td data-label="timestamp">{fmtTime(row.timestamp)}</td>
                  <td data-label="actor">{row.actor_kind}{row.actor_id ? ` / ${row.actor_id}` : ''}</td>
                  <td data-label="reason">{row.reason}</td>
                  <td data-label="operation">{row.operation}</td>
                  <td data-label="scope">{row.scope}</td>
                  <td data-label="owner">{row.owner_id || '—'}</td>
                  <td data-label="instance">{row.instance_id || '—'}</td>
                  <td data-label="secret">{row.secret_name || '—'}</td>
                  <td data-label="key">{row.key_id ? `${row.key_id} v${row.key_version ?? '?'}` : '—'}</td>
                  <td data-label="result">{row.result}</td>
                  <td data-label="error" className="kms-audit-error-cell">{row.error_class ? `${row.error_class}: ${row.error_message || ''}` : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <div className="modal-actions">
        <button className="btn btn-sm" type="button" disabled={offset === 0 || page.state === 'loading'} onClick={() => setOffset(Math.max(0, offset - limit))}>
          previous
        </button>
        <button className="btn btn-sm" type="button" disabled={page.next_offset == null || page.state === 'loading'} onClick={() => setOffset(page.next_offset)}>
          next
        </button>
      </div>
    </section>
  );
}

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
    <section className="panel admin-danger-panel">
      <div className="panel-header">
        <div className="panel-title">proxy token revocation</div>
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
