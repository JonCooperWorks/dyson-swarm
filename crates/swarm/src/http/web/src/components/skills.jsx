import React from 'react';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import { setMarketplaceCatalog, setSkillsFor } from '../store/app.js';
import { fmtTime, shortId } from '../utils/format.js';
import { MarkdownBody } from './markdown.jsx';

const CATALOG_FRESH_MS = 30 * 1000;

export function SkillsPage() {
  const { client } = useApi();
  const { catalog, loading, err, refresh } = useMarketplaceCatalog();
  const [inventory, setInventory] = React.useState(null);
  const [inventoryErr, setInventoryErr] = React.useState('');
  const [query, setQuery] = React.useState('');
  const [source, setSource] = React.useState('');
  const [tag, setTag] = React.useState('');
  const [errorsOpen, setErrorsOpen] = React.useState(true);
  const searchRef = React.useRef(null);
  const cardRefs = React.useRef([]);
  const [focusedIdx, setFocusedIdx] = React.useState(0);

  React.useEffect(() => {
    let cancelled = false;
    client.listSkills().then(inv => {
      if (cancelled) return;
      setInventory(Array.isArray(inv) ? inv : []);
      setInventoryErr('');
    }).catch(e => {
      if (!cancelled) setInventoryErr(e?.detail || e?.message || 'skills load failed');
    });
    return () => { cancelled = true; };
  }, [client]);

  React.useEffect(() => {
    const onKey = (e) => {
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
      const tagName = String(document.activeElement?.tagName || '').toLowerCase();
      if (tagName === 'input' || tagName === 'textarea' || document.activeElement?.isContentEditable) return;
      e.preventDefault();
      searchRef.current?.focus();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const catalogSkills = catalog?.skills || [];
  const sources = catalog?.sources || [];
  const catalogErrors = catalog?.errors || [];
  const sourceOptions = React.useMemo(
    () => [...new Set(catalogSkills.map(s => s.marketplace_id).filter(Boolean))].sort(),
    [catalogSkills],
  );
  const tagOptions = React.useMemo(
    () => [...new Set(catalogSkills.flatMap(s => s.tags || []).filter(Boolean))].sort(),
    [catalogSkills],
  );
  const filtered = React.useMemo(() => filterCatalog(catalogSkills, { query, source, tag }), [
    catalogSkills,
    query,
    source,
    tag,
  ]);
  const grouped = groupInventory(inventory || []);

  const onCardKeyDown = (e) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const next = e.key === 'ArrowDown'
      ? Math.min(filtered.length - 1, focusedIdx + 1)
      : Math.max(0, focusedIdx - 1);
    setFocusedIdx(next);
    cardRefs.current[next]?.focus();
  };

  return (
    <main className="detail-pane" style={{overflowY:'auto'}}>
      <div style={{maxWidth:1180, width:'100%', margin:'0 auto', padding:'22px'}}>
        <header style={{display:'flex', alignItems:'end', gap:16, marginBottom:18}}>
          <div>
            <div className="eyebrow">skills</div>
            <h1 style={{margin:'4px 0 0', fontSize:28}}>Marketplace and fleet inventory</h1>
          </div>
          <span style={{flex:1}}/>
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => refresh(true)} disabled={loading}>
            refresh
          </button>
          <span className="badge badge-info">{catalogSkills.length} catalog</span>
          <span className="badge badge-info">{(inventory || []).length} installed</span>
        </header>

        {err ? <div className="error">{err}</div> : null}
        {catalogErrors.length > 0 && errorsOpen ? (
          <div className="banner banner-error" style={{display:'flex', alignItems:'start', gap:12}}>
            <div style={{flex:1}}>
              {catalogErrors.map(e => (
                <div key={`${e.marketplace_id}:${e.error}`}>
                  <strong>{e.marketplace_id}</strong>: {e.error}
                </div>
              ))}
            </div>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setErrorsOpen(false)}>
              dismiss
            </button>
          </div>
        ) : null}

        <section className="panel">
          <div className="panel-header">
            <div className="panel-title">marketplace catalog</div>
          </div>
          {sources.length === 0 && !loading ? (
            <div className="empty-state">
              <h2>No skill marketplaces yet</h2>
              <a className="btn btn-primary btn-sm" href="#/admin/skill-marketplaces/new">add marketplace</a>
            </div>
          ) : (
            <>
              <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(180px, 1fr))', gap:10, marginBottom:14}}>
                <label className="field" style={{margin:0}}>
                  <span>search</span>
                  <input
                    ref={searchRef}
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                    placeholder="name or description"
                  />
                </label>
                <label className="field" style={{margin:0}}>
                  <span>source</span>
                  <select value={source} onChange={e => setSource(e.target.value)}>
                    <option value="">all</option>
                    {sourceOptions.map(id => <option key={id} value={id}>{id}</option>)}
                  </select>
                </label>
                <label className="field" style={{margin:0}}>
                  <span>tag</span>
                  <select value={tag} onChange={e => setTag(e.target.value)}>
                    <option value="">all</option>
                    {tagOptions.map(value => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
              </div>
              {loading && !catalog ? (
                <p className="muted small">loading…</p>
              ) : filtered.length === 0 ? (
                <p className="muted small">no matching skills</p>
              ) : (
                <div style={{display:'grid', gap:8}} onKeyDown={onCardKeyDown}>
                  {filtered.map((skill, idx) => (
                    <SkillCatalogRow
                      key={`${skill.marketplace_id}/${skill.name}`}
                      skill={skill}
                      refNode={el => { cardRefs.current[idx] = el; }}
                      onFocus={() => setFocusedIdx(idx)}
                    />
                  ))}
                </div>
              )}
            </>
          )}
        </section>

        <section className="panel">
          <div className="panel-title">installed across swarm</div>
          {inventoryErr ? <div className="error">{inventoryErr}</div> : null}
          {grouped.length === 0 ? (
            <p className="muted small">no mirrored skills yet</p>
          ) : (
            <div style={{display:'grid', gap:8}}>
              {grouped.map(group => <SkillInventoryGroup key={group.skill} group={group}/>)}
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

export function MarketplaceSkillDetailPage({ view }) {
  const { client } = useApi();
  const marketplace = view?.marketplace || '';
  const skillName = view?.skill || '';
  const [detail, setDetail] = React.useState(null);
  const [body, setBody] = React.useState(null);
  const [err, setErr] = React.useState('');
  const [modalOpen, setModalOpen] = React.useState(false);

  React.useEffect(() => {
    let cancelled = false;
    setDetail(null);
    setBody(null);
    setErr('');
    Promise.all([
      client.getMarketplaceSkill(marketplace, skillName),
      client.getMarketplaceSkillContent(marketplace, skillName),
    ]).then(([nextDetail, nextBody]) => {
      if (cancelled) return;
      setDetail(nextDetail || null);
      setBody(nextBody || null);
    }).catch(e => {
      if (!cancelled) setErr(e?.detail || e?.message || 'skill load failed');
    });
    return () => { cancelled = true; };
  }, [client, marketplace, skillName]);

  const skill = detail?.skill || (body ? packageToCatalogSkill(body) : null);
  const computedSha = body?.computed_sha256 || detail?.computed_sha256 || '';

  return (
    <main className="detail-pane" style={{overflowY:'auto'}}>
      <div style={{maxWidth:1040, width:'100%', margin:'0 auto', padding:'22px'}}>
        <a className="chip" href="#/skills">skills</a>
        {err ? <div className="error" style={{marginTop:12}}>{err}</div> : null}
        {!skill && !err ? <p className="muted small">loading…</p> : null}
        {skill ? (
          <>
            <section className="panel">
              <div className="panel-header" style={{alignItems:'start'}}>
                <div style={{minWidth:0}}>
                  <div className="eyebrow">{skill.marketplace_name || skill.marketplace_id}</div>
                  <h1 style={{margin:'4px 0 0', fontSize:30}}>{skill.name}</h1>
                  <div className="muted" style={{marginTop:8}}>{skill.description}</div>
                </div>
                <button type="button" className="btn btn-primary" onClick={() => setModalOpen(true)}>
                  Install to instance
                </button>
              </div>
              <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(210px, 1fr))', gap:10, marginTop:16}}>
                <Meta label="version" value={skill.version}/>
                <Meta label="marketplace" value={skill.marketplace_id}/>
                <Meta label="license" value={skill.license || '—'}/>
                <Meta label="min dyson" value={skill.min_dyson_version || '—'}/>
                <Meta label="declared sha256" value={body?.declared_sha256 || skill.sha256 || '—'} mono/>
                <Meta label="computed sha256" value={computedSha || '—'} mono/>
                <Meta label="content type" value={skill.content_type || '—'}/>
                {skill.author ? <AuthorMeta author={skill.author}/> : null}
              </div>
              {(skill.tags || []).length > 0 ? (
                <div style={{display:'flex', flexWrap:'wrap', gap:6, marginTop:14}}>
                  {skill.tags.map(t => <span key={t} className="chip">{t}</span>)}
                </div>
              ) : null}
            </section>
            <section className="panel">
              <div className="panel-title">SKILL.md</div>
              <div style={{maxHeight:'62vh', overflow:'auto', marginTop:12}}>
                {body ? <MarkdownBody markdown={body.skill_md}/> : <p className="muted small">loading…</p>}
              </div>
            </section>
          </>
        ) : null}
      </div>
      {modalOpen ? (
        <InstallSkillModal
          skill={skill}
          onClose={() => setModalOpen(false)}
        />
      ) : null}
    </main>
  );
}

function Meta({ label, value, mono = false }) {
  return (
    <div className="mcp-row" style={{display:'block'}}>
      <div className="eyebrow">{label}</div>
      <div className={`${mono ? 'mono ' : ''}small`} style={{wordBreak:'break-word', marginTop:4}}>{value}</div>
    </div>
  );
}

function AuthorMeta({ author }) {
  return (
    <div className="mcp-row" style={{display:'block'}}>
      <div className="eyebrow">author</div>
      <a className="chip" href={skillAuthorHref(author)} style={{marginTop:4}}>
        learned by {author.name}
      </a>
    </div>
  );
}

export function InstallSkillModal({ skill, defaultInstanceId = null, onClose, onInstalled }) {
  const { client } = useApi();
  const { catalog, refresh } = useMarketplaceCatalog();
  const [instances, setInstances] = React.useState(null);
  const [instanceSkills, setInstanceSkills] = React.useState({});
  const [selectedInstanceIds, setSelectedInstanceIds] = React.useState(() => (
    defaultInstanceId ? new Set([defaultInstanceId]) : new Set()
  ));
  const [skillQuery, setSkillQuery] = React.useState('');
  const [selectedSkillKey, setSelectedSkillKey] = React.useState(
    skill ? skillKey(skill.marketplace_id, skill.name) : '',
  );
  const [allowUpdate, setAllowUpdate] = React.useState(false);
  const [busyById, setBusyById] = React.useState({});
  const [errorById, setErrorById] = React.useState({});
  const [resultById, setResultById] = React.useState({});
  const [err, setErr] = React.useState('');

  React.useEffect(() => {
    refresh(false);
  }, [refresh]);

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose?.(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  React.useEffect(() => {
    let cancelled = false;
    client.listInstances({ status: 'live' }).then(rows => {
      if (cancelled) return;
      const liveRows = (Array.isArray(rows) ? rows : []).filter(row => row.status === 'live');
      setInstances(liveRows);
      if (!defaultInstanceId && liveRows.length === 1) {
        setSelectedInstanceIds(new Set([liveRows[0].id]));
      }
      return Promise.all(liveRows.map(row => (
        client.listInstanceSkills(row.id)
          .then(skills => [row.id, Array.isArray(skills) ? skills : []])
          .catch(() => [row.id, []])
      )));
    }).then(entries => {
      if (cancelled || !entries) return;
      setInstanceSkills(Object.fromEntries(entries));
    }).catch(e => {
      if (!cancelled) setErr(e?.detail || e?.message || 'instances load failed');
    });
    return () => { cancelled = true; };
  }, [client, defaultInstanceId]);

  const catalogSkills = catalog?.skills || [];
  const selectedSkill = skill || catalogSkills.find(s => skillKey(s.marketplace_id, s.name) === selectedSkillKey) || null;
  const pickerSkills = React.useMemo(() => {
    const q = skillQuery.trim().toLowerCase();
    return catalogSkills.filter(s => {
      if (!q) return true;
      return [s.name, s.description, s.marketplace_id].some(v => String(v || '').toLowerCase().includes(q));
    });
  }, [catalogSkills, skillQuery]);
  const selectedRows = (instances || []).filter(row => selectedInstanceIds.has(row.id));
  const requiresUpdateConfirm = selectedRows.some(row => installedSkill(instanceSkills[row.id], selectedSkill));
  const canSubmit = selectedSkill && selectedRows.length > 0 && (!requiresUpdateConfirm || allowUpdate);

  const toggleInstance = (id) => {
    setSelectedInstanceIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const submit = async () => {
    if (!canSubmit) return;
    setErr('');
    for (const row of selectedRows) {
      const existing = installedSkill(instanceSkills[row.id], selectedSkill);
      setBusyById(prev => ({ ...prev, [row.id]: true }));
      setErrorById(prev => ({ ...prev, [row.id]: '' }));
      try {
        const outcome = await client.installSkillToInstance(row.id, {
          marketplace: selectedSkill.marketplace_id,
          skill: selectedSkill.name,
          force: !!existing && allowUpdate,
        });
        setResultById(prev => ({
          ...prev,
          [row.id]: `${existing ? 'updated' : 'installed'} v${outcome?.version || selectedSkill.version}`,
        }));
        const nextSkills = await client.listInstanceSkills(row.id).catch(() => null);
        if (Array.isArray(nextSkills)) {
          setSkillsFor(row.id, nextSkills);
          setInstanceSkills(prev => ({ ...prev, [row.id]: nextSkills }));
        }
        onInstalled?.({ instanceId: row.id, outcome });
      } catch (e) {
        const message = e?.status === 409
          ? `already installed${e?.detail?.current_version ? `: v${e.detail.current_version}` : ''}`
          : (e?.detail?.error || e?.detail || e?.message || 'install failed');
        setErrorById(prev => ({ ...prev, [row.id]: message }));
      } finally {
        setBusyById(prev => ({ ...prev, [row.id]: false }));
      }
    }
  };

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <header className="modal-header">Install to instance</header>
        <div className="modal-body">
          {err ? <div className="error">{err}</div> : null}
          {!skill ? (
            <div style={{display:'grid', gap:10, marginBottom:14}}>
              <label className="field">
                <span>skill</span>
                <input value={skillQuery} onChange={e => setSkillQuery(e.target.value)} autoFocus placeholder="name or marketplace"/>
              </label>
              <div style={{maxHeight:180, overflow:'auto', display:'grid', gap:6}}>
                {pickerSkills.map(s => (
                  <label key={skillKey(s.marketplace_id, s.name)} className="mcp-row" style={{cursor:'pointer'}}>
                    <input
                      type="radio"
                      checked={selectedSkillKey === skillKey(s.marketplace_id, s.name)}
                      onChange={() => setSelectedSkillKey(skillKey(s.marketplace_id, s.name))}
                    />
                    <span style={{minWidth:0}}>
                      <strong className="mono">{s.name}</strong>
                      <span className="badge" style={{marginLeft:8}}>{s.marketplace_id}</span>
                      <span className="muted small" style={{display:'block', marginTop:3}}>{s.description}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          ) : null}

          {selectedSkill ? (
            <div className="banner banner-info" style={{marginBottom:12}}>
              <strong className="mono">{selectedSkill.name}</strong>
              <span className="badge" style={{marginLeft:8}}>{selectedSkill.marketplace_id}</span>
              <span className="muted small" style={{marginLeft:8}}>v{selectedSkill.version}</span>
            </div>
          ) : null}

          {instances === null ? (
            <p className="muted small">loading…</p>
          ) : instances.length === 0 ? (
            <p className="muted small">no live instances</p>
          ) : (
            <div style={{display:'grid', gap:8, maxHeight:300, overflow:'auto'}}>
              {instances.map(row => {
                const existing = installedSkill(instanceSkills[row.id], selectedSkill);
                const busy = !!busyById[row.id];
                const result = resultById[row.id];
                const error = errorById[row.id];
                return (
                  <label key={row.id} className="mcp-row" style={{alignItems:'start', cursor:'pointer'}}>
                    <input
                      type="checkbox"
                      checked={selectedInstanceIds.has(row.id)}
                      onChange={() => toggleInstance(row.id)}
                      disabled={busy || !!defaultInstanceId}
                    />
                    <span style={{minWidth:0, flex:1}}>
                      <span style={{display:'flex', flexWrap:'wrap', gap:8, alignItems:'center'}}>
                        <strong>{row.name || row.id}</strong>
                        <span className="chip">{shortId(row.id)}</span>
                        {existing ? <span className="badge badge-warn">installed v{existing.version || 'unknown'}</span> : <span className="badge badge-ok">ready</span>}
                        {busy ? <span className="badge badge-info">installing…</span> : null}
                        {result ? <span className="badge badge-ok">{result}</span> : null}
                      </span>
                      {error ? <span className="error" style={{display:'block', marginTop:6}}>{error}</span> : null}
                    </span>
                  </label>
                );
              })}
            </div>
          )}

          {requiresUpdateConfirm ? (
            <label className="mcp-row" style={{marginTop:12, cursor:'pointer'}}>
              <input type="checkbox" checked={allowUpdate} onChange={e => setAllowUpdate(e.target.checked)}/>
              <span>Update already installed selections</span>
            </label>
          ) : null}
        </div>
        <div className="modal-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>close</button>
          <button type="button" className="btn btn-primary" onClick={submit} disabled={!canSubmit}>
            {requiresUpdateConfirm ? 'Update selected' : 'Install selected'}
          </button>
        </div>
      </div>
    </div>
  );
}

export function SkillCatalogRow({ skill, refNode, onFocus }) {
  const agentAuthored = String(skill.marketplace_id || '').startsWith('agent-') && skill.author;
  return (
    <a
      ref={refNode}
      className="mcp-row"
      href={skillHref(skill)}
      onFocus={onFocus}
      style={{alignItems:'start', textDecoration:'none', color:'inherit'}}
    >
      <div style={{minWidth:0, flex:1}}>
        <div style={{display:'flex', alignItems:'center', gap:8, flexWrap:'wrap'}}>
          <strong className="mono">{skill.name}</strong>
          <span className="badge">{skill.marketplace_id}</span>
          <span className="muted small">v{skill.version}</span>
          {agentAuthored ? (
            <span className="badge badge-info">learned by {skill.author.name}</span>
          ) : null}
        </div>
        <div className="muted small" style={{marginTop:4, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis'}}>
          {skill.description}
        </div>
        {(skill.tags || []).length > 0 ? (
          <div style={{display:'flex', gap:6, flexWrap:'wrap', marginTop:8}}>
            {skill.tags.slice(0, 5).map(t => <span key={t} className="chip">{t}</span>)}
          </div>
        ) : null}
      </div>
    </a>
  );
}

function skillHref(skill) {
  return `#/skills/${encodeURIComponent(skill.marketplace_id)}/${encodeURIComponent(skill.name)}`;
}

function skillAuthorHref(author) {
  if (author?.href) return author.href;
  if (author?.instance_id) return `#/i/${encodeURIComponent(author.instance_id)}/skills`;
  return '#/skills';
}

export function SkillInventoryGroup({ group }) {
  return (
    <div className="mcp-row" style={{alignItems:'start'}}>
      <div style={{minWidth:0, flex:1}}>
        <div style={{display:'flex', alignItems:'center', gap:8, flexWrap:'wrap'}}>
          <strong className="mono">{group.skill}</strong>
          <span className="badge badge-info">{group.rows.length} instance{group.rows.length === 1 ? '' : 's'}</span>
          {group.originKinds.map(kind => <span key={kind} className="badge">{kind}</span>)}
        </div>
        <div className="muted small" style={{marginTop:4}}>{group.description || '—'}</div>
        <div style={{display:'flex', flexWrap:'wrap', gap:6, marginTop:8}}>
          {group.rows.map(row => (
            <a
              key={`${row.instance_id}/${row.skill}`}
              className="chip"
              href={inventoryRowHref(row)}
              title={`last swept ${fmtTime(row.synced_at)}`}
            >
              {shortId(row.instance_id)}
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}

export function SkillInventoryList({ rows }) {
  if (!rows || rows.length === 0) {
    return <p className="muted small">no mirrored skills yet</p>;
  }
  return (
    <div style={{display:'grid', gap:8}}>
      {rows.map(row => (
        <a
          key={`${row.instance_id}/${row.skill}`}
          className="mcp-row"
          href={inventoryRowHref(row)}
          style={{alignItems:'start', textDecoration:'none', color:'inherit'}}
        >
          <div style={{minWidth:0, flex:1}}>
            <div style={{display:'flex', gap:8, flexWrap:'wrap', alignItems:'center'}}>
              <strong className="mono">{row.skill}</strong>
              <span className="badge">{row.origin_kind || 'unknown'}</span>
              {row.version ? <span className="muted small">v{row.version}</span> : null}
              {!row.has_metadata ? <span className="badge badge-warn">no metadata</span> : null}
              {!row.has_body ? <span className="badge badge-warn">missing body</span> : null}
            </div>
            <div className="muted small" style={{marginTop:4}}>{row.description || '—'}</div>
            <div className="mono muted small" style={{marginTop:6}}>
              swept {fmtTime(row.synced_at)} · {row.source_path}
            </div>
          </div>
        </a>
      ))}
    </div>
  );
}

function useMarketplaceCatalog() {
  const { client } = useApi();
  const cached = useAppState(s => s.skills.catalog);
  const [loading, setLoading] = React.useState(false);
  const [err, setErr] = React.useState('');

  const refresh = React.useCallback(async (force = false) => {
    const fresh = cached?.data && Date.now() - (cached.loadedAt || 0) < CATALOG_FRESH_MS;
    if (!force && fresh) return cached.data;
    setLoading(true);
    try {
      const next = await client.listMarketplaceSkills();
      const catalog = next || { skills: [], sources: [], errors: [] };
      setMarketplaceCatalog(catalog);
      setErr('');
      return catalog;
    } catch (e) {
      setErr(e?.detail || e?.message || 'catalog load failed');
      return cached?.data || null;
    } finally {
      setLoading(false);
    }
  }, [cached?.data, cached?.loadedAt, client]);

  React.useEffect(() => {
    refresh(false);
  }, [refresh]);

  return { catalog: cached?.data, loading, err, refresh };
}

function filterCatalog(skills, { query, source, tag }) {
  const q = query.trim().toLowerCase();
  return (skills || []).filter(skill => {
    if (source && skill.marketplace_id !== source) return false;
    if (tag && !(skill.tags || []).includes(tag)) return false;
    if (!q) return true;
    return [skill.name, skill.description, skill.marketplace_id, skill.marketplace_name]
      .some(value => String(value || '').toLowerCase().includes(q));
  });
}

function groupInventory(rows) {
  const map = new Map();
  for (const row of rows || []) {
    const key = row.skill || '';
    if (!key) continue;
    if (!map.has(key)) map.set(key, { skill: key, rows: [], originKinds: new Set(), description: '' });
    const group = map.get(key);
    group.rows.push(row);
    if (row.origin_kind) group.originKinds.add(row.origin_kind);
    if (!group.description && row.description) group.description = row.description;
  }
  return [...map.values()].map(group => ({
    ...group,
    originKinds: [...group.originKinds].sort(),
  })).sort((a, b) => a.skill.localeCompare(b.skill));
}

function packageToCatalogSkill(body) {
  return {
    marketplace_id: body.marketplace_id,
    marketplace_name: body.marketplace_name,
    name: body.name,
    version: body.version,
    description: body.description,
    tags: [],
    license: null,
    min_dyson_version: null,
    sha256: body.declared_sha256,
    content_type: 'markdown',
    author: null,
  };
}

function installedSkill(rows, skill) {
  if (!skill) return null;
  return (rows || []).find(row => row.skill === skill.name) || null;
}

function skillKey(marketplace, skill) {
  return `${marketplace}/${skill}`;
}

function inventoryRowHref(row) {
  if (row.marketplace_id) {
    return `#/skills/${encodeURIComponent(row.marketplace_id)}/${encodeURIComponent(row.skill)}`;
  }
  return `#/i/${encodeURIComponent(row.instance_id)}/skills`;
}
