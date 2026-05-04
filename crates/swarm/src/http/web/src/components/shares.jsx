/* swarm — Shared artifact links.
 *
 * The lifecycle controls live in <SharesPanel> so the artifacts screen
 * can carry share status, copy, revoke, reissue, audit, rotate, and
 * manual minting without bouncing the operator to a second page.
 *
 * Legacy route:
 *   #/i/<id>/shares                                         -> SharesPage
 *
 * Capability lives in the URL itself (per-user-signed HMAC); the
 * server reconstructs it on demand for active rows so a copy-link
 * affordance can live alongside revoke + reissue.
 *
 * Deep-links from the dyson SPA's "share…" affordance — sandboxes
 * carry a same-origin `/_swarm/share-mint` escape route now, so the
 * primary mint flow doesn't need to bounce here.  The parser below is
 * kept so links that landed in someone's history still work.
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import { setSharesFor, removeShare } from '../store/app.js';
import { fmtTime } from '../utils/format.js';
import { EmptyState } from './ui.jsx';

export const TTL_OPTIONS = [
  { value: '1d', label: '1 day' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: 'never', label: 'never' },
];

export function shareAccessLogHref(instanceId, jti) {
  return `#/i/${encodeURIComponent(instanceId)}/shares/${encodeURIComponent(jti)}/log`;
}

export function artifactFilenameMap(artifactRows) {
  const out = new Map();
  for (const row of artifactRows || []) {
    if (!row?.id) continue;
    const title = typeof row.title === 'string' && row.title.trim()
      ? row.title.trim()
      : row.id;
    out.set(row.id, title);
  }
  return out;
}

export function shareFilename(row, namesByArtifactId) {
  if (!row) return '—';
  if (typeof row.artifact_title === 'string' && row.artifact_title.trim()) {
    return row.artifact_title.trim();
  }
  return namesByArtifactId?.get(row.artifact_id) || row.artifact_id || '—';
}

export function SharesPage({ instanceId }) {
  const backHref = `#/i/${encodeURIComponent(instanceId)}`;
  return (
    <main className="page page-edit page-artifacts">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">artifacts</h1>
        <p className="page-sub muted">
          Artifact sharing now lives with the artifacts list, so cached outputs
          and active public links can be managed in one pass.
        </p>
      </header>
      <SharesPanel instanceId={instanceId}/>
    </main>
  );
}

export function SharesPanel({ instanceId, artifactRows = [] }) {
  const { client } = useApi();
  const slot = useAppState(s => s.shares.byInstance[instanceId]);
  const rows = slot?.rows || null;
  const namesByArtifactId = React.useMemo(
    () => artifactFilenameMap(artifactRows),
    [artifactRows],
  );
  const [refreshing, setRefreshing] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [mintOpen, setMintOpen] = React.useState(false);
  const [minted, setMinted] = React.useState(null);

  // Hash-fragment params for deep-link mints from the dyson SPA's
  // legacy "share…" button: `#/i/<id>/shares?share_artifact=&share_chat=`.
  // The new dyson UI mints same-origin via `/_swarm/share-mint`, so
  // this is a fallback path — kept so links that landed in someone's
  // history still work.
  const [prefill, setPrefill] = React.useState({ artifact: '', chat: '' });
  React.useEffect(() => {
    const apply = () => {
      const h = window.location.hash || '';
      const q = h.split('?')[1] || '';
      const p = new URLSearchParams(q);
      const a = p.get('share_artifact');
      const c = p.get('share_chat');
      if (a && c) {
        setPrefill({ artifact: a, chat: c });
        setMintOpen(true);
        const base = h.split('?')[0];
        try { window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${base}`); } catch { /* ignore */ }
      }
    };
    apply();
    window.addEventListener('hashchange', apply);
    return () => window.removeEventListener('hashchange', apply);
  }, []);

  const refresh = React.useCallback(async () => {
    setRefreshing(true); setErr(null);
    try {
      const list = await client.listShares(instanceId);
      setSharesFor(instanceId, list || []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'list shares failed');
    } finally {
      setRefreshing(false);
    }
  }, [client, instanceId]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const revoke = async (jti) => {
    if (!confirm(`Revoke share ${jti.slice(0, 8)}…?  The URL stops working immediately.`)) return;
    setBusy(true); setErr(null);
    try {
      await client.revokeShare(jti);
      removeShare(instanceId, jti);
    } catch (e) {
      setErr(e?.detail || e?.message || 'revoke failed');
    } finally {
      setBusy(false);
    }
  };

  const reissue = async (jti, ttl) => {
    setBusy(true); setErr(null);
    try {
      const m = await client.reissueShare(jti, ttl);
      setMinted(m);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'reissue failed');
    } finally {
      setBusy(false);
    }
  };

  const rotateKey = async () => {
    if (!confirm(
      'Rotate your share signing key?  Every share you have ever issued will stop working.  Existing shares are revoked instantly; you can reissue any of them but the URLs will be different.',
    )) return;
    setBusy(true); setErr(null);
    try {
      await client.rotateShareSigningKey();
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'rotate failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {err ? <div className="error">{err}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">shared links</div>
            <div className="muted small">
              Copy, revoke, reissue, audit, or mint anonymous artifact links here.
            </div>
          </div>
          <div className="panel-actions">
            <button
              className="btn btn-ghost btn-sm"
              onClick={refresh}
              disabled={refreshing}
              title="refresh"
            >
              {refreshing ? '…' : '↻'}
            </button>
            <button
              className="btn btn-sm"
              onClick={() => { setMintOpen(true); setPrefill({ artifact: '', chat: '' }); }}
              disabled={busy}
              title="anonymous link to one artifact"
            >
              + new
            </button>
            <button
              className="btn btn-ghost btn-sm"
              onClick={rotateKey}
              disabled={busy}
              title="panic-button: invalidate every share you have ever issued"
            >
              rotate signing key
            </button>
          </div>
        </div>
        {rows === null ? (
          <p className="muted small">loading…</p>
        ) : rows.length === 0 ? (
          <p className="muted small">
            no shared links yet — click <em>+ new</em> to mint one, or use
            an artifact row's share action above.
          </p>
        ) : (
          <table className="rows">
            <thead><tr>
              <th>filename</th>
              <th>artifact</th>
              <th>label</th>
              <th>state</th>
              <th>created</th>
              <th>expires</th>
              <th></th>
            </tr></thead>
            <tbody>
              {rows.map(r => {
                const filename = shareFilename(r, namesByArtifactId);
                return (
                  <tr key={r.jti}>
                    <td data-label="filename">
                      <span className="share-file-name" title={r.artifact_id}>{filename}</span>
                    </td>
                    <td data-label="artifact"><code className="mono-sm">{r.artifact_id}</code></td>
                    <td data-label="label" className="muted small">{r.label || '—'}</td>
                    <td data-label="state">
                      {r.revoked_at
                        ? <span className="badge badge-faint">revoked</span>
                        : (r.active
                            ? <span className="badge badge-ok">active</span>
                            : <span className="badge badge-warn">expired</span>)}
                    </td>
                    <td data-label="created" className="muted small">{fmtTime(r.created_at)}</td>
                    <td data-label="expires" className="muted small">{fmtTime(r.expires_at)}</td>
                    <td className="row-actions">
                      {!r.revoked_at && r.active ? (
                        <CopyUrlButton jti={r.jti} client={client}/>
                      ) : null}
                      {!r.revoked_at && r.active ? (
                        <button className="btn btn-ghost btn-sm" onClick={() => revoke(r.jti)} disabled={busy}>
                          revoke
                        </button>
                      ) : null}
                      <ReissueButton jti={r.jti} onReissue={reissue} disabled={busy}/>
                      <AccessLogLink instanceId={instanceId} jti={r.jti}/>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>

      {mintOpen ? (
        <MintDialog
          instanceId={instanceId}
          prefill={prefill}
          onClose={() => setMintOpen(false)}
          onMinted={async (m) => { setMinted(m); setMintOpen(false); await refresh(); }}
        />
      ) : null}

      {minted ? (
        <MintedShareBanner
          minted={minted}
          onDismiss={() => setMinted(null)}
        />
      ) : null}
    </>
  );
}

export function ShareAccessLogPage({ instanceId, jti, embedded = false }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState(null);
  const [share, setShare] = React.useState(null);
  const [artifacts, setArtifacts] = React.useState([]);
  const [err, setErr] = React.useState(null);
  const backHref = `#/i/${encodeURIComponent(instanceId)}/artifacts`;

  React.useEffect(() => {
    let cancelled = false;
    setRows(null); setShare(null); setArtifacts([]); setErr(null);
    client.listShareAccesses(jti)
      .then(list => { if (!cancelled) setRows(Array.isArray(list) ? list : []); })
      .catch(e => { if (!cancelled) setErr(e?.detail || e?.message || 'list failed'); });
    client.listShares(instanceId)
      .then(list => {
        if (cancelled) return;
        const shareRows = Array.isArray(list) ? list : [];
        setSharesFor(instanceId, shareRows);
        setShare(shareRows.find(r => r.jti === jti) || null);
      })
      .catch(() => { /* access rows are the page's critical path */ });
    client.listInstanceArtifacts(instanceId)
      .then(list => { if (!cancelled) setArtifacts(Array.isArray(list) ? list : []); })
      .catch(() => { /* filename falls back to artifact id */ });
    return () => { cancelled = true; };
  }, [client, instanceId, jti]);

  const namesByArtifactId = React.useMemo(() => artifactFilenameMap(artifacts), [artifacts]);
  const filename = share ? shareFilename(share, namesByArtifactId) : `share ${jti.slice(0, 12)}…`;

  const Shell = embedded ? 'div' : 'main';
  return (
    <Shell className={embedded ? 'instance-subpage page-share-log' : 'page page-edit page-share-log'}>
      <header className={embedded ? 'subpage-header' : 'page-header'}>
        <a className="btn btn-ghost btn-sm" href={backHref}>← artifacts</a>
        <h1 className={embedded ? 'subpage-title' : 'page-title'}>access log</h1>
        <p className="page-sub muted">
          <span>{filename}</span>
          {share?.artifact_id ? <> · <code className="mono-sm">{share.artifact_id}</code></> : null}
        </p>
      </header>

      <section className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">log</div>
            <div className="muted small"><code className="mono-sm">{jti.slice(0, 12)}…</code></div>
          </div>
          <div className="panel-actions">
            <a className="btn btn-ghost btn-sm" href={backHref}>done</a>
          </div>
        </div>
        {err ? <div className="error">{err}</div> : null}
        {rows === null && !err ? <p className="muted small">loading…</p> : null}
        {rows && rows.length === 0 ? <ShareLogEmpty/> : null}
        {rows && rows.length > 0 ? <ShareAccessTable rows={rows}/> : null}
      </section>
    </Shell>
  );
}

function CopyUrlButton({ jti, client }) {
  const [busy, setBusy] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const onClick = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await client.getShareUrl(jti);
      const url = r && r.url;
      if (!url) throw new Error('no url returned');
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      setErr(e?.detail || e?.message || 'copy failed');
      setTimeout(() => setErr(null), 2500);
    } finally {
      setBusy(false);
    }
  };
  return (
    <button
      className="btn btn-ghost btn-sm"
      onClick={onClick}
      disabled={busy}
      title="copy the share URL to the clipboard"
    >
      {err ? err : copied ? 'copied' : busy ? '…' : 'copy url'}
    </button>
  );
}

function ReissueButton({ jti, onReissue, disabled }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);
  return (
    <span ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <button className="btn btn-ghost btn-sm" onClick={() => setOpen(!open)} disabled={disabled}>
        reissue
      </button>
      {open ? (
        <div className="dropdown" role="menu" style={{
          position: 'absolute', right: 0, top: '100%', marginTop: 4,
          background: 'var(--panel)', border: '1px solid var(--line)',
          borderRadius: 6, padding: 6, zIndex: 10, display: 'flex', gap: 4,
        }}>
          {TTL_OPTIONS.map(opt => (
            <button
              key={opt.value}
              className="btn btn-ghost btn-sm"
              onClick={() => { setOpen(false); onReissue(jti, opt.value); }}
            >{opt.label}</button>
          ))}
        </div>
      ) : null}
    </span>
  );
}

function AccessLogLink({ instanceId, jti }) {
  return (
    <a className="btn btn-ghost btn-sm" href={shareAccessLogHref(instanceId, jti)} title="recent accesses">
      log
    </a>
  );
}

function ShareLogEmpty() {
  return (
    <EmptyState glyph="0" title="No accesses yet">
      This shared link has not been opened.
    </EmptyState>
  );
}

function ShareAccessTable({ rows }) {
  return (
    <table className="rows">
      <thead><tr><th>when</th><th>status</th><th>IP</th><th>user-agent</th></tr></thead>
      <tbody>
        {rows.map(r => (
          <tr key={r.id}>
            <td data-label="when" className="muted small">{fmtTime(r.accessed_at)}</td>
            <td data-label="status">
              <span className={`badge ${r.status >= 200 && r.status < 300 ? 'badge-ok' : 'badge-warn'}`}>
                {r.status}
              </span>
            </td>
            <td data-label="IP" className="mono-sm">{r.remote_addr || '—'}</td>
            <td data-label="user-agent" className="mono-sm muted" style={{ maxWidth: 520, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.user_agent || ''}>
              {r.user_agent || '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function MintDialog({ instanceId, prefill, onClose, onMinted }) {
  const { client } = useApi();
  const [artifact, setArtifact] = React.useState(prefill.artifact || '');
  const [chat, setChat] = React.useState(prefill.chat || '');
  const [ttl, setTtl] = React.useState('7d');
  const [label, setLabel] = React.useState('');
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!artifact.trim() || !chat.trim()) {
      setErr('artifact id and chat id are both required');
      return;
    }
    setBusy(true); setErr(null);
    try {
      const m = await client.mintShare(instanceId, artifact.trim(), {
        chat_id: chat.trim(),
        ttl,
        label: label.trim() || null,
      });
      onMinted(m);
    } catch (e) {
      setErr(e?.detail || e?.message || 'mint failed');
      setBusy(false);
    }
  };

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} role="dialog" aria-label="mint share">
        <h3 style={{ marginTop: 0 }}>new share</h3>
        <form onSubmit={submit} className="form">
          <label className="field">
            <span>artifact id</span>
            <input value={artifact} onChange={e => setArtifact(e.target.value)} placeholder="a1234…" autoFocus={!prefill.artifact}/>
          </label>
          <label className="field">
            <span>chat id</span>
            <input value={chat} onChange={e => setChat(e.target.value)} placeholder="c1234…"/>
          </label>
          <label className="field">
            <span>ttl</span>
            <select value={ttl} onChange={e => setTtl(e.target.value)}>
              {TTL_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </label>
          <label className="field">
            <span>label (optional)</span>
            <input value={label} onChange={e => setLabel(e.target.value)} placeholder="for the partner team"/>
          </label>
          {err ? <div className="error">{err}</div> : null}
          <div className="modal-actions">
            <button type="button" className="btn btn-ghost" onClick={onClose} disabled={busy}>cancel</button>
            <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'minting…' : 'mint share'}</button>
          </div>
        </form>
      </div>
    </div>
  );
}

function MintedShareBanner({ minted, onDismiss }) {
  const [copied, setCopied] = React.useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(minted.url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* ignore */ }
  };
  return (
    <div className="banner banner-info">
      <div>
        share minted — copy it now, the URL is the capability and won't be re-shown
        outside the per-row <em>copy url</em> button:
      </div>
      <code className="mono-sm" style={{ display: 'block', marginTop: 4, wordBreak: 'break-all' }}>
        {minted.url}
      </code>
      <div className="muted small" style={{ marginTop: 6 }}>
        expires {fmtTime(minted.expires_at)} · revoke anytime from shared links.
      </div>
      <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
        <button className="btn btn-sm btn-primary" onClick={copy}>{copied ? 'copied' : 'copy link'}</button>
        <button className="btn btn-ghost btn-sm" onClick={onDismiss}>dismiss</button>
      </div>
    </div>
  );
}
