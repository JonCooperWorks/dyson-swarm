/* swarm — Shares page (anonymous artefact links).
 *
 * Reachable from the instance detail header's `shared <badge>`
 * button:
 *
 *   #/i/<id>/shares                                         → SharesPage
 *
 * Mirrors the shape of TasksListPage (page-edit width, page-form
 * layout, single panel block, one row per share).  Capability lives
 * in the URL itself (per-user-signed HMAC); the server reconstructs
 * it on demand for active rows so a copy-link affordance can live
 * alongside revoke + reissue.
 *
 * Deep-links from the dyson SPA's "share…" affordance — sandboxes
 * carry a same-origin `/_swarm/share-mint` escape route now, so the
 * primary mint flow doesn't need to bounce here.  This page stays
 * the source of truth for an existing share's audit + lifecycle.
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import { setSharesFor, removeShare } from '../store/app.js';

const TTL_OPTIONS = [
  { value: '1d', label: '1 day' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: 'never', label: 'never (revoke manually)' },
];

export function SharesPage({ instanceId }) {
  const { client } = useApi();
  const slot = useAppState(s => s.shares.byInstance[instanceId]);
  const rows = slot?.rows || null;
  const [refreshing, setRefreshing] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [mintOpen, setMintOpen] = React.useState(false);
  const [minted, setMinted] = React.useState(null);
  const backHref = `#/i/${encodeURIComponent(instanceId)}`;

  // Hash-fragment params for deep-link mints from the dyson SPA's
  // legacy "share…" button: `#/i/<id>/shares?share_artefact=&share_chat=`.
  // The new dyson UI mints same-origin via `/_swarm/share-mint`, so
  // this is a fallback path — kept so links that landed in someone's
  // history still work.
  const [prefill, setPrefill] = React.useState({ artefact: '', chat: '' });
  React.useEffect(() => {
    const apply = () => {
      const h = window.location.hash || '';
      const q = h.split('?')[1] || '';
      const p = new URLSearchParams(q);
      const a = p.get('share_artefact');
      const c = p.get('share_chat');
      if (a && c) {
        setPrefill({ artefact: a, chat: c });
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

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') window.location.hash = backHref; };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [backHref]);

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
    <main className="page page-edit">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">shared</h1>
        <p className="page-sub muted">
          Anonymous links for individual artefacts.  Each URL is the capability:
          per-user HMAC signature in the URL, server-side revocation list, expiry
          enforced at fetch.  Rotate the signing key to invalidate every share at once.
        </p>
      </header>

      {err ? <div className="error">{err}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <div className="panel-title">shares</div>
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
              onClick={() => { setMintOpen(true); setPrefill({ artefact: '', chat: '' }); }}
              disabled={busy}
              title="anonymous link to one artefact"
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
            no shares yet — click <em>+ new</em> to mint a link, or use the <em>share…</em>
            button on an artefact inside the agent.
          </p>
        ) : (
          <table className="rows">
            <thead><tr>
              <th>jti</th>
              <th>artefact</th>
              <th>label</th>
              <th>state</th>
              <th>created</th>
              <th>expires</th>
              <th></th>
            </tr></thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.jti}>
                  <td><code className="mono-sm" title={r.jti}>{r.jti.slice(0, 12)}…</code></td>
                  <td><code className="mono-sm">{r.artefact_id}</code></td>
                  <td className="muted small">{r.label || '—'}</td>
                  <td>
                    {r.revoked_at
                      ? <span className="badge badge-faint">revoked</span>
                      : (r.active
                          ? <span className="badge badge-ok">active</span>
                          : <span className="badge badge-warn">expired</span>)}
                  </td>
                  <td className="muted small">{fmtTime(r.created_at)}</td>
                  <td className="muted small">{fmtTime(r.expires_at)}</td>
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
                    <AccessesButton jti={r.jti} client={client}/>
                  </td>
                </tr>
              ))}
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
    </main>
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

function AccessesButton({ jti, client }) {
  const [open, setOpen] = React.useState(false);
  const [rows, setRows] = React.useState(null);
  const [err, setErr] = React.useState(null);
  React.useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setRows(null); setErr(null);
    client.listShareAccesses(jti)
      .then(list => { if (!cancelled) setRows(Array.isArray(list) ? list : []); })
      .catch(e => { if (!cancelled) setErr(e?.detail || e?.message || 'list failed'); });
    return () => { cancelled = true; };
  }, [open, jti, client]);
  return (
    <>
      <button className="btn btn-ghost btn-sm" onClick={() => setOpen(true)} title="recent accesses">
        log
      </button>
      {open ? (
        <div className="modal-scrim" onClick={() => setOpen(false)}>
          <div className="modal" onClick={e => e.stopPropagation()} role="dialog" aria-label="share access log">
            <h3 style={{ marginTop: 0 }}>access log <code className="mono-sm muted">{jti.slice(0, 12)}…</code></h3>
            {err ? <div className="error">{err}</div> : null}
            {rows === null && !err ? <p className="muted small">loading…</p> : null}
            {rows && rows.length === 0 ? <p className="muted small">no accesses yet.</p> : null}
            {rows && rows.length > 0 ? (
              <table className="rows">
                <thead><tr><th>when</th><th>status</th><th>IP</th><th>user-agent</th></tr></thead>
                <tbody>
                  {rows.map(r => (
                    <tr key={r.id}>
                      <td className="muted small">{fmtTime(r.accessed_at)}</td>
                      <td>
                        <span className={`badge ${r.status >= 200 && r.status < 300 ? 'badge-ok' : 'badge-warn'}`}>
                          {r.status}
                        </span>
                      </td>
                      <td className="mono-sm">{r.remote_addr || '—'}</td>
                      <td className="mono-sm muted" style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.user_agent || ''}>
                        {r.user_agent || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
            <div className="modal-actions">
              <button className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>close</button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}

function MintDialog({ instanceId, prefill, onClose, onMinted }) {
  const { client } = useApi();
  const [artefact, setArtefact] = React.useState(prefill.artefact || '');
  const [chat, setChat] = React.useState(prefill.chat || '');
  const [ttl, setTtl] = React.useState('7d');
  const [label, setLabel] = React.useState('');
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!artefact.trim() || !chat.trim()) {
      setErr('artefact id and chat id are both required');
      return;
    }
    setBusy(true); setErr(null);
    try {
      const m = await client.mintShare(instanceId, artefact.trim(), {
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
            <span>artefact id</span>
            <input value={artefact} onChange={e => setArtefact(e.target.value)} placeholder="a1234…" autoFocus={!prefill.artefact}/>
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
        expires {fmtTime(minted.expires_at)} · revoke anytime from this panel.
      </div>
      <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
        <button className="btn btn-sm btn-primary" onClick={copy}>{copied ? 'copied' : 'copy link'}</button>
        <button className="btn btn-ghost btn-sm" onClick={onDismiss}>dismiss</button>
      </div>
    </div>
  );
}

function fmtTime(secs) {
  if (!secs) return '—';
  try { return new Date(secs * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z'); }
  catch { return String(secs); }
}
