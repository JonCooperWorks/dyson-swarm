/* swarm — Shares panel for the InstanceDetail view.
 *
 * Mirrors the pattern of UsersPanel / ProxyTokensPanel in admin.jsx
 * and SnapshotsPanel in instances.jsx: <section className="panel">
 * with a panel-header + actions, a rows table, and a one-shot mint
 * dialog that surfaces the URL once.  Capability lives in the URL —
 * the server never sees it after the response so we never store or
 * round-trip it.
 *
 * Mint takes (artefact_id, chat_id, ttl, label).  artefact_id + chat_id
 * are pre-filled when the URL hash carries them — the dyson SPA's
 * "Share..." affordance opens this page with those IDs in the
 * fragment so the user lands on a one-click mint.
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';

const TTL_OPTIONS = [
  { value: '1d', label: '1 day' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
];

export function SharesPanel({ instanceId, disabled }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [mintOpen, setMintOpen] = React.useState(false);
  const [minted, setMinted] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  // Hash-fragment params for deep-link mint flows.  Format:
  // `#/i/<id>?share_artefact=<aid>&share_chat=<cid>` — the dyson SPA
  // opens this URL when a user clicks "Share..." on an artefact,
  // landing them on the instance with the mint dialog pre-filled.
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
        // Strip the params so a refresh doesn't re-open the dialog.
        const base = h.split('?')[0];
        try { window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${base}`); } catch { /* ignore */ }
      }
    };
    apply();
    window.addEventListener('hashchange', apply);
    return () => window.removeEventListener('hashchange', apply);
  }, []);

  const refresh = React.useCallback(async () => {
    setErr(null);
    try {
      const list = await client.listShares(instanceId);
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'list shares failed');
    }
  }, [client, instanceId]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const revoke = async (jti) => {
    if (!confirm(`Revoke share ${jti.slice(0, 8)}…?  The URL stops working immediately.`)) return;
    setBusy(true); setErr(null);
    try {
      await client.revokeShare(jti);
      await refresh();
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
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">shares</div>
        <div className="panel-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={busy}>refresh</button>
          <button
            className="btn btn-sm"
            onClick={() => { setMintOpen(true); setPrefill({ artefact: '', chat: '' }); }}
            disabled={busy || disabled}
            title="anonymous link to one artefact"
          >
            new share
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
      {err ? <div className="error">{err}</div> : null}
      {rows === null ? (
        <p className="muted small">loading…</p>
      ) : rows.length === 0 ? (
        <p className="muted small">no shares yet — mint one to share an artefact link.</p>
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
                    <button className="btn btn-ghost btn-sm" onClick={() => revoke(r.jti)} disabled={busy}>
                      revoke
                    </button>
                  ) : null}
                  <ReissueButton jti={r.jti} onReissue={reissue} disabled={busy}/>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

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
    </section>
  );
}

function ReissueButton({ jti, onReissue, disabled }) {
  const [open, setOpen] = React.useState(false);
  return (
    <span style={{ position: 'relative', display: 'inline-block' }}>
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
        share minted — copy it now, the URL is the capability and isn't shown again:
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
