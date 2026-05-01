/* swarm — Artefacts page (cached artefacts surface).
 *
 * Two routes:
 *
 *   #/artefacts                    → all my artefacts (cross-instance)
 *   #/i/<id>/artefacts             → per-instance, with a chat-scoped sweep
 *
 * Bytes live on swarm under [backup].local_cache_dir/artefacts/.  Rows
 * persist past cube reset, so this page is the durable record of what
 * an agent ever produced — even if its source instance is gone.  Each
 * row exposes:
 *
 *   - "open" — point at the swarm-served raw URL (cache-first, falls
 *     through to the cube on miss + write-throughs the bytes).
 *   - "share" — quick-mint a 7d anonymous share via the existing
 *     `/v1/instances/:id/artefacts/:art_id/shares` endpoint; the
 *     resulting URL is shown once and can be copied to clipboard.
 *
 * The per-instance variant adds a "sweep" affordance that walks the
 * cube's `/api/conversations/:chat/artefacts` listing and ingests
 * every row's metadata into the cache — bodies are not pulled here
 * (memory blast radius), open/share lazy-fills them.
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';

const QUICK_TTL = '7d';

export function MyArtefactsPage() {
  const { client } = useApi();
  const [rows, setRows] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [minted, setMinted] = React.useState(null);

  const refresh = React.useCallback(async () => {
    setErr(null);
    try {
      const list = await client.listMyArtefacts({ limit: 1000 });
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'list failed');
    }
  }, [client]);

  React.useEffect(() => { refresh(); }, [refresh]);

  return (
    <main className="page page-edit">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href="#/">← back</a>
        <h1 className="page-title">artefacts</h1>
        <p className="page-sub muted">
          Everything your agents have produced and that has reached swarm.  Stored on swarm,
          so they survive cube reset.  Pick any to share via an anonymous link.
        </p>
      </header>

      {err ? <div className="error">{err}</div> : null}
      {minted ? <MintedBanner minted={minted} onDismiss={() => setMinted(null)}/> : null}

      <ArtefactTable
        rows={rows}
        client={client}
        busy={busy}
        setBusy={setBusy}
        setErr={setErr}
        setMinted={setMinted}
        refresh={refresh}
        showInstance
      />
    </main>
  );
}

export function InstanceArtefactsPage({ instanceId }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [minted, setMinted] = React.useState(null);
  const [chatFilter, setChatFilter] = React.useState('');
  const [sweepChat, setSweepChat] = React.useState('');
  const backHref = `#/i/${encodeURIComponent(instanceId)}`;

  const refresh = React.useCallback(async () => {
    setErr(null);
    try {
      const list = await client.listInstanceArtefacts(instanceId, {
        chatId: chatFilter || undefined,
      });
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'list failed');
    }
  }, [client, instanceId, chatFilter]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const sweep = async () => {
    if (!sweepChat.trim()) {
      setErr('chat id required to sweep');
      return;
    }
    setBusy(true); setErr(null);
    try {
      await client.sweepInstanceArtefacts(instanceId, sweepChat.trim());
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'sweep failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="page page-edit">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">artefacts</h1>
        <p className="page-sub muted">
          Cached artefacts for this instance.  Reads come from swarm first; cube is only
          hit on cache miss.  Survives reset.
        </p>
      </header>

      {err ? <div className="error">{err}</div> : null}
      {minted ? <MintedBanner minted={minted} onDismiss={() => setMinted(null)}/> : null}

      <section className="panel">
        <div
          className="panel-header"
          style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}
        >
          <div className="panel-title" style={{ marginRight: 4 }}>filters</div>
          <input
            value={chatFilter}
            onChange={e => setChatFilter(e.target.value)}
            placeholder="filter chat id (blank = all)"
            style={{ flex: 1, minWidth: 160 }}
          />
          <input
            value={sweepChat}
            onChange={e => setSweepChat(e.target.value)}
            placeholder="sweep chat id (cube → cache)"
            style={{ flex: 1, minWidth: 160 }}
          />
          <button className="btn btn-sm" onClick={sweep} disabled={busy}>
            {busy ? 'sweeping…' : 'sweep'}
          </button>
        </div>
      </section>

      <ArtefactTable
        rows={rows}
        client={client}
        busy={busy}
        setBusy={setBusy}
        setErr={setErr}
        setMinted={setMinted}
        refresh={refresh}
      />
    </main>
  );
}

function ArtefactTable({ rows, client, busy, setBusy, setErr, setMinted, refresh, showInstance }) {
  if (rows === null) return <p className="muted small">loading…</p>;
  if (rows.length === 0) {
    return (
      <p className="muted small">
        no cached artefacts yet — they appear here as soon as one is read through swarm
        (e.g. via an existing share link or via <em>sweep</em> on a per-instance view).
      </p>
    );
  }

  const remove = async (row) => {
    if (!confirm(`Remove cached copy of "${row.title}"?  This drops the swarm row + on-disk body; the live cube still has it (until reset).`)) return;
    setBusy(true); setErr(null);
    try {
      await client.deleteInstanceArtefact(row.instance_id, row.id);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete failed');
    } finally {
      setBusy(false);
    }
  };

  const share = async (row) => {
    setBusy(true); setErr(null);
    try {
      const m = await client.mintShare(row.instance_id, row.id, {
        chat_id: row.chat_id,
        ttl: QUICK_TTL,
        label: null,
      });
      setMinted(m);
    } catch (e) {
      setErr(e?.detail || e?.message || 'share mint failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">artefacts</div>
        <div className="panel-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh} title="refresh">↻</button>
        </div>
      </div>
      <table className="rows">
        <thead><tr>
          <th>title</th>
          <th>kind</th>
          {showInstance ? <th>instance</th> : null}
          <th>chat</th>
          <th>size</th>
          <th>cached</th>
          <th></th>
        </tr></thead>
        <tbody>
          {rows.map(r => (
            <tr key={`${r.instance_id}/${r.id}`}>
              <td data-label="title">
                <span title={r.id}>{r.title || r.id}</span>
              </td>
              <td data-label="kind"><span className="badge badge-faint">{r.kind}</span></td>
              {showInstance ? (
                <td data-label="instance">
                  <a className="mono-sm" href={`#/i/${encodeURIComponent(r.instance_id)}/artefacts`}>
                    {shortId(r.instance_id)}
                  </a>
                </td>
              ) : null}
              <td data-label="chat" className="mono-sm muted">{shortId(r.chat_id)}</td>
              <td data-label="size" className="muted small">{fmtBytes(r.bytes)}</td>
              <td data-label="cached" className="muted small">{fmtTime(r.cached_at)}</td>
              <td className="row-actions">
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={async () => {
                    try {
                      await client.openInstanceArtefactRaw(r.instance_id, r.id);
                    } catch (e) {
                      setErr(e?.detail || e?.message || 'open failed');
                    }
                  }}
                  title="open the cached body in a new tab"
                >open</button>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => share(r)}
                  disabled={busy}
                  title={`mint a ${QUICK_TTL} anonymous share link`}
                >share</button>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => remove(r)}
                  disabled={busy}
                  title="remove the swarm cache copy"
                >drop</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function MintedBanner({ minted, onDismiss }) {
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
        share minted — capability is in the URL, copy it now (revoke from
        the per-instance shares panel anytime):
      </div>
      <code className="mono-sm" style={{ display: 'block', marginTop: 4, wordBreak: 'break-all' }}>
        {minted.url}
      </code>
      <div className="muted small" style={{ marginTop: 6 }}>
        expires {fmtTime(minted.expires_at)}.
      </div>
      <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
        <button className="btn btn-sm btn-primary" onClick={copy}>{copied ? 'copied' : 'copy link'}</button>
        <button className="btn btn-ghost btn-sm" onClick={onDismiss}>dismiss</button>
      </div>
    </div>
  );
}

function shortId(s) {
  if (!s) return '—';
  return s.length > 12 ? `${s.slice(0, 8)}…${s.slice(-3)}` : s;
}

function fmtBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0; let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

function fmtTime(secs) {
  if (!secs) return '—';
  try { return new Date(secs * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z'); }
  catch { return String(secs); }
}
