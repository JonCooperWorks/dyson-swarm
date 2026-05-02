/* swarm — Artefacts pages (cached artefacts surface).
 *
 * Two routes share one component:
 *
 *   #/artefacts                    → all my artefacts (cross-instance)
 *   #/i/<id>/artefacts             → per-instance
 *
 * Both render the same `<ArtefactsView>` shell — back link, title +
 * subtitle, and a paginated table.  The cross-instance variant adds
 * an "instance" column; the per-instance variant adds a single
 * "sweep" button in the panel header that prompts for a chat id and
 * walks the cube's listing into the cache.
 *
 * Bytes live on swarm under [backup].local_cache_dir/artefacts/.
 * Each row exposes:
 *   - "open"  — authenticated fetch + blob URL window.open
 *   - "share" — quick-mint a 7d anonymous share link
 *   - "drop"  — remove the swarm cache copy
 */

import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import { setSharesFor } from '../store/app.js';
import { SharesPanel } from './shares.jsx';

const QUICK_TTL = '7d';
const PAGE_SIZE = 25;
const MD_PLUGINS = [remarkGfm, remarkBreaks];
const MARKDOWNISH_RE = /(^|\n)\s{0,3}(#{1,6}\s+\S|[-*+]\s+\[[ xX]\]\s+\S|[-*+]\s+\S|\d+\.\s+\S|>\s+\S|```|---+\s*$|\|.+\|)|\[[^\]]+\]\([^)]+\)|`[^`\n]+`|\*\*[^*\n]+\*\*/;

export function MyArtefactsPage() {
  const { client } = useApi();
  const load = React.useCallback(
    () => client.listMyArtefacts({ limit: 1000 }),
    [client],
  );
  return (
    <ArtefactsView
      backHref="#/"
      subtitle="Everything your agents have produced and that has reached swarm.  Stored on swarm, so they survive cube reset.  Pick any to share via an anonymous link."
      load={load}
      showInstance
    />
  );
}

export function InstanceArtefactsPage({ instanceId }) {
  const { client } = useApi();
  const load = React.useCallback(
    () => client.listInstanceArtefacts(instanceId),
    [client, instanceId],
  );
  const sweep = React.useCallback(async () => {
    const chatId = prompt('chat id to sweep cube → cache:');
    if (!chatId || !chatId.trim()) return null;
    await client.sweepInstanceArtefacts(instanceId, chatId.trim());
    return null;
  }, [client, instanceId]);
  return (
    <ArtefactsView
      backHref={`#/i/${encodeURIComponent(instanceId)}`}
      subtitle="Cached artefacts for this instance, plus every anonymous link currently shared from them.  Reads come from swarm first; cube is only hit on cache miss."
      load={load}
      onSweep={sweep}
      instanceId={instanceId}
    />
  );
}

/// Shared shell.  `load` is the source of rows (refreshable); `onSweep`
/// is the optional cube→cache button shown only on the per-instance
/// variant.  Pagination is client-side over the loaded rows; the
/// underlying list endpoints already cap at 1000 (cross-instance) /
/// per-instance listings are short by construction.
function ArtefactsView({ backHref, subtitle, load, onSweep, showInstance, instanceId }) {
  const { client } = useApi();
  const shareRows = useAppState(s => (
    instanceId ? (s.shares.byInstance[instanceId]?.rows || null) : null
  ));
  const [rows, setRows] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [minted, setMinted] = React.useState(null);
  const [page, setPage] = React.useState(1);

  const refresh = React.useCallback(async () => {
    setErr(null);
    try {
      const list = await load();
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'list failed');
    }
  }, [load]);

  React.useEffect(() => { refresh(); }, [refresh]);
  // Reset to page 1 whenever the row set changes (refresh, sweep).
  React.useEffect(() => { setPage(1); }, [rows && rows.length]);

  const sweepClick = onSweep
    ? async () => {
        setBusy(true); setErr(null);
        try {
          await onSweep();
          await refresh();
        } catch (e) {
          setErr(e?.detail || e?.message || 'sweep failed');
        } finally {
          setBusy(false);
        }
      }
    : null;

  return (
    <main className="page page-edit page-artefacts">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">all artefacts</h1>
        <p className="page-sub muted">{subtitle}</p>
      </header>

      {err ? <div className="error">{err}</div> : null}
      {minted ? <MintedBanner minted={minted} onDismiss={() => setMinted(null)}/> : null}

      <ArtefactTable
        rows={rows}
        page={page}
        setPage={setPage}
        client={client}
        busy={busy}
        setBusy={setBusy}
        setErr={setErr}
        setMinted={setMinted}
        refresh={refresh}
        showInstance={showInstance}
        sweepClick={sweepClick}
        shareRows={shareRows}
      />
      {instanceId ? <SharesPanel instanceId={instanceId} artefactRows={rows || []}/> : null}
    </main>
  );
}

/// Build the deep-link URL for an artefact's reader page.  Both the
/// per-instance and cross-instance lists navigate to the same
/// canonical URL.
function artefactHref(instanceId, artefactId) {
  return `#/i/${encodeURIComponent(instanceId)}/artefacts/${encodeURIComponent(artefactId)}`;
}

function ArtefactTable({
  rows, page, setPage, client, busy, setBusy, setErr, setMinted, refresh,
  showInstance, sweepClick, shareRows,
}) {
  if (rows === null) return <p className="muted small">loading…</p>;

  const total = rows.length;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const safePage = Math.min(Math.max(1, page), pageCount);
  const start = (safePage - 1) * PAGE_SIZE;
  const visible = rows.slice(start, start + PAGE_SIZE);
  const activeShares = activeSharesByArtefact(shareRows);

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
      try {
        const shares = await client.listShares(row.instance_id);
        setSharesFor(row.instance_id, shares || []);
      } catch { /* shared-links panel refresh can recover */ }
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
          {sweepClick ? (
            <button
              className="btn btn-ghost btn-sm"
              onClick={sweepClick}
              disabled={busy}
              title="sweep a chat's artefacts from cube into the swarm cache"
            >{busy ? 'sweeping…' : 'sweep'}</button>
          ) : null}
          <button className="btn btn-ghost btn-sm" onClick={refresh} title="refresh">↻</button>
        </div>
      </div>
      {rows.length === 0 ? (
        <p className="muted small">
          no cached artefacts yet — sweep a chat into the swarm cache, or let
          them appear as artefacts are read through swarm.
        </p>
      ) : (
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
            {visible.map(r => (
              <tr
                key={`${r.instance_id}/${r.id}`}
                className={activeShares.get(r.id) ? 'artefact-row-shared' : undefined}
              >
                <td data-label="title">
                  <span title={r.id}>{r.title || r.id}</span>
                  {activeShares.get(r.id) ? (
                    <span
                      className="badge badge-info artefact-shared-badge"
                      title="active anonymous shared links"
                    >
                      shared {activeShares.get(r.id)}
                    </span>
                  ) : null}
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
                  <a
                    className="btn btn-ghost btn-sm"
                    href={artefactHref(r.instance_id, r.id)}
                    title="open the cached body in the reader"
                  >open</a>
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
      )}
      {pageCount > 1 ? (
        <Pagination
          page={safePage}
          pageCount={pageCount}
          total={total}
          start={start}
          shown={visible.length}
          onPage={setPage}
        />
      ) : null}
    </section>
  );
}

export function activeSharesByArtefact(rows) {
  const out = new Map();
  for (const row of rows || []) {
    if (!row || row.revoked_at || !row.active) continue;
    out.set(row.artefact_id, (out.get(row.artefact_id) || 0) + 1);
  }
  return out;
}

function Pagination({ page, pageCount, total, start, shown, onPage }) {
  return (
    <div
      className="panel-footer muted small"
      style={{ display: 'flex', gap: 8, alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px' }}
    >
      <span>
        showing {start + 1}–{start + shown} of {total}
      </span>
      <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <button
          className="btn btn-ghost btn-sm"
          onClick={() => onPage(page - 1)}
          disabled={page <= 1}
          title="previous page"
        >‹ prev</button>
        <span style={{ minWidth: 70, textAlign: 'center' }}>{page} / {pageCount}</span>
        <button
          className="btn btn-ghost btn-sm"
          onClick={() => onPage(page + 1)}
          disabled={page >= pageCount}
          title="next page"
        >next ›</button>
      </span>
    </div>
  );
}

/// Deep-linkable artefact reader page.  Mounted at
///   #/i/<instance>/artefacts/<id>
/// — both the per-instance and cross-instance listings link here on
/// "open".  The page hydrates row metadata from
/// `getInstanceArtefactMeta` (so a cold reload works) and fetches
/// bytes via `fetchInstanceArtefactBytes`.
///
/// Render branches mirror dyson's reader (views-secondary.jsx):
///   - image/* (or kind=='image') → <img> from a blob URL
///   - text/markdown (or .md/.markdown name / kind=='security_review')
///       → react-markdown w/ remark-gfm + remark-breaks
///   - text/* / json / xml → <pre> raw text
///   - everything else → download card
///
/// Header parity with dyson: title chip, kind badge, anonymous-share
/// dropdown (1d / 7d / 30d / never), copy-bytes / copy-url, download.
export function ArtefactPage({ instanceId, artefactId }) {
  const { client } = useApi();
  const [row, setRow] = React.useState(null);
  const [rowErr, setRowErr] = React.useState(null);
  const [state, setState] = React.useState({
    loading: true, err: null, mime: '', text: null, blob: null, blobUrl: null,
  });

  // Hydrate row metadata.  Cold deep-link load: caller may not have
  // a list cached, so fetch the single row directly.
  React.useEffect(() => {
    let cancelled = false;
    setRow(null); setRowErr(null);
    client.getInstanceArtefactMeta(instanceId, artefactId)
      .then(r => { if (!cancelled) setRow(r); })
      .catch(e => { if (!cancelled) setRowErr(e?.detail || e?.message || 'metadata fetch failed'); });
    return () => { cancelled = true; };
  }, [client, instanceId, artefactId]);

  // Hydrate body bytes once we know the row exists.  Re-runs on
  // navigation between artefacts even though the page stays mounted.
  React.useEffect(() => {
    let cancelled = false;
    let createdUrl = null;
    setState({ loading: true, err: null, mime: '', text: null, blob: null, blobUrl: null });
    (async () => {
      try {
        const { blob, mime, text } = await client.fetchInstanceArtefactBytes(
          instanceId, artefactId,
        );
        if (cancelled) return;
        const isImage = (mime || '').startsWith('image/')
          || (row && row.kind === 'image')
          || (row && (row.mime || '').startsWith('image/'));
        if (isImage) createdUrl = URL.createObjectURL(blob);
        setState({ loading: false, err: null, mime, text, blob, blobUrl: createdUrl });
      } catch (e) {
        if (cancelled) return;
        setState({ loading: false, err: String(e?.message || e), mime: '', text: null, blob: null, blobUrl: null });
      }
    })();
    return () => {
      cancelled = true;
      if (createdUrl) URL.revokeObjectURL(createdUrl);
    };
  }, [client, instanceId, artefactId, row && row.kind, row && row.mime]);

  const backHref = `#/i/${encodeURIComponent(instanceId)}/artefacts`;

  const download = () => {
    if (!state.blob) return;
    const url = state.blobUrl || URL.createObjectURL(state.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (row && row.title) || artefactId;
    document.body.appendChild(a); a.click(); a.remove();
    if (!state.blobUrl) setTimeout(() => URL.revokeObjectURL(url), 5000);
  };

  return (
    <main className="page page-edit page-artefact-reader">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">
          {row?.title || artefactId}
        </h1>
        <p className="page-sub muted">
          {row ? (
            <>
              {row.kind}
              {row.mime ? ` · ${row.mime}` : ''}
              {' · '}{fmtBytes(row.bytes)}
              {' · '}cached {fmtTime(row.cached_at)}
              {' · instance '}
              <a className="mono-sm" href={backHref}>{shortId(instanceId)}</a>
              {row.chat_id ? <> · chat <span className="mono-sm">{shortId(row.chat_id)}</span></> : null}
            </>
          ) : rowErr ? (
            <span className="error">{rowErr}</span>
          ) : 'loading…'}
        </p>
      </header>

      {row ? (
        <ArtefactActionsBar
          client={client}
          row={row}
          state={state}
          onDownload={download}
        />
      ) : null}

      <section className="panel artefact-body-panel">
        <div className="artefact-body-frame">
          <ArtefactBody row={row || { kind: '', mime: '', title: '' }} state={state} />
        </div>
      </section>
    </main>
  );
}

/// Header bar with copy / download / share actions.  Share UI mirrors
/// dyson's ShareMenu — dropdown picker for 1d / 7d / 30d / never,
/// minted URL surfaced in a banner with copy + dismiss.
function ArtefactActionsBar({ client, row, state, onDownload }) {
  const [shareBusy, setShareBusy] = React.useState(false);
  const [shareUrl, setShareUrl] = React.useState(null);
  const [shareErr, setShareErr] = React.useState(null);
  const [shareCopied, setShareCopied] = React.useState(false);
  const [shareExp, setShareExp] = React.useState(null);

  const mintShare = async (ttl) => {
    setShareBusy(true); setShareErr(null);
    try {
      const m = await client.mintShare(row.instance_id, row.id, {
        chat_id: row.chat_id,
        ttl,
        label: null,
      });
      setShareUrl(m.url || null);
      setShareExp(m.expires_at || null);
    } catch (e) {
      setShareErr(e?.detail || e?.message || 'share failed');
    } finally {
      setShareBusy(false);
    }
  };

  const copyUrl = async () => {
    if (!shareUrl) return;
    try {
      await navigator.clipboard.writeText(shareUrl);
      setShareCopied(true);
      setTimeout(() => setShareCopied(false), 1500);
    } catch { /* ignore */ }
  };

  const isImage = (state.mime || '').startsWith('image/') || row.kind === 'image';
  const isText = state.text != null && !isImage;

  const copyBody = async () => {
    if (!isText || state.text == null) return;
    try { await navigator.clipboard.writeText(state.text); } catch { /* ignore */ }
  };

  return (
    <>
      <section
        className="panel"
        style={{
          marginBottom: 12, display: 'flex', alignItems: 'center',
          gap: 8, padding: '8px 12px', flexWrap: 'wrap',
        }}
      >
        <ShareMenu busy={shareBusy} onMint={mintShare} />
        <button
          className="btn btn-ghost btn-sm"
          onClick={copyBody}
          disabled={!isText}
          title="copy body to clipboard"
        >copy</button>
        <button
          className="btn btn-sm"
          onClick={onDownload}
          disabled={!state.blob}
          title="download bytes"
        >download</button>
      </section>
      {(shareUrl || shareErr) ? (
        <div className="banner banner-info" style={{ marginBottom: 12 }}>
          {shareErr ? (
            <>
              <span className="error">share failed: {shareErr}</span>
              <div style={{ marginTop: 8 }}>
                <button className="btn btn-ghost btn-sm" onClick={() => setShareErr(null)}>dismiss</button>
              </div>
            </>
          ) : (
            <>
              <div>anonymous share URL — capability is in the URL, copy it now:</div>
              <code className="mono-sm" style={{ display: 'block', marginTop: 4, wordBreak: 'break-all' }}>
                {shareUrl}
              </code>
              <div className="muted small" style={{ marginTop: 6 }}>
                {shareExp ? <>expires {fmtTime(shareExp)}</> : null}
              </div>
              <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
                <button className="btn btn-sm btn-primary" onClick={copyUrl}>
                  {shareCopied ? 'copied' : 'copy link'}
                </button>
                <button className="btn btn-ghost btn-sm" onClick={() => setShareUrl(null)}>dismiss</button>
              </div>
            </>
          )}
        </div>
      ) : null}
    </>
  );
}

/// TTL picker for the share-mint affordance.  Mirrors dyson's
/// ShareMenu (views-secondary.jsx): 1d / 7d / 30d / never options,
/// outside-click closes, the picked value mints immediately and the
/// resulting URL appears in a banner under the bar.
function ShareMenu({ busy, onMint }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!open) return;
    const onDoc = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);
  const pick = (ttl) => { setOpen(false); onMint(ttl); };
  return (
    <span ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        className="btn btn-ghost btn-sm"
        onClick={() => setOpen(o => !o)}
        disabled={busy}
        title="anonymous shareable link"
      >
        {busy ? 'minting…' : 'share…'}
      </button>
      {open ? (
        <div role="menu" style={{
          position: 'absolute', left: 0, top: '100%', marginTop: 4,
          background: 'var(--panel, #1e1e1e)', border: '1px solid var(--line, #333)',
          borderRadius: 6, padding: 4, zIndex: 20, display: 'flex',
          flexDirection: 'column', minWidth: 110,
          boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
        }}>
          <button className="btn btn-ghost btn-sm" onClick={() => pick('1d')}>1 day</button>
          <button className="btn btn-ghost btn-sm" onClick={() => pick('7d')}>7 days</button>
          <button className="btn btn-ghost btn-sm" onClick={() => pick('30d')}>30 days</button>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => pick('never')}
            title="never expires (revoke manually from the shared links panel)"
          >never</button>
        </div>
      ) : null}
    </span>
  );
}

export function ArtefactBody({ row, state }) {
  if (state.loading) return <p className="muted small">loading…</p>;
  if (state.err) return <div className="error">{state.err}</div>;

  const mime = state.mime || row.mime || '';
  const baseMime = contentTypeBase(mime);
  const title = row.title || '';
  const isImage = baseMime.startsWith('image/') || row.kind === 'image';
  const isMarkdown = isMarkdownArtefact({
    kind: row.kind,
    mime,
    title,
    text: state.text,
  });
  const isPlainText = !isImage && !isMarkdown
    && (baseMime.startsWith('text/') || /json|xml/.test(baseMime))
    && state.text != null;

  if (isImage && state.blobUrl) {
    return (
      <img
        src={state.blobUrl}
        alt={title}
        style={{ maxWidth: '100%', display: 'block', margin: '0 auto' }}
      />
    );
  }
  if (isMarkdown && state.text != null) {
    return (
      <MarkdownBody markdown={state.text} />
    );
  }
  if (isPlainText) {
    return (
      <pre
        className="mono-sm"
        style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0 }}
      >{state.text}</pre>
    );
  }
  // Binary fallback — render a download card.  The header's "download"
  // button is the actionable surface; this is just the inline notice.
  return (
    <div className="muted small">
      Binary artefact ({mime || 'unknown type'}) — use download.
    </div>
  );
}

export function contentTypeBase(mime) {
  return String(mime || '').split(';', 1)[0].trim().toLowerCase();
}

export function isMarkdownArtefact({ kind, mime, title, text }) {
  const baseMime = contentTypeBase(mime);
  if (
    baseMime === 'text/markdown'
    || baseMime === 'text/x-markdown'
    || baseMime === 'application/markdown'
    || /\.(md|markdown)$/i.test(title || '')
  ) {
    return true;
  }
  if (kind === 'security_review' || kind === 'markdown' || kind === 'report') {
    return text != null;
  }
  if (text == null) return false;
  if (/json|xml|csv|toml|yaml|yml/.test(baseMime)) return false;
  if (!baseMime.startsWith('text/') && baseMime !== '') return false;
  return MARKDOWNISH_RE.test(String(text));
}

function MarkdownBody({ markdown }) {
  return (
    <div className="md-body">
      <ReactMarkdown
        remarkPlugins={MD_PLUGINS}
        components={{
          a: MarkdownLink,
        }}
      >
        {markdown}
      </ReactMarkdown>
    </div>
  );
}

function MarkdownLink({ node, href, children, ...props }) {
  const safeHref = safeMarkdownHref(href);
  if (!safeHref) return <>{children}</>;
  const external = /^(https?:|mailto:)/i.test(safeHref);
  return (
    <a
      {...props}
      href={safeHref}
      target={external ? '_blank' : undefined}
      rel={external ? 'noopener noreferrer' : undefined}
    >
      {children}
    </a>
  );
}

function safeMarkdownHref(href) {
  const value = String(href || '').trim();
  if (!value) return '';
  if (/^(https?:|mailto:)/i.test(value)) return value;
  if (/^(#|\/(?!\/)|\.\/|\.\.\/)/.test(value)) return value;
  return '';
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
        share minted — capability is in the URL, copy it now.  The shared
        links panel below can revoke, reissue, copy, and audit it anytime:
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
