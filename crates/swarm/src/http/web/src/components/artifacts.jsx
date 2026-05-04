/* swarm — Artifacts pages (cached artifacts surface).
 *
 * Two routes share one component:
 *
 *   #/artifacts                    → all my artifacts (cross-instance)
 *   #/i/<id>/artifacts             → per-instance
 *
 * Both render the same `<ArtifactsView>` shell — back link, title +
 * subtitle, and a paginated table.  The cross-instance variant adds
 * an "instance" column; the per-instance variant adds a single
 * "sweep" button in the panel header that prompts for a chat id and
 * walks the cube's listing into the cache.
 *
 * Bytes live on swarm under [backup].local_cache_dir/artifacts/.
 * Each row exposes:
 *   - "open"  — authenticated fetch + blob URL window.open
 *   - "share" — mint an anonymous share link with an expiry choice
 *   - "drop"  — remove the swarm cache copy
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import { setSharesFor } from '../store/app.js';
import { MarkdownBody } from './markdown.jsx';
import { SharesPanel, TTL_OPTIONS } from './shares.jsx';
import { EmptyState, Pager } from './ui.jsx';
import { fmtBytes, fmtTime, shortId } from '../utils/format.js';

const PAGE_SIZE = 25;
const MARKDOWNISH_RE = /(^|\n)\s{0,3}(#{1,6}\s+\S|[-*+]\s+\[[ xX]\]\s+\S|[-*+]\s+\S|\d+\.\s+\S|>\s+\S|```|---+\s*$|\|.+\|)|\[[^\]]+\]\([^)]+\)|`[^`\n]+`|\*\*[^*\n]+\*\*/;

export function MyArtifactsPage() {
  const { client } = useApi();
  const loadPage = React.useCallback(
    ({ limit, offset }) => client.listMyArtifactsPage({ limit, offset }),
    [client],
  );
  return (
    <ArtifactsView
      backHref="#/"
      subtitle="Everything your agents have produced and that has reached swarm.  Stored on swarm, so they survive cube reset.  Pick any to share via an anonymous link."
      loadPage={loadPage}
      showInstance
    />
  );
}

export function InstanceArtifactsPage({ instanceId, embedded = false }) {
  const { client } = useApi();
  const loadPage = React.useCallback(
    ({ limit, offset }) => client.listInstanceArtifactsPage(instanceId, { limit, offset }),
    [client, instanceId],
  );
  const sweep = React.useCallback(async () => {
    const chatId = prompt('chat id to sweep cube → cache:');
    if (!chatId || !chatId.trim()) return null;
    await client.sweepInstanceArtifacts(instanceId, chatId.trim());
    return null;
  }, [client, instanceId]);
  return (
    <ArtifactsView
      backHref={`#/i/${encodeURIComponent(instanceId)}`}
      subtitle="Cached artifacts for this instance, plus every anonymous link currently shared from them.  Reads come from swarm first; cube is only hit on cache miss."
      loadPage={loadPage}
      onSweep={sweep}
      instanceId={instanceId}
      embedded={embedded}
    />
  );
}

/// Shared shell.  `loadPage` is the source of rows (refreshable); `onSweep`
/// is the optional cube→cache button shown only on the per-instance
/// variant.  Pagination is server-side with a one-row lookahead so
/// large caches do not land in the browser all at once.
function ArtifactsView({ backHref, subtitle, loadPage, onSweep, showInstance, instanceId, embedded = false }) {
  const { client } = useApi();
  const shareRows = useAppState(s => (
    instanceId ? (s.shares.byInstance[instanceId]?.rows || null) : null
  ));
  const [rows, setRows] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [minted, setMinted] = React.useState(null);
  const [page, setPage] = React.useState(1);

  const fetchPage = React.useCallback(async (targetPage) => {
    setErr(null);
    setRows(null);
    try {
      let nextPage = Math.max(1, targetPage || 1);
      let list = [];
      for (;;) {
        const offset = (nextPage - 1) * PAGE_SIZE;
        const pageResult = await loadPage({ limit: PAGE_SIZE + 1, offset });
        list = Array.isArray(pageResult?.rows) ? pageResult.rows : [];
        if (list.length > 0 || nextPage === 1) break;
        nextPage -= 1;
      }
      setRows(list);
      setPage(nextPage);
    } catch (e) {
      setErr(e?.detail || e?.message || 'list failed');
      setRows([]);
    }
  }, [loadPage]);

  React.useEffect(() => { fetchPage(1); }, [fetchPage]);

  const sweepClick = onSweep
    ? async () => {
        setBusy(true); setErr(null);
        try {
          await onSweep();
          await fetchPage(1);
        } catch (e) {
          setErr(e?.detail || e?.message || 'sweep failed');
        } finally {
          setBusy(false);
        }
      }
    : null;

  const Shell = embedded ? 'div' : 'main';
  return (
    <Shell className={embedded ? 'instance-subpage instance-subpage-artifacts' : 'page page-edit page-artifacts'}>
      <header className={embedded ? 'subpage-header' : 'page-header'}>
        {embedded ? null : <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>}
        <h1 className={embedded ? 'subpage-title' : 'page-title'}>artifacts</h1>
        <p className="page-sub muted">{subtitle}</p>
      </header>

      {err ? <div className="error">{err}</div> : null}
      {minted ? <MintedBanner minted={minted} onDismiss={() => setMinted(null)}/> : null}

      <ArtifactTable
        rows={rows}
        page={page}
        client={client}
        busy={busy}
        setBusy={setBusy}
        setErr={setErr}
        setMinted={setMinted}
        refresh={() => fetchPage(page)}
        showInstance={showInstance}
        sweepClick={sweepClick}
        shareRows={shareRows}
        onPage={fetchPage}
      />
      {instanceId ? <SharesPanel instanceId={instanceId} artifactRows={rows || []}/> : null}
    </Shell>
  );
}

/// Build the deep-link URL for an artifact's reader page.  Both the
/// per-instance and cross-instance lists navigate to the same
/// canonical URL.
function artifactHref(instanceId, artifactId) {
  return `#/i/${encodeURIComponent(instanceId)}/artifacts/${encodeURIComponent(artifactId)}`;
}

export function ArtifactTable({
  rows, page, client, busy, setBusy, setErr, setMinted, refresh,
  showInstance, sweepClick, shareRows, onPage = () => {},
}) {
  if (rows === null) return <p className="muted small">loading…</p>;

  const safePage = Math.max(1, page);
  const start = (safePage - 1) * PAGE_SIZE;
  const visible = rows.slice(0, PAGE_SIZE);
  const canNext = rows.length > PAGE_SIZE;
  const canPrev = safePage > 1;
  const activeShares = activeSharesByArtifact(shareRows);

  const remove = async (row) => {
    if (!confirm(`Remove cached copy of "${row.title}"?  This drops the swarm row + on-disk body; the live cube still has it (until reset).`)) return;
    setBusy(true); setErr(null);
    try {
      await client.deleteInstanceArtifact(row.instance_id, row.id);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete failed');
    } finally {
      setBusy(false);
    }
  };

  const share = async (row, ttl) => {
    setBusy(true); setErr(null);
    try {
      const m = await client.mintShare(row.instance_id, row.id, {
        chat_id: row.chat_id,
        ttl,
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
        <div className="panel-title">artifacts</div>
        <div className="panel-actions">
          {sweepClick ? (
            <button
              className="btn btn-ghost btn-sm"
              onClick={sweepClick}
              disabled={busy}
              title="sweep a chat's artifacts from cube into the swarm cache"
            >{busy ? 'sweeping…' : 'sweep'}</button>
          ) : null}
          <button className="btn btn-ghost btn-sm" onClick={refresh} title="refresh">↻</button>
        </div>
      </div>
      {rows.length === 0 ? (
        <EmptyState title="no cached artifacts yet">
          Sweep a chat into the swarm cache, or let artifacts appear as they
          are read through swarm.
        </EmptyState>
      ) : (
        <table className="rows artifact-rows">
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
                key={`${r.instance_id}/${r.chat_id}/${r.id}`}
                className={activeShares.has(artifactShareKey(r)) ? 'artifact-row-shared' : undefined}
              >
                <td data-label="title">
                  <span title={r.id}>{r.title || r.id}</span>
                  {activeShares.has(artifactShareKey(r)) ? (
                    <span
                      className="badge badge-info artifact-shared-badge"
                      title="active anonymous shared links"
                    >
                      shared {activeShares.get(artifactShareKey(r))}
                    </span>
                  ) : null}
                </td>
                <td data-label="kind"><span className="badge badge-faint">{r.kind}</span></td>
                {showInstance ? (
                  <td data-label="instance">
                    <a className="mono-sm" href={`#/i/${encodeURIComponent(r.instance_id)}/artifacts`}>
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
                    href={artifactHref(r.instance_id, r.id)}
                    title="open the cached body in the reader"
                  >open</a>
                  <ShareMenu
                    busy={busy}
                    onMint={(ttl) => share(r, ttl)}
                  />
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
      {(canPrev || canNext) ? (
        <Pager
          label={`page ${safePage} · showing ${start + 1}–${start + visible.length}`}
          canPrev={canPrev}
          canNext={canNext}
          onPrev={() => onPage(safePage - 1)}
          onNext={() => onPage(safePage + 1)}
          disabled={busy}
        />
      ) : null}
    </section>
  );
}

export function activeSharesByArtifact(rows) {
  const out = new Map();
  for (const row of rows || []) {
    if (!row || row.revoked_at || !row.active) continue;
    const key = artifactShareKey(row);
    out.set(key, (out.get(key) || 0) + 1);
  }
  return out;
}

export function artifactShareKey(row) {
  return `${row?.instance_id || ''}\u0000${row?.chat_id || ''}\u0000${row?.id || row?.artifact_id || ''}`;
}

/// Deep-linkable artifact reader page.  Mounted at
///   #/i/<instance>/artifacts/<id>
/// — both the per-instance and cross-instance listings link here on
/// "open".  The page hydrates row metadata from
/// `getInstanceArtifactMeta` (so a cold reload works) and fetches
/// bytes via `fetchInstanceArtifactBytes`.
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
export function ArtifactPage({ instanceId, artifactId, embedded = false }) {
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
    client.getInstanceArtifactMeta(instanceId, artifactId)
      .then(r => { if (!cancelled) setRow(r); })
      .catch(e => { if (!cancelled) setRowErr(e?.detail || e?.message || 'metadata fetch failed'); });
    return () => { cancelled = true; };
  }, [client, instanceId, artifactId]);

  // Hydrate body bytes once we know the row exists.  Re-runs on
  // navigation between artifacts even though the page stays mounted.
  React.useEffect(() => {
    let cancelled = false;
    let createdUrl = null;
    setState({ loading: true, err: null, mime: '', text: null, blob: null, blobUrl: null });
    (async () => {
      try {
        const { blob, mime, text } = await client.fetchInstanceArtifactBytes(
          instanceId, artifactId,
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
  }, [client, instanceId, artifactId, row && row.kind, row && row.mime]);

  const backHref = `#/i/${encodeURIComponent(instanceId)}/artifacts`;

  const download = () => {
    if (!state.blob) return;
    const url = state.blobUrl || URL.createObjectURL(state.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (row && row.title) || artifactId;
    document.body.appendChild(a); a.click(); a.remove();
    if (!state.blobUrl) setTimeout(() => URL.revokeObjectURL(url), 5000);
  };

  const Shell = embedded ? 'div' : 'main';
  return (
    <Shell className={embedded ? 'instance-subpage instance-subpage-reader' : 'page page-edit page-artifact-reader'}>
      <header className={embedded ? 'subpage-header' : 'page-header'}>
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className={embedded ? 'subpage-title' : 'page-title'}>
          {row?.title || artifactId}
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
        <ArtifactActionsBar
          client={client}
          row={row}
          state={state}
          onDownload={download}
        />
      ) : null}

      <section className="panel artifact-body-panel">
        <div className="artifact-body-frame">
          <ArtifactBody row={row || { kind: '', mime: '', title: '' }} state={state} />
        </div>
      </section>
    </Shell>
  );
}

/// Header bar with copy / download / share actions.  Share UI mirrors
/// dyson's ShareMenu — dropdown picker for 1d / 7d / 30d / never,
/// minted URL surfaced in a banner with copy + dismiss.
export function ArtifactActionsBar({ client, row, state, onDownload }) {
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
      <section className="panel artifact-actions-bar">
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
    <span ref={ref} className="share-menu">
      <button
        type="button"
        className="btn btn-ghost btn-sm"
        onClick={() => setOpen(o => !o)}
        disabled={busy}
        title="anonymous shareable link"
      >
        {busy ? 'minting…' : 'share…'}
      </button>
      {open ? (
        <div className="share-menu-popover" role="menu">
          {TTL_OPTIONS.map(opt => (
            <button
              type="button"
              key={opt.value}
              className="btn btn-ghost btn-sm"
              onClick={() => pick(opt.value)}
              title={opt.value === 'never' ? 'no expiry' : undefined}
            >
              {opt.label}
            </button>
          ))}
        </div>
      ) : null}
    </span>
  );
}

export function ArtifactBody({ row, state }) {
  if (state.loading) return <p className="muted small">loading…</p>;
  if (state.err) return <div className="error">{state.err}</div>;

  const mime = state.mime || row.mime || '';
  const baseMime = contentTypeBase(mime);
  const title = row.title || '';
  const isImage = baseMime.startsWith('image/') || row.kind === 'image';
  const isMarkdown = isMarkdownArtifact({
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
      Binary artifact ({mime || 'unknown type'}) — use download.
    </div>
  );
}

export function contentTypeBase(mime) {
  return String(mime || '').split(';', 1)[0].trim().toLowerCase();
}

export function isMarkdownArtifact({ kind, mime, title, text }) {
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
