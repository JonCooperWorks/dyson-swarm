/* swarm — Instances view (list + detail + create modal).
 *
 * Two-pane layout: left rail lists every instance the caller owns,
 * the right pane shows whichever id the URL hash names.  Hash routing
 * keeps deep-links stable across IdP redirects (the OIDC return URL
 * is always `/`, so the hash is the only thing the IdP doesn't
 * mangle).
 */

import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import {
  upsertInstance, removeInstance, selectInstance, setLoadError, setInstances,
} from '../store/app.js';

// Links inside task markdown open in a new tab — the task pane is a
// scratchpad, not a navigation target, and following a link in-place
// would blow away the user's instance state.
const TASK_MARKDOWN_PLUGINS = [remarkGfm, remarkBreaks];
const TASK_MARKDOWN_COMPONENTS = {
  a: ({ node, ...props }) => (
    <a {...props} target="_blank" rel="noopener noreferrer"/>
  ),
};

export function InstancesView({ view }) {
  const selectedId = view.name === 'instance' ? view.id : null;
  React.useEffect(() => {
    selectInstance(selectedId);
  }, [selectedId]);

  // Mobile: rail is a slide-in drawer.  Desktop CSS pins it open and
  // ignores this state.  Auto-close whenever the URL hash advances —
  // tapping a row navigates and the drawer should get out of the way.
  const [sidebarOpen, setSidebarOpen] = React.useState(false);
  React.useEffect(() => {
    setSidebarOpen(false);
  }, [selectedId]);

  // "New" is a dedicated page (#/new) rather than a modal — gives the
  // configuration surface room to breathe (advanced options, future
  // network-policy picker, etc.).  Both the rail header and the empty
  // detail pane's hero CTA navigate there.
  const goNew = () => { window.location.hash = '#/new'; };

  return (
    <div className={`instances-pane ${sidebarOpen ? 'rail-open' : ''}`}>
      <InstanceList
        selectedId={selectedId}
        onNavigate={() => setSidebarOpen(false)}
        onNew={goNew}
      />
      <div
        className="rail-scrim"
        onClick={() => setSidebarOpen(false)}
        aria-hidden="true"
      />
      <InstanceDetail
        id={selectedId}
        onOpenSidebar={() => setSidebarOpen(true)}
        onNew={goNew}
      />
    </div>
  );
}

// ─── List ─────────────────────────────────────────────────────────

function InstanceList({ selectedId, onNavigate, onNew }) {
  const { client } = useApi();
  const { byId, order } = useAppState(s => s.instances);
  const [refreshing, setRefreshing] = React.useState(false);

  const refresh = React.useCallback(async () => {
    setRefreshing(true);
    try {
      const list = await client.listInstances();
      setInstances(Array.isArray(list) ? list : []);
    } catch (err) {
      setLoadError(err?.message || 'list failed');
    } finally {
      setRefreshing(false);
    }
  }, [client]);

  // Light polling so a TTL sweeper that destroys an instance under us
  // surfaces in the UI without a manual refresh.  30s is long enough
  // not to hammer the API but short enough to feel live.
  React.useEffect(() => {
    const id = setInterval(() => {
      if (!document.hidden) refresh();
    }, 30_000);
    return () => clearInterval(id);
  }, [refresh]);

  return (
    <aside className="left-rail">
      <div className="rail-header">
        <div className="rail-title">your instances</div>
        <div className="rail-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={refreshing} title="refresh">
            {refreshing ? '…' : '↻'}
          </button>
          <button className="btn btn-sm" onClick={onNew}>new</button>
        </div>
      </div>
      <ul className="rail-list">
        {order.length === 0 ? (
          <li className="rail-empty muted small">your roster's empty — hire one →</li>
        ) : order.map(id => {
          const row = byId[id];
          const label = row.name && row.name.trim() ? row.name : '(unnamed)';
          return (
            <li key={id} className={`rail-row ${selectedId === id ? 'selected' : ''}`}>
              <a href={`#/i/${encodeURIComponent(id)}`} onClick={() => onNavigate && onNavigate()}>
                <div className="rail-row-name">{label}</div>
                <div className="rail-row-id muted small">{shortId(id)}</div>
                <div className="rail-row-meta">
                  <StatusBadge status={row.status}/>
                  <span className="muted small">{row.template_id}</span>
                </div>
              </a>
            </li>
          );
        })}
      </ul>
    </aside>
  );
}

function StatusBadge({ status }) {
  const cls = status === 'live' ? 'ok'
            : status === 'creating' ? 'warn'
            : status === 'destroyed' ? 'faint'
            : 'warn';
  return <span className={`badge badge-${cls}`}>{status}</span>;
}

// Compact id presentation: shortened by default, click-to-copy.  The
// raw UUID is bulky and steals horizontal space on mobile; the chip
// keeps the affordance ("yes this row has an id") without dominating
// the layout, and a tap copies the full value to the clipboard.
function IdChip({ id }) {
  const [copied, setCopied] = React.useState(false);
  if (!id) return null;
  const onClick = async (e) => {
    e.preventDefault();
    try {
      await navigator.clipboard.writeText(id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1100);
    } catch { /* ignore */ }
  };
  return (
    <button
      type="button"
      className="id-chip"
      onClick={onClick}
      title={copied ? 'copied!' : `${id} — tap to copy`}
    >
      <code className="mono-sm">{shortId(id)}</code>
      <span className="id-chip-action muted small">{copied ? '✓' : 'copy'}</span>
    </button>
  );
}

// Memoised markdown render so non-task state changes (busy, error,
// timer ticks) don't pay the parse+render cost on every re-render.
// Mobile devices bear the brunt of this — remark-gfm + remark-breaks
// are surprisingly expensive on a 6-paragraph task.
const TaskProse = React.memo(function TaskProse({ markdown }) {
  return (
    <div className="task-prose">
      <ReactMarkdown
        remarkPlugins={TASK_MARKDOWN_PLUGINS}
        components={TASK_MARKDOWN_COMPONENTS}
      >
        {markdown}
      </ReactMarkdown>
    </div>
  );
});

// Format a `cube_profiles` entry for the dropdown — `name — Xg disk
// · Y vCPU · Zg RAM`.  Pure (no React, no DOM) so the unit test
// stays a one-liner.  Exported for that test only.
//
// `cpu_millicores` is rendered as vCPU (1000 mc = 1 vCPU); fractional
// vCPUs (e.g. 1500 mc = 1.5 vCPU) show with one decimal.  Memory is
// MB on the wire (cubemastercli's `--memory` is decimal MB, not
// binary MiB), so 2000 MB = 2 GB exactly — render in GB when the
// value is a whole multiple of 1000, otherwise raw MB.
export function profileLabel(p) {
  if (!p) return '';
  const vcpu = (p.cpu_millicores % 1000 === 0)
    ? `${p.cpu_millicores / 1000} vCPU`
    : `${(p.cpu_millicores / 1000).toFixed(1)} vCPU`;
  const ram = (p.memory_mb % 1000 === 0)
    ? `${p.memory_mb / 1000} GB RAM`
    : `${p.memory_mb} MB RAM`;
  return `${p.name} — ${p.disk_gb} GB disk · ${vcpu} · ${ram}`;
}

// ─── New instance — dedicated page ─────────────────────────────────
//
// Each Dyson is an employee.  The form reads top-down like an offer
// letter: who they are, what they do, then the infrastructure bits.
// Promoted from a modal to a dedicated page so there's room for the
// full configuration surface (template, ttl, and — coming next —
// per-instance network policy fed to the cube's BPF egress filter).

export function NewInstancePage() {
  // ESC navigates back to the list — same affordance the modal had,
  // preserved on the page so muscle memory still works.
  React.useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') window.location.hash = '#/';
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <main className="page page-new">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href="#/">← back</a>
        <h1 className="page-title">hire a new dyson</h1>
        <p className="page-sub muted">
          Each Dyson is a long-lived employee.  Fill in the offer letter,
          then click hire.
        </p>
      </header>
      <NewInstanceForm/>
    </main>
  );
}

function NewInstanceForm() {
  const { client, auth } = useApi();
  const [name, setName] = React.useState('');
  const [task, setTask] = React.useState('');
  // Model ids the agent can pick from.  One labelled suggestion
  // group ("default", from operator-curated `default_models` in
  // /etc/dyson-swarm/config.toml via /auth/config) plus free-form
  // text input for anything else (any OpenRouter id, comma- and
  // space-tolerant).  First selected model becomes SWARM_MODEL
  // (legacy single-pick env); the full list is passed as
  // SWARM_MODELS (csv) for agents that support failover/rotation.
  const defaultModels = auth?.config?.default_models || [];
  const [models, setModels] = React.useState(
    defaultModels.length ? [defaultModels[0]] : []
  );
  // Tiering profiles surfaced via /auth/config.  Empty array means the
  // operator hasn't configured profiles yet — the form falls back to
  // the legacy free-text template id input below.  Otherwise we render
  // a dropdown and the selected profile's template_id flows into the
  // create request.
  const cubeProfiles = auth?.config?.cube_profiles || [];
  // Operator-configured default from `default_template_id` in
  // /etc/dyson-swarm/config.toml, surfaced via /auth/config.  When
  // profiles are configured the first profile's template_id matches
  // (bring-up.sh keeps them in sync), so this seeds the dropdown to
  // the right initial selection.  When exactly one profile is
  // configured we still seed from it as a belt-and-braces fallback
  // for deployments where `default_template_id` was forgotten.  Fall
  // back to a placeholder string only when the deployment hasn't
  // configured one — submit is gated on `templateId.trim()` so the
  // user sees the field empty and is forced to fill it in.
  const [templateId, setTemplateId] = React.useState(
    auth?.config?.default_template_id
      || (cubeProfiles.length === 1 ? cubeProfiles[0].template_id : '')
  );
  const [ttlSeconds, setTtlSeconds] = React.useState('');
  // Network policy state.  Default Open matches the pre-feature
  // behaviour and the row-side default — operators don't have to
  // pick anything.  See src/network_policy.rs for the four profiles.
  const [networkPolicy, setNetworkPolicy] = React.useState({
    kind: 'open',
    entries: [],
  });
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  // Two-phase flow: 'form' (fill in) → 'provisioning' (POSTed; waiting
  // on the server, which now also pre-warms Caddy's on_demand TLS
  // before returning so the user's first "open ↗" click works).
  const [phase, setPhase] = React.useState('form');

  const submit = async (e) => {
    e.preventDefault();
    if (!templateId.trim() || models.length === 0) return;
    setSubmitting(true);
    setError(null);
    try {
      const req = {
        template_id: templateId.trim(),
        env: {
          // First-pick stays under the legacy single-model env so
          // Dyson agents that read SWARM_MODEL keep working.
          SWARM_MODEL: models[0],
          // Full ordered list — Dyson agents that support multiple
          // models (failover, A/B) split this on commas.
          SWARM_MODELS: models.join(','),
        },
      };
      if (name.trim()) req.name = name.trim();
      if (task.trim()) req.task = task.trim();
      const ttl = ttlSeconds.trim() ? Number(ttlSeconds) : null;
      if (Number.isFinite(ttl) && ttl > 0) req.ttl_seconds = ttl;
      // The wire shape mirrors the Rust serde-tagged enum:
      //   { kind: "open" } | { kind: "airgap" }
      //   | { kind: "allowlist", entries: [...] }
      //   | { kind: "denylist", entries: [...] }
      req.network_policy = serializeNetworkPolicy(networkPolicy);

      setPhase('provisioning');
      // Server blocks until the sandbox is Live AND Caddy's TLS cert
      // is provisioned (pre-warmed inside instance.create()), so by
      // the time this resolves the new dyson is fully reachable.
      const result = await client.createInstance(req);

      if (result?.id) {
        window.location.hash = `#/i/${encodeURIComponent(result.id)}`;
      } else {
        window.location.hash = '#/';
      }
      return;
    } catch (err) {
      setError(err?.detail || err?.message || 'create failed');
      setPhase('form');
    } finally {
      setSubmitting(false);
    }
  };

  if (phase === 'provisioning') {
    return (
      <section className="page-section">
        <p className="muted small">getting your dyson ready…</p>
        <div className="progress-bar"><div className="progress-bar-indeterminate"/></div>
        <p className="muted small" style={{ marginTop: 12 }}>
          By the time this redirects, your dyson is live and reachable.
        </p>
      </section>
    );
  }

  return (
    <form onSubmit={submit} className="form page-form">
      <section className="page-section">
        <h2 className="section-title">identity</h2>
        <label className="field">
          <span>name</span>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="PR reviewer for foo/bar"
            autoFocus
          />
        </label>
        <label className="field">
          <span>task</span>
          <textarea
            className="textarea"
            value={task}
            onChange={e => setTask(e.target.value)}
            placeholder={`What this employee does, in prose.\n\nExample: Watch for new PRs in github.com/foo/bar. Comment with style-guide violations and link to the relevant section. Don't approve or merge.`}
            rows={6}
          />
          <span className="hint muted small">
            The agent reads this on first boot as <code>SWARM_TASK</code>.
            You can edit it later, but changes don't propagate to a
            running employee.
          </span>
        </label>
      </section>

      <section className="page-section">
        <h2 className="section-title">model</h2>
        <ModelMultiPicker
          defaultModels={defaultModels}
          selected={models}
          onChange={setModels}
        />
      </section>

      <section className="page-section">
        <h2 className="section-title">network access</h2>
        <NetworkPolicyPicker value={networkPolicy} onChange={setNetworkPolicy}/>
      </section>

      <section className="page-section">
        <h2 className="section-title">infrastructure</h2>
        {cubeProfiles.length > 1 ? (
          <label className="field">
            <span>cube profile</span>
            <select
              value={templateId}
              onChange={e => setTemplateId(e.target.value)}
              required
            >
              {cubeProfiles.map(p => (
                <option key={p.template_id} value={p.template_id}>
                  {profileLabel(p)}
                </option>
              ))}
            </select>
            <span className="hint muted small">
              Cells in different profiles get different disk / CPU /
              RAM at boot — pick the size that fits the workload.
              Profiles are operator-curated in <code>config.env</code>.
            </span>
          </label>
        ) : cubeProfiles.length === 1 ? (
          // Single profile — picker would be a no-op dropdown.  Hide
          // it; the form's templateId state is already seeded from
          // that profile (see useState above).  Operators on a
          // single-tier deployment shouldn't see UX they can't
          // meaningfully interact with.
          null
        ) : (
          <label className="field">
            <span>template id</span>
            <input
              value={templateId}
              onChange={e => setTemplateId(e.target.value)}
              placeholder="dyson-default"
              required
            />
            <span className="hint muted small">
              The cube template the sandbox boots from.  Operators
              curate <code>default_template_id</code>; override here for
              staged rollouts.
            </span>
          </label>
        )}
        <label className="field">
          <span>ttl (seconds, optional)</span>
          <input
            value={ttlSeconds}
            onChange={e => setTtlSeconds(e.target.value)}
            placeholder="86400"
            inputMode="numeric"
          />
          <span className="hint muted small">
            Auto-destroyed by the TTL sweeper after this many seconds.
            Leave blank for a long-lived employee.
          </span>
        </label>
      </section>

      {error ? <div className="error">{error}</div> : null}
      <div className="page-actions">
        <button
          type="submit"
          className="btn btn-primary"
          disabled={submitting || models.length === 0 || !templateId.trim()}
          title={models.length === 0 ? 'pick at least one model' : ''}
        >
          {submitting ? 'hiring…' : 'hire'}
        </button>
        <a className="btn btn-ghost" href="#/">cancel</a>
      </div>
    </form>
  );
}

// ─── Network-policy picker ────────────────────────────────────────
//
// Four profiles (mirrors the Rust enum in src/network_policy.rs):
//   open       — full internet, default deny on RFC1918+linklocal.
//   airgap     — no egress except the swarm /llm proxy.
//   allowlist  — LLM proxy + the listed networks (CIDR or hostname).
//   denylist   — full internet minus the listed networks.
//
// Hostnames are DNS-resolved server-side at hire time; the cube
// enforces only IPv4 CIDRs.  Auto-collapse: if the user picks
// Allowlist and clears every chip, we flip the radio to Airgap (per
// the brief — empty Allowlist is functionally Airgap, and the Rust
// API rejects Allowlist with no entries anyway).

const POLICY_OPTIONS = [
  {
    kind: 'open',
    label: 'Open (full internet)',
    help: 'Everything the dyson asks for is allowed, except RFC1918 + link-local. The swarm default — pick this when the agent needs to research, fetch dependencies, or call external APIs.',
  },
  {
    kind: 'airgap',
    label: 'Air-gapped (LLM only)',
    help: 'No outbound traffic at all, except to the swarm /llm proxy. Use when the dyson should never touch the public internet.',
  },
  {
    kind: 'allowlist',
    label: 'Allowlist (only these networks)',
    help: 'LLM proxy plus the networks you list. Add CIDRs (8.8.8.8/32) or hostnames (github.com) — hostnames resolve at hire time.',
  },
  {
    kind: 'denylist',
    label: 'Denylist (block these networks)',
    help: 'Full internet minus the networks you list. Same accept rules as allowlist for entries.',
  },
];

function NetworkPolicyPicker({ value, onChange }) {
  const setKind = (kind) => {
    if (kind === 'open' || kind === 'airgap') {
      onChange({ kind, entries: [] });
    } else {
      onChange({ kind, entries: value.entries || [] });
    }
  };
  const setEntries = (entries) => {
    // Auto-collapse: empty allowlist → airgap (the brief asks for
    // this; the API rejects allowlist with no entries anyway).
    if (value.kind === 'allowlist' && entries.length === 0) {
      onChange({ kind: 'airgap', entries: [] });
      return;
    }
    onChange({ ...value, entries });
  };
  const showEntries = value.kind === 'allowlist' || value.kind === 'denylist';
  const helpFor = POLICY_OPTIONS.find(p => p.kind === value.kind)?.help;
  return (
    <div className="net-policy-picker">
      <div className="net-policy-radios">
        {POLICY_OPTIONS.map(opt => (
          <label key={opt.kind} className={`net-policy-radio ${value.kind === opt.kind ? 'selected' : ''}`}>
            <input
              type="radio"
              name="network_policy"
              value={opt.kind}
              checked={value.kind === opt.kind}
              onChange={() => setKind(opt.kind)}
            />
            <span className="net-policy-label">{opt.label}</span>
          </label>
        ))}
      </div>
      {helpFor ? <p className="hint muted small">{helpFor}</p> : null}
      {showEntries ? (
        <EntryChipInput
          entries={value.entries}
          onChange={setEntries}
          placeholder={value.kind === 'allowlist' ? 'github.com or 8.8.8.8/32' : 'evil.example or 1.2.3.0/24'}
        />
      ) : null}
      <p className="hint muted small">
        Network access can be changed any time from the instance's detail page —
        the change snapshots the dyson and re-hires it with the new policy
        (workspace state survives, but the URL changes).
      </p>
    </div>
  );
}

const ENTRY_CIDR_RE = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/;
const ENTRY_HOST_RE =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

function isValidEntry(s) {
  const v = (s || '').trim();
  if (!v) return false;
  if (ENTRY_CIDR_RE.test(v)) return true;
  // Match the server's "rejects all-digits-and-dots" rule.
  if (/^[0-9.]+$/.test(v)) return false;
  return ENTRY_HOST_RE.test(v);
}

function EntryChipInput({ entries, onChange, placeholder }) {
  const [input, setInput] = React.useState('');
  const [warn, setWarn] = React.useState(null);
  const add = (raw) => {
    const v = (raw || '').trim();
    if (!v) return;
    if (!isValidEntry(v)) {
      setWarn(`"${v}" doesn't look like a CIDR or hostname`);
      return;
    }
    if (entries.includes(v)) return;
    setWarn(null);
    onChange([...entries, v]);
  };
  const remove = (v) => onChange(entries.filter(e => e !== v));
  const onKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ',' || (e.key === ' ' && input.includes('.'))) {
      e.preventDefault();
      add(input);
      setInput('');
    } else if (e.key === 'Backspace' && !input && entries.length) {
      remove(entries[entries.length - 1]);
    }
  };
  return (
    <div className="field">
      <span>networks</span>
      <div className="chip-input">
        {entries.map(e => (
          <span key={e} className="chip">
            <code className="mono-sm">{e}</code>
            <button
              type="button"
              className="chip-x"
              aria-label={`remove ${e}`}
              onClick={() => remove(e)}
            >×</button>
          </span>
        ))}
        <input
          className="chip-input-text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder={entries.length === 0 ? placeholder : 'add another…'}
        />
      </div>
      {warn ? <span className="hint error small">{warn}</span> : null}
      <span className="hint muted small">
        CIDRs (a.b.c.d/N or a.b.c.d) pass through verbatim. Hostnames are
        resolved at hire time; the cube enforces the IPs we resolved now —
        DNS changes won't track.
      </span>
    </div>
  );
}

function serializeNetworkPolicy(p) {
  if (!p || p.kind === 'open') return { kind: 'open' };
  if (p.kind === 'airgap') return { kind: 'airgap' };
  // allowlist / denylist — include the user's raw entries; the server
  // resolves hostnames and persists both raw + resolved.
  return { kind: p.kind, entries: p.entries || [] };
}

// Multi-select with two labelled suggestion sources: the swarm's
// operator-curated `default_models` ("default") and the configured
// upstream provider's full catalogue ("openrouter") fetched via
// /v1/models — never directly from openrouter.ai.  Free-form text
// input accepts any other id with Enter, comma, or space (when the
// input contains "/"); selected models render as removable chips
// above the input, ordered (first = primary).
function ModelMultiPicker({ defaultModels, selected, onChange }) {
  const { client } = useApi();
  const [input, setInput] = React.useState('');
  const [upstreamModels, setUpstreamModels] = React.useState(null); // null=loading, [] on err
  const [upstreamError, setUpstreamError] = React.useState(null);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const body = await client.listProviderModels();
        const ids = Array.isArray(body?.models) ? body.models.filter(Boolean) : [];
        if (!cancelled) setUpstreamModels(ids);
      } catch (e) {
        if (!cancelled) {
          setUpstreamModels([]);
          setUpstreamError(
            e?.status === 503
              ? 'no upstream provider configured'
              : (e?.message || 'fetch failed'),
          );
        }
      }
    })();
    return () => { cancelled = true; };
  }, [client]);

  const add = (id) => {
    const v = id.trim();
    if (!v) return;
    if (selected.includes(v)) return;
    onChange([...selected, v]);
  };
  const remove = (id) => onChange(selected.filter(m => m !== id));
  const onKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ',' || (e.key === ' ' && input.includes('/'))) {
      e.preventDefault();
      add(input);
      setInput('');
    } else if (e.key === 'Backspace' && !input && selected.length) {
      remove(selected[selected.length - 1]);
    }
  };

  const filter = input.trim().toLowerCase();
  const matches = (id) =>
    !selected.includes(id) && (!filter || id.toLowerCase().includes(filter));
  const defaultMatches = defaultModels.filter(matches);
  const upstreamMatches = (upstreamModels || []).filter(matches).slice(0, 12);

  return (
    <div className="field">
      <span>models</span>
      <div className="chip-input">
        {selected.map((m, i) => (
          <span key={m} className={`chip ${i === 0 ? 'chip-primary' : ''}`}>
            <code className="mono-sm">{m}</code>
            <button
              type="button"
              className="chip-x"
              aria-label={`remove ${m}`}
              onClick={() => remove(m)}
            >×</button>
          </span>
        ))}
        <input
          className="chip-input-text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder={selected.length === 0 ? 'pick at least one model' : 'add another…'}
        />
      </div>
      <div className="model-suggestions">
        {defaultMatches.length > 0 ? (
          <div className="model-suggestion-group">
            <div className="model-suggestion-label">default</div>
            <div className="model-suggestion-chips">
              {defaultMatches.map(id => (
                <button
                  key={id}
                  type="button"
                  className="chip chip-add"
                  onClick={() => add(id)}
                >+ <code className="mono-sm">{id}</code></button>
              ))}
            </div>
          </div>
        ) : null}
        <div className="model-suggestion-group">
          <div className="model-suggestion-label">
            openrouter
            {upstreamModels === null ? <span className="muted small"> · loading…</span>
             : upstreamError ? <span className="muted small"> · {upstreamError}</span>
             : null}
          </div>
          <div className="model-suggestion-chips">
            {upstreamMatches.map(id => (
              <button
                key={id}
                type="button"
                className="chip chip-add"
                onClick={() => add(id)}
              >+ <code className="mono-sm">{id}</code></button>
            ))}
            {upstreamModels !== null && upstreamMatches.length === 0 && filter ? (
              <span className="muted small">no openrouter matches for "{filter}" — press Enter to add it as a custom id</span>
            ) : null}
          </div>
        </div>
      </div>
      <span className="hint muted small">
        First chip is the primary; agents that support multiple models
        try the rest in order.  Type any model id and press Enter to
        add a custom one.
      </span>
    </div>
  );
}

function ModalShell({ title, onClose, children }) {
  // ESC closes.  Click on the scrim closes; click on the panel doesn't.
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose && onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} role="dialog" aria-label={title}>
        <header className="modal-header">{title}</header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

function KvField({ label, value }) {
  const [copied, setCopied] = React.useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value || '');
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch { /* ignore */ }
  };
  return (
    <div className="kv">
      <div className="kv-label">{label}</div>
      <div className="kv-value">
        <code>{value}</code>
        <button className="btn btn-ghost btn-sm" onClick={copy}>
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
    </div>
  );
}

// ─── Detail ───────────────────────────────────────────────────────

function InstanceDetail({ id, onOpenSidebar, onNew }) {
  const { client } = useApi();
  const row = useAppState(s => (id ? s.instances.byId[id] : null));
  const totalInstances = useAppState(s => s.instances.order.length);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);

  // Pull fresh detail when selection changes (the list view's row is a
  // strict subset of the InstanceView shape, so re-fetching catches
  // probe times and other detail-only fields).
  React.useEffect(() => {
    if (!id) return;
    let cancelled = false;
    client.getInstance(id).then(detail => {
      if (!cancelled && detail) upsertInstance(detail);
    }).catch(e => {
      if (!cancelled) setErr(e?.message || 'fetch failed');
    });
    return () => { cancelled = true; };
  }, [client, id]);

  // Background TLS warm-up for `<id>.<hostname>` whenever the detail
  // page first appears for an instance.  Caddy fronts each Dyson with
  // on_demand TLS, so the very first request to a fresh subdomain
  // triggers a Let's Encrypt round-trip (~5–15s) — without warming
  // the user's first "open ↗" click races the ACME flow and shows
  // about:blank.
  //
  // Two complementary mechanisms:
  //   1. `<link rel="preconnect">` injected into <head> — a strong
  //      hint that tells modern browsers to do TCP + TLS handshake
  //      against the origin in the background, before any nav.
  //   2. A no-cors fetch — actually consummates the request even on
  //      browsers that ignore the preconnect hint.  no-cors means we
  //      don't read the body; the TLS handshake is the whole point.
  //
  // Both fire-and-forget; failures are expected (cold cert, network
  // blip) and never surfaced to the user.
  const openUrl = row?.open_url;
  React.useEffect(() => {
    if (!openUrl) return;
    let origin;
    try { origin = new URL(openUrl).origin; } catch { return; }

    const link = document.createElement('link');
    link.rel = 'preconnect';
    link.href = origin;
    link.crossOrigin = 'use-credentials';
    document.head.appendChild(link);

    // Defer the no-cors round-trip off the critical path.  On mobile
    // the TLS handshake against a cold subdomain can fight the actual
    // page render for the radio; we want first paint first, warm-up
    // second.  requestIdleCallback when available, otherwise a small
    // timeout so we still warm before the user's likely first tap.
    const ctrl = new AbortController();
    let t;
    const schedule = window.requestIdleCallback
      || ((cb) => setTimeout(cb, 600));
    const cancel = window.cancelIdleCallback || clearTimeout;
    const handle = schedule(() => {
      t = setTimeout(() => ctrl.abort(), 20_000);
      fetch(openUrl, { mode: 'no-cors', credentials: 'include', signal: ctrl.signal })
        .catch(() => { /* expected for cold cert / network blips */ })
        .finally(() => clearTimeout(t));
    }, { timeout: 4000 });

    return () => {
      cancel(handle);
      if (t) clearTimeout(t);
      ctrl.abort();
      link.remove();
    };
  }, [openUrl]);

  if (!id) return (
    <EmptyDetail
      onOpenSidebar={onOpenSidebar}
      onNew={onNew}
      hasInstances={totalInstances > 0}
    />
  );
  if (!row) return (
    <main className="detail-pane">
      <MobileRailToggle onOpenSidebar={onOpenSidebar}/>
      <p className="muted">loading…</p>
    </main>
  );

  const probe = async () => {
    setBusy(true); setErr(null);
    try {
      const result = await client.probeInstance(id);
      // probe returns { result: "healthy" | ... }; refetch row to pick
      // up the updated last_probe_at / last_probe_status the handler
      // wrote inline.
      const next = await client.getInstance(id);
      if (next) upsertInstance(next);
      return result;
    } catch (e) {
      setErr(e?.message || 'probe failed');
    } finally {
      setBusy(false);
    }
  };

  const destroy = async () => {
    if (!confirm(`destroy instance ${id}? this is permanent.`)) return;
    setBusy(true); setErr(null);
    try {
      await client.destroyInstance(id);
      removeInstance(id);
      window.location.hash = '#/';
    } catch (e) {
      setErr(e?.message || 'destroy failed');
      setBusy(false);
    }
  };

  const displayName = row.name && row.name.trim() ? row.name : '(unnamed)';
  // open_url is computed by the backend from `[server] hostname` + the
  // instance id.  Null when swarm has no hostname configured (the
  // host-based proxy is a no-op in that case) — that's the only case
  // we hard-disable the link, since there's literally nowhere to go.
  //
  // For status≠live or no sandbox yet we still ship the href: the user
  // explicitly wants a plain `target="_blank"` to navigate.  Without an
  // href the browser opens about:blank in the new tab, which is worse
  // than landing on a 502 / "still warming up" page they can refresh.
  const canOpen = !!row.open_url;
  const isWarmingUp = canOpen && (row.status !== 'live' || !row.cube_sandbox_id);

  return (
    <main className="detail-pane">
      <MobileRailToggle onOpenSidebar={onOpenSidebar}/>
      <header className="detail-header">
        <div className="employee-card">
          <h2 className="employee-name">{displayName}</h2>
          <div className="detail-meta">
            <StatusBadge status={row.status}/>
            <NetworkPolicyBadge instance={row}/>
            {row.pinned ? <span className="badge badge-info">pinned</span> : null}
            <IdChip id={row.id}/>
          </div>
          <div className="detail-template muted small">
            template <code className="mono-sm">{row.template_id}</code>
          </div>
          <div className="employee-task">
            {row.task && row.task.trim() ? (
              <TaskProse markdown={row.task}/>
            ) : (
              <p className="muted small">
                no task description — tap <em>edit</em> to write one.
              </p>
            )}
          </div>
        </div>
        <div className="detail-actions">
          <a
            className={`btn btn-primary ${canOpen ? '' : 'btn-disabled'}`}
            href={canOpen ? row.open_url : undefined}
            target="_blank"
            rel="noopener noreferrer"
            aria-disabled={!canOpen}
            onClick={(e) => { if (!canOpen) e.preventDefault(); }}
            title={
              !canOpen
                ? 'swarm hostname is not configured — set [server] hostname in config.toml'
                : isWarmingUp
                  ? 'sandbox is still warming up — opening anyway'
                  : 'open this dyson in a new tab'
            }
          >
            open ↗
          </a>
          <a
            className="btn btn-ghost"
            href={`#/i/${encodeURIComponent(id)}/edit`}
            aria-disabled={busy}
            onClick={(e) => { if (busy) e.preventDefault(); }}
          >
            edit
          </a>
          <button className="btn btn-ghost" onClick={probe} disabled={busy}>probe</button>
          <button className="btn btn-danger" onClick={destroy} disabled={busy || row.status === 'destroyed'}>
            destroy
          </button>
        </div>
      </header>

      <section className="panel">
        <div className="panel-title">runtime</div>
        <KvRow label="created" value={fmtTime(row.created_at)}/>
        <KvRow label="last active" value={fmtTime(row.last_active_at)}/>
        <KvRow label="last probe" value={
          row.last_probe_at
            ? `${fmtTime(row.last_probe_at)} · ${probeLabel(row.last_probe_status)}`
            : 'never'
        }/>
        {row.destroyed_at ? <KvRow label="destroyed" value={fmtTime(row.destroyed_at)}/> : null}
      </section>

      {err ? <div className="error">{err}</div> : null}

      <SnapshotsPanel instanceId={id} disabled={row.status === 'destroyed'}/>
      <NetworkPolicyPanel instance={row} disabled={row.status === 'destroyed'}/>
      <SecretsPanel instanceId={id}/>
    </main>
  );
}

// ─── Edit instance — dedicated page ───────────────────────────────
//
// Promoted from a modal to a dedicated page for parity with the
// hire flow (#/new) — gives the form room to grow (e.g. a future
// network-policy editor) and gets the user a direct-linkable URL
// for the edit screen.

export function EditInstancePage({ instanceId }) {
  const { client } = useApi();
  const row = useAppState(s => (instanceId ? s.instances.byId[instanceId] : null));
  const [err, setErr] = React.useState(null);
  const backHref = `#/i/${encodeURIComponent(instanceId || '')}`;

  // Hot-fetch the row in case the operator deep-linked into the edit
  // URL without going through the detail view first (refresh, paste
  // from chat, etc.).  Same pattern as InstanceDetail.
  React.useEffect(() => {
    if (!instanceId) return;
    let cancelled = false;
    client.getInstance(instanceId).then(detail => {
      if (!cancelled && detail) upsertInstance(detail);
    }).catch(e => {
      if (!cancelled) setErr(e?.message || 'fetch failed');
    });
    return () => { cancelled = true; };
  }, [client, instanceId]);

  // ESC navigates back to the detail view — same affordance the
  // modal had, preserved on the page so muscle memory still works.
  React.useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') window.location.hash = backHref;
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [backHref]);

  return (
    <main className="page page-edit">
      <header className="page-header">
        <a className="btn btn-ghost btn-sm" href={backHref}>← back</a>
        <h1 className="page-title">edit dyson</h1>
        <p className="page-sub muted">
          Change the dyson's name, mission, or model list.  Saving
          rewrites IDENTITY.md via /api/admin/configure — the agent
          picks it up on the next turn (no restart).
        </p>
      </header>
      {err ? <div className="error">{err}</div> : null}
      {row ? (
        <>
          <EditInstanceForm instance={row} backHref={backHref}/>
          {/* Network isolation lives on the same page so operators
              get one stop for editing.  Shown for live rows only —
              destroyed rows can't be re-policied (the cube is gone)
              and the panel's "change" button gates on the same
              `disabled` prop. */}
          <NetworkPolicyPanel instance={row} disabled={row.status === 'destroyed'}/>
        </>
      ) : (
        <div className="muted">loading…</div>
      )}
    </main>
  );
}

function EditInstanceForm({ instance, backHref }) {
  const { client, auth } = useApi();
  const [name, setName] = React.useState(instance.name || '');
  const [task, setTask] = React.useState(instance.task || '');
  // Models picker reuses the same component as the create form,
  // sourced from operator-curated `default_models` plus the live
  // /v1/models upstream catalogue.  Pre-fills with the current
  // primary model when available; the agent will also accept any
  // other model id the user types.
  const initialModels = (instance.models && instance.models.length)
    ? instance.models
    : (instance.model ? [instance.model] : []);
  const [models, setModels] = React.useState(initialModels);
  const defaultModels = auth?.config?.default_models || [];
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true); setError(null);
    try {
      const payload = { name, task };
      // Only include models if the user actually picked any —
      // backend treats missing/empty as "leave unchanged".
      if (models.length > 0) payload.models = models;
      const updated = await client.updateInstance(instance.id, payload);
      upsertInstance(updated);
      window.location.hash = backHref;
    } catch (err) {
      setError(err?.detail || err?.message || 'save failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={submit} className="form">
      <label className="field">
        <span>name</span>
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="PR reviewer for foo/bar"
          autoFocus
        />
      </label>
      <label className="field">
        <span>task</span>
        <textarea
          className="textarea"
          value={task}
          onChange={e => setTask(e.target.value)}
          rows={6}
        />
      </label>
      <ModelMultiPicker
        defaultModels={defaultModels}
        selected={models}
        onChange={setModels}
      />
      {error ? <div className="error">{error}</div> : null}
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? 'saving…' : 'save'}
        </button>
        <a className="btn btn-ghost" href={backHref}>cancel</a>
      </div>
    </form>
  );
}

function EmptyDetail({ onOpenSidebar, onNew, hasInstances }) {
  return (
    <main className="detail-pane detail-empty">
      <MobileRailToggle onOpenSidebar={onOpenSidebar}/>
      <div className="empty-hero">
        <DysonSphereGlyph/>
        {hasInstances ? (
          <>
            <h1 className="empty-title">pick a dyson</h1>
            <p className="empty-sub">
              your roster is on the left — pick one to inspect, edit, or
              fire it up. or hire a new employee for a new task.
            </p>
            <div className="empty-actions">
              <button className="btn btn-primary" onClick={onNew}>+ hire a dyson</button>
            </div>
          </>
        ) : (
          <>
            <h1 className="empty-title">build your swarm</h1>
            <p className="empty-sub">
              dysons are long-lived agents you put to work — one per task,
              each with its own brief, model, and memory. start with one
              employee; scale to hundreds.
            </p>
            <div className="empty-actions">
              <button className="btn btn-primary btn-lg" onClick={onNew}>
                hire your first dyson
              </button>
            </div>
            <p className="empty-hint muted small">
              you can always change a dyson's brief or model later — nothing
              you set now is final.
            </p>
          </>
        )}
      </div>
    </main>
  );
}

/* Dyson-sphere logomark.  Three concentric arc-rings on a dim radial
 * gradient — the brand cue without shipping an image asset.  Spins
 * very slowly (90s) so it has presence on a static page without
 * being distracting.  All CSS / SVG; no fonts, no network, no JS. */
function DysonSphereGlyph() {
  return (
    <div className="empty-sphere" aria-hidden="true">
      <svg viewBox="0 0 120 120" width="120" height="120">
        <defs>
          <radialGradient id="ds-core" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.95"/>
            <stop offset="55%" stopColor="var(--accent)" stopOpacity="0.25"/>
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0"/>
          </radialGradient>
        </defs>
        <circle cx="60" cy="60" r="56" fill="url(#ds-core)"/>
        <g className="empty-sphere-rings" stroke="var(--accent)" fill="none" strokeWidth="1.2">
          <ellipse cx="60" cy="60" rx="52" ry="20" opacity="0.9"/>
          <ellipse cx="60" cy="60" rx="52" ry="20" opacity="0.55" transform="rotate(60 60 60)"/>
          <ellipse cx="60" cy="60" rx="52" ry="20" opacity="0.55" transform="rotate(120 60 60)"/>
        </g>
        <circle cx="60" cy="60" r="6" fill="var(--accent)"/>
      </svg>
    </div>
  );
}

// Hamburger that's only visible on mobile (CSS-gated).  Lives at the
// top of the detail pane so the user can pop the rail open without
// hunting for it; desktop layouts ignore the button entirely.
function MobileRailToggle({ onOpenSidebar }) {
  return (
    <button
      type="button"
      className="rail-toggle"
      onClick={() => onOpenSidebar && onOpenSidebar()}
      aria-label="show instances list"
    >
      ☰ roster
    </button>
  );
}

function KvRow({ label, value }) {
  return (
    <div className="kvrow">
      <div className="kvrow-label">{label}</div>
      <div className="kvrow-value" title={typeof value === 'string' ? value : undefined}>
        <code>{value}</code>
      </div>
    </div>
  );
}

// ─── Snapshots panel ─────────────────────────────────────────────

function SnapshotsPanel({ instanceId, disabled }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);

  const refresh = React.useCallback(async () => {
    try {
      const list = await client.listSnapshotsForInstance(instanceId);
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.message || 'list snapshots failed');
    }
  }, [client, instanceId]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const take = async (mode) => {
    setBusy(true); setErr(null);
    try {
      const fn = mode === 'backup' ? client.backupInstance : client.snapshotInstance;
      await fn.call(client, instanceId);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || `${mode} failed`);
    } finally {
      setBusy(false);
    }
  };

  const restore = async (snapshotId) => {
    if (!confirm('Restoring forks a brand-new instance from this snapshot. Continue?')) return;
    setBusy(true); setErr(null);
    try {
      const created = await client.restoreInstance({
        instance_id: instanceId,
        snapshot_id: snapshotId,
      });
      // Restore returns a CreatedInstance (new id, bearer, proxy_token).
      // The bearer/proxy tokens are sensitive but already shown at create
      // time; for restore we just navigate to the new detail page.
      if (created?.id) {
        window.location.hash = `#/i/${encodeURIComponent(created.id)}`;
      }
    } catch (e) {
      setErr(e?.detail || e?.message || 'restore failed');
    } finally {
      setBusy(false);
    }
  };

  const pull = async (snapshotId) => {
    setBusy(true); setErr(null);
    try {
      await client.pullSnapshot(snapshotId);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'pull failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">snapshots</div>
        <div className="panel-actions">
          <button className="btn btn-sm" onClick={() => take('snapshot')} disabled={busy || disabled}>
            snapshot
          </button>
          <button className="btn btn-sm" onClick={() => take('backup')} disabled={busy || disabled}
                  title="snapshot then promote to the configured backup sink">
            backup
          </button>
        </div>
      </div>
      {err ? <div className="error">{err}</div> : null}
      {rows === null ? (
        <p className="muted small">loading…</p>
      ) : rows.length === 0 ? (
        <p className="muted small">no snapshots yet.</p>
      ) : (
        <table className="rows">
          <thead><tr>
            <th>id</th><th>kind</th><th>created</th><th>remote</th><th></th>
          </tr></thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id}>
                <td><code className="mono-sm">{r.id}</code></td>
                <td><span className="badge badge-faint">{r.kind}</span></td>
                <td className="muted">{fmtTime(r.created_at)}</td>
                <td>
                  {r.remote_uri ? (
                    <span className="badge badge-info" title={r.remote_uri}>S3</span>
                  ) : <span className="muted small">local</span>}
                </td>
                <td className="row-actions">
                  {r.remote_uri ? (
                    <button className="btn btn-ghost btn-sm" onClick={() => pull(r.id)} disabled={busy}>
                      pull
                    </button>
                  ) : null}
                  <button className="btn btn-ghost btn-sm" onClick={() => restore(r.id)} disabled={busy}>
                    restore
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

// ─── Secrets panel ───────────────────────────────────────────────

function SecretsPanel({ instanceId }) {
  const { client } = useApi();
  const [names, setNames] = React.useState(null);
  const [adding, setAdding] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  const refresh = React.useCallback(async () => {
    try {
      const list = await client.listSecretNames(instanceId);
      setNames(Array.isArray(list) ? list.map(r => r.name).sort() : []);
    } catch (e) {
      setErr(e?.message || 'list secrets failed');
    }
  }, [client, instanceId]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const remove = async (name) => {
    if (!confirm(`delete secret ${name}?`)) return;
    setBusy(true); setErr(null);
    try {
      await client.deleteSecret(instanceId, name);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">secrets</div>
        <div className="panel-actions">
          <button className="btn btn-sm" onClick={() => setAdding(true)} disabled={busy}>
            add
          </button>
        </div>
      </div>
      {err ? <div className="error">{err}</div> : null}
      <p className="muted small">
        Values are write-only — set here, read by the agent at runtime.  The
        web UI lists names so existing secrets can be replaced or removed.
      </p>
      {names === null ? (
        <p className="muted small">loading…</p>
      ) : names.length === 0 ? (
        <p className="muted small">no secrets set.</p>
      ) : (
        <ul className="secret-list">
          {names.map(name => (
            <li key={name}>
              <code className="mono-sm">{name}</code>
              <button className="btn btn-ghost btn-sm" onClick={() => remove(name)} disabled={busy}>
                delete
              </button>
            </li>
          ))}
        </ul>
      )}
      {adding ? (
        <AddSecretModal
          instanceId={instanceId}
          onClose={() => setAdding(false)}
          onAdded={() => { setAdding(false); refresh(); }}
        />
      ) : null}
    </section>
  );
}

function AddSecretModal({ instanceId, onClose, onAdded }) {
  const { client } = useApi();
  const [name, setName] = React.useState('');
  const [value, setValue] = React.useState('');
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  const submit = async (e) => {
    e.preventDefault();
    if (!name.trim() || !value) return;
    setSubmitting(true); setError(null);
    try {
      await client.putSecret(instanceId, name.trim(), value);
      onAdded && onAdded();
    } catch (err) {
      setError(err?.detail || err?.message || 'put failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ModalShell onClose={onClose} title="add secret">
      <form onSubmit={submit} className="form">
        <label className="field">
          <span>name</span>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="ANTHROPIC_API_KEY"
            autoFocus
            required
          />
        </label>
        <label className="field">
          <span>value</span>
          <input
            type="password"
            value={value}
            onChange={e => setValue(e.target.value)}
            required
          />
        </label>
        {error ? <div className="error">{error}</div> : null}
        <div className="modal-actions">
          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'saving…' : 'save'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClose}>cancel</button>
        </div>
      </form>
    </ModalShell>
  );
}

function fmtTime(secs) {
  if (!secs) return '—';
  try { return new Date(secs * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z'); }
  catch { return String(secs); }
}

// Trim a UUID for display.  Full id is still on the detail page, but
// list rows + breadcrumbs read better with the first 8 chars.
function shortId(id) {
  if (!id) return '';
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}

function probeLabel(p) {
  if (!p) return 'unknown';
  if (typeof p === 'string') return p;
  if (typeof p === 'object') {
    // ProbeResult is `{ kind: "Healthy" | "Degraded" | "Unreachable" }`
    // depending on serde shape; cover both.
    return p.kind || JSON.stringify(p);
  }
  return String(p);
}

// ─── Network policy badge + change-network panel ──────────────────

function NetworkPolicyBadge({ instance }) {
  const p = instance?.network_policy;
  const kind = p?.kind || 'open';
  const label = ({
    open: 'open',
    airgap: 'air-gapped',
    allowlist: 'allowlist',
    denylist: 'denylist',
  })[kind] || kind;
  // Tooltip surfaces both the user's raw entries AND the cube-
  // enforced CIDRs so the operator can see "I typed github.com →
  // cube enforces 140.82.121.4/32".
  const entries = (p && p.entries) || [];
  const cidrs = instance?.network_policy_cidrs || [];
  const lines = [];
  if (entries.length) lines.push(`entries: ${entries.join(', ')}`);
  if (cidrs.length) lines.push(`cidrs: ${cidrs.join(', ')}`);
  const title = lines.length ? lines.join('\n') : `network: ${label}`;
  const cls = kind === 'airgap' || kind === 'allowlist'
    ? 'badge-warn' : kind === 'denylist' ? 'badge-info' : 'badge-ok';
  return <span className={`badge ${cls}`} title={title}>{label}</span>;
}

function NetworkPolicyPanel({ instance, disabled }) {
  const { client } = useApi();
  const [editing, setEditing] = React.useState(false);
  const [policy, setPolicy] = React.useState(() => normaliseInstancePolicy(instance.network_policy));
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  // Re-sync the working copy when the user navigates between
  // instances (parent's `instance` prop changes).
  React.useEffect(() => {
    setPolicy(normaliseInstancePolicy(instance.network_policy));
    setEditing(false);
    setError(null);
  }, [instance.id, instance.network_policy]);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const result = await client.changeInstanceNetwork(
        instance.id,
        serializeNetworkPolicy(policy),
      );
      // The successor has a NEW id — workspace state survives via the
      // snapshot, but the URL changes.  Surface that in the UI by
      // navigating to the new id; the user sees the old destroyed
      // row in the rail and the new live row open.
      if (result?.id) {
        window.location.hash = `#/i/${encodeURIComponent(result.id)}`;
      }
    } catch (err) {
      setError(err?.detail || err?.message || 'change-network failed');
    } finally {
      setSubmitting(false);
    }
  };

  const currentLabel =
    POLICY_OPTIONS.find(o => o.kind === (instance.network_policy?.kind || 'open'))?.label
    || 'open';
  return (
    <section className="panel">
      <header className="panel-header">
        <h3>network access</h3>
        {!editing ? (
          <button
            className="btn btn-ghost btn-sm"
            disabled={disabled}
            onClick={() => setEditing(true)}
          >
            change
          </button>
        ) : null}
      </header>
      {!editing ? (
        <div className="panel-body">
          <p>
            <strong>{currentLabel}</strong>
          </p>
          {(instance.network_policy?.entries?.length || 0) > 0 ? (
            <p className="muted small">
              entries: {(instance.network_policy.entries || []).map(e => (
                <code key={e} className="mono-sm" style={{ marginRight: 6 }}>{e}</code>
              ))}
            </p>
          ) : null}
          {(instance.network_policy_cidrs?.length || 0) > 0 ? (
            <p className="muted small">
              cube-enforced cidrs: {(instance.network_policy_cidrs || []).map(c => (
                <code key={c} className="mono-sm" style={{ marginRight: 6 }}>{c}</code>
              ))}
            </p>
          ) : null}
        </div>
      ) : (
        <div className="panel-body">
          <NetworkPolicyPicker value={policy} onChange={setPolicy}/>
          <p className="hint muted small">
            <strong>Heads up:</strong> the cube can't update its eBPF egress
            map at runtime, so changing the policy snapshots this dyson and
            re-hires it under a new id (workspace state survives via the
            snapshot). The current URL will 404 after the change — bookmark
            the new one from the rail.
          </p>
          {error ? <div className="error">{error}</div> : null}
          <div className="modal-actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={submit}
              disabled={submitting}
            >
              {submitting ? 'changing…' : 'snapshot, re-hire, destroy old'}
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => { setEditing(false); setError(null); }}
              disabled={submitting}
            >
              cancel
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

function normaliseInstancePolicy(p) {
  if (!p) return { kind: 'open', entries: [] };
  if (p.kind === 'open' || p.kind === 'airgap') return { kind: p.kind, entries: [] };
  return { kind: p.kind, entries: Array.isArray(p.entries) ? p.entries : [] };
}
