/* swarm — Instances view (list + detail + create modal).
 *
 * Desktop is a two-pane layout: a left rail lists every instance the
 * caller owns, and the right pane shows whichever id the URL hash
 * names.  Mobile collapses to one pane at a time — the list is the
 * page when nothing's selected, the detail pane takes over when a
 * row is picked, and the empty hero shows on a brand-new account.
 * Hash routing keeps deep-links stable across IdP redirects (the
 * OIDC return URL is always `/`, so the hash is the only thing the
 * IdP doesn't mangle).
 */

import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';
import { useApi } from '../hooks/useApi.jsx';
import { useAppState } from '../hooks/useAppState.js';
import {
  upsertInstance, removeInstance, selectInstance, setLoadError, setInstances,
  setWebhooksFor, setSharesFor,
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

  const totalInstances = useAppState(s => s.instances.order.length);

  // "New" is a dedicated page (#/new) rather than a modal — gives the
  // configuration surface room to breathe (advanced options, future
  // network-policy picker, etc.).  Both the rail header and the empty
  // detail pane's hero CTA navigate there.
  const goNew = () => { window.location.hash = '#/new'; };

  // Mobile is single-pane: the list IS the page when nothing's
  // selected (and the roster has anyone in it), the detail pane takes
  // over when a row is picked, and the empty hero shows on a brand-new
  // account.  CSS hides the off-mode pane via these mode classes.
  // Desktop ignores the classes and renders both panes side-by-side.
  const mobileMode = selectedId
    ? 'detail'
    : (totalInstances > 0 ? 'list' : 'empty');

  return (
    <div className={`instances-pane mobile-${mobileMode}`}>
      <InstanceList selectedId={selectedId} onNew={goNew}/>
      <InstanceDetail id={selectedId} onNew={goNew}/>
    </div>
  );
}

// ─── List ─────────────────────────────────────────────────────────

function InstanceList({ selectedId, onNew }) {
  const { client, auth } = useApi();
  const cubeProfiles = auth?.config?.cube_profiles || [];
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
              <a href={`#/i/${encodeURIComponent(id)}`}>
                <div className="rail-row-name">{label}</div>
                <div className="rail-row-id muted small">{shortId(id)}</div>
                <div className="rail-row-meta">
                  <StatusBadge status={row.status}/>
                  <CubeSizeBadge row={row} cubeProfiles={cubeProfiles}/>
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

// Small badge that surfaces the cube tier the instance was hired
// into.  Tooltip carries the full specs (`profileLabel`) so a user
// scanning the rail sees just "default", but a hover reveals the
// disk / vCPU / RAM tuple.  Renders nothing when the row has no
// matching profile (legacy rows, retired tiers, or no
// /auth/config.cube_profiles surfaced) — the absence is more honest
// than a placeholder string.
function CubeSizeBadge({ row, cubeProfiles }) {
  const profile = findCubeProfile(row?.template_id, cubeProfiles);
  if (!profile) return null;
  return (
    <span className="badge badge-size" title={profileLabel(profile)}>
      {profile.name}
    </span>
  );
}

// Compact id presentation: shortened by default, click-to-copy.  The
// raw UUID is bulky and steals horizontal space on mobile; the chip
// keeps the affordance ("yes this row has an id") without dominating
// the layout, and a tap copies the agent's public URL (so the
// operator can paste it into a curl, browser tab, or webhook
// integration).  Falls back to the raw id when no `openUrl` is
// supplied — same behaviour as before for callers that don't have
// the URL handy.
function IdChip({ id, openUrl }) {
  const [copied, setCopied] = React.useState(false);
  if (!id) return null;
  const value = openUrl || id;
  const onClick = async (e) => {
    e.preventDefault();
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1100);
    } catch { /* ignore */ }
  };
  return (
    <button
      type="button"
      className="id-chip"
      onClick={onClick}
      title={copied ? 'copied!' : `${value} — tap to copy`}
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

// Look up the `cube_profiles` entry whose template_id matches the
// instance row's.  Returns null when the operator hasn't surfaced
// profiles yet, when the row carries no template_id (legacy rows),
// or when the row's template_id is no longer in the ladder (e.g. an
// older tier has been retired).  Pure for testability.
export function findCubeProfile(templateId, cubeProfiles) {
  if (!templateId || !Array.isArray(cubeProfiles) || cubeProfiles.length === 0) {
    return null;
  }
  return cubeProfiles.find(p => p.template_id === templateId) || null;
}

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
        <h1 className="page-title">hire a new agent</h1>
        <p className="page-sub muted">
          Each agent is a long-lived employee.  Fill in the offer letter,
          then click hire.
        </p>
      </header>
      <NewInstanceForm/>
    </main>
  );
}

// Server-side `instances.create` returns once the cube is Live and
// Caddy has its TLS cert, but the dyson process inside the cube can
// still be a few seconds away from answering /healthz.  Poll the
// probe endpoint until it reports Healthy so the user lands on a
// working detail page instead of a 502.  Bounded at ~5s — past that
// the agent is genuinely stuck and the detail page is a better place
// to surface the unhealthy state (with the "probe" button to retry).
async function waitUntilHealthy(client, id) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      const r = await client.probeInstance(id);
      if (r?.status === 'healthy') return;
    } catch {
      // Mid-boot the cube can answer 502 / connection refused; we
      // just retry until the deadline.
    }
    await new Promise(res => setTimeout(res, 1000));
  }
}

// ─── Built-in tool catalogue ──────────────────────────────────────
//
// Mirror of dyson's tool registry (see crates/dyson/src/tool/*.rs).
// This is the source of truth for the SPA's "Advanced → Tools"
// picker; the wire shape is a positive include list of names that
// land in `instance.tools` and surface in the env envelope as
// `SWARM_TOOLS` (CSV).  Empty list ⇒ "register zero tools".
//
// Group ordering matches how operators tend to think about a
// dyson's job: filesystem first (the muscle), then web (the
// outside world), then KB / memory / observability, then security
// scanners, then admin/comm/skills.
// Subagents are dispatched as tools — they look like regular
// builtins to the parent agent (callable by name), but each one
// boots a child agent with its own constrained toolbox.  We list
// them in their own group so operators can see + toggle them
// alongside the leaf tools.
//
// `requiresNetwork` is set when the subagent's prompt expects
// reachable upstreams — `researcher` reads the web, `coder`
// pulls dependencies — so the airgap visual cue still applies.
const TOOL_CATALOGUE = [
  { name: 'bash',                       group: 'filesystem' },
  { name: 'read_file',                  group: 'filesystem' },
  { name: 'write_file',                 group: 'filesystem' },
  { name: 'edit_file',                  group: 'filesystem' },
  { name: 'bulk_edit',                  group: 'filesystem' },
  { name: 'list_files',                 group: 'filesystem' },
  { name: 'search_files',               group: 'filesystem' },
  { name: 'web_fetch',                  group: 'web', requiresNetwork: true },
  { name: 'web_search',                 group: 'web', requiresNetwork: true },
  { name: 'image_generate',             group: 'web', requiresNetwork: true },
  { name: 'kb_search',                  group: 'knowledge' },
  { name: 'kb_status',                  group: 'knowledge' },
  { name: 'memory_search',              group: 'knowledge' },
  { name: 'workspace',                  group: 'knowledge' },
  { name: 'dependency_scan',            group: 'security', requiresNetwork: true },
  { name: 'ast_describe',               group: 'security' },
  { name: 'ast_query',                  group: 'security' },
  { name: 'taint_trace',                group: 'security' },
  { name: 'attack_surface_analyzer',    group: 'security' },
  { name: 'exploit_builder',            group: 'security' },
  { name: 'load_skill',                 group: 'skills' },
  { name: 'skill_create',               group: 'skills' },
  { name: 'send_file',                  group: 'comm' },
  { name: 'export_conversation',        group: 'comm' },
  { name: 'planner',                    group: 'subagents' },
  { name: 'researcher',                 group: 'subagents', requiresNetwork: true },
  { name: 'verifier',                   group: 'subagents' },
  { name: 'dependency_review',          group: 'subagents', requiresNetwork: true },
  { name: 'coder',                      group: 'subagents', requiresNetwork: true },
  { name: 'security_engineer',          group: 'subagents' },
];
const ALL_TOOL_NAMES = TOOL_CATALOGUE.map(t => t.name);
export const NETWORK_REQUIRED_TOOL_NAMES = TOOL_CATALOGUE
  .filter(t => t.requiresNetwork)
  .map(t => t.name);

/// True when the policy kind blocks public-internet egress.
/// (Allowlist / denylist still let some traffic through, so we
/// only flag full airgap.)
export function isAirgap(kind) { return kind === 'airgap'; }

/// True when the tool would be a no-op under the given network
/// policy because it has no way to reach its upstream.
export function toolBlockedByNetwork(toolName, kind) {
  return isAirgap(kind) && NETWORK_REQUIRED_TOOL_NAMES.includes(toolName);
}

// Sentinel placeholder shown in MCP credential inputs on edit.  When
// the form submits with this value verbatim, the swarm side keeps
// the existing sealed token instead of overwriting — the SPA never
// reads back the real value, never decrypts.  The bullet character
// is one a real API token can't contain in any provider we ship,
// which keeps a "user typed this exact string" false-positive
// cost-free.
const MCP_KEEP_TOKEN = '••••••••';

/// Decide which tools to pre-tick when the picker first mounts.
///   - If the row already has a positive include list, use it
///     verbatim (the model gets exactly what was last pushed).
///   - Otherwise: airgap rows start with NOTHING ticked (the
///     operator opts in tool by tool), every other policy starts
///     with EVERY tool ticked (legacy + new-row default).
export function initialTools(row, kind) {
  if (row && Array.isArray(row.tools) && row.tools.length > 0) {
    return [...row.tools];
  }
  return kind === 'airgap' ? [] : [...ALL_TOOL_NAMES];
}

/// Pure helper: given a network-policy kind transition, return the
/// new tools state.  Used by both the hire and edit forms.
///
/// - Going INTO airgap (from anything else) clears the picker so
///   the operator opts in tool by tool — matches the "no network,
///   minimal surface" spirit of airgap.
/// - Going OUT of airgap (to anything else) re-ticks every tool
///   IFF the picker is currently empty.  An operator who moved
///   away from airgap typically wants the full toolbox available
///   again; preserving an empty picker would leave them with a
///   useless dyson.  When they had a non-empty selection (e.g.
///   they hand-picked a couple of tools under airgap), we
///   preserve it untouched.
/// - Every other transition (allowlist↔denylist, etc., or staying
///   on the same kind on initial mount) leaves the picker alone.
export function nextToolsForPolicyChange(prevKind, nextKind, currentTools) {
  if (prevKind !== 'airgap' && nextKind === 'airgap') return [];
  if (prevKind === 'airgap' && nextKind !== 'airgap'
      && Array.isArray(currentTools) && currentTools.length === 0) {
    return [...ALL_TOOL_NAMES];
  }
  return currentTools;
}

/// Group the catalogue once for the picker / display.
const TOOL_GROUPS = (() => {
  const m = new Map();
  for (const t of TOOL_CATALOGUE) {
    if (!m.has(t.group)) m.set(t.group, []);
    m.get(t.group).push(t);
  }
  return [...m.entries()];
})();

/// Generic checkbox-list tool picker.  Used twice with the same
/// chrome to honour "exact same behaviour as tools" — once for
/// built-in tools (grouped by category) and once for each attached
/// MCP server's catalogue (flat, ungrouped).
///
/// Props:
///   - `title`        panel header text
///   - `hint`         optional ReactNode rendered under the header
///   - `allNames`     full universe of names (drives the count + "all" button)
///   - `groups`       `[[label, [{name}]]]` ⇒ render fieldsets per group;
///                    `null` ⇒ flat grid sourced from `allNames`
///   - `value`        currently-enabled name array
///   - `onChange`     `(string[]) => void` — fired with the new selection
///   - `cellMeta`     `(name) => ({ blocked, title })` — optional row-level
///                    decoration (used by the built-in picker for the
///                    network-required airgap cue)
///   - `wrap`         `'section'` ⇒ wrap in `<section className="panel">`
///                    (default; used by the standalone built-in picker);
///                    `'bare'` ⇒ skip the outer panel wrapper (used when
///                    nesting under another card, e.g. MCP server rows)
///   - `actions`      optional ReactNode appended to `panel-actions`
function ToolPicker({
  title,
  hint,
  allNames,
  groups = null,
  value,
  onChange,
  cellMeta,
  wrap = 'section',
  actions,
}) {
  const enabled = React.useMemo(() => new Set(value), [value]);
  const total = allNames.length;
  const toggle = (name) => {
    const next = new Set(enabled);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    onChange(allNames.filter(n => next.has(n)));
  };
  const setAll = (on) => onChange(on ? [...allNames] : []);
  const flat = groups || [[null, allNames.map(n => ({ name: n }))]];

  const body = (
    <>
      <div className="panel-header">
        <div className="panel-title">{title}</div>
        <div className="panel-actions">
          <span className="muted small" style={{ marginRight: 8 }}>
            {enabled.size} / {total} enabled
          </span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => setAll(true)}
            disabled={total === 0 || enabled.size === total}
          >
            enable all
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => setAll(false)}
            disabled={enabled.size === 0}
          >
            disable all
          </button>
          {actions || null}
        </div>
      </div>
      {hint ? <p className="muted small">{hint}</p> : null}
      <div className="tools-body">
        {flat.map(([group, items]) => (
          <fieldset key={group || '_'} className="tools-group">
            {group ? (
              <legend className="tools-group-label muted small">{group}</legend>
            ) : null}
            <div className="tools-grid">
              {items.map(t => {
                const meta = cellMeta ? cellMeta(t.name) : null;
                const blocked = meta?.blocked || false;
                return (
                  <label
                    key={t.name}
                    className={`tools-cell ${blocked ? 'blocked' : ''}`}
                    title={meta?.title || undefined}
                  >
                    <input
                      type="checkbox"
                      checked={enabled.has(t.name)}
                      onChange={() => toggle(t.name)}
                    />
                    <span className="tools-cell-name mono-sm">{t.name}</span>
                  </label>
                );
              })}
            </div>
          </fieldset>
        ))}
      </div>
    </>
  );

  if (wrap === 'bare') return <div className="tool-picker">{body}</div>;
  return <section className="panel">{body}</section>;
}

/// Built-in tools picker — thin wrapper over the generic ToolPicker
/// that supplies the static catalogue + the airgap "blocked" cue.
function ToolsPicker({ value, onChange, policyKind }) {
  const cellMeta = React.useCallback((name) => {
    const blocked = toolBlockedByNetwork(name, policyKind);
    return {
      blocked,
      title: blocked
        ? "requires network — air-gapped instances can't reach upstream"
        : undefined,
    };
  }, [policyKind]);
  return (
    <ToolPicker
      title="tools"
      allNames={ALL_TOOL_NAMES}
      groups={TOOL_GROUPS}
      value={value}
      onChange={onChange}
      cellMeta={cellMeta}
      hint="Built-in tools the agent registers on boot.  Air-gapped employees start with nothing — pick only what the task actually needs."
    />
  );
}

/// Read-only tools view for the instance-detail page.  Same visual
/// rhythm as the picker but inputs are disabled so the operator
/// sees what's enabled at a glance and clicks "edit" to change it.
/// Empty `tools` on the row means "use dyson defaults" — every
/// builtin is on.
function ToolsView({ instance }) {
  const effective = React.useMemo(() => {
    if (Array.isArray(instance.tools) && instance.tools.length > 0) {
      return new Set(instance.tools);
    }
    // Empty list: airgap means "no tools", anything else means
    // "use dyson defaults" which renders as every tool enabled.
    return instance.network_policy?.kind === 'airgap'
      ? new Set()
      : new Set(ALL_TOOL_NAMES);
  }, [instance.tools, instance.network_policy?.kind]);
  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">tools</div>
        <div className="panel-actions">
          <span className="muted small">
            {effective.size} / {ALL_TOOL_NAMES.length} enabled
          </span>
        </div>
      </div>
      <div className="tools-body tools-body-readonly">
        {TOOL_GROUPS.map(([group, items]) => (
          <fieldset key={group} className="tools-group">
            <legend className="tools-group-label muted small">{group}</legend>
            <div className="tools-grid">
              {items.map(t => {
                const blocked = toolBlockedByNetwork(t.name, instance.network_policy?.kind);
                return (
                  <span
                    key={t.name}
                    className={`tools-cell ${effective.has(t.name) ? 'on' : 'off'} ${blocked ? 'blocked' : ''}`}
                    title={blocked ? 'requires network — air-gapped instance can\'t reach upstream' : undefined}
                  >
                    <input
                      type="checkbox"
                      checked={effective.has(t.name)}
                      readOnly
                      disabled
                      aria-label={t.name}
                    />
                    <span className="tools-cell-name mono-sm">{t.name}</span>
                  </span>
                );
              })}
            </div>
          </fieldset>
        ))}
      </div>
    </section>
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
  // Network policy state.  Default `nolocalnet` matches the row-side
  // SPA-side default is airgap — pick a wider profile only when
  // the task actually needs it.  This intentionally diverges from
  // the Rust NetworkPolicy::default() (NoLocalNet); existing
  // instance rows still load with whatever they were hired with,
  // only the hire form's initial radio is biased toward airgap.
  const [networkPolicy, setNetworkPolicy] = React.useState({
    kind: DEFAULT_POLICY_KIND,
    entries: [],
  });
  // MCP servers attached at hire time.  Each row is
  // { id, name, url, auth: { kind, ... } } where `id` is a local
  // identifier for React keys; the server-side wire shape (without
  // `id`) is built in `submit`.
  const [mcpServers, setMcpServers] = React.useState([]);
  // Built-in tool include list.  Airgap default → empty picker,
  // operator opts in tool-by-tool.  initialTools handles both
  // halves (airgap = [], everything else = ALL).
  const [tools, setTools] = React.useState(() => initialTools(null, DEFAULT_POLICY_KIND));
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  // Airgap rule: when the user transitions INTO airgap, drop the
  // tool picker to zero — operators have to opt in tool by tool,
  // matching the spirit of "no network, minimal surface".  Going
  // OUT of airgap with an empty picker re-ticks every tool (no
  // working dyson otherwise); going OUT with a hand-picked
  // selection preserves it.  Transition-aware so initial mount on
  // an already-airgap row doesn't clobber a pre-fill.
  //
  // The ref must be captured BEFORE the setTools updater runs, or
  // the closure reads the post-update value and the transition
  // never fires.  We snapshot to a local, update the ref, then
  // queue the state update.
  const prevPolicyKindRef = React.useRef(networkPolicy.kind);
  React.useEffect(() => {
    const prevKind = prevPolicyKindRef.current;
    prevPolicyKindRef.current = networkPolicy.kind;
    setTools(curr => nextToolsForPolicyChange(prevKind, networkPolicy.kind, curr));
  }, [networkPolicy.kind]);

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
      const mcp = serializeMcpServers(mcpServers);
      if (mcp.length > 0) req.mcp_servers = mcp;
      // Surface the tool include list in the env envelope so dyson
      // can read SWARM_TOOLS at boot.  Skip when every tool is
      // ticked AND the kind isn't airgap — that's the implicit
      // "use defaults" path and we don't want a CSV with every
      // builtin in it cluttering the env block.
      if (tools.length !== ALL_TOOL_NAMES.length || networkPolicy.kind === 'airgap') {
        req.env.SWARM_TOOLS = tools.join(',');
      }

      setPhase('provisioning');
      // Server blocks until the sandbox is Live AND Caddy's TLS cert
      // is provisioned (pre-warmed inside instance.create()), so by
      // the time this resolves the cube is reachable on the network.
      // The dyson process inside the cube can still be a few seconds
      // away from serving `/healthz` though — busy probing in the UI
      // bridges that gap so the user lands on a live agent, not a
      // 502/"warming up" detail page.
      const result = await client.createInstance(req);

      if (result?.id) {
        await waitUntilHealthy(client, result.id);
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
        <p className="muted small">getting your agent ready…</p>
        <div className="progress-bar"><div className="progress-bar-indeterminate"/></div>
        <p className="muted small" style={{ marginTop: 12 }}>
          By the time this redirects, your agent is live and reachable.
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

      <ToolsPicker
        value={tools}
        onChange={setTools}
        policyKind={networkPolicy.kind}
      />

      <section className="page-section">
        <h2 className="section-title">MCP servers</h2>
        <McpServersEditor value={mcpServers} onChange={setMcpServers}/>
        <span className="hint muted small">
          MCP traffic flows through swarm — the agent only sees a swarm
          proxy URL, never your upstream URL or its credentials. Bearer
          tokens and OAuth refresh tokens land in your encrypted user
          secret store. OAuth connections finish in a browser tab after
          you hire the agent.
        </span>
      </section>

      <section className="page-section">
        <h2 className="section-title">infrastructure</h2>
        {cubeProfiles.length >= 1 ? (
          <CubeProfilePicker
            profiles={cubeProfiles}
            value={templateId}
            onChange={setTemplateId}
          />
        ) : null /* No profiles surfaced — the form's templateId is
                    seeded from default_template_id and the operator
                    falls back to the legacy ttl-only flow. */}
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

// ─── Cube-profile picker ──────────────────────────────────────────
//
// One card per tier surfaced in /auth/config.cube_profiles.  The card
// carries the operator-friendly `name`, the specs tuple from
// profileLabel (right-aligned, monospace), and the optional
// description as muted small text below.  Mirrors the visual idiom of
// NetworkPolicyPicker so the hire form reads top-down as a stack of
// card-radios.
//
// Renders even with a single tier on the wire — the operator should
// see what they're getting, not just a hidden default.

export function CubeProfilePicker({ profiles, value, onChange }) {
  return (
    <div className="cube-profile-picker">
      <span className="field-label">cube profile</span>
      <div className="cube-profile-radios">
        {profiles.map(p => {
          const selected = value === p.template_id;
          return (
            <label
              key={p.template_id}
              className={`cube-profile-radio ${selected ? 'selected' : ''}`}
            >
              <input
                type="radio"
                name="cube_profile"
                value={p.template_id}
                checked={selected}
                onChange={() => onChange(p.template_id)}
              />
              <span className="cube-profile-name">{p.name}</span>
              <span className="cube-profile-specs">{profileLabel(p)}</span>
              {p.description ? (
                <span className="cube-profile-desc muted small">{p.description}</span>
              ) : null}
            </label>
          );
        })}
      </div>
      <span className="hint muted small">
        Cells in different profiles get different disk / CPU / RAM at
        boot — pick the size that fits the workload.
      </span>
    </div>
  );
}

// ─── Network-policy picker ────────────────────────────────────────
//
// Five profiles (mirrors the Rust enum in src/network_policy.rs):
//   nolocalnet — full internet minus RFC1918/link-local/cloud-meta.
//                Safe default — every fresh row lands here.
//   open       — same as nolocalnet PLUS an explicit 0.0.0.0/0 allow
//                that punches through the deny trie, granting LAN +
//                cloud-metadata access.  Legacy / opt-in.
//   airgap     — no egress except the swarm /llm proxy.
//   allowlist  — LLM proxy + the listed networks (CIDR or hostname).
//   denylist   — full internet minus the listed networks.
//
// Hostnames are DNS-resolved server-side at hire time; the cube
// enforces only IPv4 CIDRs.  Auto-collapse: if the user picks
// Allowlist and clears every chip, we flip the radio to Airgap (per
// the brief — empty Allowlist is functionally Airgap, and the Rust
// API rejects Allowlist with no entries anyway).

export const POLICY_OPTIONS = [
  {
    kind: 'airgap',
    label: 'Air-gapped (LLM + MCP only)',
    help: 'No outbound traffic at all, except to the swarm /llm and /mcp proxies. The agent can still call its model and any attached MCP servers (swarm forwards on its behalf), but the public internet is closed. The default — pick a wider profile only when the task actually needs it.',
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
  {
    kind: 'nolocalnet',
    label: 'Open (full internet)',
    help: 'Everything the agent asks for is allowed, except RFC1918 + link-local + cloud-metadata (169.254.169.254). Pick this when the agent needs to research, fetch dependencies, or call external APIs but should never touch your LAN or the host.',
  },
  {
    kind: 'open',
    label: 'Open + internal LAN',
    help: 'Same as Open, but ALSO permits access to private ranges (RFC1918, link-local, cloud-metadata). Pick this only when the agent legitimately needs to reach a service on your LAN or the host. Do NOT use on cloud VMs — exposes the cloud-metadata service.',
  },
];

/// SPA-side default network policy.  Picked here (not in the Rust
/// row default) so existing rows still load with whatever they
/// were originally hired with; only the hire form's initial state
/// uses this value.
export const DEFAULT_POLICY_KIND = 'airgap';

function NetworkPolicyPicker({ value, onChange }) {
  const setKind = (kind) => {
    if (kind === 'nolocalnet' || kind === 'open' || kind === 'airgap') {
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
        the sandbox briefly restarts to apply the new policy.  Workspace
        state, DNS, and webhook URLs all survive.
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
  if (!p) return { kind: 'nolocalnet' };
  if (p.kind === 'nolocalnet' || p.kind === 'open' || p.kind === 'airgap') {
    return { kind: p.kind };
  }
  // allowlist / denylist — include the user's raw entries; the server
  // resolves hostnames and persists both raw + resolved.
  return { kind: p.kind, entries: p.entries || [] };
}

// ── MCP servers ──────────────────────────────────────────────────
//
// Wire shape mirrors `McpServerSpec` / `McpAuthSpec` in
// dyson-swarm/src/mcp_servers.rs:
//   { name, url, auth: { kind: "none" } }
//   { name, url, auth: { kind: "bearer", token } }
//   { name, url, auth: { kind: "oauth", scopes, client_id?, client_secret?,
//                        authorization_url?, token_url?, registration_url? } }
//
// The OAuth flow itself runs after hire (the agent talks to swarm,
// swarm runs the dance, refresh tokens land in the user secret store).
// The form just collects the metadata.
export function serializeMcpServers(rows) {
  return rows
    .map(r => {
      const name = (r.name || '').trim();
      const url = (r.url || '').trim();
      if (!name || !url) return null;
      let auth;
      if (r.auth?.kind === 'bearer') {
        const token = (r.auth.token || '').trim();
        if (!token) return null;
        auth = { kind: 'bearer', token };
      } else if (r.auth?.kind === 'oauth') {
        const scopes = (r.auth.scopes || '')
          .split(/[\s,]+/)
          .map(s => s.trim())
          .filter(Boolean);
        auth = {
          kind: 'oauth',
          scopes,
          client_id: r.auth.client_id?.trim() || null,
          client_secret: r.auth.client_secret?.trim() || null,
          authorization_url: r.auth.authorization_url?.trim() || null,
          token_url: r.auth.token_url?.trim() || null,
          registration_url: r.auth.registration_url?.trim() || null,
        };
        // Drop nulls so the wire JSON is clean.
        for (const k of Object.keys(auth)) if (auth[k] == null) delete auth[k];
      } else {
        auth = { kind: 'none' };
      }
      return { name, url, auth };
    })
    .filter(Boolean);
}

let mcpRowCounter = 0;
function freshMcpRow() {
  mcpRowCounter += 1;
  return {
    id: `mcp-${mcpRowCounter}-${Date.now()}`,
    name: '',
    url: '',
    auth: { kind: 'none' },
  };
}

function McpServersEditor({ value, onChange }) {
  const rows = value || [];
  const update = (id, patch) =>
    onChange(rows.map(r => (r.id === id ? { ...r, ...patch } : r)));
  const updateAuth = (id, patch) =>
    onChange(
      rows.map(r => (r.id === id ? { ...r, auth: { ...r.auth, ...patch } } : r)),
    );
  const remove = id => onChange(rows.filter(r => r.id !== id));
  const add = () => onChange([...rows, freshMcpRow()]);

  if (rows.length === 0) {
    return (
      <div className="mcp-empty">
        <p className="muted small" style={{ margin: 0 }}>
          No MCP servers attached. The agent hires fine without any —
          add one if you want it to call out to Linear, GitHub, your
          own server, or anything that speaks streamable-HTTP MCP.
        </p>
        <button type="button" className="btn btn-ghost btn-sm" onClick={add}>
          + add MCP server
        </button>
      </div>
    );
  }

  return (
    <div className="mcp-list">
      {rows.map(row => (
        <McpServerCard
          key={row.id}
          row={row}
          onChange={patch => update(row.id, patch)}
          onChangeAuth={patch => updateAuth(row.id, patch)}
          onRemove={() => remove(row.id)}
        />
      ))}
      <button type="button" className="btn btn-ghost btn-sm mcp-add" onClick={add}>
        + add another
      </button>
    </div>
  );
}

function McpServerCard({ row, onChange, onChangeAuth, onRemove }) {
  const authKind = row.auth?.kind || 'none';
  return (
    <div className="mcp-card panel">
      <div className="mcp-card-head">
        <div className="mcp-card-title">
          <code className="mcp-card-name">
            {row.name?.trim() || 'unnamed'}
          </code>
          <span className={`mcp-auth-pill mcp-auth-${authKind}`}>{authKind}</span>
        </div>
        <button
          type="button"
          className="mcp-remove"
          onClick={onRemove}
          aria-label="remove server"
          title="remove"
        >
          ×
        </button>
      </div>
      <div className="mcp-card-body">
        <label className="field">
          <span>name</span>
          <input
            value={row.name}
            onChange={e => onChange({ name: e.target.value })}
            placeholder="linear"
            autoComplete="off"
          />
          <span className="hint muted small">
            Identifier the agent uses when calling tools. Lowercase,
            no spaces.
          </span>
        </label>
        <label className="field">
          <span>URL</span>
          <input
            value={row.url}
            onChange={e => onChange({ url: e.target.value })}
            placeholder="https://api.linear.app/mcp"
            autoComplete="off"
          />
        </label>
        <label className="field">
          <span>authentication</span>
          <select
            value={authKind}
            onChange={e => {
              const kind = e.target.value;
              if (kind === 'none') onChangeAuth({ kind: 'none' });
              else if (kind === 'bearer') onChangeAuth({ kind: 'bearer', token: '' });
              else if (kind === 'oauth')
                onChangeAuth({
                  kind: 'oauth',
                  scopes: '',
                  client_id: '',
                  client_secret: '',
                  authorization_url: '',
                  token_url: '',
                  registration_url: '',
                });
            }}
          >
            <option value="none">none</option>
            <option value="bearer">bearer token</option>
            <option value="oauth">OAuth 2.1 (PKCE)</option>
          </select>
        </label>
        {authKind === 'bearer' ? (
          <label className="field">
            <span>token</span>
            <input
              type="password"
              value={row.auth.token || ''}
              onChange={e => onChangeAuth({ token: e.target.value })}
              placeholder="lin_api_…"
              autoComplete="off"
            />
            <span className="hint muted small">
              Sent on every forwarded request as
              <code> Authorization: Bearer …</code>. Sealed in your
              user secret store; never reaches the agent.
            </span>
          </label>
        ) : null}
        {authKind === 'oauth' ? (
          <McpOAuthFields auth={row.auth} onChangeAuth={onChangeAuth}/>
        ) : null}
      </div>
    </div>
  );
}

function McpOAuthFields({ auth, onChangeAuth }) {
  const [advanced, setAdvanced] = React.useState(
    Boolean(auth.client_id || auth.authorization_url || auth.token_url),
  );
  return (
    <>
      <label className="field">
        <span>scopes</span>
        <input
          value={auth.scopes || ''}
          onChange={e => onChangeAuth({ scopes: e.target.value })}
          placeholder="read write"
          autoComplete="off"
        />
        <span className="hint muted small">
          Space- or comma-separated. Leave blank if the server doesn't
          require scopes.
        </span>
      </label>
      <button
        type="button"
        className="btn btn-ghost btn-sm mcp-advanced-toggle"
        onClick={() => setAdvanced(a => !a)}
      >
        {advanced ? '− hide advanced' : '+ advanced (DCR / endpoints)'}
      </button>
      {advanced ? (
        <div className="mcp-advanced">
          <label className="field">
            <span>client_id</span>
            <input
              value={auth.client_id || ''}
              onChange={e => onChangeAuth({ client_id: e.target.value })}
              placeholder="(empty = Dynamic Client Registration)"
              autoComplete="off"
            />
          </label>
          <label className="field">
            <span>client_secret</span>
            <input
              type="password"
              value={auth.client_secret || ''}
              onChange={e => onChangeAuth({ client_secret: e.target.value })}
              placeholder="(only if your provider requires it)"
              autoComplete="off"
            />
          </label>
          <label className="field">
            <span>authorization_url</span>
            <input
              value={auth.authorization_url || ''}
              onChange={e => onChangeAuth({ authorization_url: e.target.value })}
              placeholder="(empty = .well-known discovery)"
              autoComplete="off"
            />
          </label>
          <label className="field">
            <span>token_url</span>
            <input
              value={auth.token_url || ''}
              onChange={e => onChangeAuth({ token_url: e.target.value })}
              placeholder="(empty = .well-known discovery)"
              autoComplete="off"
            />
          </label>
          <label className="field">
            <span>registration_url</span>
            <input
              value={auth.registration_url || ''}
              onChange={e => onChangeAuth({ registration_url: e.target.value })}
              placeholder="(only needed if discovery doesn't expose one)"
              autoComplete="off"
            />
          </label>
        </div>
      ) : null}
    </>
  );
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

function InstanceDetail({ id, onNew }) {
  const { client, auth } = useApi();
  const cubeProfiles = auth?.config?.cube_profiles || [];
  const row = useAppState(s => (id ? s.instances.byId[id] : null));
  const totalInstances = useAppState(s => s.instances.order.length);
  // Enabled-task count for the tasks button badge.  Source of truth is
  // the per-instance webhooks slot in the store; we hydrate it here so
  // the count is correct on first paint (rather than 0 → real after
  // the user opens the tasks page).
  const enabledTaskCount = useAppState(s => {
    const slot = id ? s.webhooks.byInstance[id] : null;
    if (!slot) return null;
    return slot.rows.filter(r => r.enabled).length;
  });
  // Active share count for the "shared" button badge — same shape
  // as the tasks badge.  Active = not revoked AND not expired.
  const activeShareCount = useAppState(s => {
    const slot = id ? s.shares.byInstance[id] : null;
    if (!slot) return null;
    return slot.rows.filter(r => r.active).length;
  });
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

  // Webhooks list — fed into the "tasks" button's count badge.  Quiet
  // on failure (the badge just stays hidden); the dedicated tasks page
  // surfaces real errors when the user navigates in.
  React.useEffect(() => {
    if (!id) return;
    let cancelled = false;
    client.listWebhooks(id).then(list => {
      if (!cancelled) setWebhooksFor(id, list || []);
    }).catch(() => { /* silent — badge falls back to hidden */ });
    return () => { cancelled = true; };
  }, [client, id]);

  // Shares list — fed into the "shared" button's count badge.  Same
  // pattern as webhooks above.
  React.useEffect(() => {
    if (!id) return;
    let cancelled = false;
    client.listShares(id).then(list => {
      if (!cancelled) setSharesFor(id, list || []);
    }).catch(() => { /* silent — badge falls back to hidden */ });
    return () => { cancelled = true; };
  }, [client, id]);

  // Background TLS warm-up for `<id>.<hostname>` whenever the detail
  // page first appears for an instance.  Caddy fronts each Dyson with
  // on_demand TLS, so the very first request to a fresh subdomain
  // triggers a Let's Encrypt round-trip (~5–15s) — without warming
  // the user's first "open ↗" click races the ACME flow and shows
  // about:blank.
  //
  // `<link rel="preconnect">` opens the TCP + TLS connection in the
  // background.  The TLS handshake's SNI is what triggers Caddy's
  // on_demand_tls flow, so the preconnect alone is enough — no extra
  // HTTP request needed.  We deliberately do NOT also fire a no-cors
  // fetch through the dyson_proxy: that would have been a credentialed
  // cross-origin roundtrip kicking off via requestIdleCallback right
  // around the time the user makes their first click on the action
  // buttons, and the response-stream chatter on the main thread was
  // intermittently eating those clicks.
  const openUrl = row?.open_url;
  React.useEffect(() => {
    if (!openUrl) return;
    let origin;
    try { origin = new URL(openUrl).origin; } catch { return; }

    const link = document.createElement('link');
    link.rel = 'preconnect';
    link.href = origin;
    document.head.appendChild(link);

    return () => {
      link.remove();
    };
  }, [openUrl]);

  if (!id) return (
    <EmptyDetail
      onNew={onNew}
      hasInstances={totalInstances > 0}
    />
  );
  if (!row) return (
    <main className="detail-pane">
      <p className="muted">loading…</p>
    </main>
  );

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

  // DESTRUCTIVE in-place rebuild.  Reset the dyson on its existing
  // swarm id: hire a fresh cube under the latest template, keep
  // name/task/models/tools/network policy/secrets/MCP/bearer/DNS,
  // but DROP the workspace.  Memory, chats, knowledge base, learned
  // skills, and any in-flight work are gone.  Same URL — bookmarks
  // and webhook integrations survive.
  const reset = async () => {
    const label = row.name && row.name.trim() ? row.name : id;
    const warning =
      `RESET ${label} on the latest template?\n\n` +
      `This is DESTRUCTIVE.  The agent keeps its name, task, models, ` +
      `tools, network policy, secrets, MCP servers, URL, and bearer ` +
      `token — but its workspace will be WIPED.  Memory, chats, ` +
      `knowledge base, learned skills, and any in-flight work will be ` +
      `LOST.  This cannot be undone.\n\n` +
      `Use this when the agent got into a bad state and you want a ` +
      `clean start without losing its identity.`;
    if (!confirm(warning)) return;
    setBusy(true); setErr(null);
    try {
      const updated = await client.resetInstance(id);
      if (updated) upsertInstance(updated);
    } catch (e) {
      setErr(e?.message || 'reset failed');
    } finally {
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
      <header className="detail-header">
        <div className="employee-card">
          <h2 className="employee-name">{displayName}</h2>
          <div className="detail-meta">
            <StatusBadge status={row.status}/>
            <CubeSizeBadge row={row} cubeProfiles={cubeProfiles}/>
            <NetworkPolicyBadge instance={row}/>
            {row.pinned ? <span className="badge badge-info">pinned</span> : null}
            <IdChip id={row.id} openUrl={row.open_url}/>
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
                  : 'open this agent in a new tab'
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
          <a
            className="btn btn-ghost"
            href={`#/i/${encodeURIComponent(id)}/tasks`}
            aria-disabled={busy}
            onClick={(e) => { if (busy) e.preventDefault(); }}
            title="webhook-triggered tasks for this agent"
          >
            tasks
            {enabledTaskCount > 0
              ? <span className="btn-count-badge" aria-label={`${enabledTaskCount} enabled`}>{enabledTaskCount}</span>
              : null}
          </a>
          <a
            className="btn btn-ghost"
            href={`#/i/${encodeURIComponent(id)}/shares`}
            aria-disabled={busy}
            onClick={(e) => { if (busy) e.preventDefault(); }}
            title="anonymous artefact share links — copy, revoke, audit"
          >
            shared
            {activeShareCount > 0
              ? <span className="btn-count-badge" aria-label={`${activeShareCount} active`}>{activeShareCount}</span>
              : null}
          </a>
          <button
            className="btn btn-danger"
            onClick={reset}
            disabled={busy || row.status === 'destroyed'}
            title="DESTRUCTIVE: hire a fresh agent on the latest template with this one's config — but workspace data (memory, chats, kb, skills) is NOT carried over"
          >
            reset
          </button>
          <button className="btn btn-danger" onClick={destroy} disabled={busy || row.status === 'destroyed'}>
            destroy
          </button>
        </div>
      </header>

      <section className="panel">
        <div className="panel-title">runtime</div>
        {(() => {
          const profile = findCubeProfile(row.template_id, cubeProfiles);
          if (!profile) return null;
          return <KvRow label="size" value={profileLabel(profile)}/>;
        })()}
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
      <ToolsView instance={row}/>
      <SecretsPanel instanceId={id}/>
      <McpServersPanel
        instanceId={id}
        policyKind={row.network_policy?.kind}
        disabled={row.status === 'destroyed'}
      />

      {/* IDENTITY.md prose lives at the very bottom — operators reach
          for actions / runtime / snapshots / policy first; the agent's
          own self-description is reference material, not something
          you scan to act on. */}
      <section className="panel">
        <div className="panel-title">instructions</div>
        <div className="employee-task">
          {row.task && row.task.trim() ? (
            <TaskProse markdown={row.task}/>
          ) : (
            <p className="muted small">
              no task description — tap <em>edit</em> to write one.
            </p>
          )}
        </div>
      </section>
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
        <h1 className="page-title">edit agent</h1>
        <p className="page-sub muted">
          Change the agent's identity, model, toolbox, or network access.
          Network changes restart the sandbox briefly; everything else
          saves in place.
        </p>
      </header>
      {err ? <div className="error">{err}</div> : null}
      {row ? (
        <EditInstanceForm
          instance={row}
          backHref={backHref}
          formId="edit-instance-form"
        />
      ) : (
        <div className="muted">loading…</div>
      )}
    </main>
  );
}

/// Bottom action bar for the edit page.  Lives at the END of the
/// page so the user sees every editable surface first; the submit
/// button is wired to the form via `form="<id>"` so a click here
/// triggers the same handler as a button-inside-form submit.
/// MCP changes save through their own panel buttons; identity /
/// model / tools / network all flow through this single save.
function EditInstanceActionBar({ formId, backHref, policyChanged }) {
  // The submit-state lives inside EditInstanceForm; we mirror busy
  // state via a custom event so the bottom button can disable while
  // the underlying form is in-flight.  Tiny, dependency-free, and
  // keeps the form local to its own state tree.
  const [submitting, setSubmitting] = React.useState(false);
  React.useEffect(() => {
    const onState = (e) => {
      if (e.detail?.formId === formId) setSubmitting(Boolean(e.detail.submitting));
    };
    window.addEventListener('edit-form-state', onState);
    return () => window.removeEventListener('edit-form-state', onState);
  }, [formId]);
  const label = submitting
    ? (policyChanged ? 'restarting sandbox…' : 'saving…')
    : 'save';
  return (
    <div className="edit-action-bar">
      <button
        type="submit"
        form={formId}
        className="btn btn-primary btn-lg"
        disabled={submitting}
      >
        {label}
      </button>
      <a className="btn btn-ghost" href={backHref}>cancel</a>
    </div>
  );
}

function EditInstanceForm({ instance, backHref, formId }) {
  const { client, auth } = useApi();
  const disabled = instance.status === 'destroyed';
  const [name, setName] = React.useState(instance.name || '');
  const [task, setTask] = React.useState(instance.task || '');
  // Models picker reuses the same component as the create form.
  // Pre-fills with the current primary model when available; the
  // agent will also accept any other model id the user types.
  const initialModelsList = (instance.models && instance.models.length)
    ? instance.models
    : (instance.model ? [instance.model] : []);
  const [models, setModels] = React.useState(initialModelsList);
  const defaultModels = auth?.config?.default_models || [];

  // Tool include list — pre-fill with the row's persisted positive
  // list when present.  Empty `instance.tools` means "use defaults"
  // which the picker renders as everything ticked, except on
  // air-gapped rows where empty stays empty (operator opts in).
  const [tools, setTools] = React.useState(() =>
    initialTools(instance, instance.network_policy?.kind)
  );
  const [toolsDirty, setToolsDirty] = React.useState(false);
  const setToolsTracked = (next) => { setToolsDirty(true); setTools(next); };

  // Network policy state shared with the picker so transitioning
  // INTO airgap immediately clears the tool checkboxes — same
  // ergonomic guard the hire form has.  Initialised from the row.
  const [networkPolicy, setNetworkPolicy] = React.useState(
    () => normaliseInstancePolicy(instance.network_policy),
  );
  // Same transition rule as the hire form (snapshot ref BEFORE
  // queuing setTools so the closure sees the right `prev`).
  const prevPolicyKindRef = React.useRef(networkPolicy.kind);
  React.useEffect(() => {
    const prevKind = prevPolicyKindRef.current;
    prevPolicyKindRef.current = networkPolicy.kind;
    setTools(curr => {
      const next = nextToolsForPolicyChange(prevKind, networkPolicy.kind, curr);
      // Mark dirty if the rule mutated the picker, so the new
      // selection flows through on save (otherwise we'd silently
      // keep the row's pre-fill in the patch payload).
      if (next !== curr) setToolsDirty(true);
      return next;
    });
  }, [networkPolicy.kind]);

  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  // Mirror submitting state to the bottom action bar via a small
  // custom event.  Beats lifting the state up purely to wire one
  // button — the form stays self-contained and the page-level
  // composition (sibling panels) stays flat.
  React.useEffect(() => {
    window.dispatchEvent(new CustomEvent('edit-form-state', {
      detail: { formId, submitting },
    }));
  }, [formId, submitting]);

  const policyChanged = !samePolicy(
    normaliseInstancePolicy(instance.network_policy),
    networkPolicy,
  );

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true); setError(null);
    try {
      // Step 1: identity / models / tools — live PATCH on the
      // existing id (no sandbox churn).  Skip the request entirely
      // when nothing in this group changed.
      const patch = {};
      if (name !== (instance.name || '')) patch.name = name;
      if (task !== (instance.task || '')) patch.task = task;
      if (models.length > 0
          && JSON.stringify(models) !== JSON.stringify(initialModelsList)) {
        patch.models = models;
      }
      if (toolsDirty) patch.tools = tools;
      if (Object.keys(patch).length > 0) {
        // Backend rejects an empty PATCH; only send when there's a
        // delta.  Always include name + task when sending so the
        // backend's "missing means unchanged" semantic still
        // produces an updated row in the response.
        const payload = { name, task, ...patch };
        const updated = await client.updateInstance(instance.id, payload);
        upsertInstance(updated);
      }

      // Step 2: network policy — restarts the sandbox under the same
      // id (in-place rotation), so DNS, bearer tokens and webhook
      // URLs all survive.  Skipped when the policy is untouched.
      if (policyChanged) {
        const updated = await client.changeInstanceNetwork(
          instance.id,
          serializeNetworkPolicy(networkPolicy),
        );
        if (updated) upsertInstance(updated);
      }
      window.location.hash = backHref;
    } catch (err) {
      setError(err?.detail || err?.message || 'save failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="edit-stack">
      <form id={formId} onSubmit={submit} className="form page-form">
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
              rows={6}
            />
            <span className="hint muted small">
              Saving rewrites IDENTITY.md via /api/admin/configure —
              the running agent picks it up on its next turn
              (no restart).
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
          {policyChanged ? (
            <p className="hint muted small">
              <strong>Heads up:</strong> the sandbox briefly restarts to apply
              the new policy.  Workspace state, DNS, and webhook URLs all
              survive.
            </p>
          ) : null}
        </section>

        <ToolsPicker
          value={tools}
          onChange={setToolsTracked}
          policyKind={networkPolicy.kind}
        />

        {error ? <div className="error">{error}</div> : null}
      </form>

      {/* MCP servers — separate panel because each row commits
          independently (add / connect-OAuth / disconnect / remove).
          Lives outside the form so its buttons don't trigger the
          identity submit. */}
      <McpServersPanel
        instanceId={instance.id}
        policyKind={networkPolicy.kind}
        disabled={disabled}
      />

      <EditInstanceActionBar
        formId={formId}
        backHref={backHref}
        policyChanged={policyChanged}
      />
    </div>
  );
}

function EmptyDetail({ onNew, hasInstances }) {
  return (
    <main className="detail-pane detail-empty">
      <div className="empty-hero">
        <DysonSphereGlyph/>
        {hasInstances ? (
          <>
            <h1 className="empty-title">pick an agent</h1>
            <p className="empty-sub">
              your roster is on the left — pick one to inspect, edit, or
              fire it up. or hire a new employee for a new task.
            </p>
            <div className="empty-actions">
              <button className="btn btn-primary" onClick={onNew}>+ hire an agent</button>
            </div>
          </>
        ) : (
          <>
            <h1 className="empty-title">build your swarm</h1>
            <p className="empty-sub">
              agents are long-lived workers you put to work — one per task,
              each with its own brief, model, and memory. start with one
              employee; scale to hundreds.
            </p>
            <div className="empty-actions">
              <button className="btn btn-primary btn-lg" onClick={onNew}>
                hire your first agent
              </button>
            </div>
            <p className="empty-hint muted small">
              you can always change an agent's brief or model later — nothing
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
                <td data-label="id"><code className="mono-sm">{r.id}</code></td>
                <td data-label="kind"><span className="badge badge-faint">{r.kind}</span></td>
                <td data-label="created" className="muted">{fmtTime(r.created_at)}</td>
                <td data-label="remote">
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

// ─── MCP servers panel (instance detail) ──────────────────────────
//
// Lives next to SecretsPanel.  Lists the MCP servers attached to one
// instance, lets the user add / edit / delete / disconnect, and
// kicks off OAuth flows in a new tab.  All persistence goes through
// `InstanceService::{put,delete,disconnect}_mcp_server`, which seals
// the entry in user_secrets and pushes the new `mcp_servers` block to
// the running dyson via the configure endpoint.

function McpServersPanel({ instanceId, policyKind, disabled }) {
  const { client } = useApi();
  const [rows, setRows] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  // editing: null | { mode: 'new' } | { mode: 'edit', row } | { mode: 'loading' }
  // The "loading" state shows a spinner while we fetch the full URL
  // for the edit form (the listing strips query strings; the edit
  // modal needs the un-stripped value to pre-fill cleanly).
  const [editing, setEditing] = React.useState(null);

  const refresh = React.useCallback(async () => {
    try {
      const list = await client.listMcpServers(instanceId);
      setRows(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.detail || e?.message || 'list failed');
    }
  }, [client, instanceId]);
  React.useEffect(() => { refresh(); }, [refresh]);

  const remove = async name => {
    if (!confirm(`remove MCP server ${name}? the agent will stop seeing this tool set.`)) return;
    setBusy(true); setErr(null);
    try {
      await client.deleteMcpServer(instanceId, name);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'delete failed');
    } finally {
      setBusy(false);
    }
  };

  const disconnect = async name => {
    if (!confirm(`clear OAuth tokens for ${name}? you'll need to reconnect before the agent can use it.`)) return;
    setBusy(true); setErr(null);
    try {
      await client.disconnectMcpServer(instanceId, name);
      await refresh();
    } catch (e) {
      setErr(e?.detail || e?.message || 'disconnect failed');
    } finally {
      setBusy(false);
    }
  };

  const connect = async name => {
    setBusy(true); setErr(null);
    try {
      const ret = `${window.location.origin}/#/i/${encodeURIComponent(instanceId)}`;
      const { authorization_url } = await client.startMcpOAuth(instanceId, name, { return_to: ret });
      // Open in a new tab so the user keeps their place; the callback
      // page lands them somewhere they can close.
      window.open(authorization_url, '_blank', 'noopener,noreferrer');
    } catch (e) {
      setErr(e?.detail || e?.message || 'oauth start failed');
    } finally {
      setBusy(false);
    }
  };

  const submitEdit = async (spec) => {
    setBusy(true); setErr(null);
    try {
      await client.putMcpServer(instanceId, spec.name, { url: spec.url, auth: spec.auth });
      await refresh();
      setEditing(null);
    } catch (e) {
      setErr(e?.detail || e?.message || 'save failed');
    } finally {
      setBusy(false);
    }
  };

  // Edit-button path: fetch the FULL URL via getMcpServer (the listing
  // strips query strings) so the modal pre-fills with whatever the
  // operator originally saved.  Shows a transient busy state while
  // the round-trip lands; on failure we fall back to the stripped row
  // so the user can still edit (worst case: they re-paste the URL).
  const openEdit = async (row) => {
    setBusy(true); setErr(null);
    try {
      const detail = await client.getMcpServer(instanceId, row.name);
      setEditing({ mode: 'edit', row: detail || row });
    } catch (e) {
      // Fall back to listing data — better than blocking the edit.
      console.warn('[swarm] mcp edit: getMcpServer failed', e);
      setEditing({ mode: 'edit', row });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">mcp servers</div>
        <div className="panel-actions">
          <button
            className="btn btn-sm"
            onClick={() => setEditing({ mode: 'new' })}
            disabled={disabled || busy}
          >
            add
          </button>
        </div>
      </div>
      {err ? <div className="error">{err}</div> : null}
      <p className="muted small">
        Swarm proxies every MCP request — the agent only sees a swarm URL,
        never your upstream URL or its credentials. OAuth tokens land in
        your encrypted user secret store and refresh transparently.
      </p>
      {rows === null ? (
        <p className="muted small">loading…</p>
      ) : rows.length === 0 ? (
        <p className="muted small">no MCP servers attached.</p>
      ) : (
        <ul className="mcp-row-list">
          {rows.map(r => (
            <McpServerRow
              key={r.name}
              row={r}
              instanceId={instanceId}
              policyKind={policyKind}
              busy={busy || disabled}
              onEdit={() => openEdit(r)}
              onConnect={() => connect(r.name)}
              onDisconnect={() => disconnect(r.name)}
              onRemove={() => remove(r.name)}
              onCatalogUpdated={() => refresh()}
            />
          ))}
        </ul>
      )}
      {editing ? (
        <McpServerEditModal
          existingNames={(rows || []).map(r => r.name)}
          initial={editing.mode === 'edit' ? editing.row : null}
          onCancel={() => setEditing(null)}
          onSubmit={submitEdit}
          busy={busy}
        />
      ) : null}
    </section>
  );
}

function McpServerRow({
  row,
  instanceId,
  policyKind,
  busy,
  onEdit,
  onConnect,
  onDisconnect,
  onRemove,
  onCatalogUpdated,
}) {
  const { client } = useApi();
  const isOauth = row.auth_kind === 'oauth';
  // OAuth-not-connected is the only state that surfaces a "connect"
  // CTA; bearer / none / oauth-connected all just show the auth pill.
  const needsConnect = isOauth && !row.connected;

  // ── Tools-list connection state ────────────────────────────────
  // Status is derived: a non-null catalog ⇒ "connected" until the user
  // re-runs the check.  Errors come from the most recent check attempt
  // and clear on the next successful one.
  const initialCatalog = row.tools_catalog || null;
  const [catalog, setCatalog] = React.useState(initialCatalog);
  const [checking, setChecking] = React.useState(false);
  const [checkErr, setCheckErr] = React.useState(null);
  // Reset state when the row's identity changes (e.g. parent refresh).
  React.useEffect(() => {
    setCatalog(row.tools_catalog || null);
    setCheckErr(null);
  }, [row.name, row.tools_catalog]);

  // Selection state.  `null` ⇒ "use default" — the airgap rule then
  // determines what the picker shows ticked (mirrors the built-in
  // tools section's `initialTools` semantics: airgap → none, else
  // every tool in the catalogue).
  const initialSelection = Array.isArray(row.enabled_tools) ? row.enabled_tools : null;
  const [selection, setSelection] = React.useState(initialSelection);
  React.useEffect(() => {
    setSelection(Array.isArray(row.enabled_tools) ? row.enabled_tools : null);
  }, [row.name, row.enabled_tools]);

  const allToolNames = React.useMemo(
    () => (catalog?.tools || []).map(t => t.name),
    [catalog],
  );
  // Effective selection used to drive the picker.  Null ⇒ apply the
  // airgap rule against the catalogue.
  const effective = React.useMemo(() => {
    if (Array.isArray(selection)) return selection;
    if (allToolNames.length === 0) return [];
    return policyKind === 'airgap' ? [] : [...allToolNames];
  }, [selection, allToolNames, policyKind]);

  const runCheck = async () => {
    setChecking(true); setCheckErr(null);
    try {
      const result = await client.checkMcpServer(instanceId, row.name);
      const next = {
        tools: result.tools || [],
        last_checked_at: result.last_checked_at,
      };
      setCatalog(next);
      // Don't pre-write a selection — the next render computes the
      // effective default from the catalogue + airgap rule.  The user
      // sees ticks immediately and saves only by toggling.
      onCatalogUpdated && onCatalogUpdated();
    } catch (e) {
      setCheckErr(e?.detail || e?.message || 'check failed');
    } finally {
      setChecking(false);
    }
  };

  const persistSelection = async (next) => {
    // Mirror the built-in picker's "implicit-all" semantics: when the
    // user re-ticks every tool on a non-airgap row, drop back to null
    // so the proxy stops filtering and the row tracks the catalogue
    // as it grows.  Airgap rows always get an explicit list.
    const allOn = next.length === allToolNames.length
      && next.every(n => allToolNames.includes(n));
    const wireValue = (allOn && policyKind !== 'airgap') ? null : next;
    setSelection(wireValue);
    try {
      await client.setMcpEnabledTools(instanceId, row.name, wireValue);
    } catch (e) {
      // Roll back local state on failure so the picker reflects what
      // the server actually has.
      setSelection(initialSelection);
      console.warn('[swarm] mcp setEnabledTools failed', e);
    }
  };

  const statusBadge = (() => {
    if (checking) return <span className="mcp-row-status small muted">checking…</span>;
    if (checkErr) return <span className="mcp-row-status small mcp-row-warning">check failed</span>;
    if (catalog) return (
      <span className="mcp-row-status small muted">
        connected · {catalog.tools.length} tools
      </span>
    );
    return <span className="mcp-row-status small muted">not connected</span>;
  })();

  return (
    <li className="mcp-row">
      <div className="mcp-row-head">
        <code className="mcp-row-name">{row.name}</code>
        <span className={`mcp-auth-pill mcp-auth-${row.auth_kind}`}>
          {row.auth_kind}
        </span>
        {needsConnect ? (
          <span className="mcp-row-warning small">oauth not authorised</span>
        ) : null}
        {statusBadge}
      </div>
      <div className="mcp-row-url muted small" title={row.url}>{row.url}</div>
      <div className="mcp-row-actions">
        {needsConnect ? (
          <button className="btn btn-primary btn-sm" onClick={onConnect} disabled={busy}>
            connect
          </button>
        ) : null}
        {isOauth && row.connected ? (
          <button className="btn btn-ghost btn-sm" onClick={onConnect} disabled={busy}>
            reconnect
          </button>
        ) : null}
        {isOauth && row.connected ? (
          <button className="btn btn-ghost btn-sm" onClick={onDisconnect} disabled={busy}>
            disconnect
          </button>
        ) : null}
        <button
          className="btn btn-ghost btn-sm"
          onClick={runCheck}
          disabled={busy || checking || (isOauth && !row.connected)}
          title={isOauth && !row.connected ? 'authenticate before checking' : undefined}
        >
          {catalog ? 're-check' : 'check'}
        </button>
        <button className="btn btn-ghost btn-sm" onClick={onEdit} disabled={busy}>
          edit
        </button>
        <button className="btn btn-ghost btn-sm" onClick={onRemove} disabled={busy}>
          remove
        </button>
      </div>
      {checkErr ? <div className="error" style={{ marginTop: 8 }}>{checkErr}</div> : null}
      {catalog ? (
        <ToolPicker
          title="tools"
          allNames={allToolNames}
          value={effective}
          onChange={persistSelection}
          wrap="bare"
          hint={
            allToolNames.length === 0
              ? 'Upstream advertises no tools.'
              : `Tools advertised by ${row.name}.  Air-gapped instances start with nothing — pick only what the task actually needs.`
          }
        />
      ) : null}
    </li>
  );
}

function McpServerEditModal({ initial, existingNames, onCancel, onSubmit, busy }) {
  // Initial row when editing carries `name`, `url`, `auth_kind` (no
  // tokens — those stay server-side).  Credential inputs pre-fill
  // with the static MCP_KEEP_TOKEN sentinel when the existing auth
  // shape matches; if the user doesn't change the placeholder, the
  // server keeps the sealed value (we never decrypt to display).
  // Touching the field replaces the placeholder with whatever the
  // user types — flip back to "keep" by re-typing the bullets,
  // though the typical flow is just to leave it alone.
  const isNew = !initial;
  const initialAuthKind = initial?.auth_kind || 'none';
  // True when the credential field for this auth kind is already
  // populated server-side and the operator is editing (not adding).
  // Bearer always carries a token, OAuth optionally carries a
  // client_secret — for OAuth we conservatively pre-mask only when
  // we actually know there's something stored.  `initial` doesn't
  // surface the secret presence today, so we mask whenever the auth
  // shape matches: a false-positive mask reveals nothing.
  const hasExistingBearer = !isNew && initialAuthKind === 'bearer';
  const hasExistingOauthSecret = !isNew && initialAuthKind === 'oauth';
  const [name, setName] = React.useState(initial?.name || '');
  const [url, setUrl] = React.useState(initial?.url || '');
  const [authKind, setAuthKind] = React.useState(initialAuthKind);
  const [token, setToken] = React.useState(hasExistingBearer ? MCP_KEEP_TOKEN : '');
  const [scopes, setScopes] = React.useState('');
  const [advanced, setAdvanced] = React.useState(false);
  const [clientId, setClientId] = React.useState('');
  const [clientSecret, setClientSecret] = React.useState(
    hasExistingOauthSecret ? MCP_KEEP_TOKEN : ''
  );
  const [authorizationUrl, setAuthorizationUrl] = React.useState('');
  const [tokenUrl, setTokenUrl] = React.useState('');
  const [registrationUrl, setRegistrationUrl] = React.useState('');
  const [err, setErr] = React.useState(null);

  // Auth kind changed mid-edit → drop any "keep existing" sentinels.
  // Switching shape clears the stored creds anyway (server-side), so
  // pre-filled bullets are misleading after the switch.
  React.useEffect(() => {
    if (authKind !== initialAuthKind) {
      if (token === MCP_KEEP_TOKEN) setToken('');
      if (clientSecret === MCP_KEEP_TOKEN) setClientSecret('');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authKind]);

  const submit = (e) => {
    e.preventDefault();
    setErr(null);
    const trimmed = (name || '').trim();
    if (!trimmed) { setErr('name is required'); return; }
    if (isNew && existingNames.includes(trimmed)) {
      setErr(`a server named "${trimmed}" already exists`);
      return;
    }
    if (!url.trim()) { setErr('url is required'); return; }
    let auth;
    if (authKind === 'bearer') {
      if (!token.trim()) { setErr('bearer token is required'); return; }
      // Sentinel passes through verbatim — swarm's put path detects
      // it and keeps the existing sealed token.
      auth = { kind: 'bearer', token: token.trim() };
    } else if (authKind === 'oauth') {
      const sc = (scopes || '').split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
      auth = { kind: 'oauth', scopes: sc };
      if (clientId.trim()) auth.client_id = clientId.trim();
      if (clientSecret.trim()) auth.client_secret = clientSecret.trim();
      if (authorizationUrl.trim()) auth.authorization_url = authorizationUrl.trim();
      if (tokenUrl.trim()) auth.token_url = tokenUrl.trim();
      if (registrationUrl.trim()) auth.registration_url = registrationUrl.trim();
    } else {
      auth = { kind: 'none' };
    }
    onSubmit({ name: trimmed, url: url.trim(), auth });
  };

  return (
    <div className="modal-scrim" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header mcp-modal-header">
          <span>{isNew ? 'add mcp server' : `edit ${initial.name}`}</span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={onCancel}
            disabled={busy}
            aria-label="close"
          >
            ×
          </button>
        </div>
        <form className="form modal-body" onSubmit={submit}>
          <label className="field">
            <span>name</span>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="linear"
              disabled={!isNew /* server name is the storage key — immutable */}
              autoFocus={isNew}
              autoComplete="off"
            />
            {!isNew ? (
              <span className="hint muted small">
                Names are immutable — remove and re-add to rename.
              </span>
            ) : null}
          </label>
          <label className="field">
            <span>URL</span>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://api.linear.app/mcp"
              autoComplete="off"
            />
          </label>
          <label className="field">
            <span>authentication</span>
            <select value={authKind} onChange={e => setAuthKind(e.target.value)}>
              <option value="none">none</option>
              <option value="bearer">bearer token</option>
              <option value="oauth">OAuth 2.1 (PKCE)</option>
            </select>
            {!isNew && initial.auth_kind !== authKind ? (
              <span className="hint muted small">
                Switching auth shape clears any stored OAuth tokens.
              </span>
            ) : null}
          </label>
          {authKind === 'bearer' ? (
            <label className="field">
              <span>token</span>
              <input
                type="password"
                value={token}
                onChange={e => setToken(e.target.value)}
                placeholder="lin_api_…"
                autoComplete="off"
              />
              <span className="hint muted small">
                Sealed in your user secret store. Leave the
                <code className="byok-inline-code">{MCP_KEEP_TOKEN}</code>
                placeholder to keep the existing token; replace it
                to rotate.  Swarm never reads the value back.
              </span>
            </label>
          ) : null}
          {authKind === 'oauth' ? (
            <>
              <label className="field">
                <span>scopes</span>
                <input
                  value={scopes}
                  onChange={e => setScopes(e.target.value)}
                  placeholder="read write"
                  autoComplete="off"
                />
              </label>
              <button
                type="button"
                className="btn btn-ghost btn-sm mcp-advanced-toggle"
                onClick={() => setAdvanced(a => !a)}
              >
                {advanced ? '− hide advanced' : '+ advanced (DCR / endpoints)'}
              </button>
              {advanced ? (
                <div className="mcp-advanced">
                  <label className="field">
                    <span>client_id</span>
                    <input
                      value={clientId}
                      onChange={e => setClientId(e.target.value)}
                      placeholder="(empty = Dynamic Client Registration)"
                      autoComplete="off"
                    />
                  </label>
                  <label className="field">
                    <span>client_secret</span>
                    <input
                      type="password"
                      value={clientSecret}
                      onChange={e => setClientSecret(e.target.value)}
                      placeholder="(only if your provider requires it)"
                      autoComplete="off"
                    />
                  </label>
                  <label className="field">
                    <span>authorization_url</span>
                    <input
                      value={authorizationUrl}
                      onChange={e => setAuthorizationUrl(e.target.value)}
                      placeholder="(empty = .well-known discovery)"
                      autoComplete="off"
                    />
                  </label>
                  <label className="field">
                    <span>token_url</span>
                    <input
                      value={tokenUrl}
                      onChange={e => setTokenUrl(e.target.value)}
                      placeholder="(empty = .well-known discovery)"
                      autoComplete="off"
                    />
                  </label>
                  <label className="field">
                    <span>registration_url</span>
                    <input
                      value={registrationUrl}
                      onChange={e => setRegistrationUrl(e.target.value)}
                      placeholder="(only needed if discovery doesn't expose one)"
                      autoComplete="off"
                    />
                  </label>
                </div>
              ) : null}
            </>
          ) : null}
          {err ? <div className="error">{err}</div> : null}
          <div className="modal-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'saving…' : 'save'}
            </button>
            <button type="button" className="btn btn-ghost" onClick={onCancel} disabled={busy}>
              cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Network policy badge + change-network panel ──────────────────

function NetworkPolicyBadge({ instance }) {
  const p = instance?.network_policy;
  const kind = p?.kind || 'nolocalnet';
  const label = ({
    nolocalnet: 'open',
    open: 'open + lan',
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
    ? 'badge-warn'
    : kind === 'denylist' || kind === 'open'
      ? 'badge-info'
      : 'badge-ok';
  return <span className={`badge ${cls}`} title={title}>{label}</span>;
}

function NetworkPolicyPanel({ instance, disabled }) {
  const { client } = useApi();
  const [policy, setPolicy] = React.useState(() => normaliseInstancePolicy(instance.network_policy));
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState(null);

  // Re-sync the working copy when the user navigates between
  // instances (parent's `instance.id` changes).  Do NOT depend on
  // `instance.network_policy` itself — the 30s instance-list poll
  // upserts a fresh object reference on every tick and that would
  // wipe in-progress edits.
  React.useEffect(() => {
    setPolicy(normaliseInstancePolicy(instance.network_policy));
    setError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [instance.id]);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      // In-place rotation: same swarm id, fresh sandbox under the new
      // policy.  DNS, bearer, secrets and webhook URLs all survive.
      const updated = await client.changeInstanceNetwork(
        instance.id,
        serializeNetworkPolicy(policy),
      );
      if (updated) upsertInstance(updated);
    } catch (err) {
      setError(err?.detail || err?.message || 'change-network failed');
    } finally {
      setSubmitting(false);
    }
  };

  const dirty = !samePolicy(
    normaliseInstancePolicy(instance.network_policy),
    policy,
  );
  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-title">network access</div>
      </div>
      <p className="muted small">
        Egress profile enforced by the cube's eBPF map.  Changing it
        briefly restarts the sandbox; workspace state, DNS, and
        webhook URLs all survive.
      </p>
      <NetworkPolicyPicker value={policy} onChange={setPolicy}/>
      {error ? <div className="error">{error}</div> : null}
      {dirty ? (
        <div className="modal-actions">
          <button
            type="button"
            className="btn btn-primary"
            onClick={submit}
            disabled={submitting || disabled}
          >
            {submitting ? 'restarting sandbox…' : 'apply'}
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => {
              setPolicy(normaliseInstancePolicy(instance.network_policy));
              setError(null);
            }}
            disabled={submitting}
          >
            revert
          </button>
        </div>
      ) : null}
    </section>
  );
}

function samePolicy(a, b) {
  if (a.kind !== b.kind) return false;
  const ae = a.entries || [];
  const be = b.entries || [];
  if (ae.length !== be.length) return false;
  for (let i = 0; i < ae.length; i++) {
    if (ae[i] !== be[i]) return false;
  }
  return true;
}

function normaliseInstancePolicy(p) {
  if (!p) return { kind: 'nolocalnet', entries: [] };
  if (p.kind === 'nolocalnet' || p.kind === 'open' || p.kind === 'airgap') {
    return { kind: p.kind, entries: [] };
  }
  return { kind: p.kind, entries: Array.isArray(p.entries) ? p.entries : [] };
}
