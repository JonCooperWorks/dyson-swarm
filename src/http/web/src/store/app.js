/* swarm — global app state.
 *
 * Two top-level slices:
 *   - meta:      cold-load status, current view, error banner
 *   - instances: list-keyed-by-id, ordered list of ids for stable
 *                rendering, currently-selected id for the detail panel
 *
 * Reducers are tiny and exported individually; no action/type indirection
 * (mirrors Dyson's pattern).  Components import the setters they need.
 */

import { createStore } from './createStore.js';

const initial = {
  meta: {
    bootstrapped: false,
    loadError: null,
    view: parseHashView(),
  },
  instances: {
    byId: {},
    order: [],
    selectedId: null,
  },
  // Per-instance webhook ("tasks") roster keyed by instance id.  Each
  // value is `{ rows: WebhookView[], loadedAt }` where rows is the
  // array returned by listWebhooks().  Cached so the badge in the
  // detail-view "tasks" button doesn't blink to zero every time the
  // user reopens the row.
  webhooks: {
    byInstance: {},
  },
};

export const store = createStore(initial);

// ─── meta ──────────────────────────────────────────────────────────

export function setBootstrapped(v) {
  store.dispatch(s => s.meta.bootstrapped === v ? s : {
    ...s, meta: { ...s.meta, bootstrapped: !!v },
  });
}

export function setLoadError(err) {
  store.dispatch(s => s.meta.loadError === err ? s : {
    ...s, meta: { ...s.meta, loadError: err || null },
  });
}

export function setView(view) {
  store.dispatch(s => s.meta.view === view ? s : {
    ...s, meta: { ...s.meta, view },
  });
}

// ─── instances ─────────────────────────────────────────────────────

export function setInstances(rows) {
  store.dispatch(s => {
    const byId = {};
    const order = [];
    for (const row of rows || []) {
      byId[row.id] = row;
      order.push(row.id);
    }
    return { ...s, instances: { ...s.instances, byId, order } };
  });
}

export function upsertInstance(row) {
  if (!row?.id) return;
  store.dispatch(s => {
    const existing = s.instances.byId[row.id];
    const byId = { ...s.instances.byId, [row.id]: { ...existing, ...row } };
    const order = existing ? s.instances.order : [...s.instances.order, row.id];
    return { ...s, instances: { ...s.instances, byId, order } };
  });
}

export function removeInstance(id) {
  store.dispatch(s => {
    if (!s.instances.byId[id]) return s;
    const byId = { ...s.instances.byId };
    delete byId[id];
    const order = s.instances.order.filter(x => x !== id);
    const selectedId = s.instances.selectedId === id ? null : s.instances.selectedId;
    return { ...s, instances: { byId, order, selectedId } };
  });
}

export function selectInstance(id) {
  store.dispatch(s => s.instances.selectedId === id ? s : {
    ...s, instances: { ...s.instances, selectedId: id || null },
  });
}

// ─── webhooks (UI: "tasks") ────────────────────────────────────────

export function setWebhooksFor(instanceId, rows) {
  if (!instanceId) return;
  store.dispatch(s => ({
    ...s,
    webhooks: {
      ...s.webhooks,
      byInstance: {
        ...s.webhooks.byInstance,
        [instanceId]: { rows: Array.isArray(rows) ? rows : [], loadedAt: Date.now() },
      },
    },
  }));
}

export function upsertWebhook(instanceId, row) {
  if (!instanceId || !row?.name) return;
  store.dispatch(s => {
    const slot = s.webhooks.byInstance[instanceId] || { rows: [], loadedAt: 0 };
    const idx = slot.rows.findIndex(r => r.name === row.name);
    const rows = idx >= 0
      ? slot.rows.map((r, i) => (i === idx ? { ...r, ...row } : r))
      : [...slot.rows, row];
    return {
      ...s,
      webhooks: {
        ...s.webhooks,
        byInstance: { ...s.webhooks.byInstance, [instanceId]: { rows, loadedAt: Date.now() } },
      },
    };
  });
}

export function removeWebhook(instanceId, name) {
  if (!instanceId || !name) return;
  store.dispatch(s => {
    const slot = s.webhooks.byInstance[instanceId];
    if (!slot) return s;
    const rows = slot.rows.filter(r => r.name !== name);
    return {
      ...s,
      webhooks: {
        ...s.webhooks,
        byInstance: { ...s.webhooks.byInstance, [instanceId]: { rows, loadedAt: Date.now() } },
      },
    };
  });
}

// ─── hash routing ──────────────────────────────────────────────────
//
// Hash paths the SPA understands (mirrors what Dyson does — keeps a
// single mount path so the IdP redirect stays one config entry):
//   #/                 → instances list (default)
//   #/i/<id>           → instance detail
//   #/i/<id>/edit      → dedicated edit page (replaces the old EditEmployeeModal)
//   #/new              → dedicated hire page (replaces the old CreateModal)
//   #/admin            → admin (users, proxy tokens)
//
// Anything else falls back to the list.  Order matters: every
// /tasks subroute is a strict prefix of the detail pattern, so all
// of them must match BEFORE the bare `#/i/<id>` rule.  Same trick the
// edit pattern uses.

export function parseHashView() {
  if (typeof window === 'undefined') return { name: 'instances', id: null };
  const h = window.location.hash || '#/';
  // Audit subroutes are checked before /tasks/new and /tasks/<name> —
  // `audit` is a reserved task slug (the validator forbids slashes,
  // but we still want a stable URL when someone hand-edits it).
  const auditDetail = h.match(/^#\/i\/([^/?#]+)\/tasks\/audit\/([^/?#]+)/);
  if (auditDetail) return {
    name: 'instance-task-audit-detail',
    id: decodeURIComponent(auditDetail[1]),
    deliveryId: decodeURIComponent(auditDetail[2]),
  };
  const audit = h.match(/^#\/i\/([^/?#]+)\/tasks\/audit/);
  if (audit) return { name: 'instance-task-audit', id: decodeURIComponent(audit[1]) };
  const taskNew = h.match(/^#\/i\/([^/?#]+)\/tasks\/new/);
  if (taskNew) return { name: 'instance-task-new', id: decodeURIComponent(taskNew[1]), taskName: null };
  const taskEdit = h.match(/^#\/i\/([^/?#]+)\/tasks\/([^/?#]+)/);
  if (taskEdit) return {
    name: 'instance-task-edit',
    id: decodeURIComponent(taskEdit[1]),
    taskName: decodeURIComponent(taskEdit[2]),
  };
  const tasks = h.match(/^#\/i\/([^/?#]+)\/tasks/);
  if (tasks) return { name: 'instance-tasks', id: decodeURIComponent(tasks[1]), taskName: null };
  const edit = h.match(/^#\/i\/([^/?#]+)\/edit/);
  if (edit) return { name: 'instance-edit', id: decodeURIComponent(edit[1]) };
  const m = h.match(/^#\/i\/([^/?#]+)/);
  if (m) return { name: 'instance', id: decodeURIComponent(m[1]) };
  if (h.startsWith('#/new')) return { name: 'instance-new', id: null };
  if (h.startsWith('#/admin')) return { name: 'admin', id: null };
  if (h.startsWith('#/keys')) return { name: 'byok', id: null };
  return { name: 'instances', id: null };
}
