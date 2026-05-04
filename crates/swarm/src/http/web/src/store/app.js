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
  // Per-instance share roster — same shape as webhooks.  Backs the
  // artefacts button's shared count, artefact row highlights, and
  // the shared-links panel.
  shares: {
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

// ─── shares (anonymous artefact links) ────────────────────────────

export function setSharesFor(instanceId, rows) {
  if (!instanceId) return;
  store.dispatch(s => ({
    ...s,
    shares: {
      ...s.shares,
      byInstance: {
        ...s.shares.byInstance,
        [instanceId]: { rows: Array.isArray(rows) ? rows : [], loadedAt: Date.now() },
      },
    },
  }));
}

export function removeShare(instanceId, jti) {
  if (!instanceId || !jti) return;
  store.dispatch(s => {
    const slot = s.shares.byInstance[instanceId];
    if (!slot) return s;
    // Local mark-as-revoked rather than splice — keeps the row in
    // the table so the operator sees what just happened (the badge
    // counts only `active` rows so it still ticks down).
    const now = Math.floor(Date.now() / 1000);
    const rows = slot.rows.map(r => (
      r.jti === jti && !r.revoked_at ? { ...r, revoked_at: now, active: false } : r
    ));
    return {
      ...s,
      shares: {
        ...s.shares,
        byInstance: { ...s.shares.byInstance, [instanceId]: { rows, loadedAt: Date.now() } },
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
  const shareLog = h.match(/^#\/i\/([^/?#]+)\/shares\/([^/?#]+)\/log/);
  if (shareLog) return {
    name: 'share-access-log',
    id: decodeURIComponent(shareLog[1]),
    jti: decodeURIComponent(shareLog[2]),
  };
  const shares = h.match(/^#\/i\/([^/?#]+)\/shares/);
  if (shares) return { name: 'instance-shares', id: decodeURIComponent(shares[1]) };
  // Deep-linked single-artefact reader.  Must come before the bare
  // `#/i/<id>/artefacts` route so a canonical /<art_id> at the tail
  // doesn't get swallowed by the listing route.
  const instArtefactDetail = h.match(/^#\/i\/([^/?#]+)\/artefacts\/([^/?#]+)/);
  if (instArtefactDetail) return {
    name: 'instance-artefact',
    id: decodeURIComponent(instArtefactDetail[1]),
    artefactId: decodeURIComponent(instArtefactDetail[2]),
  };
  const instArtefacts = h.match(/^#\/i\/([^/?#]+)\/artefacts/);
  if (instArtefacts) return { name: 'instance-artefacts', id: decodeURIComponent(instArtefacts[1]) };
  const edit = h.match(/^#\/i\/([^/?#]+)\/edit/);
  if (edit) return { name: 'instance-edit', id: decodeURIComponent(edit[1]) };
  const m = h.match(/^#\/i\/([^/?#]+)/);
  if (m) return { name: 'instance', id: decodeURIComponent(m[1]) };
  if (h.startsWith('#/new')) return { name: 'instance-new', id: null };
  if (h.startsWith('#/admin/mcp-catalog/new')) {
    return { name: 'admin-mcp-catalog-new', id: null };
  }
  const adminCatalogEdit = h.match(/^#\/admin\/mcp-catalog\/([^/?#]+)/);
  if (adminCatalogEdit) {
    return {
      name: 'admin-mcp-catalog-edit',
      id: null,
      catalogId: decodeURIComponent(adminCatalogEdit[1]),
    };
  }
  if (h.startsWith('#/admin')) return { name: 'admin', id: null };
  if (h.startsWith('#/keys')) return { name: 'byok', id: null };
  if (h.startsWith('#/artefacts')) return { name: 'artefacts', id: null };
  return { name: 'instances', id: null };
}
