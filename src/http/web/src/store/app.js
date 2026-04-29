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
// Anything else falls back to the list.  Order matters: the edit
// pattern is a strict prefix of the detail pattern, so it has to be
// checked first or `#/i/foo/edit` would be parsed as `view.id = "foo"`.

export function parseHashView() {
  if (typeof window === 'undefined') return { name: 'instances', id: null };
  const h = window.location.hash || '#/';
  const edit = h.match(/^#\/i\/([^/?#]+)\/edit/);
  if (edit) return { name: 'instance-edit', id: decodeURIComponent(edit[1]) };
  const m = h.match(/^#\/i\/([^/?#]+)/);
  if (m) return { name: 'instance', id: decodeURIComponent(m[1]) };
  if (h.startsWith('#/new')) return { name: 'instance-new', id: null };
  if (h.startsWith('#/admin')) return { name: 'admin', id: null };
  return { name: 'instances', id: null };
}
