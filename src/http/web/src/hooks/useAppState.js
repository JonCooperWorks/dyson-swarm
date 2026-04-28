/* swarm — store hook.
 *
 * Wraps useSyncExternalStore so components can read the global snapshot.
 * Selectors are encouraged to keep renders narrow.
 */

import React from 'react';
import { store } from '../store/app.js';

export function useAppState(selector) {
  const select = selector || ((s) => s);
  // useSyncExternalStore needs both a getSnapshot for client renders and
  // a server-side snapshot getter; SPA-only so they're identical.
  return React.useSyncExternalStore(
    store.subscribe,
    () => select(store.getSnapshot()),
    () => select(store.getSnapshot()),
  );
}
