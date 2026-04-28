/* swarm — SPA entry.
 *
 * Bootstrap order (mirrors Dyson):
 *   1. bootstrapAuth() — calls GET /auth/config; if mode=oidc and we
 *      don't have a usable token, redirects to the IdP and never
 *      returns.  When we do have one, schedules a silent refresh.
 *   2. Build a SwarmClient with getToken bound to sessionStorage so
 *      silent refreshes propagate without rebuilding the client.
 *   3. boot(client) — confirms the user's account is active and pulls
 *      the initial instance list into the store.
 *   4. createRoot().render() — Phase 3 will replace <Splash/> with the
 *      real app shell.
 *
 * Splash branches:
 *   - mode=none           → AuthDisabledSplash
 *   - bootstrap throws    → BootErrorSplash (network / 5xx)
 *   - boot returns 403    → InactiveAccountSplash
 *   - happy path          → <App/> (phase 3)
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import './styles/tokens.css';
import './styles/layout.css';
import './styles/panels.css';

import { bootstrapAuth } from './api/auth.js';
import { SwarmClient } from './api/client.js';
import { boot } from './api/boot.js';
import { ApiProvider } from './hooks/useApi.jsx';
import {
  AuthDisabledSplash, InactiveAccountSplash, BootErrorSplash,
} from './components/splash.jsx';
import { App } from './components/app.jsx';

async function start() {
  const root = document.getElementById('root');
  if (!root) return;
  const mount = createRoot(root);

  let auth;
  try {
    auth = await bootstrapAuth();
  } catch (err) {
    mount.render(<BootErrorSplash message={err?.message || String(err)} onRetry={() => location.reload()}/>);
    return;
  }

  if (auth.mode === 'none') {
    mount.render(<AuthDisabledSplash/>);
    return;
  }

  const client = new SwarmClient({ getToken: auth.getToken });
  const result = await boot(client);

  if (!result.ok && result.reason === 'inactive') {
    mount.render(<InactiveAccountSplash onLogout={auth.logout}/>);
    return;
  }
  if (!result.ok) {
    mount.render(<BootErrorSplash message={result.error?.message || 'cold-load failed'} onRetry={() => location.reload()}/>);
    return;
  }

  mount.render(
    <ApiProvider client={client} auth={auth}>
      <App/>
    </ApiProvider>
  );
}

start().catch(err => {
  // Last-ditch error path — bootstrapAuth's catch should have handled
  // most of these, but a thrown error before mount.render exists
  // (e.g. createRoot fails) lands here.
  // eslint-disable-next-line no-console
  console.error('swarm boot failed:', err);
});
