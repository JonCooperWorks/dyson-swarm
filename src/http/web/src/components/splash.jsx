/* swarm — splash screens.
 *
 * Three end states the SPA can show without entering the main shell:
 *   - <AuthDisabledSplash/>   — backend reports mode:"none"
 *   - <InactiveAccountSplash/>— OIDC succeeded but user_middleware 403'd
 *   - <BootErrorSplash/>      — network / 5xx
 */

import React from 'react';

export function AuthDisabledSplash() {
  return (
    <main className="splash">
      <h1>swarm</h1>
      <p>This deployment doesn't have OIDC configured for the web UI.</p>
      <p className="muted small">
        Set <code>[oidc].spa_client_id</code> in <code>config.toml</code> to
        enable the browser flow, or use the CLI with an opaque api key minted
        through <code>POST /v1/admin/users/:id/keys</code>.
      </p>
    </main>
  );
}

export function InactiveAccountSplash({ onLogout }) {
  return (
    <main className="splash">
      <h1>account pending activation</h1>
      <p>
        Your sign-in succeeded, but your swarm account hasn't been
        activated yet.
      </p>
      <p className="muted small">
        An administrator can activate you with <br/>
        <code>POST /v1/admin/users/:id/activate</code>.
      </p>
      {onLogout ? <button onClick={onLogout} className="btn">sign out</button> : null}
    </main>
  );
}

export function BootErrorSplash({ message, onRetry }) {
  return (
    <main className="splash">
      <h1>swarm</h1>
      <p>Couldn't reach the API.</p>
      <p className="muted small">{message || 'unknown error'}</p>
      {onRetry ? <button onClick={onRetry} className="btn">retry</button> : null}
    </main>
  );
}
