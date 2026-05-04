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
  const detail = classifyBootError(message);
  return (
    <main className="splash">
      <h1>swarm</h1>
      <p>{detail.title}</p>
      <p className="muted small">{detail.body}</p>
      {onRetry ? <button onClick={onRetry} className="btn">retry</button> : null}
    </main>
  );
}

function classifyBootError(message) {
  const text = String(message || '').trim();
  const lower = text.toLowerCase();
  if (lower.includes('auth callback') || lower.includes('state mismatch')) {
    return {
      title: 'Sign-in could not finish.',
      body: text || 'The browser sign-in session expired or no longer matches this tab. Retry sign-in from this page.',
    };
  }
  if (lower.includes('inactive') || lower.includes('not activated')) {
    return {
      title: 'Account pending activation.',
      body: text || 'Your account exists, but an administrator still needs to activate it.',
    };
  }
  if (lower.includes('failed to fetch') || lower.includes('network') || lower.includes('api')) {
    return {
      title: "Couldn't reach the API.",
      body: text || 'The API did not respond. Check the deployment and retry.',
    };
  }
  return {
    title: 'Swarm could not finish loading.',
    body: text || 'Unknown error.',
  };
}
