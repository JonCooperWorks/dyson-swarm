/* swarm — top chrome.
 *
 * Brand on the left, current view tag in the middle, sign-out on the
 * right.  Phase 3 only has a single view (Instances) so the middle
 * cell is text; Phase 5 will hook the admin switcher in here.
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';

export function TopBar({ view }) {
  const { auth } = useApi();
  // The admin link is shown to every authenticated caller (OIDC mode
  // or local-dev no-auth).  Hiding it on a stale JWT-permissions
  // claim — which is what the previous `auth.isAdmin` gate did —
  // surprised operators whose Auth0 role had just been updated:
  // their session token didn't yet carry the new permission, the
  // link disappeared, and they assumed swarm had broken.  The server
  // already gates `/v1/admin/*` (404 for non-admins), and AdminView
  // probes `/v1/admin/users` on mount and renders a clean
  // "not authorized" splash when the probe 401/403s — so showing the
  // link for non-admins lands them on a clear message rather than
  // hiding the navigation surface entirely.
  const onAdminRoute = view?.name === 'admin';
  const onByokRoute = view?.name === 'byok';
  const onArtefactsRoute = view?.name === 'artefacts';
  const onInstancesRoute = !onAdminRoute && !onByokRoute && !onArtefactsRoute;
  const showAdminLink = auth?.mode === 'oidc' || auth?.mode === 'none';
  return (
    <header className="topbar">
      <div className="topbar-brand">swarm</div>
      <nav className="topbar-nav">
        <a className={onInstancesRoute ? 'active' : ''} href="#/">instances</a>
        <a className={onArtefactsRoute ? 'active' : ''} href="#/artefacts">artefacts</a>
        <a className={onByokRoute ? 'active' : ''} href="#/keys">keys</a>
        {showAdminLink ? (
          <a className={onAdminRoute ? 'active' : ''} href="#/admin">admin</a>
        ) : null}
      </nav>
      <div className="topbar-actions">
        {auth.mode === 'oidc' ? (
          <button className="btn btn-ghost btn-sm" onClick={auth.logout}>sign out</button>
        ) : null}
      </div>
    </header>
  );
}
