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
  // `view.name === 'admin'` is the route-active state; `auth.isAdmin`
  // is the JWT-permissions-claim state from bootstrapAuth.  The admin
  // link only renders for actual admins — server returns 404 for
  // non-admins (see require_admin_role on the swarm side), so a
  // visible link would just dead-end into a missing-page error.
  const onAdminRoute = view?.name === 'admin';
  const onByokRoute = view?.name === 'byok';
  const onInstancesRoute = !onAdminRoute && !onByokRoute;
  return (
    <header className="topbar">
      <div className="topbar-brand">swarm</div>
      <nav className="topbar-nav">
        <a className={onInstancesRoute ? 'active' : ''} href="#/">instances</a>
        <a className={onByokRoute ? 'active' : ''} href="#/keys">keys</a>
        {auth.isAdmin ? (
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
