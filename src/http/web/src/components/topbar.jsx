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
  return (
    <header className="topbar">
      <div className="topbar-brand">swarm</div>
      <nav className="topbar-nav">
        <a className={!onAdminRoute ? 'active' : ''} href="#/">instances</a>
        {auth.isAdmin ? (
          <a className={onAdminRoute ? 'active' : ''} href="#/admin">admin</a>
        ) : null}
        <span className="topbar-view">· {viewLabel(view)}</span>
      </nav>
      <div className="topbar-actions">
        {auth.mode === 'oidc' ? (
          <button className="btn btn-ghost" onClick={auth.logout}>sign out</button>
        ) : null}
      </div>
    </header>
  );
}

function viewLabel(view) {
  if (!view) return '';
  switch (view.name) {
    case 'instances': return 'instances';
    case 'instance':  return `instances · ${view.id}`;
    case 'admin':     return 'admin';
    default:          return '';
  }
}
