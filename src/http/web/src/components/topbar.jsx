/* warden — top chrome.
 *
 * Brand on the left, current view tag in the middle, sign-out on the
 * right.  Phase 3 only has a single view (Instances) so the middle
 * cell is text; Phase 5 will hook the admin switcher in here.
 */

import React from 'react';
import { useApi } from '../hooks/useApi.jsx';

export function TopBar({ view }) {
  const { auth } = useApi();
  return (
    <header className="topbar">
      <div className="topbar-brand">warden</div>
      <div className="topbar-view">{viewLabel(view)}</div>
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
