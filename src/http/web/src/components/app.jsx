/* swarm — top-level shell.
 *
 * Owns the hash-router subscription and renders the right view for
 * the current hash.  Hash routing (rather than HTML5 History) keeps
 * the IdP redirect target stable: every callback URL is `/` and the
 * hash decides what we show.
 */

import React from 'react';
import { useAppState } from '../hooks/useAppState.js';
import { setView, parseHashView } from '../store/app.js';
import { TopBar } from './topbar.jsx';
import { InstancesView, NewInstancePage, EditInstancePage } from './instances.jsx';
import { AdminView } from './admin.jsx';
import { ByokView } from './byok.jsx';

export function App() {
  const view = useAppState(s => s.meta.view);
  const loadError = useAppState(s => s.meta.loadError);

  // Subscribe to hash changes once.  parseHashView() is pure so
  // re-running it on each hashchange is cheap.
  React.useEffect(() => {
    const onHash = () => setView(parseHashView());
    window.addEventListener('hashchange', onHash);
    onHash(); // sync once on mount in case the hash changed during boot
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  return (
    <div className="app">
      <TopBar view={view}/>
      {loadError ? <div className="banner banner-error">{loadError}</div> : null}
      {renderView(view)}
    </div>
  );
}

function renderView(view) {
  switch (view.name) {
    case 'instances':
    case 'instance':
      return <InstancesView view={view}/>;
    case 'instance-new':
      return <NewInstancePage/>;
    case 'instance-edit':
      return <EditInstancePage instanceId={view.id}/>;
    case 'admin':
      return <AdminView/>;
    case 'byok':
      return <ByokView/>;
    default:
      return <InstancesView view={{ name: 'instances', id: null }}/>;
  }
}
