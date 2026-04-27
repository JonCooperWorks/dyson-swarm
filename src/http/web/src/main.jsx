/* warden — SPA entry.
 *
 * Phase 1 stub: render a placeholder so the build pipeline can be
 * verified end-to-end (vite build -> dist -> include_bytes! -> axum).
 * Phases 2-3 add OIDC bootstrap and the real UI.
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import './styles/tokens.css';
import './styles/layout.css';

function Splash() {
  return (
    <main className="splash">
      <h1>warden</h1>
      <p className="muted">orchestrator for Dyson agents in CubeSandbox MicroVMs</p>
      <p className="muted small">UI scaffolding in progress.</p>
    </main>
  );
}

const root = document.getElementById('root');
if (root) createRoot(root).render(<Splash/>);
