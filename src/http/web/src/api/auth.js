/* warden — auth bootstrap for the SPA.
 *
 * Backend tells us via GET /auth/config which mode is active.  For OIDC
 * we run a textbook Authorization Code + PKCE flow against whatever IdP
 * the operator configured — Auth0, Okta, Keycloak, Entra, dex, take
 * your pick.  Warden never sees plaintext credentials; it just verifies
 * the JWT the IdP signs back.
 *
 * Token storage:
 *   sessionStorage holds (a) the in-flight PKCE state during the
 *   redirect round-trip and (b) the access/refresh tokens once we have
 *   them.  sessionStorage is per-tab, dies on tab close, survives the
 *   redirect.  XSS would still hand an attacker the token; the
 *   trust model here is the same as Dyson's — single-tenant deployments
 *   on Tailscale / loopback / behind a real auth proxy.  Multi-tenant
 *   public deployments should run a BFF instead, but that's a different
 *   doc.  The SPA uses Authorization: Bearer (not cookies) so CSRF is
 *   not exploitable on this surface.
 *
 * Refresh:
 *   We schedule a silent refresh ~60s before expires_in runs out.  On
 *   failure (revoked, IdP down) we redirect for a fresh authorization.
 *
 * Discovery:
 *   The backend /auth/config returns just issuer + audience + client_id
 *   + required_scopes.  The SPA fetches authorization_endpoint and
 *   token_endpoint directly from <issuer>/.well-known/openid-configuration
 *   — every modern IdP serves it CORS-enabled.  This keeps warden out
 *   of the IdP discovery business and avoids an unauthenticated
 *   server-side fetch with attacker-influenced URLs.
 */

const STORAGE_KEY = 'warden:auth';
const PENDING_KEY = 'warden:auth:pending';
const REFRESH_LEEWAY_S = 60;

// ──────────────────────────────────────────────────────────────────
// Storage primitives.
// ──────────────────────────────────────────────────────────────────

function readTokens() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function writeTokens(tokens) {
  if (!tokens) sessionStorage.removeItem(STORAGE_KEY);
  else sessionStorage.setItem(STORAGE_KEY, JSON.stringify(tokens));
}

function readPending() {
  try {
    const raw = sessionStorage.getItem(PENDING_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function writePending(p) {
  if (!p) sessionStorage.removeItem(PENDING_KEY);
  else sessionStorage.setItem(PENDING_KEY, JSON.stringify(p));
}

// ──────────────────────────────────────────────────────────────────
// PKCE — RFC 7636.  S256 challenge from a 32-byte verifier; base64url
// encoded so the values survive a query-string round-trip unchanged.
// ──────────────────────────────────────────────────────────────────

function base64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(byteLen = 32) {
  const a = new Uint8Array(byteLen);
  crypto.getRandomValues(a);
  return base64url(a);
}

async function pkceChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64url(new Uint8Array(digest));
}

// ──────────────────────────────────────────────────────────────────
// Discovery.
// ──────────────────────────────────────────────────────────────────

export async function loadAuthConfig() {
  const r = await fetch('/auth/config', { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`/auth/config: ${r.status}`);
  return r.json();
}

async function discoverIssuer(issuer) {
  // Trim trailing slash so we don't double-slash the well-known path.
  const base = issuer.replace(/\/+$/, '');
  const url = `${base}/.well-known/openid-configuration`;
  const r = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`oidc discovery failed: ${url} -> ${r.status}`);
  const doc = await r.json();
  if (!doc.authorization_endpoint || !doc.token_endpoint) {
    throw new Error('oidc discovery: missing authorization_endpoint or token_endpoint');
  }
  return doc;
}

// ──────────────────────────────────────────────────────────────────
// Authorization Code + PKCE flow.
// ──────────────────────────────────────────────────────────────────

function redirectUri() {
  // Fixed root callback.  The SPA detects the ?code=&state= return on
  // its normal mount path and short-circuits.
  return `${window.location.origin}/`;
}

async function startAuthorizationFlow(cfg, discovery) {
  const verifier = randomString(32);
  const challenge = await pkceChallenge(verifier);
  const state = randomString(16);
  writePending({
    verifier,
    state,
    returnTo: window.location.hash || '#/',
    issuedAt: Date.now(),
  });

  const scopes = ['openid', ...(cfg.required_scopes || [])];
  // offline_access is harmless on IdPs that ignore unknown scopes; on
  // ones that respect it we get a refresh_token back.  Auth0, Okta,
  // Keycloak all respect it; Google ignores it (uses access_type instead).
  if (!scopes.includes('offline_access')) scopes.push('offline_access');

  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', cfg.client_id);
  url.searchParams.set('redirect_uri', redirectUri());
  url.searchParams.set('scope', scopes.join(' '));
  url.searchParams.set('audience', cfg.audience);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);
  window.location.assign(url.toString());
}

async function handleCallback(cfg, discovery) {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  if (!code) return null;

  const pending = readPending();
  writePending(null);
  if (!pending || pending.state !== state) {
    writeTokens(null);
    throw new Error('auth callback: state mismatch');
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri(),
    client_id: cfg.client_id,
    code_verifier: pending.verifier,
  });
  const r = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!r.ok) {
    const detail = await r.text().catch(() => '');
    throw new Error(`token exchange failed: ${r.status}${detail ? ` — ${detail}` : ''}`);
  }
  const tokens = await r.json();
  writeTokens(toStorageShape(tokens));

  // Strip ?code=&state= from the URL bar so a refresh doesn't re-trigger
  // exchange (and so deep-link hashes survive).
  const url = new URL(window.location.href);
  url.search = '';
  url.hash = pending.returnTo || '';
  window.history.replaceState(null, '', url.toString());
  return tokens;
}

function toStorageShape(t) {
  // expires_in is seconds-from-now; convert to absolute epoch ms so a
  // sleeping tab doesn't keep using a token past its real expiry.
  const expSec = typeof t.expires_in === 'number' ? t.expires_in : 3600;
  return {
    access_token: t.access_token,
    refresh_token: t.refresh_token || null,
    expires_at: Date.now() + expSec * 1000,
    token_type: t.token_type || 'Bearer',
    scope: t.scope || null,
  };
}

// ──────────────────────────────────────────────────────────────────
// Silent refresh.  Falls through to a full re-redirect on failure.
// ──────────────────────────────────────────────────────────────────

async function refreshTokens(cfg, discovery) {
  const tokens = readTokens();
  if (!tokens?.refresh_token) return null;
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
    client_id: cfg.client_id,
  });
  const r = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!r.ok) return null;
  const next = await r.json();
  const merged = toStorageShape(next);
  // Some IdPs rotate the refresh token, others don't — preserve the
  // existing one when the response omits it.
  if (!merged.refresh_token) merged.refresh_token = tokens.refresh_token;
  writeTokens(merged);
  return merged;
}

function scheduleRefresh(cfg, discovery, onRedirect) {
  const tokens = readTokens();
  if (!tokens?.access_token) return;
  const ms = tokens.expires_at - Date.now() - REFRESH_LEEWAY_S * 1000;
  if (ms <= 0) {
    refreshTokens(cfg, discovery).then(t => {
      if (t) scheduleRefresh(cfg, discovery, onRedirect);
      else onRedirect();
    });
    return;
  }
  setTimeout(() => {
    refreshTokens(cfg, discovery).then(t => {
      if (t) scheduleRefresh(cfg, discovery, onRedirect);
      else onRedirect();
    });
  }, ms);
}

// ──────────────────────────────────────────────────────────────────
// AuthSession — what main.jsx waits on before mounting React.
// Returns { mode, getToken, logout } once the SPA has a usable token,
// or { mode: 'none' } when the deployment doesn't expose a browser-flow
// auth path (the SPA renders a "use the CLI" splash).
// ──────────────────────────────────────────────────────────────────

export async function bootstrapAuth() {
  const cfg = await loadAuthConfig();

  if (cfg.mode === 'none') {
    return { mode: 'none', getToken: () => null, logout: () => {} };
  }
  if (cfg.mode !== 'oidc') {
    throw new Error(`unknown auth mode: ${cfg.mode}`);
  }

  const discovery = await discoverIssuer(cfg.issuer);

  let tokens = readTokens();
  if (!tokens) {
    tokens = await handleCallback(cfg, discovery);
  }
  if (tokens && tokens.expires_at - Date.now() < REFRESH_LEEWAY_S * 1000) {
    tokens = await refreshTokens(cfg, discovery);
  }
  if (!tokens?.access_token) {
    await startAuthorizationFlow(cfg, discovery);
    // startAuthorizationFlow navigates away; nothing after this line
    // runs except in tests where the redirect is a no-op stub.
    return new Promise(() => {});
  }

  const onRedirect = () => startAuthorizationFlow(cfg, discovery).catch(() => {});
  scheduleRefresh(cfg, discovery, onRedirect);

  return {
    mode: 'oidc',
    getToken: () => readTokens()?.access_token || null,
    logout: () => {
      writeTokens(null);
      writePending(null);
      onRedirect();
    },
  };
}
