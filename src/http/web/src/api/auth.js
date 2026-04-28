/* swarm — auth bootstrap for the SPA.
 *
 * Backend tells us via GET /auth/config which mode is active.  For OIDC
 * we run a textbook Authorization Code + PKCE flow against whatever IdP
 * the operator configured — Auth0, Okta, Keycloak, Entra, dex, take
 * your pick.  Swarm never sees plaintext credentials; it just verifies
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
 *   — every modern IdP serves it CORS-enabled.  This keeps swarm out
 *   of the IdP discovery business and avoids an unauthenticated
 *   server-side fetch with attacker-influenced URLs.
 */

const STORAGE_KEY = 'swarm:auth';
const PENDING_KEY = 'swarm:auth:pending';
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
  if (!tokens) {
    sessionStorage.removeItem(STORAGE_KEY);
    clearSessionCookie();
  } else {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(tokens));
    setSessionCookie(tokens.access_token, tokens.expires_at);
  }
}

// Mirror the access token into a Domain-scoped cookie so navigation to
// `<id>.<hostname>` (the per-Dyson reverse proxy in dyson_proxy.rs) can
// authenticate.  Anchor clicks, image loads, and URL-bar visits don't
// carry Authorization headers; the proxy reads this cookie as a Bearer
// fallback when the header is absent.
//
// Domain is derived from the apex hostname (everything after the first
// label), so the cookie is sent for both `apex.example.com` and every
// `<sub>.apex.example.com`.  SameSite=Lax keeps it off cross-site POSTs;
// the proxy has no state-changing cookie-only verbs anyway.  Secure
// gates it to HTTPS (the deployment is HTTPS-only via Caddy).
const COOKIE_NAME = 'dyson_swarm_session';
function cookieDomain() {
  const host = window.location.hostname;
  // No-op when running on localhost / a single-label host (cookies work
  // fine without an explicit Domain attribute in those cases).
  if (!host.includes('.') || /^[\d.]+$/.test(host)) return null;
  // Strip the leading label so the cookie covers parent + every sibling
  // subdomain.  e.g. host="dyson.myprivate.network" -> ".myprivate.network".
  // For a single-label-deep deployment ("foo.bar"), this yields ".bar"
  // which is fine — browsers reject TLD-only cookies anyway.
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  return parts.slice(1).join('.');
}
function setSessionCookie(token, expiresAtMs) {
  if (!token) return;
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'SameSite=Lax',
  ];
  if (window.location.protocol === 'https:') parts.push('Secure');
  const dom = cookieDomain();
  if (dom) parts.push(`Domain=${dom}`);
  if (expiresAtMs) parts.push(`Expires=${new Date(expiresAtMs).toUTCString()}`);
  document.cookie = parts.join('; ');
}
function clearSessionCookie() {
  const parts = [
    `${COOKIE_NAME}=`,
    'Path=/',
    'SameSite=Lax',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ];
  if (window.location.protocol === 'https:') parts.push('Secure');
  const dom = cookieDomain();
  if (dom) parts.push(`Domain=${dom}`);
  document.cookie = parts.join('; ');
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
    // Held only for `id_token_hint` on RP-initiated logout — never
    // sent to swarm's API.  Auth0's end_session endpoint accepts
    // logout without a hint but skips the consent screen with one.
    id_token: t.id_token || null,
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
    return { mode: 'none', config: cfg, getToken: () => null, logout: () => {}, isAdmin: false };
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

  // Every load — not just callback — re-stamps the parent-domain cookie
  // dyson_proxy reads when no Authorization header is present.
  // sessionStorage survives the redirect round-trip, but the cookie is
  // only set inside writeTokens(); mirror it here so a plain refresh
  // (where writeTokens never ran) still yields a usable cookie.
  setSessionCookie(tokens.access_token, tokens.expires_at);

  const onRedirect = () => startAuthorizationFlow(cfg, discovery).catch(() => {});
  scheduleRefresh(cfg, discovery, onRedirect);

  // Read the admin role out of the access token so the SPA can hide
  // privileged UI from non-admins.  Server still does its own check on
  // every /v1/admin/* request and returns 404 for non-admins (see
  // require_admin_role in src/auth/admin.rs); this is purely a UX
  // gate so legitimate admins don't see "no such endpoint" errors and
  // non-admins don't see clickable admin chrome that 404s back.
  const isAdmin = checkAdminClaim(readTokens()?.access_token, cfg);
  return {
    mode: 'oidc',
    config: cfg,
    getToken: () => readTokens()?.access_token || null,
    logout: () => signOut(cfg, discovery, onRedirect),
    isAdmin,
  };
}

/// Decode the JWT body (no verification — that's the server's job)
/// and check whether the configured admin claim contains the configured
/// admin role.  Returns false on any malformed input — fail closed.
function checkAdminClaim(token, cfg) {
  if (!token || !cfg?.admin_claim || !cfg?.admin_role) return false;
  const parts = token.split('.');
  if (parts.length < 2) return false;
  try {
    // base64url → base64 → JSON.  atob handles base64; we map -/_ → +/.
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '=='.slice((b64.length + 2) % 4);
    const claims = JSON.parse(atob(padded));
    const arr = claims[cfg.admin_claim];
    return Array.isArray(arr) && arr.includes(cfg.admin_role);
  } catch {
    return false;
  }
}

// RP-initiated logout (OIDC spec).  Clearing the SPA's tokens isn't
// enough on its own — the IdP still has a session cookie, so the
// next /authorize round-trip silently re-issues a token for the same
// user (classic "sign-out doesn't sign out" trap).  We redirect to
// the IdP's end_session_endpoint so it drops its own session, then
// it bounces back to `${origin}/` with no tokens, where bootstrapAuth
// kicks off a fresh authorization flow.
//
// Auth0 / Okta / Keycloak all expose end_session_endpoint via
// discovery.  IdPs that don't (rare these days) fall back to the old
// behavior — local-only logout — which is at least no worse than the
// previous implementation.
//
// `post_logout_redirect_uri` must be allowlisted on the IdP side
// (Auth0: Application → "Allowed Logout URLs").  When the IdP
// rejects the URL it 400s the redirect; the user lands on an error
// page instead of swarm's splash.
function signOut(cfg, discovery, onRedirect) {
  const tokens = readTokens();
  writeTokens(null);
  writePending(null);
  if (!discovery.end_session_endpoint) {
    onRedirect();
    return;
  }
  const url = new URL(discovery.end_session_endpoint);
  url.searchParams.set('client_id', cfg.client_id);
  url.searchParams.set('post_logout_redirect_uri', `${window.location.origin}/`);
  if (tokens?.id_token) url.searchParams.set('id_token_hint', tokens.id_token);
  window.location.assign(url.toString());
}
