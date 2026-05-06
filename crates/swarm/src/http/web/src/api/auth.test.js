/* Tests for the SPA's auth bootstrap.
 *
 * The interesting bits to lock down here are the Domain= calculation
 * for the session-mirror cookie (a too-broad value leaks the access
 * token to sibling subdomains under the parent), and the cookie's
 * required SameSite / Secure / Path attributes.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import {
  bootstrapAuth,
  computeCookieDomain,
  computeCookieAttributes,
  cookieDomainsToClear,
  handleCallback,
  parseReturnTo,
} from './auth.js';

afterEach(() => {
  sessionStorage.clear();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('computeCookieDomain', () => {
  test('returns null on a single-label host (no embedded "." → cookie scoped to host)', () => {
    expect(computeCookieDomain('localhost')).toBeNull();
  });

  test('returns null on a bare IPv4 address', () => {
    expect(computeCookieDomain('192.168.1.10')).toBeNull();
  });

  test('two-label hosts return the host itself (not just the TLD)', () => {
    // "foo.bar" — Domain=foo.bar covers foo.bar + every subdomain.
    expect(computeCookieDomain('foo.bar')).toBe('foo.bar');
  });

  test('three-label apex returns the host itself, NOT the parent', () => {
    // Regression: a previous version stripped the first label and
    // returned "example.com" — that would broadcast the session cookie
    // to wiki.example.com / status.example.com / etc., letting any
    // sibling app sniff the access token or fixate the session.  The
    // SPA runs on the apex; its subdomains (per-Dyson UIs) inherit by
    // virtue of being below the apex.
    expect(computeCookieDomain('swarm.example.com')).toBe('swarm.example.com');
  });

  test('four-label deployments still scope to their own apex', () => {
    expect(computeCookieDomain('swarm.myprivate.network')).toBe('swarm.myprivate.network');
    expect(computeCookieDomain('a.b.c.example.com')).toBe('a.b.c.example.com');
  });
});

describe('cookieDomainsToClear', () => {
  test('localhost / single-label only sweeps the host-only scope', () => {
    expect(cookieDomainsToClear('localhost')).toEqual([null]);
  });

  test('bare IPv4 only sweeps the host-only scope', () => {
    expect(cookieDomainsToClear('192.168.1.10')).toEqual([null]);
  });

  test('three-label apex sweeps host + parent (eTLD+1) but skips bare TLD', () => {
    // The parent sweep is the load-bearing one: an earlier SPA bug set
    // Domain=myprivate.network on every login, and those zombie cookies
    // shadow the new host-scoped one and surface as a stale-aud 401.
    expect(cookieDomainsToClear('swarm.myprivate.network')).toEqual([
      null,
      'swarm.myprivate.network', '.swarm.myprivate.network',
      'myprivate.network', '.myprivate.network',
    ]);
  });

  test('deeper hosts walk every parent down to eTLD+1', () => {
    expect(cookieDomainsToClear('a.b.c.example.com')).toEqual([
      null,
      'a.b.c.example.com', '.a.b.c.example.com',
      'b.c.example.com', '.b.c.example.com',
      'c.example.com', '.c.example.com',
      'example.com', '.example.com',
    ]);
  });
});

describe('computeCookieAttributes', () => {
  test('sets Path=/, SameSite=Strict, Domain=<host>', () => {
    const out = computeCookieAttributes({
      host: 'swarm.example.com',
      protocol: 'https:',
    });
    expect(out).toContain('Path=/');
    expect(out).toContain('SameSite=Strict');
    expect(out).toContain('Domain=swarm.example.com');
  });

  test('adds Secure on https origins', () => {
    const out = computeCookieAttributes({
      host: 'swarm.example.com',
      protocol: 'https:',
    });
    expect(out).toContain('Secure');
  });

  test('omits Secure on http (local dev) — browsers reject Secure over plaintext', () => {
    const out = computeCookieAttributes({
      host: 'localhost',
      protocol: 'http:',
    });
    expect(out).not.toContain('Secure');
  });

  test('omits Domain= on hosts where it would not apply', () => {
    const out = computeCookieAttributes({
      host: 'localhost',
      protocol: 'http:',
    });
    expect(out.find((p) => p.startsWith('Domain='))).toBeUndefined();
  });
});

describe('parseReturnTo', () => {
  // The proxy bounces logged-out browser GETs to
  // `https://<apex>/?return_to=https://<id>.<apex>/<path>`; this
  // validator is what stops a hostile param from turning the SPA
  // into an open redirect.

  const apex = 'swarm.example.com';

  test('accepts the apex itself', () => {
    expect(parseReturnTo('https://swarm.example.com/foo', apex))
      .toBe('https://swarm.example.com/foo');
  });

  test('accepts a single-label subdomain of the apex', () => {
    expect(parseReturnTo('https://abc123.swarm.example.com/path?x=1', apex))
      .toBe('https://abc123.swarm.example.com/path?x=1');
  });

  test('rejects http:// (cookie is Secure; Caddy redirects HTTP→HTTPS)', () => {
    expect(parseReturnTo('http://swarm.example.com/', apex)).toBeNull();
  });

  test('rejects multi-label prefixes (sandbox-of-a-sandbox)', () => {
    expect(parseReturnTo('https://a.b.swarm.example.com/', apex)).toBeNull();
  });

  test('rejects foreign hosts', () => {
    expect(parseReturnTo('https://evil.com/', apex)).toBeNull();
    // Substring-but-not-suffix attack — apex appears in the host but
    // the registrable domain is evil.com.
    expect(parseReturnTo('https://swarm.example.com.evil.com/', apex)).toBeNull();
  });

  test('rejects malformed / missing input', () => {
    expect(parseReturnTo(null, apex)).toBeNull();
    expect(parseReturnTo('', apex)).toBeNull();
    expect(parseReturnTo('not a url', apex)).toBeNull();
    expect(parseReturnTo('https://swarm.example.com/', null)).toBeNull();
  });
});

describe('handleCallback', () => {
  test('hands the subdomain session cookie to the server as HttpOnly state', async () => {
    window.history.pushState(null, '', '/?code=fresh-code&state=fresh-state#/i/abc');
    sessionStorage.setItem('swarm:auth:pending', JSON.stringify({
      verifier: 'verifier',
      state: 'fresh-state',
      returnTo: '#/i/abc',
      issuedAt: Date.now(),
    }));
    const fetch = vi.fn(async (url, opts = {}) => {
      if (url === 'https://issuer.example/token') {
        return new Response(JSON.stringify({
          access_token: 'access.jwt.token',
          refresh_token: 'refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (url === '/auth/session') {
        expect(opts.method).toBe('POST');
        expect(opts.headers.Authorization).toBe('Bearer access.jwt.token');
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch ${url}`);
    });
    vi.stubGlobal('fetch', fetch);

    await handleCallback(
      { client_id: 'client-id' },
      { token_endpoint: 'https://issuer.example/token' },
    );

    expect(fetch).toHaveBeenCalledWith('/auth/session', expect.objectContaining({
      method: 'POST',
    }));
    expect(document.cookie).not.toContain('dyson_swarm_session=');
  });

  test('recovers from stale callback state instead of trapping retry on the same URL', async () => {
    window.history.pushState(null, '', '/?code=old-code&state=old-state#/i/abc');
    sessionStorage.setItem('swarm:auth:pending', JSON.stringify({
      verifier: 'new-verifier',
      state: 'new-state',
      returnTo: '#/i/abc',
      issuedAt: Date.now(),
    }));
    sessionStorage.setItem('swarm:auth', JSON.stringify({
      access_token: 'stale-token',
      expires_at: Date.now() + 60_000,
    }));
    const fetch = vi.fn(() => Promise.resolve({ ok: true }));
    vi.stubGlobal('fetch', fetch);

    await expect(handleCallback(
      { client_id: 'client-id' },
      { token_endpoint: 'https://issuer.example/token' },
    )).resolves.toBeNull();

    expect(window.location.search).toBe('');
    expect(window.location.hash).toBe('#/i/abc');
    expect(sessionStorage.getItem('swarm:auth:pending')).toBeNull();
    expect(sessionStorage.getItem('swarm:auth')).toBeNull();
    expect(fetch).toHaveBeenCalledWith('/auth/session', expect.objectContaining({
      method: 'DELETE',
    }));
  });
});

describe('bootstrapAuth', () => {
  test('redeems a fresh callback before consulting stale cached tokens', async () => {
    vi.useFakeTimers();
    window.history.pushState(null, '', '/?code=fresh-code&state=fresh-state');
    sessionStorage.setItem('swarm:auth:pending', JSON.stringify({
      verifier: 'fresh-verifier',
      state: 'fresh-state',
      returnTo: '#/',
      issuedAt: Date.now(),
    }));
    sessionStorage.setItem('swarm:auth', JSON.stringify({
      access_token: 'stale-token',
      refresh_token: null,
      expires_at: Date.now() - 60_000,
      token_type: 'Bearer',
    }));

    const fetch = vi.fn(async (url, opts = {}) => {
      if (url === '/auth/config') {
        return new Response(JSON.stringify({
          mode: 'oidc',
          issuer: 'https://issuer.example',
          audience: 'swarm',
          client_id: 'spa-client',
          required_scopes: [],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (url === 'https://issuer.example/.well-known/openid-configuration') {
        return new Response(JSON.stringify({
          authorization_endpoint: 'https://issuer.example/authorize',
          token_endpoint: 'https://issuer.example/token',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (url === 'https://issuer.example/token') {
        expect(opts.method).toBe('POST');
        expect(String(opts.body)).toContain('grant_type=authorization_code');
        expect(String(opts.body)).toContain('code=fresh-code');
        expect(String(opts.body)).toContain('code_verifier=fresh-verifier');
        return new Response(JSON.stringify({
          access_token: 'fresh-token',
          refresh_token: 'fresh-refresh',
          expires_in: 3600,
          token_type: 'Bearer',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (url === '/auth/session') {
        expect(opts.headers.Authorization).toBe('Bearer fresh-token');
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch ${url}`);
    });
    vi.stubGlobal('fetch', fetch);

    const auth = await bootstrapAuth();

    expect(auth.getToken()).toBe('fresh-token');
    expect(window.location.search).toBe('');
    expect(sessionStorage.getItem('swarm:auth:pending')).toBeNull();
    expect(fetch).toHaveBeenCalledWith(
      'https://issuer.example/token',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});
