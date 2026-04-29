/* Tests for the SPA's auth bootstrap.
 *
 * The interesting bits to lock down here are the Domain= calculation
 * for the session-mirror cookie (a too-broad value leaks the access
 * token to sibling subdomains under the parent), and the cookie's
 * required SameSite / Secure / Path attributes.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { computeCookieDomain, computeCookieAttributes, cookieDomainsToClear } from './auth.js';

afterEach(() => {
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
  test('sets Path=/, SameSite=Lax, Domain=<host>', () => {
    const out = computeCookieAttributes({
      host: 'swarm.example.com',
      protocol: 'https:',
    });
    expect(out).toContain('Path=/');
    expect(out).toContain('SameSite=Lax');
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
