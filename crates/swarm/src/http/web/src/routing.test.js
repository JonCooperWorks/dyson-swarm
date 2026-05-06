import { afterEach, describe, expect, test } from 'vitest';

import { canonicalizePathRoute, routeHashFromLocation } from './routing.js';

afterEach(() => {
  window.history.pushState(null, '', '/');
});

describe('routeHashFromLocation', () => {
  test('keeps hash routes unchanged', () => {
    window.history.pushState(null, '', '/i/abc/tools#/admin');
    expect(routeHashFromLocation()).toBe('#/admin');
  });

  test('maps clean instance subpage paths to hash routes', () => {
    window.history.pushState(null, '', '/i/abc/tools');
    expect(routeHashFromLocation()).toBe('#/i/abc/tools');
  });

  test('maps clean admin and top-level app paths to hash routes', () => {
    window.history.pushState(null, '', '/admin/mcp-catalog/brave');
    expect(routeHashFromLocation()).toBe('#/admin/mcp-catalog/brave');
    window.history.pushState(null, '', '/artifacts');
    expect(routeHashFromLocation()).toBe('#/artifacts');
  });

  test('does not treat arbitrary server paths as app routes', () => {
    window.history.pushState(null, '', '/auth/config');
    expect(routeHashFromLocation()).toBe('#/');
    window.history.pushState(null, '', '/newsletter');
    expect(routeHashFromLocation()).toBe('#/');
  });
});

describe('canonicalizePathRoute', () => {
  test('rewrites clean browser subpage paths into hash URLs', () => {
    window.history.pushState(null, '', '/i/abc/mcp?pane=docker');
    expect(canonicalizePathRoute()).toBe(true);
    expect(window.location.pathname).toBe('/');
    expect(window.location.search).toBe('');
    expect(window.location.hash).toBe('#/i/abc/mcp?pane=docker');
  });

  test('leaves existing hash URLs alone', () => {
    window.history.pushState(null, '', '/i/abc/mcp#/i/abc/tools');
    expect(canonicalizePathRoute()).toBe(false);
    expect(window.location.pathname).toBe('/i/abc/mcp');
    expect(window.location.hash).toBe('#/i/abc/tools');
  });
});
