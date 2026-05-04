/* Tests for hash-route parsing.
 *
 * Order matters: every section subroute (`#/i/<id>/identity`,
 * `#/i/<id>/network`, …) is a strict prefix of the bare detail
 * pattern (`#/i/<id>`), so a regression that reordered the matches
 * would silently mis-route a section URL to the summary view with
 * `view.id = "<id>"`.  These tests pin the happy paths and the
 * prefix-shadow case.
 */
import { afterEach, describe, expect, test } from 'vitest';

import { parseHashView } from './app.js';

afterEach(() => {
  // parseHashView reads window.location.hash; reset between tests
  // so leakage from one case doesn't influence the next.
  if (typeof window !== 'undefined') window.location.hash = '#/';
});

describe('parseHashView', () => {
  test('empty / "#/" routes to the instances list', () => {
    window.location.hash = '#/';
    expect(parseHashView()).toEqual({ name: 'instances', id: null });
  });

  test('"#/i/<id>" routes to the instance detail view', () => {
    window.location.hash = '#/i/fluffy-otter-042-4b26de';
    expect(parseHashView()).toEqual({
      name: 'instance',
      id: 'fluffy-otter-042-4b26de',
    });
  });

  test('"#/i/<id>/edit" is preserved as an alias of the identity section', () => {
    // Stale tabs land on the nearest retired edit surface without
    // reviving the old `instance-edit` route.
    window.location.hash = '#/i/fluffy-otter-042-4b26de/edit';
    expect(parseHashView()).toEqual({
      name: 'instance-identity',
      id: 'fluffy-otter-042-4b26de',
    });
  });

  test('"#/i/<id>/identity" routes to the identity section (NOT the detail view)', () => {
    window.location.hash = '#/i/abc/identity';
    expect(parseHashView()).toEqual({
      name: 'instance-identity',
      id: 'abc',
    });
  });

  test('every per-section URL gets its own view name', () => {
    const cases = {
      identity: 'instance-identity',
      model: 'instance-model',
      network: 'instance-network',
      tools: 'instance-tools',
      mcp: 'instance-mcp',
      snapshots: 'instance-snapshots',
      runtime: 'instance-runtime',
    };
    for (const [slug, name] of Object.entries(cases)) {
      window.location.hash = `#/i/abc/${slug}`;
      expect(parseHashView()).toEqual({ name, id: 'abc' });
    }
  });

  test('"#/new" routes to the dedicated hire page', () => {
    window.location.hash = '#/new';
    expect(parseHashView()).toEqual({ name: 'instance-new', id: null });
  });

  test('"#/admin" routes to the admin view', () => {
    window.location.hash = '#/admin';
    expect(parseHashView()).toEqual({ name: 'admin', id: null });
  });

  test('unknown paths fall back to the instances list', () => {
    window.location.hash = '#/something-bogus';
    expect(parseHashView()).toEqual({ name: 'instances', id: null });
  });

  test('decodes percent-encoded ids on both detail and section routes', () => {
    // Operator pastes a URL where the `-` survives encoding but
    // some other char in the slug got encoded — make sure we hand
    // a clean id back to downstream consumers.
    window.location.hash = '#/i/fluffy%2Dotter%2D042';
    expect(parseHashView().id).toBe('fluffy-otter-042');
    window.location.hash = '#/i/fluffy%2Dotter%2D042/network';
    expect(parseHashView()).toEqual({
      name: 'instance-network',
      id: 'fluffy-otter-042',
    });
  });

  test('"#/i/<id>/tasks" routes to the tasks list (NOT the detail view)', () => {
    // Same prefix-shadow concern as edit: every /tasks subroute
    // must match before the bare detail pattern.
    window.location.hash = '#/i/abc/tasks';
    expect(parseHashView()).toEqual({
      name: 'instance-tasks',
      id: 'abc',
      taskName: null,
    });
  });

  test('"#/i/<id>/tasks/new" routes to the new-task page', () => {
    window.location.hash = '#/i/abc/tasks/new';
    expect(parseHashView()).toEqual({
      name: 'instance-task-new',
      id: 'abc',
      taskName: null,
    });
  });

  test('"#/i/<id>/tasks/<name>" routes to the edit-task page', () => {
    window.location.hash = '#/i/abc/tasks/github-deploy';
    expect(parseHashView()).toEqual({
      name: 'instance-task-edit',
      id: 'abc',
      taskName: 'github-deploy',
    });
  });

  test('"#/i/<id>/shares/<jti>/log" routes to the share access log page', () => {
    window.location.hash = '#/i/abc/shares/jti%2D123/log';
    expect(parseHashView()).toEqual({
      name: 'share-access-log',
      id: 'abc',
      jti: 'jti-123',
    });
  });
});
