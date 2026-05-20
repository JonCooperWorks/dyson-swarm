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

  test('clean browser subpage paths route like their hash equivalents', () => {
    window.history.pushState(null, '', '/i/abc/tools');
    expect(parseHashView()).toEqual({ name: 'instance-tools', id: 'abc' });

    window.history.pushState(null, '', '/admin/mcp-catalog');
    expect(parseHashView()).toEqual({ name: 'admin-mcp-catalog', id: null });

    window.history.pushState(null, '', '/admin/mcp-catalog/github');
    expect(parseHashView()).toEqual({
      name: 'admin-mcp-catalog-edit',
      id: null,
      catalogId: 'github',
    });

    window.history.pushState(null, '', '/admin/skill-marketplaces/team-skills');
    expect(parseHashView()).toEqual({
      name: 'admin-skill-marketplace-edit',
      id: null,
      marketplaceId: 'team-skills',
    });
  });

  test('hash routes win when both path and hash are present', () => {
    window.history.pushState(null, '', '/i/abc/tools#/admin');
    expect(parseHashView()).toEqual({ name: 'admin', id: null });
  });

  test('every per-section URL gets its own view name', () => {
    const cases = {
      identity: 'instance-identity',
      model: 'instance-model',
      network: 'instance-network',
      tools: 'instance-tools',
      channels: 'instance-channels',
      mcp: 'instance-mcp',
      'agent-secrets': 'instance-agent-secrets',
      snapshots: 'instance-snapshots',
      skills: 'instance-skills',
    };
    for (const [slug, name] of Object.entries(cases)) {
      window.location.hash = `#/i/abc/${slug}`;
      expect(parseHashView()).toEqual({ name, id: 'abc' });
    }
  });

  test('removed runtime section URL falls back to instance summary', () => {
    window.location.hash = '#/i/abc/runtime';
    expect(parseHashView()).toEqual({ name: 'instance', id: 'abc' });
  });

  test('"#/new" routes to the dedicated hire page', () => {
    window.location.hash = '#/new';
    expect(parseHashView()).toEqual({ name: 'instance-new', id: null });
  });

  test('"#/admin" routes to the admin view', () => {
    window.location.hash = '#/admin';
    expect(parseHashView()).toEqual({ name: 'admin', id: null });
  });

  test('admin section routes get their own view names', () => {
    const cases = {
      'mcp-catalog': 'admin-mcp-catalog',
      'skill-marketplaces': 'admin-skill-marketplaces',
      users: 'admin-users',
      'proxy-tokens': 'admin-proxy-tokens',
      'kms-audit': 'admin-kms-audit',
    };
    for (const [slug, name] of Object.entries(cases)) {
      window.location.hash = `#/admin/${slug}`;
      expect(parseHashView()).toEqual({ name, id: null });
    }
  });

  test('"#/admin/mcp-catalog/*" routes to catalog section and editor pages', () => {
    window.location.hash = '#/admin/mcp-catalog';
    expect(parseHashView()).toEqual({ name: 'admin-mcp-catalog', id: null });

    window.location.hash = '#/admin/mcp-catalog/new';
    expect(parseHashView()).toEqual({ name: 'admin-mcp-catalog-new', id: null });

    window.location.hash = '#/admin/mcp-catalog/github%2Dtools';
    expect(parseHashView()).toEqual({
      name: 'admin-mcp-catalog-edit',
      id: null,
      catalogId: 'github-tools',
    });
  });

  test('"#/admin/skill-marketplaces/*" routes to marketplace editor pages', () => {
    window.location.hash = '#/admin/skill-marketplaces';
    expect(parseHashView()).toEqual({ name: 'admin-skill-marketplaces', id: null });

    window.location.hash = '#/admin/skill-marketplaces/new';
    expect(parseHashView()).toEqual({ name: 'admin-skill-marketplace-new', id: null });

    window.location.hash = '#/admin/skill-marketplaces/team%2Dskills';
    expect(parseHashView()).toEqual({
      name: 'admin-skill-marketplace-edit',
      id: null,
      marketplaceId: 'team-skills',
    });
  });

  test('"#/skills/*" routes to marketplace skill details', () => {
    window.location.hash = '#/skills/team%2Dskills/code%2Dreview';
    expect(parseHashView()).toEqual({
      name: 'marketplace-skill-detail',
      id: null,
      marketplace: 'team-skills',
      skill: 'code-review',
    });
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
