/* Tests for hash-route parsing.
 *
 * Order matters: the edit pattern (`#/i/<id>/edit`) is a strict
 * prefix of the detail pattern (`#/i/<id>`), so a regression that
 * reordered the matches would silently mis-route the edit URL to
 * the detail view with `view.id = "<id>"`.  These tests pin the
 * happy paths and the prefix-shadow case.
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

  test('"#/i/<id>/edit" routes to the dedicated edit page (NOT the detail view)', () => {
    // Regression guard: an earlier ordering checked the detail
    // pattern first, so this URL silently parsed as the detail
    // view with `view.id = "<id>"` and the dedicated edit page
    // never rendered.
    window.location.hash = '#/i/fluffy-otter-042-4b26de/edit';
    expect(parseHashView()).toEqual({
      name: 'instance-edit',
      id: 'fluffy-otter-042-4b26de',
    });
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

  test('decodes percent-encoded ids on both detail and edit routes', () => {
    // Operator pastes a URL where the `-` survives encoding but
    // some other char in the slug got encoded — make sure we hand
    // a clean id back to downstream consumers.
    window.location.hash = '#/i/fluffy%2Dotter%2D042';
    expect(parseHashView().id).toBe('fluffy-otter-042');
    window.location.hash = '#/i/fluffy%2Dotter%2D042/edit';
    expect(parseHashView()).toEqual({
      name: 'instance-edit',
      id: 'fluffy-otter-042',
    });
  });
});
