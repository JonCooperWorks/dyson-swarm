import { afterEach, describe, expect, test } from 'vitest';
import React from 'react';
import { cleanup, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import {
  artefactFilenameMap,
  ShareAccessLogPage,
  shareAccessLogHref,
  shareFilename,
  SharesPanel,
} from './shares.jsx';
import { ApiProvider } from '../hooks/useApi.jsx';

afterEach(() => { cleanup(); });

describe('share filename helpers', () => {
  test('uses artefact titles for shared table filenames', () => {
    const names = artefactFilenameMap([
      { id: 'a1', title: 'report.md' },
      { id: 'a2', title: '   ' },
    ]);

    expect(shareFilename({ artefact_id: 'a1' }, names)).toBe('report.md');
    expect(shareFilename({ artefact_id: 'a2' }, names)).toBe('a2');
    expect(shareFilename({ artefact_id: 'missing' }, names)).toBe('missing');
    expect(shareFilename({ artefact_id: 'a1', artefact_title: ' api.md ' }, new Map())).toBe('api.md');
  });

  test('builds a stable access-log route', () => {
    expect(shareAccessLogHref('inst/1', 'jti-123')).toBe('#/i/inst%2F1/shares/jti-123/log');
  });
});

describe('shared links UI', () => {
  test('renders filenames and routes log actions to the access-log page', async () => {
    const client = {
      listShares: () => Promise.resolve([
        {
          jti: 'jti-abc',
          artefact_id: 'a1',
          label: 'review copy',
          active: true,
          created_at: 0,
          expires_at: null,
          revoked_at: null,
        },
      ]),
    };

    render(
      <ApiProvider client={client} auth={{}}>
        <SharesPanel
          instanceId="inst"
          artefactRows={[{ id: 'a1', title: 'handoff.md' }]}
        />
      </ApiProvider>,
    );

    expect(await screen.findByText('handoff.md')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'log' })).toHaveAttribute(
      'href',
      '#/i/inst/shares/jti-abc/log',
    );
  });

  test('renders the standalone access log empty state', async () => {
    const client = {
      listShareAccesses: () => Promise.resolve([]),
      listShares: () => Promise.resolve([
        { jti: 'jti-empty', artefact_id: 'a-empty', active: true },
      ]),
      listInstanceArtefacts: () => Promise.resolve([
        { id: 'a-empty', title: 'empty-state.md' },
      ]),
    };

    render(
      <ApiProvider client={client} auth={{}}>
        <ShareAccessLogPage instanceId="inst" jti="jti-empty"/>
      </ApiProvider>,
    );

    expect(await screen.findByText('No accesses yet')).toBeInTheDocument();
    expect(screen.getByText('This shared link has not been opened.')).toBeInTheDocument();
    expect(await screen.findByText('empty-state.md')).toBeInTheDocument();
  });
});
