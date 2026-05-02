/* Regression coverage for the swarm-side artefact reader.  Most
 * artefacts are report-shaped Markdown, but cache metadata can arrive
 * as text/plain or with a charset suffix on the content type.  These
 * tests lock down the "render it like a document" path instead of
 * slipping back to a raw <pre>.
 */
import { describe, expect, test, afterEach } from 'vitest';
import React from 'react';
import { render, screen, cleanup } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import {
  ArtefactBody,
  activeSharesByArtefact,
  contentTypeBase,
  isMarkdownArtefact,
} from './artefacts.jsx';

afterEach(() => { cleanup(); });

describe('artefact markdown detection', () => {
  test('normalizes content types with charset parameters', () => {
    expect(contentTypeBase('text/markdown; charset=utf-8')).toBe('text/markdown');
  });

  test('treats markdown reports as markdown even when cached as text/plain', () => {
    expect(isMarkdownArtefact({
      kind: 'other',
      mime: 'text/plain; charset=utf-8',
      title: 'report.txt',
      text: '# Findings\n\n- [x] fixed',
    })).toBe(true);
  });

  test('does not render structured text formats through markdown heuristics', () => {
    expect(isMarkdownArtefact({
      kind: 'other',
      mime: 'application/json',
      title: 'payload.json',
      text: '{"heading":"# not markdown"}',
    })).toBe(false);
  });
});

describe('activeSharesByArtefact', () => {
  test('counts only live shared links per artefact', () => {
    const counts = activeSharesByArtefact([
      { artefact_id: 'a1', active: true, revoked_at: null },
      { artefact_id: 'a1', active: true, revoked_at: null },
      { artefact_id: 'a1', active: false, revoked_at: null },
      { artefact_id: 'a2', active: true, revoked_at: 123 },
      { artefact_id: 'a3', active: true, revoked_at: null },
    ]);

    expect(counts.get('a1')).toBe(2);
    expect(counts.has('a2')).toBe(false);
    expect(counts.get('a3')).toBe(1);
  });
});

describe('ArtefactBody markdown rendering', () => {
  test('renders headings, task lists, and tables from text/plain markdown-ish reports', () => {
    const { container } = render(
      <ArtefactBody
        row={{ kind: 'other', mime: null, title: 'report.txt' }}
        state={{
          loading: false,
          err: null,
          mime: 'text/plain; charset=utf-8',
          text: '# Findings\n\n- [x] patched\n\n| risk | status |\n| --- | --- |\n| high | fixed |',
          blob: null,
          blobUrl: null,
        }}
      />,
    );

    expect(screen.getByRole('heading', { name: 'Findings', level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('checkbox')).toBeDisabled();
    expect(container.querySelector('table')).not.toBeNull();
    expect(container.querySelector('pre')).toBeNull();
  });

  test('opens external markdown links in a new tab', () => {
    render(
      <ArtefactBody
        row={{ kind: 'security_review', mime: 'text/markdown', title: 'report.md' }}
        state={{
          loading: false,
          err: null,
          mime: 'text/markdown',
          text: '[NVD](https://nvd.nist.gov/)',
          blob: null,
          blobUrl: null,
        }}
      />,
    );

    const link = screen.getByRole('link', { name: 'NVD' });
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });
});
