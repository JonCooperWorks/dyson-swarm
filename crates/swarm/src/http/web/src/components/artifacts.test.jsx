/* Regression coverage for the swarm-side artifact reader.  Most
 * artifacts are report-shaped Markdown, but cache metadata can arrive
 * as text/plain or with a charset suffix on the content type.  These
 * tests lock down the "render it like a document" path instead of
 * slipping back to a raw <pre>.
 */
import { describe, expect, test, afterEach, vi } from 'vitest';
import React from 'react';
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import {
  ArtifactTable,
  ArtifactBody,
  ArtifactActionsBar,
  activeSharesByArtifact,
  artifactShareKey,
  contentTypeBase,
  isMarkdownArtifact,
} from './artifacts.jsx';

afterEach(() => { cleanup(); });

describe('artifact markdown detection', () => {
  test('normalizes content types with charset parameters', () => {
    expect(contentTypeBase('text/markdown; charset=utf-8')).toBe('text/markdown');
  });

  test('treats markdown reports as markdown even when cached as text/plain', () => {
    expect(isMarkdownArtifact({
      kind: 'other',
      mime: 'text/plain; charset=utf-8',
      title: 'report.txt',
      text: '# Findings\n\n- [x] fixed',
    })).toBe(true);
  });

  test('does not render structured text formats through markdown heuristics', () => {
    expect(isMarkdownArtifact({
      kind: 'other',
      mime: 'application/json',
      title: 'payload.json',
      text: '{"heading":"# not markdown"}',
    })).toBe(false);
  });
});

describe('activeSharesByArtifact', () => {
  test('counts only live shared links per artifact', () => {
    const counts = activeSharesByArtifact([
      { instance_id: 'inst-a', chat_id: 'c1', artifact_id: 'a1', active: true, revoked_at: null },
      { instance_id: 'inst-a', chat_id: 'c1', artifact_id: 'a1', active: true, revoked_at: null },
      { instance_id: 'inst-a', chat_id: 'c1', artifact_id: 'a1', active: false, revoked_at: null },
      { instance_id: 'inst-a', chat_id: 'c1', artifact_id: 'a2', active: true, revoked_at: 123 },
      { instance_id: 'inst-a', chat_id: 'c2', artifact_id: 'a1', active: true, revoked_at: null },
    ]);

    expect(counts.get(artifactShareKey({ instance_id: 'inst-a', chat_id: 'c1', id: 'a1' }))).toBe(2);
    expect(counts.has(artifactShareKey({ instance_id: 'inst-a', chat_id: 'c1', id: 'a2' }))).toBe(false);
    expect(counts.get(artifactShareKey({ instance_id: 'inst-a', chat_id: 'c2', id: 'a1' }))).toBe(1);
  });
});

describe('ArtifactTable pagination', () => {
  test('shows one server page and advances through the pager', () => {
    const rows = Array.from({ length: 26 }, (_, i) => ({
      id: `art-${i}`,
      instance_id: 'inst-a',
      chat_id: 'c-0001',
      kind: 'other',
      title: `file-${i}.txt`,
      bytes: 100 + i,
      cached_at: 1000 + i,
    }));
    const onPage = vi.fn();

    render(
      <ArtifactTable
        rows={rows}
        page={1}
        client={{}}
        busy={false}
        setBusy={() => {}}
        setErr={() => {}}
        setMinted={() => {}}
        refresh={() => {}}
        showInstance={false}
        sweepClick={null}
        shareRows={[]}
        onPage={onPage}
      />,
    );

    expect(screen.getByText('file-0.txt')).toBeInTheDocument();
    expect(screen.queryByText('file-25.txt')).toBeNull();
    expect(screen.getByText(/page 1 · showing 1–25/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /next/i }));
    expect(onPage).toHaveBeenCalledWith(2);
  });

  test('marks rows with active shared links', () => {
    render(
      <ArtifactTable
        rows={[{
          id: 'art-1',
          instance_id: 'inst-a',
          chat_id: 'c-0001',
          kind: 'image',
          title: 'dyson.png',
          bytes: 1024,
          cached_at: 1000,
        }]}
        page={1}
        client={{}}
        busy={false}
        setBusy={() => {}}
        setErr={() => {}}
        setMinted={() => {}}
        refresh={() => {}}
        showInstance={false}
        sweepClick={null}
        shareRows={[
          { instance_id: 'inst-a', chat_id: 'c-0001', artifact_id: 'art-1', active: true, revoked_at: null },
          { instance_id: 'inst-a', chat_id: 'c-0001', artifact_id: 'art-1', active: true, revoked_at: null },
        ]}
      />,
    );

    expect(screen.getByText('shared 2')).toBeInTheDocument();
    expect(screen.getByText('dyson.png').closest('tr')).toHaveClass('artifact-row-shared');
  });

  test('does not mark a new artifact as shared when only the artifact id matches', () => {
    render(
      <ArtifactTable
        rows={[{
          id: 'art-1',
          instance_id: 'inst-a',
          chat_id: 'new-chat',
          kind: 'image',
          title: 'new.png',
          bytes: 1024,
          cached_at: 1000,
        }]}
        page={1}
        client={{}}
        busy={false}
        setBusy={() => {}}
        setErr={() => {}}
        setMinted={() => {}}
        refresh={() => {}}
        showInstance={false}
        sweepClick={null}
        shareRows={[
          { instance_id: 'inst-a', chat_id: 'old-chat', artifact_id: 'art-1', active: true, revoked_at: null },
        ]}
      />,
    );

    expect(screen.queryByText(/shared/)).toBeNull();
    expect(screen.getByText('new.png').closest('tr')).not.toHaveClass('artifact-row-shared');
  });

  test('keeps old and new artifacts with the same id separated by chat', () => {
    render(
      <ArtifactTable
        rows={[
          {
            id: 'art-1',
            instance_id: 'inst-a',
            chat_id: 'old-chat',
            kind: 'image',
            title: 'old.png',
            bytes: 1024,
            cached_at: 1000,
          },
          {
            id: 'art-1',
            instance_id: 'inst-a',
            chat_id: 'new-chat',
            kind: 'image',
            title: 'new.png',
            bytes: 1024,
            cached_at: 1001,
          },
        ]}
        page={1}
        client={{}}
        busy={false}
        setBusy={() => {}}
        setErr={() => {}}
        setMinted={() => {}}
        refresh={() => {}}
        showInstance={false}
        sweepClick={null}
        shareRows={[
          { instance_id: 'inst-a', chat_id: 'old-chat', artifact_id: 'art-1', active: true, revoked_at: null },
        ]}
      />,
    );

    expect(screen.getByText('old.png').closest('tr')).toHaveClass('artifact-row-shared');
    expect(screen.getByText('new.png').closest('tr')).not.toHaveClass('artifact-row-shared');
  });

  test('lets row sharing choose an expiry before minting', async () => {
    const client = {
      mintShare: vi.fn().mockResolvedValue({
        url: 'https://share.example.test/a',
        expires_at: 123,
      }),
      listShares: vi.fn().mockResolvedValue([]),
    };
    const setMinted = vi.fn();

    render(
      <ArtifactTable
        rows={[{
          id: 'art-1',
          instance_id: 'inst-a',
          chat_id: 'c-0001',
          kind: 'other',
          title: 'report.md',
          bytes: 1024,
          cached_at: 1000,
        }]}
        page={1}
        client={client}
        busy={false}
        setBusy={() => {}}
        setErr={() => {}}
        setMinted={setMinted}
        refresh={() => {}}
        showInstance={false}
        sweepClick={null}
        shareRows={[]}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: /share/i }));
    fireEvent.click(screen.getByRole('button', { name: '30 days' }));

    await waitFor(() => {
      expect(client.mintShare).toHaveBeenCalledWith('inst-a', 'art-1', {
        chat_id: 'c-0001',
        ttl: '30d',
        label: null,
      });
    });
    expect(setMinted).toHaveBeenCalledWith({
      url: 'https://share.example.test/a',
      expires_at: 123,
    });
  });
});

describe('ArtifactActionsBar', () => {
  test('keeps the detail share menu on the artifact action bar with clean expiry labels', () => {
    const { container } = render(
      <ArtifactActionsBar
        client={{ mintShare: vi.fn() }}
        row={{
          id: 'art-1',
          instance_id: 'inst-a',
          chat_id: 'c-0001',
          kind: 'other',
        }}
        state={{
          blob: new Blob(['body']),
          mime: 'text/plain',
          text: 'body',
        }}
        onDownload={() => {}}
      />,
    );

    expect(container.querySelector('.artifact-actions-bar')).not.toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /share/i }));

    expect(screen.getByRole('button', { name: 'never' })).toHaveAttribute('title', 'no expiry');
    expect(screen.queryByText(/revoke manually/i)).toBeNull();
  });
});

describe('ArtifactBody markdown rendering', () => {
  test('renders headings, task lists, and tables from text/plain markdown-ish reports', () => {
    const { container } = render(
      <ArtifactBody
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
      <ArtifactBody
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
