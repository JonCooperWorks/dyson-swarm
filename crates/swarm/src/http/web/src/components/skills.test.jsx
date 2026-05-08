import { afterEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { MarketplaceSkillDetailPage, SkillCatalogRow } from './skills.jsx';

afterEach(() => {
  cleanup();
  window.location.hash = '';
});

describe('SkillCatalogRow', () => {
  test('links agent-authored marketplace skills back to the author instance', () => {
    render(
      <SkillCatalogRow
        skill={{
          marketplace_id: 'agent-axelrod',
          marketplace_name: 'Axelrod skills',
          name: 'debug-logs',
          version: '0.1.0',
          description: 'Read logs before guessing.',
          content_type: 'workspace',
          author: {
            name: 'Axelrod',
            instance_id: 'axelrod',
            href: '#/i/axelrod/skills',
          },
        }}
      />,
    );

    expect(screen.getByText('debug-logs')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /debug-logs/ }))
      .toHaveAttribute('href', '#/skills/agent-axelrod/debug-logs');
    expect(screen.getByText('learned by Axelrod')).toBeInTheDocument();
  });

  test('detail page renders metadata, markdown, and installs to a live instance', async () => {
    const skill = {
      marketplace_id: 'team-skills',
      marketplace_name: 'Team Skills',
      name: 'code-review',
      version: '1.0.0',
      description: 'Review code changes.',
      tags: ['review', 'code'],
      license: 'MIT',
      min_dyson_version: '0.1.0',
      sha256: 'declared',
      content_type: 'inline',
      author: null,
    };
    const client = {
      getMarketplaceSkill: vi.fn(async () => ({
        skill,
        preview: '# Code Review',
        computed_sha256: 'computed',
      })),
      getMarketplaceSkillContent: vi.fn(async () => ({
        marketplace_id: 'team-skills',
        marketplace_name: 'Team Skills',
        name: 'code-review',
        version: '1.0.0',
        description: 'Review code changes.',
        declared_sha256: 'declared',
        computed_sha256: 'computed',
        skill_md: '# Code Review\n\nUse this skill.',
      })),
      listMarketplaceSkills: vi.fn(async () => ({
        sources: [{ id: 'team-skills' }],
        skills: [skill],
        errors: [],
      })),
      listInstances: vi.fn(async () => ([
        { id: 'inst-1', name: 'Reviewer', status: 'live' },
      ])),
      listInstanceSkills: vi.fn(async () => []),
      installSkillToInstance: vi.fn(async () => ({
        installed: true,
        version: '1.0.0',
        sha256: 'computed',
      })),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <MarketplaceSkillDetailPage view={{ marketplace: 'team-skills', skill: 'code-review' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'code-review' })).toBeInTheDocument();
    expect(screen.getByText('declared')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Code Review' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Install to instance' }));
    expect(await screen.findByText('Reviewer')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Install selected' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Install selected' }));

    await waitFor(() => {
      expect(client.installSkillToInstance).toHaveBeenCalledWith('inst-1', {
        marketplace: 'team-skills',
        skill: 'code-review',
        force: false,
      });
    });
    expect(await screen.findByText('installed v1.0.0')).toBeInTheDocument();
  });
});
