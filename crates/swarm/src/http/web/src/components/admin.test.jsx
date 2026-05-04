import { afterEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { AdminView } from './admin.jsx';

afterEach(() => {
  cleanup();
  window.location.hash = '';
});

describe('AdminView Docker MCP catalog', () => {
  test('links add and edit actions to dedicated catalog pages', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminListMcpDockerCatalog: vi.fn().mockResolvedValue({
        allow_raw_json: false,
        servers: [{
          id: 'github',
          label: 'GitHub',
          template: '{"servers":{}}',
          credentials: [],
          source: 'admin',
          created_at: 1,
          updated_at: 2,
        }],
      }),
      adminDeleteMcpDockerCatalogServer: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('link', { name: 'add preset' }))
      .toHaveAttribute('href', '#/admin/mcp-catalog/new');
    expect(await screen.findByRole('link', { name: 'edit' }))
      .toHaveAttribute('href', '#/admin/mcp-catalog/github');
  });

  test('adds an admin Docker MCP preset with credential placeholders on the full page', async () => {
    let rows = [];
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminRevokeProxyToken: vi.fn(),
      adminListMcpDockerCatalog: vi.fn(async () => ({ allow_raw_json: false, servers: rows })),
      adminPutMcpDockerCatalogServer: vi.fn(async (id, payload) => {
        rows = [{
          id,
          ...payload,
          source: 'admin',
          created_at: 1,
          updated_at: 2,
        }];
        return rows[0];
      }),
      adminDeleteMcpDockerCatalogServer: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-mcp-catalog-new' }}/>
      </ApiProvider>,
    );

    const template = await screen.findByLabelText('Docker MCP JSON template');
    expect(template).toHaveValue('');
    expect(template.getAttribute('placeholder')).toContain('"servers"');
    const baseTemplate = JSON.stringify({
      servers: {
        github: {
          type: 'stdio',
          command: 'docker',
          args: ['run', '--rm', '-i', '-e', 'GITHUB_TOKEN', 'ghcr.io/example/github-mcp'],
          env: { GITHUB_TOKEN: '' },
        },
      },
    });
    fireEvent.change(template, {
      target: {
        value: baseTemplate,
      },
    });
    fireEvent.change(screen.getByLabelText('id'), { target: { value: 'github' } });
    fireEvent.change(screen.getByLabelText('label'), { target: { value: 'GitHub' } });
    fireEvent.change(screen.getByLabelText('description'), {
      target: { value: 'GitHub MCP tools' },
    });
    fireEvent.click(screen.getByRole('button', { name: /servers\.github\.env\.GITHUB_TOKEN/ }));
    expect(screen.getByLabelText('payload path')).toHaveValue('servers.github.env.GITHUB_TOKEN');
    fireEvent.change(screen.getByLabelText('user field name'), {
      target: { value: 'github_token' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'bind credential' }));
    await waitFor(() => expect(template.value).toContain('{{credential.github_token}}'));
    expect(template.value).toContain('"GITHUB_TOKEN": "{{credential.github_token}}"');
    expect(screen.getByText('github_token')).toBeInTheDocument();
    expect(screen.getAllByText('servers.github.env.GITHUB_TOKEN').length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.adminPutMcpDockerCatalogServer).toHaveBeenCalledTimes(1));
    expect(client.adminPutMcpDockerCatalogServer).toHaveBeenCalledWith('github', {
      label: 'GitHub',
      description: 'GitHub MCP tools',
      template: expect.stringContaining('{{credential.github_token}}'),
      credentials: [{
        id: 'github_token',
        label: 'github_token',
        description: null,
        required: true,
        secret: true,
        placeholder: null,
      }],
    });
    expect(window.location.hash).toBe('#/admin');
  });
});
