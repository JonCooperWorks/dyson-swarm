import { afterEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { AdminView } from './admin.jsx';

afterEach(() => { cleanup(); });

describe('AdminView Docker MCP catalog', () => {
  test('adds an admin Docker MCP preset with credential placeholders', async () => {
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
        <AdminView/>
      </ApiProvider>,
    );

    await screen.findByText('no Docker MCP presets.');
    fireEvent.click(screen.getByRole('button', { name: 'add preset' }));
    fireEvent.change(screen.getByLabelText('Docker MCP JSON template'), {
      target: {
        value: JSON.stringify({
          servers: {
            github: {
              type: 'stdio',
              command: 'docker',
              args: ['run', '--rm', '-i', '-e', 'GITHUB_TOKEN', 'ghcr.io/example/github-mcp'],
              env: { GITHUB_TOKEN: '{{credential.github_token}}' },
            },
          },
        }),
      },
    });
    fireEvent.change(screen.getByLabelText('id'), { target: { value: 'github' } });
    fireEvent.change(screen.getByLabelText('label'), { target: { value: 'GitHub' } });
    fireEvent.change(screen.getByLabelText('description'), {
      target: { value: 'GitHub MCP tools' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'add placeholder' }));
    fireEvent.change(screen.getByLabelText('placeholder 1 id'), {
      target: { value: 'github_token' },
    });
    fireEvent.change(screen.getByLabelText('placeholder 1 label'), {
      target: { value: 'GitHub token' },
    });
    fireEvent.change(screen.getByLabelText('placeholder 1 input placeholder'), {
      target: { value: 'ghp_...' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.adminPutMcpDockerCatalogServer).toHaveBeenCalledTimes(1));
    expect(client.adminPutMcpDockerCatalogServer).toHaveBeenCalledWith('github', {
      label: 'GitHub',
      description: 'GitHub MCP tools',
      template: expect.stringContaining('{{credential.github_token}}'),
      credentials: [{
        id: 'github_token',
        label: 'GitHub token',
        description: null,
        required: true,
        secret: true,
        placeholder: 'ghp_...',
      }],
    });
    await screen.findByText('GitHub');
  });
});
