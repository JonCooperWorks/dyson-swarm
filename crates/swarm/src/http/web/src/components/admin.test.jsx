import { afterEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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
          description: '**GitHub** MCP tools with [docs](https://example.test/docs).',
          placeholders: [],
          source: 'admin',
          status: 'active',
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

    expect(await screen.findByRole('link', { name: 'add template' }))
      .toHaveAttribute('href', '#/admin/mcp-catalog/new');
    expect(await screen.findByRole('link', { name: 'edit' }))
      .toHaveAttribute('href', '#/admin/mcp-catalog/github');
    expect(await screen.findByRole('link', { name: 'docs' }))
      .toHaveAttribute('href', 'https://example.test/docs');
  });

  test('adds an admin Docker MCP template with payload placeholders on the full page', async () => {
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
          status: 'active',
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
          env: { GITHUB_TOKEN: 'YOUR_API_KEY_HERE' },
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
    expect(screen.getByText('selected JSON value')).toBeInTheDocument();
    expect(screen.getAllByText('YOUR_API_KEY_HERE').length).toBeGreaterThan(0);
    fireEvent.change(screen.getByLabelText('placeholder name'), {
      target: { value: 'github_token' },
    });
    fireEvent.change(screen.getByLabelText('friendly name'), {
      target: { value: 'GitHub token' },
    });
    expect(screen.getByText('{{placeholder.github_token}}')).toBeInTheDocument();
    expect(screen.queryByText(/credential/i)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'bind placeholder' }));
    await waitFor(() => expect(template.value).toContain('{{placeholder.github_token}}'));
    expect(template.value).toContain('"GITHUB_TOKEN": "{{placeholder.github_token}}"');
    expect(screen.getByText('github_token')).toBeInTheDocument();
    expect(screen.getByText('GitHub token')).toBeInTheDocument();
    expect(screen.getAllByText('servers.github.env.GITHUB_TOKEN').length).toBeGreaterThan(0);
    const bodyText = document.body.textContent;
    expect(bodyText.indexOf('saved placeholders')).toBeLessThan(bodyText.indexOf('payload path'));
    expect(bodyText.indexOf('GitHub token')).toBeLessThan(bodyText.indexOf('payload path'));
    fireEvent.click(within(screen.getByText('github_token').closest('.admin-catalog-placeholder-row')).getByRole('button', { name: 'delete' }));
    await waitFor(() => expect(template.value).not.toContain('{{placeholder.github_token}}'));
    expect(screen.queryByText('GitHub token')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /servers\.github\.env\.GITHUB_TOKEN/ }));
    fireEvent.change(screen.getByLabelText('placeholder name'), {
      target: { value: 'github_token' },
    });
    fireEvent.change(screen.getByLabelText('friendly name'), {
      target: { value: 'GitHub token' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'bind placeholder' }));
    await waitFor(() => expect(template.value).toContain('{{placeholder.github_token}}'));
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.adminPutMcpDockerCatalogServer).toHaveBeenCalledTimes(1));
    expect(client.adminPutMcpDockerCatalogServer).toHaveBeenCalledWith('github', {
      label: 'GitHub',
      description: 'GitHub MCP tools',
      template: expect.stringContaining('{{placeholder.github_token}}'),
      placeholders: [{
        id: 'github_token',
        label: 'GitHub token',
        description: null,
        required: true,
        secret: true,
        placeholder: null,
      }],
    });
    expect(window.location.hash).toBe('#/admin');
  });

  test('does not leak placeholders from an edited template into a fresh add page', async () => {
    const rows = [{
      id: 'brave',
      label: 'Brave',
      description: 'Search tools',
      template: JSON.stringify({
        servers: {
          brave: {
            type: 'stdio',
            command: 'docker',
            args: ['run', '--rm', '-i', '-e', 'BRAVE_API_KEY', 'docker.io/mcp/brave-search'],
            env: { BRAVE_API_KEY: '{{placeholder.brave_api_key}}' },
          },
        },
      }),
      placeholders: [{
        id: 'brave_api_key',
        label: 'Brave API key',
        required: true,
        secret: true,
      }],
      source: 'admin',
      status: 'active',
      created_at: 1,
      updated_at: 2,
    }];
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminRevokeProxyToken: vi.fn(),
      adminListMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: false, servers: rows }),
      adminPutMcpDockerCatalogServer: vi.fn(),
      adminDeleteMcpDockerCatalogServer: vi.fn(),
    };

    const { rerender } = render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-mcp-catalog-edit', catalogId: 'brave' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByText('Brave API key')).toBeInTheDocument();
    rerender(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-mcp-catalog-new' }}/>
      </ApiProvider>,
    );

    const template = await screen.findByLabelText('Docker MCP JSON template');
    expect(template).toHaveValue('');
    expect(screen.queryByText('Brave API key')).toBeNull();
    expect(screen.getByText('no template placeholders')).toBeInTheDocument();
  });

  test('shows pending Docker MCP requests in the same catalog panel', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminListMcpDockerCatalog: vi.fn().mockResolvedValue({
        allow_raw_json: false,
        servers: [{
          id: 'brave',
          label: 'Brave',
          template: '{"servers":{}}',
          description: 'Requested image',
          placeholders: [],
          source: 'user',
          status: 'pending',
          requested_by_user_id: 'user-1',
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

    expect(await screen.findByText('pending')).toBeInTheDocument();
    expect(screen.getByText(/requested by/)).toBeInTheDocument();
    expect(screen.getByText('user-1')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'edit' }))
      .toHaveAttribute('href', '#/admin/mcp-catalog/brave');
  });
});
