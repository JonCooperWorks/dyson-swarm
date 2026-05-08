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
  test('links DB-backed skill marketplace sources to dedicated pages', async () => {
    const sources = [{
      id: 'team-skills',
      source_type: 'http',
      location: 'https://example.test/marketplace.json',
      enabled: true,
      created_at: 1,
      updated_at: 2,
      last_fetch_at: null,
      last_success_at: null,
      last_error: null,
    }];
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminListMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: false, servers: [] }),
      adminListSkillMarketplaces: vi.fn(async () => ({ sources })),
      adminPutSkillMarketplaceSource: vi.fn(),
      adminDeleteSkillMarketplaceSource: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView/>
      </ApiProvider>,
    );

    expect(await screen.findByText('skill marketplaces')).toBeInTheDocument();
    expect(await screen.findByText('team-skills')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'add marketplace' }))
      .toHaveAttribute('href', '#/admin/skill-marketplaces/new');
    expect(screen.getByRole('link', { name: 'edit' }))
      .toHaveAttribute('href', '#/admin/skill-marketplaces/team-skills');
  });

  test('shows an empty state for skill marketplaces', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminListMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: false, servers: [] }),
      adminListSkillMarketplaces: vi.fn(async () => ({ sources: [] })),
      adminPutSkillMarketplaceSource: vi.fn(),
      adminDeleteSkillMarketplaceSource: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'No skill marketplaces yet' }))
      .toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'add marketplace' }).length).toBeGreaterThan(0);
  });

  test('adds and edits skill marketplace sources on the full page', async () => {
    let sources = [{
      id: 'team-skills',
      source_type: 'http',
      location: 'https://example.test/marketplace.json',
      enabled: true,
      created_at: 1,
      updated_at: 2,
      last_fetch_at: null,
      last_success_at: null,
      last_error: null,
    }];
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminListSkillMarketplaces: vi.fn(async () => ({ sources })),
      adminPutSkillMarketplaceSource: vi.fn(async (id, payload) => {
        sources = [{ id, ...payload, created_at: 1, updated_at: 3 }];
        return sources[0];
      }),
    };

    const { rerender } = render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-skill-marketplace-new' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'add skill marketplace' }))
      .toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('id'), { target: { value: 'team-skills' } });
    fireEvent.change(screen.getByLabelText('type'), { target: { value: 'http' } });
    fireEvent.change(screen.getByLabelText('url'), {
      target: { value: 'https://example.test/marketplace.json' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.adminPutSkillMarketplaceSource).toHaveBeenCalledWith('team-skills', {
      source_type: 'http',
      location: 'https://example.test/marketplace.json',
      enabled: true,
    }));
    expect(window.location.hash).toBe('#/admin');

    window.location.hash = '';
    rerender(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-skill-marketplace-edit', marketplaceId: 'team-skills' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'edit team-skills' }))
      .toBeInTheDocument();
    expect(screen.getByLabelText('url')).toHaveValue('https://example.test/marketplace.json');
    fireEvent.change(screen.getByLabelText('url'), {
      target: { value: 'https://example.test/marketplace-v2.json' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.adminPutSkillMarketplaceSource).toHaveBeenLastCalledWith('team-skills', {
      source_type: 'http',
      location: 'https://example.test/marketplace-v2.json',
      enabled: true,
    }));
  });

  test('file source_type is no longer in the dropdown', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminListSkillMarketplaces: vi.fn(async () => ({ sources: [] })),
      adminPutSkillMarketplaceSource: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-skill-marketplace-new' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'add skill marketplace' }))
      .toBeInTheDocument();
    const type = screen.getByLabelText('type');
    expect(within(type).getByRole('option', { name: 'inline' })).toBeInTheDocument();
    expect(within(type).getByRole('option', { name: 'http' })).toBeInTheDocument();
    expect(within(type).queryByRole('option', { name: 'file' })).toBeNull();
  });

  test('inline marketplace with malformed JSON shows parse error and does not POST', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminListSkillMarketplaces: vi.fn(async () => ({ sources: [] })),
      adminPutSkillMarketplaceSource: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-skill-marketplace-new' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'add skill marketplace' }))
      .toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('id'), { target: { value: 'team-skills' } });
    const editor = screen.getByLabelText('marketplace index JSON');
    fireEvent.change(editor, { target: { value: '{ broken' } });
    fireEvent.blur(editor);
    expect(await screen.findByText(/parse error:/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'save' }));
    expect(client.adminPutSkillMarketplaceSource).not.toHaveBeenCalled();
  });

  test('inline marketplace with valid JSON sends source_type=inline and the JSON as location', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminListSkillMarketplaces: vi.fn(async () => ({ sources: [] })),
      adminPutSkillMarketplaceSource: vi.fn(),
    };
    const indexJson = '{"schema_version":1,"marketplace":{"id":"team-skills","name":"Team skills"},"skills":[]}';

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-skill-marketplace-new' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'add skill marketplace' }))
      .toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('id'), { target: { value: 'team-skills' } });
    fireEvent.change(screen.getByLabelText('marketplace index JSON'), {
      target: { value: indexJson },
    });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.adminPutSkillMarketplaceSource).toHaveBeenCalledWith('team-skills', {
      source_type: 'inline',
      location: indexJson,
      enabled: true,
    }));
  });

  test('http marketplace rejects non-https URL on submit', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminListSkillMarketplaces: vi.fn(async () => ({ sources: [] })),
      adminPutSkillMarketplaceSource: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-skill-marketplace-new' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'add skill marketplace' }))
      .toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('id'), { target: { value: 'team-skills' } });
    fireEvent.change(screen.getByLabelText('type'), { target: { value: 'http' } });
    fireEvent.change(screen.getByLabelText('url'), {
      target: { value: 'http://example.test/marketplace.json' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    expect(screen.getByText('marketplace url must use https')).toBeInTheDocument();
    expect(client.adminPutSkillMarketplaceSource).not.toHaveBeenCalled();
  });

  test('SkillMarketplaceEditorPage renders with the wide admin catalog class', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminPutSkillMarketplaceSource: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-skill-marketplace-new' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'add skill marketplace' }))
      .toBeInTheDocument();
    expect(document.querySelector('main.admin-catalog-page'))
      .toHaveClass('admin-catalog-page-wide');
  });

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

  test('Docker catalog form rejects non-object JSON template', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminRevokeProxyToken: vi.fn(),
      adminListMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: false, servers: [] }),
      adminPutMcpDockerCatalogServer: vi.fn(),
      adminDeleteMcpDockerCatalogServer: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-mcp-catalog-new' }}/>
      </ApiProvider>,
    );

    const template = await screen.findByLabelText('Docker MCP JSON template');
    fireEvent.change(screen.getByLabelText('id'), { target: { value: 'github' } });
    fireEvent.change(screen.getByLabelText('label'), { target: { value: 'GitHub' } });
    fireEvent.change(template, { target: { value: '[]' } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    expect(screen.getByText('template must be a JSON object')).toBeInTheDocument();
    expect(client.adminPutMcpDockerCatalogServer).not.toHaveBeenCalled();
  });

  test('Docker catalog form shows green status with placeholder count when template is valid', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminRevokeProxyToken: vi.fn(),
      adminListMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: false, servers: [] }),
      adminPutMcpDockerCatalogServer: vi.fn(),
      adminDeleteMcpDockerCatalogServer: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-mcp-catalog-new' }}/>
      </ApiProvider>,
    );

    const template = await screen.findByLabelText('Docker MCP JSON template');
    fireEvent.change(template, {
      target: {
        value: JSON.stringify({
          servers: {
            github: {
              type: 'stdio',
              command: 'docker',
              args: ['run', '--rm', '{{placeholder.github_image}}'],
            },
          },
        }),
      },
    });
    fireEvent.blur(template);

    expect(await screen.findByText('valid JSON (1 placeholder)')).toHaveClass('json-editor-status-ok');
  });

  test('Docker catalog form blocks submit when JSON template is malformed', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminRevokeProxyToken: vi.fn(),
      adminListMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: false, servers: [] }),
      adminPutMcpDockerCatalogServer: vi.fn(),
      adminDeleteMcpDockerCatalogServer: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-mcp-catalog-new' }}/>
      </ApiProvider>,
    );

    const template = await screen.findByLabelText('Docker MCP JSON template');
    fireEvent.change(screen.getByLabelText('id'), { target: { value: 'github' } });
    fireEvent.change(screen.getByLabelText('label'), { target: { value: 'GitHub' } });
    fireEvent.change(template, { target: { value: '{ broken' } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    expect(client.adminPutMcpDockerCatalogServer).not.toHaveBeenCalled();
    expect(screen.getByText(/Expected property name/)).toBeInTheDocument();
  });

  test('DockerCatalogEditorPage renders with the wide admin catalog class', async () => {
    const client = {
      adminListUsers: vi.fn().mockResolvedValue([]),
      adminRevokeProxyToken: vi.fn(),
      adminListMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: false, servers: [] }),
      adminPutMcpDockerCatalogServer: vi.fn(),
      adminDeleteMcpDockerCatalogServer: vi.fn(),
    };

    render(
      <ApiProvider client={client} auth={{ mode: 'none' }}>
        <AdminView view={{ name: 'admin-mcp-catalog-new' }}/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'add Docker MCP template' }))
      .toBeInTheDocument();
    expect(document.querySelector('main.admin-catalog-page'))
      .toHaveClass('admin-catalog-page-wide');
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
