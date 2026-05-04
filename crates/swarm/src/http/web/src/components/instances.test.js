/* Tests for the cube-profile dropdown label formatter.
 *
 * Lives next to its module so the operator-visible string stays
 * stable — the SPA is the only place an operator sees these
 * profiles, and a label change shouldn't sneak in via a refactor.
 */
import { describe, expect, test, afterEach, vi } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { setInstances, setSharesFor, setWebhooksFor } from '../store/app.js';
import {
  profileLabel,
  serializeMcpServers,
  splitMcpSetupRows,
  isAirgap,
  toolBlockedByNetwork,
  NETWORK_REQUIRED_TOOL_NAMES,
  initialTools,
  nextToolsForPolicyChange,
  DEFAULT_POLICY_KIND,
  POLICY_OPTIONS,
  CubeProfilePicker,
  McpServersPanel,
  NewInstanceForm,
  parseMcpCliJsonConfig,
  findCubeProfile,
  InstancesView,
  instanceRailHref,
  instanceSectionFromView,
} from './instances.jsx';

afterEach(() => {
  cleanup();
  window.history.pushState(null, '', '/');
  setInstances([]);
  setWebhooksFor('a', []);
  setSharesFor('a', []);
});

describe('instance subpage rail routing', () => {
  test('keeps sibling instance links on the active section', () => {
    expect(instanceRailHref('next-id', { name: 'instance-edit', id: 'current' }))
      .toBe('#/i/next-id/edit');
    expect(instanceRailHref('next-id', { name: 'instance-tasks', id: 'current' }))
      .toBe('#/i/next-id/tasks');
    expect(instanceRailHref('next-id', { name: 'share-access-log', id: 'current', jti: 'jti' }))
      .toBe('#/i/next-id/artefacts');
  });

  test('treats deep task and artefact pages as their parent section', () => {
    expect(instanceSectionFromView({ name: 'instance-task-edit', id: 'current', taskName: 'deploy' }))
      .toBe('tasks');
    expect(instanceSectionFromView({ name: 'instance-artefact', id: 'current', artefactId: 'a1' }))
      .toBe('artefacts');
  });

  test('renders an instance subpage inside the two-pane instance shell', async () => {
    const row = {
      id: 'a',
      name: 'Alpha',
      status: 'live',
      task: 'Run useful work.',
      created_at: 0,
      last_active_at: 0,
      last_probe_at: null,
      open_url: 'https://a.example.test',
      network_policy: { kind: 'nolocalnet', entries: [] },
    };
    setInstances([row, { ...row, id: 'b', name: 'Beta' }]);
    const client = {
      getInstance: () => Promise.resolve(row),
      listInstances: () => Promise.resolve([row]),
      listWebhooks: () => Promise.resolve([]),
      listShares: () => Promise.resolve([]),
    };

    render(
      React.createElement(ApiProvider, { client, auth: { config: { cube_profiles: [] } } },
        React.createElement(InstancesView, { view: { name: 'instance-tasks', id: 'a' } }),
      ),
    );

    expect(screen.getAllByText('Alpha').length).toBeGreaterThan(0);
    expect(screen.getByText('Beta')).toBeInTheDocument();
    expect(screen.getByText(/no webhooks yet/)).toBeInTheDocument();
    expect(screen.getByText('Beta').closest('a')).toHaveAttribute('href', '#/i/b/tasks');
  });

  test('offers an overview tab back to the agent overview', () => {
    const row = {
      id: 'a',
      name: 'Alpha',
      status: 'live',
      task: 'Run useful work.',
      created_at: 0,
      last_active_at: 0,
      last_probe_at: null,
      open_url: 'https://a.example.test',
      network_policy: { kind: 'nolocalnet', entries: [] },
    };
    setInstances([row]);
    const client = {
      getInstance: () => Promise.resolve(row),
      listInstances: () => Promise.resolve([row]),
      listWebhooks: () => Promise.resolve([]),
      listShares: () => Promise.resolve([]),
      listSnapshotsForInstance: () => Promise.resolve([]),
      listSecrets: () => Promise.resolve([]),
      listMcpServers: () => Promise.resolve([]),
    };

    render(
      React.createElement(ApiProvider, { client, auth: { config: { cube_profiles: [] } } },
        React.createElement(InstancesView, { view: { name: 'instance', id: 'a' } }),
      ),
    );

    const overview = screen.getByRole('link', { name: 'overview' });
    expect(overview).toHaveAttribute('href', '#/i/a');
    expect(overview).toHaveClass('btn-active');
  });

  test('does not highlight artefacts solely because shared links exist', async () => {
    const row = {
      id: 'a',
      name: 'Alpha',
      status: 'live',
      task: 'Run useful work.',
      created_at: 0,
      last_active_at: 0,
      last_probe_at: null,
      open_url: 'https://a.example.test',
      network_policy: { kind: 'nolocalnet', entries: [] },
    };
    setInstances([row]);
    setSharesFor('a', [{ jti: 'jti', artefact_id: 'art', active: true, revoked_at: null }]);
    const client = {
      getInstance: () => Promise.resolve(row),
      listInstances: () => Promise.resolve([row]),
      listWebhooks: () => Promise.resolve([]),
      listShares: () => Promise.resolve([{ jti: 'jti', artefact_id: 'art', active: true, revoked_at: null }]),
    };

    render(
      React.createElement(ApiProvider, { client, auth: { config: { cube_profiles: [] } } },
        React.createElement(InstancesView, { view: { name: 'instance-tasks', id: 'a' } }),
      ),
    );

    const artefacts = screen.getByRole('link', { name: /artefacts/i });
    expect(artefacts).not.toHaveClass('btn-active');
    expect(screen.getByLabelText('1 active shared')).toBeInTheDocument();
  });
});

describe('profileLabel', () => {
  test('renders the operator-facing tuple for a whole-cpu, whole-GB profile', () => {
    // cubemastercli memory unit is MB (decimal), so 2000 MB = 2 GB.
    expect(profileLabel({
      name: 'default',
      template_id: 'tpl-default',
      disk_gb: 5,
      cpu_millicores: 2000,
      memory_mb: 2000,
    })).toBe('default — 5 GB disk · 2 vCPU · 2 GB RAM');
  });

  test('formats fractional vcpu with one decimal', () => {
    // 1500 millicores = 1.5 vCPU — shouldn't read as "1 vCPU" or "2 vCPU".
    expect(profileLabel({
      name: 'small',
      template_id: 'tpl-small',
      disk_gb: 1,
      cpu_millicores: 1500,
      memory_mb: 1000,
    })).toBe('small — 1 GB disk · 1.5 vCPU · 1 GB RAM');
  });

  test('falls back to MB when memory is not a whole multiple of 1000', () => {
    // 1500 MB ≈ 1.5 GB — would round if we naively used integer division;
    // raw MB keeps the label honest.
    expect(profileLabel({
      name: 'odd',
      template_id: 'tpl-odd',
      disk_gb: 10,
      cpu_millicores: 4000,
      memory_mb: 1500,
    })).toBe('odd — 10 GB disk · 4 vCPU · 1500 MB RAM');
  });

  test('large profiles render correctly', () => {
    expect(profileLabel({
      name: 'xl',
      template_id: 'tpl-xl',
      disk_gb: 200,
      cpu_millicores: 8000,
      memory_mb: 16000,
    })).toBe('xl — 200 GB disk · 8 vCPU · 16 GB RAM');
  });

  test('returns empty string on a falsy profile', () => {
    // The dropdown maps over an array — defending against an
    // undefined entry keeps a malformed /auth/config response from
    // crashing the whole page.
    expect(profileLabel(null)).toBe('');
    expect(profileLabel(undefined)).toBe('');
  });
});

describe('findCubeProfile', () => {
  const PROFILES = [
    { name: 'default', template_id: 'tpl-default', disk_gb: 5, cpu_millicores: 2000, memory_mb: 2000 },
    { name: 'large', template_id: 'tpl-large', disk_gb: 10, cpu_millicores: 4000, memory_mb: 4000 },
  ];

  test('returns the matching profile by template_id', () => {
    expect(findCubeProfile('tpl-large', PROFILES).name).toBe('large');
  });

  test('returns null when no profile matches (retired tier or stale row)', () => {
    expect(findCubeProfile('tpl-vanished', PROFILES)).toBeNull();
  });

  test('returns null for missing inputs (legacy row, empty ladder, etc.)', () => {
    expect(findCubeProfile(null, PROFILES)).toBeNull();
    expect(findCubeProfile('tpl-default', [])).toBeNull();
    expect(findCubeProfile('tpl-default', null)).toBeNull();
    expect(findCubeProfile(undefined, undefined)).toBeNull();
  });
});

describe('CubeProfilePicker', () => {
  const PROFILES = [
    {
      name: 'small',
      template_id: 'tpl-small',
      disk_gb: 5,
      cpu_millicores: 1000,
      memory_mb: 512,
      description: 'General agents, light coding, chat.',
    },
    {
      name: 'default',
      template_id: 'tpl-default',
      disk_gb: 5,
      cpu_millicores: 2000,
      memory_mb: 2000,
      description: "Today's default — most agents.",
    },
    {
      // No description — exercises the "skip muted line" branch.
      name: 'bare',
      template_id: 'tpl-bare',
      disk_gb: 10,
      cpu_millicores: 4000,
      memory_mb: 4000,
    },
  ];

  // The JSX transform doesn't run on .js test files, so build the
  // element tree with React.createElement.  Avoids renaming this
  // file (and breaking the import path the snapshot CI happens to
  // pin in) while keeping the picker covered.
  const h = React.createElement;

  test('renders one card per profile with name + specs + description', () => {
    render(h(CubeProfilePicker, { profiles: PROFILES, value: 'tpl-default', onChange: () => {} }));
    // The user reads the tier name first ("default for the agent")
    // and the specs line confirms what they're getting.
    expect(screen.getByText('small')).toBeInTheDocument();
    expect(screen.getByText('default')).toBeInTheDocument();
    expect(screen.getByText(/5 GB disk · 2 vCPU · 2 GB RAM/)).toBeInTheDocument();
    expect(screen.getByText("Today's default — most agents.")).toBeInTheDocument();
    expect(screen.getByText('General agents, light coding, chat.')).toBeInTheDocument();
  });

  test('selected card carries the .selected class so the --accent border applies', () => {
    const { container } = render(
      h(CubeProfilePicker, { profiles: PROFILES, value: 'tpl-default', onChange: () => {} })
    );
    const selected = container.querySelectorAll('.cube-profile-radio.selected');
    expect(selected.length).toBe(1);
    expect(selected[0].textContent).toContain('default');
  });

  test('onChange fires with the new template_id when a card is clicked', () => {
    const calls = [];
    render(h(CubeProfilePicker, { profiles: PROFILES, value: 'tpl-default', onChange: (v) => calls.push(v) }));
    // Click the radio inside the small card.  Hit the input directly
    // so we don't depend on the label-wrapper's click-forwarding,
    // which jsdom occasionally fumbles.
    fireEvent.click(screen.getByDisplayValue('tpl-small'));
    expect(calls).toEqual(['tpl-small']);
  });

  test('omits the description line when the profile has no description', () => {
    const { container } = render(
      h(CubeProfilePicker, { profiles: [PROFILES[2]], value: 'tpl-bare', onChange: () => {} })
    );
    // The .cube-profile-desc span is the only carrier of the
    // description; absence of the field must not render an empty span.
    expect(container.querySelector('.cube-profile-desc')).toBeNull();
  });

  test('renders a single-tier deployment instead of hiding (drops the > 1 guard)', () => {
    render(h(CubeProfilePicker, { profiles: [PROFILES[1]], value: 'tpl-default', onChange: () => {} }));
    expect(screen.getByText('default')).toBeInTheDocument();
  });
});

describe('McpServersPanel', () => {
  const h = React.createElement;

  function renderPanel(client, props = {}) {
    const fullClient = {
      listMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: true, servers: [] }),
      ...client,
    };
    return render(
      h(ApiProvider, { client: fullClient, auth: { config: { cube_profiles: [] } } },
        h(McpServersPanel, {
          instanceId: 'inst-1',
          policyKind: 'nolocalnet',
          disabled: false,
          ...props,
        }),
      ),
    );
  }

  test('remote add flow stays field-based and does not use the JSON config endpoint', async () => {
    const calls = [];
    const client = {
      listMcpServers: vi.fn().mockResolvedValue([]),
      putMcpServer: vi.fn(async (...args) => { calls.push(args); return { ok: true }; }),
      putMcpJsonConfig: vi.fn(),
    };
    renderPanel(client);

    await screen.findByText('no MCP servers attached.');
    expect(screen.queryByLabelText('MCP JSON config')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'add' }));
    expect(screen.getByText('add mcp server')).toBeInTheDocument();
    expect(screen.queryByLabelText('MCP JSON config')).toBeNull();

    fireEvent.change(screen.getByLabelText('name'), { target: { value: 'linear' } });
    fireEvent.change(screen.getByLabelText('URL'), { target: { value: 'https://api.linear.app/mcp' } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.putMcpServer).toHaveBeenCalledTimes(1));
    expect(calls[0]).toEqual([
      'inst-1',
      'linear',
      {
        url: 'https://api.linear.app/mcp',
        auth: { kind: 'none' },
      },
    ]);
    expect(client.putMcpJsonConfig).not.toHaveBeenCalled();
  });

  test('Docker JSON add path is hidden when the catalog disallows raw JSON', async () => {
    const client = {
      listMcpServers: vi.fn().mockResolvedValue([]),
      listMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: false, servers: [] }),
      putMcpServer: vi.fn(),
      putMcpJsonConfig: vi.fn(),
    };
    renderPanel(client);

    await screen.findByText('no MCP servers attached.');
    fireEvent.click(screen.getByRole('button', { name: 'add' }));
    expect(screen.queryByRole('option', { name: 'Docker JSON' })).toBeNull();
    expect(screen.getByLabelText('MCP server type')).toHaveValue('remote');
  });

  test('Docker add path shows the JSON editor and saves through the single-server config API', async () => {
    let rows = [];
    const dockerConfig = {
      servers: {
        github: {
          type: 'stdio',
          command: 'docker',
          args: ['run', '-i', '--rm', 'ghcr.io/example/github-mcp'],
        },
      },
    };
    const client = {
      listMcpServers: vi.fn(async () => rows),
      putMcpServer: vi.fn(),
      putMcpJsonConfig: vi.fn(async () => {
        rows = [{
          name: 'github',
          url: 'docker://ghcr.io/example/github-mcp',
          server_type: 'docker',
          auth_kind: 'none',
          connected: true,
        }];
        return { ok: true };
      }),
    };
    renderPanel(client);

    await screen.findByText('no MCP servers attached.');
    fireEvent.click(screen.getByRole('button', { name: 'add' }));
    expect(screen.getByRole('option', { name: 'Docker JSON' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('MCP server type'), { target: { value: 'docker' } });

    const editor = screen.getByLabelText('MCP JSON config');
    expect(editor).toHaveValue('');
    expect(editor.getAttribute('placeholder')).toContain('<container-image>');
    expect(editor.getAttribute('placeholder')).not.toContain('ghcr.io/example/github-mcp');
    expect(screen.queryByLabelText('Example MCP JSON shape')).toBeNull();
    fireEvent.change(editor, { target: { value: JSON.stringify(dockerConfig, null, 2) } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.putMcpJsonConfig).toHaveBeenCalledTimes(1));
    expect(client.putMcpJsonConfig).toHaveBeenCalledWith('inst-1', dockerConfig);
    expect(client.putMcpServer).not.toHaveBeenCalled();
    await screen.findByText('github');
    expect(screen.queryByLabelText('MCP JSON config')).toBeNull();
  });

  test('Docker rows can be edited through their saved MCP JSON', async () => {
    const savedConfig = {
      servers: {
        github: {
          type: 'stdio',
          command: 'docker',
          args: ['run', '-i', '--rm', 'ghcr.io/example/github-mcp'],
        },
      },
    };
    const updatedConfig = {
      servers: {
        github: {
          type: 'stdio',
          command: 'docker',
          args: ['run', '--rm', '-i', '--entrypoint', 'python', 'ghcr.io/example/github-mcp', './entrypoint.py'],
        },
      },
    };
    const client = {
      listMcpServers: vi.fn().mockResolvedValue([{
        name: 'github',
        url: 'docker://ghcr.io/example/github-mcp',
        server_type: 'docker',
        auth_kind: 'none',
        connected: true,
      }]),
      getMcpJsonConfig: vi.fn().mockResolvedValue({ config: savedConfig }),
      putMcpJsonConfig: vi.fn().mockResolvedValue({ ok: true }),
      putMcpServer: vi.fn(),
    };
    renderPanel(client);

    await screen.findByText('github');
    fireEvent.click(screen.getByRole('button', { name: 'edit' }));

    await waitFor(() => expect(client.getMcpJsonConfig).toHaveBeenCalledWith('inst-1', 'github'));
    const editor = screen.getByLabelText('MCP JSON config');
    expect(editor).toHaveValue(JSON.stringify(savedConfig, null, 2));
    fireEvent.change(editor, { target: { value: JSON.stringify(updatedConfig, null, 2) } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.putMcpJsonConfig).toHaveBeenCalledWith('inst-1', updatedConfig));
    expect(client.putMcpServer).not.toHaveBeenCalled();
  });

  test('Docker catalog presets show read-only JSON and save only credentials', async () => {
    const catalog = {
      allow_raw_json: false,
      servers: [{
        id: 'github',
        label: 'GitHub',
        description: 'GitHub MCP tools',
        template: JSON.stringify({
          servers: {
            github: {
              type: 'stdio',
              command: 'docker',
              args: ['run', '--rm', '-i', '-e', 'GITHUB_TOKEN', 'ghcr.io/example/github-mcp'],
              env: { GITHUB_TOKEN: '{{credential.github_token}}' },
            },
          },
        }),
        credentials: [{
          id: 'github_token',
          label: 'GitHub token',
          required: true,
          secret: true,
        }],
      }],
    };
    let rows = [];
    const client = {
      listMcpServers: vi.fn(async () => rows),
      listMcpDockerCatalog: vi.fn().mockResolvedValue(catalog),
      putMcpDockerCatalogServer: vi.fn(async () => {
        rows = [{
          name: 'github',
          url: 'docker://ghcr.io/example/github-mcp',
          server_type: 'docker',
          docker_catalog_id: 'github',
          auth_kind: 'none',
          connected: true,
        }];
        return { ok: true, name: 'github' };
      }),
      putMcpJsonConfig: vi.fn(),
      putMcpServer: vi.fn(),
    };
    renderPanel(client);

    await screen.findByText('no MCP servers attached.');
    fireEvent.click(screen.getByRole('button', { name: 'add' }));
    fireEvent.change(screen.getByLabelText('MCP server type'), { target: { value: 'docker_catalog' } });

    expect(screen.getByDisplayValue(/ghcr\.io\/example\/github-mcp/)).toHaveAttribute('readonly');
    fireEvent.change(screen.getByLabelText('GitHub token'), { target: { value: 'ghp_secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(client.putMcpDockerCatalogServer).toHaveBeenCalledWith(
      'inst-1',
      'github',
      { github_token: 'ghp_secret' },
    ));
    expect(client.putMcpJsonConfig).not.toHaveBeenCalled();
    await screen.findByText('github');
  });

  test('Docker catalog rows with no placeholders have no edit surface', async () => {
    const client = {
      listMcpServers: vi.fn().mockResolvedValue([{
        name: 'github',
        url: 'docker://ghcr.io/example/github-mcp',
        server_type: 'docker',
        docker_catalog_id: 'github',
        auth_kind: 'none',
        connected: true,
      }]),
      listMcpDockerCatalog: vi.fn().mockResolvedValue({
        allow_raw_json: false,
        servers: [{
          id: 'github',
          label: 'GitHub',
          template: JSON.stringify({
            servers: {
              github: {
                type: 'stdio',
                command: 'docker',
                args: ['run', '--rm', '-i', 'ghcr.io/example/github-mcp'],
              },
            },
          }),
          credentials: [],
        }],
      }),
      getMcpJsonConfig: vi.fn(),
      putMcpJsonConfig: vi.fn(),
      putMcpServer: vi.fn(),
    };
    renderPanel(client);

    await screen.findByText('github');
    expect(screen.queryByRole('button', { name: 'edit' })).toBeNull();
    expect(client.getMcpJsonConfig).not.toHaveBeenCalled();
  });

  test('Docker add path does not submit the grey example when the editor is empty', async () => {
    const client = {
      listMcpServers: vi.fn().mockResolvedValue([]),
      putMcpServer: vi.fn(),
      putMcpJsonConfig: vi.fn(),
    };
    renderPanel(client);

    await screen.findByText('no MCP servers attached.');
    fireEvent.click(screen.getByRole('button', { name: 'add' }));
    fireEvent.change(screen.getByLabelText('MCP server type'), { target: { value: 'docker' } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    expect(await screen.findByText(/before saving/)).toBeInTheDocument();
    expect(client.putMcpJsonConfig).not.toHaveBeenCalled();
    expect(client.putMcpServer).not.toHaveBeenCalled();
  });

  test('Docker JSON editor rejects HTTP configs so remote servers stay on the remote API path', async () => {
    const client = {
      listMcpServers: vi.fn().mockResolvedValue([]),
      putMcpServer: vi.fn(),
      putMcpJsonConfig: vi.fn(),
    };
    renderPanel(client);

    await screen.findByText('no MCP servers attached.');
    fireEvent.click(screen.getByRole('button', { name: 'add' }));
    fireEvent.change(screen.getByLabelText('MCP server type'), { target: { value: 'docker' } });
    fireEvent.change(screen.getByLabelText('MCP JSON config'), {
      target: {
        value: JSON.stringify({
          servers: {
            linear: {
              type: 'http',
              url: 'https://api.linear.app/mcp',
            },
          },
        }),
      },
    });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    expect(await screen.findByText(/Use the remote MCP form/)).toBeInTheDocument();
    expect(client.putMcpJsonConfig).not.toHaveBeenCalled();
    expect(client.putMcpServer).not.toHaveBeenCalled();
  });
});

describe('parseMcpCliJsonConfig', () => {
  test('accepts Claude-style mcpServers configs', () => {
    const config = {
      mcpServers: {
        massive: {
          command: 'docker',
          args: ['run', '--rm', '-i', 'joncooperworks/mcp_massive:latest'],
        },
      },
    };

    expect(parseMcpCliJsonConfig(JSON.stringify(config))).toEqual(config);
  });

  test('rejects configs with both server maps', () => {
    const config = {
      servers: {},
      mcpServers: {
        massive: {
          command: 'docker',
          args: ['run', 'joncooperworks/mcp_massive:latest'],
        },
      },
    };

    expect(() => parseMcpCliJsonConfig(JSON.stringify(config))).toThrow(/either `servers` or `mcpServers`/);
  });
});

describe('serializeMcpServers', () => {
  test('returns an empty array when no rows are configured', () => {
    expect(serializeMcpServers([])).toEqual([]);
  });

  test('drops rows missing a name or url so partial form state never reaches swarm', () => {
    // The hire form lets the user click "+ add" without typing anything;
    // we don't want a `{name:"", url:""}` to land in the wire payload
    // and then 400 on the server side — silently dropping is the right
    // call here because the user can see the row is empty.
    const rows = [
      { id: 'a', name: '', url: 'https://x', auth: { kind: 'none' } },
      { id: 'b', name: 'x', url: '', auth: { kind: 'none' } },
      { id: 'c', name: 'y', url: 'https://y', auth: { kind: 'none' } },
    ];
    const out = serializeMcpServers(rows);
    expect(out).toEqual([{ name: 'y', url: 'https://y', auth: { kind: 'none' } }]);
  });

  test('serializes a bearer server with the token verbatim', () => {
    const rows = [
      {
        id: 'b1',
        name: 'linear',
        url: 'https://api.linear.app/mcp',
        auth: { kind: 'bearer', token: 'lin_xxx' },
      },
    ];
    expect(serializeMcpServers(rows)).toEqual([
      {
        name: 'linear',
        url: 'https://api.linear.app/mcp',
        auth: { kind: 'bearer', token: 'lin_xxx' },
      },
    ]);
  });

  test('drops a bearer row with an empty token (would fail upstream auth anyway)', () => {
    const rows = [
      { id: 'b', name: 'x', url: 'https://x', auth: { kind: 'bearer', token: '   ' } },
    ];
    expect(serializeMcpServers(rows)).toEqual([]);
  });

  test('parses oauth scopes (comma- and space-tolerant) and omits empty discovery fields', () => {
    // The minimal OAuth shape: discovery + DCR.  Empty client_id /
    // endpoint fields must NOT appear in the wire JSON, because the
    // server-side serde defaults treat absent and `null` differently —
    // an empty string would land as `Some("")` and break URL parsing.
    const rows = [
      {
        id: 'o1',
        name: 'github',
        url: 'https://copilot-api.githubusercontent.com/mcp',
        auth: {
          kind: 'oauth',
          scopes: 'read,write   user',
          client_id: '',
          client_secret: '',
          authorization_url: '',
          token_url: '',
          registration_url: '',
        },
      },
    ];
    expect(serializeMcpServers(rows)).toEqual([
      {
        name: 'github',
        url: 'https://copilot-api.githubusercontent.com/mcp',
        auth: { kind: 'oauth', scopes: ['read', 'write', 'user'] },
      },
    ]);
  });

  test('preserves explicitly-supplied OAuth endpoints + client_id', () => {
    const rows = [
      {
        id: 'o2',
        name: 'gh',
        url: 'https://up/mcp',
        auth: {
          kind: 'oauth',
          scopes: '',
          client_id: 'my-client',
          client_secret: 's3cret',
          authorization_url: 'https://auth/x',
          token_url: 'https://auth/t',
          registration_url: '',
        },
      },
    ];
    expect(serializeMcpServers(rows)).toEqual([
      {
        name: 'gh',
        url: 'https://up/mcp',
        auth: {
          kind: 'oauth',
          scopes: [],
          client_id: 'my-client',
          client_secret: 's3cret',
          authorization_url: 'https://auth/x',
          token_url: 'https://auth/t',
        },
      },
    ]);
  });
});

describe('splitMcpSetupRows', () => {
  test('separates hire-time remote specs from Docker JSON configs', () => {
    const dockerConfig = {
      mcpServers: {
        massive: {
          command: 'docker',
          args: ['run', '--rm', '-i', 'joncooperworks/mcp_massive:latest'],
        },
      },
    };

    expect(splitMcpSetupRows([
      {
        id: 'remote',
        serverType: 'remote',
        name: 'linear',
        url: 'https://api.linear.app/mcp',
        auth: { kind: 'none' },
      },
      {
        id: 'docker',
        serverType: 'docker',
        jsonText: JSON.stringify(dockerConfig),
      },
    ])).toEqual({
      remote: [{
        name: 'linear',
        url: 'https://api.linear.app/mcp',
        auth: { kind: 'none' },
      }],
      dockerConfigs: [dockerConfig],
      dockerCatalogServers: [],
    });
  });

  test('rejects duplicate names across remote and Docker setup rows', () => {
    const dockerConfig = {
      servers: {
        linear: {
          type: 'stdio',
          command: 'docker',
          args: ['run', '--rm', '-i', 'ghcr.io/example/linear-mcp'],
        },
      },
    };

    expect(() => splitMcpSetupRows([
      {
        id: 'remote',
        serverType: 'remote',
        name: 'linear',
        url: 'https://api.linear.app/mcp',
        auth: { kind: 'none' },
      },
      {
        id: 'docker',
        serverType: 'docker',
        jsonText: JSON.stringify(dockerConfig),
      },
    ])).toThrow(/configured more than once/);
  });

  test('collects Docker catalog credentials without sending rendered JSON', () => {
    const catalog = {
      servers: [{
        id: 'github',
        label: 'GitHub',
        template: JSON.stringify({
          servers: {
            github: {
              type: 'stdio',
              command: 'docker',
              args: ['run', '--rm', '-i', 'ghcr.io/example/github-mcp'],
              env: { GITHUB_TOKEN: '{{credential.github_token}}' },
            },
          },
        }),
        credentials: [{
          id: 'github_token',
          label: 'GitHub token',
          required: true,
          secret: true,
        }],
      }],
    };

    expect(splitMcpSetupRows([
      {
        id: 'catalog',
        serverType: 'docker_catalog',
        catalogId: 'github',
        credentials: { github_token: 'ghp_secret' },
      },
    ], catalog)).toEqual({
      remote: [],
      dockerConfigs: [],
      dockerCatalogServers: [{
        catalogId: 'github',
        credentials: { github_token: 'ghp_secret' },
      }],
    });
  });
});

describe('NewInstanceForm MCP setup', () => {
  test('lets a new agent attach a Docker MCP server before redirecting', async () => {
    const dockerConfig = {
      servers: {
        github: {
          type: 'stdio',
          command: 'docker',
          args: ['run', '--rm', '-i', 'ghcr.io/example/github-mcp'],
        },
      },
    };
    const client = {
      createInstance: vi.fn().mockResolvedValue({
        id: 'inst-1',
        url: 'https://inst-1.swarm.example',
      }),
      putMcpJsonConfig: vi.fn().mockResolvedValue({ ok: true }),
      probeInstance: vi.fn().mockResolvedValue({ status: 'healthy' }),
      listMcpDockerCatalog: vi.fn().mockResolvedValue({ allow_raw_json: true, servers: [] }),
    };

    render(React.createElement(
      ApiProvider,
      {
        client,
        auth: {
          config: {
            default_models: ['openai/gpt-5.1'],
            default_template_id: 'tpl-default',
            cube_profiles: [],
          },
        },
      },
      React.createElement(NewInstanceForm),
    ));

    fireEvent.click(screen.getByRole('button', { name: /add MCP server/i }));
    await screen.findByRole('option', { name: 'Docker JSON' });
    fireEvent.change(screen.getByLabelText('MCP server type'), { target: { value: 'docker' } });
    expect(screen.getByText('docker config')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('MCP JSON config'), {
      target: { value: JSON.stringify(dockerConfig, null, 2) },
    });
    expect(screen.getByText('github')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'create agent' }));

    await waitFor(() => expect(client.createInstance).toHaveBeenCalledTimes(1));
    expect(client.createInstance.mock.calls[0][0]).not.toHaveProperty('mcp_servers');
    await waitFor(() => expect(client.putMcpJsonConfig).toHaveBeenCalledWith('inst-1', dockerConfig));
    expect(client.probeInstance).toHaveBeenCalledWith('inst-1');
  });
});

describe('isAirgap', () => {
  test('only the literal "airgap" kind counts as airgapped', () => {
    expect(isAirgap('airgap')).toBe(true);
    // The four other policy kinds let some traffic through, so a
    // tool that "needs network" still has a path.
    expect(isAirgap('open')).toBe(false);
    expect(isAirgap('nolocalnet')).toBe(false);
    expect(isAirgap('allowlist')).toBe(false);
    expect(isAirgap('denylist')).toBe(false);
  });

  test('null / undefined / unknown kinds are treated as not airgap', () => {
    // Defensive: a row with a missing or unrecognised policy kind
    // should fall through to "not airgap" rather than greying out
    // the whole tool list.
    expect(isAirgap(null)).toBe(false);
    expect(isAirgap(undefined)).toBe(false);
    expect(isAirgap('unknown')).toBe(false);
  });
});

describe('NETWORK_REQUIRED_TOOL_NAMES', () => {
  test('exposes exactly the tools that need public-internet egress', () => {
    // This is the contract the SPA uses to grey out cells under
    // airgap; tightening it should be a deliberate edit, not a
    // silent slide.  Order matches TOOL_CATALOGUE.
    expect(NETWORK_REQUIRED_TOOL_NAMES).toEqual([
      'web_fetch',
      'web_search',
      'image_generate',
      'dependency_scan',
      // Subagents whose prompts/tools assume reachable upstream:
      // researcher uses web_search; dependency_review hits OSV;
      // coder pulls deps mid-fix.  planner / verifier /
      // security_engineer are offline-capable so they're absent.
      'researcher',
      'dependency_review',
      'coder',
    ]);
  });
});

describe('toolBlockedByNetwork', () => {
  test('marks every network-required tool blocked under airgap', () => {
    // The picker's "blocked" treatment hangs off this — a tool
    // that needs network can't reach upstream when the cube is
    // airgapped, so the operator gets the visual cue.
    for (const name of NETWORK_REQUIRED_TOOL_NAMES) {
      expect(toolBlockedByNetwork(name, 'airgap')).toBe(true);
    }
  });

  test('does not block tools that work offline, even under airgap', () => {
    // Filesystem / KB / AST tools all run in-cube with no upstream.
    expect(toolBlockedByNetwork('bash', 'airgap')).toBe(false);
    expect(toolBlockedByNetwork('read_file', 'airgap')).toBe(false);
    expect(toolBlockedByNetwork('ast_query', 'airgap')).toBe(false);
    expect(toolBlockedByNetwork('kb_search', 'airgap')).toBe(false);
  });

  test('does not block any tool when the policy permits egress', () => {
    // Open / nolocalnet / allowlist / denylist all let *some*
    // traffic through, so we leave the picker alone — the operator
    // is on the hook for verifying their allow/deny entries.
    for (const kind of ['open', 'nolocalnet', 'allowlist', 'denylist']) {
      for (const name of NETWORK_REQUIRED_TOOL_NAMES) {
        expect(toolBlockedByNetwork(name, kind)).toBe(false);
      }
    }
  });

  test('an unknown tool name is never blocked', () => {
    // Forward-compat: a future dyson tool the SPA doesn't know
    // about shouldn't get spuriously greyed out — opt-in only.
    expect(toolBlockedByNetwork('future_tool', 'airgap')).toBe(false);
  });

  test('offline-capable subagents are not blocked under airgap', () => {
    // planner / verifier / security_engineer all run from local
    // file inputs and don't pull upstream.  Greying them out
    // would mislead an operator who explicitly wants an offline
    // hardened review under airgap.
    expect(toolBlockedByNetwork('planner', 'airgap')).toBe(false);
    expect(toolBlockedByNetwork('verifier', 'airgap')).toBe(false);
    expect(toolBlockedByNetwork('security_engineer', 'airgap')).toBe(false);
  });

  test('subagents that need upstream are blocked under airgap', () => {
    expect(toolBlockedByNetwork('researcher', 'airgap')).toBe(true);
    expect(toolBlockedByNetwork('dependency_review', 'airgap')).toBe(true);
    expect(toolBlockedByNetwork('coder', 'airgap')).toBe(true);
  });
});

describe('initialTools', () => {
  test('uses the row\'s persisted positive list verbatim', () => {
    const row = { tools: ['bash', 'read_file'] };
    expect(initialTools(row, 'open')).toEqual(['bash', 'read_file']);
  });

  test('empty list on a non-airgap row defaults to every tool ticked', () => {
    // "Use dyson defaults" — operator hasn't trimmed the toolbox,
    // so the picker shows all builtins as enabled.
    const row = { tools: [] };
    const got = initialTools(row, 'nolocalnet');
    expect(got).toContain('bash');
    expect(got).toContain('web_fetch');
    expect(got).toContain('researcher');
    expect(got.length).toBeGreaterThan(20);
  });

  test('empty list on an airgap row stays empty', () => {
    // Airgap default is "opt in tool by tool" — pre-filling all
    // would give the operator a worse starting point than what
    // the row already represents.
    const row = { tools: [] };
    expect(initialTools(row, 'airgap')).toEqual([]);
  });

  test('null row + airgap kind starts empty (new-instance airgap path)', () => {
    expect(initialTools(null, 'airgap')).toEqual([]);
  });

  test('null row + non-airgap kind starts with every tool ticked', () => {
    const got = initialTools(null, 'open');
    expect(got.length).toBeGreaterThan(20);
    expect(got).toContain('bash');
  });
});

describe('nextToolsForPolicyChange', () => {
  test('clears the picker on transition INTO airgap', () => {
    // The ergonomic guard from the hire form, ported to edit.
    // Operator picks airgap, every tool drops — they opt back in.
    expect(nextToolsForPolicyChange(
      'open', 'airgap', ['bash', 'read_file'],
    )).toEqual([]);
    expect(nextToolsForPolicyChange(
      'nolocalnet', 'airgap', ['web_fetch'],
    )).toEqual([]);
    expect(nextToolsForPolicyChange(
      'allowlist', 'airgap', ['kb_search'],
    )).toEqual([]);
  });

  test('does NOT clear when staying on airgap (e.g. initial mount)', () => {
    // Critical for edit: a row that's already airgap with a
    // pre-fill of opted-in tools must NOT lose them on form
    // mount.  prev === next so the helper is a no-op.
    const tools = ['ast_query', 'workspace'];
    expect(nextToolsForPolicyChange('airgap', 'airgap', tools))
      .toBe(tools);
  });

  test('preserves a non-empty selection on transition OUT of airgap', () => {
    // The operator hand-picked a couple of tools under airgap;
    // moving to open shouldn't silently re-tick the world.
    const tools = ['ast_query'];
    expect(nextToolsForPolicyChange('airgap', 'open', tools))
      .toBe(tools);
    expect(nextToolsForPolicyChange('airgap', 'nolocalnet', tools))
      .toBe(tools);
  });

  test('re-ticks every tool on airgap → other when picker is empty', () => {
    // The other half of the user-requested rule: an airgap row
    // with no tools enabled becomes useless when network opens
    // up unless we re-fill the toolbox.  Empty + leaving airgap
    // = full set.
    const got = nextToolsForPolicyChange('airgap', 'open', []);
    expect(got).toContain('bash');
    expect(got).toContain('web_fetch');
    expect(got).toContain('researcher');
    expect(got.length).toBeGreaterThan(20);
    // Every other non-airgap target gets the same treatment.
    expect(nextToolsForPolicyChange('airgap', 'nolocalnet', []).length)
      .toBe(got.length);
    expect(nextToolsForPolicyChange('airgap', 'allowlist', []).length)
      .toBe(got.length);
    expect(nextToolsForPolicyChange('airgap', 'denylist', []).length)
      .toBe(got.length);
  });

  test('does NOT clear on non-airgap-to-non-airgap transitions', () => {
    // Allowlist ↔ denylist ↔ open all let traffic through, so
    // there's no reason to wipe the picker.
    const tools = ['bash', 'web_fetch'];
    expect(nextToolsForPolicyChange('open', 'allowlist', tools))
      .toBe(tools);
    expect(nextToolsForPolicyChange('allowlist', 'denylist', tools))
      .toBe(tools);
    expect(nextToolsForPolicyChange('nolocalnet', 'open', tools))
      .toBe(tools);
  });
});

describe('default network policy', () => {
  test('hire form defaults to airgap', () => {
    // The operator-asked-for default: airgap.  A hire that
    // doesn't override gets the smallest blast radius.  Going
    // with anything wider should be a deliberate pick.
    expect(DEFAULT_POLICY_KIND).toBe('airgap');
  });

  test('policy radio order is airgap → allowlist → denylist → open → open+lan', () => {
    // The brief order; matters because the picker renders in
    // POLICY_OPTIONS order and operators read top-down.
    expect(POLICY_OPTIONS.map(o => o.kind)).toEqual([
      'airgap',
      'allowlist',
      'denylist',
      'nolocalnet',
      'open',
    ]);
  });
});
