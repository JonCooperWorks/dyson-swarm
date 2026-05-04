/* End-to-end DOM tests for the per-section instance detail pages.
 *
 * The unified edit form was retired in favour of one URL per
 * configuration surface.  These tests cover the inline apply/revert
 * wiring for the sections that replaced it.
 */
import { describe, expect, test, vi, afterEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { InstancesView } from './instances.jsx';
import { ApiProvider } from '../hooks/useApi.jsx';
import { setInstances, setSharesFor, setWebhooksFor } from '../store/app.js';

afterEach(() => {
  cleanup();
  setInstances([]);
  setWebhooksFor('inst-test', []);
  setSharesFor('inst-test', []);
});

function makeStubClient(row, overrides = {}) {
  return {
    getInstance: vi.fn().mockResolvedValue(row),
    listInstances: vi.fn().mockResolvedValue([row]),
    listWebhooks: vi.fn().mockResolvedValue([]),
    listShares: vi.fn().mockResolvedValue([]),
    listProviderModels: vi.fn().mockResolvedValue({ models: [] }),
    listSnapshotsForInstance: vi.fn().mockResolvedValue([]),
    listSecretNames: vi.fn().mockResolvedValue([]),
    listMcpServers: vi.fn().mockResolvedValue([]),
    updateInstance: vi.fn().mockImplementation(async (_id, payload) => ({ ...row, ...payload })),
    changeInstanceNetwork: vi.fn().mockImplementation(async (_id, policy) => ({
      ...row,
      network_policy: policy,
    })),
    ...overrides,
  };
}

function renderSection(view, row, { auth, clientOverrides } = {}) {
  setInstances([row]);
  const client = makeStubClient(row, clientOverrides || {});
  const ctxAuth = auth || {
    config: {
      default_models: ['anthropic/claude-sonnet-4-5', 'openai/gpt-5'],
      cube_profiles: [],
    },
  };
  return {
    client,
    ...render(
      <ApiProvider client={client} auth={ctxAuth}>
        <InstancesView view={view}/>
      </ApiProvider>,
    ),
  };
}

function makeRow(overrides = {}) {
  return {
    id: 'inst-test',
    name: 'TARS',
    task: 'Security review.',
    template_id: 'tpl-1',
    status: 'live',
    cube_sandbox_id: 'sb-1',
    network_policy: { kind: 'open', entries: [] },
    network_policy_cidrs: [],
    models: ['anthropic/claude-sonnet-4-5'],
    tools: [],
    pinned: false,
    expires_at: null,
    last_active_at: 0,
    last_probe_at: null,
    last_probe_status: null,
    created_at: 0,
    destroyed_at: null,
    ...overrides,
  };
}

describe('identity section', () => {
  test('apply / revert appear only when the form is dirty', async () => {
    renderSection({ name: 'instance-identity', id: 'inst-test' }, makeRow());

    const nameInput = await screen.findByDisplayValue('TARS');
    expect(screen.queryByRole('button', { name: /^apply$/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /^revert$/i })).toBeNull();

    fireEvent.change(nameInput, { target: { value: 'TARS-2' } });
    expect(screen.getByRole('button', { name: /^apply$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^revert$/i })).toBeInTheDocument();
  });

  test('apply patches the identity without touching network', async () => {
    const { client } = renderSection({ name: 'instance-identity', id: 'inst-test' }, makeRow());

    const nameInput = await screen.findByDisplayValue('TARS');
    fireEvent.change(nameInput, { target: { value: 'TARS-2' } });
    fireEvent.click(screen.getByRole('button', { name: /^apply$/i }));

    await waitFor(() => expect(client.updateInstance).toHaveBeenCalled());
    const [id, payload] = client.updateInstance.mock.calls[0];
    expect(id).toBe('inst-test');
    expect(payload).toMatchObject({ name: 'TARS-2', task: 'Security review.' });
    expect(client.changeInstanceNetwork).not.toHaveBeenCalled();
  });

  test('revert restores the original name and brief', async () => {
    renderSection({ name: 'instance-identity', id: 'inst-test' }, makeRow());

    const nameInput = await screen.findByDisplayValue('TARS');
    fireEvent.change(nameInput, { target: { value: 'NEW' } });
    fireEvent.click(screen.getByRole('button', { name: /^revert$/i }));

    expect(nameInput.value).toBe('TARS');
    expect(screen.queryByRole('button', { name: /^apply$/i })).toBeNull();
  });
});

describe('model section', () => {
  test('apply patches only the model list', async () => {
    const { client } = renderSection({ name: 'instance-model', id: 'inst-test' }, makeRow());

    fireEvent.click(await screen.findByRole('button', {
      name: 'remove anthropic/claude-sonnet-4-5',
    }));
    const input = screen.getByPlaceholderText('pick at least one model');
    fireEvent.change(input, { target: { value: 'openai/gpt-5' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    fireEvent.click(screen.getByRole('button', { name: /^apply$/i }));

    await waitFor(() => expect(client.updateInstance).toHaveBeenCalled());
    const [, payload] = client.updateInstance.mock.calls[0];
    expect(payload).toEqual({ models: ['openai/gpt-5'] });
    expect(client.changeInstanceNetwork).not.toHaveBeenCalled();
  });
});

describe('tools section', () => {
  test('unticking a tool becomes dirty and saves the trimmed array', async () => {
    const row = makeRow({
      tools: [
        'read_file', 'write_file', 'edit_file', 'bulk_edit',
        'list_files', 'search_files',
      ],
    });
    const { client } = renderSection({ name: 'instance-tools', id: 'inst-test' }, row);

    const bulkEdit = await screen.findByRole('checkbox', { name: /bulk_edit/ });
    expect(bulkEdit).toBeChecked();
    fireEvent.click(bulkEdit);
    expect(bulkEdit).not.toBeChecked();

    fireEvent.click(screen.getByRole('button', { name: /^apply$/i }));
    await waitFor(() => expect(client.updateInstance).toHaveBeenCalled());
    const [, payload] = client.updateInstance.mock.calls[0];
    expect(payload.tools).toBeDefined();
    expect(payload.tools).not.toContain('bulk_edit');
    for (const t of ['read_file', 'write_file', 'edit_file', 'list_files', 'search_files']) {
      expect(payload.tools).toContain(t);
    }
  });

  test('an airgap row mounts with its persisted tool list intact', async () => {
    const row = makeRow({
      network_policy: { kind: 'airgap', entries: [] },
      tools: ['bash', 'read_file'],
    });
    renderSection({ name: 'instance-tools', id: 'inst-test' }, row);

    const bash = await screen.findByRole('checkbox', { name: 'bash' });
    const readFile = await screen.findByRole('checkbox', { name: 'read_file' });
    const writeFile = await screen.findByRole('checkbox', { name: 'write_file' });
    expect(bash).toBeChecked();
    expect(readFile).toBeChecked();
    expect(writeFile).not.toBeChecked();
  });
});

describe('network section', () => {
  test('apply hits client.changeInstanceNetwork with the new policy', async () => {
    const { client } = renderSection({ name: 'instance-network', id: 'inst-test' }, makeRow());

    const airgapRadio = await screen.findByRole('radio', { name: /air-gapped/i });
    fireEvent.click(airgapRadio);
    fireEvent.click(screen.getByRole('button', { name: /^apply$/i }));

    await waitFor(() => expect(client.changeInstanceNetwork).toHaveBeenCalled());
    const [id, policy] = client.changeInstanceNetwork.mock.calls[0];
    expect(id).toBe('inst-test');
    expect(policy.kind).toBe('airgap');
    expect(client.updateInstance).not.toHaveBeenCalled();
  });
});

describe('summary section', () => {
  test('renders brief, activity, and section links', async () => {
    renderSection({ name: 'instance', id: 'inst-test' }, makeRow());

    expect(await screen.findByText(/Security review/)).toBeInTheDocument();
    expect(screen.getByText(/^activity$/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /^identity$/ })).toHaveAttribute(
      'href',
      '#/i/inst-test/identity',
    );
  });
});
