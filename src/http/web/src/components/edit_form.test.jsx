/* End-to-end DOM tests for the EditInstancePage form.
 *
 * The hire form's behaviour got pure-function coverage in
 * instances.test.js (initialTools / nextToolsForPolicyChange /
 * toolBlockedByNetwork).  This file goes one layer up and renders
 * the actual edit page so we catch wiring regressions:
 *
 * - Section order (tools is above network access).
 * - Airgap rule fires on edit when the operator picks airgap from
 *   the network panel inside the form (the bug the operator hit
 *   live: airgap was a no-op on edit).
 * - Pre-fill: an already-airgap row keeps its persisted tool list
 *   on mount (the transition guard isn't supposed to wipe it).
 *
 * RTL + jsdom; no real backend touched (the API client is stubbed).
 */
import { describe, expect, test, vi, afterEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

// RTL doesn't auto-cleanup under vitest unless `globals: true` is
// set; explicitly tear down between tests so multi-render assertions
// ("multiple elements with the role …") don't trip on stale DOM.
afterEach(() => { cleanup(); });

import { EditInstancePage } from './instances.jsx';
import { ApiProvider } from '../hooks/useApi.jsx';
import { upsertInstance } from '../store/app.js';

// Stub the API client.  Edit page calls getInstance on mount; we
// resolve with the seeded row.  Other client methods aren't hit
// in these tests (we don't actually save).
function makeStubClient(row) {
  return {
    getInstance: vi.fn().mockResolvedValue(row),
    updateInstance: vi.fn().mockResolvedValue(row),
    changeInstanceNetwork: vi.fn().mockResolvedValue(row),
    listInstances: vi.fn().mockResolvedValue([row]),
    listMcpServers: vi.fn().mockResolvedValue([]),
  };
}

function renderEdit(row, { auth } = {}) {
  // Seed the store so EditInstancePage's `useAppState` selector
  // picks the row up immediately (the page also re-fetches via
  // getInstance, which the stub satisfies).
  upsertInstance(row);
  const client = makeStubClient(row);
  const ctxAuth = auth || { config: { default_models: ['anthropic/claude-sonnet-4-5'] } };
  return {
    client,
    ...render(
      <ApiProvider client={client} auth={ctxAuth}>
        <EditInstancePage instanceId={row.id}/>
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

describe('EditInstancePage layout', () => {
  test('network access renders ABOVE the tools panel (same as hire form)', async () => {
    renderEdit(makeRow());
    // Wait for the form to materialise (useEffect re-fetches on mount).
    const networkHeading = await screen.findByRole('heading', { name: /network access/i });
    const toolsTitle = await screen.findByText(/^tools$/i);

    // DOM order: comparing positions inside the same parent stack.
    const stack = networkHeading.closest('section').parentElement;
    expect(stack).toBe(toolsTitle.closest('section').parentElement);
    const positions = [...stack.children];
    const netIdx = positions.indexOf(networkHeading.closest('section'));
    const toolsIdx = positions.indexOf(toolsTitle.closest('section'));
    expect(netIdx).toBeGreaterThan(-1);
    expect(toolsIdx).toBeGreaterThan(-1);
    expect(netIdx).toBeLessThan(toolsIdx);
  });
});

describe('EditInstancePage airgap rule', () => {
  test('selecting airgap clears every tool in the picker', async () => {
    // Row starts on `open` with the default-everything-ticked
    // implicit list (tools=[]).  After picking airgap, the picker
    // must drop to zero — same behaviour as the hire form.
    renderEdit(makeRow({ network_policy: { kind: 'open', entries: [] } }));

    // Sanity: at least one tool is initially ticked (the
    // empty-list-on-non-airgap row pre-fills "every tool").
    const bashCheckbox = await screen.findByRole('checkbox', { name: 'bash' });
    expect(bashCheckbox).toBeChecked();

    // Click the airgap radio inside the network access section.
    // The picker uses radios labelled by their kind label
    // ("air-gapped"); we look up by the underlying `value`.
    const airgapRadio = screen.getByRole('radio', { name: /air-gapped/i });
    fireEvent.click(airgapRadio);

    // Every checkbox in the tools picker should now be unticked.
    const toolCheckboxes = screen.getAllByRole('checkbox');
    for (const cb of toolCheckboxes) {
      expect(cb).not.toBeChecked();
    }


  });

  test('airgap row mount does NOT wipe a persisted tool list', async () => {
    // Regression: the transition-aware effect must not fire on
    // initial mount when the row was already airgap.  An operator
    // who hand-picked `bash` + `read_file` last week should see
    // exactly those still ticked when they re-open edit.
    const row = makeRow({
      network_policy: { kind: 'airgap', entries: [] },
      tools: ['bash', 'read_file'],
    });
    renderEdit(row);

    const bash = await screen.findByRole('checkbox', { name: 'bash' });
    const readFile = await screen.findByRole('checkbox', { name: 'read_file' });
    const writeFile = await screen.findByRole('checkbox', { name: 'write_file' });
    expect(bash).toBeChecked();
    expect(readFile).toBeChecked();
    expect(writeFile).not.toBeChecked();


  });

  test('switching OUT of airgap with a hand-picked selection keeps it', async () => {
    // Airgap → open with a non-empty tool set: the operator opted
    // in deliberately, so don't undo their work.
    const row = makeRow({
      network_policy: { kind: 'airgap', entries: [] },
      tools: ['bash'],
    });
    renderEdit(row);

    const bash = await screen.findByRole('checkbox', { name: 'bash' });
    expect(bash).toBeChecked();

    const openRadio = screen.getByRole('radio', { name: /^Open \(full internet\)$/i });
    fireEvent.click(openRadio);

    // Bash still ticked, web_fetch still NOT ticked (we didn't
    // re-tick the world — the operator's curated set survived).
    expect(bash).toBeChecked();
    const webFetch = screen.getByRole('checkbox', { name: 'web_fetch' });
    expect(webFetch).not.toBeChecked();
  });

  test('switching OUT of airgap with an empty picker re-ticks every tool', async () => {
    // The opposite case: an airgap row with the empty default
    // (no tools enabled) widens the network — the operator
    // probably wants the full toolbox available again, otherwise
    // they're left with a useless dyson.  initialTools renders
    // airgap+empty as "no checkboxes ticked"; flipping away from
    // airgap re-fills.
    const row = makeRow({
      network_policy: { kind: 'airgap', entries: [] },
      tools: [],
    });
    renderEdit(row);

    // Sanity: every tool starts unticked (initialTools(row, 'airgap') = []).
    const bash = await screen.findByRole('checkbox', { name: 'bash' });
    expect(bash).not.toBeChecked();

    const openRadio = screen.getByRole('radio', { name: /^Open \(full internet\)$/i });
    fireEvent.click(openRadio);

    // After leaving airgap with no prior selection, every tool
    // becomes ticked (the operator gets a working dyson).
    expect(bash).toBeChecked();
    const webFetch = screen.getByRole('checkbox', { name: 'web_fetch' });
    expect(webFetch).toBeChecked();
  });
});

describe('EditInstancePage parity with hire form', () => {
  test('renders identity, model, network access, tools in that order', async () => {
    renderEdit(makeRow());

    const identity = await screen.findByRole('heading', { name: /^identity$/i });
    const model = await screen.findByRole('heading', { name: /^model$/i });
    const network = await screen.findByRole('heading', { name: /^network access$/i });
    const tools = await screen.findByText(/^tools$/i);

    // All four headings live inside the same form element.
    const form = identity.closest('form');
    expect(form).not.toBeNull();
    expect(form.contains(model)).toBe(true);
    expect(form.contains(network)).toBe(true);
    expect(form.contains(tools)).toBe(true);

    // DOM-order check via document position.  Mirrors the hire
    // form: identity → model → network → tools.
    const order = (a, b) =>
      Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(order(identity, model)).toBe(true);
    expect(order(model, network)).toBe(true);
    expect(order(network, tools)).toBe(true);


  });

  test('saves identity / models / tools as a PATCH on submit', async () => {
    const row = makeRow();
    const { client } = renderEdit(row);

    const nameInput = await screen.findByDisplayValue('TARS');
    fireEvent.change(nameInput, { target: { value: 'TARS-2' } });

    // Click the bottom save button (form submit).
    const save = screen.getByRole('button', { name: /^save$/i });
    fireEvent.click(save);

    // updateInstance was called with the new name; no
    // change-network call because the policy didn't move.
    await vi.waitFor(() => {
      expect(client.updateInstance).toHaveBeenCalled();
    });
    const [id, payload] = client.updateInstance.mock.calls[0];
    expect(id).toBe('inst-test');
    expect(payload.name).toBe('TARS-2');
    expect(client.changeInstanceNetwork).not.toHaveBeenCalled();


  });

  test('save button label switches when the network policy is dirty', async () => {
    renderEdit(makeRow({ network_policy: { kind: 'open', entries: [] } }));

    // Untouched: button reads "save".
    expect(await screen.findByRole('button', { name: /^save$/i })).toBeInTheDocument();

    // Pick airgap — policy is now dirty, label updates to call
    // out the snapshot+re-hire that's about to happen.
    fireEvent.click(screen.getByRole('radio', { name: /air-gapped/i }));
    expect(screen.getByRole('button', { name: /snapshot \+ re-hire/i })).toBeInTheDocument();


  });
});
