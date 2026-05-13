import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { ActivityPage } from './activity.jsx';
import { exportToolCallsNdjson, listToolCallFacets, listToolCalls, streamToolCalls } from '../api/audit.js';

vi.mock('../api/audit.js', () => ({
  listToolCalls: vi.fn(),
  listToolCallFacets: vi.fn(),
  exportToolCallsNdjson: vi.fn(),
  streamToolCalls: vi.fn(() => () => {}),
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.useRealTimers();
  window.localStorage.clear();
  delete navigator.clipboard;
});

beforeEach(() => {
  listToolCallFacets.mockResolvedValue({ tools: ['bash', 'mcp__github__create_issue'], servers: ['github', 'linear'] });
  streamToolCalls.mockImplementation(() => () => {});
});

function renderActivity(client = {}) {
  return render(
    <ApiProvider client={client} auth={{ mode: 'none' }}>
      <ActivityPage instanceId="inst-a" embedded/>
    </ApiProvider>,
  );
}

const rows = [{
  id: 1,
  llm_audit_id: 7,
  instance_id: 'inst-a',
  tool_use_id: 'call-1',
  tool_name: 'bash',
  mcp_server: null,
  input: { cmd: 'pwd' },
  result: { stdout: '/workspace' },
  is_error: false,
  called_at: 1760000000,
  resulted_at: 1760000002,
  mcp_audit_id: null,
  mcp_status: null,
  mcp_duration_ms: null,
}];

const mcpRow = {
  ...rows[0],
  id: 2,
  tool_use_id: 'call-2',
  tool_name: 'mcp__github__create_issue',
  mcp_server: 'github',
  input: { title: 'ship it' },
  result: { ok: true },
  called_at: 1760000010,
  resulted_at: 1760000011,
  mcp_audit_id: 99,
  mcp_status: 200,
  mcp_duration_ms: 42,
};

describe('ActivityPage', () => {
  test('renders the empty state without filters', async () => {
    listToolCalls.mockResolvedValue({ items: [], next_cursor: null });
    listToolCallFacets.mockResolvedValueOnce({ tools: [], servers: [] });
    renderActivity();

    expect(await screen.findByText(/no tool calls yet/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^tool:/i })).toBeNull();
    expect(streamToolCalls).toHaveBeenCalled();
  });

  test('renders rows, opens the drawer, and applies filters', async () => {
    listToolCalls.mockResolvedValue({ items: rows, next_cursor: 1 });
    renderActivity();

    expect((await screen.findAllByText('bash')).length).toBeGreaterThan(0);
    await waitFor(() => expect(screen.getByRole('button', { name: /server: all/i })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('listitem'));
    expect(screen.getByRole('dialog', { name: /tool call detail/i })).toBeInTheDocument();
    expect(screen.getByText('call-1')).toBeInTheDocument();
    expect(screen.getByText(/workspace/)).toBeInTheDocument();

    chooseFilter('status', 'ok');
    await waitFor(() => expect(listToolCalls).toHaveBeenLastCalledWith(
      expect.anything(),
      'inst-a',
      expect.objectContaining({ status: 'ok' }),
    ));
  });

  test('reopening a selected tool dropdown still shows the other options', async () => {
    listToolCalls.mockResolvedValue({ items: [rows[0], mcpRow], next_cursor: 2 });
    renderActivity();

    await screen.findAllByRole('listitem');
    chooseFilter('tool', 'bash');

    fireEvent.click(screen.getByRole('button', { name: /tool: bash/i }));

    const listbox = screen.getByRole('listbox', { name: /tool options/i });
    expect(within(listbox).getByRole('option', { name: 'bash' })).toBeInTheDocument();
    expect(within(listbox).getByRole('option', { name: 'mcp__github__create_issue' })).toBeInTheDocument();
  });

  test('chip clear resets an active filter and updates the row list', async () => {
    listToolCalls.mockImplementation((client, instanceId, filters) => Promise.resolve({
      items: filters.tool === 'bash' ? [rows[0]] : [rows[0], mcpRow],
      next_cursor: null,
    }));
    renderActivity();

    expect(await screen.findAllByRole('listitem')).toHaveLength(2);
    chooseFilter('tool', 'bash');
    await waitFor(() => expect(screen.getAllByRole('listitem')).toHaveLength(1));

    fireEvent.click(screen.getByRole('button', { name: /clear tool filter/i }));

    await waitFor(() => expect(screen.getAllByRole('listitem')).toHaveLength(2));
    expect(screen.getByRole('button', { name: /tool: all/i })).toBeInTheDocument();
  });

  test('empty state with filters offers a clear button for all chips', async () => {
    listToolCalls.mockImplementation((client, instanceId, filters) => Promise.resolve({
      items: filters.status === 'err' ? [] : rows,
      next_cursor: null,
    }));
    renderActivity();

    await screen.findByRole('listitem');
    chooseFilter('status', 'err');

    expect(await screen.findByText(/no calls match these filters/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /clear filters/i }));

    await waitFor(() => expect(screen.getByRole('button', { name: /status: all/i })).toBeInTheDocument());
    await waitFor(() => expect(screen.getByRole('listitem')).toBeInTheDocument());
  });

  test('updates an open drawer when a result attaches to an existing row', async () => {
    const pending = {
      ...rows[0],
      result: null,
      is_error: null,
      resulted_at: null,
    };
    const completed = {
      ...pending,
      result: { stdout: 'audit-smoke' },
      is_error: false,
      resulted_at: pending.called_at + 3,
    };
    let pushToolCall;
    streamToolCalls.mockImplementationOnce((client, instanceId, filters, onEvent) => {
      pushToolCall = onEvent;
      return () => {};
    });
    listToolCallFacets.mockResolvedValue({ tools: ['bash'], servers: [] });
    listToolCalls.mockResolvedValue({ items: [pending], next_cursor: pending.id });
    renderActivity();

    fireEvent.click(await screen.findByRole('listitem'));
    expect(screen.queryByText(/audit-smoke/)).toBeNull();

    act(() => pushToolCall(completed));

    expect(await screen.findByText(/audit-smoke/)).toBeInTheDocument();
  });

  test('in-flight rows show pulsing and stale amber duration dots', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-05-14T12:00:40Z'));
    listToolCalls.mockResolvedValue({
      items: [
        { ...rows[0], id: 3, tool_use_id: 'fresh', result: null, is_error: null, called_at: 1778760030, resulted_at: null },
        { ...rows[0], id: 4, tool_use_id: 'stale', result: null, is_error: null, called_at: 1778760000, resulted_at: null },
      ],
      next_cursor: null,
    });
    renderActivity();

    expect(await screen.findByLabelText(/fresh is waiting for a tool result/i)).toHaveClass('activity-duration-pending');
    expect(screen.getByLabelText(/stale has no result yet/i)).toHaveClass('activity-duration-stale');
  });

  test('live tail shows a new-row pill instead of jumping when scrolled away', async () => {
    let pushToolCall;
    streamToolCalls.mockImplementationOnce((client, instanceId, filters, onEvent) => {
      pushToolCall = onEvent;
      return () => {};
    });
    listToolCalls.mockResolvedValue({ items: rows, next_cursor: 1 });
    renderActivity();

    await screen.findByRole('listitem');
    const list = screen.getByRole('list');
    list.scrollTop = 120;
    fireEvent.scroll(list);

    act(() => pushToolCall({ ...mcpRow, id: 5, tool_use_id: 'call-5' }));

    expect(await screen.findByRole('button', { name: /↑ 1 new/i })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /↑ 1 new/i }));

    expect(screen.queryByRole('button', { name: /↑ 1 new/i })).toBeNull();
    expect(list.scrollTop).toBe(0);
  });

  test('pause buffers live rows and resume drains them to the top', async () => {
    let pushToolCall;
    streamToolCalls.mockImplementationOnce((client, instanceId, filters, onEvent) => {
      pushToolCall = onEvent;
      return () => {};
    });
    listToolCalls.mockResolvedValue({ items: rows, next_cursor: 1 });
    renderActivity();

    await screen.findByRole('listitem');
    fireEvent.click(screen.getByRole('button', { name: /^live/i }));

    act(() => pushToolCall({ ...mcpRow, id: 6, tool_use_id: 'call-6' }));

    expect(screen.getByRole('button', { name: /paused · 1 new/i })).toBeInTheDocument();
    expect(screen.queryByText('mcp__github__create_issue')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /paused · 1 new/i }));

    expect(await screen.findByText('mcp__github__create_issue')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^live/i })).toBeInTheDocument();
  });

  test('drawer closes on Escape and copies the full unsealed row JSON', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    navigator.clipboard = { writeText };
    listToolCalls.mockResolvedValue({ items: [mcpRow], next_cursor: 2 });
    renderActivity();

    await screen.findByRole('listitem');
    fireEvent.click(screen.getByRole('listitem'));
    expect(screen.getByRole('dialog', { name: /tool call detail/i })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /copy as JSON/i }));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('"tool_use_id": "call-2"'));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('"result": {'));

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: /tool call detail/i })).toBeNull();
  });

  test('keyboard navigation moves selection and opens/closes the drawer', async () => {
    listToolCalls.mockResolvedValue({ items: [rows[0], mcpRow], next_cursor: 2 });
    renderActivity();

    const region = await screen.findByRole('region', { name: /tool-call activity/i });
    region.focus();
    fireEvent.keyDown(region, { key: 'j' });
    fireEvent.keyDown(region, { key: 'j' });
    fireEvent.keyDown(region, { key: 'Enter' });

    expect(screen.getByRole('dialog', { name: /tool call detail/i })).toHaveTextContent('call-2');

    fireEvent.keyDown(region, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: /tool call detail/i })).toBeNull();

    fireEvent.keyDown(region, { key: 'k' });
    fireEvent.keyDown(region, { key: 'Enter' });
    expect(screen.getByRole('dialog', { name: /tool call detail/i })).toHaveTextContent('call-1');
  });

  test('density toggle persists across remounts', async () => {
    listToolCalls.mockResolvedValue({ items: rows, next_cursor: 1 });
    const view = renderActivity();

    await screen.findByRole('listitem');
    expect(screen.getByRole('button', { name: /density: comfortable/i })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /density: comfortable/i }));
    expect(window.localStorage.getItem('dyson.activity.density')).toBe('compact');

    view.unmount();
    renderActivity();

    expect(await screen.findByRole('button', { name: /density: compact/i })).toBeInTheDocument();
  });
});

function chooseFilter(kind, value) {
  fireEvent.click(screen.getByRole('button', { name: new RegExp(`^${kind}:`, 'i') }));
  fireEvent.click(screen.getByRole('option', { name: value }));
}
