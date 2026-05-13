import { afterEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { ActivityPage } from './activity.jsx';
import { listToolCallFacets, listToolCalls, streamToolCalls } from '../api/audit.js';

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

describe('ActivityPage', () => {
  test('renders the empty state without filters', async () => {
    listToolCalls.mockResolvedValue({ items: [], next_cursor: null });
    listToolCallFacets.mockResolvedValue({ tools: [], servers: [] });
    renderActivity();

    expect(await screen.findByText(/no tool calls yet/i)).toBeInTheDocument();
    expect(screen.queryByLabelText('tool filter')).toBeNull();
    expect(streamToolCalls).toHaveBeenCalled();
  });

  test('renders rows, opens the drawer, and applies filters', async () => {
    listToolCalls.mockResolvedValue({ items: rows, next_cursor: 1 });
    listToolCallFacets.mockResolvedValue({
      tools: ['bash', 'mcp__github__create_issue'],
      servers: ['github'],
    });
    renderActivity();

    expect((await screen.findAllByText('bash')).length).toBeGreaterThan(0);
    await waitFor(() => expect(datalistValues('tool filter')).toContain('mcp__github__create_issue'));
    expect(screen.getByPlaceholderText('any mcp server')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('listitem'));
    expect(screen.getByRole('dialog', { name: /tool call detail/i })).toBeInTheDocument();
    expect(screen.getByText('call-1')).toBeInTheDocument();
    expect(screen.getByText(/workspace/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('status filter'), { target: { value: 'ok' } });
    await waitFor(() => expect(listToolCalls).toHaveBeenLastCalledWith(
      expect.anything(),
      'inst-a',
      expect.objectContaining({ status: 'ok' }),
    ));
  });

  test('populates searchable tool and server filters from instance-wide facets', async () => {
    listToolCalls.mockResolvedValue({ items: rows, next_cursor: 1 });
    listToolCallFacets.mockResolvedValue({
      tools: ['bash', 'mcp__github__create_issue'],
      servers: ['github'],
    });
    renderActivity();

    await screen.findByRole('listitem');
    expect(screen.getByPlaceholderText('any tool')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('any mcp server')).toBeInTheDocument();
    await waitFor(() => {
      expect(datalistValues('tool filter')).toEqual(['bash', 'mcp__github__create_issue']);
      expect(datalistValues('mcp server filter')).toEqual(['github']);
    });
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

  test('keeps searchable filters visible when status err has no matches', async () => {
    listToolCalls
      .mockResolvedValueOnce({ items: rows, next_cursor: 1 })
      .mockResolvedValue({ items: [], next_cursor: null });
    listToolCallFacets.mockResolvedValue({ tools: ['bash'], servers: ['github'] });
    renderActivity();

    await screen.findByRole('listitem');
    fireEvent.change(screen.getByLabelText('status filter'), { target: { value: 'err' } });

    expect(await screen.findByText('no tool calls match these filters.')).toBeInTheDocument();
    expect(screen.getByLabelText('tool filter')).toBeInTheDocument();
    expect(screen.getByLabelText('status filter')).toHaveValue('err');
    expect(screen.getByPlaceholderText('any tool')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('any status')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('any mcp server')).toBeInTheDocument();
  });

  test('keeps searchable filters visible when status ok has no matches', async () => {
    const pending = { ...rows[0], result: null, is_error: null, resulted_at: null };
    listToolCalls
      .mockResolvedValueOnce({ items: [pending], next_cursor: pending.id })
      .mockResolvedValue({ items: [], next_cursor: null });
    listToolCallFacets.mockResolvedValue({ tools: ['bash'], servers: ['github'] });
    renderActivity();

    await screen.findByRole('listitem');
    fireEvent.change(screen.getByLabelText('status filter'), { target: { value: 'ok' } });

    expect(await screen.findByText('no tool calls match these filters.')).toBeInTheDocument();
    expect(screen.getByLabelText('tool filter')).toBeInTheDocument();
    expect(screen.getByLabelText('status filter')).toHaveValue('ok');
    expect(screen.getByPlaceholderText('any tool')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('any status')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('any mcp server')).toBeInTheDocument();
  });

  test('keeps searchable filters visible when payload search has no matches', async () => {
    listToolCalls
      .mockResolvedValueOnce({ items: rows, next_cursor: 1 })
      .mockResolvedValue({ items: [], next_cursor: null });
    listToolCallFacets.mockResolvedValue({ tools: ['bash'], servers: ['github'] });
    renderActivity();

    await screen.findByRole('listitem');
    fireEvent.change(screen.getByLabelText('search tool payloads'), { target: { value: 'not-here' } });

    expect(await screen.findByText('no tool calls match these filters.')).toBeInTheDocument();
    expect(screen.getByLabelText('tool filter')).toBeInTheDocument();
    expect(screen.getByLabelText('search tool payloads')).toHaveValue('not-here');
    expect(screen.getByPlaceholderText('any tool')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('any status')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('any mcp server')).toBeInTheDocument();
  });

  test('keeps searchable filters visible when tool or server has no matches', async () => {
    listToolCalls
      .mockResolvedValueOnce({ items: rows, next_cursor: 1 })
      .mockResolvedValue({ items: [], next_cursor: null });
    listToolCallFacets.mockResolvedValue({ tools: ['bash'], servers: ['github'] });
    renderActivity();

    await screen.findByRole('listitem');
    fireEvent.change(screen.getByLabelText('tool filter'), { target: { value: 'mcp__missing__tool' } });

    expect(await screen.findByText('no tool calls match these filters.')).toBeInTheDocument();
    expect(screen.getByLabelText('tool filter')).toHaveValue('mcp__missing__tool');
    expect(screen.getByPlaceholderText('any tool')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('tool filter'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('mcp server filter'), { target: { value: 'linear' } });

    expect(await screen.findByText('no tool calls match these filters.')).toBeInTheDocument();
    expect(screen.getByLabelText('mcp server filter')).toHaveValue('linear');
    expect(screen.getByPlaceholderText('any tool')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('any status')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('any mcp server')).toBeInTheDocument();
  });
});

function datalistValues(label) {
  const input = screen.getByLabelText(label);
  const list = document.getElementById(input.getAttribute('list'));
  return [...(list?.querySelectorAll('option') || [])].map(option => option.value);
}
