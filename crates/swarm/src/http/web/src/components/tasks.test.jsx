import { afterEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { setWebhooksFor } from '../store/app.js';
import { AuditListPage, TaskFormPage, TasksListPage } from './tasks.jsx';

afterEach(() => {
  cleanup();
  setWebhooksFor('inst-a', []);
});

describe('AuditListPage', () => {
  test('keeps audit filtering task-only and removes the old error search', async () => {
    setWebhooksFor('inst-a', [{ name: 'deploy' }]);
    const listInstanceDeliveries = vi.fn().mockResolvedValue([]);

    render(
      <ApiProvider
        client={{
          listInstanceDeliveries,
          listWebhooks: vi.fn().mockResolvedValue([]),
        }}
        auth={{ mode: 'none' }}
      >
        <AuditListPage instanceId="inst-a" embedded/>
      </ApiProvider>,
    );

    await waitFor(() => expect(listInstanceDeliveries).toHaveBeenCalled());

    expect(screen.queryByPlaceholderText(/search errors/i)).toBeNull();
    expect(screen.queryByRole('button', { name: /^search$/i })).toBeNull();
    expect(screen.getByRole('combobox')).toHaveDisplayValue('all webhooks');
    expect(screen.getByText('no deliveries yet')).toBeInTheDocument();
    expect(listInstanceDeliveries.mock.calls[0][1]).not.toHaveProperty('q');
  });
});

describe('TasksListPage', () => {
  test('keeps task instructions off the roster', async () => {
    const listWebhooks = vi.fn().mockResolvedValue([{
      name: 'mail-research',
      description: '# Research prompt\n\n- Decide whether to invest.',
      auth_scheme: 'hmac_sha256',
      enabled: true,
      path: '/webhooks/inst-a/mail-research',
    }]);

    render(
      <ApiProvider
        client={{
          listWebhooks,
        }}
        auth={{ mode: 'none' }}
      >
        <TasksListPage instanceId="inst-a" embedded/>
      </ApiProvider>,
    );

    await waitFor(() => expect(listWebhooks).toHaveBeenCalled());
    expect(screen.getByText(/that webhook's stable chat/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'mail-research' })).toBeInTheDocument();
    expect(screen.queryByText(/Decide whether to invest/i)).toBeNull();
  });
});

describe('TaskFormPage', () => {
  test.each([
    ['Standard Webhooks', 'webhook-signature', 'hmac_v2'],
    ['GitHub', 'x-hub-signature-256', 'hmac_v2'],
    ['Stripe', 'stripe-signature', 'hmac_v2'],
    ['Slack', 'x-slack-signature', 'hmac_v2'],
    ['Shopify', 'x-shopify-hmac-sha256', 'hmac_v2'],
    ['AgentMail', 'svix-signature', 'hmac_v2'],
  ])('preset button %s populates the verifier form', async (label, header, mode) => {
    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: label }));

    expect(screen.getByLabelText('verifier mode')).toHaveValue(mode);
    expect(screen.getByLabelText('signature header')).toHaveValue(header);
  });

  test('Verify widget renders structured error reason inline', async () => {
    const verifyWebhookDelivery = vi.fn().mockResolvedValue({
      type: 'all_signatures_mismatched',
    });
    const getWebhook = vi.fn().mockResolvedValue({
      name: 'standard',
      description: '',
      auth_scheme: 'hmac_sha256',
      verifier_mode: 'hmac_v2',
      signature_header: 'webhook-signature',
      enabled: true,
      has_secret: true,
    });

    render(
      <ApiProvider
        client={{ getWebhook, verifyWebhookDelivery, listWebhookDeliveries: vi.fn().mockResolvedValue([]) }}
        auth={{ mode: 'none' }}
      >
        <TaskFormPage instanceId="inst-a" taskName="standard" embedded/>
      </ApiProvider>,
    );

    await screen.findByDisplayValue('standard');
    fireEvent.change(screen.getByLabelText('recorded delivery'), {
      target: { value: 'webhook-id: msg_123\n\n{"event":"ping"}' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'verify' }));

    await waitFor(() => expect(verifyWebhookDelivery).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/all_signatures_mismatched/)).toBeInTheDocument();
  });

  test('Verify widget renders success with rendered payload preview', async () => {
    const verifyWebhookDelivery = vi.fn().mockResolvedValue({
      ok: true,
      rendered_payload_b64: btoa('msg_123.1700000000.{"event":"ping"}'),
      matched_version: 'v1',
    });
    const getWebhook = vi.fn().mockResolvedValue({
      name: 'standard',
      description: '',
      auth_scheme: 'hmac_sha256',
      verifier_mode: 'hmac_v2',
      signature_header: 'webhook-signature',
      enabled: true,
      has_secret: true,
    });

    render(
      <ApiProvider
        client={{ getWebhook, verifyWebhookDelivery, listWebhookDeliveries: vi.fn().mockResolvedValue([]) }}
        auth={{ mode: 'none' }}
      >
        <TaskFormPage instanceId="inst-a" taskName="standard" embedded/>
      </ApiProvider>,
    );

    await screen.findByDisplayValue('standard');
    fireEvent.change(screen.getByLabelText('recorded delivery'), {
      target: { value: 'webhook-id: msg_123\n\n{"event":"ping"}' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'verify' }));

    expect(await screen.findByText(/matched v1/)).toBeInTheDocument();
    expect(screen.getByText(/msg_123\.1700000000/)).toBeInTheDocument();
  });

  test('starts setup with the provider URL visible before create', () => {
    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    expect(screen.getAllByText('provider URL').length).toBeGreaterThan(0);
    expect(screen.getByText(/stable chat for that webhook/i)).toBeInTheDocument();
    expect(screen.getByLabelText('url')).toHaveValue(
      `${window.location.origin}/webhooks/inst-a/webhook-name`,
    );
    expect(screen.getByRole('button', { name: 'name first' })).toBeDisabled();

    fireEvent.change(screen.getByLabelText('name'), {
      target: { value: 'mail-research' },
    });

    expect(screen.getByLabelText('url')).toHaveValue(
      `${window.location.origin}/webhooks/inst-a/mail-research`,
    );
    expect(screen.getByRole('button', { name: 'copy' })).toBeEnabled();
  });

  test('renders task instructions as markdown on the detail form', async () => {
    const getWebhook = vi.fn().mockResolvedValue({
      name: 'mail-research',
      description: '# Mail brief\n\n- Research each company\n\n[SEC](https://www.sec.gov/)',
      auth_scheme: 'hmac_sha256',
      enabled: true,
      has_secret: true,
    });

    render(
      <ApiProvider
        client={{
          getWebhook,
        }}
        auth={{ mode: 'none' }}
      >
        <TaskFormPage instanceId="inst-a" taskName="mail-research" embedded/>
      </ApiProvider>,
    );

    expect(await screen.findByRole('heading', { name: 'Mail brief', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('Research each company')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'SEC' })).toHaveAttribute('target', '_blank');
  });

  test('sends the configured HMAC signature header when creating', async () => {
    const createWebhook = vi.fn().mockResolvedValue({
      name: 'github',
      description: '',
      auth_scheme: 'hmac_sha256',
      signature_header: 'x-hub-signature-256',
      enabled: true,
      path: '/webhooks/inst-a/github',
    });

    render(
      <ApiProvider
        client={{ createWebhook }}
        auth={{ mode: 'none' }}
      >
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    fireEvent.change(screen.getByLabelText('name'), {
      target: { value: 'github' },
    });
    fireEvent.change(screen.getByPlaceholderText('paste or generate a strong random string'), {
      target: { value: 'super-secret' },
    });
    fireEvent.change(screen.getByLabelText('signature header'), {
      target: { value: 'X-Hub-Signature-256' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'create webhook' }));

    await waitFor(() => expect(createWebhook).toHaveBeenCalledTimes(1));
    expect(createWebhook.mock.calls[0][1]).toMatchObject({
      name: 'github',
      auth_scheme: 'hmac_sha256',
      signature_header: 'x-hub-signature-256',
      secret: 'super-secret',
    });
  });

  test('Recent-deliveries Inspect modal shows raw bytes and toggles to hex', async () => {
    const getWebhook = vi.fn().mockResolvedValue({
      name: 'github',
      description: '',
      auth_scheme: 'hmac_sha256',
      verifier_mode: 'legacy_hmac',
      signature_header: 'x-hub-signature-256',
      enabled: true,
      has_secret: true,
    });
    const listWebhookDeliveries = vi.fn().mockResolvedValue([{
      id: 'd1',
      fired_at: 100,
      status_code: 401,
      latency_ms: 5,
      signature_ok: false,
      body_size: 15,
      content_type: 'application/json',
      error: 'all signatures mismatched',
    }]);
    const getDelivery = vi.fn().mockResolvedValue({
      id: 'd1',
      webhook_name: 'github',
      fired_at: 100,
      status_code: 401,
      latency_ms: 5,
      signature_ok: false,
      body_text: '{"event":"ping"}',
      body_b64: btoa('{"event":"ping"}'),
    });

    render(
      <ApiProvider
        client={{ getWebhook, listWebhookDeliveries, getDelivery }}
        auth={{ mode: 'none' }}
      >
        <TaskFormPage instanceId="inst-a" taskName="github" embedded/>
      </ApiProvider>,
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Inspect' }));
    expect(await screen.findByText('{"event":"ping"}')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'view as hex' }));
    expect(screen.getByText(/7b226576656e7422/)).toBeInTheDocument();
  });

  test('Replay button posts to replay endpoint and refreshes rows', async () => {
    const getWebhook = vi.fn().mockResolvedValue({
      name: 'github',
      description: '',
      auth_scheme: 'hmac_sha256',
      verifier_mode: 'legacy_hmac',
      signature_header: 'x-hub-signature-256',
      enabled: true,
      has_secret: true,
    });
    const listWebhookDeliveries = vi.fn().mockResolvedValue([{
      id: 'd1',
      fired_at: 100,
      status_code: 401,
      latency_ms: 5,
      signature_ok: false,
    }]);
    const replayWebhookDelivery = vi.fn().mockResolvedValue({ ok: true });

    render(
      <ApiProvider
        client={{ getWebhook, listWebhookDeliveries, replayWebhookDelivery }}
        auth={{ mode: 'none' }}
      >
        <TaskFormPage instanceId="inst-a" taskName="github" embedded/>
      </ApiProvider>,
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Replay' }));
    await waitFor(() => expect(replayWebhookDelivery).toHaveBeenCalledWith('inst-a', 'github', 'd1'));
    expect(listWebhookDeliveries).toHaveBeenCalledTimes(2);
  });

  test('Pause toggle posts the enabled flag from the row', async () => {
    const listWebhooks = vi.fn().mockResolvedValue([{
      name: 'deploy',
      description: '',
      auth_scheme: 'hmac_sha256',
      verifier_mode: 'legacy_hmac',
      enabled: true,
      path: '/webhooks/inst-a/deploy',
    }]);
    const setWebhookEnabled = vi.fn().mockResolvedValue({
      name: 'deploy',
      description: '',
      auth_scheme: 'hmac_sha256',
      verifier_mode: 'legacy_hmac',
      enabled: false,
      path: '/webhooks/inst-a/deploy',
    });

    render(
      <ApiProvider
        client={{ listWebhooks, setWebhookEnabled }}
        auth={{ mode: 'none' }}
      >
        <TasksListPage instanceId="inst-a" embedded/>
      </ApiProvider>,
    );

    fireEvent.click(await screen.findByRole('button', { name: 'disable' }));
    await waitFor(() => expect(setWebhookEnabled).toHaveBeenCalledWith('inst-a', 'deploy', false));
  });
});
