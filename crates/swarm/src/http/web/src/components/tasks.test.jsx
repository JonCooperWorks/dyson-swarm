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
  test('vendor tabs hide auth-scheme radios entirely', () => {
    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('tab', { name: 'Stripe' }));

    expect(screen.queryByRole('radio', { name: /HMAC-SHA256/i })).toBeNull();
    expect(screen.queryByRole('radio', { name: /Bearer/i })).toBeNull();
    expect(screen.queryByRole('radio', { name: /no auth/i })).toBeNull();
  });

  test('Custom tab shows all three auth-scheme radios', () => {
    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('tab', { name: 'Custom' }));

    expect(screen.getByRole('radio', { name: /HMAC-SHA256/i })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /Bearer/i })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /no auth/i })).toBeInTheDocument();
  });

  test('selecting Stripe tab hides Bearer and no-auth modes from the form state', async () => {
    const createWebhook = vi.fn().mockResolvedValue({
      name: 'stripe',
      description: '',
      preset_id: 'stripe',
      auth_scheme: 'hmac_sha256',
      signature_header: 'stripe-signature',
      enabled: true,
      path: '/webhooks/inst-a/stripe',
    });

    render(
      <ApiProvider client={{ createWebhook }} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('tab', { name: 'Stripe' }));
    expect(screen.queryByRole('radio', { name: /Bearer/i })).toBeNull();

    fireEvent.change(screen.getByLabelText('name'), {
      target: { value: 'stripe' },
    });
    fireEvent.change(screen.getByLabelText(/shared secret/i), {
      target: { value: 'stripe-secret-with-enough-length' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'create webhook' }));

    await waitFor(() => expect(createWebhook).toHaveBeenCalledTimes(1));
    expect(createWebhook.mock.calls[0][1]).toMatchObject({
      preset_id: 'stripe',
      auth_scheme: 'hmac_sha256',
      verifier_mode: 'hmac_v2',
      signature_header: 'stripe-signature',
    });
    expect(createWebhook.mock.calls[0][1]).not.toMatchObject({
      verifier_mode: 'bearer_v2',
    });
  });

  test('Svix create preserves the single-space signature separator', async () => {
    const createWebhook = vi.fn().mockResolvedValue({
      name: 'svix',
      description: '',
      preset_id: 'svix',
      auth_scheme: 'hmac_sha256',
      signature_header: 'svix-signature',
      enabled: true,
      path: '/webhooks/inst-a/svix',
    });

    render(
      <ApiProvider client={{ createWebhook }} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('tab', { name: 'Svix' }));
    fireEvent.change(screen.getByLabelText('name'), {
      target: { value: 'svix' },
    });
    fireEvent.change(screen.getByLabelText(/shared secret/i), {
      target: { value: 'svix-secret-with-enough-length' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'create webhook' }));

    await waitFor(() => expect(createWebhook).toHaveBeenCalledTimes(1));
    expect(createWebhook.mock.calls[0][1]).toMatchObject({
      preset_id: 'svix',
      signature_header: 'svix-signature',
      signature_separator: ' ',
      signature_value_split: ',',
      timestamp_header: 'svix-timestamp',
      payload_template: '{{id}}.{{timestamp}}.{{body}}',
      idempotency_header: 'svix-id',
    });
  });

  test('vendor tab renders read-only summary card with algo, encoding, signature header, payload template', () => {
    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('tab', { name: 'Stripe' }));

    expect(screen.getByText('Algorithm')).toBeInTheDocument();
    expect(screen.getByText('sha256')).toBeInTheDocument();
    expect(screen.getByText('Encoding')).toBeInTheDocument();
    expect(screen.getByText('hex')).toBeInTheDocument();
    expect(screen.getByText('Signature header')).toBeInTheDocument();
    expect(screen.getByText('stripe-signature')).toBeInTheDocument();
    expect(screen.getByText('Payload signed')).toBeInTheDocument();
    expect(screen.getByText('{{timestamp}}.{{body}}')).toBeInTheDocument();
  });

  test('vendor tab Generate button populates the secret field with 32 bytes of base64url', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });

    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('tab', { name: 'Standard Webhooks' }));
    fireEvent.click(screen.getByRole('button', { name: 'Generate' }));

    const secret = screen.getByLabelText(/shared secret/i);
    expect(secret.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(secret.value));
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
      target: { value: JSON.stringify({ headers: { 'webhook-id': 'msg_123' }, body: '{"event":"ping"}' }) },
    });
    fireEvent.click(screen.getByRole('button', { name: 'verify' }));

    await waitFor(() => expect(verifyWebhookDelivery).toHaveBeenCalledTimes(1));
    expect(verifyWebhookDelivery.mock.calls[0][2]).toMatchObject({
      headers: { 'webhook-id': 'msg_123' },
      body_b64: btoa('{"event":"ping"}'),
    });
    expect(await screen.findByText(/signatures did not match/i)).toBeInTheDocument();
  });

  test('Use last failed delivery button calls verify-only from last-failed', async () => {
    const verifyWebhookDelivery = vi.fn().mockResolvedValue({
      type: 'all_signatures_mismatched',
    });
    const getWebhook = vi.fn().mockResolvedValue({
      name: 'standard',
      description: '',
      preset_id: 'standard-webhooks',
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
    fireEvent.click(screen.getByRole('button', { name: /use last failed delivery/i }));

    await waitFor(() => expect(verifyWebhookDelivery).toHaveBeenCalledWith(
      'inst-a',
      'standard',
      null,
      { fromLastFailed: true },
    ));
  });

  test('tab row uses role=tab and arrow-key navigation works', () => {
    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    const standard = screen.getByRole('tab', { name: 'Standard Webhooks' });
    standard.focus();
    fireEvent.keyDown(standard, { key: 'ArrowRight' });
    expect(screen.getByRole('tab', { name: 'GitHub' })).toHaveFocus();
    fireEvent.keyDown(screen.getByRole('tab', { name: 'GitHub' }), { key: 'ArrowLeft' });
    expect(standard).toHaveFocus();
  });

  test('Replace flow on the secret field never echoes back from the server', async () => {
    const getWebhook = vi.fn().mockResolvedValue({
      name: 'stripe',
      description: '',
      preset_id: 'stripe',
      auth_scheme: 'hmac_sha256',
      verifier_mode: 'hmac_v2',
      signature_header: 'stripe-signature',
      signature_algo: 'sha256',
      signature_encoding: 'hex',
      signature_prefix: 'v1=',
      signature_separator: ',',
      signature_value_split: '=',
      timestamp_header: 'stripe-signature',
      timestamp_skew_secs: 300,
      payload_template: '{{timestamp}}.{{body}}',
      enabled: true,
      has_secret: true,
      secret: 'server-must-never-send-this',
    });

    render(
      <ApiProvider
        client={{ getWebhook, listWebhookDeliveries: vi.fn().mockResolvedValue([]) }}
        auth={{ mode: 'none' }}
      >
        <TaskFormPage instanceId="inst-a" taskName="stripe" embedded/>
      </ApiProvider>,
    );

    await screen.findByDisplayValue('stripe');
    expect(screen.queryByDisplayValue('server-must-never-send-this')).toBeNull();
    expect(screen.getByText('••••••••')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Replace' }));
    const secret = screen.getByLabelText(/shared secret/i);
    expect(secret).toHaveValue('');
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
    expect(screen.getByText(/6d73675f313233/)).toBeInTheDocument();
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
    expect(screen.getAllByRole('button', { name: 'copy' })[0]).toBeEnabled();
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
      target: { value: 'super-secret-with-enough-length' },
    });
    fireEvent.click(screen.getByRole('tab', { name: 'Custom' }));
    fireEvent.change(screen.getByLabelText('signature header'), {
      target: { value: 'X-Hub-Signature-256' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'create webhook' }));

    await waitFor(() => expect(createWebhook).toHaveBeenCalledTimes(1));
    expect(createWebhook.mock.calls[0][1]).toMatchObject({
      name: 'github',
      auth_scheme: 'hmac_sha256',
      signature_header: 'x-hub-signature-256',
      secret: 'super-secret-with-enough-length',
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
