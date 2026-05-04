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
    expect(screen.getByRole('link', { name: 'mail-research' })).toBeInTheDocument();
    expect(screen.queryByText(/Decide whether to invest/i)).toBeNull();
  });
});

describe('TaskFormPage', () => {
  test('starts setup with the provider URL visible before create', () => {
    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TaskFormPage instanceId="inst-a" taskName={null} embedded/>
      </ApiProvider>,
    );

    expect(screen.getAllByText('provider URL').length).toBeGreaterThan(0);
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
});
