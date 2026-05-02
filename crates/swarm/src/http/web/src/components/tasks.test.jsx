import { afterEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { setWebhooksFor } from '../store/app.js';
import { AuditListPage } from './tasks.jsx';

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
    expect(screen.getByRole('combobox')).toHaveDisplayValue('all tasks');
    expect(screen.getByText('no deliveries yet')).toBeInTheDocument();
    expect(listInstanceDeliveries.mock.calls[0][1]).not.toHaveProperty('q');
  });
});
