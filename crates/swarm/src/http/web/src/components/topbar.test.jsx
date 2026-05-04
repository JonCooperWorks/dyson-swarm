import { afterEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { cleanup, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { TopBar } from './topbar.jsx';

afterEach(() => { cleanup(); });

describe('TopBar', () => {
  test('labels the global artefacts nav item with its scope', () => {
    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TopBar view={{ name: 'artefacts' }}/>
      </ApiProvider>,
    );

    expect(screen.getByRole('link', { name: 'all artefacts' })).toHaveAttribute('href', '#/artefacts');
    expect(screen.getByRole('link', { name: 'agents' })).toHaveAttribute('href', '#/');
  });

  test('renders sign out as a topbar nav-aligned control', () => {
    const logout = vi.fn();
    render(
      <ApiProvider client={{}} auth={{ mode: 'oidc', logout }}>
        <TopBar view={{ name: 'instances' }}/>
      </ApiProvider>,
    );

    const button = screen.getByRole('button', { name: 'sign out' });
    expect(button).toHaveClass('topbar-signout');
  });
});
