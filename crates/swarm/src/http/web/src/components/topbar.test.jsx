import { afterEach, describe, expect, test } from 'vitest';
import React from 'react';
import { cleanup, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { ApiProvider } from '../hooks/useApi.jsx';
import { TopBar } from './topbar.jsx';

afterEach(() => { cleanup(); });

describe('TopBar', () => {
  test('labels the artefacts nav item without the "all" prefix', () => {
    render(
      <ApiProvider client={{}} auth={{ mode: 'none' }}>
        <TopBar view={{ name: 'artefacts' }}/>
      </ApiProvider>,
    );

    expect(screen.getByRole('link', { name: 'artefacts' })).toHaveAttribute('href', '#/artefacts');
    expect(screen.queryByRole('link', { name: 'all artefacts' })).toBeNull();
  });
});
