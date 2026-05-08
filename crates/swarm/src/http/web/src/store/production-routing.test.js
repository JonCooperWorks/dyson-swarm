import { afterEach, describe, expect, test, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const WEB_ROOT = resolve(__dirname, '..', '..');

afterEach(() => {
  vi.restoreAllMocks();
  delete globalThis.__REACT_DEVTOOLS_GLOBAL_HOOK__;
  document.body.innerHTML = '';
  sessionStorage.clear();
  window.history.pushState(null, '', '/');
});

describe('production route bootstrap', () => {
  test('refreshing an instance section route survives React DevTools injection', async () => {
    const outDir = mkdtempSync(join(tmpdir(), 'swarm-web-prod-'));
    try {
      execFileSync(
        'npm',
        ['run', 'build:nocheck', '--', '--outDir', outDir, '--emptyOutDir'],
        { cwd: WEB_ROOT, stdio: 'pipe' },
      );
      const assetDir = join(outDir, 'assets');
      const assets = await readdir(assetDir);
      const entry = assets.find(name => name.endsWith('.js'));
      expect(entry).toBeTruthy();

      document.body.innerHTML = '<div id="root"></div>';
      window.history.pushState(null, '', '/#/i/a/skills');
      sessionStorage.setItem('swarm:auth', JSON.stringify({
        access_token: 'header.payload.signature',
        expires_at: Date.now() + 60 * 60 * 1000,
      }));
      globalThis.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {
        supportsFiber: true,
        isDisabled: false,
        inject: vi.fn(() => undefined),
        onScheduleFiberRoot: vi.fn(),
        onCommitFiberRoot: vi.fn(),
        onCommitFiberUnmount: vi.fn(),
      };
      const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
      vi.stubGlobal('fetch', vi.fn(mockFetch));

      const bundle = readFileSync(join(assetDir, entry), 'utf8');
      Function(`${bundle}\n//# sourceURL=${join(assetDir, entry)}`)();

      await waitFor(() => {
        expect(document.body.textContent).toContain('Alpha');
        expect(document.body.textContent).toContain('skills');
      });
      expect(consoleError).not.toHaveBeenCalledWith(
        expect.stringContaining('Cannot read properties of undefined'),
        expect.anything(),
      );
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  }, 30000);
});

function jsonResponse(body, init = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

function mockFetch(input) {
  const url = String(input);
  if (url === '/auth/config') {
    return Promise.resolve(jsonResponse({
      mode: 'oidc',
      issuer: 'https://issuer.test',
      audience: 'aud',
      client_id: 'cid',
      required_scopes: [],
    }));
  }
  if (url === 'https://issuer.test/.well-known/openid-configuration') {
    return Promise.resolve(jsonResponse({
      authorization_endpoint: 'https://issuer.test/authorize',
      token_endpoint: 'https://issuer.test/token',
    }));
  }
  if (url === '/auth/session') {
    return Promise.resolve(jsonResponse({ ok: true }));
  }
  if (url === '/v1/instances') {
    return Promise.resolve(jsonResponse([instanceRow()]));
  }
  if (url === '/v1/instances/a') {
    return Promise.resolve(jsonResponse(instanceRow()));
  }
  if (
    url === '/v1/instances/a/webhooks'
    || url === '/v1/instances/a/shares'
    || url === '/v1/instances/a/skills'
  ) {
    return Promise.resolve(jsonResponse([]));
  }
  return Promise.resolve(jsonResponse({}, { status: 404 }));
}

function instanceRow() {
  return {
    id: 'a',
    name: 'Alpha',
    status: 'live',
    task: 'Run useful work.',
    created_at: 0,
    last_active_at: 0,
    last_probe_at: null,
    open_url: 'https://a.example.test/',
    network_policy: { kind: 'nolocalnet', entries: [] },
    tools: [],
    models: ['openrouter/test'],
  };
}
