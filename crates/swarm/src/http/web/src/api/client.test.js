/* Tests for the swarm SPA's SwarmClient HTTP wrapper.
 *
 * The interesting bits to lock down:
 *   - Authorization: Bearer header is stamped from the injected getToken
 *   - the `getToken` callback is consulted on every request (we don't
 *     cache a stale value)
 *   - Path components are URL-encoded (id with slash, name with space)
 *   - 204 No Content returns null (not a parse error)
 *   - non-2xx surfaces an Error with .status
 */
import { describe, expect, test, vi } from 'vitest';

import { SwarmClient } from './client.js';

function jsonResponse(body, init = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

// Response constructor in jsdom rejects bodyless statuses (204/304); use a
// builder that bypasses the constructor's body restriction.
function noContentResponse() {
  return new Response(null, { status: 204, headers: {} });
}

describe('SwarmClient', () => {
  test('stamps Authorization: Bearer when getToken returns a value', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ instances: [] }));
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => 'tok-abc' });
    await client.listInstances();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [, init] = fetchImpl.mock.calls[0];
    const auth = init.headers.get('authorization');
    expect(auth).toBe('Bearer tok-abc');
  });

  test('does not stamp Authorization when getToken returns null', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ instances: [] }));
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.listInstances();
    const [, init] = fetchImpl.mock.calls[0];
    expect(init.headers.get('authorization')).toBeNull();
  });

  test('regression: getToken is called fresh on every request, not cached', async () => {
    let token = 'first';
    // Distinct Response objects per call — Response bodies are single-use.
    const fetchImpl = vi.fn(() => Promise.resolve(jsonResponse({})));
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => token });
    await client.listInstances();
    token = 'second';
    await client.listInstances();
    expect(fetchImpl.mock.calls[0][1].headers.get('authorization')).toBe('Bearer first');
    expect(fetchImpl.mock.calls[1][1].headers.get('authorization')).toBe('Bearer second');
  });

  test('encodes path components — slash in instance id cannot escape route', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({}));
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.getInstance('abc/../admin');
    const [url] = fetchImpl.mock.calls[0];
    expect(url).toBe('/v1/instances/abc%2F..%2Fadmin');
  });

  test('encodes secret name path component', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(noContentResponse());
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.putSecret('inst1', 'API KEY', 'val');
    const [url] = fetchImpl.mock.calls[0];
    expect(url).toBe('/v1/instances/inst1/secrets/API%20KEY');
  });

  test('remote MCP add/update uses the per-server API path', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.putMcpServer('inst/1', 'linear server', {
      url: 'https://api.linear.app/mcp',
      auth: { kind: 'none' },
    });
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe('/v1/instances/inst%2F1/mcp/servers/linear%20server');
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body)).toEqual({
      url: 'https://api.linear.app/mcp',
      auth: { kind: 'none' },
      enabled_tools: null,
    });
  });

  test('Docker MCP JSON uses only the single-server config API path', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    const config = {
      servers: {
        github: {
          type: 'stdio',
          command: 'docker',
          args: ['run', '-i', '--rm', 'ghcr.io/example/github-mcp'],
        },
      },
    };
    await client.putMcpJsonConfig('inst/1', config);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe('/v1/instances/inst%2F1/mcp/config');
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body)).toEqual(config);
  });

  test('Docker MCP JSON fetch can be scoped to one server', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ config: { servers: {} } }));
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.getMcpJsonConfig('inst/1', 'github server');
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe('/v1/instances/inst%2F1/mcp/config?server=github%20server');
    expect(init.headers.get('accept')).toBe('application/json');
  });

  test('admin Docker MCP catalog methods use admin routes', async () => {
    const fetchImpl = vi.fn(() => Promise.resolve(jsonResponse({ ok: true })));
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.adminListMcpDockerCatalog();
    await client.adminPutMcpDockerCatalogServer('github/preset', {
      label: 'GitHub',
      description: null,
      template: '{"servers":{}}',
      credentials: [{ id: 'github_token', label: 'GitHub token' }],
    });
    await client.adminDeleteMcpDockerCatalogServer('github/preset');

    expect(fetchImpl.mock.calls[0][0]).toBe('/v1/admin/mcp/docker-catalog');
    expect(fetchImpl.mock.calls[0][1].headers.get('accept')).toBe('application/json');
    expect(fetchImpl.mock.calls[1][0]).toBe('/v1/admin/mcp/docker-catalog/github%2Fpreset');
    expect(fetchImpl.mock.calls[1][1].method).toBe('PUT');
    expect(JSON.parse(fetchImpl.mock.calls[1][1].body)).toEqual({
      label: 'GitHub',
      description: null,
      template: '{"servers":{}}',
      credentials: [{ id: 'github_token', label: 'GitHub token' }],
    });
    expect(fetchImpl.mock.calls[2][0]).toBe('/v1/admin/mcp/docker-catalog/github%2Fpreset');
    expect(fetchImpl.mock.calls[2][1].method).toBe('DELETE');
  });

  test('204 No Content returns null instead of throwing on JSON parse', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(noContentResponse());
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    const out = await client.destroyInstance('i1');
    expect(out).toBeNull();
  });

  test('non-2xx throws an Error with .status set', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response('forbidden', { status: 403, headers: { 'Content-Type': 'text/plain' } }),
    );
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    let thrown;
    try {
      await client.listInstances();
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(thrown.status).toBe(403);
    expect(thrown.detail).toBe('forbidden');
  });

  test('non-2xx unwraps JSON error payloads into .detail', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: 'no client_id and no registration endpoint' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    let thrown;
    try {
      await client.startMcpOAuth('i1', 'github');
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(thrown.status).toBe(400);
    expect(thrown.detail).toBe('no client_id and no registration endpoint');
    expect(thrown.message).toContain('no client_id and no registration endpoint');
  });

  test('createInstance posts JSON body with Content-Type', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse({ id: 'new1' }));
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => 'tok' });
    await client.createInstance({ template_id: 't', env: { SWARM_MODEL: 'gpt-4o' } });
    const [, init] = fetchImpl.mock.calls[0];
    expect(init.method).toBe('POST');
    expect(init.headers.get('content-type')).toBe('application/json');
    expect(JSON.parse(init.body)).toEqual({
      template_id: 't',
      env: { SWARM_MODEL: 'gpt-4o' },
    });
  });

  test('updateInstance: omits empty/missing fields from the PATCH body', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(noContentResponse());
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.updateInstance('i1', { name: 'rename', task: '', models: [] });
    const [, init] = fetchImpl.mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body).toEqual({ name: 'rename', task: '' }); // empty models[] dropped
  });

  test('updateInstance: forwards a non-empty `tools` array verbatim', async () => {
    // Regression for the silent-drop bug.  Earlier the destructure was
    // `{ name, task, models }` and any `tools` array on the call site
    // was thrown away before reaching the wire — so unchecking a tool
    // in the SPA edit form fired a PATCH with no `tools` key and the
    // backend's update_tools branch never ran.
    const fetchImpl = vi.fn().mockResolvedValue(noContentResponse());
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.updateInstance('i1', {
      name: 'axelrod',
      task: 'do the thing',
      tools: ['read_file', 'write_file', 'list_files'],
    });
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe('/v1/instances/i1');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body)).toEqual({
      name: 'axelrod',
      task: 'do the thing',
      tools: ['read_file', 'write_file', 'list_files'],
    });
  });

  test('updateInstance: forwards `tools: []` (meaningful — resets to defaults)', async () => {
    // Distinct from the empty-models case: an empty tools array is
    // the sentinel for "use agent defaults" on the swarm side, so the
    // client must NOT collapse it to "no field sent".
    const fetchImpl = vi.fn().mockResolvedValue(noContentResponse());
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.updateInstance('i1', { tools: [] });
    const body = JSON.parse(fetchImpl.mock.calls[0][1].body);
    expect(body).toEqual({ tools: [] });
  });

  test('updateInstance: drops `tools` when not an array', async () => {
    // null/undefined/missing all mean "leave tools unchanged" — same
    // semantic the swarm handler enforces (Option<Vec> with serde
    // default).
    const fetchImpl = vi.fn().mockResolvedValue(noContentResponse());
    const client = new SwarmClient({ fetch: fetchImpl, getToken: () => null });
    await client.updateInstance('i1', { name: 'rename', tools: null });
    const body = JSON.parse(fetchImpl.mock.calls[0][1].body);
    expect(body).toEqual({ name: 'rename' });
  });

  test('throws when no fetch is available', () => {
    expect(() => new SwarmClient({ fetch: null })).toThrow(/no fetch implementation/);
  });
});
