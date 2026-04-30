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
