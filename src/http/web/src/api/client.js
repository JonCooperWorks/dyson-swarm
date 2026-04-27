/* warden — HTTP client for the orchestrator's REST API.
 *
 * Every method maps to one endpoint in src/http/*.rs.  Constructor
 * accepts an injectable fetch + getToken so tests can mock without
 * touching globals.
 *
 * Auth shape: every request goes through _authedFetch which stamps
 * `Authorization: Bearer <token>` (when getToken returns one).  The
 * SPA uses the token from sessionStorage; CLI / curl callers attach
 * their own bearer.  No cookies, no CSRF marker — Authorization
 * headers can't be auto-attached cross-origin without preflight, so
 * CSRF isn't a viable attack against this surface.
 */

export class WardenClient {
  constructor({ fetch: fetchImpl, getToken } = {}) {
    const globalFetch = typeof globalThis.fetch === 'function'
      ? globalThis.fetch.bind(globalThis)
      : null;
    this._fetch = fetchImpl === undefined ? globalFetch : fetchImpl;
    this._getToken = typeof getToken === 'function' ? getToken : () => null;
    if (!this._fetch) throw new Error('WardenClient: no fetch implementation available');
  }

  _authedFetch(url, init) {
    const headers = new Headers((init && init.headers) || {});
    const token = this._getToken();
    if (token && !headers.has('authorization')) {
      headers.set('authorization', `Bearer ${token}`);
    }
    return this._fetch(url, { ...(init || {}), headers });
  }

  async _json(url, init) {
    const r = await this._authedFetch(url, init);
    if (!r.ok) {
      const detail = await r.text().catch(() => '');
      throw httpError(`${(init && init.method) || 'GET'} ${url}`, r.status, detail);
    }
    // 204 No Content carries no body — return null rather than choking
    // on JSON.parse('').
    if (r.status === 204) return null;
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('json')) return null;
    return r.json();
  }

  // ─── Instances ──────────────────────────────────────────────────

  listInstances({ status } = {}) {
    const qs = status ? `?status=${encodeURIComponent(status)}` : '';
    return this._json(`/v1/instances${qs}`, { headers: { Accept: 'application/json' } });
  }

  getInstance(id) {
    return this._json(`/v1/instances/${encodeURIComponent(id)}`);
  }

  createInstance(req) {
    return this._json('/v1/instances', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
  }

  destroyInstance(id) {
    return this._json(`/v1/instances/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  instanceUrl(id) {
    return this._json(`/v1/instances/${encodeURIComponent(id)}/url`);
  }

  probeInstance(id) {
    return this._json(`/v1/instances/${encodeURIComponent(id)}/probe`, { method: 'POST' });
  }

  // ─── Snapshots / backups / restore ──────────────────────────────

  snapshotInstance(id, name) {
    const body = name ? JSON.stringify({ name }) : '{}';
    return this._json(`/v1/instances/${encodeURIComponent(id)}/snapshot`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
  }

  backupInstance(id, name) {
    const body = name ? JSON.stringify({ name }) : '{}';
    return this._json(`/v1/instances/${encodeURIComponent(id)}/backup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
  }

  restoreInstance(req) {
    return this._json(`/v1/instances/${encodeURIComponent(req.instance_id || '')}/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
  }

  pullSnapshot(id) {
    return this._json(`/v1/snapshots/${encodeURIComponent(id)}/pull`, { method: 'POST' });
  }

  // ─── Per-instance secrets ───────────────────────────────────────

  putSecret(instanceId, name, value) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/secrets/${encodeURIComponent(name)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value }),
      },
    );
  }

  deleteSecret(instanceId, name) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/secrets/${encodeURIComponent(name)}`,
      { method: 'DELETE' },
    );
  }

  // ─── Admin (admin-bearer required; OIDC users can't reach these) ─

  adminListUsers() {
    return this._json('/v1/admin/users');
  }
  adminActivateUser(id) {
    return this._json(`/v1/admin/users/${encodeURIComponent(id)}/activate`, { method: 'POST' });
  }
  adminSuspendUser(id) {
    return this._json(`/v1/admin/users/${encodeURIComponent(id)}/suspend`, { method: 'POST' });
  }
  adminMintApiKey(id, label) {
    return this._json(`/v1/admin/users/${encodeURIComponent(id)}/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: label || null }),
    });
  }
  adminRevokeApiKey(token) {
    return this._json(`/v1/admin/users/keys/${encodeURIComponent(token)}`, { method: 'DELETE' });
  }
  adminRevokeProxyToken(token) {
    return this._json(
      `/v1/admin/proxy_tokens/${encodeURIComponent(token)}/revoke`,
      { method: 'POST' },
    );
  }
}

// Surface HTTP status on the thrown error so callers can branch on
// 401 / 403 / 404 without parsing strings.
function httpError(label, status, detail) {
  const msg = `${label}: ${status}${detail ? ` — ${detail}` : ''}`;
  const e = new Error(msg);
  e.status = status;
  e.detail = detail || '';
  return e;
}
