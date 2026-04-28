/* swarm — HTTP client for the orchestrator's REST API.
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

export class SwarmClient {
  constructor({ fetch: fetchImpl, getToken } = {}) {
    const globalFetch = typeof globalThis.fetch === 'function'
      ? globalThis.fetch.bind(globalThis)
      : null;
    this._fetch = fetchImpl === undefined ? globalFetch : fetchImpl;
    this._getToken = typeof getToken === 'function' ? getToken : () => null;
    if (!this._fetch) throw new Error('SwarmClient: no fetch implementation available');
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

  /// PATCH the employee profile.  Body fields are optional — pass only
  /// what you want changed.  When `models` is supplied (non-empty
  /// array), swarm also pushes the new list into the running dyson
  /// via /api/admin/configure (Stage 8.3 runtime reconfigure).
  updateInstance(id, { name, task, models } = {}) {
    const body = {};
    if (typeof name === 'string') body.name = name;
    if (typeof task === 'string') body.task = task;
    if (Array.isArray(models) && models.length > 0) body.models = models;
    return this._json(`/v1/instances/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
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

  listSnapshotsForInstance(instanceId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/snapshots`,
      { headers: { Accept: 'application/json' } },
    );
  }

  // ─── Models (upstream provider catalogue) ──────────────────────

  /// Returns `{ models: ["anthropic/claude-sonnet-4-5", ...] }` from
  /// the configured upstream LLM provider (e.g. OpenRouter).  Used by
  /// the create-form picker so the SPA never talks to the upstream
  /// directly.
  listProviderModels() {
    return this._json('/v1/models', { headers: { Accept: 'application/json' } });
  }

  // ─── Per-instance secrets ───────────────────────────────────────

  // Returns names only (the backend deliberately strips values).
  listSecretNames(instanceId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/secrets`,
      { headers: { Accept: 'application/json' } },
    );
  }

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

  // ─── Admin (caller must carry the configured admin permission/role) ─

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
  /// Stage 6: set the user's OpenRouter USD spend cap.  Mirrors
  /// upstream when the user already has a key minted.
  adminSetOpenRouterLimit(id, limit_usd) {
    return this._json(`/v1/admin/users/${encodeURIComponent(id)}/openrouter_limit`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ limit_usd }),
    });
  }
  /// Stage 6: force a fresh OpenRouter key mint for the user.
  /// Returns the plaintext once — surface immediately, never log.
  adminForceMintOpenRouterKey(id) {
    return this._json(`/v1/admin/users/${encodeURIComponent(id)}/openrouter_key/mint`, {
      method: 'POST',
    });
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
