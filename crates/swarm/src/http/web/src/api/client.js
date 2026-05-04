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
      const detail = await readErrorDetail(r);
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

  /// In-place rebuild.  Resets the dyson on its existing swarm id:
  /// fresh cube under the latest template, preserving config/MCP/
  /// bearer/DNS and replaying the sealed swarm state mirror for memory,
  /// chats, kb, and skills.
  resetInstance(id) {
    return this._json(`/v1/instances/${encodeURIComponent(id)}/reset`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
  }

  /// PATCH the employee profile.  Body fields are optional — pass only
  /// what you want changed.  When `models` or `tools` is supplied,
  /// swarm pushes the new value into the running agent via
  /// /api/admin/configure (Stage 8.3 runtime reconfigure).  An empty
  /// `tools` array is meaningful — it resets the row to "use agent
  /// defaults" — so we forward `[]` through to the backend instead
  /// of dropping it like the empty-models case.
  updateInstance(id, { name, task, models, tools } = {}) {
    const body = {};
    if (typeof name === 'string') body.name = name;
    if (typeof task === 'string') body.task = task;
    if (Array.isArray(models) && models.length > 0) body.models = models;
    if (Array.isArray(tools)) body.tools = tools;
    return this._json(`/v1/instances/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  instanceUrl(id) {
    return this._json(`/v1/instances/${encodeURIComponent(id)}/url`);
  }

  /// Change the instance's egress profile.  CubeAPI doesn't expose
  /// a runtime PATCH for the eBPF maps, so swarm orchestrates a
  /// snapshot+restore+destroy: workspace state survives, but the
  /// instance ID changes.  Caller should redirect to the new id.
  changeInstanceNetwork(id, networkPolicy) {
    return this._json(
      `/v1/instances/${encodeURIComponent(id)}/change-network`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ network_policy: networkPolicy }),
      },
    );
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

  /// Permanent delete: removes on-disk bytes (and remote backup bytes
  /// when promoted) and tombstones the row.  Idempotent on the server
  /// — calling twice on the same id returns 204 both times — so the
  /// SPA can safely optimistic-remove without disambiguating races.
  deleteSnapshot(id) {
    return this._json(`/v1/snapshots/${encodeURIComponent(id)}`, { method: 'DELETE' });
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

  // ─── Per-instance webhooks ("tasks" in UI copy) ────────────────────
  //
  // Each row is `{ name, description, auth_scheme, enabled, has_secret,
  // path, created_at, updated_at }`.  Signing keys never round-trip in
  // either direction — `has_secret` is the only signal the client gets,
  // and the secret lives in owner-sealed infrastructure storage that is
  // not passed into the agent runtime.

  listWebhooks(instanceId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/webhooks`,
      { headers: { Accept: 'application/json' } },
    );
  }

  getWebhook(instanceId, name) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/webhooks/${encodeURIComponent(name)}`,
    );
  }

  /// POST a new webhook.  Body: `{name, description, auth_scheme,
  /// secret?, enabled?}`.  `secret` is required for any scheme other
  /// than `none`.
  createWebhook(instanceId, body) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/webhooks`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
    );
  }

  /// PATCH an existing webhook.  Any of `description`, `auth_scheme`,
  /// `secret` (rotates the key), `enabled` may be supplied; missing
  /// fields stay unchanged.
  updateWebhook(instanceId, name, body) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/webhooks/${encodeURIComponent(name)}`,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
    );
  }

  deleteWebhook(instanceId, name) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/webhooks/${encodeURIComponent(name)}`,
      { method: 'DELETE' },
    );
  }

  /// Convenience wrapper around PATCH for the list-page enable/disable
  /// toggle.  Returns the refreshed row.
  setWebhookEnabled(instanceId, name, enabled) {
    return this.updateWebhook(instanceId, name, { enabled });
  }

  /// Recent delivery log for a webhook — newest first, capped at
  /// `limit` (default 50, max 200).  No payload bodies; metadata only.
  listWebhookDeliveries(instanceId, name, { limit = 50 } = {}) {
    const qs = limit ? `?limit=${encodeURIComponent(limit)}` : '';
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/webhooks/${encodeURIComponent(name)}/deliveries${qs}`,
      { headers: { Accept: 'application/json' } },
    );
  }

  /// Cross-task audit log for an instance — newest first, cursor-paginated
  /// by `fired_at` seconds.  `before` is the previous page's oldest
  /// `fired_at`; `webhook` filters to one task. Each row also carries
  /// `webhook_name` so the SPA can render which task fired it.
  listInstanceDeliveries(instanceId, { limit = 50, before, webhook } = {}) {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (before != null) params.set('before', String(before));
    if (webhook) params.set('webhook', webhook);
    const qs = params.toString();
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/deliveries${qs ? `?${qs}` : ''}`,
      { headers: { Accept: 'application/json' } },
    );
  }

  /// Single delivery row including the request body — for the audit
  /// detail page.  Returns `{ ..., body_text, body_b64 }`; `body_text`
  /// is set when the body is valid utf8, `body_b64` always carries the
  /// raw bytes so binary payloads round-trip cleanly.
  getDelivery(instanceId, deliveryId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/deliveries/${encodeURIComponent(deliveryId)}`,
      { headers: { Accept: 'application/json' } },
    );
  }

  // ─── Swarm-side artifact cache ─────────────────────────────────
  //
  // Backs the "all my artifacts" panel and the share-mint affordance.
  // Cubes are ephemeral; this surface persists past cube reset (bytes
  // live on swarm under [backup].local_cache_dir).  Each row is
  // `{id, instance_id, chat_id, kind, title, mime, bytes, created_at,
  // cached_at}`.

  /// Owner-wide listing across every instance.  Newest cached_at first.
  listMyArtifacts({ limit } = {}) {
    return this.listMyArtifactsPage({ limit }).then(page => page.rows);
  }

  listMyArtifactsPage({ limit, offset } = {}) {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (offset) params.set('offset', String(offset));
    const qs = params.toString();
    return this._json(
      `/v1/artifacts${qs ? `?${qs}` : ''}`,
      { headers: { Accept: 'application/json' } },
    ).then(rows => ({ rows: Array.isArray(rows) ? rows : [] }));
  }

  /// Per-instance listing, optionally narrowed to one chat (mirrors
  /// dyson's `/api/conversations/:chat/artifacts` shape).
  listInstanceArtifacts(instanceId, { chatId } = {}) {
    return this.listInstanceArtifactsPage(instanceId, { chatId }).then(page => page.rows);
  }

  listInstanceArtifactsPage(instanceId, { chatId, limit, offset } = {}) {
    const params = new URLSearchParams();
    if (chatId) params.set('chat_id', chatId);
    if (limit) params.set('limit', String(limit));
    if (offset) params.set('offset', String(offset));
    const qs = params.toString();
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/artifacts${qs ? `?${qs}` : ''}`,
      { headers: { Accept: 'application/json' } },
    ).then(rows => ({ rows: Array.isArray(rows) ? rows : [] }));
  }

  /// Pre-populate the cache for one chat by walking the cube's listing.
  /// Bodies are not pulled (memory blast radius); the share mint OR a
  /// `getInstanceArtifactRaw` call brings bytes in lazily.
  sweepInstanceArtifacts(instanceId, chatId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/artifacts/sweep`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId }),
      },
    );
  }

  /// Path to the swarm-served raw bytes — point an `<img>` or
  /// `<a download>` at this rather than fetching JSON.  Cache-first;
  /// falls through to the live cube on miss and write-throughs the
  /// bytes for next time.
  instanceArtifactRawUrl(instanceId, artifactId) {
    return `/v1/instances/${encodeURIComponent(instanceId)}/artifacts/${encodeURIComponent(artifactId)}/raw`;
  }

  /// Open the raw artifact in a new tab.  A plain `<a href>` to the
  /// /raw endpoint 401s — that surface is bearer-gated and a browser
  /// click can't carry the SPA's session token.  Workaround: fetch
  /// with the bearer, wrap the bytes in a blob URL, open that.  The
  /// blob URL is short-lived (revoked when the new tab closes) so
  /// the bytes don't leak to the address bar or referrer headers.
  /// Returns the blob URL so the caller can revoke it on cleanup.
  async openInstanceArtifactRaw(instanceId, artifactId) {
    const url = this.instanceArtifactRawUrl(instanceId, artifactId);
    const r = await this._authedFetch(url, { method: 'GET' });
    if (!r.ok) {
      const detail = await r.text().catch(() => '');
      throw httpError(`GET ${url}`, r.status, detail);
    }
    const blob = await r.blob();
    const objectUrl = URL.createObjectURL(blob);
    window.open(objectUrl, '_blank', 'noopener,noreferrer');
    // Revoke after a beat — the new tab has already loaded by then.
    setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
    return objectUrl;
  }

  /// Single-row metadata for the deep-linked artifact reader page.
  /// Returns null on 404 so the page can render an empty state.
  getInstanceArtifactMeta(instanceId, artifactId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/artifacts/${encodeURIComponent(artifactId)}`,
    ).catch(e => {
      if (e && e.status === 404) return null;
      throw e;
    });
  }

  /// Fetch raw artifact bytes + mime for in-SPA rendering (the
  /// reader pane uses this to render markdown, images, etc inline
  /// rather than dumping the body into a fresh tab).  Returns
  /// `{ blob, mime, text }` — text is the UTF-8 decode for the
  /// markdown render path; blob is for image / download paths.
  /// The caller is responsible for revoking any objectURL it
  /// creates from `blob`.
  async fetchInstanceArtifactBytes(instanceId, artifactId) {
    const url = this.instanceArtifactRawUrl(instanceId, artifactId);
    const r = await this._authedFetch(url, { method: 'GET' });
    if (!r.ok) {
      const detail = await r.text().catch(() => '');
      throw httpError(`GET ${url}`, r.status, detail);
    }
    const mime = r.headers.get('content-type') || '';
    const blob = await r.blob();
    let text = null;
    if (mime.startsWith('text/') || /json|xml|markdown/.test(mime)) {
      try { text = await blob.text(); } catch { /* binary fallback */ }
    }
    return { blob, mime, text };
  }

  /// Drop a row + its on-disk body.  Idempotent — 204 even when no
  /// row existed or the row wasn't owned by the caller.
  deleteInstanceArtifact(instanceId, artifactId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/artifacts/${encodeURIComponent(artifactId)}`,
      { method: 'DELETE' },
    );
  }

  // ─── Anonymous artifact shares ─────────────────────────────────
  //
  // `mintShare` returns `{url, jti, expires_at, label, created_at}`;
  // the URL is shown to the user once and never stored plaintext.
  // listShares returns rows of `{jti, instance_id, chat_id,
  // artifact_id, created_at, expires_at, revoked_at, label, active}`.
  // Revocation is by jti and is idempotent.

  mintShare(instanceId, artifactId, body) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/artifacts/${encodeURIComponent(artifactId)}/shares`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
    );
  }

  listShares(instanceId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/shares`,
      { headers: { Accept: 'application/json' } },
    );
  }

  revokeShare(jti) {
    return this._json(`/v1/shares/${encodeURIComponent(jti)}`, { method: 'DELETE' });
  }

  /// Re-derive the URL for an active share.  The signature is
  /// deterministic (postcard payload + per-user signing key), so the
  /// server hands the URL back on demand without ever storing
  /// plaintext.  Throws on revoked / expired shares (HTTP 410).
  getShareUrl(jti) {
    return this._json(`/v1/shares/${encodeURIComponent(jti)}/url`);
  }

  reissueShare(jti, ttl) {
    return this._json(`/v1/shares/${encodeURIComponent(jti)}/reissue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl }),
    });
  }

  listShareAccesses(jti) {
    return this._json(`/v1/shares/${encodeURIComponent(jti)}/accesses`);
  }

  /// Panic-button: rotate the user's signing key.  Every share they've
  /// ever issued instantly fails verification; the rows survive on
  /// the server for audit but the URLs are dead.
  rotateShareSigningKey() {
    return this._json('/v1/shares/rotate-key', { method: 'POST' });
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
  adminListMcpDockerCatalog() {
    return this._json('/v1/admin/mcp/docker-catalog', {
      headers: { Accept: 'application/json' },
    });
  }
  adminPutMcpDockerCatalogServer(id, { label, description = null, template, placeholders = [] }) {
    return this._json(`/v1/admin/mcp/docker-catalog/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, description, template, placeholders }),
    });
  }
  adminDeleteMcpDockerCatalogServer(id) {
    return this._json(`/v1/admin/mcp/docker-catalog/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  // ─── Provider keys (BYOK) ──────────────────────────────────────────
  //
  // Stage 7: per-user keys for any provider in the registry, plus a
  // single `byo` slot that carries both upstream URL and key.  Stored
  // server-side in user_secrets, encrypted under the user's age key
  // (same envelope used by the legacy lazy-minted OpenRouter key).

  /// `[{name, has_byok, has_platform, supports_byo}, ...]` for every
  /// provider in the adapter registry.  Drives the BYOK status table.
  listProviders() {
    return this._json('/v1/providers', { headers: { Accept: 'application/json' } });
  }

  /// `[{provider}, ...]` for the providers where the current caller
  /// has a BYOK row set.  Names only — never returns plaintext.
  listMyByok() {
    return this._json('/v1/byok', { headers: { Accept: 'application/json' } });
  }

  /// PUT a BYOK key.  Body shape:
  ///   - `{key}` for ordinary providers (anthropic, openai, groq, ...)
  ///   - `{upstream, key}` for `byo` (the user's custom endpoint)
  /// The server validates synchronously by probing the upstream — a
  /// 422 means the provider rejected the key, 502 means we couldn't
  /// reach the provider at all.
  putByok(provider, { key, upstream } = {}) {
    const body = upstream ? { key, upstream } : { key };
    return this._json(`/v1/byok/${encodeURIComponent(provider)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  /// DELETE a BYOK row.  Idempotent — 204 even when no row existed.
  deleteByok(provider) {
    return this._json(`/v1/byok/${encodeURIComponent(provider)}`, { method: 'DELETE' });
  }

  // ─── Per-instance MCP servers ──────────────────────────────────────
  //
  // Records live in user_secrets sealed under the user's age cipher.
  // Docker stdio servers can be added from one MCP JSON object; the
  // agent only ever sees a swarm proxy URL.

  /// `[{name, url, auth_kind, connected}, ...]` for one instance.
  /// `connected` is true for bearer/none entries (always usable) and
  /// for OAuth entries that have completed their flow at least once.
  /// Listing returns URLs with their query string + fragment stripped —
  /// the listing surface is read-only and we don't want a glance at the
  /// SPA to leak a query-string credential.  Edit-form pre-fill uses
  /// `getMcpServer` below, which serves the full URL.
  listMcpServers(instanceId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/servers`,
      { headers: { Accept: 'application/json' } },
    );
  }

  listMcpDockerCatalog() {
    return this._json('/v1/mcp/docker-catalog', {
      headers: { Accept: 'application/json' },
    });
  }

  putMcpDockerCatalogServer(instanceId, catalogId, placeholders = {}) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/docker-catalog/${encodeURIComponent(catalogId)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ placeholders }),
      },
    );
  }

  getMcpJsonConfig(instanceId, serverName = null) {
    const qs = serverName ? `?server=${encodeURIComponent(serverName)}` : '';
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/config${qs}`,
      { headers: { Accept: 'application/json' } },
    );
  }

  putMcpJsonConfig(instanceId, config) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/config`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      },
    );
  }

  deleteMcpJsonConfig(instanceId) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/config`,
      { method: 'DELETE' },
    );
  }

  /// Single-server detail with the FULL URL (query string included).
  /// Used by the edit modal to pre-fill without forcing the operator
  /// to re-enter a query-string credential they already saved.
  getMcpServer(instanceId, name) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/servers/${encodeURIComponent(name)}`,
      { headers: { Accept: 'application/json' } },
    );
  }

  /// PUT one server.  Body matches the hire-form serializer minus
  /// `name` (carried in the URL).  Idempotent — replaces existing rows.
  /// `enabled_tools` mirrors the built-in tools allowlist semantics:
  /// `null` ⇒ "use default" (proxy passes tools/list through unfiltered);
  /// an array ⇒ explicit allowlist (proxy filters tools/list responses
  /// and rejects tools/call for names outside the set).
  putMcpServer(instanceId, name, { url, auth, enabled_tools = null }) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/servers/${encodeURIComponent(name)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, auth, enabled_tools }),
      },
    );
  }

  /// Run a connection check: swarm opens an MCP session against the
  /// upstream (initialize + tools/list) and returns the catalog.  The
  /// catalog is also persisted on the entry so subsequent listMcpServers
  /// calls render it without round-tripping the upstream.
  /// Returns `{ ok: true, tools: [{name, description?}], last_checked_at }`
  /// on success.  Throws on transport / auth / upstream failure.
  checkMcpServer(instanceId, name) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/servers/${encodeURIComponent(name)}/check`,
      { method: 'POST' },
    );
  }

  /// Update only the `enabled_tools` allowlist on a server (URL + auth
  /// untouched).  `null` ⇒ "use default" (proxy stops filtering);
  /// array ⇒ explicit allowlist.  Used by the inline tool picker so
  /// toggling a checkbox doesn't have to round-trip the credential.
  setMcpEnabledTools(instanceId, name, enabled_tools) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/servers/${encodeURIComponent(name)}/enabled-tools`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled_tools }),
      },
    );
  }

  /// DELETE one server.  Pushes the new (smaller) `mcp_servers` block
  /// to the running dyson on success.
  deleteMcpServer(instanceId, name) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/servers/${encodeURIComponent(name)}`,
      { method: 'DELETE' },
    );
  }

  /// Wipe stored OAuth tokens so the next request through the proxy
  /// 428s "oauth not authorised yet" — used by the SPA's "disconnect"
  /// button when the user wants to force a re-auth.
  disconnectMcpServer(instanceId, name) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/servers/${encodeURIComponent(name)}/disconnect`,
      { method: 'POST' },
    );
  }

  /// Kick off an OAuth 2.1 flow.  Returns `{ authorization_url }` —
  /// the SPA navigates to it; the upstream provider redirects the
  /// user's browser to `<swarm>/mcp/oauth/callback` which finishes the
  /// flow and lands the user on `return_to` (or shows a small "you can
  /// close this tab" page when none was supplied).
  startMcpOAuth(instanceId, serverName, { return_to } = {}) {
    return this._json(
      `/v1/instances/${encodeURIComponent(instanceId)}/mcp/oauth/start`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_name: serverName, return_to: return_to || null }),
      },
    );
  }
}

async function readErrorDetail(response) {
  const raw = await response.text().catch(() => '');
  if (!raw) return '';
  const ct = response.headers.get('content-type') || '';
  if (!ct.includes('json')) return raw;
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed?.detail === 'string' && parsed.detail) return parsed.detail;
    if (typeof parsed?.error === 'string' && parsed.error) return parsed.error;
    if (typeof parsed?.message === 'string' && parsed.message) return parsed.message;
  } catch {
    // Fall through to the raw payload when the body claims JSON but
    // isn't parseable — better than losing the upstream hint.
  }
  return raw;
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
