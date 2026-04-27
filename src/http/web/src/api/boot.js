/* warden — cold-load.
 *
 * After auth bootstrap and before React mounts we probe the API to
 * confirm the user's account is active and pull the initial instance
 * list into the store.  Failures bubble up as a banner — the shell
 * still renders so the user can see what went wrong.
 */

import { setInstances, setBootstrapped, setLoadError } from '../store/app.js';

export async function boot(client) {
  try {
    const list = await client.listInstances();
    setInstances(Array.isArray(list) ? list : []);
    setBootstrapped(true);
    return { ok: true };
  } catch (err) {
    setBootstrapped(true);
    setLoadError(err?.message || 'failed to reach warden');
    // 403 from user_middleware means the user's row exists but isn't
    // Active — surface it so the splash can guide them to ask their
    // admin for activation.
    if (err?.status === 403) return { ok: false, reason: 'inactive' };
    if (err?.status === 401) return { ok: false, reason: 'unauthenticated' };
    return { ok: false, reason: 'network', error: err };
  }
}
