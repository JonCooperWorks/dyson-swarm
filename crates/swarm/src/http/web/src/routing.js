const SPA_PATH_PREFIXES = [
  '/i/',
  '/new',
  '/admin',
  '/keys',
  '/artifacts',
];

function isSpaPath(path) {
  return SPA_PATH_PREFIXES.some(prefix => {
    if (prefix.endsWith('/')) return path.startsWith(prefix);
    return path === prefix || path.startsWith(`${prefix}/`);
  });
}

export function routeHashFromLocation(loc = window.location) {
  const hash = loc?.hash || '';
  if (hash.startsWith('#/')) return hash;
  const path = loc?.pathname || '/';
  if (!isSpaPath(path)) return '#/';
  return `#${path}${loc?.search || ''}`;
}

export function canonicalizePathRoute(loc = window.location, history = window.history) {
  const hash = loc?.hash || '';
  const path = loc?.pathname || '/';
  if (hash || !isSpaPath(path)) return false;
  history.replaceState(null, '', `/${routeHashFromLocation(loc)}`);
  return true;
}
