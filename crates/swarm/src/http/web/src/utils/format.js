export function shortId(value, { head = 8, tail = 3, max = 12 } = {}) {
  const s = String(value || '');
  if (!s) return '—';
  return s.length > max ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
}

export function fmtBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

export function fmtTime(secs, { style = 'iso' } = {}) {
  if (!secs) return '—';
  try {
    const d = new Date(secs * 1000);
    if (style === 'locale') return d.toLocaleString();
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  } catch {
    return String(secs);
  }
}
