export function resolveApiBase(value?: string, hosted = false): string {
  const input = value?.trim() ?? '';
  if (!input || input === '/api') {
    if (hosted) throw new Error('Set VITE_API_BASE_URL to your HTTPS backend origin in Vercel.');
    return '/api';
  }
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error('VITE_API_BASE_URL must be an HTTP(S) backend origin or /api.');
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !['', '/', '/api', '/api/'].includes(url.pathname) ||
    /[\s<>"']/.test(input)
  ) {
    throw new Error(
      'VITE_API_BASE_URL must be an HTTP(S) origin, optionally ending in /api, without credentials, query, or fragment.',
    );
  }
  if (
    hosted &&
    (url.protocol !== 'https:' ||
      /^(localhost|127(?:\.\d+){3}|\[::1\])$/.test(url.hostname) ||
      url.hostname.endsWith('.localhost'))
  ) {
    throw new Error('Vercel requires an external HTTPS VITE_API_BASE_URL, not a local backend.');
  }
  return `${url.origin}/api`;
}
