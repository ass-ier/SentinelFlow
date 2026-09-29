import type { BeforeSendEvent } from '@vercel/analytics/react';

const publicPages = new Set([
  '/',
  '/events',
  '/alerts',
  '/rules',
  '/testing',
  '/replay',
  '/sigma',
  '/evidence',
]);

export function analyticsRoute(pathname: string): string | null {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/dashboard') return '/';
  if (path === '/detections') return '/testing';
  if (publicPages.has(path)) return path;
  const detail = /^\/(events|alerts|rules)\/[^/]+$/.exec(path);
  return detail ? `/${detail[1]}/:id` : null;
}

export function safeAnalyticsReferrer(referrer: string): boolean {
  if (!referrer) return true;
  try {
    const url = new URL(referrer);
    return (
      ['https:', 'http:'].includes(url.protocol) &&
      url.pathname === '/' &&
      !url.search &&
      !url.hash &&
      !url.username &&
      !url.password
    );
  } catch {
    return false;
  }
}

export function redactAnalyticsPageView(
  event: BeforeSendEvent,
  origin: string,
): BeforeSendEvent | null {
  if (event.type !== 'pageview') return null;
  try {
    const url = new URL(event.url);
    const route = analyticsRoute(url.pathname);
    if (url.origin !== origin || !route) return null;
    return { type: 'pageview', url: `${origin}${route}` };
  } catch {
    return null;
  }
}
