import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  analyticsRoute,
  redactAnalyticsPageView,
  safeAnalyticsReferrer,
} from '../src/services/analytics';
import { deferred, json, mockApi, renderApp } from './helpers';

const publicHealth = { status: 'ok', version: '0.1.0', auth_required: false, public_demo: true };
const origin = window.location.origin;
const analyticsScript = () => document.querySelector('script[src="/_vercel/insights/script.js"]');

beforeEach(() => {
  vi.stubEnv('PROD', true);
  vi.stubEnv('VITE_WEB_ANALYTICS', 'true');
  delete window.va;
  delete window.vaq;
  delete window.vai;
  delete window.vam;
  analyticsScript()?.remove();
});

afterEach(() => {
  vi.unstubAllEnvs();
  analyticsScript()?.remove();
  delete window.va;
  delete window.vaq;
  delete window.vai;
  delete window.vam;
});

describe('analytics data minimization', () => {
  it.each([
    ['/', '/'],
    ['/dashboard', '/'],
    ['/events', '/events'],
    ['/events/sensitive-event-id', '/events/:id'],
    ['/alerts/sensitive-alert-id/', '/alerts/:id'],
    ['/rules/AUTH-001', '/rules/:id'],
    ['/detections', '/testing'],
    ['/testing', '/testing'],
    ['/replay', '/replay'],
    ['/sigma', '/sigma'],
    ['/evidence', '/evidence'],
    ['/integrations', null],
    ['/notifications/private-delivery', null],
    ['/unknown/customer-name', null],
    ['/alerts/id/nested-private-path', null],
  ])('aggregates or excludes %s', (path, expected) => {
    expect(analyticsRoute(path)).toBe(expected);
  });

  it('removes queries, fragments and record IDs from the actual outbound URL', () => {
    expect(
      redactAnalyticsPageView(
        {
          type: 'pageview',
          url: `${origin}/alerts/private-alert?run_id=private-run&q=person%40example.test#raw`,
        },
        origin,
      ),
    ).toEqual({ type: 'pageview', url: `${origin}/alerts/:id` });
  });

  it.each([
    { type: 'event' as const, url: `${origin}/events` },
    { type: 'pageview' as const, url: 'not a URL' },
    { type: 'pageview' as const, url: 'https://unrelated.example.test/events' },
    { type: 'pageview' as const, url: `${origin}/integrations` },
  ])('drops unsupported or untrusted events: $url', (event) => {
    expect(redactAnalyticsPageView(event, origin)).toBeNull();
  });

  it.each(['', 'https://www.linkedin.com/', 'https://example.test'])(
    'permits empty or origin-only referrals: %s',
    (referrer) => expect(safeAnalyticsReferrer(referrer)).toBe(true),
  );

  it.each([
    'https://example.test/events/private-id',
    'https://example.test/?q=private-search',
    'https://example.test/#private-note',
    'https://user:password@example.test/',
    'file:///private/path',
    'invalid',
  ])('does not expose a detailed or malformed referral: %s', (referrer) => {
    expect(safeAnalyticsReferrer(referrer)).toBe(false);
  });
});

describe('production public-demo analytics', () => {
  it('waits for positive public-mode confirmation before loading the collector', async () => {
    const pending = deferred<typeof publicHealth>();
    const va = vi.fn();
    window.va = va;
    mockApi({ 'GET /api/health': () => pending.promise });
    renderApp('/events?run_id=private-run&q=private-search');
    expect(analyticsScript()).toBeNull();
    expect(va).not.toHaveBeenCalled();
    pending.resolve(publicHealth);
    await screen.findByText('Demo API connected');
    await waitFor(() => expect(analyticsScript()).not.toBeNull());
    expect(analyticsScript()).toHaveAttribute('data-disable-auto-track', '1');
    expect(analyticsScript()).toHaveAttribute('data-view-endpoint', '/_vercel/insights/view');
    expect(va).toHaveBeenCalledWith('pageview', { route: '/events', path: '/events' });
    expect(JSON.stringify(va.mock.calls)).not.toMatch(/private-run|private-search/);
  });

  it.each(['development', 'local build', 'private backend', 'failed health', 'unsafe referral'])(
    'does not load analytics for %s',
    async (mode) => {
      if (mode === 'development') vi.stubEnv('PROD', false);
      if (mode === 'local build') vi.stubEnv('VITE_WEB_ANALYTICS', 'false');
      if (mode === 'unsafe referral')
        vi.spyOn(document, 'referrer', 'get').mockReturnValue(
          'https://example.test/?token=private',
        );
      mockApi({
        'GET /api/health':
          mode === 'private backend'
            ? { ...publicHealth, public_demo: false }
            : mode === 'failed health'
              ? json({ error: { message: 'Offline' } }, 503)
              : publicHealth,
      });
      renderApp('/');
      await screen.findByRole('heading', { name: 'Overview' });
      await waitFor(() =>
        expect(
          mode === 'failed health'
            ? screen.getByText('API unavailable')
            : screen.getByText(
                mode === 'private backend' ? 'Local API connected' : 'Demo API connected',
              ),
        ).toBeInTheDocument(),
      );
      expect(analyticsScript()).toBeNull();
      expect(window.va).toBeUndefined();
    },
  );

  it('tracks SPA page changes without treating search changes as new page views', async () => {
    const va = vi.fn();
    window.va = va;
    mockApi({ 'GET /api/health': publicHealth });
    const user = userEvent.setup();
    renderApp('/');
    await screen.findByText('Demo API connected');
    await waitFor(() => expect(va).toHaveBeenCalledWith('pageview', { route: '/', path: '/' }));
    await user.click(screen.getByRole('link', { name: 'Events' }));
    await screen.findByRole('heading', { name: 'Event explorer' });
    await waitFor(() =>
      expect(va).toHaveBeenCalledWith('pageview', { route: '/events', path: '/events' }),
    );
    const beforeSearch = va.mock.calls.filter(([type]) => type === 'pageview').length;
    await user.type(screen.getByLabelText('Search events'), 'private-user');
    await user.click(screen.getByRole('button', { name: 'Search' }));
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('q=private-user'));
    expect(va.mock.calls.filter(([type]) => type === 'pageview')).toHaveLength(beforeSearch);
    expect(analyticsScript()).toHaveAttribute('src', '/_vercel/insights/script.js');
  });

  it('does not load the collector on unknown or private-management routes', async () => {
    mockApi({ 'GET /api/health': publicHealth });
    renderApp('/unknown/private-identifier');
    await screen.findByText('Demo API connected');
    expect(analyticsScript()).toBeNull();
    expect(window.va).toBeUndefined();
  });

  it('discloses analytics on the hosted public limits page without showing developer logs', async () => {
    mockApi({ 'GET /api/health': publicHealth });
    renderApp('/evidence');
    await screen.findByRole('heading', { name: 'Website usage analytics' });
    expect(screen.queryByLabelText('Actual validation command output')).not.toBeInTheDocument();
    expect(screen.getByText(/Search values, URL parameters, fragments/)).toBeInTheDocument();
  });

  it('stops a loaded collector from sending after health failure or app unmount', async () => {
    const va = vi.fn();
    window.va = va;
    mockApi({ 'GET /api/health': publicHealth });
    const user = userEvent.setup();
    const rendered = renderApp('/');
    await screen.findByText('Demo API connected');
    await waitFor(() => expect(analyticsScript()).not.toBeNull());
    const callback = va.mock.calls.find(([type]) => type === 'beforeSend')?.[1];
    expect(typeof callback).toBe('function');
    const event = { type: 'pageview', url: `${origin}/events?q=secret` };
    expect(callback(event)).toEqual({ type: 'pageview', url: `${origin}/events` });
    mockApi({ 'GET /api/health': json({ error: { message: 'Offline' } }, 503) });
    await user.click(screen.getByRole('button', { name: 'Refresh workspace data' }));
    await screen.findByText('API unavailable');
    expect(callback(event)).toBeNull();
    rendered.unmount();
    expect(callback(event)).toBeNull();
  });
});
