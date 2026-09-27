import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { dashboard, emptyDashboard, run } from './fixtures';
import { deferred, json, mockApi, renderApp } from './helpers';

describe('operational overview', () => {
  it('shows loading without manufacturing dashboard values', async () => {
    const response = deferred<typeof dashboard>();
    mockApi({ 'GET /api/dashboard': () => response.promise });
    renderApp();
    expect(screen.getByText('Loading operational overview…')).toBeInTheDocument();
    expect(screen.queryByText('Events processed')).not.toBeInTheDocument();
    await act(async () => response.resolve(dashboard));
    expect(await screen.findByText('Events processed')).toBeInTheDocument();
  });

  it('maps real counters, sources, rule activity, and ATT&CK data', async () => {
    mockApi();
    renderApp();
    await screen.findByText('Events processed');
    expect(screen.getByText('Events processed').parentElement).toHaveTextContent('27');
    expect(screen.getByText('Active alerts').parentElement).toHaveTextContent('3');
    expect(screen.getByText('Critical alerts').parentElement).toHaveTextContent('1');
    expect(screen.getByText('High alerts').parentElement).toHaveTextContent('2');
    expect(screen.getByText('Detection rules', { selector: 'dt' }).parentElement).toHaveTextContent(
      '7',
    );
    expect(screen.getByText('6 enabled now')).toBeInTheDocument();
    expect(screen.getByText('Brute Force', { exact: true })).toBeInTheDocument();
    const sourceSection = screen.getByRole('heading', { name: 'Top source IPs' }).parentElement!
      .parentElement!;
    expect(within(sourceSection).getByRole('link', { name: '192.0.2.7' })).toHaveAttribute(
      'href',
      '/events?source_ip=192.0.2.7',
    );
    expect(within(sourceSection).getByText('19')).toBeInTheDocument();
    expect(
      screen.getByRole('img', { name: /Event and alert counts over time/ }),
    ).toBeInTheDocument();
  });

  it('shows a useful empty state rather than fixture data', async () => {
    mockApi({ 'GET /api/dashboard': emptyDashboard, 'GET /api/runs': { items: [], total: 0 } });
    renderApp();
    expect(await screen.findByText('No event activity in this scope')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Choose a dataset' })).toHaveAttribute(
      'href',
      '/replay',
    );
    expect(screen.queryByText('192.0.2.7')).not.toBeInTheDocument();
    expect(screen.queryByRole('img', { name: /Event and alert counts/ })).not.toBeInTheDocument();
  });

  it('keeps failures explicit and retryable', async () => {
    let attempts = 0;
    mockApi({
      'GET /api/dashboard': () =>
        ++attempts === 1
          ? json({ error: { code: 'unavailable', message: 'Database unavailable.' } }, 503)
          : dashboard,
    });
    const user = userEvent.setup();
    renderApp();
    expect(await screen.findByRole('alert')).toHaveTextContent('Database unavailable.');
    expect(screen.queryByText('No alerts to investigate')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('27')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('changes backend scope and preserves it in navigation', async () => {
    const fetch = mockApi();
    const user = userEvent.setup();
    renderApp();
    await screen.findByText('Events processed');
    await user.selectOptions(screen.getByLabelText('Run scope'), run.id);
    await waitFor(() =>
      expect(fetch.mock.calls.some(([url]) => String(url) === '/api/dashboard?run_id=run-1')).toBe(
        true,
      ),
    );
    expect(screen.getByRole('link', { name: 'Alerts' })).toHaveAttribute(
      'href',
      '/alerts?run_id=run-1',
    );
    expect(screen.getByText('Events & alerts in one isolated run')).toBeInTheDocument();
  });

  it('supports keyboard dismissal of responsive navigation', async () => {
    mockApi();
    const user = userEvent.setup();
    renderApp();
    await user.click(screen.getByRole('button', { name: 'Open navigation' }));
    expect(screen.getByRole('button', { name: 'Close navigation' })).toHaveAttribute(
      'aria-expanded',
      'true',
    );
    await user.keyboard('{Escape}');
    expect(screen.getByRole('button', { name: 'Open navigation' })).toHaveAttribute(
      'aria-expanded',
      'false',
    );
  });

  it('stores only the entered session token and retries with authorization', async () => {
    const fetch = mockApi({
      'GET /api/health': { status: 'ok', version: '0.1.0', auth_required: true },
    });
    const user = userEvent.setup();
    renderApp();
    await screen.findByText('Events processed');
    await user.click(screen.getByRole('button', { name: 'Connection settings' }));
    const dialog = screen.getByRole('dialog', { name: 'Connection settings' });
    await user.type(within(dialog).getByLabelText('API token'), 'test-only-session-token');
    await user.click(within(dialog).getByRole('button', { name: 'Save connection' }));
    expect(sessionStorage.getItem('sentinelflow.token')).toBe('test-only-session-token');
    await waitFor(() =>
      expect(
        fetch.mock.calls.some(
          ([, init]) =>
            (init?.headers as Record<string, string>)?.Authorization ===
            'Bearer test-only-session-token',
        ),
      ).toBe(true),
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
