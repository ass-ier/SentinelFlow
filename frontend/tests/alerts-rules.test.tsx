import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { AlertStatus } from '../src/types';
import { alert, alertDetail, observedReport, rule } from './fixtures';
import { deferred, json, mockApi, renderApp } from './helpers';

describe('alert evidence and triage', () => {
  it('preserves a canonical pinned snapshot even when no YAML text is returned', async () => {
    const canonical = Object.fromEntries(
      Object.entries(rule).filter(([key]) => key !== 'yaml' && key !== 'updated_at'),
    );
    mockApi({ 'GET /api/alerts/alert-1': { ...alertDetail, rule_snapshot: canonical } });
    const user = userEvent.setup();
    renderApp('/alerts/alert-1');
    await user.click(await screen.findByText('Pinned internal definition (JSON)'));
    expect(JSON.parse(screen.getByLabelText('Pinned rule definition JSON').textContent!)).toEqual(
      canonical,
    );
    expect(screen.queryByLabelText('Rule snapshot YAML')).not.toBeInTheDocument();
  });

  it('shows exact bounds, linked evidence, entities, and the independent pinned rule', async () => {
    const fetch = mockApi({ 'GET /api/rules': { items: [], total: 0 } });
    const user = userEvent.setup();
    renderApp('/alerts/alert-1?run_id=run-1');
    expect(await screen.findByRole('heading', { level: 1, name: rule.name })).toBeInTheDocument();
    expect(screen.getByText('Triggering events').parentElement).toHaveTextContent('2');
    expect(screen.getByRole('list', { name: 'Detection timeline' })).toHaveTextContent(
      '2026-01-15 10:00:00',
    );
    expect(screen.getByRole('list', { name: 'Detection timeline' })).toHaveTextContent(
      '2026-01-15 10:00:30',
    );
    expect(screen.getByRole('heading', { name: 'Pinned rule snapshot' })).toBeInTheDocument();
    expect(
      screen.getByText(/current operational rule may differ or no longer exist/i),
    ).toBeInTheDocument();
    expect(screen.getAllByText('Fixture Author')).toHaveLength(2);
    expect(screen.getByRole('link', { name: 'Current rule' })).toHaveAttribute(
      'href',
      '/rules/AUTH-001?run_id=run-1',
    );
    expect(screen.getByRole('link', { name: 'Explore time window' })).toHaveAttribute(
      'href',
      '/events?run_id=run-1&timestamp_from=2026-01-15T10%3A00%3A00Z&timestamp_to=2026-01-15T10%3A00%3A30Z',
    );
    await user.click(screen.getByRole('button', { name: 'Show raw event fixture-event-1' }));
    expect(screen.getByLabelText('Raw event fixture-event-1')).toHaveTextContent(
      'raw fixture input',
    );
    expect(fetch.mock.calls.some(([url]) => String(url).startsWith('/api/rules'))).toBe(false);
  });

  it.each<AlertStatus>(['investigating', 'resolved', 'false_positive', 'suppressed'])(
    'persists the real %s status with an optional note',
    async (nextStatus) => {
      let current = alertDetail;
      const fetch = mockApi({
        'GET /api/alerts/alert-1': () => current,
        'PATCH /api/alerts/alert-1/status': () => {
          current = { ...current, status: nextStatus };
          return { ...alert, status: nextStatus };
        },
      });
      const user = userEvent.setup();
      renderApp('/alerts/alert-1');
      await screen.findByRole('heading', { name: rule.name, level: 1 });
      await user.selectOptions(screen.getByLabelText('Set alert status'), nextStatus);
      await user.type(
        screen.getByLabelText('Investigation note (optional)'),
        'Reviewed fixture evidence.',
      );
      await user.click(screen.getByRole('button', { name: 'Save status' }));
      expect(await screen.findByText('Investigation status saved.')).toBeInTheDocument();
      expect(screen.getByLabelText('Set alert status')).toHaveValue(nextStatus);
      const request = fetch.mock.calls.find(
        ([url, init]) => url === '/api/alerts/alert-1/status' && init.method === 'PATCH',
      );
      expect(JSON.parse(String(request?.[1].body))).toEqual({
        status: nextStatus,
        note: 'Reviewed fixture evidence.',
      });
    },
  );

  it('retains the previous status when a mutation fails', async () => {
    mockApi({
      'PATCH /api/alerts/alert-1/status': json(
        { error: { code: 'write_failed', message: 'Status could not be saved.' } },
        503,
      ),
    });
    const user = userEvent.setup();
    renderApp('/alerts/alert-1');
    await screen.findByRole('heading', { name: rule.name, level: 1 });
    await user.selectOptions(screen.getByLabelText('Set alert status'), 'resolved');
    await user.click(screen.getByRole('button', { name: 'Save status' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Status not changed');
    expect(screen.getByLabelText('Set alert status')).toHaveValue('new');
    expect(screen.getByText('Current status').parentElement).toHaveTextContent('New');
    expect(screen.queryByText('Investigation status saved.')).not.toBeInTheDocument();
  });

  it('applies alert severity, status, rule, and query filters to the API', async () => {
    const fetch = mockApi();
    const user = userEvent.setup();
    renderApp('/alerts?run_id=run-1');
    await screen.findByRole('table', { name: 'Alert register' });
    await user.selectOptions(screen.getByLabelText('Severity'), 'high');
    await user.selectOptions(screen.getByLabelText('Status'), 'investigating');
    await user.type(screen.getByLabelText('Rule ID'), 'AUTH-001');
    await user.type(screen.getByLabelText('Search alerts'), 'fixture-user');
    await user.click(screen.getByRole('button', { name: 'Apply filters' }));
    await waitFor(() => {
      const request = fetch.mock.calls
        .map(([url]) => new URL(String(url), 'http://localhost'))
        .find((url) => url.pathname === '/api/alerts' && url.searchParams.has('q'));
      expect(Object.fromEntries(request!.searchParams)).toEqual({
        q: 'fixture-user',
        severity: 'high',
        status: 'investigating',
        rule_id: 'AUTH-001',
        run_id: 'run-1',
        offset: '0',
        limit: '25',
      });
    });
  });

  it('provides an actionable empty alert queue', async () => {
    mockApi({ 'GET /api/alerts': { items: [], total: 0, offset: 0, limit: 25 } });
    renderApp('/alerts');
    expect(await screen.findByText('No alerts in this scope')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Replay a dataset' })).toHaveAttribute(
      'href',
      '/replay',
    );
  });
});

describe('operational rule controls', () => {
  it('searches the real catalog on the client', async () => {
    const fetch = mockApi();
    const user = userEvent.setup();
    renderApp('/rules');
    await screen.findByRole('switch', { name: `Disable ${rule.name}` });
    await user.type(screen.getByLabelText('Search detection rules'), 'no-such-rule');
    expect(screen.getByText('No rules match this search')).toBeInTheDocument();
    expect(fetch.mock.calls.filter(([url]) => url === '/api/rules')).toHaveLength(1);
    await user.click(screen.getByRole('button', { name: 'Clear search' }));
    expect(screen.getByRole('switch', { name: `Disable ${rule.name}` })).toBeInTheDocument();
  });

  it('waits for a persisted toggle rather than optimistically inventing success', async () => {
    const response = deferred<typeof rule>();
    let enabled = true;
    const fetch = mockApi({
      'GET /api/rules': () => ({ items: [{ ...rule, enabled }], total: 1 }),
      'PATCH /api/rules/AUTH-001': async () => {
        const result = await response.promise;
        enabled = result.enabled;
        return result;
      },
    });
    const user = userEvent.setup();
    renderApp('/rules');
    const control = await screen.findByRole('switch', { name: `Disable ${rule.name}` });
    await user.click(control);
    expect(control).toBeDisabled();
    expect(control).toHaveAttribute('aria-checked', 'true');
    await act(async () => response.resolve({ ...rule, enabled: false }));
    expect(await screen.findByRole('switch', { name: `Enable ${rule.name}` })).toHaveAttribute(
      'aria-checked',
      'false',
    );
    expect(screen.getByText(/disabled for new runs. Existing runs keep/)).toBeInTheDocument();
    const request = fetch.mock.calls.find(([, init]) => init.method === 'PATCH');
    expect(JSON.parse(String(request?.[1].body))).toEqual({ enabled: false });
  });

  it('keeps the original enable state when the API refuses a toggle', async () => {
    mockApi({
      'PATCH /api/rules/AUTH-001': json(
        { error: { code: 'write_failed', message: 'Rule store unavailable.' } },
        500,
      ),
    });
    const user = userEvent.setup();
    renderApp('/rules');
    await user.click(await screen.findByRole('switch', { name: `Disable ${rule.name}` }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Rule state not changed');
    expect(screen.getByRole('switch', { name: `Disable ${rule.name}` })).toHaveAttribute(
      'aria-checked',
      'true',
    );
  });

  it('tests disabled definitions without enabling them and preserves OBSERVED', async () => {
    const fetch = mockApi({
      'GET /api/rules/AUTH-001': { ...rule, enabled: false },
      'POST /api/rules/AUTH-001/test': observedReport,
    });
    const user = userEvent.setup();
    renderApp('/rules/AUTH-001');
    await screen.findByRole('heading', { name: rule.name, level: 1 });
    await user.selectOptions(screen.getByLabelText('Dataset'), 'positive-fixture');
    await user.click(screen.getByRole('button', { name: 'Run definition test' }));
    expect(await screen.findByText(/Observation only. Unknown expectations/)).toBeInTheDocument();
    expect(screen.queryByText('PASS')).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([, init]) => init.method === 'PATCH')).toBe(false);
    const request = fetch.mock.calls.find(([url]) => url === '/api/rules/AUTH-001/test');
    expect(JSON.parse(String(request?.[1].body))).toEqual({ dataset_id: 'positive-fixture' });
  });
});
