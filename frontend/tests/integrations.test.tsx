import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type {
  Connector,
  Delivery,
  Destination,
  IntegrationOverview,
} from '../src/types/integrations';
import { alertDetail } from './fixtures';
import { deferred, json, mockApi, renderApp } from './helpers';

const connector: Connector = {
  id: 'sentinel-default',
  name: 'Microsoft Sentinel',
  type: 'microsoft_sentinel',
  mode: 'live',
  enabled: false,
  tenant_id: null,
  client_id: null,
  workspace_id: null,
  secret_ref: 'SENTINEL_CLIENT_SECRET',
  profiles: [{ id: 'signin_logs', enabled: true, interval_seconds: 60 }],
  overlap_seconds: 120,
  lookback_seconds: 900,
  page_size: 200,
  max_pages: 5,
  status: 'disabled',
  last_success: null,
  last_failure: null,
  last_error: null,
  last_event_time: null,
  events_received: 0,
  events_processed: 0,
  events_failed: 0,
  duplicate_events: 0,
  retry_count: 0,
  run_id: null,
};
const overview: IntegrationOverview = {
  connectors: [connector],
  notifications: {},
  external_enabled: false,
  notifications_enabled: false,
  public_demo: false,
  worker: { running: false, enabled: true, last_error: null },
  profiles: {
    microsoft_sentinel: [
      { id: 'signin_logs', table: 'SigninLogs', timestamp: 'TimeGenerated', normalizer: 'signin' },
    ],
    microsoft_graph: [
      { id: 'signins', table: 'signIns', timestamp: 'createdDateTime', normalizer: 'signin' },
    ],
  },
};
const destination: Destination = {
  id: 'destination-1',
  name: 'Mock Power Automate',
  type: 'power_automate',
  mode: 'demo',
  enabled: true,
  url_ref: null,
  authentication: 'none',
  auth_ref: null,
  timeout_seconds: 5,
  max_attempts: 3,
  retry_seconds: 5,
  health: 'configured',
  last_delivery: null,
  failure_count: 0,
};
const delivery: Delivery = {
  id: 'delivery-1',
  idempotency_key: 'synthetic-idempotency',
  alert_id: 'alert-1',
  destination_id: destination.id,
  status: 'delivered',
  attempt_count: 1,
  created_at: '2026-01-15T10:00:00Z',
  last_attempt_at: '2026-01-15T10:00:01Z',
  delivered_at: '2026-01-15T10:00:01Z',
  http_status: 202,
  error: null,
  next_attempt_at: null,
  mock: true,
  event: 'security_alert',
};
const defaults = {
  'GET /api/integrations': overview,
  'GET /api/integrations/credentials': { items: [], total: 0 },
  'GET /api/notifications/destinations': { items: [destination], total: 1 },
  'GET /api/notifications/policies': { items: [], total: 0 },
  'GET /api/notifications/deliveries': { items: [delivery], total: 1 },
};

describe('telemetry connector management', () => {
  it('shows disabled sources without claiming connected or receiving telemetry', async () => {
    mockApi(defaults);
    renderApp('/integrations');
    const table = await screen.findByRole('table', { name: 'Telemetry connectors' });
    expect(table).toHaveTextContent('Disabled');
    expect(table).toHaveTextContent('No successful operation');
    expect(within(table).getByRole('button', { name: 'Poll now' })).toBeDisabled();
    expect(screen.queryByText('Microsoft Sentinel Connected')).not.toBeInTheDocument();
  });

  it('distinguishes initial loading from actual connection status', async () => {
    const pending = deferred<IntegrationOverview>();
    mockApi({ ...defaults, 'GET /api/integrations': () => pending.promise });
    renderApp('/integrations');
    expect(await screen.findByText(/Loading connector status/)).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'Telemetry connectors' })).not.toBeInTheDocument();
    await act(async () => pending.resolve(overview));
    expect(await screen.findByRole('table', { name: 'Telemetry connectors' })).toBeInTheDocument();
  });

  it.each([401, 403, 503])(
    'shows a %s API error instead of a successful connection',
    async (status) => {
      mockApi({
        ...defaults,
        'GET /api/integrations': json(
          { error: { code: 'unavailable', message: 'Integration access unavailable.' } },
          status,
        ),
      });
      renderApp('/integrations');
      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Integration status could not be loaded',
      );
      expect(screen.queryByText('Connector state updated.')).not.toBeInTheDocument();
    },
  );

  it('submits only a credential reference when configuring a live connector', async () => {
    const fetch = mockApi({ ...defaults, 'POST /api/integrations/connectors': connector });
    const user = userEvent.setup();
    renderApp('/integrations');
    await screen.findByRole('table', { name: 'Telemetry connectors' });
    await user.click(screen.getByRole('button', { name: 'Configure connector' }));
    await user.type(screen.getByLabelText('Connector name'), 'Test source');
    await user.click(screen.getByRole('button', { name: 'Save connector' }));
    expect(await screen.findByText('Connector configuration saved.')).toBeInTheDocument();
    const request = fetch.mock.calls.find(
      ([url, init]) => url === '/api/integrations/connectors' && init.method === 'POST',
    );
    expect(JSON.parse(String(request?.[1].body))).toMatchObject({
      secret_ref: 'SENTINEL_CLIENT_SECRET',
      enabled: false,
      name: 'Test source',
    });
    expect(JSON.parse(String(request?.[1].body))).not.toHaveProperty('client_secret');
  });

  it('edits the saved connector and keeps failures actionable', async () => {
    const fetch = mockApi({
      ...defaults,
      'PATCH /api/integrations/connectors/sentinel-default': json(
        { error: { code: 'configuration_error', message: 'Connector not saved.' } },
        422,
      ),
    });
    const user = userEvent.setup();
    renderApp('/integrations');
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    await user.clear(screen.getByLabelText('Connector name'));
    await user.type(screen.getByLabelText('Connector name'), 'Changed source');
    await user.click(screen.getByRole('button', { name: 'Save connector' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Connector was not saved');
    expect(screen.getByLabelText('Connector name')).toHaveValue('Changed source');
    expect(fetch.mock.calls.some(([, init]) => init.method === 'PATCH')).toBe(true);
  });

  it('does not convert a connector poll error into success', async () => {
    mockApi({
      ...defaults,
      'POST /api/integrations/connectors/sentinel-default/test': {
        ...connector,
        last_error: 'forbidden',
      },
    });
    const user = userEvent.setup();
    renderApp('/integrations');
    await user.click(await screen.findByRole('button', { name: 'Test connection' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Connector reported Forbidden');
    expect(screen.queryByText(/Connection query completed/)).not.toBeInTheDocument();
  });

  it('displays real returned demo counts, links and explicit non-live status', async () => {
    const fetch = mockApi({
      ...defaults,
      'POST /api/integrations/demo': {
        mode: 'demo',
        connector_id: 'demo',
        run_id: 'connector-run',
        events_processed: 13,
        status: 'mock',
        deliveries: [delivery],
        live_tested: false,
      },
    });
    const user = userEvent.setup();
    renderApp('/integrations');
    await user.selectOptions(screen.getByLabelText('Demo telemetry source'), 'microsoft_graph');
    await user.click(screen.getByRole('button', { name: 'Run offline demonstration' }));
    expect(await screen.findByText(/13 normalized events/)).toHaveTextContent(
      '1 deliveries accepted by the mock receiver',
    );
    expect(screen.getByRole('link', { name: 'Inspect alerts and provenance' })).toHaveAttribute(
      'href',
      '/alerts?run_id=connector-run',
    );
    const request = fetch.mock.calls.find(([url]) => url === '/api/integrations/demo');
    expect(JSON.parse(String(request?.[1].body))).toEqual({ source: 'microsoft_graph' });
  });

  it('revokes an integration credential using its reference, not the token', async () => {
    const credential = {
      id: 'key-1',
      name: 'Collector',
      scopes: ['windows:ingest'],
      connector_id: 'windows-default',
      token_ref: 'SENTINEL_INTEGRATION_COLLECTOR',
      enabled: true,
    };
    const fetch = mockApi({
      ...defaults,
      'GET /api/integrations/credentials': { items: [credential], total: 1 },
      'PATCH /api/integrations/credentials/key-1': { ...credential, enabled: false },
    });
    const user = userEvent.setup();
    renderApp('/integrations');
    await user.click(screen.getByText('Scoped integration credentials'));
    await user.click(await screen.findByRole('button', { name: 'Revoke' }));
    await waitFor(() =>
      expect(
        fetch.mock.calls.some(
          ([url, init]) => url === '/api/integrations/credentials/key-1' && init.method === 'PATCH',
        ),
      ).toBe(true),
    );
    const request = fetch.mock.calls.find(([, init]) => init.method === 'PATCH');
    expect(JSON.parse(String(request?.[1].body))).toMatchObject({
      token_ref: credential.token_ref,
      enabled: false,
    });
  });

  it('submits a timezone-normalized expiration without accepting the secret value', async () => {
    const fetch = mockApi({
      ...defaults,
      'POST /api/integrations/credentials': { id: 'expiring' },
    });
    const user = userEvent.setup();
    renderApp('/integrations');
    await user.click(screen.getByText('Scoped integration credentials'));
    await user.type(await screen.findByLabelText('Credential name'), 'Expiring reader');
    await user.type(screen.getByLabelText('Token environment reference'), 'SENTINEL_INTEGRATION_R');
    fireEvent.change(screen.getByLabelText('Expiration (local time)'), {
      target: { value: '2099-01-01T12:30' },
    });
    await user.click(screen.getByRole('button', { name: 'Register credential reference' }));
    await waitFor(() => expect(screen.getByLabelText('Credential name')).toHaveValue(''));
    const request = fetch.mock.calls.find(
      ([url, init]) => url === '/api/integrations/credentials' && init.method === 'POST',
    );
    expect(JSON.parse(String(request?.[1].body))).toEqual({
      name: 'Expiring reader',
      token_ref: 'SENTINEL_INTEGRATION_R',
      scopes: ['alerts:read'],
      connector_id: null,
      enabled: true,
      expires_at: new Date('2099-01-01T12:30').toISOString(),
    });
    expect(screen.queryByLabelText('Secret value')).not.toBeInTheDocument();
  });

  it.each([
    ['2000-01-01T00:00:00Z', 'Expired'],
    [null, 'Enabled'],
  ])('renders credential expiration %s honestly and names as text', async (expiresAt, state) => {
    const name = '<img src=x onerror=alert(1)>';
    mockApi({
      ...defaults,
      'GET /api/integrations/credentials': {
        items: [
          {
            id: 'key',
            name,
            token_ref: 'SENTINEL_INTEGRATION_R',
            scopes: ['alerts:read'],
            connector_id: null,
            enabled: true,
            expires_at: expiresAt,
          },
        ],
        total: 1,
      },
    });
    const user = userEvent.setup();
    renderApp('/integrations');
    await user.click(screen.getByText('Scoped integration credentials'));
    const table = await screen.findByRole('table', { name: 'Scoped integration credentials' });
    expect(table).toHaveTextContent(state as string);
    expect(table).toHaveTextContent(name);
    expect(table.querySelector('img')).toBeNull();
    if (expiresAt === null) expect(table).toHaveTextContent('No expiration');
  });

  it('retains expiration and reference input after a rejected registration', async () => {
    mockApi({
      ...defaults,
      'POST /api/integrations/credentials': json(
        { error: { message: 'Set the referenced value on the server.' } },
        409,
      ),
    });
    const user = userEvent.setup();
    renderApp('/integrations');
    await user.click(screen.getByText('Scoped integration credentials'));
    await user.type(await screen.findByLabelText('Credential name'), 'Retry reader');
    await user.type(screen.getByLabelText('Token environment reference'), 'SENTINEL_INTEGRATION_R');
    fireEvent.change(screen.getByLabelText('Expiration (local time)'), {
      target: { value: '2099-01-01T12:30' },
    });
    await user.click(screen.getByRole('button', { name: 'Register credential reference' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Credential change did not complete',
    );
    expect(screen.getByLabelText('Expiration (local time)')).toHaveValue('2099-01-01T12:30');
    expect(screen.getByLabelText('Token environment reference')).toHaveValue(
      'SENTINEL_INTEGRATION_R',
    );
  });
});

describe('notification administration and investigation', () => {
  it('shows an honest empty state without requiring outbound delivery', async () => {
    mockApi({
      ...defaults,
      'GET /api/notifications/destinations': { items: [], total: 0 },
      'GET /api/notifications/deliveries': { items: [], total: 0 },
    });
    renderApp('/notifications');
    expect(await screen.findByText('No notification destinations configured.')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('queues a test without immediately claiming delivery', async () => {
    const fetch = mockApi({
      ...defaults,
      'POST /api/notifications/test': { ...delivery, status: 'pending' },
    });
    const user = userEvent.setup();
    renderApp('/notifications');
    await user.click(await screen.findByRole('button', { name: 'Send test' }));
    expect(await screen.findByText(/Notification test queued/)).toHaveTextContent(
      'Inspect delivery history',
    );
    const request = fetch.mock.calls.find(([url]) => url === '/api/notifications/test');
    expect(JSON.parse(String(request?.[1].body))).toEqual({ destination_id: destination.id });
    expect(screen.queryByText('Teams Connected')).not.toBeInTheDocument();
  });

  it('creates a disabled mock destination without accepting a secret URL', async () => {
    const fetch = mockApi({ ...defaults, 'POST /api/notifications/destinations': destination });
    const user = userEvent.setup();
    renderApp('/notifications');
    await user.click(screen.getByRole('button', { name: 'Add destination' }));
    await user.type(screen.getByLabelText('Destination name'), 'Local receiver');
    await user.selectOptions(screen.getByLabelText('Delivery mode'), 'demo');
    expect(screen.queryByLabelText('URL environment reference')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save destination' }));
    expect(await screen.findByText('Destination saved. Enable it when ready.')).toBeInTheDocument();
    const request = fetch.mock.calls.find(
      ([url, init]) => url === '/api/notifications/destinations' && init.method === 'POST',
    );
    expect(JSON.parse(String(request?.[1].body))).toMatchObject({
      mode: 'demo',
      url_ref: null,
      auth_ref: null,
      enabled: false,
    });
  });

  it('requires confirmation before deleting a destination and retains history', async () => {
    const fetch = mockApi({
      ...defaults,
      'DELETE /api/notifications/destinations/destination-1': { status: 'deleted' },
    });
    const user = userEvent.setup();
    renderApp('/notifications');
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    expect(fetch.mock.calls.some(([, init]) => init.method === 'DELETE')).toBe(false);
    await user.click(screen.getByRole('button', { name: 'Confirm delete destination' }));
    expect(
      await screen.findByText('Destination removed. Delivery history is retained.'),
    ).toBeInTheDocument();
  });

  it('saves exact routing filters and excludes replays by default', async () => {
    const fetch = mockApi({ ...defaults, 'POST /api/notifications/policies': { id: 'policy-1' } });
    const user = userEvent.setup();
    renderApp('/notifications');
    await screen.findByRole('table', { name: 'Notification destinations' });
    await user.click(screen.getByRole('button', { name: 'Create policy' }));
    await user.type(screen.getByLabelText('Policy name'), 'High priority');
    await user.click(screen.getByRole('checkbox', { name: destination.name }));
    await user.type(screen.getByLabelText('Severities'), 'high, critical');
    await user.type(screen.getByLabelText('Rule IDs'), 'AUTH-001');
    await user.click(screen.getByRole('button', { name: 'Save policy' }));
    await waitFor(() =>
      expect(fetch.mock.calls.some(([, init]) => init.method === 'POST')).toBe(true),
    );
    const request = fetch.mock.calls.find(
      ([url, init]) => url === '/api/notifications/policies' && init.method === 'POST',
    );
    expect(JSON.parse(String(request?.[1].body))).toMatchObject({
      severities: ['high', 'critical'],
      rule_ids: ['AUTH-001'],
      include_replays: false,
      destinations: [destination.id],
    });
  });

  it('shows failed delivery attempts without changing the underlying alert', async () => {
    mockApi({
      ...defaults,
      'GET /api/notifications/deliveries/delivery-1': {
        ...delivery,
        status: 'dead_letter',
        attempt_count: 3,
        http_status: 503,
        error: 'upstream_error',
        payload: { schema_version: '1.0', alert: { id: 'alert-1' } },
        attempts: [
          {
            number: 1,
            timestamp: '2026-01-15T10:00:00Z',
            http_status: 503,
            error: 'upstream_error',
          },
        ],
      },
    });
    renderApp('/notifications/delivery-1');
    expect(await screen.findByRole('table', { name: 'Delivery attempts' })).toHaveTextContent(
      '503',
    );
    expect(screen.getByText('Dead letter')).toBeInTheDocument();
    expect(screen.getByText(/No live Power Automate flow/)).toBeInTheDocument();
    expect(
      screen.getByLabelText('Outbound payload (no credentials or raw log bodies)'),
    ).toHaveTextContent('alert-1');
  });

  it('shows connector provenance and independent delivery status beside alert evidence', async () => {
    mockApi({
      ...defaults,
      'GET /api/alerts/alert-1': {
        ...alertDetail,
        telemetry_sources: [
          { provider: 'microsoft_graph', connector_id: 'graph-default', source_table: 'signIns' },
        ],
        notifications: [delivery],
      },
    });
    renderApp('/alerts/alert-1');
    expect(
      await screen.findByRole('heading', { name: 'Telemetry provenance' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Microsoft graph')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Notifications' })).toBeInTheDocument();
    expect(screen.getByText('Delivered')).toBeInTheDocument();
  });

  it.each(['/integrations', '/notifications'])(
    'removes administration in public mode at %s',
    async (path) => {
      mockApi({
        ...defaults,
        'GET /api/health': {
          status: 'ok',
          auth_required: false,
          public_demo: true,
          version: '0.1.0',
        },
        'GET /api/integrations': { ...overview, public_demo: true, connectors: [] },
      });
      renderApp(path);
      await waitFor(() => {
        expect(
          screen.queryByRole('button', { name: 'Configure connector' }),
        ).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Add destination' })).not.toBeInTheDocument();
      });
      expect(
        screen.queryByRole('button', { name: 'Run offline demonstration' }),
      ).not.toBeInTheDocument();
      expect(screen.queryByText('Scoped integration credentials')).not.toBeInTheDocument();
    },
  );
});
