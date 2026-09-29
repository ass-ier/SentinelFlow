import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { event, run } from './fixtures';
import { json, mockApi, renderApp } from './helpers';

describe('event exploration', () => {
  it('preserves process basenames alongside their full executable paths', async () => {
    mockApi({
      'GET /api/events/storage-event-1': {
        ...event,
        process: {
          name: 'powershell.exe',
          executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          pid: 321,
          command_line: 'powershell.exe -NoProfile',
          parent: {
            name: 'explorer.exe',
            executable: 'C:\\Windows\\explorer.exe',
            pid: 123,
          },
        },
      },
    });
    renderApp('/events/storage-event-1');
    await screen.findByText('Process executable (full path)');
    expect(screen.getByText('Process', { selector: 'dt' }).parentElement).toHaveTextContent(
      'powershell.exe · PID 321',
    );
    expect(screen.getByText('Parent process', { selector: 'dt' }).parentElement).toHaveTextContent(
      'explorer.exe · PID 123',
    );
    expect(screen.getByText('Process executable (full path)').parentElement).toHaveTextContent(
      'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    );
    expect(screen.getByText('Parent executable (full path)').parentElement).toHaveTextContent(
      'C:\\Windows\\explorer.exe',
    );
  });

  it('renders normalized event data and escapes expanded raw evidence', async () => {
    mockApi();
    const user = userEvent.setup();
    const { container } = renderApp('/events?run_id=run-1');
    await screen.findByText('fixture-host');
    expect(screen.getByText('fixture-user')).toBeInTheDocument();
    expect(screen.getByText('2026-01-15 10:00:00')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show raw event fixture-event-1' }));
    expect(
      JSON.parse(screen.getByLabelText('Raw event fixture-event-1').textContent!).message,
    ).toBe('<img src=x onerror="window.logExecuted=true">');
    expect(container.querySelector('img')).toBeNull();
    expect((window as unknown as Record<string, unknown>).logExecuted).toBeUndefined();
    expect(screen.getByRole('button', { name: 'Hide raw event fixture-event-1' })).toHaveAttribute(
      'aria-expanded',
      'true',
    );
  });

  it('sends exact indexed-field filters and UTC timestamps', async () => {
    const fetch = mockApi();
    const user = userEvent.setup();
    renderApp('/events?run_id=run-1');
    await screen.findByText('fixture-host');
    await user.type(screen.getByLabelText('Search events'), 'failed login');
    await user.selectOptions(screen.getByLabelText('Category'), 'authentication');
    await user.selectOptions(screen.getByLabelText('Severity'), 'high');
    await user.click(screen.getByRole('button', { name: 'More filters' }));
    await user.type(screen.getByLabelText('Source IP'), '192.0.2.7');
    await user.type(screen.getByLabelText('Host'), 'fixture-host');
    await user.type(screen.getByLabelText('User'), 'fixture-user');
    await user.type(screen.getByLabelText('Process'), 'fixture.exe');
    await user.type(screen.getByLabelText('Action'), 'login');
    await user.type(screen.getByLabelText('Event type'), 'start');
    await user.type(screen.getByLabelText('Event source'), 'fixture');
    await user.selectOptions(screen.getByLabelText('Outcome'), 'failure');
    fireEvent.change(screen.getByLabelText('From timestamp (UTC)'), {
      target: { value: '2026-01-15T10:00:00' },
    });
    fireEvent.change(screen.getByLabelText('To timestamp (UTC)'), {
      target: { value: '2026-01-15T10:05:00' },
    });
    await user.click(screen.getByRole('button', { name: 'Search' }));
    await waitFor(() => {
      const request = fetch.mock.calls
        .map(([url]) => new URL(String(url), 'http://localhost'))
        .find((url) => url.searchParams.get('q') === 'failed login');
      expect(request).toBeDefined();
      expect(Object.fromEntries(request!.searchParams)).toEqual({
        q: 'failed login',
        category: 'authentication',
        severity: 'high',
        source_ip: '192.0.2.7',
        host_name: 'fixture-host',
        user_name: 'fixture-user',
        process_name: 'fixture.exe',
        action: 'login',
        event_type: 'start',
        event_source: 'fixture',
        outcome: 'failure',
        timestamp_from: '2026-01-15T10:00:00Z',
        timestamp_to: '2026-01-15T10:05:00Z',
        run_id: 'run-1',
        offset: '0',
        limit: '25',
      });
    });
  });

  it('rejects a backwards time range without submitting it', async () => {
    const fetch = mockApi();
    const user = userEvent.setup();
    renderApp('/events');
    await screen.findByText('fixture-host');
    await user.click(screen.getByRole('button', { name: 'More filters' }));
    fireEvent.change(screen.getByLabelText('From timestamp (UTC)'), {
      target: { value: '2026-02-01T12:00' },
    });
    fireEvent.change(screen.getByLabelText('To timestamp (UTC)'), {
      target: { value: '2026-01-01T12:00' },
    });
    await user.click(screen.getByRole('button', { name: 'Search' }));
    expect(screen.getByRole('alert')).toHaveTextContent('start timestamp must be before');
    expect(
      fetch.mock.calls.filter(([url]) => String(url).startsWith('/api/events/search')),
    ).toHaveLength(1);
  });

  it('clears filters without dropping the selected run', async () => {
    mockApi({ 'GET /api/events/search': { items: [], total: 0, offset: 0, limit: 25 } });
    const user = userEvent.setup();
    renderApp('/events?source_ip=192.0.2.99&run_id=run-1');
    await screen.findByText('No events match these filters');
    await user.click(screen.getAllByRole('button', { name: 'Clear filters' })[0]);
    expect(screen.getByTestId('location')).toHaveTextContent('/events?run_id=run-1');
    expect(await screen.findByText('No events in this scope')).toBeInTheDocument();
  });

  it('paginates using backend offsets and bounded page sizes', async () => {
    const fetch = mockApi({
      'GET /api/events/search': ({ url }: { url: URL }) => ({
        items: [event],
        total: 81,
        offset: Number(url.searchParams.get('offset')),
        limit: Number(url.searchParams.get('limit')),
      }),
    });
    const user = userEvent.setup();
    renderApp('/events');
    await screen.findByText('1–25 of 81');
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    expect(await screen.findByText('26–50 of 81')).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Rows per page'), '100');
    await waitFor(() =>
      expect(fetch.mock.calls.some(([url]) => String(url).includes('offset=0&limit=100'))).toBe(
        true,
      ),
    );
    expect(await screen.findByText('1–81 of 81')).toBeInTheDocument();
  });

  it('shows server search failures instead of a no-results claim', async () => {
    mockApi({
      'GET /api/events/search': json(
        { error: { code: 'query_failure', message: 'Search index unavailable.' } },
        500,
      ),
    });
    renderApp('/events');
    expect(await screen.findByRole('alert')).toHaveTextContent('Search index unavailable.');
    expect(screen.queryByText('No events in this scope')).not.toBeInTheDocument();
  });
});

describe('event ingestion', () => {
  it('retains input and displays parser failure without a fake success', async () => {
    const fetch = mockApi({
      'POST /api/events': json(
        {
          error: { code: 'parse_error', message: 'Line 2: invalid JSON.' },
          request_id: 'ingest-request',
        },
        422,
      ),
    });
    const user = userEvent.setup();
    renderApp('/events?import=1');
    await user.type(screen.getByLabelText('Event content'), 'not-json\nstill-not-json');
    await user.click(screen.getByRole('button', { name: 'Ingest events' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Line 2: invalid JSON.');
    expect(screen.getByLabelText('Event content')).toHaveValue('not-json\nstill-not-json');
    expect(screen.queryByText('Import completed')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Ingest events' })).toBeEnabled();
    const request = fetch.mock.calls.find(
      ([url, init]) => url === '/api/events' && init.method === 'POST',
    );
    expect(JSON.parse(String(request?.[1].body))).toMatchObject({
      format: 'jsonl',
      content: 'not-json\nstill-not-json',
    });
  });

  it('shows real ingest counts and focuses the returned isolated run', async () => {
    mockApi({
      'POST /api/events': {
        run: { ...run, id: 'ingest-42', kind: 'import' },
        events_processed: 17,
        events_stored: 15,
        duplicates_ignored: 2,
        detections_triggered: 3,
        alerts_created: 3,
      },
    });
    const user = userEvent.setup();
    renderApp('/events?import=1');
    fireEvent.change(screen.getByLabelText('Event content'), {
      target: { value: '{"test":"fixture"}' },
    });
    await user.selectOptions(screen.getByLabelText('Input format'), 'json');
    await user.click(screen.getByRole('button', { name: 'Ingest events' }));
    expect(await screen.findByText('Import completed')).toBeInTheDocument();
    expect(screen.getByText('Events stored').parentElement).toHaveTextContent('15');
    expect(screen.getByText('Duplicates ignored').parentElement).toHaveTextContent('2');
    expect(screen.getByText('Detections triggered').parentElement).toHaveTextContent('3');
    await waitFor(() => expect(screen.getByLabelText('Run scope')).toHaveValue('ingest-42'));
  });

  it('reads a selected local file and sends its inert content and filename', async () => {
    const fetch = mockApi({
      'POST /api/events': {
        run,
        events_processed: 1,
        events_stored: 1,
        duplicates_ignored: 0,
        detections_triggered: 0,
        alerts_created: 0,
      },
    });
    const user = userEvent.setup();
    renderApp('/events?import=1');
    const file = new File(['{"timestamp":"2026-01-15T10:00:00Z"}'], 'fixture.jsonl', {
      type: 'application/json',
    });
    await user.upload(screen.getByLabelText('Telemetry file'), file);
    await waitFor(() =>
      expect(screen.getByLabelText('Event content')).toHaveValue(
        '{"timestamp":"2026-01-15T10:00:00Z"}',
      ),
    );
    await user.click(screen.getByRole('button', { name: 'Ingest events' }));
    await screen.findByText('Import completed');
    const request = fetch.mock.calls.find(
      ([url, init]) => url === '/api/events' && init.method === 'POST',
    );
    expect(JSON.parse(String(request?.[1].body))).toEqual({
      format: 'jsonl',
      content: '{"timestamp":"2026-01-15T10:00:00Z"}',
      name: 'fixture.jsonl',
    });
  });

  it('enforces the local five-MiB cap and never posts an oversized file', async () => {
    const fetch = mockApi();
    const user = userEvent.setup();
    renderApp('/events?import=1');
    const file = new File(['fixture'], 'oversize.jsonl');
    Object.defineProperty(file, 'size', { value: 5 * 1024 * 1024 + 1 });
    await user.upload(screen.getByLabelText('Telemetry file'), file);
    expect(await screen.findByRole('alert')).toHaveTextContent('5 MiB');
    expect(screen.getByRole('button', { name: 'Ingest events' })).toBeDisabled();
    expect(fetch.mock.calls.some(([, init]) => init.method === 'POST')).toBe(false);
  });

  it('explains how to recover from rejected late appends', async () => {
    mockApi({
      'POST /api/events': json(
        { error: { code: 'late_events', message: 'Batch precedes the watermark.' } },
        409,
      ),
    });
    const user = userEvent.setup();
    renderApp('/events?import=1');
    await screen.findByRole('option', { name: /Append to Fixture replay/ });
    await user.selectOptions(screen.getByLabelText('Import target'), 'run-1');
    fireEvent.change(screen.getByLabelText('Event content'), {
      target: { value: '{"late":true}' },
    });
    await user.click(screen.getByRole('button', { name: 'Ingest events' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('new isolated import or replay');
    expect(screen.getByLabelText('Import target')).toHaveValue('run-1');
  });
});
