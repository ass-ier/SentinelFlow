import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { alert, event, run } from './fixtures';
import { json, mockApi, renderApp } from './helpers';

describe('real replay jobs', () => {
  it('polls real progress, shows arrivals and alerts, and focuses the new run', async () => {
    let complete = false;
    const fetch = mockApi({
      'POST /api/detections/replay': {
        ...run,
        id: 'replay-2',
        status: 'pending',
        processed_events: 0,
        alerts_created: 0,
      },
      'GET /api/detections/replay/replay-2': () => ({
        ...run,
        id: 'replay-2',
        status: complete ? 'completed' : 'running',
        processed_events: complete ? 2 : 1,
      }),
      'GET /api/runs/replay-2/feed': () => ({
        events: [{ ...event, run_id: 'replay-2' }],
        alerts: complete ? [{ ...alert, run_id: 'replay-2' }] : [],
      }),
    });
    const user = userEvent.setup();
    renderApp('/replay');
    await screen.findByRole('option', { name: /Authentication positive fixture/ });
    await user.selectOptions(screen.getByLabelText('Dataset'), 'positive-fixture');
    await user.selectOptions(screen.getByLabelText('Replay speed'), '10x');
    await user.click(screen.getByRole('button', { name: 'Start replay' }));
    await waitFor(() =>
      expect(screen.getByRole('progressbar', { name: 'Replay progress' })).toHaveAttribute(
        'value',
        '1',
      ),
    );
    expect(screen.getByRole('progressbar')).toHaveAttribute('max', '2');
    expect(screen.getByRole('button', { name: 'Start replay' })).toBeDisabled();
    expect(screen.getByLabelText('Run scope')).toHaveValue('replay-2');
    expect(await screen.findByRole('table', { name: 'Replay arrivals' })).toHaveTextContent(
      'fixture-host',
    );
    const request = fetch.mock.calls.find(
      ([url, init]) => url === '/api/detections/replay' && init.method === 'POST',
    );
    expect(JSON.parse(String(request?.[1].body))).toEqual({
      dataset_id: 'positive-fixture',
      speed: '10x',
    });
    complete = true;
    await screen.findByText(
      'Replay completed. All counts above are final API results.',
      {},
      { timeout: 2000 },
    );
    expect(screen.getByRole('progressbar')).toHaveAttribute('value', '2');
    expect(await screen.findByRole('link', { name: alert.rule_name })).toHaveAttribute(
      'href',
      '/alerts/alert-1?run_id=replay-2',
    );
    expect(
      fetch.mock.calls.filter(([url]) => url === '/api/detections/replay/replay-2').length,
    ).toBeGreaterThan(1);
    expect(screen.getByRole('button', { name: 'Start replay' })).toBeEnabled();
  });

  it('sends cancellation and displays the confirmed terminal state', async () => {
    let cancelled = false;
    const fetch = mockApi({
      'GET /api/detections/replay/run-1': () => ({
        ...run,
        status: cancelled ? 'cancelled' : 'running',
        processed_events: 1,
      }),
      'GET /api/runs/run-1/feed': { events: [event], alerts: [] },
      'POST /api/detections/replay/run-1/cancel': () => {
        cancelled = true;
        return { ...run, status: 'cancelled', processed_events: 1 };
      },
    });
    const user = userEvent.setup();
    renderApp('/replay?run_id=run-1&replay_id=run-1');
    await user.click(await screen.findByRole('button', { name: 'Cancel replay' }));
    expect(
      await screen.findByText(
        'Replay cancelled. Already processed events and alerts remain available.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole('progressbar')).toHaveAttribute('value', '1');
    expect(screen.queryByRole('button', { name: 'Cancel replay' })).not.toBeInTheDocument();
    expect(
      fetch.mock.calls.some(
        ([url, init]) => url === '/api/detections/replay/run-1/cancel' && init.method === 'POST',
      ),
    ).toBe(true);
  });

  it('does not pretend cancellation succeeded when the API fails', async () => {
    mockApi({
      'GET /api/detections/replay/run-1': { ...run, status: 'running', processed_events: 1 },
      'GET /api/runs/run-1/feed': { events: [event], alerts: [] },
      'POST /api/detections/replay/run-1/cancel': json(
        { error: { code: 'cancel_failed', message: 'Cannot confirm cancellation.' } },
        503,
      ),
    });
    const user = userEvent.setup();
    renderApp('/replay?run_id=run-1&replay_id=run-1');
    await user.click(await screen.findByRole('button', { name: 'Cancel replay' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Cancellation not confirmed');
    expect(screen.getByRole('button', { name: 'Cancel replay' })).toBeEnabled();
    expect(screen.queryByText(/Replay cancelled. Already processed/)).not.toBeInTheDocument();
  });

  it('exposes a rejected realtime span without creating a fake job', async () => {
    mockApi({
      'POST /api/detections/replay': json(
        {
          error: {
            code: 'span_limit',
            message: 'Realtime span exceeds 600 seconds. Use instant or 10x.',
          },
        },
        422,
      ),
    });
    const user = userEvent.setup();
    renderApp('/replay');
    await screen.findByRole('option', { name: /Authentication positive fixture/ });
    await user.selectOptions(screen.getByLabelText('Dataset'), 'positive-fixture');
    await user.selectOptions(screen.getByLabelText('Replay speed'), 'realtime');
    await user.click(screen.getByRole('button', { name: 'Start replay' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Realtime span exceeds 600 seconds.',
    );
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start replay' })).toBeEnabled();
  });

  it('renders a terminal execution error with retained processed counts', async () => {
    mockApi({
      'GET /api/detections/replay/run-1': {
        ...run,
        status: 'failed',
        processed_events: 1,
        error: 'Dataset read failed after event 1.',
      },
      'GET /api/runs/run-1/feed': { events: [event], alerts: [] },
    });
    renderApp('/replay?run_id=run-1&replay_id=run-1');
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Dataset read failed after event 1.',
    );
    expect(screen.getByRole('progressbar')).toHaveAttribute('value', '1');
    expect(screen.queryByText(/Replay completed/)).not.toBeInTheDocument();
  });

  it('starts repeated replays with distinct returned run IDs', async () => {
    let starts = 0;
    const fetch = mockApi({
      'POST /api/detections/replay': () => ({ ...run, id: `replay-repeat-${++starts}` }),
      'GET /api/detections/replay/replay-repeat-1': { ...run, id: 'replay-repeat-1' },
      'GET /api/detections/replay/replay-repeat-2': { ...run, id: 'replay-repeat-2' },
      'GET /api/runs/replay-repeat-1/feed': { events: [event], alerts: [alert] },
      'GET /api/runs/replay-repeat-2/feed': { events: [event], alerts: [alert] },
    });
    const user = userEvent.setup();
    renderApp('/replay');
    await screen.findByRole('option', { name: /Authentication positive fixture/ });
    await user.selectOptions(screen.getByLabelText('Dataset'), 'positive-fixture');
    await user.click(screen.getByRole('button', { name: 'Start replay' }));
    await waitFor(() => expect(screen.getByLabelText('Run scope')).toHaveValue('replay-repeat-1'));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Start replay' })).toBeEnabled());
    await user.click(screen.getByRole('button', { name: 'Start replay' }));
    await waitFor(() => expect(screen.getByLabelText('Run scope')).toHaveValue('replay-repeat-2'));
    expect(
      fetch.mock.calls.filter(
        ([url, init]) => url === '/api/detections/replay' && init.method === 'POST',
      ),
    ).toHaveLength(2);
  });
});
