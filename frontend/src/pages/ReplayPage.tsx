import { useEffect, useRef, useState } from 'react';
import { Play, Square } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import { AlertTable } from '../components/AlertTable';
import { DatasetSelect, DatasetSummary } from '../components/DatasetFields';
import { EventTable } from '../components/EventEvidence';
import {
  Badge,
  Button,
  CodeBlock,
  EmptyState,
  ErrorNotice,
  Fact,
  LoadingState,
  Notice,
  PageHeader,
  Panel,
  SelectField,
  StatusBadge,
  Table,
  Time,
} from '../components/ui';
import { useResource } from '../hooks/useResource';
import { useWorkspace } from '../hooks/workspace';
import { api, route } from '../services/api';
import { label, number } from '../services/format';
import type { Alert, Collection, Dataset, NormalizedEvent, ReplaySpeed, Run } from '../types';

function active(run: Run | null) {
  return run?.status === 'pending' || run?.status === 'running';
}

export function ReplayPage() {
  const { runs, revision, refresh } = useWorkspace();
  const [params, setParams] = useSearchParams();
  const replayId = params.get('replay_id') || '';
  const datasets = useResource<Collection<Dataset>>('/datasets', { refreshKey: revision });
  const [datasetId, setDatasetId] = useState('');
  const [speed, setSpeed] = useState<ReplaySpeed>('instant');
  const [starting, setStarting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [startError, setStartError] = useState<unknown>(null);
  const [cancelError, setCancelError] = useState<unknown>(null);
  const [startedRun, setStartedRun] = useState<Run | null>(null);
  const job = useResource<Run>(
    replayId ? `/detections/replay/${encodeURIComponent(replayId)}` : null,
    {
      refreshKey: revision,
      pollMs: 500,
      pollWhile: (value) => value === null || active(value),
    },
  );
  const run = job.data || (startedRun?.id === replayId ? startedRun : null);
  const feed = useResource<{ events: NormalizedEvent[]; alerts: Alert[] }>(
    replayId ? `/runs/${encodeURIComponent(replayId)}/feed` : null,
    { refreshKey: `${revision}:${run?.status ?? ''}`, pollMs: 500, pollWhile: () => active(run) },
  );
  const lastFinished = useRef('');
  useEffect(() => {
    if (run && !active(run) && lastFinished.current !== `${run.id}:${run.status}`) {
      lastFinished.current = `${run.id}:${run.status}`;
      refresh();
    }
  }, [run, refresh]);
  const selected = datasets.data?.items.find((dataset) => dataset.id === datasetId);

  async function start() {
    setStarting(true);
    setStartError(null);
    setCancelError(null);
    try {
      const result = await api<Run>('/detections/replay', {
        method: 'POST',
        body: { dataset_id: datasetId, speed },
      });
      setStartedRun(result);
      setParams((previous) => {
        const next = new URLSearchParams(previous);
        next.set('replay_id', result.id);
        next.set('run_id', result.id);
        return next;
      });
      refresh();
    } catch (error) {
      setStartError(error);
    } finally {
      setStarting(false);
    }
  }
  async function cancel() {
    if (!run) return;
    setCancelling(true);
    setCancelError(null);
    try {
      const result = await api<Run>(`/detections/replay/${encodeURIComponent(run.id)}/cancel`, {
        method: 'POST',
      });
      job.update(result);
      setStartedRun(result);
      refresh();
    } catch (error) {
      setCancelError(error);
    } finally {
      setCancelling(false);
    }
  }
  return (
    <>
      <PageHeader
        title="Detection replay"
        description="Process a dataset chronologically and follow the actual event arrivals and detections."
      />
      <Panel
        title="Start an isolated replay"
        description="Every replay creates a fresh run and pins the current enabled rules. No existing data is cleared."
      >
        <ErrorNotice
          error={datasets.error}
          onRetry={datasets.reload}
          title="Replay datasets unavailable"
        />
        <form
          className="workbench-form"
          onSubmit={(event) => {
            event.preventDefault();
            void start();
          }}
        >
          <div className="replay-inputs">
            <DatasetSelect
              datasets={datasets.data?.items ?? []}
              value={datasetId}
              onChange={setDatasetId}
              disabled={starting || datasets.loading || active(run)}
            />
            <SelectField
              label="Replay speed"
              value={speed}
              onChange={(event) => setSpeed(event.target.value as ReplaySpeed)}
              disabled={starting || active(run)}
            >
              <option value="instant">Instant — no event-time delay</option>
              <option value="10x">10× — accelerated event time</option>
              <option value="realtime">Realtime — original event spacing</option>
            </SelectField>
            <Button
              variant="primary"
              type="submit"
              disabled={starting || !datasetId || active(run) || !!datasets.error}
            >
              <Play size={15} aria-hidden="true" />
              {starting ? 'Starting replay…' : 'Start replay'}
            </Button>
          </div>
          {selected && <DatasetSummary dataset={selected} />}
          <p className="form-note">
            Duplicate events are ignored within a run. Realtime datasets spanning more than 600
            seconds are rejected; choose instant or 10× instead.
          </p>
          <ErrorNotice error={startError} title="Replay not started" />
          {starting && <p role="status">Requesting a real replay job…</p>}
        </form>
      </Panel>
      {replayId ? (
        <Panel
          title="Replay progress"
          description={
            run ? <span className="mono">{run.id}</span> : 'Loading the selected replay job.'
          }
          actions={run && <StatusBadge status={run.status} />}
        >
          <ErrorNotice
            error={job.error}
            onRetry={job.reload}
            title="Replay status could not be refreshed"
          />
          {!!job.error && (
            <p className="panel-note">
              The last known state is retained. A connection error does not mean the backend job has
              stopped.
            </p>
          )}
          {job.loading && !run && <LoadingState label="Loading replay status" />}
          {run && (
            <div className="replay-progress">
              <div className="progress-heading">
                <strong>
                  {number(run.processed_events)}{' '}
                  <span className="muted">/ {number(run.total_events)} events processed</span>
                </strong>
                <Badge>{run.speed === '10x' ? '10×' : label(run.speed)}</Badge>
              </div>
              <progress
                max={Math.max(1, run.total_events)}
                value={run.processed_events}
                aria-label="Replay progress"
              />
              <dl className="facts replay-facts">
                <Fact term="Events processed">{number(run.processed_events)}</Fact>
                <Fact term="Duplicates ignored">{number(run.duplicate_events)}</Fact>
                <Fact term="Alerts created">{number(run.alerts_created)}</Fact>
                <Fact term="Pinned rules">{number(run.rules_count)}</Fact>
                <Fact term="Event watermark (UTC)">
                  <Time value={run.watermark} />
                </Fact>
              </dl>
              <div className="replay-job-actions">
                <p role="status">
                  {run.status === 'completed'
                    ? 'Replay completed. All counts above are final API results.'
                    : run.status === 'cancelled'
                      ? 'Replay cancelled. Already processed events and alerts remain available.'
                      : run.status === 'failed'
                        ? 'Replay failed. Inspect the backend error below.'
                        : 'Polling the backend job every 500 ms. Progress is not simulated.'}
                </p>
                {active(run) && (
                  <Button variant="danger" disabled={cancelling} onClick={() => void cancel()}>
                    <Square size={13} aria-hidden="true" />
                    {cancelling ? 'Cancelling…' : 'Cancel replay'}
                  </Button>
                )}
              </div>
              {run.error && (
                <ErrorNotice error={new Error(run.error)} title="Replay execution error" />
              )}
              <ErrorNotice error={cancelError} title="Cancellation not confirmed" />
              <details className="disclosure">
                <summary>Recorded run & performance metrics</summary>
                <CodeBlock
                  value={{
                    created_at: run.created_at,
                    completed_at: run.completed_at,
                    ...run.metrics,
                  }}
                  label="Replay metrics"
                />
              </details>
            </div>
          )}
        </Panel>
      ) : (
        <Notice>
          Select a dataset to start a replay, or reopen a previous run below. The run scope changes
          automatically when a new replay starts.
        </Notice>
      )}
      {replayId && (
        <>
          <ErrorNotice error={feed.error} onRetry={feed.reload} title="Replay feed unavailable" />
          <Panel
            title="Event arrivals"
            description={
              feed.data
                ? `${number(feed.data.events.length)} returned arrival records · The backend feed is bounded; use the explorer for the complete stored run.`
                : 'Fetching stored event arrivals from the selected run.'
            }
            actions={
              <Link className="text-link" to={route('/events', replayId)}>
                Open run in explorer
              </Link>
            }
          >
            {feed.loading && <LoadingState label="Loading replay arrivals" />}
            {feed.data &&
              (feed.data.events.length ? (
                <EventTable events={feed.data.events} caption="Replay arrivals" />
              ) : (
                <EmptyState
                  title="Waiting for event arrivals"
                  description="Rows appear only after the backend has processed and stored events."
                />
              ))}
          </Panel>
          <Panel
            title="Detections in this replay"
            description="Open an alert to investigate its pinned definition and raw evidence."
            actions={
              <Link className="text-link" to={route('/alerts', replayId)}>
                Open run alert queue
              </Link>
            }
          >
            {feed.loading && <LoadingState label="Loading replay detections" />}
            {feed.data &&
              (feed.data.alerts.length ? (
                <AlertTable alerts={feed.data.alerts} compact />
              ) : (
                <EmptyState
                  title="No alerts returned for this run"
                  description="A benign replay may correctly produce no alerts. This is an observation, not a validation assertion."
                />
              ))}
          </Panel>
        </>
      )}
      <Panel
        title="Recent runs"
        description="Reopen a replay or inspect an import without overwriting earlier evidence."
      >
        {runs.length ? (
          <Table caption="Recent runs">
            <thead>
              <tr>
                <th scope="col">Run</th>
                <th scope="col">Kind</th>
                <th scope="col">Created (UTC)</th>
                <th scope="col">Processed</th>
                <th scope="col">Alerts</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {[...runs]
                .sort((a, b) => b.created_at.localeCompare(a.created_at))
                .slice(0, 12)
                .map((item) => (
                  <tr key={item.id}>
                    <td>
                      <Link
                        className="cell-primary"
                        to={
                          item.kind === 'replay'
                            ? route('/replay', item.id, { replay_id: item.id })
                            : route('/events', item.id)
                        }
                      >
                        {item.name}
                      </Link>
                      <span className="cell-secondary mono">{item.id}</span>
                    </td>
                    <td>{label(item.kind)}</td>
                    <td>
                      <Time value={item.created_at} />
                    </td>
                    <td className="mono">{number(item.processed_events)}</td>
                    <td className="mono">{number(item.alerts_created)}</td>
                    <td>
                      <StatusBadge status={item.status} />
                    </td>
                  </tr>
                ))}
            </tbody>
          </Table>
        ) : (
          <p className="panel-empty">No stored runs yet. Start a replay or import telemetry.</p>
        )}
      </Panel>
    </>
  );
}
