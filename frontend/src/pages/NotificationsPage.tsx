import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { DeliveryTable } from '../components/DeliveryTable';
import { DestinationForm } from '../components/DestinationForm';
import { NotificationPolicies } from '../components/NotificationPolicies';
import {
  Badge,
  Button,
  CodeBlock,
  EmptyState,
  ErrorNotice,
  LoadingState,
  Notice,
  PageHeader,
  Panel,
  StatusBadge,
  Table,
  Time,
} from '../components/ui';
import { useResource } from '../hooks/useResource';
import { useWorkspace } from '../hooks/workspace';
import { api } from '../services/api';
import type { Collection } from '../types';
import type { Delivery, DeliveryDetail, Destination } from '../types/integrations';

export function NotificationsPage() {
  const { publicDemo } = useWorkspace();
  const destinations = useResource<Collection<Destination>>('/notifications/destinations', {
    pollMs: 5000,
  });
  const [offset, setOffset] = useState(0);
  const history = useResource<Collection<Delivery>>(
    `/notifications/deliveries?offset=${offset}&limit=25`,
    { pollMs: 3000 },
  );
  const [editing, setEditing] = useState<Destination | 'new' | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [message, setMessage] = useState('');
  const [deleting, setDeleting] = useState<string | null>(null);
  async function action(
    path: string,
    method: 'POST' | 'DELETE',
    body?: unknown,
    success = 'Destination state saved.',
  ) {
    setBusy(true);
    setError(null);
    setMessage('');
    try {
      await api(path, { method, body });
      destinations.reload();
      history.reload();
      setMessage(success);
      setDeleting(null);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  }
  const names = Object.fromEntries(
    (destinations.data?.items || []).map((item) => [item.id, item.name]),
  );
  return (
    <>
      <PageHeader
        title="Notifications"
        description="Queue, retry and inspect delivery without blocking detection. Delivered means the endpoint accepted the request, not that Teams displayed it."
        actions={
          !publicDemo && (
            <Button variant="primary" onClick={() => setEditing('new')}>
              Add destination
            </Button>
          )
        }
      />
      <nav className="integration-navigation" aria-label="Integration sections">
        <Link to="/integrations">Telemetry connectors</Link>
        <Link to="/notifications" aria-current="page">
          Notifications &amp; delivery
        </Link>
      </nav>
      {publicDemo && (
        <Notice>
          Outbound delivery and notification administration are disabled in the shared public demo.
        </Notice>
      )}
      <ErrorNotice error={error} title="Notification operation did not complete" />
      {message && <Notice tone="success">{message}</Notice>}
      <ErrorNotice
        error={destinations.error}
        onRetry={destinations.reload}
        title="Destinations could not be loaded"
      />
      {destinations.loading && <LoadingState label="Loading notification destinations" />}
      <Panel
        title="Destinations"
        description="Power Automate is the Teams orchestration path. Generic webhooks work independently."
      >
        {destinations.data?.items.length ? (
          <Table caption="Notification destinations">
            <thead>
              <tr>
                <th scope="col">Destination</th>
                <th scope="col">State</th>
                <th scope="col">Last delivery</th>
                <th scope="col">Failures</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {destinations.data.items.map((destination) => (
                <tr key={destination.id}>
                  <td>
                    <strong className="cell-primary">{destination.name}</strong>
                    <span className="cell-secondary">
                      {destination.type === 'power_automate' ? 'Power Automate' : 'Generic webhook'}
                    </span>
                    {destination.mode === 'demo' && <Badge>Mock / offline</Badge>}
                  </td>
                  <td>
                    <StatusBadge status={destination.health} />
                    <span className="cell-secondary">
                      {destination.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                  <td>
                    {destination.last_delivery?.last_attempt_at ? (
                      <Time value={destination.last_delivery.last_attempt_at} />
                    ) : (
                      'Not attempted'
                    )}
                  </td>
                  <td className="mono">{destination.failure_count}</td>
                  <td>
                    <div className="row-actions">
                      <Button disabled={publicDemo || busy} onClick={() => setEditing(destination)}>
                        Edit
                      </Button>
                      <Button
                        disabled={publicDemo || busy}
                        onClick={() =>
                          void action(
                            `/notifications/destinations/${destination.id}/enabled`,
                            'POST',
                            { enabled: !destination.enabled },
                          )
                        }
                      >
                        {destination.enabled ? 'Disable' : 'Enable'}
                      </Button>
                      <Button
                        disabled={publicDemo || busy || !destination.enabled}
                        onClick={() =>
                          void action(
                            '/notifications/test',
                            'POST',
                            { destination_id: destination.id },
                            'Notification test queued. Inspect delivery history for the actual result.',
                          )
                        }
                      >
                        Send test
                      </Button>
                      <Button
                        disabled={publicDemo || busy}
                        onClick={() => setDeleting(destination.id)}
                      >
                        Delete
                      </Button>
                      {deleting === destination.id && (
                        <>
                          <Button
                            variant="danger"
                            disabled={busy}
                            onClick={() =>
                              void action(
                                `/notifications/destinations/${destination.id}`,
                                'DELETE',
                                undefined,
                                'Destination removed. Delivery history is retained.',
                              )
                            }
                          >
                            Confirm delete destination
                          </Button>
                          <Button onClick={() => setDeleting(null)}>Keep destination</Button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          !destinations.loading &&
          !destinations.error && (
            <EmptyState
              title="No notification destinations configured."
              description="Detection and investigation still work. Add a server-backed destination or run the offline integration demonstration."
            />
          )
        )}
      </Panel>
      {!publicDemo && editing && (
        <DestinationForm
          key={editing === 'new' ? 'new' : editing.id}
          destination={editing === 'new' ? undefined : editing}
          onCancel={() => setEditing(null)}
          onSave={() => {
            setEditing(null);
            destinations.reload();
            setMessage('Destination saved. Enable it when ready.');
          }}
        />
      )}
      <NotificationPolicies destinations={destinations.data?.items || []} readOnly={publicDemo} />
      <Panel
        title="Delivery history"
        description="A delivery failure never removes the underlying alert. HTTP response bodies and authentication values are not stored."
      >
        <ErrorNotice
          error={history.error}
          onRetry={history.reload}
          title="Delivery history could not be loaded"
        />
        {history.loading && <LoadingState label="Loading delivery history" />}
        {history.data && (
          <>
            <DeliveryTable deliveries={history.data.items} names={names} />
            <div className="form-actions">
              <span>{history.data.total} total deliveries</span>
              <Button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 25))}>
                Previous deliveries
              </Button>
              <Button
                disabled={offset + 25 >= history.data.total}
                onClick={() => setOffset(offset + 25)}
              >
                Next deliveries
              </Button>
            </div>
          </>
        )}
      </Panel>
    </>
  );
}

export function DeliveryDetailPage() {
  const { id = '' } = useParams();
  const resource = useResource<DeliveryDetail>(
    `/notifications/deliveries/${encodeURIComponent(id)}`,
    {
      pollMs: 3000,
      pollWhile: (value) => !!value && ['pending', 'processing', 'failed'].includes(value.status),
    },
  );
  return (
    <>
      <PageHeader
        title="Notification delivery"
        description={`Delivery ${id}`}
        breadcrumbs={<Link to="/notifications">Notifications &amp; delivery history</Link>}
      />
      <ErrorNotice
        error={resource.error}
        onRetry={resource.reload}
        title="Delivery could not be loaded"
      />
      {resource.loading && <LoadingState label="Loading delivery evidence" />}
      {resource.data && (
        <>
          {resource.data.mock && (
            <Notice>
              Mock endpoint delivery only. No live Power Automate flow or Teams channel was
              contacted.
            </Notice>
          )}
          <DeliveryTable deliveries={[resource.data]} />
          <Panel title="Attempt history">
            <Table caption="Delivery attempts">
              <thead>
                <tr>
                  <th scope="col">Attempt</th>
                  <th scope="col">Time (UTC)</th>
                  <th scope="col">HTTP status</th>
                  <th scope="col">Error</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.attempts.map((attempt) => (
                  <tr key={attempt.number}>
                    <td>{attempt.number}</td>
                    <td>
                      <Time value={attempt.timestamp} />
                    </td>
                    <td>{attempt.http_status ?? 'No response'}</td>
                    <td>{attempt.error || 'None'}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Panel>
          <CodeBlock
            label="Outbound payload (no credentials or raw log bodies)"
            value={resource.data.payload}
          />
          <p className="form-note">
            Idempotency key: <span className="mono break-all">{resource.data.idempotency_key}</span>
          </p>
        </>
      )}
    </>
  );
}
