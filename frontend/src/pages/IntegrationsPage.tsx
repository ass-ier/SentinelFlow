import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ConnectorForm } from '../components/ConnectorForm';
import { CONNECTOR_NAMES } from '../services/integrations';
import { CredentialSettings } from '../components/CredentialSettings';
import {
  Badge,
  Button,
  EmptyState,
  ErrorNotice,
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
import type {
  Connector,
  ConnectorType,
  DemoResult,
  IntegrationOverview,
} from '../types/integrations';

export function IntegrationsPage() {
  const { publicDemo, refresh, revision } = useWorkspace();
  const resource = useResource<IntegrationOverview>('/integrations', {
    refreshKey: revision,
    pollMs: 5000,
  });
  const [editing, setEditing] = useState<Connector | 'new' | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [message, setMessage] = useState('');
  const [source, setSource] = useState<ConnectorType>('microsoft_sentinel');
  const [demo, setDemo] = useState<DemoResult | null>(null);
  async function operation(path: string, body?: unknown) {
    setBusy(path);
    setError(null);
    setMessage('');
    try {
      const result = await api<Connector>(path, { method: 'POST', body });
      if (result.last_error)
        throw new Error(
          `Connector reported ${label(result.last_error)}. Check configuration and retry.`,
        );
      setMessage(
        path.endsWith('/test')
          ? 'Connection query completed. No telemetry was imported by this test.'
          : 'Connector state updated.',
      );
      resource.reload();
      refresh();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy('');
    }
  }
  return (
    <>
      <PageHeader
        title="Integrations"
        description="Bring telemetry into the existing detection engine. External services are optional and disabled by default."
        actions={
          !publicDemo && (
            <Button variant="primary" onClick={() => setEditing('new')}>
              Configure connector
            </Button>
          )
        }
      />
      <nav className="integration-navigation" aria-label="Integration sections">
        <Link to="/integrations" aria-current="page">
          Telemetry connectors
        </Link>
        <Link to="/notifications">Notifications &amp; delivery</Link>
      </nav>
      <ErrorNotice
        error={resource.error}
        onRetry={resource.reload}
        title="Integration status could not be loaded"
      />
      {resource.loading && <LoadingState label="Loading connector status" />}
      {publicDemo ? (
        <Notice>
          External integrations and integration administration are disabled in this shared synthetic
          demo. Use a private installation for the offline connector demonstration or your own
          telemetry.
        </Notice>
      ) : (
        <>
          <Notice>
            No secrets are accepted in these forms. Configure credentials only in the server
            environment; the UI stores references. Mock delivery never means Teams received a
            message.
          </Notice>
          {!!resource.data?.worker.last_error && (
            <Notice tone="warning">
              Integration worker: {label(resource.data.worker.last_error)}. Alerts remain stored
              while delivery is unavailable.
            </Notice>
          )}
        </>
      )}
      <ErrorNotice error={error} title="Integration operation did not complete" />
      {message && <Notice tone="success">{message}</Notice>}
      {resource.data && (
        <Panel
          title="Telemetry sources"
          description="One independent checkpoint per enabled query profile. Times are UTC."
        >
          {resource.data.connectors.length ? (
            <Table caption="Telemetry connectors">
              <thead>
                <tr>
                  <th scope="col">Connector / source</th>
                  <th scope="col">State</th>
                  <th scope="col">Received / normalized</th>
                  <th scope="col">Last success</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.connectors.map((connector) => (
                  <tr key={connector.id}>
                    <td>
                      <strong className="cell-primary">{connector.name}</strong>
                      <span className="cell-secondary">{CONNECTOR_NAMES[connector.type]}</span>
                      <span className="cell-secondary mono">{connector.id}</span>
                      {connector.mode === 'demo' && <Badge>Mock / offline</Badge>}
                    </td>
                    <td>
                      <StatusBadge status={connector.status} />
                      {connector.last_error && (
                        <span className="cell-secondary">{label(connector.last_error)}</span>
                      )}
                      <span className="cell-secondary">
                        {connector.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="mono">
                      {number(connector.events_received)} / {number(connector.events_processed)}
                      <span className="cell-secondary">
                        {number(connector.duplicate_events)} duplicates;{' '}
                        {number(connector.events_failed)} rejected
                      </span>
                    </td>
                    <td>
                      {connector.last_success ? (
                        <Time value={connector.last_success} />
                      ) : (
                        'No successful operation'
                      )}
                      {connector.run_id && (
                        <Link className="cell-secondary" to={route('/events', connector.run_id)}>
                          Inspect received events
                        </Link>
                      )}
                    </td>
                    <td>
                      <div className="row-actions">
                        <Button
                          disabled={publicDemo || !!busy}
                          onClick={() => setEditing(connector)}
                        >
                          Edit
                        </Button>
                        <Button
                          disabled={publicDemo || !!busy}
                          onClick={() =>
                            void operation(`/integrations/connectors/${connector.id}/enabled`, {
                              enabled: !connector.enabled,
                            })
                          }
                        >
                          {connector.enabled ? 'Disable' : 'Enable'}
                        </Button>
                        {connector.type !== 'windows_wef' && (
                          <>
                            <Button
                              disabled={publicDemo || !!busy}
                              onClick={() =>
                                void operation(`/integrations/connectors/${connector.id}/test`)
                              }
                            >
                              Test connection
                            </Button>
                            <Button
                              disabled={publicDemo || !!busy || !connector.enabled}
                              onClick={() =>
                                void operation(`/integrations/connectors/${connector.id}/poll`)
                              }
                            >
                              Poll now
                            </Button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <EmptyState
              title="External connectors are disabled"
              description="Microsoft Sentinel, Microsoft Entra / Graph, and Windows / AD / WEF are available in private installations."
            />
          )}
        </Panel>
      )}
      {!publicDemo && resource.data && editing && (
        <ConnectorForm
          key={editing === 'new' ? 'new' : editing.id}
          connector={editing === 'new' ? undefined : editing}
          overview={resource.data}
          onCancel={() => setEditing(null)}
          onSave={() => {
            setEditing(null);
            resource.reload();
            setMessage('Connector configuration saved.');
          }}
        />
      )}
      {!publicDemo && (
        <Panel
          title="Offline integration demonstration"
          description="Actual loopback HTTP mocks, deterministic synthetic telemetry, real detections and a persisted delivery history. No Microsoft credentials or external requests."
        >
          <form
            className="integration-demo"
            onSubmit={async (event) => {
              event.preventDefault();
              setBusy('demo');
              setError(null);
              setDemo(null);
              try {
                const result = await api<DemoResult>('/integrations/demo', {
                  method: 'POST',
                  body: { source },
                });
                setDemo(result);
                resource.reload();
                refresh();
              } catch (failure) {
                setError(failure);
              } finally {
                setBusy('');
              }
            }}
          >
            <SelectField
              label="Demo telemetry source"
              value={source}
              onChange={(e) => setSource(e.target.value as ConnectorType)}
            >
              {Object.entries(CONNECTOR_NAMES).map(([key, name]) => (
                <option key={key} value={key}>
                  {name}
                </option>
              ))}
            </SelectField>
            <Button variant="primary" type="submit" disabled={!!busy}>
              {busy === 'demo' ? 'Running local demonstration...' : 'Run offline demonstration'}
            </Button>
          </form>
          {demo && (
            <Notice tone={demo.status === 'mock' ? 'success' : 'warning'}>
              {number(demo.events_processed)} normalized events.{' '}
              {demo.deliveries.filter((item) => item.status === 'delivered').length} deliveries
              accepted by the mock receiver. No live Microsoft service was contacted.{' '}
              <Link to={route('/alerts', demo.run_id)}>Inspect alerts and provenance</Link>
              {' · '}
              <Link to="/notifications">Open delivery history</Link>
            </Notice>
          )}
        </Panel>
      )}
      {!publicDemo && <CredentialSettings />}
    </>
  );
}
