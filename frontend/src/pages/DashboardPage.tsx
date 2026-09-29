import { ArrowRight, Play, Upload } from 'lucide-react';
import { Link } from 'react-router-dom';
import { ActivityChart } from '../components/ActivityChart';
import { AlertTable } from '../components/AlertTable';
import { MitreTags } from '../components/Provenance';
import {
  Badge,
  EmptyState,
  ErrorNotice,
  LinkButton,
  LoadingState,
  PageHeader,
  Panel,
  Table,
} from '../components/ui';
import { useResource } from '../hooks/useResource';
import { useWorkspace } from '../hooks/workspace';
import { queryString, route } from '../services/api';
import { number } from '../services/format';
import type { Dashboard } from '../types';

export function DashboardPage() {
  const { runId, revision, publicDemo } = useWorkspace();
  const dashboard = useResource<Dashboard>(`/dashboard${queryString({ run_id: runId })}`, {
    refreshKey: revision,
  });
  const data = dashboard.data;
  return (
    <>
      <PageHeader
        title="Overview"
        description="Telemetry, detections, and the evidence behind them."
        actions={
          <>
            {!publicDemo && (
              <LinkButton to={route('/events', runId, { import: '1' })}>
                <Upload size={15} aria-hidden="true" />
                Import events
              </LinkButton>
            )}
            <LinkButton variant="primary" to={route('/replay', runId)}>
              <Play size={15} aria-hidden="true" />
              Replay dataset
            </LinkButton>
          </>
        }
      />
      <ErrorNotice
        error={dashboard.error}
        onRetry={dashboard.reload}
        title="Overview could not be loaded"
      />
      {dashboard.loading && <LoadingState label="Loading operational overview" />}
      {data && (
        <>
          <dl className="metrics-strip">
            <div>
              <dt>Events processed</dt>
              <dd>{number(data.events_processed)}</dd>
              <span>
                {number(data.runs)} {data.runs === 1 ? 'run' : 'runs'} in scope
              </span>
            </div>
            <div>
              <dt>Active alerts</dt>
              <dd>{number(data.active_alerts)}</dd>
              <span>Open for triage</span>
            </div>
            <div className="metric-critical">
              <dt>Critical alerts</dt>
              <dd>{number(data.critical_alerts)}</dd>
              <span>Highest severity</span>
            </div>
            <div className="metric-high">
              <dt>High alerts</dt>
              <dd>{number(data.high_alerts)}</dd>
              <span>Priority investigation</span>
            </div>
            <div>
              <dt>Detection rules</dt>
              <dd>{number(data.detection_rules)}</dd>
              <span>{number(data.enabled_rules)} enabled now</span>
            </div>
          </dl>
          <Panel
            title="Telemetry activity"
            description={
              runId
                ? 'Event-time activity in the selected run.'
                : 'Event-time activity across all stored runs. Replays remain separate runs.'
            }
            actions={<Badge>{runId ? 'Selected run' : 'All runs'}</Badge>}
          >
            {data.timeline.length ? (
              <ActivityChart data={data.timeline} />
            ) : (
              <EmptyState
                title="No event activity in this scope"
                description={
                  publicDemo
                    ? 'Replay an included synthetic dataset. Each run keeps its evidence and rule snapshot isolated.'
                    : 'Replay an included dataset or import your own telemetry. Every new run keeps its evidence and rule snapshot isolated.'
                }
                action={
                  <LinkButton variant="primary" to={route('/replay', runId)}>
                    <Play size={14} aria-hidden="true" />
                    Choose a dataset
                  </LinkButton>
                }
              />
            )}
          </Panel>
          <Panel
            title="Recent alerts"
            description={`${number(data.total_alerts)} total alerts in scope · Select an alert to open its evidence.`}
            actions={
              <Link className="text-link" to={route('/alerts', runId)}>
                Open alert queue <ArrowRight size={14} aria-hidden="true" />
              </Link>
            }
          >
            {data.recent_alerts.length ? (
              <AlertTable alerts={data.recent_alerts} compact />
            ) : (
              <EmptyState
                title="No alerts to investigate"
                description="No rule has produced an alert in this scope. A successful benign validation does not create operational alerts."
              />
            )}
          </Panel>
          <div className="overview-secondary">
            <section className="register-section" aria-labelledby="sources-title">
              <div className="section-heading">
                <h2 id="sources-title">Top source IPs</h2>
                <span className="muted">Events</span>
              </div>
              {data.top_sources.length ? (
                <ol className="ranked-list">
                  {data.top_sources.map((source) => (
                    <li key={source.ip}>
                      <Link className="mono" to={route('/events', runId, { source_ip: source.ip })}>
                        {source.ip}
                      </Link>
                      <strong className="mono">{number(source.count)}</strong>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="section-empty">Source addresses will appear after ingestion.</p>
              )}
            </section>
            <section className="register-section" aria-labelledby="top-rules-title">
              <div className="section-heading">
                <h2 id="top-rules-title">Top triggered rules</h2>
                <span className="muted">Alerts</span>
              </div>
              {data.top_rules.length ? (
                <ol className="ranked-list">
                  {data.top_rules.map((rule) => (
                    <li key={rule.rule_id}>
                      <div>
                        <Link to={route('/alerts', runId, { rule_id: rule.rule_id })}>
                          {rule.name}
                        </Link>
                        <Link
                          className="cell-secondary mono"
                          to={route(`/rules/${encodeURIComponent(rule.rule_id)}`, runId)}
                        >
                          {rule.rule_id}
                        </Link>
                      </div>
                      <strong className="mono">{number(rule.count)}</strong>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="section-empty">
                  Triggered rules will appear with their actual alert counts.
                </p>
              )}
            </section>
          </div>
          <Panel
            title="MITRE ATT&amp;CK activity"
            description="Mappings on triggered detections, not a claim of technique coverage."
          >
            {data.mitre.length ? (
              <Table caption="MITRE ATT&amp;CK activity">
                <thead>
                  <tr>
                    <th scope="col">Technique</th>
                    <th scope="col">Name</th>
                    <th scope="col">Triggered rules</th>
                    <th scope="col">Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {data.mitre.map((technique) => (
                    <tr key={technique.id}>
                      <td>
                        <MitreTags techniques={[technique.id]} />
                      </td>
                      <td>{technique.name}</td>
                      <td>
                        <div className="tag-list">
                          {technique.rules.map((id) => (
                            <Link
                              key={id}
                              className="mono"
                              to={route('/alerts', runId, { rule_id: id })}
                            >
                              {id}
                            </Link>
                          ))}
                        </div>
                      </td>
                      <td className="mono">{number(technique.count)}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <p className="panel-empty">No ATT&amp;CK-mapped alerts in this scope.</p>
            )}
          </Panel>
        </>
      )}
    </>
  );
}
