import { useEffect, useState } from 'react';
import { ArrowRight, ChevronRight, FileSearch, Save } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { EventTable } from '../components/EventEvidence';
import { DeliveryTable } from '../components/DeliveryTable';
import { MitreTags, Provenance } from '../components/Provenance';
import { RuleDefinition } from '../components/RuleDefinition';
import {
  Badge,
  Button,
  CodeBlock,
  EmptyState,
  ErrorNotice,
  Fact,
  LinkButton,
  LoadingState,
  Notice,
  PageHeader,
  Panel,
  SelectField,
  SeverityBadge,
  StatusBadge,
  TextField,
  Time,
} from '../components/ui';
import { useResource } from '../hooks/useResource';
import { useWorkspace } from '../hooks/workspace';
import { api, route } from '../services/api';
import { label, number } from '../services/format';
import type { Alert, AlertDetail, AlertStatus } from '../types';

export function AlertDetailPage() {
  const { id = '' } = useParams();
  const { runId, revision, refresh, publicDemo } = useWorkspace();
  const detail = useResource<AlertDetail>(`/alerts/${encodeURIComponent(id)}`, {
    refreshKey: revision,
  });
  const alert = detail.data;
  const [status, setStatus] = useState<AlertStatus>('new');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (alert) setStatus(alert.status);
  }, [alert]);
  useEffect(() => {
    setNote('');
    setSaveError(null);
    setSaved(false);
  }, [id]);

  async function saveStatus() {
    if (!alert) return;
    setSaving(true);
    setSaveError(null);
    setSaved(false);
    try {
      const updated = await api<Alert>(`/alerts/${encodeURIComponent(alert.id)}/status`, {
        method: 'PATCH',
        body: { status, ...(note.trim() ? { note: note.trim() } : {}) },
      });
      detail.update({ ...alert, ...updated });
      setStatus(updated.status);
      setSaved(true);
      setNote('');
      refresh();
    } catch (error) {
      setStatus(alert.status);
      setSaveError(error);
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHeader
        title={alert?.rule_name || 'Alert investigation'}
        description={alert ? `Alert ${alert.id}` : 'Loading the detection and its evidence chain.'}
        breadcrumbs={
          <>
            <Link to={route('/alerts', alert?.run_id || runId)}>Alerts</Link>
            <ChevronRight size={13} aria-hidden="true" />
            <span>Investigation</span>
          </>
        }
        actions={
          alert && (
            <LinkButton to={route(`/rules/${encodeURIComponent(alert.rule_id)}`, alert.run_id)}>
              Current rule <ArrowRight size={14} aria-hidden="true" />
            </LinkButton>
          )
        }
      />
      <ErrorNotice error={detail.error} onRetry={detail.reload} title="Alert could not be loaded" />
      {detail.loading && <LoadingState label="Loading alert evidence" />}
      {alert && (
        <>
          <div className="investigation-strip">
            <div>
              <span className="fact-label">Severity</span>
              <SeverityBadge severity={alert.severity} />
            </div>
            <div>
              <span className="fact-label">Current status</span>
              <StatusBadge status={alert.status} />
            </div>
            <div>
              <span className="fact-label">Triggering events</span>
              <strong className="mono">{number(alert.event_count)}</strong>
            </div>
            <div>
              <span className="fact-label">Rule / branch</span>
              <a href="#rule-snapshot" className="mono">
                {alert.rule_id}
              </a>
              <span className="muted">{alert.branch || 'Default'}</span>
            </div>
            <div>
              <span className="fact-label">Run</span>
              <Link
                to={route('/events', alert.run_id)}
                className="mono truncate-run"
                title={alert.run_id}
              >
                {alert.run_id}
              </Link>
            </div>
          </div>
          <div className="investigation-layout">
            <div>
              <section className="investigation-summary">
                <h2>Detection summary</h2>
                <p className="reading-text">{alert.description}</p>
                <MitreTags techniques={alert.mitre_attack} />
              </section>
              <ol className="evidence-timeline" aria-label="Detection timeline">
                <li>
                  <span>First evidence</span>
                  <Time value={alert.first_seen} />
                  <small>UTC</small>
                </li>
                <li>
                  <span>Detection triggered</span>
                  <Time value={alert.triggered_at} />
                  <small>UTC</small>
                </li>
                <li>
                  <span>Last evidence</span>
                  <Time value={alert.last_seen} />
                  <small>UTC</small>
                </li>
              </ol>
              <section className="entity-section">
                <h2>Entities in the evidence</h2>
                <dl className="facts facts-grid">
                  <Fact term="Source IPs">
                    {alert.source_entities.ips.length ? (
                      <div className="entity-links">
                        {alert.source_entities.ips.map((ip) => (
                          <Link
                            key={ip}
                            className="mono"
                            to={route('/events', alert.run_id, { source_ip: ip })}
                          >
                            {ip}
                          </Link>
                        ))}
                      </div>
                    ) : (
                      'Not present'
                    )}
                  </Fact>
                  <Fact term="Affected hosts">
                    {alert.affected_entities.hosts.length ? (
                      <div className="entity-links">
                        {alert.affected_entities.hosts.map((host) => (
                          <Link key={host} to={route('/events', alert.run_id, { host_name: host })}>
                            {host}
                          </Link>
                        ))}
                      </div>
                    ) : (
                      'Not present'
                    )}
                  </Fact>
                  <Fact term="Affected users">
                    {alert.affected_entities.users.length ? (
                      <div className="entity-links">
                        {alert.affected_entities.users.map((user) => (
                          <Link key={user} to={route('/events', alert.run_id, { user_name: user })}>
                            {user}
                          </Link>
                        ))}
                      </div>
                    ) : (
                      'Not present'
                    )}
                  </Fact>
                  <Fact term="Destination IPs">
                    <span className="mono">
                      {alert.affected_entities.destination_ips.join(', ') || 'Not present'}
                    </span>
                  </Fact>
                </dl>
                <details className="disclosure">
                  <summary>Exact correlation group</summary>
                  <CodeBlock value={alert.group} label="Correlation group" />
                </details>
              </section>
            </div>
            <aside className="case-controls" aria-label="Investigation controls">
              <h2>Investigation status</h2>
              {publicDemo ? (
                <Notice>
                  Read-only in the shared demo. Status changes and investigation notes are available
                  in private local mode.
                </Notice>
              ) : (
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    void saveStatus();
                  }}
                >
                  <SelectField
                    label="Set alert status"
                    value={status}
                    onChange={(event) => {
                      setStatus(event.target.value as AlertStatus);
                      setSaved(false);
                    }}
                    disabled={saving}
                  >
                    {['new', 'investigating', 'resolved', 'false_positive', 'suppressed'].map(
                      (value) => (
                        <option key={value} value={value}>
                          {label(value)}
                        </option>
                      ),
                    )}
                  </SelectField>
                  <TextField
                    label="Investigation note (optional)"
                    value={note}
                    onChange={(event) => setNote(event.target.value)}
                    maxLength={2000}
                    disabled={saving}
                  />
                  <Button
                    variant="primary"
                    type="submit"
                    disabled={saving || (status === alert.status && !note.trim())}
                  >
                    <Save size={14} aria-hidden="true" />
                    {saving ? 'Saving…' : 'Save status'}
                  </Button>
                </form>
              )}
              <ErrorNotice error={saveError} title="Status not changed" />
              {saved && (
                <p className="success-text" role="status">
                  Investigation status saved.
                </p>
              )}
              <p className="form-note">
                Status changes preserve the original detection and evidence.
              </p>
              <div className="case-provenance">
                <h3>Detection attribution</h3>
                <Provenance value={alert.provenance} />
              </div>
            </aside>
          </div>
          <Panel
            title="Telemetry provenance"
            description="Provider attribution is distinct from detection-rule provenance."
          >
            {alert.telemetry_sources?.length ? (
              <dl className="facts facts-grid">
                {alert.telemetry_sources.map((source, index) => (
                  <Fact key={index} term={label(source.provider)}>
                    <span className="break-all">
                      {source.connector_id || 'Manual upload'}
                      {source.source_table && ` / ${source.source_table}`}
                      {source.source_channel && ` / ${source.source_channel}`}
                    </span>
                  </Fact>
                ))}
              </dl>
            ) : (
              <p className="panel-note">
                Manual or legacy ingestion. Inspect raw event metadata for source details.
              </p>
            )}
          </Panel>
          <Panel
            title="Notifications"
            description="Delivery state is independent of investigation status."
          >
            <DeliveryTable deliveries={alert.notifications || []} />
            <Link to="/notifications">Notification destinations and delivery history</Link>
          </Panel>
          <Panel
            title="Triggering evidence"
            description={`${number(alert.event_count)} linked events · ${number(alert.evidence_ids.length)} stored evidence references · UTC`}
            actions={
              <LinkButton
                to={route('/events', alert.run_id, {
                  timestamp_from: alert.first_seen,
                  timestamp_to: alert.last_seen,
                })}
              >
                <FileSearch size={14} aria-hidden="true" />
                Explore time window
              </LinkButton>
            }
          >
            <p className="panel-note">
              These rows are the linked trigger evidence. The broader time-window explorer can
              include unrelated events.
            </p>
            {alert.evidence.length ? (
              <EventTable
                events={[...alert.evidence].sort((a, b) =>
                  a.event.timestamp.localeCompare(b.event.timestamp),
                )}
                caption="Triggering evidence"
              />
            ) : (
              <EmptyState
                title="No linked evidence returned"
                description="The API returned this alert without evidence records. Verify the stored run before drawing conclusions."
              />
            )}
          </Panel>
          <div id="rule-snapshot" className="anchor-target">
            <Panel
              title="Pinned rule snapshot"
              description="Exact definition used by this run. The current operational rule may differ or no longer exist."
              actions={<Badge>Pinned evidence</Badge>}
            >
              <Notice>
                Changing today’s rule does not rewrite this alert. This snapshot remains available
                independently of the rule catalog.
              </Notice>
              <RuleDefinition rule={alert.rule_snapshot} snapshot />
              <details className="disclosure">
                <summary>Complete snapshot JSON</summary>
                <CodeBlock value={alert.rule_snapshot} label="Complete rule snapshot JSON" />
              </details>
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
