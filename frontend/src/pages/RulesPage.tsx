import { useState } from 'react';
import { ArrowRight, FlaskConical } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { DatasetSelect, DatasetSummary } from '../components/DatasetFields';
import { MitreTags } from '../components/Provenance';
import { RuleDefinition } from '../components/RuleDefinition';
import { ValidationReportView } from '../components/ValidationReport';
import {
  Button,
  EmptyState,
  ErrorNotice,
  LinkButton,
  LoadingState,
  Notice,
  PageHeader,
  Panel,
  SeverityBadge,
  Table,
  TextField,
  Time,
} from '../components/ui';
import { useResource } from '../hooks/useResource';
import { useWorkspace } from '../hooks/workspace';
import { api, route } from '../services/api';
import { duration, number } from '../services/format';
import type { Collection, Dataset, Rule, ValidationReport } from '../types';

export function RulesPage() {
  const { runId, revision, refresh } = useWorkspace();
  const rules = useResource<Collection<Rule>>('/rules', { refreshKey: revision });
  const [query, setQuery] = useState('');
  const [pending, setPending] = useState<Set<string>>(new Set());
  const [toggleError, setToggleError] = useState<unknown>(null);
  const [feedback, setFeedback] = useState('');
  const visible =
    rules.data?.items.filter((rule) =>
      [rule.id, rule.name, rule.description, ...rule.mitre_attack]
        .join(' ')
        .toLowerCase()
        .includes(query.toLowerCase()),
    ) ?? [];

  async function toggle(rule: Rule) {
    setPending((ids) => new Set(ids).add(rule.id));
    setToggleError(null);
    setFeedback('');
    try {
      const updated = await api<Rule>(`/rules/${encodeURIComponent(rule.id)}`, {
        method: 'PATCH',
        body: { enabled: !rule.enabled },
      });
      rules.update((previous) => ({
        ...previous,
        items: previous.items.map((item) => (item.id === updated.id ? updated : item)),
      }));
      setFeedback(
        `${updated.name} ${updated.enabled ? 'enabled' : 'disabled'} for new runs. Existing runs keep their pinned rules.`,
      );
      refresh();
    } catch (error) {
      setToggleError(error);
    } finally {
      setPending((ids) => {
        const next = new Set(ids);
        next.delete(rule.id);
        return next;
      });
    }
  }
  return (
    <>
      <PageHeader
        title="Detection rules"
        description="Inspect data-driven definitions, thresholds, and grouping. Operational settings apply to new runs."
        actions={
          <LinkButton to={route('/testing', runId)}>
            <FlaskConical size={15} aria-hidden="true" />
            Detection testing
          </LinkButton>
        }
      />
      <Notice>
        Enable changes affect new imports and replays only. Active runs and existing alerts retain
        their pinned rule snapshots.
      </Notice>
      <div className="rule-search-row">
        <TextField
          label="Search detection rules"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Name, rule ID, or ATT&CK technique…"
        />
        {rules.data && (
          <p className="muted">
            {number(rules.data.items.filter((rule) => rule.enabled).length)} enabled /{' '}
            {number(rules.data.total)} definitions · Global catalog
          </p>
        )}
      </div>
      <ErrorNotice error={toggleError} title="Rule state not changed" />
      {feedback && (
        <p role="status" className="success-text">
          {feedback}
        </p>
      )}
      <Panel
        title="Rule catalog"
        description={
          rules.data
            ? `${number(visible.length)} matching definitions`
            : 'Current operational definitions, independent of event scope.'
        }
      >
        <ErrorNotice
          error={rules.error}
          onRetry={rules.reload}
          title="Rule catalog could not be loaded"
        />
        {rules.loading && <LoadingState label="Loading detection rules" />}
        {rules.data &&
          (visible.length ? (
            <Table caption="Detection rules" className="rules-table">
              <thead>
                <tr>
                  <th scope="col">Detection</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Threshold / window</th>
                  <th scope="col">Grouped by</th>
                  <th scope="col">MITRE ATT&CK</th>
                  <th scope="col">New runs</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <Link
                        className="cell-primary"
                        to={route(`/rules/${encodeURIComponent(rule.id)}`, runId)}
                      >
                        {rule.name}
                      </Link>
                      <span className="cell-secondary mono">{rule.id}</span>
                    </td>
                    <td>
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td>
                      <span className="cell-primary">{number(rule.threshold.count)} events</span>
                      <span className="cell-secondary">
                        {duration(rule.threshold.window_seconds)} window
                      </span>
                    </td>
                    <td className="mono">{rule.group_by.join(', ') || 'Ungrouped'}</td>
                    <td>
                      <MitreTags techniques={rule.mitre_attack} />
                    </td>
                    <td>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={rule.enabled}
                        aria-label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.name}`}
                        className="rule-switch"
                        disabled={pending.has(rule.id)}
                        onClick={() => void toggle(rule)}
                      >
                        <span className="switch-track">
                          <span />
                        </span>
                        <span>
                          {pending.has(rule.id) ? 'Saving…' : rule.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <EmptyState
              title={query ? 'No rules match this search' : 'No definitions returned'}
              description={
                query
                  ? 'Try a rule ID or a broader name.'
                  : 'Check that the backend has loaded its included rule definitions.'
              }
              action={
                query ? <Button onClick={() => setQuery('')}>Clear search</Button> : undefined
              }
            />
          ))}
      </Panel>
    </>
  );
}

export function RuleDetailPage() {
  const { id = '' } = useParams();
  const { runId, revision, refresh } = useWorkspace();
  const rule = useResource<Rule>(`/rules/${encodeURIComponent(id)}`, { refreshKey: revision });
  const datasets = useResource<Collection<Dataset>>('/datasets', { refreshKey: revision });
  const [datasetId, setDatasetId] = useState('');
  const [expected, setExpected] = useState('');
  const [toggling, setToggling] = useState(false);
  const [toggleError, setToggleError] = useState<unknown>(null);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<unknown>(null);
  const [report, setReport] = useState<ValidationReport | null>(null);
  const selectedDataset = datasets.data?.items.find((dataset) => dataset.id === datasetId);

  async function toggle() {
    if (!rule.data) return;
    setToggling(true);
    setToggleError(null);
    try {
      const updated = await api<Rule>(`/rules/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: { enabled: !rule.data.enabled },
      });
      rule.update(updated);
      refresh();
    } catch (error) {
      setToggleError(error);
    } finally {
      setToggling(false);
    }
  }
  async function test() {
    setTesting(true);
    setReport(null);
    setTestError(null);
    try {
      const result = await api<ValidationReport>(`/rules/${encodeURIComponent(id)}/test`, {
        method: 'POST',
        body: {
          dataset_id: datasetId,
          ...(expected !== '' ? { expected_alerts: Number(expected) } : {}),
        },
      });
      setReport(result);
    } catch (error) {
      setTestError(error);
    } finally {
      setTesting(false);
    }
  }
  return (
    <>
      <PageHeader
        title={rule.data?.name || 'Detection definition'}
        description={
          <>
            <span className="mono">{id}</span> · Current operational rule, not an alert’s historical
            snapshot.
          </>
        }
        actions={<LinkButton to={route('/rules', runId)}>Back to rules</LinkButton>}
      />
      <ErrorNotice
        error={rule.error}
        onRetry={rule.reload}
        title="Current rule could not be loaded"
      />
      {!!rule.error && (
        <Notice>
          An existing alert retains its exact rule snapshot even if this definition is no longer in
          the current catalog.
        </Notice>
      )}
      {rule.loading && <LoadingState label="Loading rule definition" />}
      {rule.data && (
        <>
          <Panel
            title="Current definition"
            description={
              <span>
                Last updated <Time value={rule.data.updated_at} /> UTC
              </span>
            }
            actions={
              <button
                type="button"
                role="switch"
                aria-checked={rule.data.enabled}
                aria-label={`${rule.data.enabled ? 'Disable' : 'Enable'} ${rule.data.name}`}
                className="rule-switch"
                disabled={toggling}
                onClick={() => void toggle()}
              >
                <span className="switch-track">
                  <span />
                </span>
                {toggling
                  ? 'Saving…'
                  : rule.data.enabled
                    ? 'Enabled for new runs'
                    : 'Disabled for new runs'}
              </button>
            }
          >
            <ErrorNotice error={toggleError} title="Rule state not changed" />
            <p className="panel-note">
              Changes here do not affect active replays or rewrite historical evidence.
            </p>
            <RuleDefinition rule={rule.data} />
          </Panel>
          <Panel
            title="Test this definition"
            description="An isolated definition test; disabled definitions are tested explicitly without changing their enabled state."
          >
            <form
              className="definition-test"
              onSubmit={(event) => {
                event.preventDefault();
                void test();
              }}
            >
              <ErrorNotice
                error={datasets.error}
                onRetry={datasets.reload}
                title="Dataset manifest could not be loaded"
              />
              <div className="form-grid">
                <DatasetSelect
                  datasets={datasets.data?.items ?? []}
                  value={datasetId}
                  onChange={(value) => {
                    setDatasetId(value);
                    setReport(null);
                  }}
                  disabled={testing || datasets.loading}
                />
                <TextField
                  label="Expected alerts (optional)"
                  type="number"
                  min={0}
                  step={1}
                  value={expected}
                  onChange={(event) => {
                    setExpected(event.target.value);
                    setReport(null);
                  }}
                  hint="Leave empty to use saved expectations. An unknown custom expectation is OBSERVED, not PASS."
                  disabled={testing}
                />
              </div>
              {selectedDataset && <DatasetSummary dataset={selectedDataset} />}
              <ErrorNotice error={testError} title="Definition test could not run" />
              <div className="form-actions">
                <Button type="submit" variant="primary" disabled={testing || !datasetId}>
                  <FlaskConical size={15} aria-hidden="true" />
                  {testing ? 'Testing definition…' : 'Run definition test'}
                </Button>
                <Link className="text-link" to={route('/testing', runId, { rule_id: id })}>
                  Full testing workbench <ArrowRight size={13} aria-hidden="true" />
                </Link>
              </div>
              {testing && (
                <p role="status">Running an isolated test against the selected dataset…</p>
              )}
            </form>
          </Panel>
          {report && <ValidationReportView report={report} />}
        </>
      )}
    </>
  );
}
