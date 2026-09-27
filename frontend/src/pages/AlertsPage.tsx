import { Search } from 'lucide-react';
import { AlertTable } from '../components/AlertTable';
import {
  Button,
  EmptyState,
  ErrorNotice,
  LinkButton,
  LoadingState,
  PageHeader,
  Pagination,
  Panel,
  SelectField,
  TextField,
} from '../components/ui';
import { useListFilters } from '../hooks/useListFilters';
import { useResource } from '../hooks/useResource';
import { useWorkspace } from '../hooks/workspace';
import { route } from '../services/api';
import { label, number } from '../services/format';
import type { Alert, Paginated } from '../types';

const alertFilters = ['q', 'severity', 'status', 'rule_id'] as const;

export function AlertsPage() {
  const { runId, revision } = useWorkspace();
  const filters = useListFilters(alertFilters);
  const alerts = useResource<Paginated<Alert>>(`/alerts${filters.query}`, { refreshKey: revision });
  return (
    <>
      <PageHeader
        title="Alert queue"
        description="Triage detections, preserve investigation status, and follow each alert to its evidence."
      />
      <section className="filter-section" aria-label="Alert search filters">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            filters.apply();
          }}
          className="search-toolbar"
        >
          <TextField
            className="search-field"
            label="Search alerts"
            value={filters.draft.q}
            onChange={(event) => filters.setField('q', event.target.value)}
            placeholder="Rule, source, host, or user…"
          />
          <SelectField
            label="Severity"
            value={filters.draft.severity}
            onChange={(event) => filters.setField('severity', event.target.value)}
          >
            <option value="">All severities</option>
            {['informational', 'low', 'medium', 'high', 'critical'].map((value) => (
              <option key={value} value={value}>
                {label(value)}
              </option>
            ))}
          </SelectField>
          <SelectField
            label="Status"
            value={filters.draft.status}
            onChange={(event) => filters.setField('status', event.target.value)}
          >
            <option value="">All statuses</option>
            {['new', 'investigating', 'resolved', 'false_positive', 'suppressed'].map((value) => (
              <option key={value} value={value}>
                {label(value)}
              </option>
            ))}
          </SelectField>
          <TextField
            label="Rule ID"
            className="rule-filter"
            value={filters.draft.rule_id}
            onChange={(event) => filters.setField('rule_id', event.target.value)}
            placeholder="Exact rule ID"
          />
          <Button type="submit" variant="primary">
            <Search size={15} aria-hidden="true" />
            Apply filters
          </Button>
        </form>
        {filters.active.length > 0 && (
          <div className="active-filters">
            <span className="muted">{filters.active.length} filters applied</span>
            <Button variant="ghost" onClick={filters.clear}>
              Clear filters
            </Button>
          </div>
        )}
      </section>
      <Panel
        title="Investigation register"
        description={
          alerts.data
            ? `${number(alerts.data.total)} matching alerts · ${runId ? 'Selected run' : 'All runs'}`
            : 'Alerts and counts are limited to the visible run scope.'
        }
      >
        <ErrorNotice
          error={alerts.error}
          onRetry={alerts.reload}
          title="Alert queue could not be loaded"
        />
        {alerts.loading && <LoadingState label="Loading alerts" />}
        {alerts.data &&
          (alerts.data.items.length ? (
            <AlertTable alerts={alerts.data.items} />
          ) : (
            <EmptyState
              title={
                filters.active.length ? 'No alerts match these filters' : 'No alerts in this scope'
              }
              description={
                filters.active.length
                  ? 'Clear a filter or select a different run. Resolved and suppressed alerts remain searchable.'
                  : 'Replay an included positive scenario to create an alert with a traceable rule snapshot and triggering events.'
              }
              action={
                filters.active.length ? (
                  <Button onClick={filters.clear}>Clear filters</Button>
                ) : (
                  <LinkButton to={route('/replay', runId)}>Replay a dataset</LinkButton>
                )
              }
            />
          ))}
        {alerts.data && (
          <Pagination
            total={alerts.data.total}
            offset={alerts.data.offset}
            limit={alerts.data.limit}
            onChange={filters.paginate}
          />
        )}
      </Panel>
    </>
  );
}
