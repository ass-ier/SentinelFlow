import { useState } from 'react';
import { Search, SlidersHorizontal, Upload, X } from 'lucide-react';
import { useParams, useSearchParams } from 'react-router-dom';
import { EventRecord, EventTable } from '../components/EventEvidence';
import { IngestForm } from '../components/IngestForm';
import {
  Button,
  EmptyState,
  ErrorNotice,
  LinkButton,
  LoadingState,
  Notice,
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
import { fromUtcInput, label, number, utcInput } from '../services/format';
import type { NormalizedEvent, Paginated } from '../types';

const eventFilters = [
  'q',
  'category',
  'severity',
  'source_ip',
  'user_name',
  'host_name',
  'action',
  'outcome',
  'process_name',
  'event_type',
  'event_source',
  'timestamp_from',
  'timestamp_to',
] as const;
const fieldNames: Record<string, string> = {
  q: 'Search',
  source_ip: 'Source IP',
  user_name: 'User',
  host_name: 'Host',
  process_name: 'Process',
  event_type: 'Event type',
  event_source: 'Event source',
  timestamp_from: 'From (UTC)',
  timestamp_to: 'To (UTC)',
};

export function EventsPage() {
  const { runId, revision, publicDemo } = useWorkspace();
  const [params, setParams] = useSearchParams();
  const filters = useListFilters(eventFilters);
  const [advanced, setAdvanced] = useState(false);
  const [importOpen, setImportOpen] = useState(params.get('import') === '1');
  const [filterError, setFilterError] = useState<unknown>(null);
  const events = useResource<Paginated<NormalizedEvent>>(`/events/search${filters.query}`, {
    refreshKey: revision,
  });
  const set = filters.setField;
  function closeImport() {
    setImportOpen(false);
    const next = new URLSearchParams(params);
    next.delete('import');
    setParams(next, { replace: true });
  }
  return (
    <>
      <PageHeader
        title="Event explorer"
        description="Search normalized telemetry. Expand any row to inspect its original, untrusted input."
        actions={
          !publicDemo && (
            <Button
              variant="primary"
              onClick={() => setImportOpen((value) => !value)}
              aria-expanded={importOpen}
              aria-controls="event-import"
            >
              <Upload size={15} aria-hidden="true" />
              Import events
            </Button>
          )
        }
      />
      {importOpen && publicDemo && (
        <Notice>
          Importing logs is unavailable in the public demo. Replay an included synthetic dataset
          instead; custom telemetry belongs in a private local installation.
        </Notice>
      )}
      {importOpen && !publicDemo && (
        <div id="event-import">
          <Panel
            title="Import telemetry"
            actions={
              <Button variant="ghost" onClick={closeImport}>
                <X size={14} aria-hidden="true" />
                Close import
              </Button>
            }
          >
            <IngestForm />
          </Panel>
        </div>
      )}
      <section className="filter-section" aria-label="Event search filters">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const from = filters.draft.timestamp_from;
            const to = filters.draft.timestamp_to;
            if (from && to && Date.parse(from) > Date.parse(to)) {
              setFilterError(
                new Error(
                  'The start timestamp must be before the end timestamp. Both values are UTC.',
                ),
              );
              return;
            }
            setFilterError(null);
            filters.apply();
          }}
        >
          <div className="search-toolbar">
            <TextField
              label="Search events"
              value={filters.draft.q}
              onChange={(event) => set('q', event.target.value)}
              placeholder="Search indexed event fields…"
              className="search-field"
            />
            <SelectField
              label="Category"
              value={filters.draft.category}
              onChange={(event) => set('category', event.target.value)}
            >
              <option value="">All categories</option>
              {[
                'authentication',
                'process',
                'network',
                'identity',
                'file',
                'system',
                'application',
              ].map((value) => (
                <option key={value} value={value}>
                  {label(value)}
                </option>
              ))}
            </SelectField>
            <SelectField
              label="Severity"
              value={filters.draft.severity}
              onChange={(event) => set('severity', event.target.value)}
            >
              <option value="">All severities</option>
              {['informational', 'low', 'medium', 'high', 'critical'].map((value) => (
                <option key={value} value={value}>
                  {label(value)}
                </option>
              ))}
            </SelectField>
            <Button
              aria-expanded={advanced}
              aria-controls="advanced-event-filters"
              onClick={() => setAdvanced((value) => !value)}
            >
              <SlidersHorizontal size={15} aria-hidden="true" />
              More filters
            </Button>
            <Button variant="primary" type="submit">
              <Search size={15} aria-hidden="true" />
              Search
            </Button>
          </div>
          {advanced && (
            <div id="advanced-event-filters" className="advanced-filters form-grid">
              {[
                'source_ip',
                'host_name',
                'user_name',
                'process_name',
                'action',
                'event_type',
                'event_source',
              ].map((key) => (
                <TextField
                  key={key}
                  label={fieldNames[key] || label(key)}
                  value={filters.draft[key]}
                  onChange={(event) => set(key, event.target.value)}
                  placeholder="Exact match"
                />
              ))}
              <SelectField
                label="Outcome"
                value={filters.draft.outcome}
                onChange={(event) => set('outcome', event.target.value)}
              >
                <option value="">All outcomes</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
                <option value="unknown">Unknown</option>
              </SelectField>
              <TextField
                label="From timestamp (UTC)"
                type="datetime-local"
                step="1"
                value={utcInput(filters.draft.timestamp_from)}
                onChange={(event) => set('timestamp_from', fromUtcInput(event.target.value))}
              />
              <TextField
                label="To timestamp (UTC)"
                type="datetime-local"
                step="1"
                value={utcInput(filters.draft.timestamp_to)}
                onChange={(event) => set('timestamp_to', fromUtcInput(event.target.value))}
              />
            </div>
          )}
        </form>
        <ErrorNotice error={filterError} title="Check the time range" />
        {filters.active.length > 0 && (
          <div className="active-filters" aria-label="Applied filters">
            {filters.active.map(([key, value]) => (
              <button
                key={key}
                className="filter-chip"
                onClick={() => filters.remove(key)}
                aria-label={`Remove ${fieldNames[key] || label(key)} filter`}
              >
                {fieldNames[key] || label(key)}: {value}
                <X size={12} aria-hidden="true" />
              </button>
            ))}
            <Button variant="ghost" onClick={filters.clear}>
              Clear filters
            </Button>
          </div>
        )}
      </section>
      <Panel
        title="Event register"
        description={
          events.data
            ? `${number(events.data.total)} matching events · ${runId ? 'Selected run' : 'All runs'} · UTC`
            : 'Results reflect the current run scope and applied filters.'
        }
      >
        <ErrorNotice
          error={events.error}
          onRetry={events.reload}
          title="Events could not be loaded"
        />
        {events.loading && <LoadingState label="Loading events" />}
        {events.data &&
          (events.data.items.length ? (
            <EventTable events={events.data.items} />
          ) : (
            <EmptyState
              title={
                filters.active.length ? 'No events match these filters' : 'No events in this scope'
              }
              description={
                filters.active.length
                  ? 'Broaden the time range, remove an exact-match filter, or select a different run.'
                  : 'Import a telemetry file or replay an included dataset to begin an investigation.'
              }
              action={
                filters.active.length ? (
                  <Button onClick={filters.clear}>Clear filters</Button>
                ) : (
                  <LinkButton to={route('/replay', runId)}>Choose a replay dataset</LinkButton>
                )
              }
            />
          ))}
        {events.data && (
          <Pagination
            total={events.data.total}
            offset={events.data.offset}
            limit={events.data.limit}
            onChange={filters.paginate}
          />
        )}
      </Panel>
    </>
  );
}

export function EventDetailPage() {
  const { id = '' } = useParams();
  const { runId, revision } = useWorkspace();
  const event = useResource<NormalizedEvent>(`/events/${encodeURIComponent(id)}`, {
    refreshKey: revision,
  });
  return (
    <>
      <PageHeader
        title="Event evidence"
        description="The normalized record alongside its preserved raw input. All timestamps are UTC."
        actions={
          <LinkButton to={route('/events', event.data?.run_id || runId)}>Back to events</LinkButton>
        }
      />
      <ErrorNotice error={event.error} onRetry={event.reload} title="Event could not be loaded" />
      {event.loading && <LoadingState label="Loading event evidence" />}
      {event.data && (
        <Panel
          title={event.data.event.action}
          description={`Stored in isolated run ${event.data.run_id}`}
        >
          <EventRecord event={event.data} />
        </Panel>
      )}
    </>
  );
}
