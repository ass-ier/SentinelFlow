import { Fragment, useId, useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { route } from '../services/api';
import type { InlineEvent, NormalizedEvent } from '../types';
import { CodeBlock, Fact, IconButton, SeverityBadge, StatusBadge, Table, Time } from './ui';

export function EventRecord({
  event,
  runId,
}: {
  event: NormalizedEvent | InlineEvent;
  runId?: string;
}) {
  return (
    <div className="event-record">
      <dl className="facts facts-grid">
        <Fact term="Event ID">
          <span className="mono">{event.event.id}</span>
        </Fact>
        <Fact term="Storage ID">
          {'storage_id' in event ? (
            <span className="mono">{event.storage_id}</span>
          ) : (
            'Not persisted — isolated validation'
          )}
        </Fact>
        <Fact term="Run">
          <span className="mono">
            {'run_id' in event ? event.run_id : runId || 'Isolated validation'}
          </span>
        </Fact>
        <Fact term="Timestamp (UTC)">
          <Time value={event.event.timestamp} />
        </Fact>
        <Fact term="Source">{event.event.source}</Fact>
        {typeof event.metadata.provider === 'string' && (
          <Fact term="Telemetry provider">{event.metadata.provider}</Fact>
        )}
        {typeof event.metadata.connector_id === 'string' && (
          <Fact term="Connector ID">{event.metadata.connector_id}</Fact>
        )}
        {typeof event.metadata.source_table === 'string' && (
          <Fact term="Source table">{event.metadata.source_table}</Fact>
        )}
        {typeof event.metadata.source_channel === 'string' && (
          <Fact term="Source channel">{event.metadata.source_channel}</Fact>
        )}
        {typeof event.metadata.ingested_at === 'string' && (
          <Fact term="Ingested (UTC)">
            <Time value={event.metadata.ingested_at} />
          </Fact>
        )}
        <Fact term="Category / type">
          {event.event.category} / {event.event.type}
        </Fact>
        <Fact term="Action">{event.event.action}</Fact>
        <Fact term="Outcome">
          <StatusBadge status={event.event.outcome} />
        </Fact>
        <Fact term="Severity">
          <SeverityBadge severity={event.event.severity} />
        </Fact>
        <Fact term="Host">
          {event.host.name || '—'}
          {event.host.ip && ` · ${event.host.ip}`}
        </Fact>
        <Fact term="User">{event.user.name}</Fact>
        <Fact term="Source IP / port">
          <span className="mono">
            {event.source.ip || '—'}
            {event.source.port !== null && `:${event.source.port}`}
          </span>
        </Fact>
        <Fact term="Destination IP / port">
          <span className="mono">
            {event.destination.ip || '—'}
            {event.destination.port !== null && `:${event.destination.port}`}
          </span>
        </Fact>
        <Fact term="Process">
          {event.process.name || '—'}
          {event.process.pid !== null && ` · PID ${event.process.pid}`}
        </Fact>
        {event.process.executable && (
          <Fact term="Process executable (full path)">
            <span className="mono">{event.process.executable}</span>
          </Fact>
        )}
        <Fact term="Parent process">
          {event.process.parent.name || '—'}
          {event.process.parent.pid !== null && ` · PID ${event.process.parent.pid}`}
        </Fact>
        {event.process.parent.executable && (
          <Fact term="Parent executable (full path)">
            <span className="mono">{event.process.parent.executable}</span>
          </Fact>
        )}
        <Fact term="Protocol">{event.network.protocol}</Fact>
        {event.dns.query && (
          <Fact term="DNS query">
            <span className="mono">{event.dns.query}</span>
          </Fact>
        )}
        {event.file.path && (
          <Fact term="File path">
            <span className="mono">{event.file.path}</span>
          </Fact>
        )}
      </dl>
      {event.process.command_line && (
        <CodeBlock value={event.process.command_line} label="Process command line — inert text" />
      )}
      <CodeBlock value={event.raw_event} label={`Raw event ${event.event.id}`} />
      <details className="disclosure">
        <summary>Complete normalized event &amp; metadata</summary>
        <CodeBlock value={event} label="Normalized event JSON" />
      </details>
    </div>
  );
}

export function EventTable({
  events,
  caption = 'Events',
  compact = false,
  isolated = false,
  runId,
}: {
  events: (NormalizedEvent | InlineEvent)[];
  caption?: string;
  compact?: boolean;
  isolated?: boolean;
  runId?: string;
}) {
  const tableId = useId();
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const toggle = (id: string) => {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  return (
    <Table caption={caption} className="event-table">
      <thead>
        <tr>
          <th scope="col">
            <span className="sr-only">Raw evidence</span>
          </th>
          <th scope="col">
            Timestamp <span className="column-unit">UTC</span>
          </th>
          <th scope="col">Event</th>
          <th scope="col">Source IP</th>
          {!compact && <th scope="col">Host / user</th>}
          <th scope="col">Outcome</th>
          {!compact && <th scope="col">Severity</th>}
        </tr>
      </thead>
      <tbody>
        {events.map((event) => {
          const stored = 'storage_id' in event;
          const rowId = stored ? event.storage_id : event.event.id;
          const evidenceId = `event-${tableId}-${rowId}`;
          const isOpen = expanded.has(rowId);
          return (
            <Fragment key={rowId}>
              <tr className={isOpen ? 'is-expanded' : undefined}>
                <td className="expand-cell">
                  <IconButton
                    label={`${isOpen ? 'Hide' : 'Show'} raw event ${event.event.id}`}
                    aria-expanded={isOpen}
                    aria-controls={evidenceId}
                    onClick={() => toggle(rowId)}
                  >
                    {isOpen ? (
                      <ChevronDown size={16} aria-hidden="true" />
                    ) : (
                      <ChevronRight size={16} aria-hidden="true" />
                    )}
                  </IconButton>
                </td>
                <td>
                  {stored && !isolated ? (
                    <Link
                      to={route(`/events/${encodeURIComponent(event.storage_id)}`, event.run_id)}
                    >
                      <Time value={event.event.timestamp} />
                    </Link>
                  ) : (
                    <Time value={event.event.timestamp} />
                  )}
                </td>
                <td>
                  <span className="cell-primary">{event.event.action}</span>
                  <span className="cell-secondary">
                    {event.event.category} · {event.event.type}
                  </span>
                </td>
                <td className="mono">{event.source.ip || '—'}</td>
                {!compact && (
                  <td>
                    <span className="cell-primary">{event.host.name || '—'}</span>
                    <span className="cell-secondary">{event.user.name || 'No user'}</span>
                  </td>
                )}
                <td>
                  <StatusBadge status={event.event.outcome} />
                </td>
                {!compact && (
                  <td>
                    <SeverityBadge severity={event.event.severity} />
                  </td>
                )}
              </tr>
              {isOpen && (
                <tr className="evidence-row" id={evidenceId}>
                  <td colSpan={compact ? 5 : 7}>
                    <EventRecord event={event} runId={runId} />
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </tbody>
    </Table>
  );
}
