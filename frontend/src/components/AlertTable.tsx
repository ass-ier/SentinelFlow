import { Link } from 'react-router-dom';
import { ArrowUpRight } from 'lucide-react';
import { route } from '../services/api';
import { number } from '../services/format';
import type { Alert } from '../types';
import { SeverityBadge, StatusBadge, Table, Time } from './ui';

export function AlertTable({ alerts, compact = false }: { alerts: Alert[]; compact?: boolean }) {
  return (
    <Table caption="Alert register" className="alert-table">
      <thead>
        <tr>
          <th scope="col">Severity</th>
          <th scope="col">Detection / alert</th>
          <th scope="col">Source</th>
          {!compact && <th scope="col">Host / user</th>}
          <th scope="col">Evidence</th>
          <th scope="col">
            Triggered <span className="column-unit">UTC</span>
          </th>
          <th scope="col">Status</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map((alert) => (
          <tr key={alert.id}>
            <td>
              <SeverityBadge severity={alert.severity} />
            </td>
            <td>
              <Link
                className="cell-primary alert-link"
                to={route(`/alerts/${encodeURIComponent(alert.id)}`, alert.run_id)}
              >
                {alert.rule_name}
                <ArrowUpRight size={13} aria-hidden="true" />
              </Link>
              <span className="cell-secondary mono">
                <Link to={route(`/rules/${encodeURIComponent(alert.rule_id)}`, alert.run_id)}>
                  {alert.rule_id}
                </Link>
                {' · '}
                {alert.id}
              </span>
            </td>
            <td className="mono">{alert.source_entities.ips.join(', ') || '—'}</td>
            {!compact && (
              <td>
                <span className="cell-primary">
                  {alert.affected_entities.hosts.join(', ') || '—'}
                </span>
                <span className="cell-secondary">
                  {alert.affected_entities.users.join(', ') || 'No user'}
                </span>
              </td>
            )}
            <td>
              <span className="mono">{number(alert.event_count)}</span>{' '}
              <span className="muted">events</span>
            </td>
            <td>
              <Time value={alert.triggered_at} />
            </td>
            <td>
              <StatusBadge status={alert.status} />
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
