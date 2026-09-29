import { Link } from 'react-router-dom';
import { label } from '../services/format';
import type { Delivery } from '../types/integrations';
import { Badge, EmptyState, StatusBadge, Table, Time } from './ui';

export function DeliveryTable({
  deliveries,
  names = {},
}: {
  deliveries: Delivery[];
  names?: Record<string, string>;
}) {
  if (!deliveries.length)
    return (
      <EmptyState
        title="No notification deliveries"
        description="Alerts remain available even when no notification rule or destination is configured."
      />
    );
  return (
    <Table caption="Notification delivery history">
      <thead>
        <tr>
          <th scope="col">Alert / event</th>
          <th scope="col">Destination</th>
          <th scope="col">Delivery state</th>
          <th scope="col">Attempts</th>
          <th scope="col">Last attempt (UTC)</th>
        </tr>
      </thead>
      <tbody>
        {deliveries.map((delivery) => (
          <tr key={delivery.id}>
            <td>
              {delivery.alert_id ? (
                <Link className="mono" to={`/alerts/${delivery.alert_id}`}>
                  {delivery.alert_id.slice(0, 12)}
                </Link>
              ) : (
                'Notification test'
              )}
              <span className="cell-secondary">
                {delivery.event === 'notification_test'
                  ? 'Not a security incident'
                  : 'Security alert'}
              </span>
            </td>
            <td>
              {names[delivery.destination_id] || delivery.destination_id}
              {delivery.mock && (
                <span className="cell-secondary">
                  <Badge>Mock delivery</Badge>
                </span>
              )}
            </td>
            <td>
              <Link to={`/notifications/${delivery.id}`}>
                <StatusBadge status={delivery.status} />
              </Link>
              {delivery.http_status && (
                <span className="cell-secondary">HTTP {delivery.http_status}</span>
              )}
              {delivery.error && <span className="cell-secondary">{label(delivery.error)}</span>}
              {delivery.next_attempt_at && (
                <span className="cell-secondary">
                  Retry <Time value={new Date(delivery.next_attempt_at * 1000).toISOString()} />
                </span>
              )}
            </td>
            <td className="mono">{delivery.attempt_count}</td>
            <td>
              {delivery.last_attempt_at ? (
                <Time value={delivery.last_attempt_at} />
              ) : (
                'Not attempted'
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
