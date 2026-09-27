import { number, utc } from '../services/format';
import type { Dashboard } from '../types';
import { Table, Time } from './ui';

export function ActivityChart({ data }: { data: Dashboard['timeline'] }) {
  const width = 1000;
  const height = 186;
  const left = 0;
  const right = 0;
  const top = 14;
  const bottom = 14;
  const chartHeight = height - top - bottom;
  const chartWidth = width - left - right;
  const max = Math.max(1, ...data.map((point) => Math.max(point.events, point.alerts)));
  const slot = chartWidth / Math.max(data.length, 1);
  const barWidth = Math.max(1, Math.min(28, slot * 0.55));
  const x = (index: number) => left + slot * (index + 0.5);
  const y = (value: number) => top + chartHeight - (value / max) * chartHeight;
  const alertPoints = data.map((point, index) => `${x(index)},${y(point.alerts)}`).join(' ');
  const axisIndices = [...new Set([0, Math.floor((data.length - 1) / 2), data.length - 1])];

  return (
    <div className="activity-chart">
      <div className="chart-legend" aria-hidden="true">
        <span>
          <i className="legend-event" />
          Events
        </span>
        <span>
          <i className="legend-alert" />
          Alerts
        </span>
        <span className="muted">Counts per interval · UTC</span>
      </div>
      <div className="chart-plot">
        <div className="chart-y-labels" aria-hidden="true">
          <span>{number(max)}</span>
          <span>{number(max / 2)}</span>
          <span>0</span>
        </div>
        <svg
          viewBox={`0 0 ${width} ${height}`}
          preserveAspectRatio="none"
          role="img"
          aria-label="Event and alert counts over time. Exact values are available in the activity data table below."
        >
          {[0, 0.5, 1].map((fraction) => (
            <g key={fraction}>
              <line
                className="chart-grid"
                x1={left}
                x2={width - right}
                y1={y(max * fraction)}
                y2={y(max * fraction)}
              />
            </g>
          ))}
          {data.map((point, index) => (
            <rect
              className="event-bar"
              key={point.timestamp}
              x={x(index) - barWidth / 2}
              y={y(point.events)}
              width={barWidth}
              height={(point.events / max) * chartHeight}
              rx={1}
            >
              <title>
                {utc(point.timestamp)} UTC: {point.events} events, {point.alerts} alerts
              </title>
            </rect>
          ))}
          {data.length > 1 && <polyline className="alert-line" points={alertPoints} />}
          {data.map((point, index) =>
            point.alerts > 0 ? (
              <circle
                key={point.timestamp}
                className="alert-point"
                cx={x(index)}
                cy={y(point.alerts)}
                r={3}
              >
                <title>
                  {utc(point.timestamp)} UTC: {point.alerts} alerts
                </title>
              </circle>
            ) : null,
          )}
        </svg>
      </div>
      <div className="chart-x-labels" aria-hidden="true">
        {axisIndices.map((index) => (
          <span key={index}>{utc(data[index]?.timestamp, true)}</span>
        ))}
      </div>
      <div className="chart-range mono">
        {utc(data[0]?.timestamp)} — {utc(data[data.length - 1]?.timestamp)} UTC
      </div>
      <details className="chart-data disclosure">
        <summary>View exact activity data</summary>
        <Table caption="Activity data">
          <thead>
            <tr>
              <th scope="col">Interval (UTC)</th>
              <th scope="col">Events</th>
              <th scope="col">Alerts</th>
            </tr>
          </thead>
          <tbody>
            {data.map((point) => (
              <tr key={point.timestamp}>
                <td>
                  <Time value={point.timestamp} />
                </td>
                <td>{number(point.events)}</td>
                <td>{number(point.alerts)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </details>
    </div>
  );
}
