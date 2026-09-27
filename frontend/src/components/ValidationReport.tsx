import { useState } from 'react';
import { Download } from 'lucide-react';
import { downloadJson, duration, label, number } from '../services/format';
import type { Expected, ValidationReport as Report, ValidationResult } from '../types';
import { EventTable } from './EventEvidence';
import { MitreTags, Provenance } from './Provenance';
import {
  Badge,
  Button,
  CodeBlock,
  ErrorNotice,
  Fact,
  Notice,
  SeverityBadge,
  StatusBadge,
  Table,
  Time,
} from './ui';

function ExpectedTable({ values, title }: { values: Expected[] | null; title: string }) {
  return (
    <section className="expectation-column">
      <h4>
        {title}{' '}
        <span className="muted">{values === null ? 'Unknown' : `${values.length} alerts`}</span>
      </h4>
      {values === null ? (
        <p>No saved expectation. An observation is not a PASS.</p>
      ) : values.length === 0 ? (
        <p className="zero-expectation">0 alerts</p>
      ) : (
        <Table caption={title}>
          <thead>
            <tr>
              <th scope="col">Rule</th>
              <th scope="col">Severity</th>
              <th scope="col">Evidence</th>
              <th scope="col">Branch</th>
            </tr>
          </thead>
          <tbody>
            {values.map((value, index) => (
              <tr key={`${value.rule_id}-${value.branch}-${index}`}>
                <td className="mono">{value.rule_id}</td>
                <td>
                  <SeverityBadge severity={value.severity} />
                </td>
                <td>
                  {value.event_count === null
                    ? 'Not asserted'
                    : `${number(value.event_count)} events`}
                </td>
                <td>{value.branch || 'Default'}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  );
}

function Result({ result }: { result: ValidationResult }) {
  return (
    <details
      className={`validation-result result-${result.status}`}
      open={result.status !== 'passed'}
    >
      <summary>
        <StatusBadge status={result.status} />
        <div className="result-name">
          <strong>{result.name}</strong>
          <span className="mono">
            {result.test_id} · {result.dataset_id}
          </span>
        </div>
        <span className="result-counts">
          Expected {result.expected === null ? 'unknown' : result.expected.length}
          <span aria-hidden="true"> / </span>Actual {result.actual.length}
        </span>
        <Badge>{label(result.kind)}</Badge>
      </summary>
      <div className="result-detail">
        <dl className="facts facts-grid">
          <Fact term="Events processed">{number(result.events_processed)}</Fact>
          <Fact term="Duplicates ignored">{number(result.duplicates_ignored)}</Fact>
          <Fact term="Measured duration">{duration(result.duration_seconds)}</Fact>
        </dl>
        {result.kind === 'benign' && (
          <Notice>
            This is a controlled benign fixture. Its expected behavior is not an estimate of
            enterprise false-positive rates.
          </Notice>
        )}
        {result.expected === null && (
          <Notice tone="warning">
            OBSERVED: there is no saved expected result for this selection. Supply an expected alert
            count when testing a custom definition to make an assertion.
          </Notice>
        )}
        {result.errors.length > 0 && (
          <div className="notice notice-error" role="alert">
            <div>
              <strong>Validation differences</strong>
              <ul>
                {result.errors.map((error, index) => (
                  <li key={index}>{error}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
        <div className="expectation-grid">
          <ExpectedTable title="Expected detections" values={result.expected} />
          <ExpectedTable title="Observed detections" values={result.actual} />
        </div>
        {result.alerts.length > 0 && (
          <section className="isolated-alerts">
            <h4>Isolated test alerts</h4>
            <p className="muted">
              These alerts belong to this validation result, not the operational alert queue.
            </p>
            {result.alerts.map((alert) => (
              <details className="disclosure" key={alert.id}>
                <summary>
                  <SeverityBadge severity={alert.severity} /> {alert.rule_name} ·{' '}
                  {number(alert.event_count)} evidence events
                </summary>
                <dl className="facts facts-grid">
                  <Fact term="Rule">
                    <span className="mono">{alert.rule_id}</span>
                  </Fact>
                  <Fact term="Evidence count">{number(alert.event_count)}</Fact>
                  <Fact term="First evidence (UTC)">
                    <Time value={alert.first_seen} />
                  </Fact>
                  <Fact term="Last evidence (UTC)">
                    <Time value={alert.last_seen} />
                  </Fact>
                  <Fact term="Sources">
                    <span className="mono">
                      {alert.source_entities.ips.join(', ') || 'Not present'}
                    </span>
                  </Fact>
                  <Fact term="MITRE ATT&CK">
                    <MitreTags techniques={alert.mitre_attack} />
                  </Fact>
                </dl>
                <p>{alert.description}</p>
                <Provenance value={alert.provenance} />
                {alert.evidence.length > 0 && (
                  <section className="definition-section">
                    <h4>Inline triggering evidence</h4>
                    <p className="muted">
                      These records are included in this isolated report. Expand a row to inspect
                      raw input; no persistent event or alert links are created.
                    </p>
                    <EventTable
                      events={alert.evidence}
                      caption={`Isolated evidence for ${result.test_id} / ${alert.id}`}
                      isolated
                      runId={alert.run_id}
                    />
                  </section>
                )}
                <CodeBlock value={alert} label="Isolated alert JSON" />
              </details>
            ))}
          </section>
        )}
        <details className="disclosure">
          <summary>Measured execution metrics</summary>
          <CodeBlock value={result.metrics} label="Scenario metrics" />
        </details>
      </div>
    </details>
  );
}

export function ValidationReportView({ report }: { report: Report }) {
  const [failuresOnly, setFailuresOnly] = useState(false);
  const [downloadError, setDownloadError] = useState<unknown>(null);
  const results = failuresOnly
    ? report.results.filter((result) => result.status === 'failed')
    : report.results;
  return (
    <section className="validation-report" aria-label="Validation results">
      <div className="report-heading">
        <div>
          <h2>Validation results</h2>
          <p>
            Scope: <strong>{report.scope}</strong> · Measured duration{' '}
            {duration(report.duration_seconds)}
          </p>
        </div>
        <div className="report-actions">
          <StatusBadge status={report.status} />
          <Button
            onClick={() => {
              try {
                downloadJson(report, 'sentinelflow-validation.json');
                setDownloadError(null);
              } catch (error) {
                setDownloadError(error);
              }
            }}
          >
            <Download size={14} aria-hidden="true" />
            Download JSON
          </Button>
        </div>
      </div>
      <ErrorNotice error={downloadError} title="Report download failed" />
      <dl className="report-metrics">
        <div>
          <dt>Passed</dt>
          <dd>{number(report.passed)}</dd>
        </div>
        <div>
          <dt>Failed</dt>
          <dd>{number(report.failed)}</dd>
        </div>
        <div>
          <dt>Total scenarios</dt>
          <dd>{number(report.total)}</dd>
        </div>
        <div>
          <dt>Benign passed / total</dt>
          <dd>
            {number(report.benign_passed)} <span>/ {number(report.benign_total)}</span>
          </dd>
        </div>
      </dl>
      {report.status === 'observed' && (
        <Notice tone="warning">
          Observation only. Unknown expectations are never reported as passing validation.
        </Notice>
      )}
      <div className="result-toolbar">
        <p>
          {number(results.length)} scenario results shown. Expand a row for exact expected and
          observed detections.
        </p>
        <label className="checkbox-field">
          <input
            type="checkbox"
            checked={failuresOnly}
            onChange={(event) => setFailuresOnly(event.target.checked)}
          />
          Failures only
        </label>
      </div>
      <div className="result-list">
        {results.map((result) => (
          <Result key={result.test_id} result={result} />
        ))}
      </div>
      {!results.length && (
        <p className="panel-empty">
          {failuresOnly
            ? 'No failed scenarios in this report.'
            : 'The API returned no scenario results.'}
        </p>
      )}
    </section>
  );
}
