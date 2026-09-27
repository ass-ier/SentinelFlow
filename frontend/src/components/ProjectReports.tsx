import { label, number } from '../services/format';
import type { BenchmarkArtifact, TestCounts, ValidationArtifact } from '../types';
import { Badge, CodeBlock, ErrorNotice, Fact, Notice, StatusBadge, Table, Time } from './ui';

export function ArtifactStatus({ status, current }: { status: string; current: boolean }) {
  return !current || status === 'stale' ? (
    <Badge tone="warning">Stale artifact</Badge>
  ) : (
    <StatusBadge status={status} />
  );
}

function CountTable({
  rows,
  caption,
}: {
  rows: [string, TestCounts | undefined][];
  caption: string;
}) {
  return (
    <Table caption={caption}>
      <thead>
        <tr>
          <th scope="col">Executed suite</th>
          <th scope="col">Passed</th>
          <th scope="col">Failed</th>
          <th scope="col">Total</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(([name, counts]) => (
          <tr key={name}>
            <th scope="row">{name}</th>
            {counts ? (
              <>
                <td className="mono">{number(counts.passed)}</td>
                <td className="mono">{number(counts.failed)}</td>
                <td className="mono">{number(counts.total)}</td>
              </>
            ) : (
              <td colSpan={3} className="muted">
                Not recorded
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function commandText(command: string | string[]): string {
  return Array.isArray(command)
    ? command
        .map((argument) => (/\s/.test(argument) ? JSON.stringify(argument) : argument))
        .join(' ')
    : command;
}

export function ComprehensiveReport({ report }: { report: ValidationArtifact }) {
  const current = report.is_current && report.status !== 'stale';
  const categories = Object.entries(report.backend?.categories ?? {});
  return (
    <>
      {!current && (
        <Notice tone="warning">
          This saved validation is stale for the current sources. Its recorded results remain
          available, but do not validate today’s workspace. Run <code>make validate</code> again.
        </Notice>
      )}
      {report.error && (
        <ErrorNotice error={new Error(report.error)} title="Recorded validation failure" />
      )}
      <dl className="facts facts-grid artifact-facts">
        <Fact term="Total unique tests passed">
          {report.total_tests_passed === undefined
            ? 'Not recorded'
            : number(report.total_tests_passed)}
        </Fact>
        <Fact term="Backend coverage">
          {report.backend?.coverage_percent === undefined
            ? 'Not recorded'
            : `${number(report.backend.coverage_percent)}%`}
        </Fact>
        <Fact term="Controlled benign passed / total">
          {report.detections
            ? `${number(report.detections.benign_passed)} / ${number(report.detections.benign_total)}`
            : 'Not recorded'}
        </Fact>
        <Fact term="Started (UTC)">
          <Time value={report.started_at} />
        </Fact>
        <Fact term="Completed (UTC)">
          <Time value={report.completed_at} />
        </Fact>
        <Fact term="Measured duration">
          {report.duration_seconds === undefined
            ? 'Not recorded'
            : `${number(report.duration_seconds)} s`}
        </Fact>
      </dl>
      <CountTable
        caption="Comprehensive validation counts"
        rows={[
          ['Backend tests', report.backend],
          ['Frontend tests', report.frontend],
          ['Detection scenarios', report.detections],
        ]}
      />
      <p className="scope-note">
        Unique test totals count backend and frontend cases. Detection scenarios are separate;
        benign cases and backend categories are subsets, not additional unique tests.
      </p>
      <details className="disclosure" open={report.status === 'failed'}>
        <summary>Executed validation steps</summary>
        {report.steps.length ? (
          <Table caption="Executed validation steps" className="validation-step-table">
            <thead>
              <tr>
                <th scope="col">Step</th>
                <th scope="col">Recorded command</th>
                <th scope="col">Result</th>
                <th scope="col">Exit code</th>
                <th scope="col">Measured duration</th>
              </tr>
            </thead>
            <tbody>
              {report.steps.map((step, index) => (
                <tr key={`${index}-${step.name}`}>
                  <td>{step.name}</td>
                  <td>
                    <code>{commandText(step.command)}</code>
                  </td>
                  <td>
                    <StatusBadge status={step.status} />
                  </td>
                  <td className="mono">{step.exit_code}</td>
                  <td className="mono">{number(step.duration_seconds)} s</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <p className="muted">No executed steps were recorded.</p>
        )}
      </details>
      {categories.length > 0 && (
        <details className="disclosure">
          <summary>Backend test categories — overlapping subsets</summary>
          <CountTable
            caption="Backend test categories"
            rows={categories.map(([name, counts]) => [label(name), counts])}
          />
        </details>
      )}
      <details className="disclosure">
        <summary>Complete executed validation report & source fingerprint</summary>
        <p className="form-note">
          {current
            ? 'Source fingerprint matches the current workspace.'
            : 'Source freshness was not confirmed for this artifact.'}
        </p>
        <p className="mono break-all">{report.source_fingerprint}</p>
        <CodeBlock value={report} label="Recorded validation JSON" />
      </details>
    </>
  );
}

export function BenchmarkReport({ report }: { report: BenchmarkArtifact }) {
  return (
    <>
      {(!report.is_current || report.status === 'stale') && (
        <Notice tone="warning">
          This benchmark is stale for the current sources. Re-run the benchmark to measure the
          current implementation; the saved values below are historical measurements.
        </Notice>
      )}
      <dl className="facts facts-grid artifact-facts">
        <Fact term="Events processed">{number(report.events_processed)}</Fact>
        <Fact term="Events per second">{number(report.events_per_second)}</Fact>
        <Fact term="Detection time">{number(report.detection_seconds)} s</Fact>
        <Fact term="Alerts generated">{number(report.alerts_generated)}</Fact>
        <Fact term="Rules evaluated">{number(report.rules_evaluated)}</Fact>
        <Fact term="Active rules">{number(report.active_rules)}</Fact>
        <Fact term="Measured at (UTC)">
          <Time value={report.measured_at} />
        </Fact>
        <Fact term="Measurement scope">{report.scope}</Fact>
      </dl>
      <details className="disclosure">
        <summary>Complete benchmark measurements</summary>
        <CodeBlock value={report} label="Recorded benchmark JSON" />
      </details>
    </>
  );
}
