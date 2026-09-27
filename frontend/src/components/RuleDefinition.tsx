import type { RuleSnapshot } from '../types';
import { duration, number } from '../services/format';
import { MitreTags, Provenance } from './Provenance';
import { CodeBlock, Fact, Notice, SeverityBadge } from './ui';

export function RuleDefinition({
  rule,
  snapshot = false,
}: {
  rule: RuleSnapshot;
  snapshot?: boolean;
}) {
  return (
    <div className="rule-definition">
      <div className="definition-heading">
        <div>
          <span className="mono muted">{rule.id}</span>
          <h3>{rule.name}</h3>
        </div>
        <SeverityBadge severity={rule.severity} />
      </div>
      <p className="reading-text">{rule.description}</p>
      <dl className="facts facts-grid rule-facts">
        <Fact term="Threshold">
          {number(rule.threshold.count)} {rule.threshold.count === 1 ? 'event' : 'events'}
        </Fact>
        <Fact term="Window">{duration(rule.threshold.window_seconds)}</Fact>
        <Fact term="Group by">
          <span className="mono">{rule.group_by.join(', ') || 'Ungrouped'}</span>
        </Fact>
        <Fact term="Suppression">{duration(rule.suppression_seconds)}</Fact>
        <Fact term={snapshot ? 'Enabled in snapshot' : 'Enabled for new runs'}>
          {rule.enabled ? 'Yes' : 'No'}
        </Fact>
        <Fact term="MITRE ATT&CK">
          <MitreTags techniques={rule.mitre_attack} />
        </Fact>
      </dl>
      <section className="definition-section">
        <h3>Match criteria</h3>
        <CodeBlock value={rule.conditions} label="Rule conditions" />
        {rule.branches.length > 0 && <CodeBlock value={rule.branches} label="Detection branches" />}
      </section>
      <section className="definition-section">
        <h3>Investigation considerations</h3>
        {rule.false_positives.length > 0 && (
          <ul className="prose-list">
            {rule.false_positives.map((item, index) => (
              <li key={`${index}-${item}`}>{item}</li>
            ))}
          </ul>
        )}
        <Notice>
          Matching indicators are a starting point for investigation, not proof of compromise.
          Included benign fixtures do not estimate enterprise false-positive rates.
        </Notice>
      </section>
      <section className="definition-section">
        <h3>Provenance & attribution</h3>
        <Provenance value={rule.provenance} />
      </section>
      <details className="disclosure">
        <summary>
          {rule.yaml
            ? snapshot
              ? 'Pinned internal YAML'
              : 'Internal rule YAML'
            : 'Pinned internal definition (JSON)'}
        </summary>
        {!rule.yaml && (
          <p className="form-note">
            The backend returned this definition as canonical JSON, without YAML text.
          </p>
        )}
        <CodeBlock
          value={rule.yaml ?? rule}
          label={
            rule.yaml
              ? snapshot
                ? 'Rule snapshot YAML'
                : 'Internal rule YAML'
              : 'Pinned rule definition JSON'
          }
        />
      </details>
      {rule.provenance.original_yaml && (
        <details className="disclosure">
          <summary>Original Sigma source</summary>
          <CodeBlock value={rule.provenance.original_yaml} label="Original Sigma YAML" />
        </details>
      )}
    </div>
  );
}
