import { label, number } from '../services/format';
import type { Dataset } from '../types';
import { Badge, Fact, SelectField } from './ui';
import { ExternalLinkSafe } from './Provenance';

export function DatasetSelect({
  datasets,
  value,
  onChange,
  disabled,
  allowAll = false,
  label: fieldLabel = 'Dataset',
}: {
  datasets: Dataset[];
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  allowAll?: boolean;
  label?: string;
}) {
  const kinds = [...new Set(datasets.map((dataset) => dataset.kind))];
  return (
    <SelectField
      label={fieldLabel}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      disabled={disabled}
      required={!allowAll}
    >
      <option value="">{allowAll ? 'All included datasets' : 'Select a dataset…'}</option>
      {kinds.map((kind) => (
        <optgroup key={kind} label={label(kind)}>
          {datasets
            .filter((dataset) => dataset.kind === kind)
            .map((dataset) => (
              <option key={dataset.id} value={dataset.id}>
                {dataset.name} · {number(dataset.event_count)} events
              </option>
            ))}
        </optgroup>
      ))}
    </SelectField>
  );
}

export function DatasetSummary({ dataset }: { dataset: Dataset }) {
  return (
    <div className="dataset-summary">
      <div className="dataset-summary-heading">
        <span className="mono">{dataset.path}</span>
        <div className="tag-list">
          <Badge>{label(dataset.kind)}</Badge>
          <Badge>{dataset.synthetic ? 'Synthetic' : 'External sample'}</Badge>
        </div>
      </div>
      <dl className="facts facts-grid">
        <Fact term="Included events">{number(dataset.event_count)}</Fact>
        <Fact term="Format">{dataset.format.toUpperCase()}</Fact>
        <Fact term="Saved expectation">{number(dataset.expected.length)} alerts</Fact>
        <Fact term="License">{dataset.license || 'Not supplied'}</Fact>
        <Fact term="Source">
          <ExternalLinkSafe href={dataset.source}>
            {dataset.source || 'Not supplied'}
          </ExternalLinkSafe>
        </Fact>
      </dl>
      <details className="disclosure compact-disclosure">
        <summary>Dataset integrity</summary>
        <p className="mono break-all">SHA-256: {dataset.sha256}</p>
      </details>
    </div>
  );
}
