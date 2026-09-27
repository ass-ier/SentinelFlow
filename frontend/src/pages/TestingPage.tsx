import { useState } from 'react';
import { FlaskConical } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import { DatasetSelect, DatasetSummary } from '../components/DatasetFields';
import { ValidationReportView } from '../components/ValidationReport';
import {
  Button,
  ErrorNotice,
  LoadingState,
  Notice,
  PageHeader,
  Panel,
  SelectField,
} from '../components/ui';
import { useResource } from '../hooks/useResource';
import { useWorkspace } from '../hooks/workspace';
import { api } from '../services/api';
import type { Collection, Dataset, Rule, ValidationReport } from '../types';

export function TestingPage() {
  const { revision } = useWorkspace();
  const [params] = useSearchParams();
  const datasets = useResource<Collection<Dataset>>('/datasets', { refreshKey: revision });
  const rules = useResource<Collection<Rule>>('/rules', { refreshKey: revision });
  const [datasetId, setDatasetId] = useState(params.get('dataset_id') || '');
  const [ruleId, setRuleId] = useState(params.get('rule_id') || '');
  const [scope, setScope] = useState<'bundled' | 'current'>('bundled');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [report, setReport] = useState<ValidationReport | null>(null);
  const selected = datasets.data?.items.find((dataset) => dataset.id === datasetId);
  async function run() {
    setPending(true);
    setError(null);
    setReport(null);
    try {
      const result = await api<ValidationReport>('/detections/validate', {
        method: 'POST',
        body: {
          scope,
          ...(datasetId ? { dataset_id: datasetId } : {}),
          ...(ruleId ? { rule_id: ruleId } : {}),
        },
      });
      setReport(result);
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  return (
    <>
      <PageHeader
        title="Detection testing"
        description="Assert expected behavior against included datasets. Keep observations separate from passing assertions."
      />
      <Notice>
        Validation is isolated: it does not ingest events or create alerts in your investigation
        runs. Counts below are returned by real execution.
      </Notice>
      <Panel
        title="Validation workbench"
        description="Run the included baseline or compare current operational definitions against saved expectations."
      >
        <ErrorNotice
          error={datasets.error}
          onRetry={datasets.reload}
          title="Dataset manifest unavailable"
        />
        <ErrorNotice error={rules.error} onRetry={rules.reload} title="Rule catalog unavailable" />
        {(datasets.loading || rules.loading) && <LoadingState label="Loading validation inputs" />}
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void run();
          }}
          className="workbench-form"
        >
          <div className="form-grid testing-grid">
            <DatasetSelect
              datasets={datasets.data?.items ?? []}
              value={datasetId}
              onChange={(value) => {
                setDatasetId(value);
                setReport(null);
              }}
              disabled={pending || datasets.loading}
              allowAll
            />
            <SelectField
              label="Detection"
              value={ruleId}
              onChange={(event) => {
                setRuleId(event.target.value);
                setReport(null);
              }}
              disabled={pending || rules.loading}
            >
              <option value="">All definitions</option>
              {rules.data?.items.map((rule) => (
                <option key={rule.id} value={rule.id}>
                  {rule.id} · {rule.name}
                </option>
              ))}
            </SelectField>
            <SelectField
              label="Definition scope"
              value={scope}
              onChange={(event) => {
                setScope(event.target.value as 'bundled' | 'current');
                setReport(null);
              }}
              disabled={pending}
            >
              <option value="bundled">Bundled baseline</option>
              <option value="current">Current operational rules</option>
            </SelectField>
          </div>
          <p className="scope-note">
            {scope === 'bundled'
              ? 'Bundled baseline validates the included immutable definitions independently of operational enable/disable changes.'
              : 'Current scope evaluates today’s changed or disabled rules against saved expectations. Differences can correctly cause FAIL.'}
          </p>
          {selected && <DatasetSummary dataset={selected} />}
          <ErrorNotice error={error} title="Validation could not run" />
          <div className="form-actions split-actions">
            <p className="form-note">
              Controlled benign scenarios are included. Passing them is not a claim of zero
              real-world false positives.
            </p>
            <Button
              variant="primary"
              type="submit"
              disabled={
                pending || datasets.loading || rules.loading || !!datasets.error || !!rules.error
              }
            >
              <FlaskConical size={15} aria-hidden="true" />
              {pending ? 'Running validation…' : 'Run validation'}
            </Button>
          </div>
          {pending && (
            <p role="status">
              Executing validation scenarios. Results will appear when execution completes.
            </p>
          )}
        </form>
      </Panel>
      {report && <ValidationReportView report={report} />}
      {!report && !pending && (
        <div className="workbench-empty">
          <h2>No validation result yet</h2>
          <p>
            Choose a dataset and detection, or run the full included baseline. PASS, FAIL, and
            OBSERVED are derived only from the API response.
          </p>
        </div>
      )}
    </>
  );
}
