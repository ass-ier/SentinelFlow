import { useRef, useState } from 'react';
import { Braces, Check, Download, FlaskConical, Upload } from 'lucide-react';
import { DatasetSelect, DatasetSummary } from '../components/DatasetFields';
import { Provenance } from '../components/Provenance';
import { ValidationReportView } from '../components/ValidationReport';
import {
  Badge,
  Button,
  CodeBlock,
  ErrorNotice,
  LinkButton,
  LoadingState,
  Notice,
  PageHeader,
  Panel,
  SelectField,
  TextareaField,
  TextField,
} from '../components/ui';
import { useResource } from '../hooks/useResource';
import { useWorkspace } from '../hooks/workspace';
import { api, route } from '../services/api';
import { MAX_SIGMA_BYTES, readTextFile, validateContent } from '../services/format';
import type {
  Collection,
  Dataset,
  Rule,
  RuleSnapshot,
  SigmaSample,
  ValidationReport,
} from '../types';

interface SigmaSource {
  yaml: string;
  source_url: string;
  license: string;
  license_url: string;
}

export function SigmaPage() {
  const { runId, revision, refresh, publicDemo } = useWorkspace();
  const samples = useResource<{ items: SigmaSample[] }>('/sigma/samples', { refreshKey: revision });
  const datasets = useResource<Collection<Dataset>>('/datasets', { refreshKey: revision });
  const [sampleId, setSampleId] = useState('');
  const [loadedSample, setLoadedSample] = useState<SigmaSample | null>(null);
  const [source, setSource] = useState<SigmaSource>({
    yaml: '',
    source_url: '',
    license: '',
    license_url: '',
  });
  const [enabled, setEnabled] = useState(false);
  const [datasetId, setDatasetId] = useState('');
  const [expected, setExpected] = useState('');
  const [pending, setPending] = useState<'compile' | 'import' | 'test' | 'file' | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [compiled, setCompiled] = useState<{ rule: RuleSnapshot; warnings: string[] } | null>(null);
  const [imported, setImported] = useState<Rule | null>(null);
  const [report, setReport] = useState<ValidationReport | null>(null);
  const readVersion = useRef(0);
  const selectedDataset = datasets.data?.items.find((dataset) => dataset.id === datasetId);

  function clearResults() {
    setCompiled(null);
    setImported(null);
    setReport(null);
    setError(null);
  }
  function edit(key: keyof SigmaSource, value: string) {
    setSource((previous) => ({ ...previous, [key]: value }));
    clearResults();
  }
  function loadSample() {
    const sample = samples.data?.items.find((item) => item.id === sampleId);
    if (!sample) return;
    setSource({
      yaml: sample.yaml,
      source_url: sample.source_url,
      license: sample.license,
      license_url: sample.license_url,
    });
    setLoadedSample(sample);
    setDatasetId(sample.dataset_id);
    setExpected(String(sample.expected_alerts));
    setEnabled(false);
    clearResults();
  }
  async function readFile(file: File | undefined) {
    if (!file) return;
    const version = ++readVersion.current;
    setPending('file');
    clearResults();
    try {
      const yaml = await readTextFile(file, ['.yml', '.yaml'], MAX_SIGMA_BYTES);
      if (version === readVersion.current) {
        setSource({ yaml, source_url: '', license: '', license_url: '' });
        setLoadedSample(null);
        setDatasetId('');
        setExpected('');
      }
    } catch (failure) {
      if (version === readVersion.current) setError(failure);
    } finally {
      if (version === readVersion.current) setPending(null);
    }
  }
  async function execute(action: 'compile' | 'import' | 'test') {
    setPending(action);
    setError(null);
    if (action === 'test') setReport(null);
    if (action === 'compile') setCompiled(null);
    if (action === 'import') setImported(null);
    try {
      validateContent(source.yaml, MAX_SIGMA_BYTES);
      const body = Object.fromEntries(
        Object.entries(source).filter(([, value]) => value.trim() !== ''),
      );
      if (action === 'compile') {
        setCompiled(
          await api<{ rule: RuleSnapshot; warnings: string[] }>('/sigma/compile', {
            method: 'POST',
            body,
          }),
        );
      } else if (action === 'import') {
        setImported(
          await api<Rule>('/sigma/import', { method: 'POST', body: { ...body, enabled } }),
        );
        refresh();
      } else {
        setReport(
          await api<ValidationReport>('/sigma/test', {
            method: 'POST',
            body: { ...body, dataset_id: datasetId, expected_alerts: Number(expected) },
          }),
        );
      }
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(null);
    }
  }
  return (
    <>
      <PageHeader
        title="Sigma workbench"
        description="Compile a documented subset, preserve attribution, and validate the actual translated definition."
      />
      <Notice>
        Limited Sigma compatibility, not a full Sigma backend. Unsupported features are rejected
        explicitly rather than silently reinterpreted.
      </Notice>
      <Panel
        title="Sigma source"
        description={
          publicDemo
            ? 'Load a pinned, licensed sample. Public compilation and testing accept only the unchanged bundled sources.'
            : 'Load a pinned, redistributable sample or provide your own rule and provenance.'
        }
      >
        <ErrorNotice
          error={samples.error}
          onRetry={samples.reload}
          title="Sigma samples unavailable"
        />
        {samples.loading && <LoadingState label="Loading pinned Sigma samples" />}
        <div className="sigma-source-tools">
          <SelectField
            label="Pinned sample"
            value={sampleId}
            onChange={(event) => setSampleId(event.target.value)}
            disabled={!!pending}
          >
            <option value="">Choose a sample…</option>
            {samples.data?.items.map((sample) => (
              <option key={sample.id} value={sample.id}>
                {sample.name} · {sample.author}
              </option>
            ))}
          </SelectField>
          <Button onClick={loadSample} disabled={!!pending || !sampleId}>
            <Download size={14} aria-hidden="true" />
            Load sample
          </Button>
          {!publicDemo && (
            <TextField
              label="Upload Sigma YAML"
              type="file"
              accept=".yml,.yaml"
              onChange={(event) => void readFile(event.target.files?.[0])}
              disabled={!!pending}
              hint="Maximum 64 KiB. YAML is sent to the safe backend compiler."
            />
          )}
        </div>
        {loadedSample && (
          <p className="sample-attribution">
            Loaded sample by <strong>{loadedSample.author}</strong> · {loadedSample.license}.
            Original attribution remains in the source and compiled rule.
          </p>
        )}
        <TextareaField
          label="Sigma YAML"
          hint={
            publicDemo
              ? 'Read-only pinned source. Its attribution and license are preserved.'
              : 'Maximum 64 KiB of UTF-8 source, for pasted or uploaded YAML.'
          }
          value={source.yaml}
          onChange={(event) => edit('yaml', event.target.value)}
          rows={17}
          className="code-input sigma-editor"
          spellCheck={false}
          disabled={!!pending}
          readOnly={publicDemo}
          placeholder={
            publicDemo
              ? 'Load a pinned sample above.'
              : 'Paste a supported Sigma rule, or load a pinned sample above.'
          }
        />
        <div className="form-grid sigma-provenance-fields">
          <TextField
            label="Source URL"
            type="url"
            value={source.source_url}
            onChange={(event) => edit('source_url', event.target.value)}
            disabled={!!pending}
            readOnly={publicDemo}
            placeholder="https://…"
          />
          <TextField
            label="License"
            value={source.license}
            onChange={(event) => edit('license', event.target.value)}
            disabled={!!pending}
            readOnly={publicDemo}
            placeholder="Preserve the original license"
          />
          <TextField
            label="License URL"
            type="url"
            value={source.license_url}
            onChange={(event) => edit('license_url', event.target.value)}
            disabled={!!pending}
            readOnly={publicDemo}
            placeholder="https://…"
          />
        </div>
        <div className="sigma-actions">
          <Button
            variant="primary"
            disabled={!!pending || !source.yaml.trim()}
            onClick={() => void execute('compile')}
          >
            <Braces size={15} aria-hidden="true" />
            {pending === 'compile' ? 'Compiling…' : 'Compile rule'}
          </Button>
          {!publicDemo && (
            <Button
              disabled={!!pending || !source.yaml.trim()}
              onClick={() => void execute('import')}
            >
              <Upload size={15} aria-hidden="true" />
              {pending === 'import'
                ? 'Importing…'
                : enabled
                  ? 'Import enabled rule'
                  : 'Import disabled rule'}
            </Button>
          )}
          {!publicDemo && (
            <label className="checkbox-field">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(event) => setEnabled(event.target.checked)}
                disabled={!!pending}
              />
              Enable for future runs on import
            </label>
          )}
        </div>
        <p className="form-note">
          {publicDemo
            ? 'Compilation and tests are isolated. Importing or editing rules is unavailable in this shared demo.'
            : 'Imported rules are disabled unless you explicitly enable them. Compilation alone does not add a rule to the catalog.'}
        </p>
        <ErrorNotice error={error} title="Sigma operation not completed" />
        {pending && (
          <p role="status">
            {pending === 'file'
              ? 'Reading YAML text…'
              : `Executing Sigma ${pending} on the backend…`}
          </p>
        )}
      </Panel>
      {imported && (
        <Panel
          title="Imported rule"
          description="This definition is now saved in the operational catalog."
          actions={
            <Badge tone={imported.enabled ? 'warning' : 'neutral'}>
              {imported.enabled ? 'Enabled for new runs' : 'Disabled by default'}
            </Badge>
          }
        >
          <div className="imported-rule">
            <Check size={18} aria-hidden="true" />
            <strong>{imported.name}</strong>
            <LinkButton to={route(`/rules/${encodeURIComponent(imported.id)}`, runId)}>
              Inspect imported rule
            </LinkButton>
          </div>
          <Provenance value={imported.provenance} />
        </Panel>
      )}
      {compiled && (
        <Panel
          title="Compilation result"
          description="Compiled only. This is the backend’s internal representation, not proof that the rule detects your data."
          actions={<Badge tone="success">Compiled</Badge>}
        >
          <Provenance value={compiled.rule.provenance} />
          {compiled.warnings.map((warning, index) => (
            <Notice key={index} tone="warning">
              {warning}
            </Notice>
          ))}
          <CodeBlock
            value={compiled.rule.yaml ?? compiled.rule}
            label={compiled.rule.yaml ? 'Compiled internal YAML' : 'Compiled rule JSON'}
          />
          {compiled.rule.yaml && (
            <details className="disclosure">
              <summary>Compiled rule JSON</summary>
              <CodeBlock value={compiled.rule} label="Compiled rule JSON" />
            </details>
          )}
        </Panel>
      )}
      <Panel
        title="Validate this Sigma source"
        description="Run the current YAML as an isolated test. Importing or enabling it is not required."
      >
        <ErrorNotice
          error={datasets.error}
          onRetry={datasets.reload}
          title="Sigma test datasets unavailable"
        />
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void execute('test');
          }}
          className="workbench-form"
        >
          {loadedSample && (
            <div className="fixture-shortcuts">
              <span className="muted">Sample fixtures:</span>
              <Button
                onClick={() => {
                  setDatasetId(loadedSample.dataset_id);
                  setExpected(String(loadedSample.expected_alerts));
                  setReport(null);
                }}
                disabled={!!pending}
              >
                Use positive fixture
              </Button>
              <Button
                onClick={() => {
                  setDatasetId(loadedSample.negative_dataset_id);
                  setExpected('0');
                  setReport(null);
                }}
                disabled={!!pending}
              >
                Use negative fixture
              </Button>
            </div>
          )}
          <div className="form-grid">
            <DatasetSelect
              datasets={datasets.data?.items ?? []}
              value={datasetId}
              onChange={(value) => {
                setDatasetId(value);
                setReport(null);
              }}
              disabled={!!pending || datasets.loading}
              label="Sigma test dataset"
            />
            <TextField
              label="Expected alert count"
              type="number"
              min={0}
              step={1}
              required
              value={expected}
              onChange={(event) => {
                setExpected(event.target.value);
                setReport(null);
              }}
              hint="A required assertion. Use 0 for an expected benign result."
              disabled={!!pending}
            />
          </div>
          {selectedDataset && <DatasetSummary dataset={selectedDataset} />}
          <div className="form-actions">
            <Button
              variant="primary"
              type="submit"
              disabled={
                !!pending ||
                !source.yaml.trim() ||
                !datasetId ||
                expected === '' ||
                !!datasets.error
              }
            >
              <FlaskConical size={15} aria-hidden="true" />
              {pending === 'test' ? 'Testing Sigma source…' : 'Run Sigma test'}
            </Button>
          </div>
        </form>
      </Panel>
      {report && <ValidationReportView report={report} />}
      <section className="sigma-help">
        <h2>Supported subset</h2>
        <p>
          Selectors, <code>and</code>, <code>or</code>, <code>not</code>, parentheses, and{' '}
          <code>all / 1 of</code> selector patterns. Equality, contains, startswith, and endswith
          support list-OR or <code>all</code> modifiers. Wildcards use a constrained backend
          translation.
        </p>
        <details className="disclosure">
          <summary>Supported fields &amp; explicit limitations</summary>
          <p>
            <code>Image</code> and <code>ParentImage</code> match the preserved full paths in{' '}
            <code>process.executable</code> and <code>process.parent.executable</code>. Basename
            fields remain available separately as <code>process.name</code> and{' '}
            <code>process.parent.name</code>.
          </p>
          <p>
            <code>Image</code>, <code>ParentImage</code>, <code>CommandLine</code>,{' '}
            <code>User</code>, <code>Computer</code>, <code>TargetFilename</code>,{' '}
            <code>DestinationIp</code>, <code>DestinationPort</code>, <code>SourceIp</code>,{' '}
            <code>SourcePort</code>, and <code>QueryName</code>.
          </p>
          <p>
            Only backend-supported logsources are accepted. Correlations, arbitrary logsources,
            unsupported modifiers, and unconstrained regular expressions are not silently
            approximated. The compiler returns the exact unsupported feature.
          </p>
          <p>
            Preserve author, upstream source, and license when redistributing a rule. The pinned
            samples’ provenance is shown above and carried into matching alerts.
          </p>
        </details>
      </section>
    </>
  );
}
