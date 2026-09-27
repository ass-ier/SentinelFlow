import { useRef, useState } from 'react';
import { Upload } from 'lucide-react';
import { useWorkspace } from '../hooks/workspace';
import { api } from '../services/api';
import { number, readTextFile, validateContent } from '../services/format';
import type { IngestResult, InputFormat } from '../types';
import { Button, ErrorNotice, Fact, Notice, SelectField, TextareaField, TextField } from './ui';

export function IngestForm() {
  const { runs, setRunId, refresh } = useWorkspace();
  const [format, setFormat] = useState<InputFormat>('jsonl');
  const [content, setContent] = useState('');
  const [name, setName] = useState('');
  const [fileName, setFileName] = useState('');
  const [targetRun, setTargetRun] = useState('');
  const [year, setYear] = useState('');
  const [pending, setPending] = useState(false);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<IngestResult | null>(null);
  const readVersion = useRef(0);

  async function readFile(file: File | undefined) {
    const version = ++readVersion.current;
    setError(null);
    setResult(null);
    setContent('');
    setFileName('');
    if (!file) return;
    setReading(true);
    try {
      const text = await readTextFile(file, ['.json', '.jsonl', '.csv', '.log', '.txt']);
      if (version === readVersion.current) {
        setContent(text);
        setFileName(file.name);
      }
    } catch (failure) {
      if (version === readVersion.current) setError(failure);
    } finally {
      if (version === readVersion.current) setReading(false);
    }
  }

  async function submit() {
    setError(null);
    setResult(null);
    try {
      validateContent(content);
      setPending(true);
      const response = await api<IngestResult>('/events', {
        method: 'POST',
        body: {
          format,
          content,
          ...(name.trim() || fileName ? { name: name.trim() || fileName } : {}),
          ...(targetRun ? { run_id: targetRun } : {}),
          ...(format === 'syslog' && year ? { syslog_year: Number(year) } : {}),
        },
      });
      setResult(response);
      setRunId(response.run.id);
      refresh();
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }

  return (
    <form
      className="ingest-form"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <p className="muted">
        Import JSON, JSONL, CSV, syslog-style text, or Windows event JSON exports. Actual EVTX files
        are not supported. Files are read as inert text, never executed.
      </p>
      <div className="form-grid">
        <SelectField
          label="Input format"
          value={format}
          onChange={(event) => setFormat(event.target.value as InputFormat)}
          disabled={pending}
        >
          <option value="jsonl">JSONL — one event per line</option>
          <option value="json">JSON</option>
          <option value="csv">CSV</option>
          <option value="syslog">Syslog-style text</option>
          <option value="windows">Windows event JSON</option>
        </SelectField>
        <TextField
          label="Import name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          maxLength={200}
          placeholder="Optional; defaults to the filename"
          disabled={pending}
        />
        <TextField
          label="Telemetry file"
          type="file"
          accept=".json,.jsonl,.csv,.log,.txt"
          hint="Maximum 5 MiB. Select the input format explicitly."
          disabled={pending}
          onChange={(event) => void readFile(event.target.files?.[0])}
        />
        <SelectField
          label="Import target"
          value={targetRun}
          onChange={(event) => setTargetRun(event.target.value)}
          disabled={pending}
        >
          <option value="">New isolated run (recommended)</option>
          {runs.map((run) => (
            <option key={run.id} value={run.id}>
              Append to {run.name} · {run.id.slice(0, 8)}
            </option>
          ))}
        </SelectField>
        {format === 'syslog' && (
          <TextField
            label="Syslog year (UTC)"
            type="number"
            min={1970}
            max={2100}
            value={year}
            onChange={(event) => setYear(event.target.value)}
            hint="UTC year from 1970 through 2100 for yearless syslog records. Omit to use the backend default."
            disabled={pending}
          />
        )}
      </div>
      <TextareaField
        label="Event content"
        className="code-input"
        value={content}
        rows={7}
        onChange={(event) => {
          setContent(event.target.value);
          setResult(null);
        }}
        placeholder="Choose a telemetry file above, or paste its contents here."
        spellCheck={false}
        disabled={pending || reading}
        hint={
          fileName
            ? `Loaded ${fileName}. Review or edit before importing.`
            : 'Pasted content uses the same 5 MiB limit.'
        }
      />
      {targetRun && (
        <Notice tone="warning">
          Appends must not precede this run’s event-time watermark. Use a new isolated run for older
          events or a repeat test.
        </Notice>
      )}
      <ErrorNotice error={error} title="Import not completed" />
      {reading && <p role="status">Reading local file…</p>}
      {result && (
        <Notice tone="success">
          <strong>Import completed</strong>
          <dl className="facts facts-grid ingest-results">
            <Fact term="Events processed">{number(result.events_processed)}</Fact>
            <Fact term="Events stored">{number(result.events_stored)}</Fact>
            <Fact term="Duplicates ignored">{number(result.duplicates_ignored)}</Fact>
            <Fact term="Detections triggered">{number(result.detections_triggered)}</Fact>
            <Fact term="Alerts created">{number(result.alerts_created)}</Fact>
          </dl>
          <p>
            Explorer scope changed to <span className="mono">{result.run.id}</span>.
          </p>
        </Notice>
      )}
      <div className="form-actions split-actions">
        <p className="form-note">
          New runs sort events chronologically and pin the current enabled rules.
        </p>
        <Button variant="primary" type="submit" disabled={pending || reading || !content.trim()}>
          <Upload size={15} aria-hidden="true" />
          {pending ? 'Importing & evaluating…' : 'Ingest events'}
        </Button>
      </div>
      {pending && (
        <p className="sr-only" role="status">
          Import is processing. Counts will appear after the API completes.
        </p>
      )}
    </form>
  );
}
