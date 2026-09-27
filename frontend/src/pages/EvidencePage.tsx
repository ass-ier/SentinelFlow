import { useEffect, useRef, useState } from 'react';
import { FileTree } from '../components/FileTree';
import { ArtifactStatus, BenchmarkReport, ComprehensiveReport } from '../components/ProjectReports';
import {
  Badge,
  EmptyState,
  ErrorNotice,
  LoadingState,
  Notice,
  PageHeader,
  Panel,
  SelectField,
  TextField,
} from '../components/ui';
import { useResource } from '../hooks/useResource';
import { useWorkspace } from '../hooks/workspace';
import { queryString } from '../services/api';
import { number } from '../services/format';
import type { ProjectEvidence } from '../types';

export function EvidencePage() {
  const { revision } = useWorkspace();
  const evidence = useResource<ProjectEvidence>('/project/evidence', {
    refreshKey: revision,
    pollMs: 1500,
  });
  const [selectedPath, setSelectedPath] = useState('');
  const [fileQuery, setFileQuery] = useState('');
  const [follow, setFollow] = useState(true);
  const logRef = useRef<HTMLPreElement>(null);
  const data = evidence.data;
  const documents = data?.documents ?? [];
  const path = documents.some((document) => document.path === selectedPath)
    ? selectedPath
    : documents.find((document) => document.path === 'README.md')?.path || documents[0]?.path || '';
  const document = useResource<{ path: string; content: string }>(
    path ? `/project/document${queryString({ path })}` : null,
    { refreshKey: revision },
  );
  const files =
    data?.files.filter((file) => file.path.toLowerCase().includes(fileQuery.toLowerCase())) ?? [];
  useEffect(() => {
    if (follow && logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [follow, data?.validation_log]);

  return (
    <>
      <PageHeader
        title="Project evidence"
        description="Executed validation, measured performance, and the files included with this project. No simulated results."
      />
      <ErrorNotice
        error={evidence.error}
        onRetry={evidence.reload}
        title="Project artifacts could not be loaded"
      />
      {evidence.loading && <LoadingState label="Loading recorded project evidence" />}
      {data && (
        <>
          <Panel
            title="Comprehensive validation"
            description="Artifacts produced by the repository validation command, not by this page."
            actions={
              data.validation_running ? (
                <Badge tone="warning">Validation running</Badge>
              ) : data.validation ? (
                <ArtifactStatus
                  status={data.validation.status}
                  current={data.validation.is_current}
                />
              ) : (
                <Badge>Not yet validated</Badge>
              )
            }
          >
            {data.validation_running && (
              <Notice tone="warning">
                A validation process is running. The live log below refreshes from its actual
                output. An older report is not proof that this execution has passed.
              </Notice>
            )}
            {data.validation ? (
              <div className="artifact-record">
                {data.validation_running && <h3>Previous recorded report</h3>}
                <ComprehensiveReport report={data.validation} />
              </div>
            ) : (
              <EmptyState
                title="No completed validation artifact"
                description={
                  <>
                    Run <code>make validate</code> from the repository root. A passing result will
                    only appear after the command has actually completed and written its report.
                  </>
                }
              />
            )}
          </Panel>
          <Panel
            title="Live validation log"
            description="Read-only execution evidence · Refreshes from the backend every 1.5 seconds."
            actions={
              <label className="checkbox-field">
                <input
                  type="checkbox"
                  checked={follow}
                  onChange={(event) => setFollow(event.target.checked)}
                />
                Follow output
              </label>
            }
          >
            {data.validation_log ? (
              <pre
                className="validation-log"
                ref={logRef}
                tabIndex={0}
                aria-label="Actual validation command output"
              >
                {data.validation_log}
              </pre>
            ) : (
              <p className="panel-empty">
                No execution log exists yet. This page cannot run shell commands.
              </p>
            )}
            <p className="panel-note" role="status">
              {data.validation_running
                ? 'Receiving real validation output.'
                : 'No validation process reported as running.'}
            </p>
          </Panel>
          <Panel
            title="Measured benchmark"
            description="Measurements from a recorded benchmark execution. Hardware, rule sets, and datasets affect these values."
            actions={
              data.benchmark && (
                <ArtifactStatus
                  status={data.benchmark.status}
                  current={data.benchmark.is_current}
                />
              )
            }
          >
            {data.benchmark ? (
              <div className="artifact-record">
                <BenchmarkReport report={data.benchmark} />
              </div>
            ) : (
              <EmptyState
                title="No measured benchmark yet"
                description="Run the repository benchmark or comprehensive validation to record real throughput and detection timings."
              />
            )}
          </Panel>
          <div className="project-browser">
            <Panel
              title="Included file inventory"
              description={`${number(data.files.length)} backend-reported files`}
            >
              <div className="inventory-search">
                <TextField
                  label="Filter file paths"
                  value={fileQuery}
                  onChange={(event) => setFileQuery(event.target.value)}
                  placeholder="test-data/, tests/, scripts/, docs/…"
                />
              </div>
              {files.length ? (
                <FileTree files={files} documents={documents} onDocument={setSelectedPath} />
              ) : (
                <p className="panel-empty">No file paths match this filter.</p>
              )}
            </Panel>
            <div id="project-document">
              <Panel
                title="Project documents"
                description="Read source documentation without executing HTML or embedded content."
              >
                {documents.length ? (
                  <>
                    <div className="document-picker">
                      <SelectField
                        label="Document"
                        value={path}
                        onChange={(event) => setSelectedPath(event.target.value)}
                      >
                        {documents.map((item) => (
                          <option key={item.path} value={item.path}>
                            {item.title} · {item.path}
                          </option>
                        ))}
                      </SelectField>
                    </div>
                    <ErrorNotice
                      error={document.error}
                      onRetry={document.reload}
                      title="Document could not be loaded"
                    />
                    {document.loading && <LoadingState label="Loading project document" />}
                    {document.data && (
                      <>
                        <p className="document-path mono">{document.data.path}</p>
                        <pre
                          className="document-content"
                          tabIndex={0}
                          aria-label={`Document content: ${document.data.path}`}
                        >
                          {document.data.content}
                        </pre>
                      </>
                    )}
                  </>
                ) : (
                  <p className="panel-empty">No readable documents were returned by the backend.</p>
                )}
              </Panel>
            </div>
          </div>
        </>
      )}
    </>
  );
}
