import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { json, mockApi, renderApp } from './helpers';
import { benchmarkArtifact, validationArtifact } from './project-fixtures';

describe('project evidence without fabricated claims', () => {
  it('labels missing artifacts as not yet validated', async () => {
    mockApi();
    renderApp('/evidence');
    expect(await screen.findByText('Not yet validated')).toBeInTheDocument();
    expect(screen.getByText('No completed validation artifact')).toBeInTheDocument();
    expect(screen.getByText('No measured benchmark yet')).toBeInTheDocument();
    expect(screen.queryByText('PASS', { exact: true })).not.toBeInTheDocument();
    expect(
      screen.getByText('No execution log exists yet. This page cannot run shell commands.'),
    ).toBeInTheDocument();
  });

  it('renders actual validation logs, measured numbers, and included files safely', async () => {
    mockApi({
      'GET /api/project/evidence': {
        validation: validationArtifact,
        benchmark: benchmarkArtifact,
        validation_log:
          'ACTUAL COMMAND OUTPUT\n17 passed\n<script>window.evidenceExecuted=true</script>',
        validation_running: false,
        files: [
          { path: 'test-data/authentication/included.jsonl', bytes: 1034 },
          { path: 'backend/tests/unit/test_fixture.py', bytes: 811 },
          { path: 'scripts/validate.py', bytes: 93 },
          { path: 'docs/testing.md', bytes: 42 },
        ],
        documents: [{ path: 'docs/testing.md', title: 'Testing guide' }],
      },
      'GET /api/project/document': {
        path: 'docs/testing.md',
        content:
          '# Testing guide\n<img src=x onerror="window.evidenceExecuted=true">\nMeasured evidence only.',
      },
    });
    const user = userEvent.setup();
    const { container } = renderApp('/evidence');
    expect(await screen.findByLabelText('Actual validation command output')).toHaveTextContent(
      '17 passed',
    );
    expect(screen.getByText('Total unique tests passed').parentElement).toHaveTextContent('17');
    expect(screen.getByText('Backend coverage').parentElement).toHaveTextContent('92.5%');
    expect(screen.getByText('Controlled benign passed / total').parentElement).toHaveTextContent(
      '2 / 2',
    );
    const counts = screen.getByRole('table', { name: 'Comprehensive validation counts' });
    expect(
      within(counts).getByRole('rowheader', { name: 'Backend tests' }).parentElement,
    ).toHaveTextContent('Backend tests11011');
    expect(
      within(counts).getByRole('rowheader', { name: 'Frontend tests' }).parentElement,
    ).toHaveTextContent('Frontend tests606');
    expect(
      within(counts).getByRole('rowheader', { name: 'Detection scenarios' }).parentElement,
    ).toHaveTextContent('Detection scenarios505');
    expect(screen.getByText('Events per second').parentElement).toHaveTextContent('241.75');
    expect(screen.getByText('Detection time').parentElement).toHaveTextContent('0.0000123 s');
    expect(screen.getByText('Alerts generated').parentElement).toHaveTextContent('3');
    expect(screen.getByText('Rules evaluated').parentElement).toHaveTextContent('840');
    expect(screen.getByText('Active rules').parentElement).toHaveTextContent('7');
    expect(screen.getByText('Measured at (UTC)').parentElement).toHaveTextContent(
      '2026-01-15 11:00:04.012345',
    );
    await user.click(screen.getByText('Executed validation steps', { selector: 'summary' }));
    const steps = screen.getByRole('table', { name: 'Executed validation steps' });
    expect(within(steps).getByText('python -m pytest backend/tests')).toBeInTheDocument();
    expect(within(steps).getByText('npm --prefix frontend test')).toBeInTheDocument();
    expect(within(steps).getByText('2.075 s')).toBeInTheDocument();
    await user.click(screen.getByText('Backend test categories — overlapping subsets'));
    const categories = screen.getByRole('table', { name: 'Backend test categories' });
    expect(
      within(categories).getByRole('rowheader', { name: 'Parser' }).parentElement,
    ).toHaveTextContent('Parser404');
    expect(screen.getByText('included.jsonl')).toBeInTheDocument();
    expect(screen.getByText('test_fixture.py')).toBeInTheDocument();
    expect(screen.getByText('validate.py')).toBeInTheDocument();
    expect(await screen.findByLabelText('Document content: docs/testing.md')).toHaveTextContent(
      '<img src=x onerror="window.evidenceExecuted=true">',
    );
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect((window as unknown as Record<string, unknown>).evidenceExecuted).toBeUndefined();
  });

  it('polls genuine in-progress output until completed evidence appears', async () => {
    let complete = false;
    const fetch = mockApi({
      'GET /api/project/evidence': () => ({
        validation: complete ? validationArtifact : null,
        benchmark: null,
        validation_log: complete ? '17 passed\nSTATUS: VALIDATED' : 'Running parser tests…',
        validation_running: !complete,
        files: [],
        documents: [],
      }),
    });
    renderApp('/evidence');
    expect(await screen.findByText('Validation running')).toBeInTheDocument();
    expect(screen.getByLabelText('Actual validation command output')).toHaveTextContent(
      'Running parser tests',
    );
    expect(screen.queryByText('PASS', { exact: true })).not.toBeInTheDocument();
    complete = true;
    await waitFor(
      () =>
        expect(screen.getByLabelText('Actual validation command output')).toHaveTextContent(
          'STATUS: VALIDATED',
        ),
      { timeout: 2500 },
    );
    expect(screen.getByText('Total unique tests passed').parentElement).toHaveTextContent('17');
    expect(
      fetch.mock.calls.filter(([url]) => url === '/api/project/evidence').length,
    ).toBeGreaterThan(1);
  });

  it('retains historical numbers but never marks stale artifacts as current validation', async () => {
    mockApi({
      'GET /api/project/evidence': {
        validation: { ...validationArtifact, status: 'stale', is_current: false },
        benchmark: { ...benchmarkArtifact, status: 'stale', is_current: false },
        validation_running: false,
        validation_log: 'Previous execution completed.',
        files: [],
        documents: [],
      },
    });
    renderApp('/evidence');
    await screen.findByText(/This saved validation is stale for the current sources/);
    const validation = screen.getByRole('region', { name: 'Comprehensive validation' });
    expect(within(validation).getByText('Stale artifact')).toHaveClass('badge-warning');
    expect(
      within(validation).queryByText('Validated', { selector: '.badge' }),
    ).not.toBeInTheDocument();
    expect(screen.getByText('Total unique tests passed').parentElement).toHaveTextContent('17');
    const benchmark = screen.getByRole('region', { name: 'Measured benchmark' });
    expect(within(benchmark).getByText('Stale artifact')).toHaveClass('badge-warning');
    expect(within(benchmark).queryByText('PASS', { selector: '.badge' })).not.toBeInTheDocument();
    expect(within(benchmark).getByText('Events per second').parentElement).toHaveTextContent(
      '241.75',
    );
  });

  it('shows partial failed executions without fabricating absent suite counts', async () => {
    mockApi({
      'GET /api/project/evidence': {
        validation: {
          status: 'failed',
          is_current: true,
          started_at: validationArtifact.started_at,
          completed_at: validationArtifact.completed_at,
          duration_seconds: 0.75,
          source_fingerprint: validationArtifact.source_fingerprint,
          error: 'Frontend formatting failed with exit code 1.',
          steps: [
            {
              name: 'Frontend formatting',
              command: ['npm', '--prefix', 'frontend', 'run', 'format:check'],
              status: 'failed',
              exit_code: 1,
              duration_seconds: 0.75,
            },
          ],
        },
        benchmark: null,
        validation_running: false,
        validation_log: 'Frontend formatting: FAIL',
        files: [],
        documents: [],
      },
    });
    renderApp('/evidence');
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Frontend formatting failed with exit code 1.',
    );
    expect(screen.getByText('Total unique tests passed').parentElement).toHaveTextContent(
      'Not recorded',
    );
    const counts = screen.getByRole('table', { name: 'Comprehensive validation counts' });
    expect(within(counts).getAllByText('Not recorded')).toHaveLength(3);
    expect(within(counts).queryByText('0')).not.toBeInTheDocument();
    const steps = screen.getByRole('table', { name: 'Executed validation steps' });
    expect(within(steps).getByText('npm --prefix frontend run format:check')).toBeInTheDocument();
    expect(within(steps).getByText('1')).toBeInTheDocument();
    expect(screen.queryByText('PASS', { exact: true })).not.toBeInTheDocument();
  });

  it('labels an older saved report while a new validation command is still running', async () => {
    mockApi({
      'GET /api/project/evidence': {
        validation: validationArtifact,
        benchmark: null,
        validation_running: true,
        validation_log: 'Running current frontend tests…',
        files: [],
        documents: [],
      },
    });
    renderApp('/evidence');
    expect(await screen.findByText('Previous recorded report')).toBeInTheDocument();
    const validation = screen.getByRole('region', { name: 'Comprehensive validation' });
    expect(within(validation).getByText('Validation running')).toHaveClass('badge-warning');
    expect(
      within(validation).queryByText('Validated', { selector: '.badge' }),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText('Actual validation command output')).toHaveTextContent(
      'Running current frontend tests',
    );
  });

  it('fetches selected documents by exact allowlisted paths', async () => {
    const fetch = mockApi({
      'GET /api/project/evidence': {
        validation: null,
        benchmark: null,
        validation_log: '',
        validation_running: false,
        files: [],
        documents: [
          { path: 'README.md', title: 'Overview' },
          { path: 'docs/testing.md', title: 'Testing guide' },
        ],
      },
      'GET /api/project/document': ({ url }: { url: URL }) => ({
        path: url.searchParams.get('path'),
        content: `Document: ${url.searchParams.get('path')}`,
      }),
    });
    const user = userEvent.setup();
    renderApp('/evidence');
    await screen.findByLabelText('Document content: README.md');
    await user.selectOptions(screen.getByLabelText('Document'), 'docs/testing.md');
    expect(await screen.findByLabelText('Document content: docs/testing.md')).toHaveTextContent(
      'Document: docs/testing.md',
    );
    expect(
      fetch.mock.calls.some(([url]) => url === '/api/project/document?path=docs%2Ftesting.md'),
    ).toBe(true);
  });

  it('keeps artifact read failures distinct from an unvalidated empty state', async () => {
    mockApi({
      'GET /api/project/evidence': json(
        { error: { code: 'artifact_read', message: 'Artifact store unavailable.' } },
        500,
      ),
    });
    renderApp('/evidence');
    expect(await screen.findByRole('alert')).toHaveTextContent('Artifact store unavailable.');
    expect(screen.queryByText('Not yet validated')).not.toBeInTheDocument();
  });
});
