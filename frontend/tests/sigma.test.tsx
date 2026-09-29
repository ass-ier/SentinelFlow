import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { benignReport, failedReport, sigmaRule, sigmaSample } from './fixtures';
import { json, mockApi, renderApp } from './helpers';

async function loadSample(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByRole('option', {
    name: /Sigma unit-test process indicator · Sigma Fixture Author/,
  });
  await user.selectOptions(screen.getByLabelText('Pinned sample'), sigmaSample.id);
  await user.click(screen.getByRole('button', { name: 'Load sample' }));
}

describe('limited Sigma workbench', () => {
  it('shows the exact compiled JSON when the backend does not return YAML text', async () => {
    const canonical = Object.fromEntries(
      Object.entries(sigmaRule).filter(([key]) => key !== 'yaml' && key !== 'updated_at'),
    );
    mockApi({ 'POST /api/sigma/compile': { rule: canonical, warnings: [] } });
    const user = userEvent.setup();
    renderApp('/sigma');
    await loadSample(user);
    await user.click(screen.getByRole('button', { name: 'Compile rule' }));
    const output = await screen.findByLabelText('Compiled rule JSON');
    expect(JSON.parse(output.textContent!)).toEqual(canonical);
    expect(screen.queryByLabelText('Compiled internal YAML')).not.toBeInTheDocument();
  });

  it('loads actual sample YAML and attribution then compiles on the API', async () => {
    const fetch = mockApi({
      'POST /api/sigma/compile': {
        rule: sigmaRule,
        warnings: ['Fixture warning returned by compiler.'],
      },
    });
    const user = userEvent.setup();
    renderApp('/sigma');
    await loadSample(user);
    expect(screen.getByLabelText('Sigma YAML')).toHaveValue(sigmaSample.yaml);
    expect(screen.getByLabelText('Source URL')).toHaveValue(sigmaSample.source_url);
    expect(screen.getByLabelText('License')).toHaveValue('Test fixture');
    await user.click(screen.getByRole('button', { name: 'Compile rule' }));
    expect(await screen.findByRole('heading', { name: 'Compilation result' })).toBeInTheDocument();
    expect(screen.getByText('Fixture warning returned by compiler.')).toBeInTheDocument();
    expect(screen.getAllByText('Sigma Fixture Author').length).toBeGreaterThan(1);
    expect(screen.getByLabelText('Compiled internal YAML').textContent).toBe(sigmaRule.yaml);
    const request = fetch.mock.calls.find(([url]) => url === '/api/sigma/compile');
    expect(JSON.parse(String(request?.[1].body))).toEqual({
      yaml: sigmaSample.yaml,
      source_url: sigmaSample.source_url,
      license: sigmaSample.license,
      license_url: sigmaSample.license_url,
    });
  });

  it('reports unsupported Sigma features rather than producing an approximate success', async () => {
    mockApi({
      'POST /api/sigma/compile': json(
        {
          error: {
            code: 'unsupported_sigma',
            message: 'Unsupported modifier: re. The rule was not compiled.',
          },
        },
        422,
      ),
    });
    const user = userEvent.setup();
    renderApp('/sigma');
    await loadSample(user);
    await user.click(screen.getByRole('button', { name: 'Compile rule' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Unsupported modifier: re.');
    expect(screen.queryByRole('heading', { name: 'Compilation result' })).not.toBeInTheDocument();
    expect(screen.queryByText('Compiled', { exact: true })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Sigma YAML')).toHaveValue(sigmaSample.yaml);
  });

  it('imports disabled by default and links the actual saved definition', async () => {
    const fetch = mockApi({ 'POST /api/sigma/import': sigmaRule });
    const user = userEvent.setup();
    renderApp('/sigma?run_id=run-1');
    await loadSample(user);
    expect(screen.getByLabelText('Enable for future runs on import')).not.toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Import disabled rule' }));
    expect(await screen.findByRole('link', { name: 'Inspect imported rule' })).toHaveAttribute(
      'href',
      '/rules/sigma-unit-fixture?run_id=run-1',
    );
    const request = fetch.mock.calls.find(([url]) => url === '/api/sigma/import');
    expect(JSON.parse(String(request?.[1].body))).toMatchObject({
      enabled: false,
      source_url: sigmaSample.source_url,
    });
    expect(screen.getAllByText('Sigma Fixture Author').length).toBeGreaterThan(1);
  });

  it('allows explicit enable-on-import without silently enabling a rule', async () => {
    const fetch = mockApi({ 'POST /api/sigma/import': { ...sigmaRule, enabled: true } });
    const user = userEvent.setup();
    renderApp('/sigma');
    await loadSample(user);
    await user.click(screen.getByLabelText('Enable for future runs on import'));
    await user.click(screen.getByRole('button', { name: 'Import enabled rule' }));
    expect(
      await screen.findByText('Enabled for new runs', { selector: '.badge' }),
    ).toBeInTheDocument();
    const request = fetch.mock.calls.find(([url]) => url === '/api/sigma/import');
    expect(JSON.parse(String(request?.[1].body))).toMatchObject({ enabled: true });
  });

  it('tests the negative fixture with an explicit zero assertion', async () => {
    const fetch = mockApi({ 'POST /api/sigma/test': benignReport });
    const user = userEvent.setup();
    renderApp('/sigma');
    await loadSample(user);
    await user.click(screen.getByRole('button', { name: 'Use negative fixture' }));
    expect(screen.getByLabelText('Sigma test dataset')).toHaveValue('benign-fixture');
    expect(screen.getByLabelText('Expected alert count')).toHaveValue(0);
    await user.click(screen.getByRole('button', { name: 'Run Sigma test' }));
    expect(await screen.findAllByText('PASS')).toHaveLength(2);
    const request = fetch.mock.calls.find(([url]) => url === '/api/sigma/test');
    expect(JSON.parse(String(request?.[1].body))).toMatchObject({
      dataset_id: 'benign-fixture',
      expected_alerts: 0,
    });
  });

  it('renders a backend FAIL and clears stale compilation on edits', async () => {
    mockApi({
      'POST /api/sigma/compile': { rule: sigmaRule, warnings: [] },
      'POST /api/sigma/test': failedReport,
    });
    const user = userEvent.setup();
    renderApp('/sigma');
    await loadSample(user);
    await user.click(screen.getByRole('button', { name: 'Compile rule' }));
    await screen.findByRole('heading', { name: 'Compilation result' });
    await user.click(screen.getByRole('button', { name: 'Run Sigma test' }));
    expect(await screen.findAllByText('FAIL')).toHaveLength(2);
    fireEvent.change(screen.getByLabelText('Sigma YAML'), {
      target: { value: 'title: Changed fixture' },
    });
    await waitFor(() =>
      expect(screen.queryByRole('heading', { name: 'Compilation result' })).not.toBeInTheDocument(),
    );
    expect(screen.queryByRole('heading', { name: 'Validation results' })).not.toBeInTheDocument();
  });
});
