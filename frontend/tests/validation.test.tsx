import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { benignReport, failedReport, observedReport, passedReport } from './fixtures';
import { deferred, json, mockApi, renderApp } from './helpers';

describe('real detection validation results', () => {
  it('renders inline raw evidence without fabricated storage IDs or operational links', async () => {
    mockApi({ 'POST /api/detections/validate': passedReport });
    const user = userEvent.setup();
    const { container } = renderApp('/testing');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Run validation' })).toBeEnabled(),
    );
    await user.click(screen.getByRole('button', { name: 'Run validation' }));
    await user.click(await screen.findByText('Included brute-force scenario'));
    const section = screen
      .getByRole('heading', { name: 'Isolated test alerts' })
      .closest('section')!;
    await user.click(within(section).getByText(/evidence events/));
    const evidence = screen.getByRole('table', {
      name: 'Isolated evidence for AUTH-POSITIVE / validation-alert-1',
    });
    expect(within(evidence).queryByRole('link')).not.toBeInTheDocument();
    await user.click(
      within(evidence).getByRole('button', { name: 'Show raw event fixture-event-1' }),
    );
    expect(within(evidence).getByText('Not persisted — isolated validation')).toBeInTheDocument();
    expect(
      within(evidence).getByText('validation:positive-fixture', { selector: 'span' }),
    ).toBeInTheDocument();
    expect(
      JSON.parse(within(evidence).getByLabelText('Raw event fixture-event-1').textContent!).message,
    ).toBe('<img src=x onerror="window.logExecuted=true">');
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('a[href^="/alerts/validation"]')).toBeNull();
    expect(container.querySelector('a[href^="/events/storage"]')).toBeNull();
  });

  it('labels null evidence counts in count-only assertions as not asserted, never zero', async () => {
    const counted = {
      ...passedReport,
      results: [
        {
          ...passedReport.results[0],
          expected: [{ ...passedReport.results[0].actual[0], event_count: null, branch: 'any' }],
        },
      ],
    };
    mockApi({ 'POST /api/rules/AUTH-001/test': counted });
    const user = userEvent.setup();
    renderApp('/rules/AUTH-001');
    await screen.findByRole('option', { name: /Authentication positive fixture/ });
    await user.selectOptions(screen.getByLabelText('Dataset'), 'positive-fixture');
    await user.type(screen.getByLabelText('Expected alerts (optional)'), '1');
    await user.click(screen.getByRole('button', { name: 'Run definition test' }));
    await user.click(await screen.findByText('Included brute-force scenario'));
    const expected = screen.getByRole('table', { name: 'Expected detections' });
    expect(within(expected).getByText('Not asserted')).toBeInTheDocument();
    expect(within(expected).queryByText('0 events')).not.toBeInTheDocument();
    const actual = screen.getByRole('table', { name: 'Observed detections' });
    expect(within(actual).getByText('2 events')).toBeInTheDocument();
  });

  it('shows pending execution without a fabricated pass count', async () => {
    const response = deferred<typeof passedReport>();
    mockApi({ 'POST /api/detections/validate': () => response.promise });
    const user = userEvent.setup();
    renderApp('/testing');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Run validation' })).toBeEnabled(),
    );
    expect(screen.getByText('No validation result yet')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Run validation' }));
    expect(
      screen.getByText(
        'Executing validation scenarios. Results will appear when execution completes.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText('PASS')).not.toBeInTheDocument();
    expect(screen.queryByText('Total scenarios')).not.toBeInTheDocument();
    await act(async () => response.resolve(passedReport));
    expect(await screen.findAllByText('PASS')).toHaveLength(2);
  });

  it('defaults to bundled definitions and asserts the real benign zero-alert result', async () => {
    const fetch = mockApi({ 'POST /api/detections/validate': benignReport });
    const user = userEvent.setup();
    renderApp('/testing');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Run validation' })).toBeEnabled(),
    );
    await user.selectOptions(screen.getByLabelText('Dataset'), 'benign-fixture');
    await user.selectOptions(screen.getByLabelText('Detection'), 'AUTH-001');
    await user.click(screen.getByRole('button', { name: 'Run validation' }));
    await screen.findByRole('heading', { name: 'Validation results' });
    expect(screen.getByText('Benign passed / total').parentElement).toHaveTextContent('1 / 1');
    await user.click(screen.getByText('Controlled benign fixture'));
    expect(screen.getAllByText('0 alerts', { selector: 'p' })).toHaveLength(2);
    expect(
      screen.getByText(/controlled benign fixture. Its expected behavior/),
    ).toBeInTheDocument();
    const request = fetch.mock.calls.find(([url]) => url === '/api/detections/validate');
    expect(JSON.parse(String(request?.[1].body))).toEqual({
      scope: 'bundled',
      dataset_id: 'benign-fixture',
      rule_id: 'AUTH-001',
    });
  });

  it('renders actual failed comparisons and current-scope differences', async () => {
    const fetch = mockApi({
      'POST /api/detections/validate': { ...failedReport, scope: 'current' },
    });
    const user = userEvent.setup();
    renderApp('/testing');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Run validation' })).toBeEnabled(),
    );
    await user.selectOptions(screen.getByLabelText('Definition scope'), 'current');
    await user.click(screen.getByRole('button', { name: 'Run validation' }));
    expect(await screen.findByText('Expected 1 alert; observed 0.')).toBeInTheDocument();
    expect(screen.getAllByText('FAIL')).toHaveLength(2);
    expect(screen.getByText('Failed', { selector: 'dt' }).parentElement).toHaveTextContent('1');
    expect(screen.queryByText('PASS')).not.toBeInTheDocument();
    const request = fetch.mock.calls.find(([url]) => url === '/api/detections/validate');
    expect(JSON.parse(String(request?.[1].body))).toEqual({ scope: 'current' });
  });

  it('never promotes an unknown expectation to PASS', async () => {
    mockApi({ 'POST /api/detections/validate': observedReport });
    const user = userEvent.setup();
    renderApp('/testing');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Run validation' })).toBeEnabled(),
    );
    await user.click(screen.getByRole('button', { name: 'Run validation' }));
    expect(await screen.findByText(/Observation only. Unknown expectations/)).toBeInTheDocument();
    expect(
      screen.getByText(/No saved expectation. An observation is not a PASS./),
    ).toBeInTheDocument();
    expect(screen.queryByText('PASS', { exact: true })).not.toBeInTheDocument();
    expect(screen.getByText('Passed', { selector: 'dt' }).parentElement).toHaveTextContent('0');
  });

  it('does not show a report when validation cannot execute', async () => {
    mockApi({ 'POST /api/detections/validate': json({ detail: 'Unknown dataset.' }, 422) });
    const user = userEvent.setup();
    renderApp('/testing');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Run validation' })).toBeEnabled(),
    );
    await user.click(screen.getByRole('button', { name: 'Run validation' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Unknown dataset.');
    expect(screen.queryByRole('heading', { name: 'Validation results' })).not.toBeInTheDocument();
  });

  it('downloads the actual returned report without substituting a summary', async () => {
    mockApi({ 'POST /api/detections/validate': passedReport });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    const user = userEvent.setup();
    renderApp('/testing');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Run validation' })).toBeEnabled(),
    );
    await user.click(screen.getByRole('button', { name: 'Run validation' }));
    await user.click(await screen.findByRole('button', { name: 'Download JSON' }));
    const blob = vi.mocked(URL.createObjectURL).mock.calls.at(-1)?.[0] as Blob;
    expect(blob).toBeInstanceOf(Blob);
    const text = await new Promise<string>((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.readAsText(blob);
    });
    expect(JSON.parse(text)).toEqual(passedReport);
  });
});
