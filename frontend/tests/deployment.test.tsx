import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../src/services/api';
import { resolveApiBase } from '../src/services/apiBase';
import { benignReport, sigmaRule, sigmaSample } from './fixtures';
import { deferred, json, mockApi, renderApp } from './helpers';

const publicHealth = {
  status: 'ok',
  version: '0.1.0',
  auth_required: false,
  public_demo: true,
  public_demo_run_limit: 20,
};

afterEach(() => vi.unstubAllEnvs());

describe('deployment API configuration', () => {
  it.each([
    [undefined, '/api'],
    ['', '/api'],
    ['/api', '/api'],
    ['http://127.0.0.1:18865', 'http://127.0.0.1:18865/api'],
    ['https://backend.example.test/', 'https://backend.example.test/api'],
    ['https://backend.example.test/api/', 'https://backend.example.test/api'],
  ])('resolves %s without doubling the API prefix', (input, expected) => {
    expect(resolveApiBase(input)).toBe(expected);
  });

  it.each([
    '//backend.example.test',
    'javascript:alert(1)',
    'https://user:password@backend.example.test',
    'https://backend.example.test/custom/path',
    'https://backend.example.test/?token=test-only',
    'https://backend.example.test/#fragment',
    'https://backend.example.test/;script-src',
  ])('rejects invalid or credential-bearing base %s', (input) => {
    expect(() => resolveApiBase(input)).toThrow(/VITE_API_BASE_URL/);
  });

  it.each(['', '/api', 'http://backend.example.test', 'https://localhost', 'https://127.0.0.1'])(
    'refuses an unconfigured or local Vercel backend: %s',
    (input) => expect(() => resolveApiBase(input, true)).toThrow(/Vercel/),
  );

  it('accepts an explicit HTTPS origin for Vercel', () => {
    expect(resolveApiBase('https://backend.example.test', true)).toBe(
      'https://backend.example.test/api',
    );
  });

  it('uses the configured cross-origin URL for actual requests', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'https://backend.example.test');
    const fetch = vi.fn().mockResolvedValue(json({ status: 'ok' }));
    vi.stubGlobal('fetch', fetch);
    await api('/health');
    expect(fetch).toHaveBeenCalledWith(
      'https://backend.example.test/api/health',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('does not ask public visitors for a token to unlock deliberately restricted operations', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        json(
          {
            error: { code: 'public_demo_restricted', message: 'Unavailable in the public demo.' },
          },
          403,
        ),
      ),
    );
    await expect(api('/rules', { method: 'POST', body: {} })).rejects.toMatchObject({
      status: 403,
      code: 'public_demo_restricted',
      message: 'Unavailable in the public demo.',
    });
  });
});

describe('shared public demo boundaries', () => {
  it('identifies shared synthetic data and hides upload and connection controls', async () => {
    mockApi({ 'GET /api/health': publicHealth });
    renderApp('/');
    await screen.findByText('Shared synthetic demo.');
    expect(screen.getByText('Demo API connected')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Import events' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Connection settings' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Replay dataset' })).toBeInTheDocument();
  });

  it('does not expose an upload form even through a bookmarked import URL', async () => {
    mockApi({ 'GET /api/health': publicHealth });
    renderApp('/events?import=1');
    await screen.findByText('Shared synthetic demo.');
    expect(screen.queryByRole('button', { name: 'Import events' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Import telemetry' })).not.toBeInTheDocument();
    expect(screen.getByText(/Importing logs is unavailable/)).toBeInTheDocument();
  });

  it.each(['/rules', '/rules/AUTH-001'])('makes bundled switches read-only on %s', async (path) => {
    const fetch = mockApi({ 'GET /api/health': publicHealth });
    const user = userEvent.setup();
    renderApp(path);
    await screen.findByText('Shared synthetic demo.');
    const control = await screen.findByRole('switch');
    expect(control).toBeDisabled();
    await user.click(control);
    expect(fetch.mock.calls.some(([, init]) => init.method === 'PATCH')).toBe(false);
  });

  it('preserves alert evidence but does not collect public investigation notes', async () => {
    mockApi({ 'GET /api/health': publicHealth });
    renderApp('/alerts/alert-1');
    await screen.findByRole('heading', { name: 'Triggering evidence' });
    expect(screen.queryByLabelText('Investigation note (optional)')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save status' })).not.toBeInTheDocument();
    expect(screen.getByText(/Read-only in the shared demo/)).toBeInTheDocument();
  });

  it('keeps pinned Sigma compilation and benign testing functional without importing', async () => {
    const fetch = mockApi({
      'GET /api/health': publicHealth,
      'POST /api/sigma/compile': { rule: sigmaRule, warnings: [] },
      'POST /api/sigma/test': benignReport,
    });
    const user = userEvent.setup();
    renderApp('/sigma');
    await screen.findByText('Shared synthetic demo.');
    await screen.findByRole('option', { name: /Sigma unit-test process indicator/ });
    await user.selectOptions(screen.getByLabelText('Pinned sample'), sigmaSample.id);
    await user.click(screen.getByRole('button', { name: 'Load sample' }));
    expect(screen.getByLabelText('Sigma YAML')).toHaveAttribute('readonly');
    expect(screen.getByLabelText('Source URL')).toHaveAttribute('readonly');
    expect(screen.queryByLabelText('Upload Sigma YAML')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Import.*rule/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Compile rule' }));
    await screen.findByRole('heading', { name: 'Compilation result' });
    await user.click(screen.getByRole('button', { name: 'Use negative fixture' }));
    await user.click(screen.getByRole('button', { name: 'Run Sigma test' }));
    await waitFor(() =>
      expect(fetch.mock.calls.some(([url]) => url === '/api/sigma/test')).toBe(true),
    );
    expect(fetch.mock.calls.some(([url]) => url === '/api/sigma/import')).toBe(false);
  });

  it('waits for deployment mode before requesting developer evidence', async () => {
    const pending = deferred<typeof publicHealth>();
    const fetch = mockApi({ 'GET /api/health': () => pending.promise });
    renderApp('/evidence');
    expect(fetch.mock.calls.some(([url]) => String(url).includes('/project/'))).toBe(false);
    pending.resolve(publicHealth);
    await screen.findByRole('heading', { name: 'Demo data & limits' });
    expect(fetch.mock.calls.some(([url]) => String(url).includes('/project/'))).toBe(false);
    expect(screen.getByText(/At most 20 runs/)).toBeInTheDocument();
  });

  it('supports the detections deep-link alias without losing the selected scope', async () => {
    mockApi({ 'GET /api/health': publicHealth });
    renderApp('/detections?run_id=run-1');
    await waitFor(() =>
      expect(screen.getByTestId('location')).toHaveTextContent('/testing?run_id=run-1'),
    );
    expect(screen.getByRole('heading', { name: 'Detection testing' })).toBeInTheDocument();
  });
});
