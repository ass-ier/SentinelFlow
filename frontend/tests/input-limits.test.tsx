import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { getToken, MAX_TOKEN_LENGTH, saveToken } from '../src/services/api';
import { MAX_SIGMA_BYTES, readTextFile, validateContent } from '../src/services/format';
import { run } from './fixtures';
import { mockApi, renderApp } from './helpers';

describe('API token limits', () => {
  it.each([
    { name: 'embedded whitespace', value: 'fixture token' },
    { name: 'leading and trailing whitespace', value: ' fixture-token ' },
    { name: 'a trailing newline', value: 'fixture-token\n' },
    { name: 'non-ASCII characters', value: 'fixturé-token' },
    { name: 'more than 256 characters', value: 'x'.repeat(MAX_TOKEN_LENGTH + 1) },
  ])('rejects $name without changing the saved token', ({ value }) => {
    saveToken('previous-fixture-token');
    expect(() => saveToken(value)).toThrow('256 printable ASCII characters with no whitespace');
    expect(getToken()).toBe('previous-fixture-token');
  });

  it('accepts exactly 256 printable ASCII characters and an empty removal', () => {
    const token = '!~Aa0._-'.repeat(32);
    expect(token).toHaveLength(256);
    saveToken(token);
    expect(getToken()).toBe(token);
    saveToken('');
    expect(getToken()).toBe('');
    expect(sessionStorage.getItem('sentinelflow.token')).toBeNull();
  });

  it('does not forward invalid legacy session-storage tokens', () => {
    sessionStorage.setItem('sentinelflow.token', 'legacy-invalid-token\n');
    expect(getToken()).toBe('');
  });

  it('preserves a clear storage-unavailable error for otherwise valid tokens', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage blocked', 'SecurityError');
    });
    expect(() => saveToken('valid-fixture-token')).toThrow('Session storage is unavailable');
  });

  it('shows matching native constraints and rejects invalid input in connection settings', async () => {
    saveToken('previous-fixture-token');
    mockApi();
    const user = userEvent.setup();
    renderApp('/');
    await user.click(screen.getByRole('button', { name: 'Connection settings' }));
    const dialog = screen.getByRole('dialog', { name: 'Connection settings' });
    const input = within(dialog).getByLabelText('API token');
    expect(input).toHaveAttribute('maxlength', '256');
    expect(input).toHaveAttribute('pattern', '[!-~]{0,256}');
    expect(
      within(dialog).getByText(/256 printable ASCII characters with no whitespace/),
    ).toBeInTheDocument();
    fireEvent.change(input, { target: { value: 'not a valid token' } });
    expect(input).toBeInvalid();
    await user.click(within(dialog).getByRole('button', { name: 'Save connection' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(
      '256 printable ASCII characters with no whitespace',
    );
    expect(getToken()).toBe('previous-fixture-token');
    expect(dialog).toBeInTheDocument();
  });
});

describe('Sigma YAML limits', () => {
  it('accepts the exact 64 KiB boundary without lowering the independent log limit', async () => {
    const content = '#'.repeat(MAX_SIGMA_BYTES);
    expect(() => validateContent(content, MAX_SIGMA_BYTES)).not.toThrow();
    await expect(
      readTextFile(new File([content], 'boundary.yaml'), ['.yaml'], MAX_SIGMA_BYTES),
    ).resolves.toBe(content);
    expect(() => validateContent(`${content}x`, MAX_SIGMA_BYTES)).toThrow('64 KiB');
    expect(() => validateContent(`${content}x`)).not.toThrow();
  });

  it('rejects oversized Sigma files before reading them', async () => {
    mockApi();
    const user = userEvent.setup();
    renderApp('/sigma');
    const file = new File(['small'], 'too-large.yml');
    Object.defineProperty(file, 'size', { value: MAX_SIGMA_BYTES + 1 });
    const read = vi.spyOn(file, 'text');
    await user.upload(screen.getByLabelText('Upload Sigma YAML'), file);
    expect(await screen.findByRole('alert')).toHaveTextContent('64 KiB');
    expect(read).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Compile rule' })).toBeDisabled();
  });

  it('rejects pasted YAML by UTF-8 byte size before any compiler request', async () => {
    const fetch = mockApi();
    const user = userEvent.setup();
    renderApp('/sigma');
    const content = `title: Fixture\n#${'界'.repeat(Math.floor(MAX_SIGMA_BYTES / 3))}`;
    expect(content.length).toBeLessThan(MAX_SIGMA_BYTES);
    fireEvent.change(screen.getByLabelText('Sigma YAML'), { target: { value: content } });
    await user.click(screen.getByRole('button', { name: 'Compile rule' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('64 KiB');
    expect(fetch.mock.calls.some(([, init]) => init.method === 'POST')).toBe(false);
    expect(screen.getByLabelText('Sigma YAML')).toHaveValue(content);
  });
});

describe('syslog year limits', () => {
  it('blocks 2101 but sends the inclusive maximum 2100', async () => {
    const fetch = mockApi({
      'POST /api/events': {
        run,
        events_processed: 1,
        events_stored: 1,
        duplicates_ignored: 0,
        detections_triggered: 0,
        alerts_created: 0,
      },
    });
    const user = userEvent.setup();
    renderApp('/events?import=1');
    await user.selectOptions(screen.getByLabelText('Input format'), 'syslog');
    const year = screen.getByLabelText('Syslog year (UTC)');
    expect(year).toHaveAttribute('min', '1970');
    expect(year).toHaveAttribute('max', '2100');
    expect(screen.getByText(/UTC year from 1970 through 2100/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Event content'), {
      target: { value: 'Jan 15 10:00:00 fixture-host fixture: test event' },
    });
    fireEvent.change(year, { target: { value: '2101' } });
    expect(year).toBeInvalid();
    await user.click(screen.getByRole('button', { name: 'Ingest events' }));
    expect(fetch.mock.calls.some(([, init]) => init.method === 'POST')).toBe(false);
    fireEvent.change(year, { target: { value: '2100' } });
    expect(year).toBeValid();
    await user.click(screen.getByRole('button', { name: 'Ingest events' }));
    await waitFor(() => expect(screen.getByText('Import completed')).toBeInTheDocument());
    const request = fetch.mock.calls.find(
      ([url, init]) => url === '/api/events' && init.method === 'POST',
    );
    expect(JSON.parse(String(request?.[1].body))).toMatchObject({
      format: 'syslog',
      syslog_year: 2100,
    });
  });
});
