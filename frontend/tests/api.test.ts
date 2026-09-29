import { describe, expect, it, vi } from 'vitest';
import { api, ApiError, getToken, queryString, route, saveToken } from '../src/services/api';
import {
  fromUtcInput,
  MAX_UPLOAD_BYTES,
  number,
  readTextFile,
  safeUrl,
  utc,
  validateContent,
} from '../src/services/format';
import { json } from './helpers';

describe('API contract', () => {
  it('uses the same-origin /api prefix and no implicit authorization', async () => {
    const fetch = vi.fn().mockResolvedValue(json({ events_processed: 23 }));
    vi.stubGlobal('fetch', fetch);
    await expect(api('/dashboard')).resolves.toEqual({ events_processed: 23 });
    expect(fetch).toHaveBeenCalledWith(
      '/api/dashboard',
      expect.objectContaining({ method: 'GET', headers: { Accept: 'application/json' } }),
    );
  });

  it('sends the entered session token and serializes mutation bodies exactly', async () => {
    saveToken('test-only-token');
    const fetch = vi.fn().mockResolvedValue(json({ status: 'investigating' }));
    vi.stubGlobal('fetch', fetch);
    await api('/alerts/a/status', {
      method: 'PATCH',
      body: { status: 'investigating', note: 'Fixture note' },
    });
    expect(fetch).toHaveBeenCalledWith(
      '/api/alerts/a/status',
      expect.objectContaining({
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          Authorization: 'Bearer test-only-token',
        },
        body: '{"status":"investigating","note":"Fixture note"}',
        method: 'PATCH',
      }),
    );
    saveToken('');
    expect(getToken()).toBe('');
  });

  it('preserves structured error codes and request IDs', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        json(
          {
            error: { code: 'invalid_event', message: 'Event 3 has no timestamp.' },
            request_id: 'request-fixture-1',
          },
          400,
        ),
      ),
    );
    await expect(api('/events')).rejects.toMatchObject({
      message: 'Event 3 has no timestamp.',
      status: 400,
      code: 'invalid_event',
      requestId: 'request-fixture-1',
    });
  });

  it('handles FastAPI validation errors without assuming their shape', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        json(
          {
            detail: [
              { loc: ['body', 'content'], msg: 'Invalid JSON' },
              { loc: ['body', 'events', 2], msg: 'Missing timestamp' },
              null,
            ],
          },
          422,
        ),
      ),
    );
    await expect(api('/events')).rejects.toThrow(
      'content: Invalid JSON; events.2: Missing timestamp',
    );
  });

  it('handles string detail errors and provides authorization guidance', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ detail: 'Token required' }, 401)));
    await expect(api('/rules')).rejects.toThrow('Token required Open Connection settings');
  });

  it('gives actionable guidance for late-batch conflicts', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          json({ error: { code: 'late_events', message: 'Older than run watermark.' } }, 409),
        ),
    );
    await expect(api('/events')).rejects.toThrow('new isolated import or replay');
  });

  it('does not add ingestion advice to an unrelated rule-import conflict', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        json(
          {
            error: { code: 'rule_conflict', message: 'A rule with this ID already exists' },
          },
          409,
        ),
      ),
    );
    await expect(api('/sigma/import')).rejects.toMatchObject({
      message: 'A rule with this ID already exists',
    });
  });

  it('does not turn a network failure into empty successful data', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    await expect(api('/dashboard')).rejects.toMatchObject({ code: 'network_error', status: 0 });
  });

  it('preserves aborts rather than displaying them as server failures', async () => {
    const error = new DOMException('Aborted', 'AbortError');
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(error));
    await expect(api('/dashboard')).rejects.toBe(error);
  });

  it.each([200, 502])('rejects non-JSON responses with HTTP %i', async (status) => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response('<html>Proxy failure</html>', { status })),
    );
    await expect(api('/dashboard')).rejects.toBeInstanceOf(ApiError);
  });

  it('encodes filters and retains meaningful zero and false values', () => {
    expect(
      queryString({ q: 'a & b', offset: 0, enabled: false, absent: undefined, empty: '' }),
    ).toBe('?q=a+%26+b&offset=0&enabled=false');
    expect(route('/events', 'run / 1', { source_ip: '192.0.2.7' })).toBe(
      '/events?run_id=run+%2F+1&source_ip=192.0.2.7',
    );
  });
});

describe('untrusted evidence boundaries', () => {
  it('rejects executable external links without altering their visible text', () => {
    expect(safeUrl('javascript:alert(1)')).toBeUndefined();
    expect(safeUrl('data:text/html,unsafe')).toBeUndefined();
    expect(safeUrl('https://example.test/source')).toBe('https://example.test/source');
  });

  it('uses UTC rather than the viewer’s timezone for search boundaries', () => {
    expect(fromUtcInput('2026-01-15T10:12')).toBe('2026-01-15T10:12:00Z');
    expect(utc('2026-01-15T10:12:00Z')).toBe('2026-01-15 10:12:00');
  });

  it('preserves precise event bounds and small measured values', () => {
    expect(utc('2026-01-15T10:12:00.000123Z')).toBe('2026-01-15 10:12:00.000123');
    expect(utc('2026-01-15T13:12:00+03:00')).toBe('2026-01-15 10:12:00');
    expect(number(0.0000123)).toBe('0.0000123');
  });

  it('reads supported files as text', async () => {
    const file = new File(['<script>inert</script>'], 'fixture.jsonl');
    await expect(readTextFile(file, ['.jsonl'])).resolves.toBe('<script>inert</script>');
  });

  it('rejects oversized files before reading them', async () => {
    const file = new File(['small'], 'fixture.jsonl');
    Object.defineProperty(file, 'size', { value: MAX_UPLOAD_BYTES + 1 });
    await expect(readTextFile(file, ['.jsonl'])).rejects.toThrow('5 MiB');
  });

  it('rejects unsupported file extensions', async () => {
    await expect(readTextFile(new File(['file'], 'fixture.exe'), ['.jsonl'])).rejects.toThrow(
      'Unsupported file type',
    );
  });

  it('rejects empty and over-limit pasted content in UTF-8 bytes', () => {
    expect(() => validateContent(' \n ')).toThrow('Choose a file');
    expect(() => validateContent('界'.repeat(Math.floor(MAX_UPLOAD_BYTES / 3) + 1))).toThrow(
      '5 MiB',
    );
  });
});
