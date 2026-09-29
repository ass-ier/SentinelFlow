const TOKEN_KEY = 'sentinelflow.token';
export const MAX_TOKEN_LENGTH = 256;
export const TOKEN_PATTERN = `[!-~]{0,${MAX_TOKEN_LENGTH}}`;
export const TOKEN_REQUIREMENTS = 'Use at most 256 printable ASCII characters with no whitespace.';

function validToken(token: string): boolean {
  return token.length <= MAX_TOKEN_LENGTH && !/[^\x21-\x7e]/.test(token);
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(message: string, status = 0, code = 'request_failed', requestId?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

export function getToken(): string {
  try {
    const token = sessionStorage.getItem(TOKEN_KEY) || '';
    return validToken(token) ? token : '';
  } catch {
    return '';
  }
}

export function saveToken(token: string): void {
  if (!validToken(token)) throw new Error(TOKEN_REQUIREMENTS);
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    throw new Error('Session storage is unavailable. Allow browser storage and retry.');
  }
}

function object(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function parseError(payload: unknown, status: number): ApiError {
  const root = object(payload);
  const error = object(root?.error);
  let message = typeof error?.message === 'string' ? error.message : '';
  if (!message && typeof root?.detail === 'string') message = root.detail;
  if (!message && Array.isArray(root?.detail)) {
    message = root.detail
      .map((entry: unknown) => {
        const detail = object(entry);
        if (typeof detail?.msg !== 'string') return '';
        const location = Array.isArray(detail.loc)
          ? detail.loc
              .filter((item) => typeof item === 'string' || typeof item === 'number')
              .filter((item) => item !== 'body')
              .join('.')
          : '';
        return location ? `${location}: ${detail.msg}` : detail.msg;
      })
      .filter(Boolean)
      .join('; ');
  }
  if (!message) message = `The request could not be completed (HTTP ${status}). Please retry.`;
  if ((status === 401 || status === 403) && error?.code !== 'public_demo_restricted') {
    message += ' Open Connection settings to check your API token.';
  }
  if (
    status === 409 &&
    (error?.code === 'late_events' || /watermark|out.of.order|late events|older/i.test(message))
  ) {
    message += ' For events older than a run’s watermark, start a new isolated import or replay.';
  }
  return new ApiError(
    message,
    status,
    typeof error?.code === 'string' ? error.code : 'request_failed',
    typeof root?.request_id === 'string' ? root.request_id : undefined,
  );
}

export async function api<T>(
  path: string,
  options: {
    method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
    body?: unknown;
    signal?: AbortSignal;
  } = {},
): Promise<T> {
  const token = getToken();
  const base = resolveApiBase(import.meta.env.VITE_API_BASE_URL);
  let response: Response;
  try {
    response = await fetch(`${base}${path}`, {
      method: options.method ?? 'GET',
      signal: options.signal,
      headers: {
        Accept: 'application/json',
        ...(options.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
    });
  } catch (error) {
    if (object(error)?.name === 'AbortError') throw error;
    throw new ApiError(
      'Cannot reach the SentinelFlow API. Check that the backend is running, then retry.',
      0,
      'network_error',
    );
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ApiError(
      response.ok
        ? 'The API returned an unreadable response. Check the backend connection and retry.'
        : `The API returned HTTP ${response.status} without a readable error. Check the backend and retry.`,
      response.status,
      'invalid_response',
    );
  }
  if (!response.ok) throw parseError(payload, response.status);
  return payload as T;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The operation failed. Please retry.';
}

export function queryString(
  values: Record<string, string | number | boolean | null | undefined>,
): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
  }
  return params.size ? `?${params.toString()}` : '';
}

export function route(
  path: string,
  runId?: string | null,
  params: Record<string, string | number | undefined> = {},
): string {
  return `${path}${queryString({ run_id: runId, ...params })}`;
}
import { resolveApiBase } from './apiBase';
