import { render } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { vi } from 'vitest';
import { App } from '../src/App';
import {
  alert,
  alertDetail,
  benignDataset,
  dashboard,
  dataset,
  event,
  rule,
  run,
  sigmaSample,
} from './fixtures';

interface RequestContext {
  url: URL;
  init: RequestInit;
  body: Record<string, unknown>;
}
type Handler = (context: RequestContext) => unknown | Promise<unknown>;

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function mockApi(overrides: Record<string, unknown | Handler> = {}) {
  const defaults: Record<string, unknown> = {
    'GET /api/health': { status: 'ok', version: '0.1.0', auth_required: false },
    'GET /api/runs': { items: [run], total: 1 },
    'GET /api/dashboard': dashboard,
    'GET /api/events/search': { items: [event], total: 1, offset: 0, limit: 25 },
    'GET /api/events/storage-event-1': event,
    'GET /api/alerts': { items: [alert], total: 1, offset: 0, limit: 25 },
    'GET /api/alerts/alert-1': alertDetail,
    'GET /api/rules': { items: [rule], total: 1 },
    'GET /api/rules/AUTH-001': rule,
    'GET /api/datasets': { items: [dataset, benignDataset], total: 2 },
    'GET /api/sigma/samples': { items: [sigmaSample] },
    'GET /api/project/evidence': {
      validation: null,
      benchmark: null,
      validation_log: '',
      validation_running: false,
      files: [],
      documents: [],
    },
  };
  const handlers = { ...defaults, ...overrides };
  const fetch = vi.fn(async (input: RequestInfo | URL, init: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    const key = `${init.method || 'GET'} ${url.pathname}`;
    const handler = handlers[key];
    if (handler === undefined)
      return json({ error: { code: 'not_found', message: `No test API handler: ${key}` } }, 404);
    const body =
      typeof init.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : {};
    const result =
      typeof handler === 'function' ? await (handler as Handler)({ url, init, body }) : handler;
    return result instanceof Response ? result : json(result);
  });
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

function LocationProbe() {
  const location = useLocation();
  return (
    <output data-testid="location" hidden>
      {location.pathname}
      {location.search}
    </output>
  );
}

export function renderApp(path = '/') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
      <LocationProbe />
    </MemoryRouter>,
  );
}

export function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
