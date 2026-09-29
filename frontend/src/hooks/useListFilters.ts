import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { queryString } from '../services/api';

export function useListFilters(keys: readonly string[]) {
  const [params, setParams] = useSearchParams();
  const serialized = params.toString();
  const initial = () => Object.fromEntries(keys.map((key) => [key, params.get(key) || '']));
  const [draft, setDraft] = useState<Record<string, string>>(initial);
  useEffect(() => {
    const current = new URLSearchParams(serialized);
    setDraft(Object.fromEntries(keys.map((key) => [key, current.get(key) || ''])));
  }, [serialized, keys]);

  const parsedLimit = Number(params.get('limit') || 25);
  const parsedOffset = Number(params.get('offset') || 0);
  const limit = [25, 50, 100].includes(parsedLimit) ? parsedLimit : 25;
  const offset = Number.isSafeInteger(parsedOffset) && parsedOffset >= 0 ? parsedOffset : 0;
  const active = keys
    .filter((key) => params.get(key))
    .map((key) => [key, params.get(key)!] as const);
  const query = queryString({
    ...Object.fromEntries(active),
    run_id: params.get('run_id'),
    offset,
    limit,
  });

  function setField(key: string, value: string) {
    setDraft((previous) => ({ ...previous, [key]: value }));
  }
  function apply() {
    const next = new URLSearchParams(params);
    keys.forEach((key) => {
      if (draft[key]?.trim()) next.set(key, draft[key].trim());
      else next.delete(key);
    });
    next.delete('offset');
    setParams(next);
  }
  function clear() {
    const next = new URLSearchParams(params);
    keys.forEach((key) => next.delete(key));
    next.delete('offset');
    setParams(next);
  }
  function remove(key: string) {
    const next = new URLSearchParams(params);
    next.delete(key);
    next.delete('offset');
    setParams(next);
  }
  function paginate(newOffset: number, newLimit: number) {
    const next = new URLSearchParams(params);
    next.set('offset', String(newOffset));
    next.set('limit', String(newLimit));
    setParams(next);
  }

  return { draft, setField, apply, clear, remove, active, limit, offset, query, paginate };
}
