import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../services/api';

interface ResourceState<T> {
  path: string | null;
  data: T | null;
  error: unknown;
  loading: boolean;
  refreshing: boolean;
}

interface ResourceOptions<T> {
  refreshKey?: string | number;
  pollMs?: number;
  pollWhile?: (data: T | null) => boolean;
}

export function useResource<T>(path: string | null, options: ResourceOptions<T> = {}) {
  const [state, setState] = useState<ResourceState<T>>({
    path,
    data: null,
    error: null,
    loading: path !== null,
    refreshing: false,
  });
  const [generation, setGeneration] = useState(0);
  const polling = useRef(options);
  polling.current = options;
  const refreshKey = options.refreshKey ?? 0;

  useEffect(() => {
    if (path === null) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let lastData: T | null = null;
    const controller = new AbortController();

    async function load(first: boolean) {
      if (first) {
        setState((previous) => ({
          path,
          data: previous.path === path ? previous.data : null,
          error: null,
          loading: previous.path !== path || previous.data === null,
          refreshing: previous.path === path && previous.data !== null,
        }));
      }
      try {
        const data = await api<T>(path!, { signal: controller.signal });
        lastData = data;
        if (!stopped) setState({ path, data, error: null, loading: false, refreshing: false });
      } catch (error) {
        if (!stopped) {
          setState((previous) => ({
            path,
            data: previous.path === path ? previous.data : null,
            error,
            loading: false,
            refreshing: false,
          }));
        }
      } finally {
        const { pollMs, pollWhile } = polling.current;
        if (!stopped && pollMs && (!pollWhile || pollWhile(lastData))) {
          timer = setTimeout(() => void load(false), pollMs);
        }
      }
    }
    void load(true);
    return () => {
      stopped = true;
      controller.abort();
      clearTimeout(timer);
    };
  }, [path, generation, refreshKey]);

  const reload = useCallback(() => setGeneration((value) => value + 1), []);
  const update = useCallback(
    (updater: T | ((previous: T) => T)) => {
      setState((previous) => {
        if (previous.path !== path) return previous;
        const data =
          typeof updater === 'function'
            ? previous.data === null
              ? null
              : (updater as (previous: T) => T)(previous.data)
            : updater;
        return { ...previous, data, error: null, loading: false };
      });
    },
    [path],
  );

  const current =
    state.path === path
      ? state
      : { path, data: null, error: null, loading: path !== null, refreshing: false };
  return { ...current, reload, update };
}
