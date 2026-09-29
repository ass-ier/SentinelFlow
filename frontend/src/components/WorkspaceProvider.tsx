import { useCallback, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { WorkspaceContext } from '../hooks/workspace';
import { useResource } from '../hooks/useResource';
import type { Collection, Health, Run } from '../types';

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [params, setParams] = useSearchParams();
  const [revision, setRevision] = useState(0);
  const runs = useResource<Collection<Run>>('/runs', { refreshKey: revision });
  const health = useResource<Health>('/health', { refreshKey: revision, pollMs: 15000 });
  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  const runId = params.get('run_id') || '';
  const setRunId = useCallback(
    (id: string) => {
      setParams((previous) => {
        const next = new URLSearchParams(previous);
        if (id) next.set('run_id', id);
        else next.delete('run_id');
        next.delete('offset');
        return next;
      });
    },
    [setParams],
  );
  const value = useMemo(
    () => ({
      runId,
      runs: runs.data?.items ?? [],
      runsLoading: runs.loading,
      runsError: runs.error,
      publicDemo: health.data?.public_demo === true,
      health: { data: health.data, loading: health.loading, error: health.error },
      revision,
      refresh,
      setRunId,
    }),
    [
      runId,
      runs.data,
      runs.loading,
      runs.error,
      health.data,
      health.loading,
      health.error,
      revision,
      refresh,
      setRunId,
    ],
  );
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}
