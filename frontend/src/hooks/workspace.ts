import { createContext, useContext } from 'react';
import type { Run } from '../types';

export interface Workspace {
  runId: string;
  runs: Run[];
  runsLoading: boolean;
  runsError: unknown;
  revision: number;
  refresh: () => void;
  setRunId: (id: string) => void;
}

export const WorkspaceContext = createContext<Workspace | null>(null);

export function useWorkspace(): Workspace {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error('Workspace context is required.');
  return value;
}
