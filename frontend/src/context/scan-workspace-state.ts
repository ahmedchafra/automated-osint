import { createContext, useContext, type Dispatch } from 'react';
import type { ScanWorkspaceAction, ScanWorkspaceState } from './ScanWorkspaceContext';

export const ScanWorkspaceStateContext = createContext<{
  state: ScanWorkspaceState;
  dispatch: Dispatch<ScanWorkspaceAction>;
} | undefined>(undefined);

export function useScanWorkspace() {
  const context = useContext(ScanWorkspaceStateContext);
  if (!context) throw new Error('useScanWorkspace must be used within ScanWorkspaceProvider');
  return context;
}
