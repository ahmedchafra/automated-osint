import { createContext, useContext, useReducer, type ReactNode, type Dispatch } from 'react';
import type { LogEvent } from '../components/EventLog';
import type { FindingRow } from '../components/FindingsTable';

export type TabId = 'infrastructure' | 'identity' | 'secrets' | 'threat-intel' | 'brand' | 'web-osint';

export interface DomainDeepAnalysisProgress {
  collector: string;
  status: 'running' | 'done' | 'error';
  domain?: string;
  findings_count?: number;
  error?: string;
  /** Phase 2 (CVE) specific fields */
  technology?: string;
  phase?: 'domain' | 'cve';
  index?: number;
  total?: number;
}

export interface EmailDeepAnalysisProgress {
  email: string;
  index: number;
  total: number;
  collector: string;
  status: 'running' | 'done' | 'error';
  findings_count?: number;
  error?: string;
}

export interface ScanJob {
  id: string;
  scan_id: string;
  celery_task_id: string;
  job_type: string;
  stage: string;
  status: 'QUEUED' | 'RUNNING' | 'RETRYING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  input_type?: string | null;
  input_value?: string | null;
  progress: {
    event?: string;
    payload?: Record<string, unknown>;
    updated_at?: string;
  };
  result_summary: Record<string, unknown>;
  error?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  updated_at: string;
}

export interface ScanWorkspaceState {
  scan: any | null;
  findings: FindingRow[];
  jobs: ScanJob[];
  wsConnected: boolean;
  activeTab: TabId;
  eventLog: LogEvent[];
  completedVectors: string[];
  totalVectors: number;
  pivotEmail: string | null;
  pivotStatus: 'idle' | 'running' | 'done' | 'error';
  pivotFindings: FindingRow[];
  filters: {
    severity: string;
    entityType: string;
    search: string;
  };
  activeEntityTypes: string[];
  // Domain deep analysis state
  domainDeepAnalysisRunning: boolean;
  domainDeepAnalysisDomain: string | null;
  domainDeepAnalysisProgress: DomainDeepAnalysisProgress[];
  // Email deep analysis state
  emailDeepAnalysisRunning: boolean;
  emailDeepAnalysisEmails: string[];
  emailDeepAnalysisProgress: EmailDeepAnalysisProgress[];
  // Breach check state
  breachCheckRunning: boolean;
  breachCheckProgress: { email: string; index: number; total: number; status: string; found?: number }[];
  // Org scan domain enrichment
  activeEnrichmentDomain: string | null;
}

export type ScanWorkspaceAction =
  | { type: 'SCAN_LOADED'; scan: any; payload?: any }
  | { type: 'SET_TOTAL_VECTORS'; total: number }
  | { type: 'FINDINGS_UPDATED'; findings: FindingRow[]; payload?: any }
  | { type: 'JOBS_UPDATED'; jobs: ScanJob[] }
  | { type: 'FINDING_PUSHED'; finding: FindingRow; payload?: any }
  | { type: 'WS_CONNECTED' }
  | { type: 'WS_DISCONNECTED' }
  | { type: 'VECTOR_COMPLETED'; vector: string; stage?: string; findingsCreated?: number }
  | { type: 'EVENT_LOG'; event: LogEvent; payload?: any }
  | { type: 'TAB_CHANGED'; tab: TabId }
  | { type: 'FILTERS_CHANGED'; filters: Partial<ScanWorkspaceState['filters']> }
  | { type: 'ENTITY_TYPES_CHANGED'; types: string[] }
  | { type: 'PIVOT_STARTED'; email: string }
  | { type: 'PIVOT_STATUS'; status: 'running' | 'done' | 'error' }
  | { type: 'PIVOT_FINDINGS'; findings: FindingRow[] }
  | { type: 'PIVOT_RESET' }
  | { type: 'SET_TAB'; tab: TabId }
  | { type: 'DOMAIN_DEEP_ANALYSIS_STARTED'; domain: string }
  | { type: 'DOMAIN_DEEP_ANALYSIS_PROGRESS'; payload: any }
  | { type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED'; payload: any }
  | { type: 'EMAIL_DEEP_ANALYSIS_STARTED'; emails: string[] }
  | { type: 'EMAIL_DEEP_ANALYSIS_PROGRESS'; payload: any }
  | { type: 'EMAIL_DEEP_ANALYSIS_COMPLETED'; payload: any }
  | { type: 'BREACH_CHECK_STARTED'; emails: string[] }
  | { type: 'BREACH_CHECK_PROGRESS'; payload: any }
  | { type: 'BREACH_CHECK_COMPLETED'; payload: any }
  | { type: 'SET_ENRICHMENT_DOMAIN'; domain: string | null }
  | { type: 'DOMAIN_DEEP_ANALYSIS_CLOSED' };

const INITIAL_STATE: ScanWorkspaceState = {
  scan: null,
  findings: [],
  jobs: [],
  wsConnected: false,
  activeTab: 'infrastructure',
  eventLog: [],
  completedVectors: [],
  totalVectors: 0,
  pivotEmail: null,
  pivotStatus: 'idle',
  pivotFindings: [],
  filters: { severity: '', entityType: '', search: '' },
  activeEntityTypes: [],
  domainDeepAnalysisRunning: false,
  domainDeepAnalysisDomain: null,
  domainDeepAnalysisProgress: [],
  emailDeepAnalysisRunning: false,
  emailDeepAnalysisEmails: [],
  emailDeepAnalysisProgress: [],
  breachCheckRunning: false,
  breachCheckProgress: [],
  activeEnrichmentDomain: null,
};

function reducer(state: ScanWorkspaceState, action: ScanWorkspaceAction): ScanWorkspaceState {
  switch (action.type) {
    case 'SCAN_LOADED':
      return { ...state, scan: action.scan };
    case 'SET_TOTAL_VECTORS':
      return { ...state, totalVectors: action.total };
    case 'FINDINGS_UPDATED':
      return { ...state, findings: action.findings };
    case 'JOBS_UPDATED':
      return { ...state, jobs: action.jobs };
    case 'FINDING_PUSHED':
      return { ...state, findings: [...state.findings, action.finding] };
    case 'WS_CONNECTED':
      return { ...state, wsConnected: true };
    case 'WS_DISCONNECTED':
      return { ...state, wsConnected: false };
    case 'VECTOR_COMPLETED':
      return {
        ...state,
        completedVectors: state.completedVectors.includes(action.vector)
          ? state.completedVectors
          : [...state.completedVectors, action.vector],
      };
    case 'EVENT_LOG':
      return {
        ...state,
        eventLog: [action.event, ...state.eventLog].slice(0, 80),
      };
    case 'TAB_CHANGED':
      return { ...state, activeTab: action.tab };
    case 'FILTERS_CHANGED':
      return { ...state, filters: { ...state.filters, ...action.filters } };
    case 'ENTITY_TYPES_CHANGED':
      return { ...state, activeEntityTypes: action.types };
    case 'PIVOT_STARTED':
      return { ...state, pivotEmail: action.email, pivotStatus: 'running', pivotFindings: [] };
    case 'PIVOT_STATUS':
      return { ...state, pivotStatus: action.status };
    case 'PIVOT_FINDINGS':
      return { ...state, pivotFindings: action.findings, pivotStatus: 'done' };
    case 'PIVOT_RESET':
      return { ...state, pivotEmail: null, pivotStatus: 'idle', pivotFindings: [] };
    case 'SET_TAB':
      return { ...state, activeTab: action.tab };
    case 'DOMAIN_DEEP_ANALYSIS_STARTED':
      return {
        ...state,
        domainDeepAnalysisRunning: true,
        domainDeepAnalysisDomain: action.domain,
        domainDeepAnalysisProgress: [],
      };
    case 'DOMAIN_DEEP_ANALYSIS_PROGRESS':
      return {
        ...state,
        domainDeepAnalysisProgress: [
          ...state.domainDeepAnalysisProgress.filter(p => p.collector !== action.payload.collector),
          action.payload,
        ],
      };
    case 'DOMAIN_DEEP_ANALYSIS_COMPLETED':
      return { ...state, domainDeepAnalysisRunning: false };
    case 'EMAIL_DEEP_ANALYSIS_STARTED':
      return {
        ...state,
        emailDeepAnalysisRunning: true,
        emailDeepAnalysisEmails: action.emails,
        emailDeepAnalysisProgress: [],
      };
    case 'EMAIL_DEEP_ANALYSIS_PROGRESS':
      return {
        ...state,
        emailDeepAnalysisProgress: [
          ...state.emailDeepAnalysisProgress.filter(
            p => !(p.email === action.payload.email && p.collector === action.payload.collector)
          ),
          action.payload,
        ],
      };
    case 'EMAIL_DEEP_ANALYSIS_COMPLETED':
      return { ...state, emailDeepAnalysisRunning: false };
    case 'BREACH_CHECK_STARTED':
      return {
        ...state,
        breachCheckRunning: true,
        breachCheckProgress: [],
      };
    case 'BREACH_CHECK_PROGRESS':
      return {
        ...state,
        breachCheckProgress: [
          ...state.breachCheckProgress.filter(
            p => !(p.email === action.payload.email && p.status === 'checking')
          ),
          action.payload,
        ],
      };
    case 'BREACH_CHECK_COMPLETED':
      return { ...state, breachCheckRunning: false };
    case 'SET_ENRICHMENT_DOMAIN':
      return { ...state, activeEnrichmentDomain: action.domain };
    case 'DOMAIN_DEEP_ANALYSIS_CLOSED':
      return {
        ...state,
        domainDeepAnalysisDomain: null,
        domainDeepAnalysisRunning: false,
      };
    default:
      return state;
  }
}

const ScanWorkspaceContext = createContext<{
  state: ScanWorkspaceState;
  dispatch: Dispatch<ScanWorkspaceAction>;
}>({ state: INITIAL_STATE, dispatch: () => {} });

export function ScanWorkspaceProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, INITIAL_STATE);
  return (
    <ScanWorkspaceContext.Provider value={{ state, dispatch }}>
      {children}
    </ScanWorkspaceContext.Provider>
  );
}

export function useScanWorkspace() {
  return useContext(ScanWorkspaceContext);
}
