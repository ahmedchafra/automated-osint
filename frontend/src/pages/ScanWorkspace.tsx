import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Crosshair, Loader2, Shield, AlertTriangle, ChevronRight,
  Globe, Server, Building2, Mail, Search, CheckCircle2, XCircle,
  Zap, ArrowRight, RotateCcw, Activity, Trash2, StopCircle,
  Download, FileSpreadsheet, Lock, Share2,
} from 'lucide-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import apiClient, { deleteScan, cancelScan, triggerOrgInfra } from '../api/client';
import { openScanWebSocket } from '../api/ws';
import { useScanWorkspace } from '../context/ScanWorkspaceContext';
import { useAuth } from '../context/AuthContext';
import { useNotification } from '../context/NotificationContext';
import type { ScanEvent } from '../api/ws';
import type { AssetRecord, ScanJob, TabId, ScanWorkspaceState, ScanWorkspaceAction } from '../context/ScanWorkspaceContext';
import ErrorBoundary from '../components/ErrorBoundary';
import { InfrastructureTab } from '../components/workspace/InfrastructureTab';
import { IdentityTab } from '../components/workspace/IdentityTab';
import { ThreatIntelTab } from '../components/workspace/ThreatIntelTab';
import { BrandProtectionTab } from '../components/workspace/BrandProtectionTab';
import { SecretsTab } from '../components/workspace/SecretsTab';
import { WebOsintTab } from '../components/workspace/WebOsintTab';
import { PipelineProgress } from '../components/workspace/PipelineProgress';
import CollaboratorModal from '../components/workspace/CollaboratorModal';

/* ─── Types ─────────────────────────────────────────────────────────── */

interface ToolEvent {
  id: string;
  tool: string;
  status: 'running' | 'completed' | 'error' | 'timeout';
  target?: string;
  collected?: number;
  elapsed?: number;
  error?: string;
}

interface PhaseEvent {
  phase: string;
  phase_index: number;
  status: 'started' | 'completed';
  result?: Record<string, unknown>;
}

interface ScanResult {
  scan_id: string;
  status: string;
  total_findings?: number;
  links_created?: number;
  phases?: Record<string, unknown>;
}

type AppView = 'loading' | 'input' | 'pipeline' | 'results';

const ACTIVE_JOB_STATUSES = new Set(['QUEUED', 'RUNNING', 'RETRYING']);
const TERMINAL_JOB_STATUSES = new Set(['COMPLETED', 'FAILED', 'CANCELLED']);

const JOB_LABELS: Record<string, string> = {
  execute_scan: 'Full scan',
  execute_initial_scan: 'Domain discovery',
  execute_ip_scan: 'IP discovery',
  execute_org_scan: 'Organization discovery',
  execute_org_infra: 'Organization enrichment',
  domain_deep_analysis: 'Domain deep analysis',
  email_deep_analysis: 'Email deep analysis',
  email_breach_check: 'Breach check',
  github_secrets_scan: 'GitHub secrets',
  shodan_enrich: 'Shodan enrichment',
  censys_enrich: 'Censys enrichment',
  dnstwist_only: 'Lookalike domains',
  ahmia_search: 'Dark-web search',
  telegram_monitor: 'Telegram monitor',
  run_ai_dork_task: 'AI search',
  active_validation: 'Active validation',
};

function JobActivityPanel({ jobs }: { jobs: ScanJob[] }) {
  if (jobs.length === 0) return null;
  const activeCount = jobs.filter(job => ACTIVE_JOB_STATUSES.has(job.status)).length;
  const visibleJobs = jobs.slice(0, 8);

  return (
    <div style={{
      margin: '0 0 16px', borderRadius: 'var(--radius-lg)',
      background: 'var(--bg-secondary)', border: '1px solid var(--border)', overflow: 'hidden',
    }}>
      <div style={{
        padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 8,
        borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600,
      }}>
        {activeCount > 0 ? <Loader2 size={14} className="spin" style={{ color: 'var(--accent)' }} /> : <Activity size={14} />}
        <span>Background jobs</span>
        <span style={{ marginLeft: 'auto', color: activeCount > 0 ? 'var(--accent)' : 'var(--text-muted)', fontSize: 11 }}>
          {activeCount > 0 ? `${activeCount} active` : 'idle'}
        </span>
      </div>
      {visibleJobs.map(job => {
        const active = ACTIVE_JOB_STATUSES.has(job.status);
        const failed = job.status === 'FAILED';
        const progressPayload = job.progress?.payload;
        const progressLabel = typeof progressPayload?.phase === 'string'
          ? progressPayload.phase
          : typeof progressPayload?.tool === 'string'
            ? progressPayload.tool
            : job.progress?.event?.replaceAll('_', ' ');
        return (
          <div key={job.id} style={{
            padding: '7px 14px', display: 'flex', alignItems: 'center', gap: 8,
            borderBottom: '1px solid var(--border)', fontSize: 11,
          }}>
            {active ? <Loader2 size={12} className="spin" style={{ color: 'var(--accent)' }} />
              : failed ? <XCircle size={12} style={{ color: '#ef4444' }} />
                : <CheckCircle2 size={12} style={{ color: job.status === 'CANCELLED' ? '#f59e0b' : '#10b981' }} />}
            <span style={{ color: 'var(--text-strong)', fontWeight: 500 }}>
              {JOB_LABELS[job.job_type] || job.job_type}
            </span>
            {job.input_value && (
              <span style={{
                color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 280,
              }}>
                {job.input_value}
              </span>
            )}
            {progressLabel && active && (
              <span style={{ color: 'var(--accent)', fontSize: 10 }}>
                {progressLabel}
              </span>
            )}
            <span style={{ marginLeft: 'auto', color: failed ? '#ef4444' : 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {job.status.toLowerCase()}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/* ─── Tool metadata ─────────────────────────────────────────────────── */

const PHASE_ORDER = ['INFRASTRUCTURE', 'SERVICES', 'IDENTITY', 'SEARCH'];

// Each tab declares which entity_types belong to it. Adding a new
// entity_type to the backend enums is now a one-line change here — the
// badge counts and filter logic both read from this single source of
// truth. The list mirrors `backend/app/schemas/enums.py:EntityType`.
type TabConfig = { id: TabId; label: string; icon: typeof Globe; entityTypes: string[] };

const TABS: TabConfig[] = [
  {
    id: 'infrastructure',
    label: 'Infrastructure',
    icon: Globe,
    entityTypes: ['SUBDOMAIN', 'IP_ADDRESS', 'PORT_SERVICE', 'HOST_METADATA', 'DNS_RECORD', 'TLS_CERT', 'ASN_INFO', 'URL', 'DOMAIN_METADATA'],
  },
  {
    id: 'identity',
    label: 'Identity',
    icon: Mail,
    entityTypes: ['EMAIL', 'BREACH', 'EMAIL_PLATFORM', 'PROFILE'],
  },
  {
    id: 'web-osint',
    label: 'Web OSINT',
    icon: Globe,
    entityTypes: ['TECHNOLOGY', 'HTTP_HEADER', 'HISTORICAL_URL', 'WAYBACK_SNAPSHOT', 'CVE', 'VULNERABILITY'],
  },
  {
    id: 'secrets',
    label: 'Secrets',
    icon: Search,
    entityTypes: ['LEAKED_SECRET', 'GITHUB_REPO', 'CREDENTIAL'],
  },
  {
    id: 'threat-intel',
    label: 'Threat Intel',
    icon: Activity,
    entityTypes: ['TELEGRAM_MESSAGE', 'TELEGRAM_CHANNEL', 'ONION_SITE', 'DARKWEB_MENTION'],
  },
  {
    id: 'brand',
    label: 'Brand Protection',
    icon: Shield,
    entityTypes: ['LOOKALIKE_DOMAIN', 'PHISHING_SITE', 'CLOUD_BUCKET', 'EXPOSED_FILE', 'DORK_RESULT'],
  },
];

/* ─── Input view ────────────────────────────────────────────────────── */

function InputView({ onSubmit, error }: { onSubmit: (d: string) => void; error: string | null }) {
  const [domain, setDomain] = useState('');
  return (
    <motion.div
      className="pipeline-input-view"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
    >
      <div className="pipeline-input-hero">
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.5 }}
        >
          <Crosshair size={48} className="pipeline-input-icon" />
        </motion.div>
        <h1 className="pipeline-input-title">Launch Reconnaissance</h1>
        <p className="pipeline-input-subtitle">
          Enter a target domain. All intelligence vectors will execute sequentially
          with real-time results streamed as each tool completes.
        </p>
      </div>

      <form className="pipeline-input-form" onSubmit={(e) => { e.preventDefault(); onSubmit(domain.trim()); }}>
        <div className="pipeline-input-row">
          <Globe size={18} style={{ color: 'var(--text-muted)' }} />
          <input
            type="text"
            className="pipeline-input"
            placeholder="utm.tn"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            autoFocus
            spellCheck={false}
          />
          <motion.button
            type="submit"
            className="pipeline-launch-btn"
            disabled={!domain}
            whileHover={domain ? { scale: 1.02 } : undefined}
            whileTap={domain ? { scale: 0.97 } : undefined}
          >
            <Zap size={16} />
            <span>Launch</span>
          </motion.button>
        </div>
      </form>

      {error && (
        <motion.div
          className="pipeline-error"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <AlertTriangle size={16} />
          <span>{error}</span>
        </motion.div>
      )}

      <div className="pipeline-phases-preview">
        {PHASE_ORDER.map((phase, i) => (
          <motion.div
            key={phase}
            className="phase-preview-item"
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 + i * 0.1 }}
          >
            <div className="phase-preview-dot" />
            <span>{phase}</span>
            {i < PHASE_ORDER.length - 1 && <ArrowRight size={12} className="phase-preview-arrow" />}
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}

/* ─── Pipeline view ─────────────────────────────────────────────────── */

const TARGET_TYPE_ICONS: Record<string, typeof Globe> = {
  domain: Globe,
  ip: Server,
  organization: Building2,
};

const TARGET_TYPE_LABELS: Record<string, string> = {
  domain: 'Domain',
  ip: 'IP',
  organization: 'Organization',
};

function PipelineView({ scanId, targetDomain, targetType = 'domain', onComplete }: {
  scanId: string; targetDomain: string; targetType?: string; onComplete: (result: ScanResult) => void;
}) {
  const [tools, setTools] = useState<ToolEvent[]>([]);
  const [phases, setPhases] = useState<PhaseEvent[]>([]);
  const [declaredPhases, setDeclaredPhases] = useState<string[]>([]);
  const [currentPhase, setCurrentPhase] = useState('');
  const [overallStatus, setOverallStatus] = useState<'running' | 'completed' | 'error'>('running');
  const { addNotification } = useNotification();
  const queryClient = useQueryClient();
  const wsRef = useRef<WebSocket | null>(null);
  const toolSequence = useRef(0);
  const completionHandled = useRef(false);
  const terminalFailureHandled = useRef(false);

  const { data: persistedScan } = useQuery({
    queryKey: ['scanWorkspace', scanId],
    queryFn: async () => (await apiClient.get(`/scans/${scanId}`)).data,
    refetchInterval: 2_000,
  });
  const { data: pipelineJobs = [] } = useQuery<ScanJob[]>({
    queryKey: ['scanJobs', scanId],
    queryFn: async () => (await apiClient.get(`/scans/${scanId}/jobs`)).data,
    refetchInterval: 2_000,
  });

  useEffect(() => {
    if (!persistedScan || completionHandled.current) return;
    if (persistedScan.status === 'COMPLETED') {
      completionHandled.current = true;
      onComplete({
        scan_id: scanId,
        status: 'COMPLETED',
        total_findings: persistedScan.findings_count || 0,
        links_created: persistedScan.links_count || 0,
      });
    } else if (
      ['FAILED', 'CANCELLED'].includes(persistedScan.status)
      && !terminalFailureHandled.current
    ) {
      terminalFailureHandled.current = true;
      addNotification({
        type: 'error',
        title: persistedScan.status === 'CANCELLED' ? 'Scan Cancelled' : 'Scan Failed',
        message: targetDomain,
      });
    }
  }, [persistedScan, scanId, targetDomain, onComplete, addNotification]);

  useEffect(() => {
    const connectTimer = window.setTimeout(() => {
      wsRef.current = openScanWebSocket(scanId, (event: ScanEvent) => {
      switch (event.event) {
        case 'scan_started':
          if (Array.isArray(event.phases)) {
            setDeclaredPhases(event.phases.filter((phase): phase is string => typeof phase === 'string'));
          }
          break;
        case 'phase_started':
          setCurrentPhase(event.phase as string);
          setPhases(prev => [...prev, { phase: event.phase as string, phase_index: event.phase_index as number, status: 'started' }]);
          break;
        case 'phase_completed':
          setPhases(prev => [...prev.filter(p => p.phase !== event.phase), {
            phase: event.phase as string,
            phase_index: event.phase_index as number,
            status: 'completed',
            result: event.result as Record<string, unknown> | undefined,
          }]);
          break;
        case 'tool_started':
          setTools(prev => [...prev, {
            id: `${String(event.tool)}:${String(event.target ?? '')}:${toolSequence.current++}`,
            tool: event.tool as string,
            status: 'running' as const,
            target: event.target as string,
          }].slice(-200));
          break;
        case 'tool_completed':
          setTools(prev => updateFirstRunningTool(prev, event, {
            status: 'completed', collected: event.collected as number,
            elapsed: event.elapsed_seconds as number,
          }));
          // Findings were persisted before this event — trigger immediate refetch
          queryClient.invalidateQueries({ queryKey: ['scanFindings', scanId] });
          break;
        case 'tool_error':
          setTools(prev => updateFirstRunningTool(prev, event, {
            status: 'error', error: event.error as string,
          }));
          break;
        case 'tool_timeout':
          setTools(prev => updateFirstRunningTool(prev, event, {
            status: 'timeout', elapsed: event.elapsed_seconds as number,
          }));
          break;
        case 'scan_completed':
          completionHandled.current = true;
          setOverallStatus('completed');
          addNotification({
            type: 'success',
            title: 'Scan Complete',
            message: `${targetDomain} — ${event.total_findings ?? '?'} findings collected`,
          });
          onComplete({ scan_id: scanId, status: 'COMPLETED', total_findings: event.total_findings as number, links_created: event.links_created as number, phases: event.phases as Record<string, unknown> });
          break;
        case 'scan_failed':
          terminalFailureHandled.current = true;
          setOverallStatus('error');
          addNotification({
            type: 'error',
            title: 'Scan Failed',
            message: `${targetDomain} — one or more phases encountered errors`,
          });
          break;
      }
      });
    }, 50);

    return () => {
      window.clearTimeout(connectTimer);
      wsRef.current?.close();
    };
  }, [scanId, onComplete, targetDomain, addNotification, queryClient]);

  const activePhaseCount = Math.max(declaredPhases.length, phases.length, 1);
  const displayedStatus = persistedScan?.status === 'COMPLETED'
    ? 'completed'
    : ['FAILED', 'CANCELLED'].includes(persistedScan?.status)
      ? 'error'
      : overallStatus;

  return (
    <motion.div
      className="pipeline-view"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <div className="pipeline-header">
        <div className="pipeline-target">
          {(() => { const Icon = TARGET_TYPE_ICONS[targetType] || Globe; return <Icon size={16} />; })()}
          <span className="pipeline-target-domain">{targetDomain}</span>
          <span className="pipeline-type-badge">{TARGET_TYPE_LABELS[targetType] || targetType}</span>
          <span className={`pipeline-status-badge ${displayedStatus}`}>
            {displayedStatus === 'running' && <><Loader2 size={11} className="spin" /> RUNNING</>}
            {displayedStatus === 'completed' && <><CheckCircle2 size={11} /> COMPLETED</>}
            {displayedStatus === 'error' && <><XCircle size={11} /> FAILED</>}
          </span>
        </div>
        <div className="pipeline-progress-bar-container">
          <motion.div
            className="pipeline-progress-bar-fill"
            initial={{ width: 0 }}
            animate={{ width: `${(phases.filter(p => p.status === 'completed').length / activePhaseCount) * 100}%` }}
            transition={{ duration: 0.4 }}
          />
        </div>
      </div>

      <div className="pipeline-current-phase">
        {currentPhase && (
          <motion.div
            key={currentPhase}
            initial={{ opacity: 0, y: -5 }}
            animate={{ opacity: 1, y: 0 }}
            className="current-phase-label"
          >
            <ChevronRight size={14} />
            <span>{currentPhase}</span>
          </motion.div>
        )}
        <button
          style={{
            marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 500,
            border: '1px solid rgba(251,146,60,0.3)', color: '#fb923c',
            background: 'rgba(251,146,60,0.08)', cursor: 'pointer',
          }}
          onClick={async () => {
            try {
              await cancelScan(scanId);
            } catch (_) {}
            wsRef.current?.close();
            window.location.reload();
          }}
        >
          <StopCircle size={14} />
          <span>Cancel Scan</span>
        </button>
      </div>

      <PipelineProgress
        tools={tools}
        phases={phases}
        phaseOrder={declaredPhases}
        currentPhase={currentPhase}
        findingsCount={tools.reduce((sum, t) => sum + (t.collected || 0), 0)}
      />
      <JobActivityPanel jobs={pipelineJobs} />
    </motion.div>
  );
}

function updateFirstRunningTool(
  tools: ToolEvent[],
  event: ScanEvent,
  changes: Partial<ToolEvent>,
): ToolEvent[] {
  const eventTarget = typeof event.target === 'string' ? event.target : undefined;
  let index = tools.findIndex(tool =>
    tool.status === 'running' && tool.tool === event.tool &&
    (!eventTarget || tool.target === eventTarget)
  );
  if (index < 0) {
    index = tools.findIndex(tool => tool.status === 'running' && tool.tool === event.tool);
  }
  if (index < 0) return tools;
  const updated = [...tools];
  updated[index] = { ...updated[index], ...changes };
  return updated;
}

/* ─── Results view with tabs ────────────────────────────────────────── */

function ResultsViewWithTabs({ scanId, result, targetDomain, targetType = 'domain', onNewScan, onDelete }: {
  scanId: string; result: ScanResult; targetDomain?: string; targetType?: string; onNewScan: () => void; onDelete?: () => void;
}) {
  const { state, dispatch } = useScanWorkspace();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabId>('infrastructure');

  // Compute per-tab counts from the TABS config (single source of truth).
  // Adding a new tab is a one-line change to TABS above; this memo picks
  // it up automatically.
  const tabCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const tab of TABS) {
      counts[tab.id] = state.findings.filter(f => tab.entityTypes.includes(f.entity_type)).length;
    }
    return counts;
  }, [state.findings]);

  // Download report via AJAX (so auth headers are sent)
  const downloadReport = useCallback(async (format: 'csv' | 'json' | 'pdf') => {
    try {
      const response = await apiClient.get(`/scans/${scanId}/report?format=${format}`, {
        responseType: 'blob',
      });
      const disposition = String(response.headers['content-disposition'] ?? '');
      const match = disposition.match(/filename=([^;]+)/);
      const filename = match ? match[1].replace(/"/g, '').trim() : `findings.${format}`;
      const contentType = String(response.headers['content-type'] ?? 'application/octet-stream');
      const blob = new Blob([response.data], { type: contentType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Report export failed:', err);
    }
  }, [scanId]);

  // Load scan data on mount
  const { data: scanData, isLoading } = useQuery({
    queryKey: ['scanWorkspace', scanId],
    queryFn: async () => (await apiClient.get(`/scans/${scanId}`)).data,
    enabled: !!scanId,
  });

  // Keep the interactive workspace bounded. Exports remain unbounded, while
  // the live UI loads enough evidence for investigation without transferring
  // tens of thousands of rows every few seconds.
  const FINDINGS_BATCH = 5000;
  const { data: findingsResponse } = useQuery({
    queryKey: ['scanFindings', scanId],
    queryFn: async () => (await apiClient.get(`/findings/?scan_id=${scanId}&limit=${FINDINGS_BATCH}`)).data,
    enabled: !!scanId,
    refetchInterval: state.jobs.some(job => ACTIVE_JOB_STATUSES.has(job.status))
      || state.domainDeepAnalysisRunning || state.emailDeepAnalysisRunning || state.breachCheckRunning
      ? 8_000
      : false,
  });

  const { data: jobs = [] } = useQuery<ScanJob[]>({
    queryKey: ['scanJobs', scanId],
    queryFn: async () => (await apiClient.get(`/scans/${scanId}/jobs`)).data,
    enabled: !!scanId,
    refetchInterval: (query) => {
      const currentJobs = query.state.data ?? [];
      return currentJobs.some(job => ACTIVE_JOB_STATUSES.has(job.status)) ? 1_500 : 10_000;
    },
  });

  const { data: assets = [] } = useQuery<AssetRecord[]>({
    queryKey: ['scanAssets', scanId],
    queryFn: async () => (await apiClient.get(`/scans/${scanId}/assets`)).data,
    enabled: !!scanId,
    refetchInterval: jobs.some(job => ACTIVE_JOB_STATUSES.has(job.status)) ? 4_000 : false,
  });

  // Permission check
  const { user } = useAuth();
  const { data: permissionData } = useQuery({
    queryKey: ['scanPermission', scanId],
    queryFn: async () => (await apiClient.get(`/scans/${scanId}/permissions`)).data,
    enabled: !!scanId,
  });
  const permission: string = permissionData?.permission ?? 'owner';
  const isReadOnly = permission === 'read' && !permissionData?.is_admin;
  const canManageAccess = permission === 'owner' || permissionData?.is_admin === true;

  const [collabModalOpen, setCollabModalOpen] = useState(false);

  useEffect(() => {
    if (scanData) {
      dispatch({ type: 'SCAN_LOADED', scan: scanData });
    }
  }, [scanData, dispatch]);

  useEffect(() => {
    if (findingsResponse) {
      dispatch({ type: 'FINDINGS_UPDATED', findings: findingsResponse.items ?? [] });
    }
  }, [findingsResponse, dispatch]);

  useEffect(() => {
    dispatch({ type: 'ASSETS_UPDATED', assets });
  }, [assets, dispatch]);

  const seenTerminalJobs = useRef<Set<string> | null>(null);
  useEffect(() => {
    dispatch({ type: 'JOBS_UPDATED', jobs });
    const terminalIds = new Set(
      jobs.filter(job => TERMINAL_JOB_STATUSES.has(job.status)).map(job => job.id),
    );
    if (seenTerminalJobs.current === null) {
      seenTerminalJobs.current = terminalIds;
      return;
    }

    const hasNewTerminalJob = [...terminalIds].some(id => !seenTerminalJobs.current?.has(id));
    seenTerminalJobs.current = terminalIds;
    if (hasNewTerminalJob) {
      queryClient.invalidateQueries({ queryKey: ['scanFindings', scanId] });
      queryClient.invalidateQueries({ queryKey: ['scanWorkspace', scanId] });
      queryClient.invalidateQueries({ queryKey: ['scanAssets', scanId] });
    }
  }, [jobs, scanId, dispatch, queryClient]);

  // WebSocket for live progress events (deep analysis, breach checks, etc.)
  const wsRef = useRef<WebSocket | null>(null);
  useEffect(() => {
    if (!scanId) return;
    const connectTimer = window.setTimeout(() => {
      wsRef.current = openScanWebSocket(scanId, (event: ScanEvent) => {
      switch (event.event) {
        // Email deep analysis progress
        case 'email_deep_analysis_progress':
          dispatch({ type: 'EMAIL_DEEP_ANALYSIS_PROGRESS', payload: event });
          break;
        case 'email_deep_analysis_completed':
          dispatch({ type: 'EMAIL_DEEP_ANALYSIS_COMPLETED', payload: event });
          break;
        // Breach check progress
        case 'breach_check_progress':
          dispatch({ type: 'BREACH_CHECK_PROGRESS', payload: event });
          break;
        case 'breach_check_completed':
          dispatch({ type: 'BREACH_CHECK_COMPLETED', payload: event });
          break;
        // Domain deep analysis progress
        case 'domain_deep_analysis_progress':
          dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_PROGRESS', payload: event });
          break;
        case 'domain_deep_analysis_completed':
          dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED', payload: event });
          break;
        // A tool completed during deep analysis — refetch findings immediately
        case 'tool_completed':
          queryClient.invalidateQueries({ queryKey: ['scanFindings', scanId] });
          break;
        case 'http_validation_completed':
        case 'wildcard_dns_checked':
          queryClient.invalidateQueries({ queryKey: ['scanAssets', scanId] });
          break;
        case 'active_validation_completed':
          queryClient.invalidateQueries({ queryKey: ['scanFindings', scanId] });
          queryClient.invalidateQueries({ queryKey: ['scanJobs', scanId] });
          break;
        // Scan health — refresh scan status so the tab knows it finished
        case 'scan_completed':
        case 'scan_failed':
          queryClient.invalidateQueries({ queryKey: ['scanWorkspace', scanId] });
          queryClient.invalidateQueries({ queryKey: ['scanJobs', scanId] });
          break;
        // Deep analysis started event — currently InfrastructureTab dispatches
        // this locally; handle it in WS too so other consumers can react.
        case 'domain_deep_analysis_started': {
          const payload = event.payload as { domain?: string; collectors?: string[] } | undefined;
          const collectors = Array.isArray(event.collectors)
            ? event.collectors.map(String)
            : payload?.collectors;
          dispatch({
            type: 'DOMAIN_DEEP_ANALYSIS_STARTED',
            domain: String(event.domain || payload?.domain || ''),
            collectors,
          });
          break;
        }
        // Email deep analysis error — log the collector error silently
        case 'email_deep_analysis_error':
          break;
      }
      });
    }, 50);

    return () => {
      window.clearTimeout(connectTimer);
      wsRef.current?.close();
    };
  }, [scanId, dispatch, queryClient]);

  const renderTab = () => {
    switch (activeTab) {
      case 'infrastructure': return <InfrastructureTab />;
      case 'identity': return <IdentityTab />;
      case 'secrets': return <SecretsTab />;
      case 'threat-intel': return <ThreatIntelTab />;
      case 'brand': return <BrandProtectionTab />;
      case 'web-osint': return <WebOsintTab />;
      default: return <InfrastructureTab />;
    }
  };

  if (isLoading) {
    return (
      <div className="ws-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <Loader2 size={32} className="spin" style={{ color: 'var(--accent)' }} />
      </div>
    );
  }

  return (
    <motion.div
      className="pipeline-results-view"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <div className="results-hero">
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: 'spring', stiffness: 200 }}
        >
          <CheckCircle2 size={48} style={{ color: '#10b981' }} />
        </motion.div>
        <h1>Reconnaissance Complete</h1>
        <p className="results-subtitle">
          {state.findings.length} of {result.total_findings} findings loaded · {result.links_created} correlations mapped
        </p>
        {targetDomain && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 8 }}>
            {(() => { const Icon = TARGET_TYPE_ICONS[targetType] || Globe; return <Icon size={14} style={{ opacity: 0.6 }} />; })()}
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {targetDomain}
            </span>
            <span className="pipeline-type-badge">{TARGET_TYPE_LABELS[targetType] || targetType}</span>
          </div>
        )}
      </div>

      {/* Read-only banner for collaborators */}
      {isReadOnly && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          style={{
            margin: '0 0 16px', padding: '10px 16px', borderRadius: 'var(--radius-lg)',
            display: 'flex', alignItems: 'center', gap: 10,
            background: 'rgba(251,146,60,0.08)', border: '1px solid rgba(251,146,60,0.2)',
            color: '#fb923c', fontSize: 'var(--text-sm)',
          }}
        >
          <Lock size={14} />
          <span>You have read-only access to this scan. Action buttons are hidden.</span>
        </motion.div>
      )}

      <JobActivityPanel jobs={jobs} />

      {/* Tab navigation */}
      <div className="ws-tabs">
        {TABS.map(tab => {
          const Icon = tab.icon;
          const count = tabCounts[tab.id] || 0;
          return (
            <button
              key={tab.id}
              className={`ws-tab-btn ${activeTab === tab.id ? 'ws-tab-active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={15} />
              <span>{tab.label}</span>
              {count > 0 && (
                <span style={{
                  fontSize: 10, padding: '1px 6px', borderRadius: 10,
                  background: activeTab === tab.id ? 'rgba(255,255,255,0.2)' : 'var(--accent-dim)',
                  color: activeTab === tab.id ? '#fff' : 'var(--accent)',
                  fontWeight: 600, minWidth: 18, textAlign: 'center',
                }}>
                  {count > 999 ? '999+' : count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Discovered Domains card — shown for organization scans */}
      {targetType === 'organization' && (
        <DiscoveredDomainsCard
          state={state}
          dispatch={dispatch}
          scanId={scanId}
        />
      )}

      {/* Tab content */}
      <div className="ws-tab-content">
        {renderTab()}
      </div>

      <div style={{ marginTop: 24, display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
        {canManageAccess && (
          <button
            className="btn btn-secondary"
            onClick={() => setCollabModalOpen(true)}
            style={{ padding: '10px 14px', fontSize: 'var(--text-sm)', display: 'inline-flex', alignItems: 'center', gap: 6 }}
          >
            <Share2 size={14} />
            <span>Manage Access</span>
          </button>
        )}

        <button className="results-btn-secondary" onClick={onNewScan}>
          <RotateCcw size={16} />
          <span>New Scan</span>
        </button>

        {/* Export buttons */}
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            className="btn btn-secondary"
            onClick={() => downloadReport('csv')}
            style={{ padding: '10px 14px', fontSize: 'var(--text-sm)', display: 'inline-flex', alignItems: 'center', gap: 6 }}
            title="Export as CSV"
          >
            <Download size={14} />
            <span>CSV</span>
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => downloadReport('json')}
            style={{ padding: '10px 14px', fontSize: 'var(--text-sm)', display: 'inline-flex', alignItems: 'center', gap: 6 }}
            title="Export as JSON"
          >
            <Download size={14} />
            <span>JSON</span>
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => downloadReport('pdf')}
            style={{ padding: '10px 14px', fontSize: 'var(--text-sm)', display: 'inline-flex', alignItems: 'center', gap: 6 }}
            title="Export as PDF"
          >
            <FileSpreadsheet size={14} />
            <span>PDF</span>
          </button>
        </div>

        {(result.status === 'RUNNING' || result.status === 'QUEUED' || result.status === 'PENDING') && (
          <button
            className="btn btn-secondary"
            onClick={async () => {
              try {
                await cancelScan(scanId);
              } catch (_) {}
              window.location.reload();
            }}
            style={{ padding: '10px 16px', fontSize: 'var(--text-sm)', color: '#fb923c', borderColor: 'rgba(251,146,60,0.3)' }}
          >
            <StopCircle size={14} />
            <span>Cancel Scan</span>
          </button>
        )}
        {onDelete && (
          <button className="btn btn-danger" onClick={onDelete} style={{ padding: '10px 16px', fontSize: 'var(--text-sm)' }}>
            <Trash2 size={14} />
            <span>Delete Scan</span>
          </button>
        )}
      </div>

      {/* Collaborator management modal */}
      <CollaboratorModal
        scanId={scanId}
        currentUserId={user?.id || ''}
        isOpen={collabModalOpen}
        onClose={() => setCollabModalOpen(false)}
      />
    </motion.div>
  );
}

/* ─── Discovered Domains Card (org scans) ─────────────────────────────── */

function DiscoveredDomainsCard({
  state,
  dispatch,
  scanId,
}: {
  state: ScanWorkspaceState;
  dispatch: React.Dispatch<ScanWorkspaceAction>;
  scanId: string | null;
}) {
  const [expanded, setExpanded] = useState(true);
  const [infraRunning, setInfraRunning] = useState<string | null>(null);
  const [infraError, setInfraError] = useState<string | null>(null);
  const { addNotification } = useNotification();
  const queryClient = useQueryClient();

  // Extract DOMAIN_METADATA findings (discovered org domains),
  // score them, sort by score descending.
  const discoveredDomains = useMemo(() => {
    const list = state.findings.filter(f => f.entity_type === 'DOMAIN_METADATA');
    return [...list].sort((a, b) => {
      const scoreA = (a.normalized_data as any)?.score ?? 0;
      const scoreB = (b.normalized_data as any)?.score ?? 0;
      return scoreB - scoreA;
    });
  }, [state.findings]);

  // Also look for the active enrichment domain from context
  const persistedDomain = discoveredDomains.some(f => f.entity_value === state.scan?.target_domain)
    ? state.scan?.target_domain
    : null;
  const activeEnrichmentDomain = state.activeEnrichmentDomain || persistedDomain;
  const activeInfraJob = state.jobs.find(
    job => job.job_type === 'execute_org_infra' && ACTIVE_JOB_STATUSES.has(job.status),
  );
  const runningDomain = activeInfraJob?.input_value || infraRunning;

  if (discoveredDomains.length === 0) return null;

  const handleRunInfra = async (domain: string) => {
    if (!scanId) return;
    setInfraRunning(domain);
    setInfraError(null);
    try {
      await triggerOrgInfra(scanId, domain);
      if (addNotification) {
        addNotification({
          type: 'success',
          title: 'Full pipeline started',
          message: `Running infrastructure, services, identity, and search on ${domain}`,
        });
      }
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to start infrastructure scan.';
      setInfraError(detail);
    } finally {
      setInfraRunning(null);
    }
  };

  const handleSetTarget = async (domain: string) => {
    if (!scanId) return;
    setInfraError(null);
    try {
      await apiClient.patch(`/scans/${scanId}/primary-domain`, { domain });
      dispatch({ type: 'SET_ENRICHMENT_DOMAIN', domain });
      await queryClient.invalidateQueries({ queryKey: ['scanWorkspace', scanId] });
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail || 'Failed to save the primary domain.';
      setInfraError(detail);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      style={{
        marginBottom: 16, borderRadius: 'var(--radius-lg)',
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8,
          cursor: 'pointer', userSelect: 'none',
        }}
      >
        <Building2 size={16} style={{ color: 'var(--cyber-purple)' }} />
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)', flex: 1 }}>
          Discovered Domains ({discoveredDomains.length})
        </span>
        {activeEnrichmentDomain && (
          <span style={{
            fontSize: 10, padding: '2px 8px', borderRadius: 10,
            background: 'rgba(6,182,212,0.10)', border: '1px solid rgba(6,182,212,0.2)',
            color: '#06b6d4', fontFamily: 'var(--font-mono)',
          }}>
            Target: {activeEnrichmentDomain}
          </span>
        )}
        {expanded ? <ChevronRight size={14} style={{ transform: 'rotate(90deg)', transition: 'transform 0.2s' }} />
          : <ChevronRight size={14} style={{ transition: 'transform 0.2s' }} />}
      </div>

      {/* Error banner */}
      {infraError && (
        <div style={{
          margin: '0 16px 8px', padding: '6px 10px', borderRadius: 6,
          display: 'flex', alignItems: 'center', gap: 6,
          background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
          fontSize: 11, color: 'var(--severity-critical)',
        }}>
          <AlertTriangle size={12} />
          <span>{infraError}</span>
        </div>
      )}

      {/* Body */}
      {expanded && (
        <div style={{ padding: '0 16px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
          {discoveredDomains.map(f => {
            const isActive = activeEnrichmentDomain === f.entity_value;
            const score = (f.normalized_data as any)?.score ?? 0;
            const bg = isActive ? 'rgba(6,182,212,0.08)' : 'transparent';
            const border = isActive ? '1px solid rgba(6,182,212,0.2)' : '1px solid transparent';
            return (
              <div
                key={f.id}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '6px 10px', borderRadius: 6,
                  background: bg, border,
                }}
              >
                {/* Score badge */}
                <span style={{
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  minWidth: 28, height: 20, borderRadius: 4,
                  fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)',
                  background: score >= 70
                    ? 'rgba(34,197,94,0.12)'
                    : score >= 50
                      ? 'rgba(234,179,8,0.12)'
                      : 'rgba(239,68,68,0.08)',
                  color: score >= 70
                    ? '#22c55e'
                    : score >= 50
                      ? '#eab308'
                      : '#ef4444',
                }}>
                  {score}
                </span>

                {/* Domain name */}
                <span style={{
                  flex: 1, fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600,
                  color: 'var(--text-strong)',
                }}>
                  {f.entity_value}
                </span>

                {/* Source module */}
                {f.source_module && (
                  <span style={{
                    fontSize: 9, padding: '1px 6px', borderRadius: 4,
                    background: 'var(--bg-primary)', color: 'var(--text-muted)',
                    fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
                  }}>
                    {f.source_module.replace(/^org_domain_discovery$/, 'search')
                      .replace(/^reverse_whois_whoxy$/, 'whois')}
                  </span>
                )}

                {/* Set as Target button */}
                <button
                  className="btn btn-secondary"
                  style={{
                    padding: '3px 10px', fontSize: 10,
                    opacity: isActive ? 0.6 : 1,
                  }}
                  onClick={() => handleSetTarget(f.entity_value)}
                  disabled={isActive}
                >
                  {isActive ? 'Active' : 'Target'}
                </button>

                {/* Run Infrastructure button */}
                <button
                  className="btn btn-primary"
                  style={{
                    padding: '3px 10px', fontSize: 10,
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    opacity: runningDomain === f.entity_value ? 0.7 : 1,
                  }}
                  onClick={() => handleRunInfra(f.entity_value)}
                  disabled={runningDomain !== null}
                >
                  {runningDomain === f.entity_value ? (
                    <>
                      <Loader2 size={10} className="spin" />
                      <span>Running...</span>
                    </>
                  ) : (
                    <span>Run Full Pipeline</span>
                  )}
                </button>
              </div>
            );
          })}
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, fontStyle: 'italic' }}>
            Select a domain to use as the default target for enrichment actions, or click
            <strong> Run Infra</strong> to start the full pipeline.
          </div>
        </div>
      )}
    </motion.div>
  );
}

/* ─── Main export ───────────────────────────────────────────────────── */

export default function ScanWorkspace() {
  const { id: routeScanId } = useParams<{ id?: string }>();
  const navigate = useNavigate();

  const [view, setView] = useState<AppView>(routeScanId ? 'loading' : 'input');
  const [scanId, setScanId] = useState<string | null>(routeScanId || null);
  const [targetDomain, setTargetDomain] = useState('');
  const [targetType, setTargetType] = useState('domain');
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isExistingScan, setIsExistingScan] = useState(!!routeScanId);
  const initialLoadDone = useRef(false);

  // If viewing an existing scan, check its status and route to the right view.
  // We start in 'loading' (not 'results') so there is never a blank frame
  // between mount and the API response.
  // IMPORTANT: view is deliberately excluded from the dependency array to
  // prevent an infinite re-render loop when setView('results') fires. The
  // initialLoadDone ref ensures this effect runs exactly once per mount.
  useEffect(() => {
    if (isExistingScan && scanId && !initialLoadDone.current) {
      initialLoadDone.current = true;
      apiClient.get(`/scans/${scanId}`).then(({ data }) => {
        if (data.status === 'RUNNING' || data.status === 'QUEUED' || data.status === 'PENDING') {
          setTargetDomain(data.target_domain);
          setTargetType(data.target_type || 'domain');
          setView('pipeline');
        } else {
          setTargetDomain(data.target_domain);
          setTargetType(data.target_type || 'domain');
          setScanResult({
            scan_id: scanId,
            status: data.status,
            total_findings: data.findings_count || 0,
            links_created: data.links_count || 0,
          });
          setView('results');
        }
      }).catch(() => {
        initialLoadDone.current = false; // Allow retry on next render
        setError('Failed to load scan. It may not exist.');
        setView('input');
      });
    }
  }, [isExistingScan, scanId]);

  const handleSubmit = useCallback(async (domain: string) => {
    setError(null);
    try {
      const { data } = await apiClient.post('/scans/initial', { target_domain: domain });
      setScanId(data.scan.id);
      setTargetDomain(domain);
      setTargetType(data.scan.target_type || 'domain');
      setIsExistingScan(false);
      setView('pipeline');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to launch scan';
      setError(message);
    }
  }, []);

  const handlePipelineComplete = useCallback((result: ScanResult) => {
    setScanResult(result);
    setTimeout(() => setView('results'), 1500);
  }, []);

  const handleNewScan = useCallback(() => {
    setView('input');
    setScanId(null);
    setTargetDomain('');
    setTargetType('domain');
    setScanResult(null);
    if (routeScanId) navigate('/scans/new');
  }, [routeScanId, navigate]);

  const handleDeleteScan = useCallback(async () => {
    if (!scanId) return;
    if (!window.confirm('Delete this scan and all its findings? This cannot be undone.')) return;
    try {
      await deleteScan(scanId);
      navigate('/scans');
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to delete scan.';
      window.alert(`Error: ${detail}`);
    }
  }, [scanId, navigate]);

  return (
    <div className="pipeline-page">
      <AnimatePresence mode="wait">
        {view === 'loading' && (
          <motion.div
            key="loading"
            className="ws-container"
            style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <Loader2 size={32} className="spin" style={{ color: 'var(--accent)' }} />
          </motion.div>
        )}
        {view === 'input' && (
          <InputView key="input" onSubmit={handleSubmit} error={error} />
        )}
        {view === 'pipeline' && scanId && (
          <PipelineView key="pipeline" scanId={scanId} targetDomain={targetDomain} targetType={targetType} onComplete={handlePipelineComplete} />
        )}
        {view === 'results' && scanResult && (
          <ErrorBoundary key="error-boundary-results">
            <ResultsViewWithTabs scanId={scanId!} result={scanResult} targetDomain={targetDomain} targetType={targetType} onNewScan={handleNewScan} onDelete={handleDeleteScan} />
          </ErrorBoundary>
        )}
      </AnimatePresence>
    </div>
  );
}
