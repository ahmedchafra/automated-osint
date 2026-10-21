import { useEffect, useMemo, useRef, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  Download,
  Globe,
  Search,
  Server,
  Shield,
  Sparkles,
  X,
} from 'lucide-react';
import apiClient from '../api/client';
import { openScanWebSocket } from '../api/ws';
import { ProgressBar } from '../components/ProgressBar';
import { EventLog, type LogEvent, type EventLevel } from '../components/EventLog';
import { Chip } from '../components/Chip';
import { FindingsTable, type FindingRow } from '../components/FindingsTable';

type ExportFormat = 'csv' | 'json' | 'pdf';
type SeverityFilter = '' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

interface ScanDetail {
  id: string;
  target_domain: string;
  status: 'QUEUED' | 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  selected_vectors: string[];
  target_usernames: string[];
  created_at: string;
  completed_at: string | null;
  findings: FindingRow[];
}

interface Filters {
  severity: SeverityFilter;
  vector_type: string;
  entity_type: string;
  search: string;
}

interface FindingsPage {
  items: FindingRow[];
  total: number;
}

const EMPTY_FILTERS: Filters = {
  severity: '',
  vector_type: '',
  entity_type: '',
  search: '',
};

const SEVERITIES: SeverityFilter[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEVERITY_LABELS: Record<SeverityFilter, string> = {
  '': 'All severities',
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
};

function buildFindingsQuery(scanId: string, filters: Filters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.vector_type) params.set('vector_type', filters.vector_type);
  if (filters.entity_type) params.set('entity_type', filters.entity_type);
  if (filters.search.trim()) params.set('q', filters.search.trim());
  params.set('scan_id', scanId);
  return params;
}

async function downloadExport(
  scanId: string,
  filters: Filters,
  format: ExportFormat,
): Promise<void> {
  const params = buildFindingsQuery(scanId, filters);
  params.set('format', format);
  const response = await apiClient.get(`/findings/export?${params.toString()}`, {
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
}

function ScanDetails() {
  const { id } = useParams<{ id: string }>();
  const wsRef = useRef<WebSocket | null>(null);

  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [completedVectors, setCompletedVectors] = useState<string[]>([]);
  const [totalVectors, setTotalVectors] = useState(0);
  const [eventLog, setEventLog] = useState<LogEvent[]>([]);
  const [wsConnected, setWsConnected] = useState(false);

  const isRunningState =
    (status: ScanDetail['status'] | undefined) =>
      status === 'RUNNING' || status === 'PENDING' || status === 'QUEUED';

  const addEvent = (level: EventLevel, title: string, detail?: string) => {
    setEventLog((prev) =>
      [
        {
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          level,
          title,
          detail,
          timestamp: new Date().toISOString(),
        },
        ...prev,
      ].slice(0, 80),
    );
  };

  const { data: scan, isLoading: scanLoading } = useQuery<ScanDetail>({
    queryKey: ['scan', id],
    queryFn: async () => (await apiClient.get(`/scans/${id}`)).data,
    refetchInterval: (query) =>
      isRunningState(query.state.data?.status) ? 3000 : false,
    enabled: !!id,
  });

  // Debounce full-text search so the API is not queried on every keystroke.
  const [debouncedSearch, setDebouncedSearch] = useState(filters.search);
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(filters.search), 350);
    return () => clearTimeout(timer);
  }, [filters.search]);
  const effectiveFilters = useMemo(
    () => ({ ...filters, search: debouncedSearch }),
    [filters, debouncedSearch],
  );

  const fetchFindings = async (): Promise<FindingsPage> => {
    if (!id) return { items: [], total: 0 };
    const params = buildFindingsQuery(id, effectiveFilters);
    params.set('limit', '5000');
    const response = await apiClient.get(`/findings/?${params.toString()}`);
    return {
      items: response.data.items ?? response.data,
      total: response.data.total ?? (response.data.items ?? response.data).length,
    };
  };

  const {
    data: findingsPage,
    isLoading: findingsLoading,
  } = useQuery<FindingsPage>({
    queryKey: ['findings', id, effectiveFilters],
    queryFn: fetchFindings,
    refetchInterval: () => (isRunningState(scan?.status) ? 3000 : false),
    enabled: !!scan,
  });

  const isRunning = isRunningState(scan?.status);

  useEffect(() => {
    if (!id || !isRunning) {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setWsConnected(false);
      return;
    }
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;

    const socket = openScanWebSocket(
      id,
      (event) => {
        const evt = event.event;
        if (evt === 'scan_started') {
          const total = Number(event.total_vectors ?? (event.selected_vectors as unknown as string[] | undefined)?.length ?? 0);
          setTotalVectors(total);
          addEvent(
            'info',
            'Scan started',
            `${event.target_domain as string} • ${total} vector${total === 1 ? '' : 's'} queued`,
          );
        } else if (evt === 'vector_started') {
          addEvent(
            'info',
            `${event.vector_type as string} started`,
            `Step ${event.index}/${event.total}`,
          );
        } else if (evt === 'vector_completed') {
          const vec = event.vector_type as string;
          setCompletedVectors((prev) =>
            prev.includes(vec) ? prev : [...prev, vec],
          );
          const stage = (event.stage as string | undefined) ?? '';
          addEvent(
            'success',
            `${vec} completed`,
            `${stage} • ${event.findings_created as number} findings persisted`,
          );
        } else if (evt === 'correlation_completed') {
          addEvent(
            'success',
            'Correlation complete',
            `${event.links_created as number} links across the entity graph`,
          );
        } else if (evt === 'scan_completed') {
          addEvent(
            'success',
            'Scan complete',
            `${event.findings_created as number} findings, ${event.links_created as number} links`,
          );
        } else if (evt === 'scan_failed') {
          addEvent('error', 'Scan failed', event.error as string | undefined);
        }
      },
      // Force the socket closed by the page (rather than phantom reconnect)
      // when the worker emits no further events.
      () => setWsConnected(false),
    );

    socket.onopen = () => setWsConnected(true);
    socket.onclose = () => setWsConnected(false);
    wsRef.current = socket;
    return () => {
      socket.close();
      wsRef.current = null;
      setWsConnected(false);
    };
  }, [id, isRunning]);

  if (scanLoading) {
    return (
      <div className="card text-center py-8">
        <Activity size={32} className="text-accent-primary animate-spin mb-4" />
        <h2 className="mb-2">Loading scan…</h2>
        <p className="text-gray">Fetching the latest metadata from the backend</p>
    </div>
    );
  }
  if (!scan) {
    return (
      <div className="card text-center py-8">
        <h2 className="mb-2">Scan not found</h2>
        <p className="text-gray">The scan may have been deleted or the ID is wrong</p>
        <div className="mt-6">
          <Link to="/" className="btn btn-primary">Back to dashboard</Link>
      </div>
    </div>
    );
  }

  const typedFindings = findingsPage?.items ?? [];
  const totalFindings = findingsPage?.total ?? typedFindings.length;

  const vectorOptions = Array.from(new Set(typedFindings.map((f) => f.vector_type))).sort();
  const entityTypeOptions = Array.from(new Set(typedFindings.map((f) => f.entity_type))).sort();

  const progressPct = totalVectors === 0 ? 0 : Math.min(100, (completedVectors.length / totalVectors) * 100);

  const counts = {
    subdomains: typedFindings.filter((f) => f.entity_type === 'SUBDOMAIN').length,
    ips: typedFindings.filter((f) => f.entity_type === 'IP_ADDRESS').length,
    ports: typedFindings.filter((f) => f.entity_type === 'PORT_SERVICE').length,
    cves: typedFindings.filter((f) => f.entity_type === 'CVE').length,
    breaches: typedFindings.filter((f) => f.entity_type === 'BREACH').length,
    emails: typedFindings.filter((f) => f.entity_type === 'EMAIL').length,
  };

  const toggleSeverity = (s: SeverityFilter) =>
    setFilters((prev) => ({ ...prev, severity: prev.severity === s ? '' : s }));
  const setVector = (v: string) =>
    setFilters((prev) => ({ ...prev, vector_type: prev.vector_type === v ? '' : v }));
  const setEntity = (e: string) =>
    setFilters((prev) => ({ ...prev, entity_type: prev.entity_type === e ? '' : e }));
  const clearFilters = () => setFilters(EMPTY_FILTERS);

  const filterIsActive =
    !!filters.severity || !!filters.vector_type || !!filters.entity_type || !!filters.search;

  return (
    <div>
      <div className="flex justify-between items-start mb-6 gap-6 flex-wrap">
        <div>
          <div className="text-gray text-sm flex items-center gap-2 mb-2">
            <Link to="/" className="text-gray hover:text-strong" style={{ color: 'var(--text-muted)' }}>Dashboard</Link>
            <ChevronRight size={14} />
            <span>Scan</span>
       </div>
          <h1 className="mb-3">{scan.target_domain}</h1>
          <div className="flex items-center gap-3 flex-wrap">
            <span
              className={`badge ${scan.status === 'COMPLETED' ? 'badge-success' : scan.status === 'FAILED' ? 'badge-danger' : 'badge-info'}`}
            >
              {scan.status}
           </span>
            <span className="text-sm text-gray">
              {scan.selected_vectors.join(' • ')}
           </span>
            {isRunning && (
              <div
                title={wsConnected ? 'Live: connected to worker' : 'Live: disconnected'}
                className="flex items-center gap-2 text-sm text-gray"
              >
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    background: wsConnected ? 'var(--severity-low)' : 'var(--severity-high)',
                    display: 'inline-block',
                  }}
                />
                {wsConnected ? 'Live' : 'Reconnecting'}
             </div>
            )}
         </div>
       </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => id && downloadExport(id, effectiveFilters, 'csv')}
            className="btn btn-outline"
          >
            <Download size={16} /> CSV
         </button>
          <button
            onClick={() => id && downloadExport(id, effectiveFilters, 'json')}
            className="btn btn-outline"
          >
            <Download size={16} /> JSON
         </button>
          <button
            onClick={() => id && downloadExport(id, effectiveFilters, 'pdf')}
            className="btn btn-outline"
          >
            <Download size={16} /> PDF
         </button>
       </div>
     </div>

      {/* Top stat cards */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <StatCard icon={<Globe size={20} className="text-accent-primary" />} label="Subdomains" value={counts.subdomains} />
        <StatCard icon={<Server size={20} className="text-accent-warning" />} label="Ports & Services" value={counts.ports} />
        <StatCard icon={<Shield size={20} className="text-accent-danger" />} label="Vulnerabilities" value={counts.cves} />
     </div>

      {/* Live progress card */}
      {isRunning && (
        <div className="card mb-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Sparkles size={18} className="text-accent-warning" />
              <h3 style={{ marginBottom: 0 }}>Live progress</h3>
           </div>
            <span className="text-sm font-mono text-gray">
              {completedVectors.length}/{totalVectors || '?'} vectors complete
           </span>
         </div>
          <ProgressBar value={progressPct} label="Scan progress" />
          {totalVectors > 0 && (
            <div className="flex flex-wrap gap-2 mt-4">
              {scan.selected_vectors.map((vec) => {
                const done = completedVectors.includes(vec);
                return (
                  <span
                    key={vec}
                    className={`badge ${done ? 'badge-success' : 'badge-info'}`}
                  >
                    {done ? '✓ ' : ''}{vec}
                 </span>
                );
              })}
           </div>
          )}
       </div>
      )}

      {/* Filter row */}
      <div className="card mb-6">
        <div className="flex justify-between items-center mb-3">
          <h3 style={{ marginBottom: 0 }}>Filters</h3>
          {filterIsActive && (
            <button onClick={clearFilters} className="btn btn-outline" style={{ padding: '4px 10px', fontSize: 12 }}>
              <X size={14} /> Clear all
           </button>
          )}
       </div>

        <div className="form-group">
          <label className="form-label">{SEVERITY_LABELS[filters.severity]}</label>
          <div className="flex flex-wrap gap-2">
            {SEVERITIES.map((s) => (
              <Chip key={s} active={filters.severity === s} onChange={() => toggleSeverity(s)}>
                <span className={`severity-dot ${s.toLowerCase()}`} />
                {s}
             </Chip>
            ))}
         </div>
       </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="form-label">Vector</label>
            <select
              className="form-input"
              value={filters.vector_type}
              onChange={(e) => setVector(e.target.value)}
            >
              <option value="">All vectors</option>
              {vectorOptions.map((v) => <option key={v} value={v}>{v}</option>)}
           </select>
         </div>
          <div>
            <label className="form-label">Entity type</label>
            <select
              className="form-input"
              value={filters.entity_type}
              onChange={(e) => setEntity(e.target.value)}
            >
              <option value="">All entity types</option>
              {entityTypeOptions.map((v) => <option key={v} value={v}>{v}</option>)}
           </select>
         </div>
       </div>

        <div className="form-group" style={{ marginTop: 'var(--space-4)' }}>
          <label className="form-label" htmlFor="q">Full-text search</label>
          <div style={{ position: 'relative' }}>
            <Search size={16} style={{ position: 'absolute', left: 12, top: 13, color: 'var(--text-muted)' }} />
            <input
              id="q"
              className="form-input"
              style={{ paddingLeft: 36 }}
              placeholder="Search entity value, raw data, normalized data (Postgres tsvector)…"
              value={filters.search}
              onChange={(e) => setFilters((p) => ({ ...p, search: e.target.value }))}
            />
         </div>
       </div>
     </div>

      {/* Event log */}
      {eventLog.length > 0 && (
        <div className="card mb-6">
          <h3 className="mb-3">Activity log</h3>
          <EventLog events={eventLog} />
       </div>
      )}

      {/* Findings table */}
      <div className="mb-3 flex items-baseline justify-between">
        <h2 style={{ marginBottom: 0 }}>Findings</h2>
        <span className="text-gray text-sm">
          {totalFindings} {totalFindings === 1 ? 'result' : 'results'}
          {filterIsActive ? ' after filters' : ''}
       </span>
     </div>

      <div className="card" style={{ padding: 0 }}>
        <FindingsTable
          findings={typedFindings}
          isLoading={findingsLoading && !findingsPage}
          emptyMessage={
            isRunning
              ? 'Waiting for first results from the worker…'
              : filterIsActive
                ? 'No findings match the active filters. Try clearing them.'
                : 'No findings were collected. The target may block scanners.'
          }
        />
    </div>

      <div className="mt-4 flex items-center gap-2 text-sm text-gray">
        <AlertTriangle size={14} />
        Severity reflects the kind of exposure found. Filter and export to focus on what matters.
    </div>
  </div>
  );
}

interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: number;
}

function StatCard({ icon, label, value }: StatCardProps) {
  return (
    <div className="card flex items-center gap-4">
      <div
        style={{
          width: 48,
          height: 48,
          borderRadius: 12,
          background: 'var(--surface-2)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          border: '1px solid var(--border-subtle)',
        }}
      >
        {icon}
    </div>
      <div>
        <div className="text-gray text-sm" style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
          {label}
      </div>
        <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-strong)' }}>{value}</div>
    </div>
  </div>
  );
}

export default ScanDetails;
