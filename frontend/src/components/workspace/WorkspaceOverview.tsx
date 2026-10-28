import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Database,
  Radio,
  ShieldCheck,
} from 'lucide-react';
import { useScanWorkspace } from '../../context/scan-workspace-state';
import apiClient from '../../api/client';
import type { TabId } from '../../context/ScanWorkspaceContext';
import { ENTITY_CATALOG, entityLabel } from '../../domain/entityCatalog';
import type { EntityType, ScanFacets, Severity } from '../../types/api';
import { ScopePanel } from './ScopePanel';

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

interface WorkspaceOverviewProps {
  onNavigate: (tab: TabId) => void;
  canEditScope?: boolean;
}

export function WorkspaceOverview({ onNavigate, canEditScope = false }: WorkspaceOverviewProps) {
  const { state } = useScanWorkspace();
  const hasActiveJobs = state.jobs.some(job => ['QUEUED', 'RUNNING', 'RETRYING'].includes(job.status));
  const { data: facets } = useQuery<ScanFacets>({
    queryKey: ['scanFacets', state.scan?.id],
    queryFn: async () => (await apiClient.get(`/scans/${state.scan?.id}/facets`)).data,
    enabled: Boolean(state.scan?.id),
    refetchInterval: hasActiveJobs ? 4_000 : false,
  });

  const summary = useMemo(() => {
    const entityCounts = new Map<EntityType, number>();
    const sourceCounts = new Map<string, number>();
    const severityCounts = new Map<Severity, number>();

    for (const finding of state.findings) {
      entityCounts.set(finding.entity_type, (entityCounts.get(finding.entity_type) ?? 0) + 1);
      sourceCounts.set(finding.source_module, (sourceCounts.get(finding.source_module) ?? 0) + 1);
      severityCounts.set(finding.severity, (severityCounts.get(finding.severity) ?? 0) + 1);
    }

    const exactEntityCounts = facets
      ? Object.entries(facets.findings_by_entity_type)
        .filter(([type]) => type in ENTITY_CATALOG) as [EntityType, number][]
      : [...entityCounts.entries()];
    const exactSeverityCounts = facets
      ? new Map(Object.entries(facets.findings_by_severity) as [Severity, number][])
      : severityCounts;

    return {
      entityCounts: exactEntityCounts.sort((a, b) => b[1] - a[1]),
      sourceCounts: (facets ? Object.entries(facets.findings_by_source) : [...sourceCounts.entries()])
        .sort((a, b) => b[1] - a[1]),
      severityCounts: exactSeverityCounts,
      findingsTotal: facets?.findings_total ?? state.scan?.findings_count ?? state.findings.length,
      assetsTotal: facets?.assets_total ?? state.assets.length,
      jobsTotal: facets?.jobs_total ?? state.jobs.length,
      liveAssets: facets?.assets_by_state.LIVE ?? state.assets.filter(asset => asset.state === 'LIVE').length,
      inScopeAssets: facets?.assets_in_scope ?? state.assets.filter(asset => asset.in_scope).length,
      activeJobs: facets
        ? ['QUEUED', 'RUNNING', 'RETRYING'].reduce((total, status) => total + (facets.jobs_by_status[status] ?? 0), 0)
        : state.jobs.filter(job => ['QUEUED', 'RUNNING', 'RETRYING'].includes(job.status)).length,
      failedJobs: facets?.jobs_by_status.FAILED ?? state.jobs.filter(job => job.status === 'FAILED').length,
    };
  }, [facets, state.assets, state.findings, state.jobs, state.scan?.findings_count]);

  return (
    <div className="workspace-overview" data-testid="workspace-overview">
      <section className="workspace-metric-grid" aria-label="Scan summary">
        <MetricCard
          icon={Database}
          label="Evidence"
          value={summary.findingsTotal}
          detail={`${state.findings.length.toLocaleString()} loaded · ${summary.sourceCounts.length} sources`}
        />
        <MetricCard icon={Boxes} label="Assets" value={summary.assetsTotal} detail={`${summary.inScopeAssets} in scope`} />
        <MetricCard icon={Radio} label="Live assets" value={summary.liveAssets} detail="HTTP validated" tone="success" />
        <MetricCard
          icon={summary.failedJobs ? AlertTriangle : CheckCircle2}
          label="Jobs"
          value={summary.jobsTotal}
          detail={summary.activeJobs ? `${summary.activeJobs} active` : summary.failedJobs ? `${summary.failedJobs} failed` : 'Pipeline idle'}
          tone={summary.failedJobs ? 'danger' : 'neutral'}
        />
      </section>

      <div className="workspace-overview-grid">
        <section className="workspace-panel workspace-panel-wide">
          <div className="workspace-panel-heading">
            <div>
              <span className="workspace-eyebrow">Coverage</span>
              <h2>Collected evidence</h2>
            </div>
            <button className="workspace-text-button" onClick={() => onNavigate('evidence')}>Explore all evidence</button>
          </div>
          {summary.entityCounts.length ? (
            <div className="entity-coverage-grid">
              {summary.entityCounts.map(([type, count]) => {
                const definition = ENTITY_CATALOG[type];
                return (
                  <button
                    key={type}
                    className="entity-coverage-item"
                    onClick={() => onNavigate(definition.tab)}
                    title={definition.description}
                  >
                    <span className="entity-coverage-count">{count.toLocaleString()}</span>
                    <span className="entity-coverage-label">{definition.label}</span>
                    <span className="entity-coverage-tab">{definition.tab.replace('-', ' ')}</span>
                  </button>
                );
              })}
            </div>
          ) : (
            <EmptyPanel message="Evidence will appear here as collectors finish." />
          )}
        </section>

        <section className="workspace-panel">
          <div className="workspace-panel-heading">
            <div>
              <span className="workspace-eyebrow">Prioritization</span>
              <h2>Severity</h2>
            </div>
            <ShieldCheck size={18} />
          </div>
          <div className="severity-summary">
            {SEVERITY_ORDER.map(severity => {
              const count = summary.severityCounts.get(severity) ?? 0;
              const share = summary.findingsTotal ? Math.round((count / summary.findingsTotal) * 100) : 0;
              return (
                <div className="severity-summary-row" key={severity}>
                  <span className={`severity-dot severity-${severity.toLowerCase()}`} />
                  <span>{severity}</span>
                  <div className="severity-track"><span style={{ width: `${share}%` }} /></div>
                  <strong>{count.toLocaleString()}</strong>
                </div>
              );
            })}
          </div>
        </section>

        <section className="workspace-panel">
          <div className="workspace-panel-heading">
            <div>
              <span className="workspace-eyebrow">Provenance</span>
              <h2>Top sources</h2>
            </div>
            <Activity size={18} />
          </div>
          {summary.sourceCounts.length ? (
            <div className="source-summary">
              {summary.sourceCounts.slice(0, 10).map(([source, count]) => (
                <div className="source-summary-row" key={source}>
                  <span title={source}>{source.replaceAll('_', ' ')}</span>
                  <strong>{count.toLocaleString()}</strong>
                </div>
              ))}
            </div>
          ) : (
            <EmptyPanel message="No collector results yet." />
          )}
        </section>
      </div>

      <ScopePanel canEdit={canEditScope} />

      {state.findings.length > 0 && (
        <section className="workspace-panel">
          <div className="workspace-panel-heading">
            <div>
              <span className="workspace-eyebrow">Latest</span>
              <h2>Recent evidence</h2>
            </div>
          </div>
          <div className="recent-evidence-list">
            {state.findings.slice(-8).reverse().map(finding => (
              <button key={finding.id} onClick={() => onNavigate('evidence')} className="recent-evidence-row">
                <span className={`severity-dot severity-${finding.severity.toLowerCase()}`} />
                <span className="recent-evidence-type">{entityLabel(finding.entity_type)}</span>
                <span className="recent-evidence-value" title={finding.entity_value}>{finding.entity_value}</span>
                <span className="recent-evidence-source">{finding.source_module.replaceAll('_', ' ')}</span>
              </button>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  detail,
  tone = 'neutral',
}: {
  icon: typeof Activity;
  label: string;
  value: number;
  detail: string;
  tone?: 'neutral' | 'success' | 'danger';
}) {
  return (
    <div className={`workspace-metric workspace-metric-${tone}`}>
      <div className="workspace-metric-icon"><Icon size={18} /></div>
      <div>
        <span>{label}</span>
        <strong>{value.toLocaleString()}</strong>
        <small>{detail}</small>
      </div>
    </div>
  );
}

function EmptyPanel({ message }: { message: string }) {
  return <div className="workspace-empty">{message}</div>;
}
