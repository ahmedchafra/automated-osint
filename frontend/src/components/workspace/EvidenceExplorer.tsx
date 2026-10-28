import { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Search, SlidersHorizontal } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import apiClient from '../../api/client';
import { useScanWorkspace } from '../../context/scan-workspace-state';
import { ENTITY_CATALOG, ENTITY_TYPES, entityLabel } from '../../domain/entityCatalog';
import type { EntityType, PaginatedFindings, Severity } from '../../types/api';
import { ConfidenceBar, SeverityBadge } from '../FindingsTable';

const PAGE_SIZE = 100;
const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function EvidenceExplorer() {
  const { state } = useScanWorkspace();
  const [query, setQuery] = useState('');
  const [entityType, setEntityType] = useState<EntityType | ''>('');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [page, setPage] = useState(0);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const params = useMemo(() => {
    const values = new URLSearchParams({
      scan_id: state.scan?.id ?? '',
      skip: String(page * PAGE_SIZE),
      limit: String(PAGE_SIZE),
    });
    if (query.trim()) values.set('q', query.trim());
    if (entityType) values.set('entity_type', entityType);
    if (severity) values.set('severity', severity);
    return values.toString();
  }, [entityType, page, query, severity, state.scan?.id]);

  const { data, isLoading, isFetching, error } = useQuery<PaginatedFindings>({
    queryKey: ['evidenceExplorer', state.scan?.id, page, entityType, severity, query.trim()],
    queryFn: async () => (await apiClient.get(`/findings/?${params}`)).data,
    enabled: Boolean(state.scan?.id),
  });

  const displayed = data?.items ?? [];
  const total = data?.total ?? state.findings.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const filtersActive = Boolean(query || entityType || severity);

  return (
    <section className="evidence-explorer" data-testid="evidence-explorer">
      <div className="evidence-heading">
        <div>
          <span className="workspace-eyebrow">Canonical data view</span>
          <h2>All evidence</h2>
          <p>Every stored finding is available here, including raw and normalized collector output.</p>
        </div>
        <div className="evidence-total">
          <strong>{total.toLocaleString()}</strong>
          <span>{filtersActive ? 'matching findings' : 'stored findings'}</span>
        </div>
      </div>

      <div className="evidence-filters">
        <label className="evidence-search">
          <Search size={16} />
          <input
            value={query}
            onChange={event => { setQuery(event.target.value); setPage(0); }}
            placeholder="Search stored evidence"
            aria-label="Search evidence"
          />
        </label>
        <label>
          <span>Type</span>
          <select value={entityType} onChange={event => { setEntityType(event.target.value as EntityType | ''); setPage(0); }}>
            <option value="">All entity types</option>
            {ENTITY_TYPES.map(type => <option key={type} value={type}>{ENTITY_CATALOG[type].label}</option>)}
          </select>
        </label>
        <label>
          <span>Severity</span>
          <select value={severity} onChange={event => { setSeverity(event.target.value as Severity | ''); setPage(0); }}>
            <option value="">All severities</option>
            {SEVERITIES.map(value => <option key={value} value={value}>{value}</option>)}
          </select>
        </label>
        {filtersActive && (
          <button
            className="workspace-text-button"
            onClick={() => { setQuery(''); setEntityType(''); setSeverity(''); setPage(0); }}
          >
            Clear filters
          </button>
        )}
      </div>

      {error ? (
        <div className="workspace-empty evidence-empty"><SlidersHorizontal size={22} />Unable to load evidence. Retry by changing a filter.</div>
      ) : displayed.length ? (
        <div className="evidence-table-wrap">
          <table className="evidence-table">
            <thead>
              <tr>
                <th aria-label="Expand" />
                <th>Entity</th>
                <th>Value</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {displayed.map(finding => {
                const expanded = expandedId === finding.id;
                return [
                  <tr key={finding.id} className={expanded ? 'evidence-row-expanded' : undefined}>
                    <td>
                      <button
                        className="evidence-expand"
                        onClick={() => setExpandedId(expanded ? null : finding.id)}
                        aria-label={`${expanded ? 'Collapse' : 'Expand'} ${finding.entity_value}`}
                      >
                        {expanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                      </button>
                    </td>
                    <td>
                      <span className="evidence-entity-label">{entityLabel(finding.entity_type)}</span>
                      <small>{finding.vector_type}</small>
                    </td>
                    <td><span className="evidence-value" title={finding.entity_value}>{finding.entity_value}</span></td>
                    <td><SeverityBadge severity={finding.severity} /></td>
                    <td>
                      <span className="evidence-source">{finding.source_module.replaceAll('_', ' ')}</span>
                      <span className="evidence-observations" title={`First seen ${new Date(finding.first_seen_at).toLocaleString()}`}>{finding.observation_count.toLocaleString()}× · revision {finding.revision}</span>
                    </td>
                    <td><ConfidenceBar value={finding.confidence} /></td>
                  </tr>,
                  expanded && (
                    <tr key={`${finding.id}-detail`} className="evidence-detail-row">
                      <td colSpan={6}>
                        <div className="evidence-detail">
                          <EvidenceJson title="Normalized data" value={finding.normalized_data} />
                          <EvidenceJson title="Raw collector data" value={finding.raw_data} />
                          <div className="evidence-metadata">
                            <span><strong>ID</strong>{finding.id}</span>
                            <span><strong>Created</strong>{new Date(finding.created_at).toLocaleString()}</span>
                            <span><strong>First seen</strong>{new Date(finding.first_seen_at).toLocaleString()}</span>
                            <span><strong>Last seen</strong>{new Date(finding.last_seen_at).toLocaleString()}</span>
                            <span><strong>Observations</strong>{finding.observation_count.toLocaleString()}</span>
                            <span><strong>Revision</strong>{finding.revision}</span>
                            {finding.last_observed_for && <span><strong>Observed for</strong>{finding.last_observed_for}</span>}
                            <span><strong>Tags</strong>{finding.tags.length ? finding.tags.join(', ') : 'None'}</span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  ),
                ];
              })}
            </tbody>
          </table>
        </div>
      ) : isLoading ? (
        <div className="workspace-empty evidence-empty">Loading stored evidence…</div>
      ) : (
        <div className="workspace-empty evidence-empty"><SlidersHorizontal size={22} />No evidence matches these filters.</div>
      )}

      {totalPages > 1 && (
        <div className="evidence-pagination">
          <span>Page {page + 1} of {totalPages} · {total.toLocaleString()} findings</span>
          <div>
            <button disabled={page === 0 || isFetching} onClick={() => { setExpandedId(null); setPage(current => current - 1); }}>Previous</button>
            <button disabled={page >= totalPages - 1 || isFetching} onClick={() => { setExpandedId(null); setPage(current => current + 1); }}>Next</button>
          </div>
        </div>
      )}
    </section>
  );
}

function EvidenceJson({ title, value }: { title: string; value: Record<string, unknown> }) {
  return (
    <div className="evidence-json">
      <strong>{title}</strong>
      <pre>{Object.keys(value).length ? JSON.stringify(value, null, 2) : 'No data'}</pre>
    </div>
  );
}
