import type { ReactNode } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import type { Finding } from '../types/api';

export type FindingRow = Finding;

interface SeverityBadgeProps {
  severity: string;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const cls =
    severity === 'CRITICAL' || severity === 'HIGH'
      ? 'badge-danger'
      : severity === 'MEDIUM'
        ? 'badge-warning'
        : severity === 'LOW'
          ? 'badge-info'
          : 'badge-success';
  return <span className={`badge ${cls}`}>{severity}</span>;
}

interface ConfidenceBarProps {
  value: number;
}

export function ConfidenceBar({ value }: ConfidenceBarProps) {
  const pct = Math.round(value * 100);
  const tone =
    pct >= 80 ? 'var(--severity-low)' : pct >= 50 ? 'var(--severity-medium)' : 'var(--severity-high)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 100 }}>
      <div
        style={{
          flex: 1,
          height: 4,
          background: 'var(--surface-3)',
          borderRadius: 999,
          overflow: 'hidden',
        }}
      >
        <div style={{ width: `${pct}%`, height: '100%', background: tone }} />
    </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>
        {pct}%
    </span>
  </div>
  );
}

interface FindingsTableProps {
  findings: FindingRow[];
  isLoading?: boolean;
  emptyMessage?: string;
  rightAccessory?: (finding: FindingRow) => ReactNode;
  /* ── Pagination props ──────────────────────────────────────────── */
  total?: number;
  page?: number;
  onPageChange?: (page: number) => void;
  pageSize?: number;
}

export function FindingsTable({
  findings,
  isLoading,
  emptyMessage = 'No findings to display.',
  rightAccessory,
  total,
  page = 0,
  onPageChange,
  pageSize = 100,
}: FindingsTableProps) {
  const totalPages = total != null ? Math.max(1, Math.ceil(total / pageSize)) : 1;

  if (isLoading) {
    return (
      <div style={{ padding: 'var(--space-8)', textAlign: 'center' }} className="text-gray">
        Loading findings…
    </div>
    );
  }
  if (findings.length === 0) {
    return (
      <div style={{ padding: 'var(--space-8)', textAlign: 'center' }} className="text-gray">
        {emptyMessage}
    </div>
    );
  }
  return (
    <div>
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Entity type</th>
              <th>Value</th>
              <th>Severity</th>
              <th>Vector</th>
              <th>Source</th>
              <th>Confidence</th>
              {rightAccessory && <th />}
           </tr>
         </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td className="font-medium" style={{ color: 'var(--text-muted)' }}>
                  {f.entity_type}
              </td>
                <td
                  className="font-medium"
                  style={{
                    color: 'var(--text-strong)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 13,
                    maxWidth: 360,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                  title={f.entity_value}
                >
                  {f.entity_value}
              </td>
                <td>
                  <SeverityBadge severity={f.severity} />
              </td>
                <td className="text-gray text-sm">{f.vector_type}</td>
                <td className="text-gray text-sm">{f.source_module}</td>
                <td>
                  <ConfidenceBar value={f.confidence} />
              </td>
                {rightAccessory && <td>{rightAccessory(f)}</td>}
             </tr>
            ))}
         </tbody>
       </table>
    </div>

      {/* ── Pagination footer ──────────────────────────────────────── */}
      {total != null && totalPages > 1 && onPageChange && (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
          marginTop: 12, padding: '8px 0', fontSize: 12, color: 'var(--text-muted)',
        }}>
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 0}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 10px',
              borderRadius: 6, border: '1px solid var(--border)',
              background: 'var(--bg-secondary)', color: page <= 0 ? 'var(--text-muted)' : 'var(--text)',
              cursor: page <= 0 ? 'not-allowed' : 'pointer', fontSize: 12,
              opacity: page <= 0 ? 0.4 : 1,
            }}
          >
            <ChevronLeft size={12} />
            Previous
          </button>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            Page {page + 1} of {totalPages} · {total} total
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages - 1}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 10px',
              borderRadius: 6, border: '1px solid var(--border)',
              background: 'var(--bg-secondary)', color: page >= totalPages - 1 ? 'var(--text-muted)' : 'var(--text)',
              cursor: page >= totalPages - 1 ? 'not-allowed' : 'pointer', fontSize: 12,
              opacity: page >= totalPages - 1 ? 0.4 : 1,
            }}
          >
            Next
            <ChevronRight size={12} />
          </button>
        </div>
      )}
    </div>
  );
}
