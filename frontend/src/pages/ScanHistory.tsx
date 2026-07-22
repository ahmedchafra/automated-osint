import { useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Search,
  Shield,
  AlertTriangle,
  Crosshair,
  Globe,
  Server,
  Building2,
  Loader2,
  Eye,
  Trash2,
  XCircle,
  StopCircle,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import apiClient, { deleteScan, cancelScan } from '../api/client';
import { Link } from 'react-router-dom';
import { formatDistanceToNow } from 'date-fns';
import { useSearchParams } from 'react-router-dom';
import { useState, useMemo, useRef, useEffect } from 'react';

const PAGE_SIZE = 50;

interface ScanSummary {
  id: string;
  target_domain: string;
  target_type?: string;
  status: string;
  selected_vectors: string[];
  created_at: string;
  completed_at: string | null;
  findings_count: number;
}

const STATUS_MAP: Record<string, { class: string; label: string }> = {
  COMPLETED: { class: 'badge-success', label: 'Completed' },
  FAILED: { class: 'badge-danger', label: 'Failed' },
  RUNNING: { class: 'badge-accent', label: 'Running' },
  QUEUED: { class: 'badge-warning', label: 'Queued' },
  PENDING: { class: 'badge-warning', label: 'Pending' },
};

const VECTOR_ICONS: Record<string, typeof Globe> = {
  INFRASTRUCTURE: Globe,
  SERVICES: Shield,
  IDENTITY: Search,
  SEARCH: Search,
  USERNAME: Crosshair,
};

const TYPE_FILTERS = [
  { value: '', label: 'All', icon: Globe },
  { value: 'domain', label: 'Domain', icon: Globe },
  { value: 'ip', label: 'IP', icon: Server },
  { value: 'organization', label: 'Organization', icon: Building2 },
];

function ScanHistory() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [deleting, setDeleting] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const [searchInput, setSearchInput] = useState(searchParams.get('q') || '');
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const typeFilter = searchParams.get('type') || '';
  const skip = parseInt(searchParams.get('skip') || '0', 10);
  const searchQ = searchParams.get('q') || '';

  // Debounced search: update URL param 300ms after user stops typing
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      const params = new URLSearchParams(searchParams);
      if (searchInput.trim()) {
        params.set('q', searchInput.trim());
      } else {
        params.delete('q');
      }
      params.delete('skip'); // reset pagination on new search
      setSearchParams(params, { replace: true });
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput]);

  const { data: scans, isFetching, error, isLoading } = useQuery({
    queryKey: ['scanHistory', skip, searchQ],
    queryFn: async () => {
      let url = `/scans/?limit=${PAGE_SIZE}&skip=${skip}`;
      if (searchQ) url += `&q=${encodeURIComponent(searchQ)}`;
      const response = await apiClient.get(url);
      return response.data as ScanSummary[];
    },
    refetchInterval: 5000,
    /* keep previous data while fetching new results so the UI —
       especially the search input — never unmounts or flashes. */
    placeholderData: keepPreviousData,
  });

  const filteredScans = useMemo(() => {
    const list: ScanSummary[] = scans || [];
    if (!typeFilter) return list;
    return list.filter(s => (s.target_type || 'domain') === typeFilter);
  }, [scans, typeFilter]);

  const handleDelete = async (scanId: string) => {
    setDeleting(scanId);
    setDeleteError(null);
    try {
      await deleteScan(scanId);
      queryClient.invalidateQueries({ queryKey: ['scanHistory'] });
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to delete scan.';
      setDeleteError(detail);
    } finally {
      setDeleting(null);
      setConfirmDelete(null);
    }
  };

  const handleCancel = async (scanId: string) => {
    setCancelling(scanId);
    setDeleteError(null);
    try {
      await cancelScan(scanId);
      queryClient.invalidateQueries({ queryKey: ['scanHistory'] });
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to cancel scan.';
      setDeleteError(detail);
    } finally {
      setCancelling(null);
    }
  };

  const goToPage = (newSkip: number) => {
    const params = new URLSearchParams(searchParams);
    if (newSkip > 0) params.set('skip', String(newSkip));
    else params.delete('skip');
    setSearchParams(params, { replace: true });
  };

  // On the first-ever load there's no previous data to show, so we render
  // a centered spinner.  After that, keepPreviousData keeps the table alive
  // across pagination / search — never unmount the search input.
  const isInitialLoading = isLoading;

  const scanList: ScanSummary[] = typeFilter ? filteredScans : (scans || []);
  const hasMore = (scans?.length || 0) >= PAGE_SIZE;

  return (
    <motion.div
      className="ws-container"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <div className="ws-header">
        <div className="ws-header-left">
          <Crosshair size={20} style={{ color: 'var(--accent)' }} />
          <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', color: 'var(--text-strong)' }}>
            Scan History
          </h1>
        </div>
        <Link to="/scans/new" className="btn btn-primary">
          <Crosshair size={14} />
          <span>New Scan</span>
        </Link>
      </div>

      {deleteError && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="auth-error"
          style={{ marginBottom: 'var(--space-4)' }}
        >
          <AlertTriangle size={14} />
          <span>{deleteError}</span>
        </motion.div>
      )}

      {/* Search + Filter bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        marginBottom: 'var(--space-4)', flexWrap: 'wrap',
      }}>
        {/* Search input */}
        <div style={{
          position: 'relative', flex: '1 1 220px', minWidth: 180,
        }}>
          <Search size={14} style={{
            position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)',
            color: 'var(--text-muted)', pointerEvents: 'none',
          }} />
          <input
            type="text"
            placeholder="Search by target name..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            style={{
              width: '100%', padding: '7px 12px 7px 32px', borderRadius: 6,
              fontSize: 12, fontFamily: 'var(--font-mono)',
              background: 'var(--bg-primary)', border: '1px solid var(--border)',
              color: 'var(--text)',
            }}
          />
          {searchInput && (
            <button
              onClick={() => setSearchInput('')}
              style={{
                position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
                background: 'none', border: 'none', cursor: 'pointer',
                color: 'var(--text-muted)', padding: 2, lineHeight: 1,
              }}
              title="Clear search"
            >
              <XCircle size={14} />
            </button>
          )}
        </div>

        {/* Type filter pills */}
        {TYPE_FILTERS.map(({ value, label, icon: Icon }) => (
          <button
            key={value}
            className={`ns-type-btn ${typeFilter === value ? 'ns-type-btn-active' : ''}`}
            onClick={() => {
              const params = new URLSearchParams(searchParams);
              if (value) params.set('type', value);
              else params.delete('type');
              setSearchParams(params);
            }}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '6px 12px', fontSize: 'var(--text-xs)',
            }}
          >
            <Icon size={14} />
            <span>{label}</span>
          </button>
        ))}

        {(typeFilter || searchQ) && (
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginLeft: 8 }}>
            {scanList.length} scan{(scanList.length !== 1) ? 's' : ''}
          </span>
        )}
      </div>

      {/* Inline error banner — doesn't destroy the input layout */}
      {error && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="auth-error"
          style={{ marginBottom: 'var(--space-4)' }}
        >
          <AlertTriangle size={14} />
          <span>Unable to load scan history. Retrying automatically&hellip;</span>
        </motion.div>
      )}

      {/* Initial loading (no previous data yet) */}
      {isInitialLoading && !scans ? (
        <div className="card text-center py-8" style={{ color: 'var(--text-muted)' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 'var(--space-3)',
            padding: 'var(--space-4) var(--space-6)',
            background: 'var(--glass-bg)', borderRadius: 'var(--radius-lg)',
            border: '1px solid var(--glass-border)',
            backdropFilter: 'blur(12px)',
          }}>
            <div style={{
              width: 18, height: 18,
              border: '2px solid var(--border-medium)', borderTopColor: 'var(--accent)',
              borderRadius: '50%', animation: 'spin 0.8s linear infinite',
            }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>
              Loading scan history&hellip;
            </span>
          </div>
        </div>
      ) : scanList.length === 0 ? (
        <div className="card text-center" style={{ padding: '3rem' }}>
          <Globe size={40} style={{ margin: '0 auto 1rem', opacity: 0.4 }} />
          <h3 style={{ color: 'var(--text-strong)', marginBottom: '0.5rem' }}>
            {searchQ || typeFilter ? 'No matching scans' : 'No scans yet'}
          </h3>
          <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
            {searchQ || typeFilter
              ? 'Try a different search term or clear the filters above.'
              : 'Launch your first reconnaissance operation to begin collecting intelligence.'}
          </p>
          {!searchQ && !typeFilter && (
            <Link to="/scans/new" className="btn btn-primary">
              <Crosshair size={14} />
              <span>Launch First Scan</span>
            </Link>
          )}
        </div>
      ) : (
        <>
          {/* Subtle fetching indicator above the table */}
          {isFetching && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
              marginBottom: 8,
            }}>
              <div style={{
                width: 10, height: 10,
                border: '1.5px solid var(--border-medium)', borderTopColor: 'var(--accent)',
                borderRadius: '50%', animation: 'spin 0.8s linear infinite',
              }} />
              Updating&hellip;
            </div>
          )}
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Vectors</th>
                  <th>Findings</th>
                  <th>Started</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scanList.map(scan => {
                  const statusInfo = STATUS_MAP[scan.status] || STATUS_MAP.PENDING;
                  return (
                    <tr key={scan.id}>
                      <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-strong)', fontSize: 'var(--text-sm)' }}>
                          {scan.target_domain}
                        </span>
                        {scan.target_type && scan.target_type !== 'domain' && (
                          <span className="badge badge-info" style={{
                            fontSize: 9, padding: '1px 5px', textTransform: 'uppercase',
                            letterSpacing: '0.03em', opacity: 0.8,
                          }}>
                            {scan.target_type}
                          </span>
                        )}
                      </div>
                    </td>
                      <td>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                          {scan.status === 'RUNNING' && <Loader2 size={12} className="spin" style={{ color: 'var(--accent)' }} />}
                          <span className={`badge ${statusInfo.class}`}>{statusInfo.label}</span>
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {(scan.selected_vectors || []).map(v => {
                            const Icon = VECTOR_ICONS[v] || Shield;
                            return (
                              <span key={v} className="badge badge-info" style={{ fontSize: 10, padding: '2px 6px', display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                                <Icon size={10} />
                                {v}
                              </span>
                            );
                          })}
                        </div>
                      </td>
                      <td>
                        <span style={{
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          color: (scan.findings_count || 0) > 0 ? 'var(--severity-high)' : 'var(--text-muted)',
                          fontSize: 'var(--text-sm)',
                        }}>
                          {scan.findings_count || 0}
                        </span>
                      </td>
                      <td>
                        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
                          {scan.created_at
                            ? formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })
                            : 'Unknown'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', alignItems: 'center' }}>
                          {(scan.status === 'RUNNING' || scan.status === 'QUEUED' || scan.status === 'PENDING') && (
                            <button
                              className="btn btn-secondary"
                              style={{
                                padding: '4px 8px', fontSize: 'var(--text-xs)',
                                color: '#fb923c', borderColor: 'rgba(251,146,60,0.3)',
                              }}
                              onClick={() => handleCancel(scan.id)}
                              disabled={cancelling === scan.id}
                              title="Cancel scan"
                            >
                              {cancelling === scan.id ? (
                                <Loader2 size={12} className="spin" />
                              ) : (
                                <StopCircle size={12} />
                              )}
                            </button>
                          )}
                          {confirmDelete === scan.id ? (
                            <>
                              <span style={{ fontSize: 11, color: 'var(--severity-critical)' }}>Confirm?</span>
                              <button
                                className="btn btn-danger"
                                style={{ padding: '4px 8px', fontSize: 'var(--text-xs)' }}
                                onClick={() => handleDelete(scan.id)}
                                disabled={deleting === scan.id}
                              >
                                {deleting === scan.id ? (
                                  <Loader2 size={12} className="spin" />
                                ) : (
                                  <Trash2 size={12} />
                                )}
                              </button>
                              <button
                                className="btn btn-secondary"
                                style={{ padding: '4px 8px', fontSize: 'var(--text-xs)' }}
                                onClick={() => setConfirmDelete(null)}
                              >
                                <XCircle size={12} />
                              </button>
                            </>
                          ) : (
                            <button
                              className="btn btn-secondary"
                              style={{ padding: '4px 8px', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}
                              onClick={() => setConfirmDelete(scan.id)}
                              title="Delete scan"
                              disabled={scan.status === 'RUNNING' || scan.status === 'QUEUED' || scan.status === 'PENDING'}
                            >
                              <Trash2 size={12} />
                            </button>
                          )}
                          <Link
                            to={`/scans/${scan.id}`}
                            className="btn btn-secondary"
                            style={{ padding: '4px 12px', fontSize: 'var(--text-xs)' }}
                          >
                            <Eye size={12} />
                            <span>View Details</span>
                          </Link>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            marginTop: 16, fontSize: 12, color: 'var(--text-muted)',
          }}>
            <span>
              {skip + 1}–{skip + scanList.length}
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                className="btn btn-secondary"
                disabled={skip === 0}
                onClick={() => goToPage(skip - PAGE_SIZE)}
                style={{
                  padding: '5px 12px', fontSize: 11,
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                }}
              >
                <ChevronLeft size={12} />
                <span>Previous</span>
              </button>
              <button
                className="btn btn-secondary"
                disabled={!hasMore}
                onClick={() => goToPage(skip + PAGE_SIZE)}
                style={{
                  padding: '5px 12px', fontSize: 11,
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                }}
              >
                <span>Next</span>
                <ChevronRight size={12} />
              </button>
            </div>
          </div>
        </>
      )}
    </motion.div>
  );
}

export default ScanHistory;
