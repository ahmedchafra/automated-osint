import { useState, useMemo, useRef, useEffect } from 'react';
import { ShieldCheck, Cloud, Loader2, ChevronDown, ChevronRight, Search, ExternalLink } from 'lucide-react';
import { useScanWorkspace } from '../../context/scan-workspace-state';
import apiClient from '../../api/client';

export function BrandProtectionTab() {
  const { state, dispatch } = useScanWorkspace();
  const [selectedDomainOverride, setSelectedDomain] = useState('');
  const selectedDomain = selectedDomainOverride || state.activeEnrichmentDomain || '';
  const [scanRunning, setScanRunning] = useState(false);
  const persistedScanRunning = state.jobs.some(job =>
    job.job_type === 'dnstwist_only'
    && ['QUEUED', 'RUNNING', 'RETRYING'].includes(job.status)
  );
  const isScanRunning = scanRunning || persistedScanRunning;
  const [expandedLookalike, setExpandedLookalike] = useState<string | null>(null);
  const scanLookalikeCountRef = useRef(0);
  const scanTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const lookalikes = state.findings.filter(f =>
    f.entity_type === 'LOOKALIKE_DOMAIN' || f.entity_type === 'PHISHING_SITE'
  );
  const cloudBuckets = state.findings.filter(f =>
    f.entity_type === 'CLOUD_BUCKET' || f.entity_type === 'EXPOSED_FILE'
  );
  const dorkResults = state.findings.filter(f =>
    f.entity_type === 'DORK_RESULT'
  );

  const subdomains = useMemo(() =>
    state.findings
      .filter(f => f.entity_type === 'SUBDOMAIN' && (
        f.source_module === 'dns_resolver' || Array.isArray(f.normalized_data?.resolved_ips)
      ))
      .map(f => f.entity_value),
    [state.findings]
  );

  const orgDomains = useMemo(() =>
    state.findings.filter(f => f.entity_type === 'DOMAIN_METADATA').map(f => f.entity_value),
    [state.findings]
  );

  const baseDomain = state.scan?.target_domain || '';
  const domainOptions = Array.from(new Set(
    [baseDomain, ...subdomains, ...orgDomains]
      .map(value => value.trim().toLowerCase())
      .filter(value => value && !value.includes('@') && !value.startsWith('*.'))
  ));

  const liveCount = lookalikes.filter(l => {
    const resolved = l.normalized_data?.resolved_ips;
    return Array.isArray(resolved) && resolved.length > 0;
  }).length;

  // Keep loading indicator active until new findings arrive or 120s timeout.
  useEffect(() => {
    if (!scanRunning) return;
    if (lookalikes.length > scanLookalikeCountRef.current) {
      setScanRunning(false);
      dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED', payload: {} });
      if (scanTimeoutRef.current) clearTimeout(scanTimeoutRef.current);
    }
    return () => {
      if (scanTimeoutRef.current) clearTimeout(scanTimeoutRef.current);
    };
  }, [lookalikes.length, scanRunning, dispatch]);

  const handleRunDnstwist = async () => {
    if (!selectedDomain || !state.scan?.id) return;
    // Snapshot current count so we can detect when new data arrives
    scanLookalikeCountRef.current = lookalikes.length;
    setScanRunning(true);
    dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_STARTED', domain: selectedDomain });
    // Safety timeout — fall back to idle after 120s even if no results came
    scanTimeoutRef.current = setTimeout(() => {
      setScanRunning(false);
      dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED', payload: {} });
    }, 120_000);
    try {
      await apiClient.post(`/scans/${state.scan.id}/dnstwist`, { domain: selectedDomain });
    } catch (err: unknown) {
      console.error('dnstwist failed:', err);
      setScanRunning(false);
      dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED', payload: {} });
    }
  };

  const toggleLookalike = (id: string) => {
    setExpandedLookalike(prev => prev === id ? null : id);
  };

  return (
    <div className="ws-brand">
      {/* Action panel */}
      <div style={{ marginBottom: 16, padding: '12px 16px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <ShieldCheck size={14} style={{ color: '#f59e0b' }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)' }}>Typosquatting Radar</span>
          </div>
          <div style={{ flex: 1 }} />
          <select
            value={selectedDomain}
            onChange={e => setSelectedDomain(e.target.value)}
            style={{
              padding: '5px 10px', borderRadius: 6, fontSize: 11, fontFamily: 'var(--font-mono)',
              background: 'var(--bg-primary)', border: '1px solid var(--border)', color: 'var(--text)',
              minWidth: 180,
            }}
          >
            <option value="">Select a domain...</option>
            {domainOptions.map(d => (
              <option key={d} value={d}>{d}{d === baseDomain ? ' (base)' : ''}</option>
            ))}
          </select>
          <button
            className="ws-enrich-btn-primary"
            disabled={!selectedDomain || isScanRunning}
            onClick={handleRunDnstwist}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '5px 14px', borderRadius: 6, fontSize: 11, fontWeight: 500, border: 'none',
              cursor: (!selectedDomain || isScanRunning) ? 'not-allowed' : 'pointer',
              opacity: (!selectedDomain || isScanRunning) ? 0.5 : 1,
              background: 'var(--accent)', color: '#fff',
            }}
          >
            {isScanRunning ? <Loader2 size={11} className="animate-spin" /> : <ShieldCheck size={11} />}
            {isScanRunning ? 'Scanning...' : 'Run dnstwist'}
          </button>
        </div>
        {isScanRunning && (
          <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-muted)' }}>
            Generating lookalike permutations for {selectedDomain}...
          </div>
        )}
      </div>

      {/* Summary bar */}
      {lookalikes.length > 0 && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
          <div style={{ padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, background: 'var(--severity-high)', color: '#fff' }}>
            {liveCount} LIVE (active DNS)
          </div>
          <div style={{ padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, background: 'var(--severity-low)', color: '#fff' }}>
            {lookalikes.length - liveCount} No DNS
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', alignSelf: 'center' }}>
            {lookalikes.length} permutations generated
          </div>
        </div>
      )}

      {/* Typosquatting */}
      <div className="ws-brand-section">
        <h3 className="mb-3 flex items-center gap-2">
          <ShieldCheck size={18} style={{ color: '#f59e0b' }} />
          Lookalike Domains ({lookalikes.length})
        </h3>
        {lookalikes.length === 0 ? (
          <div className="ws-coming-soon">
            <div className="ws-coming-soon-title">Lookalike domains not yet detected</div>
            <div className="ws-coming-soon-desc">Select a domain above and click "Run dnstwist" to generate lookalike domain permutations and check for active DNS resolution.</div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {lookalikes.map(l => {
              const d = l.normalized_data || {};
              const ips = Array.isArray(d.resolved_ips) ? d.resolved_ips.map(String) : [];
              const isLive = ips.length > 0;
              const isExpanded = expandedLookalike === l.id;
              return (
                <div key={l.id} style={{
                  padding: '8px 12px', borderRadius: 6,
                  background: isLive ? 'rgba(239, 68, 68, 0.05)' : 'var(--bg-primary)',
                  border: `1px solid ${isLive ? 'var(--severity-high)' : 'var(--border)'}`,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }} onClick={() => toggleLookalike(l.id)}>
                    {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600, color: 'var(--text-strong)', flex: 1 }}>
                      {l.entity_value}
                    </span>
                    {isLive ? (
                      <span className="badge badge-danger" style={{ fontSize: 9 }}>LIVE ({ips.length} IP{ips.length > 1 ? 's' : ''})</span>
                    ) : (
                      <span className="badge badge-success" style={{ fontSize: 9 }}>NO DNS</span>
                    )}
                    {d.permutation_type != null && <span className="badge badge-info" style={{ fontSize: 9 }}>{String(d.permutation_type)}</span>}
                  </div>
                  {isExpanded && (
                    <div style={{ marginTop: 8, paddingLeft: 20, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                      {isLive && (
                        <div style={{ marginBottom: 4 }}>
                          <span style={{ color: 'var(--text-muted)' }}>Resolved IPs: </span>
                          <span style={{ color: 'var(--text-strong)' }}>{ips.slice(0, 5).join(', ')}{ips.length > 5 ? ` +${ips.length - 5} more` : ''}</span>
                        </div>
                      )}
                      {d.http_status != null && (
                        <div style={{ marginBottom: 4 }}>
                          <span style={{ color: 'var(--text-muted)' }}>HTTP Status: </span>
                          <span style={{ color: 'var(--text-strong)' }}>{String(d.http_status)}</span>
                        </div>
                      )}
                      {d.mx_records != null && (
                        <div style={{ marginBottom: 4 }}>
                          <span style={{ color: 'var(--text-muted)' }}>MX: </span>
                          <span style={{ color: 'var(--text-strong)' }}>{String(d.mx_records)}</span>
                        </div>
                      )}
                      {d.dns_records != null && (
                        <div>
                          <span style={{ color: 'var(--text-muted)' }}>DNS: </span>
                          <span style={{ color: 'var(--text-strong)' }}>{String(d.dns_records)}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Dork / Search Results */}
      {dorkResults.length > 0 && (
        <div className="ws-brand-section" style={{ marginTop: 24 }}>
          <h3 className="mb-3 flex items-center gap-2">
            <Search size={18} style={{ color: '#06b6d4' }} />
            Dork / Search Results ({dorkResults.length})
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {dorkResults.map(r => {
              const nd = r.normalized_data || {};
              const title = String(nd.title || r.entity_value || '');
              const url = String(nd.url || nd.link || '');
              const snippet = String(nd.snippet || '');
              const query = String(nd.query || '');
              return (
                <div key={r.id} style={{
                  padding: '10px 14px', borderRadius: 6,
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                    <Search size={12} style={{ marginTop: 3, color: 'var(--text-muted)', flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-strong)', marginBottom: 2, wordBreak: 'break-word' }}>
                        {title}
                      </div>
                      {url && (
                        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', marginBottom: 2 }}>
                          <a href={url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', wordBreak: 'break-all' }}>
                            <ExternalLink size={10} style={{ marginRight: 4 }} />
                            {url}
                          </a>
                        </div>
                      )}
                      {snippet && (
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, fontStyle: 'italic' }}>
                          {snippet.length > 300 ? snippet.slice(0, 300) + '...' : snippet}
                        </div>
                      )}
                      <div style={{ fontSize: 10, color: 'var(--text-disabled)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
                        Query: {query.length > 80 ? query.slice(0, 80) + '...' : query}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Cloud Buckets & Exposed Files */}
      <div className="ws-brand-section" style={{ marginTop: 24 }}>
        <h3 className="mb-3 flex items-center gap-2">
          <Cloud size={18} style={{ color: '#0ea5e9' }} />
          Cloud Storage &amp; Exposed Files ({cloudBuckets.length})
        </h3>
        {cloudBuckets.length === 0 ? (
          <div className="ws-coming-soon">
            <div className="ws-coming-soon-title">No cloud buckets or exposed files found</div>
            <div className="ws-coming-soon-desc">Run a full scan to discover public S3 / GCP / Azure buckets and exposed sensitive files. Results from on-demand enrichment (Deep Domain Analysis, Threat Intel) also appear here.</div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {cloudBuckets.map(f => {
              const nd = f.normalized_data || {};
              const url = String(nd.url || f.entity_value || '');
              const isBucket = f.entity_type === 'CLOUD_BUCKET';
              const isPublic = nd.is_public === true;
              return (
                <div key={f.id} style={{
                  padding: '9px 12px', borderRadius: 6,
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                    {isBucket
                      ? <Cloud size={14} style={{ marginTop: 2, color: '#0ea5e9', flexShrink: 0 }} />
                      : <Search size={14} style={{ marginTop: 2, color: '#f59e0b', flexShrink: 0 }} />
                    }
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600, color: 'var(--text-strong)', wordBreak: 'break-all' }}>
                          {url}
                        </span>
                        {isBucket && nd.provider != null && (
                          <span className="badge" style={{ fontSize: 9, background: '#0ea5e920', color: '#0ea5e9', border: '1px solid #0ea5e940' }}>
                            {String(nd.provider)}
                          </span>
                        )}
                        {isBucket && (
                          <span className={`badge ${isPublic ? 'badge-danger' : 'badge-success'}`} style={{ fontSize: 9 }}>
                            {isPublic ? 'PUBLIC' : 'RESTRICTED'}
                          </span>
                        )}
                        {!isBucket && nd.file_type != null && (
                          <span className="badge badge-warning" style={{ fontSize: 9 }}>
                            {String(nd.file_type)}
                          </span>
                        )}
                      </div>
                      {isBucket && nd.status_code != null && (
                        <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text-muted)' }}>
                          HTTP {String(nd.status_code)}
                          {nd.bucket_name != null && <span> — bucket: <code style={{ fontSize: 10 }}>{String(nd.bucket_name)}</code></span>}
                        </div>
                      )}
                      {!isBucket && nd.snippet != null && (
                        <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                          {String(nd.snippet).length > 200 ? String(nd.snippet).slice(0, 200) + '…' : String(nd.snippet)}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
