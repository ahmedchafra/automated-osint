import { useState, useMemo } from 'react';
import { ChevronDown, ChevronRight, Search, Loader2, Zap, Mail, ShieldCheck, Key, Filter, X, Brain, Server, History, Code, Globe } from 'lucide-react';
import { useScanWorkspace } from '../../context/ScanWorkspaceContext';
import { SeverityBadge } from '../FindingsTable';
import { DeepAnalysisProgress, type ProgressItem } from './DeepAnalysisProgress';
import apiClient from '../../api/client';
import { isAxiosError } from 'axios';

const PAGE_SIZE = 25;

export function InfrastructureTab() {
  const { state, dispatch } = useScanWorkspace();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(0);
  const [selectedEmails, setSelectedEmails] = useState<Set<string>>(new Set());
  const [enrichingIps, setEnrichingIps] = useState<Set<string>>(new Set());
  const [emailSearch, setEmailSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string>('');
  const [showHarvesterPicker, setShowHarvesterPicker] = useState<string | null>(null);
  const [harvesterMode, setHarvesterMode] = useState<'quick' | 'full' | 'auto'>('auto');
  const [showRawWhois, setShowRawWhois] = useState(false);
  const [activeValidationError, setActiveValidationError] = useState<string | null>(null);
  const activeJobs = state.jobs.filter(job => ['QUEUED', 'RUNNING', 'RETRYING'].includes(job.status));
  const ledgerEnrichingIps = activeJobs
    .filter(job => job.job_type === 'shodan_enrich' || job.job_type === 'censys_enrich')
    .map(job => job.input_value)
    .filter((value): value is string => Boolean(value));
  const effectiveEnrichingIps = new Set([...enrichingIps, ...ledgerEnrichingIps]);
  const domainAnalysisRunning = state.domainDeepAnalysisRunning
    || activeJobs.some(job => job.job_type === 'domain_deep_analysis');
  const emailAnalysisRunning = state.emailDeepAnalysisRunning
    || activeJobs.some(job => job.job_type === 'email_deep_analysis');
  const activeValidationRunning = activeJobs.some(job => job.job_type === 'active_validation');

  const mainDomain = state.scan?.target_domain || '';
  const candidateAssets = state.assets.filter(asset => asset.state === 'CANDIDATE');
  const resolvedAssets = state.assets.filter(asset => asset.state === 'RESOLVED');
  const liveAssets = state.assets.filter(asset => asset.state === 'LIVE');
  const wildcardAssets = state.assets.filter(asset => asset.wildcard_suspected);
  const liveUrls = liveAssets.filter(asset => asset.asset_type === 'URL');
  const activeEligibleAssets = state.assets.filter(asset =>
    asset.in_scope
    && !asset.wildcard_suspected
    && (asset.state === 'RESOLVED' || asset.state === 'LIVE')
    && ['DOMAIN', 'SUBDOMAIN', 'IP_ADDRESS', 'URL'].includes(asset.asset_type)
  );
  const subdomains = useMemo(() => {
    const byValue = new Map<string, typeof state.findings[number]>();
    for (const finding of state.findings.filter(f => f.entity_type === 'SUBDOMAIN')) {
      const existing = byValue.get(finding.entity_value);
      if (!existing || finding.source_module === 'dns_resolver') {
        byValue.set(finding.entity_value, finding);
      }
    }
    return Array.from(byValue.values());
  }, [state.findings]);
  const allIps = state.findings.filter(f => f.entity_type === 'IP_ADDRESS');
  const ports = state.findings.filter(f => f.entity_type === 'PORT_SERVICE');
  const cves = state.findings.filter(f => f.entity_type === 'CVE');
  const hostMeta = state.findings.filter(f => f.entity_type === 'HOST_METADATA');
  const dnsRecords = state.findings.filter(f => f.entity_type === 'DNS_RECORD');
  const tlsCerts = state.findings.filter(f => f.entity_type === 'TLS_CERT');
  const whoisData = state.findings.filter(f => f.entity_type === 'DOMAIN_METADATA' && f.source_module === 'whois_lookup');
  const asnInfo = state.findings.filter(f => f.entity_type === 'ASN_INFO');
  // Web recon entity types (from deep analysis)
  const technologies = state.findings.filter(f => f.entity_type === 'TECHNOLOGY');
  const httpHeaders = state.findings.filter(f => f.entity_type === 'HTTP_HEADER');
  const historicalUrls = state.findings.filter(f => f.entity_type === 'HISTORICAL_URL');
  const waybackSnapshots = state.findings.filter(f => f.entity_type === 'WAYBACK_SNAPSHOT');
  const activeVulnerabilities = state.findings.filter(f => f.entity_type === 'VULNERABILITY');

  // Unique source modules from findings
  const sourceModules = useMemo(() => {
    const modules = new Set<string>();
    subdomains.forEach(s => { if (s.source_module) modules.add(s.source_module); });
    ports.forEach(p => { if (p.source_module) modules.add(p.source_module); });
    cves.forEach(c => { if (c.source_module) modules.add(c.source_module); });
    return Array.from(modules).sort();
  }, [subdomains, ports, cves]);

  // Searchable + filterable subdomains
  const filteredSubdomains = useMemo(() => {
    let result = subdomains;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(s => s.entity_value.toLowerCase().includes(q));
    }
    if (sourceFilter) {
      result = result.filter(s => s.source_module === sourceFilter);
    }
    return result;
  }, [subdomains, searchQuery, sourceFilter]);

  const totalPages = Math.ceil(filteredSubdomains.length / PAGE_SIZE);
  const pagedSubdomains = filteredSubdomains.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  // Deep analysis data for the selected domain
  const domainEmails = useMemo(() => {
    const seen = new Set<string>();
    return state.findings.filter(f => {
      if (f.entity_type !== 'EMAIL') return false;
      if (seen.has(f.entity_value)) return false;
      seen.add(f.entity_value);
      return true;
    });
  }, [state.findings]);

  const domainSecrets = state.findings.filter(f => f.entity_type === 'LEAKED_SECRET');
  const domainRepos = state.findings.filter(f => f.entity_type === 'GITHUB_REPO');
  // All lookalikes from any deep analysis — kept visible so the user can
  // see the full picture. A domain filter/search could be added later.
  const domainLookalikes = state.findings.filter(f => f.entity_type === 'LOOKALIKE_DOMAIN');

  const filteredEmails = useMemo(() => {
    if (!emailSearch.trim()) return domainEmails;
    const q = emailSearch.toLowerCase();
    return domainEmails.filter(e => e.entity_value.toLowerCase().includes(q));
  }, [domainEmails, emailSearch]);

  // Email deep analysis results
  const breaches = state.findings.filter(f => f.entity_type === 'BREACH');
  const emailPlatforms = state.findings.filter(f => f.entity_type === 'EMAIL_PLATFORM');
  const profiles = state.findings.filter(f => f.entity_type === 'PROFILE');

  const handleDeepAnalysis = async (domain: string) => {
    // Show theHarvester mode picker instead of immediately POSTing
    setShowHarvesterPicker(domain);
  };

  const startDeepAnalysis = async (domain: string, mode: 'quick' | 'full' | 'auto') => {
    if (!state.scan?.id) return;
    setShowHarvesterPicker(null);
    setHarvesterMode(mode);
    setSelectedEmails(new Set());
    dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_STARTED', domain });
    try {
      await apiClient.post(`/scans/${state.scan.id}/domain-deep-analysis`, { domain, theharvester_mode: mode });
    } catch (err: any) {
      dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED', payload: { error: err.message } });
    }
  };

  const handleEmailDeepAnalysis = async () => {
    if (selectedEmails.size === 0 || !state.scan?.id) return;
    dispatch({ type: 'EMAIL_DEEP_ANALYSIS_STARTED', emails: Array.from(selectedEmails) });
    try {
      await apiClient.post(`/scans/${state.scan.id}/email-deep-analysis`, {
        emails: Array.from(selectedEmails),
      });
    } catch (err: any) {
      dispatch({ type: 'EMAIL_DEEP_ANALYSIS_COMPLETED', payload: { error: err.message } });
    }
  };

  const handleEnrich = async (ip: string, provider: string = 'shodan') => {
    if (!state.scan?.id || effectiveEnrichingIps.has(ip)) return;
    setEnrichingIps(prev => new Set(prev).add(ip));
    try {
      await apiClient.post(`/scans/${state.scan.id}/shodan-enrich`, { ip, provider });
    } catch (err: any) {
      console.error('Enrich failed:', err);
    } finally {
      setEnrichingIps(prev => { const n = new Set(prev); n.delete(ip); return n; });
    }
  };

  const handleActiveValidation = async () => {
    if (!state.scan?.id || state.scan.scan_mode !== 'active' || activeValidationRunning) return;
    const confirmed = window.confirm(
      'Run Naabu, Nmap service detection, and safe Nuclei templates against the verified assets in this scan? Only continue if you are authorized to test these targets.'
    );
    if (!confirmed) return;
    setActiveValidationError(null);
    try {
      await apiClient.post(`/scans/${state.scan.id}/active-validation`);
    } catch (err: unknown) {
      if (isAxiosError<{ detail?: string }>(err)) {
        setActiveValidationError(err.response?.data?.detail || err.message);
      } else {
        setActiveValidationError(err instanceof Error ? err.message : 'Active validation failed to start');
      }
    }
  };

  const toggleEmail = (email: string) => {
    setSelectedEmails(prev => {
      const next = new Set(prev);
      if (next.has(email)) next.delete(email);
      else next.add(email);
      return next;
    });
  };

  if (subdomains.length === 0 && allIps.length === 0 && state.assets.length === 0) {
    return <div className="ws-empty">No infrastructure data yet. Run the INFRASTRUCTURE vector to populate this tab.</div>;
  }

  const getIpsForSubdomain = (sub: string) => {
    const subFindings = subdomains.filter(f => f.entity_value === sub);
    const ips: string[] = [];
    for (const f of subFindings) {
      const resolved = f.normalized_data?.resolved_ips;
      if (Array.isArray(resolved)) ips.push(...resolved);
    }
    return [...new Set(ips)];
  };

  const getPortsForIp = (ip: string) => ports.filter(f => f.entity_value.startsWith(ip));
  const getCvesForIp = (ip: string) => cves.filter(f => f.normalized_data?.ip === ip || f.entity_value.includes(ip));
  const getHostMetaForIp = (ip: string) => hostMeta.filter(f => f.entity_value === ip);
  const getDnsForIp = (ip: string) => dnsRecords.filter(f => f.entity_value === ip);

  const getDnsRecordsForSubdomain = (sub: string) => {
    const dnsFindings = subdomains.filter(f => f.entity_value === sub && f.source_module === 'dns_resolver');
    if (dnsFindings.length === 0) return null;
    return dnsFindings[0].normalized_data?.dns_records || null;
  };
  const getTlsForIp = (ip: string) => tlsCerts.filter(f => f.normalized_data?.ip === ip);

  const getBreachCountForEmail = (email: string) => breaches.filter(b =>
    b.normalized_data?.email === email || b.entity_value.startsWith(email)
  ).length;

  const getPlatformsForEmail = (email: string) => emailPlatforms.filter(p =>
    p.normalized_data?.email === email
  );

  const getProfilesForEmail = (email: string) => {
    const username = email.split('@')[0];
    return profiles.filter(p =>
      p.normalized_data?.username === username || p.normalized_data?.email === email
    );
  };

  return (
    <div className="ws-infra">
      {state.assets.length > 0 && (
        <div style={{
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '12px 16px', marginBottom: 16,
        }}>
          <div className="flex items-center justify-between" style={{ marginBottom: 10 }}>
            <div className="flex items-center gap-2">
              <ShieldCheck size={14} />
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)' }}>
                Canonical Asset Inventory
              </span>
            </div>
            <div className="flex items-center gap-2">
              {state.scan?.scan_mode === 'active' && (
                <button
                  className="ws-enrich-btn"
                  disabled={activeValidationRunning || activeEligibleAssets.length === 0}
                  onClick={handleActiveValidation}
                  title="Run Naabu → Nmap and Nuclei on verified assets"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, padding: '4px 8px' }}
                >
                  {activeValidationRunning ? <Loader2 size={11} className="spin" /> : <Zap size={11} />}
                  {activeValidationRunning ? 'Active validation running' : 'Run active validation'}
                </button>
              )}
              <span style={{
                padding: '2px 7px', borderRadius: 4, fontSize: 9,
                textTransform: 'uppercase', fontFamily: 'var(--font-mono)',
                background: 'var(--bg-primary)', color: 'var(--text-muted)',
                border: '1px solid var(--border)',
              }}>
                {state.scan?.scan_mode || 'validated'} mode
              </span>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 8 }}>
            {[
              ['Candidates', candidateAssets.length, 'var(--text-muted)'],
              ['Resolved', resolvedAssets.length, 'var(--severity-info)'],
              ['Live HTTP', liveUrls.length, '#10b981'],
              ['Wildcard', wildcardAssets.length, '#f59e0b'],
            ].map(([label, value, color]) => (
              <div key={String(label)} style={{
                padding: '8px 10px', borderRadius: 6, background: 'var(--bg-primary)',
                border: '1px solid var(--border)',
              }}>
                <div style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  {label}
                </div>
                <div style={{ fontSize: 18, fontWeight: 700, color: String(color), fontFamily: 'var(--font-mono)' }}>
                  {value}
                </div>
              </div>
            ))}
          </div>
          {liveUrls.length > 0 && (
            <div style={{ marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {liveUrls.slice(0, 12).map(asset => (
                <a
                  key={asset.id}
                  href={asset.canonical_value}
                  target="_blank"
                  rel="noreferrer noopener"
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    padding: '3px 7px', borderRadius: 4, fontSize: 10,
                    fontFamily: 'var(--font-mono)', color: '#10b981',
                    background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)',
                  }}
                >
                  <Globe size={10} />
                  {asset.canonical_value}
                  {asset.http_metadata?.status_code != null && ` [${String(asset.http_metadata.status_code)}]`}
                </a>
              ))}
            </div>
          )}
          {wildcardAssets.length > 0 && (
            <div style={{ marginTop: 8, fontSize: 10, color: '#f59e0b' }}>
              {wildcardAssets.length} wildcard-matching hostname{wildcardAssets.length === 1 ? '' : 's'} retained as evidence and excluded from service fan-out.
            </div>
          )}
          {activeValidationError && (
            <div style={{ marginTop: 8, fontSize: 10, color: '#ef4444' }}>{activeValidationError}</div>
          )}
          {activeVulnerabilities.length > 0 && (
            <div style={{ marginTop: 8, fontSize: 10, color: '#f97316' }}>
              Active validation has reported {activeVulnerabilities.length} potential vulnerabilit{activeVulnerabilities.length === 1 ? 'y' : 'ies'}; review them in Web OSINT.
            </div>
          )}
        </div>
      )}

      {/* Subdomain table with search + pagination */}
      <div className="ws-enrich-panel" style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderRadius: 8,
        padding: '12px 16px',
        marginBottom: 16,
      }}>
        <div className="flex items-center justify-between mb-2 ws-infra-toolbar">
          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)' }}>
            Subdomains ({subdomains.length})
          </span>
          <div className="flex items-center gap-2 ws-infra-controls">
            {sourceModules.length > 1 && (
              <div className="flex items-center gap-1 px-2 py-1" style={{
                background: 'var(--bg-primary)',
                border: '1px solid var(--border)',
                borderRadius: 6,
              }}>
                <Filter size={11} style={{ color: 'var(--text-muted)' }} />
                <select
                  value={sourceFilter}
                  onChange={e => { setSourceFilter(e.target.value); setPage(0); }}
                  style={{
                    background: 'transparent', border: 'none', outline: 'none',
                    fontSize: 11, color: 'var(--text)', fontFamily: 'var(--font-mono)', cursor: 'pointer',
                  }}
                >
                  <option value="">All sources</option>
                  {sourceModules.map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
            )}
            <div className="flex items-center gap-2 px-3 py-1 ws-infra-search" style={{
              background: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              borderRadius: 6,
            }}>
              <Search size={13} style={{ color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Filter subdomains..."
                value={searchQuery}
                onChange={e => { setSearchQuery(e.target.value); setPage(0); }}
                style={{
                  background: 'transparent', border: 'none', outline: 'none',
                  fontSize: 12, color: 'var(--text)', width: 180, fontFamily: 'var(--font-mono)',
                }}
              />
            </div>
            {totalPages > 1 && (
              <span className="ws-infra-page-count" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Page {page + 1}/{totalPages}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* ── Whois Registration Info Card ────────────────────────── */}
      {whoisData.length > 0 && (() => {
        const w = whoisData[0];
        const nd = w.normalized_data || {};
        return (
          <div style={{
            marginBottom: 16, padding: '8px 14px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: 8, fontSize: 11,
          }}>
            <div className="flex items-center gap-2 mb-2" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-strong)' }}>
              <ShieldCheck size={13} /> Registration Info
            </div>
            <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', alignItems: 'baseline' }}>
              {nd.registrar != null && <span>Registrar: <strong style={{ color: 'var(--text-strong)' }}>{String(nd.registrar)}</strong></span>}
              {nd.creation_date != null && <span>Created: <strong style={{ color: 'var(--text-strong)' }}>{String(nd.creation_date).split('T')[0]}</strong></span>}
              {nd.expiration_date != null && (
                <span>Expires: <strong style={{
                  color: String(nd.expiration_date).split('T')[0] < new Date().toISOString().split('T')[0] ? '#ef4444' : 'var(--text-strong)'
                }}>{String(nd.expiration_date).split('T')[0]}</strong></span>
              )}
              {Array.isArray(nd.name_servers) && nd.name_servers.length > 0 && (
                <span>NS: <strong style={{ color: 'var(--text-strong)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
                  {nd.name_servers.join(', ')}
                </strong></span>
              )}
            </div>
            {nd.raw_whois != null && (
              <div style={{ marginTop: 6 }}>
                <button
                  className="ws-enrich-btn"
                  onClick={() => setShowRawWhois(!showRawWhois)}
                  style={{ fontSize: 10, padding: '2px 8px' }}
                >
                  {showRawWhois ? 'Hide' : 'Show'} Raw Whois
                </button>
                {showRawWhois && (
                  <pre style={{
                    marginTop: 6, padding: 8, fontSize: 10, lineHeight: 1.4,
                    maxHeight: 200, overflow: 'auto', borderRadius: 6,
                    background: 'var(--bg-primary)', border: '1px solid var(--border)',
                    color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                    whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                  }}>{String(nd.raw_whois)}</pre>
                )}
              </div>
            )}
          </div>
        );
      })()}

      {/* ── ASN Info Card (from theHarvester JSON output) ────────── */}
      {asnInfo.length > 0 && (
        <div style={{
          marginBottom: 16, padding: '8px 14px',
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: 8, fontSize: 11,
        }}>
          <div className="flex items-center gap-2 mb-2" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-strong)' }}>
            <Globe size={13} /> Autonomous Systems
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {asnInfo.map((a, i) => (
              <span key={i} style={{
                padding: '2px 8px', borderRadius: 4,
                background: 'var(--bg-primary)',
                border: '1px solid var(--border)',
                fontFamily: 'var(--font-mono)', fontSize: 10,
              }}>
                {a.entity_value}
              </span>
            ))}
          </div>
        </div>
      )}

      {/*** Web Recon card was removed from the main Infrastructure tab.
           Deep analysis results (technologies, HTTP headers, Wayback data,
           historical URLs, lookalikes, CVEs from technology_cve) are
           exclusively shown in the DeepAnalysisPanel below, scoped to the
           specific domain the analysis was run on. ***/}

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th style={{ width: 30 }}></th>
              <th>Subdomain</th>
              <th style={{ width: 90 }}>Source</th>
              <th>Resolved IPs</th>
              <th>Open Ports</th>
              <th>CVEs</th>
              <th style={{ width: 140 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {/* ── Main domain (always shown first, if it matches the search) ── */}
            {mainDomain && (!sourceFilter) && (
              searchQuery.trim() === '' || mainDomain.toLowerCase().includes(searchQuery.toLowerCase())
            ) && (
              <SubdomainRow
                key="__main_domain__"
                subdomain={mainDomain}
                sourceModule={undefined}
                discoverySource="main target"
                ips={allIps.map(f => f.entity_value)}
                ports={ports}
                cves={cves}
                dnsRecords={null}
                hostMeta={hostMeta}
                tlsCerts={tlsCerts}
                crtshCerts={[]}
                expanded={expanded['__main_domain__']}
                onToggle={() => setExpanded(prev => ({ ...prev, ['__main_domain__']: !prev['__main_domain__'] }))}
                onDeepAnalysis={() => handleDeepAnalysis(mainDomain)}
                isDeepAnalyzing={domainAnalysisRunning}
                hasDeepResults={state.domainDeepAnalysisDomain === mainDomain}
                onEnrich={handleEnrich}
                enrichingIps={effectiveEnrichingIps}
                isMainDomain
              />
            )}
            {pagedSubdomains.map(sub => {
              const ips = getIpsForSubdomain(sub.entity_value);
              const isExpanded = expanded[sub.entity_value];
              const subCves = ips.flatMap(ip => getCvesForIp(ip));
              const isDeepAnalyzing = domainAnalysisRunning;
              const hasDeepResults = state.domainDeepAnalysisDomain === sub.entity_value;
              const dnsRecordsForSub = getDnsRecordsForSubdomain(sub.entity_value);
              const subHostMeta = hostMeta.filter(h => ips.includes(h.entity_value));
              const subTlsCerts = tlsCerts.filter(t =>
                typeof t.normalized_data?.ip === 'string' && ips.includes(t.normalized_data.ip)
              );
              // Crtsh certs whose subdomains_covered includes this subdomain
              const crtshCerts = tlsCerts.filter(t =>
                t.source_module === 'crtsh' &&
                Array.isArray(t.normalized_data?.subdomains_covered) &&
                t.normalized_data.subdomains_covered.includes(sub.entity_value)
              );
              return (
                <SubdomainRow
                  key={sub.id}
                  subdomain={sub.entity_value}
                  sourceModule={sub.source_module}
                  discoverySource={typeof sub.normalized_data?.discovery_source === 'string'
                    ? sub.normalized_data.discovery_source
                    : undefined}
                  ips={ips}
                  ports={ips.flatMap(ip => getPortsForIp(ip))}
                  cves={subCves}
                  dnsRecords={dnsRecordsForSub as Record<string, string[]> | null}
                  hostMeta={subHostMeta}
                  tlsCerts={subTlsCerts}
                  crtshCerts={crtshCerts}
                  expanded={isExpanded}
                  onToggle={() => setExpanded(prev => ({ ...prev, [sub.entity_value]: !prev[sub.entity_value] }))}
                  onDeepAnalysis={() => handleDeepAnalysis(sub.entity_value)}
                  isDeepAnalyzing={isDeepAnalyzing}
                  hasDeepResults={hasDeepResults}
                  onEnrich={handleEnrich}
                  enrichingIps={effectiveEnrichingIps}
                />
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination controls — clean Previous/Next with page info */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-3" style={{ padding: '0 8px' }}>
          <div className="flex items-center gap-2">
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {filteredSubdomains.length} subdomains · Page {page + 1} of {totalPages}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              className="ws-enrich-btn"
              disabled={page === 0}
              onClick={() => setPage(p => p - 1)}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 12px', fontSize: 12 }}
            >
              ← Previous
            </button>
            <button
              className="ws-enrich-btn"
              disabled={page >= totalPages - 1}
              onClick={() => setPage(p => p + 1)}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 12px', fontSize: 12 }}
            >
              Next →
            </button>
          </div>
        </div>
      )}

      {/* theHarvester mode picker modal */}
      {showHarvesterPicker && (
        <div
          onClick={() => setShowHarvesterPicker(null)}
          style={{
            position: 'fixed', inset: 0, zIndex: 1000,
            background: 'rgba(0,0,0,0.5)', display: 'flex',
            alignItems: 'center', justifyContent: 'center',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderRadius: 12, padding: 24, maxWidth: 420, width: '90%',
              boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
            }}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Brain size={18} style={{ color: 'var(--accent)' }} />
                <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-strong)' }}>
                  theHarvester Mode
                </span>
              </div>
              <button
                onClick={() => setShowHarvesterPicker(null)}
                className="ws-enrich-btn"
                style={{ padding: 4, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
              >
                <X size={14} />
              </button>
            </div>

            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.5 }}>
              Choose how theHarvester should scan <strong style={{ color: 'var(--text-strong)' }}>{showHarvesterPicker}</strong>:
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <button
                onClick={() => startDeepAnalysis(showHarvesterPicker, 'auto')}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 12, textAlign: 'left',
                  padding: 14, borderRadius: 8, border: '2px solid var(--accent)',
                  background: 'var(--bg-primary)', cursor: 'pointer',
                  transition: 'border-color 0.15s',
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent-strong)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--accent)')}
              >
                <div style={{
                  width: 32, height: 32, borderRadius: 8,
                  background: 'var(--accent-dim)', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}>
                  <Zap size={16} style={{ color: 'var(--accent)' }} />
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent)', marginBottom: 2 }}>
                    Auto — Recommended
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                    Automatically uses full mode if any API keys are configured, otherwise
                    falls back to free sources. Best balance of speed and results.
                  </div>
                </div>
              </button>

              <button
                onClick={() => startDeepAnalysis(showHarvesterPicker, 'quick')}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 12, textAlign: 'left',
                  padding: 14, borderRadius: 8, border: '1px solid var(--border)',
                  background: 'var(--bg-primary)', cursor: 'pointer',
                  transition: 'border-color 0.15s',
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
              >
                <div style={{
                  width: 32, height: 32, borderRadius: 8,
                  background: 'var(--accent-dim)', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}>
                  <Zap size={16} style={{ color: 'var(--accent)' }} />
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 2 }}>
                    Quick — Free Sources Only
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                    24 free sources (crt.sh, duckduckgo, netcraft, etc.). No API key needed.
                    Completes in ~30 seconds. Good for a fast initial sweep.
                  </div>
                </div>
              </button>

              <button
                onClick={() => startDeepAnalysis(showHarvesterPicker, 'full')}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 12, textAlign: 'left',
                  padding: 14, borderRadius: 8, border: '1px solid var(--border)',
                  background: 'var(--bg-primary)', cursor: 'pointer',
                  transition: 'border-color 0.15s',
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
              >
                <div style={{
                  width: 32, height: 32, borderRadius: 8,
                  background: 'rgba(249, 115, 22, 0.15)', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}>
                  <Brain size={16} style={{ color: '#f97316' }} />
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 2 }}>
                    Full — All API Key Sources
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                    55 sources including Shodan, Virustotal, SecurityTrails, Hunter.io, etc.
                    Uses all 40+ configured API keys. Takes ~15 minutes. Most comprehensive results.
                  </div>
                </div>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Deep Analysis Panel */}
      {state.domainDeepAnalysisDomain && (
        <DeepAnalysisPanel
          domain={state.domainDeepAnalysisDomain}
          harvesterMode={harvesterMode}
          emails={filteredEmails}
          allEmails={domainEmails}
          secrets={domainSecrets}
          repos={domainRepos}
          lookalikes={domainLookalikes}
          technologies={technologies}
          httpHeaders={httpHeaders}
          historicalUrls={historicalUrls}
          waybackSnapshots={waybackSnapshots}
          selectedEmails={selectedEmails}
          emailSearch={emailSearch}
          breaches={breaches}
          emailPlatforms={emailPlatforms}
          profiles={profiles}
          domainAnalysisRunning={domainAnalysisRunning}
          domainAnalysisProgress={state.domainDeepAnalysisProgress}
          emailAnalysisRunning={emailAnalysisRunning}
          emailAnalysisProgress={state.emailDeepAnalysisProgress}
          onToggleEmail={toggleEmail}
          onSelectAll={() => setSelectedEmails(new Set(filteredEmails.map(e => e.entity_value)))}
          onDeselectAll={() => setSelectedEmails(new Set())}
          onEmailSearchChange={setEmailSearch}
          onEmailDeepAnalysis={handleEmailDeepAnalysis}
          onClose={() => dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_CLOSED' })}
          getBreachCountForEmail={getBreachCountForEmail}
          getPlatformsForEmail={getPlatformsForEmail}
          getProfilesForEmail={getProfilesForEmail}
          getHostMetaForIp={getHostMetaForIp}
          getDnsForIp={getDnsForIp}
          getTlsForIp={getTlsForIp}
        />
      )}
    </div>
  );
}

function SubdomainRow({ subdomain, sourceModule, discoverySource, ips, ports, cves, dnsRecords, hostMeta, tlsCerts, crtshCerts, expanded, onToggle, onDeepAnalysis, isDeepAnalyzing, hasDeepResults, onEnrich, enrichingIps, isMainDomain }: {
  subdomain: string;
  sourceModule?: string;
  discoverySource?: string;
  ips: string[];
  ports: any[];
  cves: any[];
  dnsRecords: Record<string, string[]> | null;
  hostMeta: any[];
  tlsCerts: any[];
  crtshCerts: any[];
  expanded: boolean;
  onToggle: () => void;
  onDeepAnalysis: () => void;
  isDeepAnalyzing: boolean;
  hasDeepResults: boolean;
  onEnrich: (ip: string, provider: string) => void;
  enrichingIps: Set<string>;
  isMainDomain?: boolean;
}) {
  const dnsRtypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'];
  return (
    <>
      <tr className="ws-infra-row" onClick={onToggle} style={{ cursor: 'pointer' }}>
        <td>{expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</td>
        <td>
          <div className="font-mono font-medium" style={{ color: 'var(--text-strong)' }}>
            {subdomain}
            {isMainDomain && (
              <span style={{
                display: 'inline-block', marginLeft: 6, padding: '0 6px',
                borderRadius: 3, fontSize: 9, fontWeight: 600,
                background: 'rgba(99,102,241,0.15)', color: 'var(--accent)',
                border: '1px solid rgba(99,102,241,0.25)',
                verticalAlign: 'middle',
              }}>MAIN</span>
            )}
          </div>
          {discoverySource && (
            <div style={{ fontSize: 9, color: 'var(--accent)', marginTop: 1 }}>
              via {discoverySource}
            </div>
          )}
        </td>
        <td style={{ verticalAlign: 'middle' }}>
          {sourceModule ? (
            <span style={{
              display: 'inline-block', padding: '1px 7px', borderRadius: 4,
              fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 500,
              background: 'var(--bg-primary)', border: '1px solid var(--border)',
              color: 'var(--accent)',
            }}>{sourceModule}</span>
          ) : (
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>—</span>
          )}
        </td>
        <td>
          <div className="flex flex-wrap gap-1">
            {ips.slice(0, 3).map(ip => (
              <span key={ip} className="badge" style={{ fontSize: 10, fontFamily: 'var(--font-mono)' }}>{ip}</span>
            ))}
            {ips.length > 3 && <span className="badge" style={{ fontSize: 10 }}>+{ips.length - 3}</span>}
          </div>
        </td>
        <td>{ports.length}</td>
        <td>
          {cves.length > 0 ? (
            <span className="badge badge-danger">{cves.length} CVE{cves.length === 1 ? '' : 's'}</span>
          ) : (
            <span className="text-gray">—</span>
          )}
        </td>
        <td>
          <button
            className="ws-enrich-btn-primary"
            onClick={e => { e.stopPropagation(); onDeepAnalysis(); }}
            disabled={isDeepAnalyzing}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 4,
              padding: '4px 10px', borderRadius: 6, fontSize: 11,
              fontWeight: 500, border: 'none', cursor: isDeepAnalyzing ? 'not-allowed' : 'pointer',
              opacity: isDeepAnalyzing ? 0.5 : 1, background: 'var(--accent)', color: '#fff',
            }}
          >
            {isDeepAnalyzing ? <Loader2 size={12} className="animate-spin" /> : <Zap size={12} />}
            {hasDeepResults ? 'Re-analyze' : 'Deep Analysis'}
          </button>
        </td>
      </tr>
      {expanded && (
        <tr className="ws-infra-expanded">
          <td colSpan={7}>
            <div className="ws-infra-detail">

              {/* ── Source Attribution ───────────────────────────────── */}
              {discoverySource && (
                <div className="ws-infra-detail-item" style={{ padding: '4px 0' }}>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                    Discovered via <strong style={{ color: 'var(--accent)' }}>{discoverySource}</strong>
                    {sourceModule && <span> ({sourceModule})</span>}
                  </span>
                </div>
              )}

              {/* ── Certificate History (crtsh) ──────────────────────── */}
              {crtshCerts.length > 0 && (
                <div className="ws-infra-detail-item">
                  <div className="text-xs font-semibold mb-2" style={{ color: 'var(--text-strong)' }}>Certificate History ({crtshCerts.length})</div>
                  <div style={{ maxHeight: 200, overflowY: 'auto' }}>
                    {crtshCerts.map((cert, ci) => {
                      const nd = cert.normalized_data || {};
                      const subj = nd.subject || {};
                      const iss = nd.issuer || {};
                      return (
                        <div key={ci} style={{
                          fontSize: 9, lineHeight: 1.5, fontFamily: 'var(--font-mono)',
                          marginBottom: 6, padding: '4px 8px', borderRadius: 4,
                          background: 'var(--bg-primary)', border: '1px solid var(--border)',
                        }}>
                          <div>CN: <strong style={{ color: 'var(--text-strong)' }}>{subj.CN || '—'}</strong></div>
                          <div>Issuer: {iss.CN || '—'}</div>
                          <div>Validity: {nd.not_before ? String(nd.not_before).split('T')[0] : '?'} → {nd.not_after ? String(nd.not_after).split('T')[0] : '?'}</div>
                          <div>Serial: {nd.serial ? String(nd.serial).slice(0, 30) : '—'}</div>
                          <div>Covers: {(nd.subdomains_covered || []).join(', ').slice(0, 120)}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* ── DNS Records Panel ────────────────────────────────── */}
              {dnsRecords && (
                <div className="ws-infra-detail-item">
                  <div className="text-xs font-semibold mb-2" style={{ color: 'var(--text-strong)' }}>DNS Records</div>
                  {dnsRtypes.map(rtype => {
                    const records = dnsRecords[rtype];
                    if (!records || records.length === 0) return null;
                    return (
                      <div key={rtype} style={{ display: 'flex', gap: 8, marginBottom: 4, fontSize: 10 }}>
                        <span style={{
                          minWidth: 48, fontWeight: 600, color: 'var(--accent)',
                          fontFamily: 'var(--font-mono)', fontSize: 9,
                        }}>{rtype}</span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px 10px' }}>
                          {records.map((val: string, i: number) => (
                            <span key={i} style={{
                              fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text)',
                              wordBreak: 'break-all',
                            }}>{rtype === 'TXT' ? val.replace(/^"|"$/g, '') : val}</span>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* ── IP Cards ─────────────────────────────────────────── */}
              {ips.map(ip => {
                const ipPorts = ports.filter(p => p.entity_value.startsWith(ip));
                const ipCves = cves.filter(c => c.normalized_data?.ip === ip || c.entity_value.includes(ip));
                const ipHostMeta = hostMeta.filter(h => h.entity_value === ip);
                const ipTlsCerts = tlsCerts.filter(t => t.normalized_data?.ip === ip);
                const isLoading = enrichingIps.has(ip);
                const hm = ipHostMeta.length > 0 ? ipHostMeta[0].normalized_data || {} : {};

                // Group TLS certs by port
                const tlsByPort: Record<string, any> = {};
                ipTlsCerts.forEach(t => {
                  const nd = t.normalized_data || {};
                  const port = String(nd.port || '?');
                  if (!tlsByPort[port]) tlsByPort[port] = [];
                  tlsByPort[port].push(nd);
                });

                return (
                  <div key={ip} className="ws-infra-detail-item">
                    {/* IP header */}
                    <div className="flex items-center gap-2 mb-2">
                      <span className="font-mono font-medium" style={{ color: 'var(--text-strong)' }}>{ip}</span>
                      <select
                        onClick={e => e.stopPropagation()}
                        defaultValue="shodan"
                        style={{
                          padding: '1px 6px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--font-mono)',
                          background: 'var(--bg-primary)', border: '1px solid var(--border)', color: 'var(--text)',
                        }}
                      >
                        <option value="shodan">Shodan</option>
                        <option value="censys">Censys</option>
                        <option value="both">Both</option>
                      </select>
                      <button
                        className="ws-enrich-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          const select = (e.target as HTMLElement).previousElementSibling as HTMLSelectElement;
                          onEnrich(ip, select?.value || 'shodan');
                        }}
                        disabled={isLoading}
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 3,
                          padding: '2px 8px', borderRadius: 4, fontSize: 10,
                          fontWeight: 500, border: '1px solid var(--border)',
                          cursor: isLoading ? 'not-allowed' : 'pointer',
                          opacity: isLoading ? 0.5 : 1,
                          background: 'var(--bg-secondary)', color: 'var(--text)',
                        }}
                      >
                        {isLoading ? <Loader2 size={10} className="animate-spin" /> : <Zap size={10} />}
                        Enrich
                      </button>
                    </div>

                    {/* HOST_METADATA — ASN / ISP / org / location / tags */}
                    {Object.keys(hm).length > 0 && (
                      <div className="mb-2">
                        <div className="text-xs text-gray mb-1">Host Info</div>
                        <div className="flex flex-wrap gap-x-4 gap-y-1" style={{ fontSize: 10 }}>
                          {hm.asn && <span>ASN: <strong>{
                            typeof hm.asn === 'object'
                              ? (hm.asn.number ? `${hm.asn.number}${hm.asn.name ? ` - ${hm.asn.name}` : ''}` : JSON.stringify(hm.asn))
                              : hm.asn
                          }</strong></span>}
                          {hm.isp && <span>ISP: <strong>{hm.isp}</strong></span>}
                          {hm.org && <span>Org: <strong>{hm.org}</strong></span>}
                          {hm.os && <span>OS: <strong>{hm.os}</strong></span>}
                          {hm.city && hm.country && <span>Location: <strong>{hm.city}{hm.region ? `, ${hm.region}` : ''}, {hm.country}</strong></span>}
                          {hm.city && !hm.country && <span>City: <strong>{hm.city}</strong></span>}
                          {hm.country && !hm.city && <span>Country: <strong>{hm.country}</strong></span>}
                          {Array.isArray(hm.hostnames) && hm.hostnames.length > 0 && (
                            <span>Hostnames: <strong style={{ fontSize: 9 }}>{hm.hostnames.join(', ')}</strong></span>
                          )}
                          {Array.isArray(hm.tags) && hm.tags.length > 0 && (
                            <div style={{ width: '100%', marginTop: 2 }}>
                              <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>Tags: </span>
                              {hm.tags.map((tag: string) => (
                                <span key={tag} style={{
                                  display: 'inline-block', padding: '0 6px', marginRight: 4,
                                  borderRadius: 3, fontSize: 9, fontWeight: 500,
                                  background: 'rgba(99,102,241,0.12)', color: 'var(--accent)',
                                  border: '1px solid rgba(99,102,241,0.2)',
                                }}>{tag}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Enhanced Port Details */}
                    {ipPorts.length > 0 && (
                      <div className="mb-2">
                        <div className="text-xs text-gray mb-1">Open Ports</div>
                        <div className="flex flex-wrap gap-1">
                          {ipPorts.map(p => {
                            const nd = p.normalized_data || {};
                            const port = p.entity_value.split(':').pop();
                            const extra: string[] = [];
                            if (nd.product) extra.push(nd.product);
                            if (nd.version) extra.push(nd.version);
                            if (nd.transport) extra.push(nd.transport);
                            return (
                              <span key={p.id} className="ws-port-pill" title={extra.length > 0 ? extra.join(' / ') : undefined}>
                                {port}
                                {nd.service_name && !nd.product && <span className="text-gray">/{nd.service_name}</span>}
                                {nd.product && <span className="text-gray">/{nd.product}</span>}
                                {nd.version && <span className="text-gray"> {nd.version}</span>}
                              </span>
                            );
                          })}
                        </div>
                        {/* Banner / info detail for first few ports */}
                        {ipPorts.slice(0, 3).map(p => {
                          const nd = p.normalized_data || {};
                          const banner = nd.banner || nd.info || nd.data || '';
                          if (!banner) return null;
                          return (
                            <div key={p.id} className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                              Port {p.entity_value.split(':').pop()}: <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9 }}>{banner.slice(0, 200)}</span>
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {/* TLS Certificates (from shodan_host / censys_host — IP-level) */}
                    {Object.keys(tlsByPort).length > 0 && (
                      <div className="mb-2">
                        <div className="text-xs text-gray mb-1">TLS Certificates</div>
                        {Object.entries(tlsByPort).map(([port, certs]) => (
                          <div key={port} style={{ marginBottom: 6 }}>
                            {certs.map((cert: any, ci: number) => {
                              const subj = cert.subject || {};
                              const issuer = cert.issuer || {};
                              const subjStr = typeof subj === 'object' ? (subj.CN || subj.commonName || subj.organization || JSON.stringify(subj)) : String(subj);
                              const issStr = typeof issuer === 'object'
                                ? (issuer.CN || issuer.commonName || issuer.organization || (issuer.O ? `${issuer.O}` : '') || JSON.stringify(issuer))
                                : String(issuer);
                              const expires = cert.expires || cert.expiration || cert.validity_end || '';
                              const fp = cert.fingerprint || cert.fingerprint_sha256 || '';
                              const fpStr = typeof fp === 'object' ? (fp.sha256 || fp.sha1 || JSON.stringify(fp)) : String(fp);
                              const names = Array.isArray(cert.names) ? cert.names : [];
                              return (
                                <div key={ci} style={{ fontSize: 9, lineHeight: 1.5, fontFamily: 'var(--font-mono)' }}>
                                  <span>Port {port} · Subject: <strong>{subjStr}</strong></span>
                                  <span style={{ marginLeft: 12 }}>Issuer: <strong>{issStr}</strong></span>
                                  {fpStr && <div>SHA256: {String(fpStr).slice(0, 24)}…</div>}
                                  {expires && <div>Expires: {String(expires).split('T')[0]}</div>}
                                  {names.length > 0 && <div>SANs: {names.join(', ').slice(0, 120)}</div>}
                                </div>
                              );
                            })}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Vulnerabilities */}
                    {ipCves.length > 0 && (
                      <div>
                        <div className="text-xs text-gray mb-1">Vulnerabilities</div>
                        <div className="flex flex-wrap gap-1">
                          {ipCves.map(c => <SeverityBadge key={c.id} severity={c.severity} />)}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

/* ─── Deep analysis helpers ─────────────────────────────────────────── */

const COLLECTOR_LABELS: Record<string, string> = {
  hunter_domain: 'Hunter.io',
  theharvester: 'theHarvester',
  github_secrets: 'GitHub Secrets',
  dnstwist: 'dnstwist',
  builtwith: 'BuiltWith',
  http_headers: 'HTTP Headers',
  web_surface: 'Verified Web Surface',
  wayback_machine: 'Wayback Machine',
  version_detector: 'Version Detection',
};

function getCollectorStatus(
  progress: { collector: string; status: string }[],
  collectorName: string,
): 'pending' | 'running' | 'done' | 'error' {
  const entry = progress.find(p => p.collector === collectorName);
  if (!entry) return 'pending';
  if (entry.status === 'pending' || entry.status === 'done' || entry.status === 'error') return entry.status;
  return 'running';
}

/** Build the flat list of ProgressItems for the domain deep analysis progress component. */
function buildDomainProgressItems(
  progress: { collector: string; status: string; findings_count?: number; error?: string; phase?: string; technology?: string; index?: number; total?: number }[],
): ProgressItem[] {
  // Phase 1: regular collectors
  const phase1Collectors = Array.from(new Set(
    progress
      .map(item => item.collector)
      .filter(name => name && !name.startsWith('technology_cve:'))
  ));
  const items: ProgressItem[] = [];

  for (const name of phase1Collectors) {
    const p = progress.find(x => x.collector === name);
    items.push({
      id: name,
      label: COLLECTOR_LABELS[name] || name,
      status: p ? (p.status === 'done' ? 'done' : p.status === 'error' ? 'error' : 'running') : 'pending',
      findingsCount: p?.findings_count,
      error: p?.error,
      phase: 'Domain Analysis',
    });
  }

  // Phase 2: technology→CVE items (collector names start with "technology_cve:")
  const cveItems = progress.filter(p => p.collector?.startsWith('technology_cve:'));
  for (const p of cveItems) {
    items.push({
      id: p.collector,
      label: 'CVE Cross-ref',
      sublabel: p.technology,
      status: p.status === 'done' ? 'done' : p.status === 'error' ? 'error' : 'running',
      findingsCount: p.findings_count,
      error: p.error,
      phase: 'CVE Cross-Reference',
    });
  }

  return items;
}

function DeepAnalysisPanel({
  domain, harvesterMode, emails, allEmails, secrets, repos, lookalikes,
  technologies, httpHeaders, historicalUrls, waybackSnapshots,
  selectedEmails, emailSearch, breaches, emailPlatforms, profiles,
  domainAnalysisRunning, domainAnalysisProgress,
  emailAnalysisRunning, emailAnalysisProgress,
  onToggleEmail, onSelectAll, onDeselectAll, onEmailSearchChange,
  onEmailDeepAnalysis, onClose,
  getBreachCountForEmail, getPlatformsForEmail, getProfilesForEmail,
}: any) {
  const [sectionExpanded, setSectionExpanded] = useState<Record<string, boolean>>({
    emails: true, secrets: true, lookalikes: true, emailAnalysis: true,
    technologies: false, httpHeaders: false, waybackUrls: false,
  });

  // ── Domain-scoped deep analysis results ────────────────────────────
  // Deep analysis findings from different domains share the same scan's
  // findings pool. We scope each section to the current `domain` to
  // prevent cross-domain leakage (e.g. lookalikes for "utm.tn" showing
  // when the panel is open for "fsegt.utm.tn").
  function filterByDomain(findings: any[]): any[] {
    return findings.filter(f => {
      const nd = f.normalized_data || {};
      // Direct domain fields
      if (nd.original_domain === domain) return true;
      if (nd.domain === domain) return true;
      if (nd.target_domain === domain) return true;
      // URL-based entity_value (e.g. "https://fsegt.utm.tn")
      const ev = String(f.entity_value || '');
      try {
        const hostname = new URL(ev.startsWith('http') ? ev : `https://${ev}`).hostname;
        if (hostname === domain) return true;
      } catch {}
      // URL in normalized_data (e.g. original_url from wayback)
      for (const urlField of ['url', 'original_url']) {
        const val = nd[urlField];
        if (val) {
          try {
            const h = new URL(String(val)).hostname;
            if (h === domain || h.endsWith('.' + domain)) return true;
          } catch {}
        }
      }
      // Email domain suffix (moez.chafra@fsegt.utm.tn)
      if (ev.includes('@')) {
        const emailDomain = ev.split('@')[1];
        if (emailDomain === domain) return true;
      }
      // Subdomain check — entity_value is a subdomain that ends with the domain
      if (ev.endsWith('.' + domain) || ev === domain) return true;
      return false;
    });
  }

  const scopedTechnologies = filterByDomain(technologies);
  const scopedHttpHeaders = filterByDomain(httpHeaders);
  const scopedHistoricalUrls = filterByDomain(historicalUrls);
  const scopedWaybackSnapshots = filterByDomain(waybackSnapshots);
  const scopedEmails = filterByDomain(allEmails);
  // CVEs from deep analysis (technology_cve collector) don't store the
  // domain, so we use a loose match based on the dataset name in the
  // entity_value.
  const scopedBreaches = filterByDomain(breaches);
  const scopedSecrets = filterByDomain(secrets);
  // GITHUB_REPO findings reference brands/domains in their content but
  // are hosted externally (github.com). They're inherently scan-wide, so
  // we show all repos without domain-scoping.
  const scopedRepos = repos;

  // Also scope the search-filtered email list for display
  const scopedEmailsFiltered = domain ? emails.filter((e: any) => {
    const nd = e.normalized_data || {};
    if (nd.domain === domain) return true;
    const emailDomain = String(e.entity_value || '').split('@')[1];
    if (emailDomain === domain) return true;
    return false;
  }) : emails;

  const currentEmailProgress = emailAnalysisProgress.length > 0
    ? emailAnalysisProgress[emailAnalysisProgress.length - 1]
    : null;

  return (
    <div style={{
      marginTop: 24, border: '1px solid var(--accent)', borderRadius: 8, overflow: 'hidden',
      boxShadow: '0 0 0 1px var(--accent-dim)',
    }}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3" style={{ background: 'var(--accent-dim)' }}>
        <div className="flex items-center gap-2">
          <Zap size={16} style={{ color: 'var(--accent)' }} />
          <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-strong)' }}>
            Deep Analysis: {domain}
          </span>
          {harvesterMode && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 3,
              padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
              background: harvesterMode === 'full' ? 'rgba(249,115,22,0.15)' : 'var(--accent-dim)',
              border: `1px solid ${harvesterMode === 'full' ? 'rgba(249,115,22,0.3)' : 'rgba(6,182,212,0.25)'}`,
              color: harvesterMode === 'full' ? '#f97316' : 'var(--accent)',
            }}>
              theHarvester: {harvesterMode === 'full' ? 'Full (55 sources)' : harvesterMode === 'auto' ? 'Auto' : 'Quick (24 sources)'}
            </span>
          )}
          {domainAnalysisRunning && (
            <span style={{ fontSize: 10, color: 'var(--accent)', display: 'inline-flex', alignItems: 'center', gap: 3 }}>
              <Loader2 size={10} className="animate-spin" />
              in progress
            </span>
          )}
        </div>
        <button className="ws-enrich-btn" onClick={onClose} style={{ fontSize: 11 }}>Close</button>
      </div>

      <div style={{ padding: 16 }}>
        {/* ── Progress ── */}
        {domainAnalysisRunning && (
          <DeepAnalysisProgress
            running={domainAnalysisRunning}
            items={buildDomainProgressItems(domainAnalysisProgress)}
            totalFindings={
              (scopedEmails?.length || 0) + (scopedSecrets?.length || 0) + (scopedRepos?.length || 0)
              + (lookalikes?.length || 0) + (scopedTechnologies?.length || 0)
              + (scopedHttpHeaders?.length || 0) + (scopedHistoricalUrls?.length || 0)
              + (scopedWaybackSnapshots?.length || 0) + (scopedBreaches?.length || 0)
              + (emailPlatforms?.length || 0) + (profiles?.length || 0)
            }
          />
        )}
        <CollapsibleSection
          title="Emails Discovered"
          count={scopedEmails.length}
          icon={<Mail size={14} style={{ color: 'var(--accent)' }} />}
          expanded={sectionExpanded.emails}
          onToggle={() => setSectionExpanded(p => ({ ...p, emails: !p.emails }))}
        >
          {/* Search */}
          <div className="flex items-center gap-2 mb-3">
            <div className="flex items-center gap-2 px-3 py-1.5" style={{
              background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 6, flex: 1,
            }}>
              <Search size={13} style={{ color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Filter emails..."
                value={emailSearch}
                onChange={e => onEmailSearchChange(e.target.value)}
                style={{
                  background: 'transparent', border: 'none', outline: 'none',
                  fontSize: 12, color: 'var(--text)', flex: 1, fontFamily: 'var(--font-mono)',
                }}
              />
            </div>
          </div>

          {/* Email list with checkboxes */}
          <div style={{ maxHeight: 240, overflowY: 'auto', marginBottom: 10 }}>
            {scopedEmailsFiltered.map((email: any) => {
              const breachCount = getBreachCountForEmail(email.entity_value);
              const platformCount = getPlatformsForEmail(email.entity_value).length;
              const profileCount = getProfilesForEmail(email.entity_value).length;
              return (
                <label
                  key={email.id}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 6,
                    padding: '4px 10px', margin: '0 4px 4px 0', borderRadius: 6,
                    fontSize: 12, fontFamily: 'var(--font-mono)', cursor: 'pointer',
                    background: selectedEmails.has(email.entity_value) ? 'var(--accent-dim)' : 'var(--bg-primary)',
                    border: `1px solid ${selectedEmails.has(email.entity_value) ? 'var(--accent)' : 'var(--border)'}`,
                    color: 'var(--text-strong)',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={selectedEmails.has(email.entity_value)}
                    onChange={() => onToggleEmail(email.entity_value)}
                    style={{ margin: 0 }}
                  />
                  <span>{email.entity_value}</span>
                  {breachCount > 0 && <span className="badge badge-danger" style={{ fontSize: 9 }}>{breachCount}</span>}
                  {platformCount > 0 && <span className="badge badge-info" style={{ fontSize: 9 }}>+{platformCount}p</span>}
                  {profileCount > 0 && <span className="badge badge-info" style={{ fontSize: 9 }}>+{profileCount}pr</span>}
                </label>
              );
            })}
          </div>

          {/* Empty / loading state for emails */}
          {scopedEmails.length === 0 && (() => {
            const hd = getCollectorStatus(domainAnalysisProgress, 'hunter_domain');
            const th = getCollectorStatus(domainAnalysisProgress, 'theharvester');
            if (hd === 'running' || th === 'running') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Loader2 size={10} className="animate-spin" />
                Discovering emails...
              </div>;
            }
            if (hd === 'done' && th === 'done') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>No emails discovered for this domain.</div>;
            }
            return null;
          })()}

          {/* Action buttons */}
          <div className="flex items-center gap-3">
            <button className="ws-enrich-btn" onClick={onSelectAll} style={{ fontSize: 11 }}>Select All</button>
            <button className="ws-enrich-btn" onClick={onDeselectAll} style={{ fontSize: 11 }}>Deselect All</button>
            <button
              className="ws-enrich-btn-primary"
              disabled={selectedEmails.size === 0 || emailAnalysisRunning}
              onClick={onEmailDeepAnalysis}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '6px 16px', borderRadius: 6, fontSize: 13, fontWeight: 500,
                border: 'none', cursor: (selectedEmails.size === 0 || emailAnalysisRunning) ? 'not-allowed' : 'pointer',
                opacity: (selectedEmails.size === 0 || emailAnalysisRunning) ? 0.5 : 1,
                background: 'var(--accent)', color: '#fff',
              }}
            >
              {emailAnalysisRunning && <Loader2 size={13} className="animate-spin" />}
              Deep Analyze Selected ({selectedEmails.size})
            </button>
          </div>

          {/* Email analysis progress */}
          {emailAnalysisRunning && currentEmailProgress && (
            <div style={{ marginTop: 10, padding: 8, background: 'var(--bg-primary)', borderRadius: 6 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                Analyzing {currentEmailProgress.email}...
                ({currentEmailProgress.index}/{currentEmailProgress.total}) — {currentEmailProgress.collector} {currentEmailProgress.status}
              </div>
              <div style={{ height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${(currentEmailProgress.index / currentEmailProgress.total) * 100}%`,
                  background: 'var(--accent)', transition: 'width 0.3s',
                }} />
              </div>
            </div>
          )}

          {/* Per-email deep analysis results */}
          {[...selectedEmails].map((email: string) => {
            const emailBreaches = breaches.filter((b: any) => {
              const nd = (b.normalized_data || {}) as Record<string, any>;
              return nd.email === email || String(b.entity_value).startsWith(email);
            });
            const emailPlats = emailPlatforms.filter((p: any) => {
              const nd = (p.normalized_data || {}) as Record<string, any>;
              return nd.email === email;
            });
            const emailProfs = profiles.filter((p: any) => {
              const nd = (p.normalized_data || {}) as Record<string, any>;
              return nd.username === email.split('@')[0] || nd.email === email;
            });
            if (emailBreaches.length === 0 && emailPlats.length === 0 && emailProfs.length === 0) return null;

            return (
              <div key={email} style={{ marginTop: 12, padding: 12, background: 'var(--bg-primary)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>
                  {email}
                </div>

                {/* Breaches */}
                {emailBreaches.length > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: '#ef4444', marginBottom: 4 }}>
                      Breaches ({emailBreaches.length})
                    </div>
                    {emailBreaches.map((b: any) => (
                      <div key={b.id} style={{
                        padding: '4px 8px', marginBottom: 2, background: 'var(--bg-secondary)',
                        borderRadius: 4, fontSize: 11, fontFamily: 'var(--font-mono)',
                        display: 'flex', justifyContent: 'space-between',
                      }}>
                        <span style={{ color: 'var(--text-strong)' }}>
                          {b.normalized_data?.breaches?.[0]?.name || b.normalized_data?.name || b.entity_value}
                        </span>
                        <div className="flex gap-2">
                          {b.normalized_data?.risk_score != null && (
                            <span className="badge badge-danger" style={{ fontSize: 9 }}>
                              Risk: {b.normalized_data.risk_score}
                            </span>
                          )}
                          {b.normalized_data?.breaches?.length > 0 && (
                            <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>
                              {b.normalized_data.breaches.length} breach{b.normalized_data.breaches.length > 1 ? 'es' : ''}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Platform registrations (holehe) */}
                {emailPlats.length > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: '#22c55e', marginBottom: 4 }}>
                      Platform Registrations ({emailPlats.length})
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {emailPlats.map((p: any) => (
                        <div key={p.id} style={{
                          display: 'inline-flex', alignItems: 'center', gap: 3,
                          padding: '2px 6px', background: 'var(--bg-secondary)', borderRadius: 4,
                          fontSize: 10, fontFamily: 'var(--font-mono)',
                        }}>
                          {p.normalized_data?.platform || 'unknown'}
                          {p.normalized_data?.url && (
                            <a href={p.normalized_data.url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', fontSize: 10 }}>↗</a>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Social profiles (maigret) */}
                {emailProfs.length > 0 && (
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 600, color: '#3b82f6', marginBottom: 4 }}>
                      Social Profiles ({emailProfs.length})
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {emailProfs.map((p: any) => (
                        <div key={p.id} style={{
                          display: 'inline-flex', alignItems: 'center', gap: 3,
                          padding: '2px 6px', background: 'var(--bg-secondary)', borderRadius: 4,
                          fontSize: 10, fontFamily: 'var(--font-mono)',
                        }}>
                          {p.normalized_data?.platform || 'profile'}
                          {p.entity_value?.startsWith('http') && (
                            <a href={p.entity_value} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', fontSize: 10 }}>↗</a>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </CollapsibleSection>

        {/* ── GitHub Exposures Section ── */}
        <CollapsibleSection
          title="GitHub Exposures"
          count={scopedSecrets.length + scopedRepos.length}
          icon={<Key size={14} style={{ color: '#f59e0b' }} />}
          expanded={sectionExpanded.secrets}
          onToggle={() => setSectionExpanded(p => ({ ...p, secrets: !p.secrets }))}
        >
          {scopedSecrets.length > 0 && (
            <div className="table-container" style={{ marginBottom: 12 }}>
              <table>
                <thead>
                  <tr><th>Type</th><th>Repository</th><th>File</th><th>Severity</th></tr>
                </thead>
                <tbody>
                  {scopedSecrets.map((s: any) => (
                    <tr key={s.id}>
                      <td><span className="badge badge-warning" style={{ fontSize: 9 }}>{String(s.normalized_data?.secret_type || 'SECRET')}</span></td>
                      <td className="font-mono" style={{ fontSize: 11, color: 'var(--text-strong)' }}>
                        {s.normalized_data?.file_url ? (
                          <a href={String(s.normalized_data.file_url)} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>
                            {String(s.normalized_data?.repo_name || '')}
                          </a>
                        ) : String(s.normalized_data?.repo_name || '')}
                      </td>
                      <td className="font-mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                        {String(s.normalized_data?.file_path || '')}
                      </td>
                      <td><span className={`badge ${s.severity === 'HIGH' ? 'badge-danger' : 'badge-warning'}`}>{s.severity}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {scopedRepos.length > 0 && (
            <div className="table-container">
              <table>
                <thead><tr><th>Repository</th><th>Stars</th><th>Language</th></tr></thead>
                <tbody>
                  {scopedRepos.map((r: any) => (
                    <tr key={r.id}>
                      <td className="font-mono" style={{ fontSize: 11, color: 'var(--text-strong)' }}>
                        <a href={String(r.entity_value)} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>
                          {String(r.normalized_data?.repo_name || r.entity_value)}
                        </a>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{String(r.normalized_data?.stars || '—')}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{String(r.normalized_data?.language || '—')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {scopedSecrets.length === 0 && scopedRepos.length === 0 && (() => {
            const gs = getCollectorStatus(domainAnalysisProgress, 'github_secrets');
            if (gs === 'running') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Loader2 size={10} className="animate-spin" />
                Scanning GitHub for leaked secrets and related repositories...
              </div>;
            }
            if (gs === 'done' || gs === 'error') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>No leaked secrets or related repositories found.</div>;
            }
            return null;
          })()}
        </CollapsibleSection>

        {/* ── Lookalike Domains Section ── */}
        <CollapsibleSection
          title="Lookalike Domains"
          count={lookalikes.length}
          icon={<ShieldCheck size={14} style={{ color: '#f59e0b' }} />}
          expanded={sectionExpanded.lookalikes}
          onToggle={() => setSectionExpanded(p => ({ ...p, lookalikes: !p.lookalikes }))}
        >
          {lookalikes.length > 0 ? (
            <div className="ws-lookalike-grid">
              {lookalikes.map((l: any) => {
                const d = l.normalized_data || {};
                const ips = d.resolved_ips || [];
                return (
                  <div key={l.id} className="ws-lookalike-card">
                    <div className="font-mono font-medium" style={{ color: 'var(--text-strong)', fontSize: 13 }}>
                      {l.entity_value}
                    </div>
                    <div className="flex gap-2 mt-2 flex-wrap">
                      {ips.length > 0 ? (
                        <span className="badge badge-danger">LIVE ({ips.length} IP{ips.length > 1 ? 's' : ''})</span>
                      ) : (
                        <span className="badge badge-success">NO DNS</span>
                      )}
                      {d.permutation_type && <span className="badge badge-info">{d.permutation_type}</span>}
                    </div>
                    {ips.length > 0 && (
                      <div className="mt-2 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                        {ips.slice(0, 3).join(', ')}{ips.length > 3 ? ` +${ips.length - 3}` : ''}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (() => {
            const dw = getCollectorStatus(domainAnalysisProgress, 'dnstwist');
            if (dw === 'running') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Loader2 size={10} className="animate-spin" />
                Generating lookalike domain permutations...
              </div>;
            }
            if (dw === 'done' || dw === 'error') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>No lookalike domains detected.</div>;
            }
            return null;
          })()}
        </CollapsibleSection>

        {/* ── Web Recon Section ── */}
        <CollapsibleSection
          title="Web Technologies (BuiltWith)"
          count={scopedTechnologies.length}
          icon={<Server size={14} style={{ color: '#22c55e' }} />}
          expanded={sectionExpanded.technologies}
          onToggle={() => setSectionExpanded(p => ({ ...p, technologies: !p.technologies }))}
        >
          {scopedTechnologies.length > 0 ? (
            <div>
              {(() => {
                const grouped: Record<string, any[]> = {};
                scopedTechnologies.forEach((t: any) => {
                  const nd = t.normalized_data || {};
                  const group = (nd.group as string) || 'Other';
                  if (!grouped[group]) grouped[group] = [];
                  grouped[group].push(nd);
                });
                return Object.entries(grouped).map(([group, items]) => (
                  <div key={group} style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      {group}
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {items.map((item: any, i: number) => (
                        <div key={i} className="badge badge-info" style={{ fontSize: 10, padding: '4px 10px' }}>
                          {item.category}
                          {item.live > 0 && <span style={{ color: '#10b981', marginLeft: 3 }}>●</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                ));
              })()}
            </div>
          ) : (() => {
            const bw = getCollectorStatus(domainAnalysisProgress, 'builtwith');
            if (bw === 'running') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Loader2 size={10} className="animate-spin" />
                Fetching web technology stack...
              </div>;
            }
            if (bw === 'done' || bw === 'error') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>No technology data found for this domain.</div>;
            }
            return null;
          })()}
        </CollapsibleSection>

        {/* ── HTTP Headers Section ── */}
        <CollapsibleSection
          title="HTTP Response Headers"
          count={scopedHttpHeaders.length}
          icon={<Code size={14} style={{ color: '#3b82f6' }} />}
          expanded={sectionExpanded.httpHeaders}
          onToggle={() => setSectionExpanded(p => ({ ...p, httpHeaders: !p.httpHeaders }))}
        >
          {scopedHttpHeaders.length > 0 ? (
            <div>
              {scopedHttpHeaders.map((h: any, i: number) => {
                const nd = h.normalized_data || {};
                const headers = nd.headers as Record<string, string> || {};
                return (
                  <div key={i} style={{
                    padding: '8px 10px', marginBottom: 8, borderRadius: 6,
                    background: 'var(--bg-primary)', border: '1px solid var(--border)',
                    fontFamily: 'var(--font-mono)', fontSize: 10,
                  }}>
                    <div style={{ color: 'var(--text-strong)', marginBottom: 4 }}>
                      {String(nd.url || h.entity_value)}
                      {nd.status ? (
                        <span style={{
                          marginLeft: 6, padding: '1px 6px', borderRadius: 3,
                          color: Number(nd.status) >= 400 ? '#ef4444' : Number(nd.status) >= 300 ? '#f59e0b' : '#10b981',
                          background: Number(nd.status) >= 400 ? 'rgba(239,68,68,0.1)' : Number(nd.status) >= 300 ? 'rgba(245,158,11,0.1)' : 'rgba(16,185,129,0.1)',
                          fontSize: 9, fontWeight: 600,
                        }}>
                          {String(nd.status)}
                        </span>
                      ) : null}
                      {nd.content_length ? (
                        <span style={{ marginLeft: 6, color: 'var(--text-muted)', fontSize: 9 }}>
                          {String(nd.content_length)} bytes
                        </span>
                      ) : null}
                    </div>
                    {nd.error && <div style={{ color: '#ef4444', marginBottom: 2 }}>{String(nd.error)}</div>}
                    {Object.entries(headers).map(([k, v]) => (
                      <div key={k} style={{ color: 'var(--text-muted)', lineHeight: 1.6 }}>
                        <span style={{ color: 'var(--accent)' }}>{k}:</span> {String(v).slice(0, 200)}
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          ) : (() => {
            const hh = getCollectorStatus(domainAnalysisProgress, 'web_surface');
            if (hh === 'running') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Loader2 size={10} className="animate-spin" />
                Capturing HTTP response headers...
              </div>;
            }
            if (hh === 'done' || hh === 'error') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>No HTTP response headers captured.</div>;
            }
            return null;
          })()}
        </CollapsibleSection>

        {/* ── Historical URLs (Wayback Machine) Section ── */}
        <CollapsibleSection
          title="Historical URLs (Wayback Machine)"
          count={scopedHistoricalUrls.length + scopedWaybackSnapshots.length}
          icon={<History size={14} style={{ color: '#f59e0b' }} />}
          expanded={sectionExpanded.waybackUrls}
          onToggle={() => setSectionExpanded(p => ({ ...p, waybackUrls: !p.waybackUrls }))}
        >
          {scopedHistoricalUrls.length > 0 || scopedWaybackSnapshots.length > 0 ? (
            <div>
              {scopedWaybackSnapshots.length > 0 && (
                <div style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 4 }}>Latest Snapshot</div>
                  {scopedWaybackSnapshots.map((s: any, i: number) => {
                    const nd = s.normalized_data || {};
                    return (
                      <div key={i} style={{
                        padding: '6px 10px', borderRadius: 6,
                        background: 'var(--bg-primary)', border: '1px solid var(--border)',
                        fontSize: 10, fontFamily: 'var(--font-mono)',
                      }}>
                        <div style={{ color: 'var(--text-strong)' }}>
                          {nd.original_url || s.entity_value}
                        </div>
                        <div style={{ color: 'var(--text-muted)', marginTop: 2 }}>
                          {nd.timestamp && <span>Archived: {String(nd.timestamp)}</span>}
                          {nd.wayback_url && (
                            <a href={String(nd.wayback_url)} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', marginLeft: 8 }}>
                              View on Wayback ↗
                            </a>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
              {scopedHistoricalUrls.length > 0 && (
                <div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 4 }}>
                    Historical Pages ({scopedHistoricalUrls.length})
                  </div>
                  <div style={{ maxHeight: 300, overflowY: 'auto' }}>
                    {scopedHistoricalUrls.map((u: any, i: number) => {
                      const nd = u.normalized_data || {};
                      return (
                        <div key={i} style={{
                          display: 'flex', gap: 8, alignItems: 'center',
                          padding: '4px 8px', marginBottom: 2, borderRadius: 4,
                          background: 'var(--bg-primary)', border: '1px solid var(--border)',
                          fontSize: 9, fontFamily: 'var(--font-mono)',
                        }}>
                          <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>
                            {nd.timestamp ? String(nd.timestamp).slice(0, 8) : '?'}
                          </span>
                          <span style={{ color: 'var(--text-strong)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {nd.original_url || u.entity_value}
                          </span>
                          <span style={{ color: '#10b981', flexShrink: 0 }}>{String(nd.status_code || '')}</span>
                          {nd.wayback_url && (
                            <a href={String(nd.wayback_url)} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', flexShrink: 0 }}>↗</a>
                          )}
                          {nd.content_type && (
                            <span className="badge" style={{ fontSize: 8, flexShrink: 0 }}>{String(nd.mime_type || '').split('/')[1] || String(nd.content_type)}</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          ) : (() => {
            const wb = getCollectorStatus(domainAnalysisProgress, 'wayback_machine');
            if (wb === 'running') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Loader2 size={10} className="animate-spin" />
                Fetching archived pages from Wayback Machine...
              </div>;
            }
            if (wb === 'done' || wb === 'error') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>No historical URLs found for this domain.</div>;
            }
            return null;
          })()}
        </CollapsibleSection>
      </div>
    </div>
  );
}

function CollapsibleSection({ title, count, icon, expanded, onToggle, children }: {
  title: string; count: number; icon: React.ReactNode;
  expanded: boolean; onToggle: () => void; children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div
        className="flex items-center gap-2"
        onClick={onToggle}
        style={{ cursor: 'pointer', marginBottom: 8, userSelect: 'none' }}
      >
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        {icon}
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)' }}>
          {title} ({count})
        </span>
      </div>
      {expanded && <div style={{ paddingLeft: 8 }}>{children}</div>}
    </div>
  );
}
