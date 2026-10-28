import { useState } from 'react';
import { Server, Code, History, AlertTriangle, Globe, ChevronDown, ChevronRight, ShieldCheck, FolderSearch, Loader2 } from 'lucide-react';
import { useScanWorkspace } from '../../context/scan-workspace-state';
import type { FindingRow } from '../FindingsTable';
import apiClient from '../../api/client';
import { errorMessage } from '../../utils/errors';

export function WebOsintTab() {
  const { state } = useScanWorkspace();
  const [discoveryProfile, setDiscoveryProfile] = useState<'common' | 'exposure'>('common');
  const [dispatchingDiscovery, setDispatchingDiscovery] = useState(false);
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    technologies: true,
    httpHeaders: false,
    historicalUrls: false,
    cves: true,
    vulnerabilities: true,
    tls: true,
    crawl: true,
    contentDiscovery: true,
  });

  // ── Web recon findings ───────────────────────────────────────────────
  const technologies = state.findings.filter(f => f.entity_type === 'TECHNOLOGY');
  const httpHeaders = state.findings.filter(f => f.entity_type === 'HTTP_HEADER');
  const historicalUrls = state.findings.filter(f => f.entity_type === 'HISTORICAL_URL');
  const waybackSnapshots = state.findings.filter(f => f.entity_type === 'WAYBACK_SNAPSHOT');
  const cves = state.findings.filter(f => f.entity_type === 'CVE' && f.source_module === 'technology_cve');
  const versionFindings = state.findings.filter(f => f.entity_type === 'TECHNOLOGY_VERSION');
  const vulnerabilities = state.findings.filter(f => f.entity_type === 'VULNERABILITY');
  const tlsAssessments = state.findings.filter(f => f.entity_type === 'TLS_ASSESSMENT');
  const crawledPages = state.findings.filter(f => f.entity_type === 'CRAWLED_PAGE');
  const webEndpoints = state.findings.filter(f => f.entity_type === 'WEB_ENDPOINT');
  const webForms = state.findings.filter(f => f.entity_type === 'WEB_FORM');
  const webParameters = state.findings.filter(f => f.entity_type === 'WEB_PARAMETER');
  const javascriptAssets = state.findings.filter(f => f.entity_type === 'JAVASCRIPT_ASSET');
  const contentDiscoveries = state.findings.filter(f => f.entity_type === 'CONTENT_DISCOVERY');
  const crawlTotal = crawledPages.length + webEndpoints.length + webForms.length + webParameters.length + javascriptAssets.length;
  const eligibleUrls = state.assets.filter(asset => (
    asset.asset_type === 'URL'
    && asset.state === 'LIVE'
    && asset.in_scope
    && !asset.wildcard_suspected
  ));
  const discoveryJob = state.jobs.find(job => (
    job.job_type === 'content_discovery'
    && ['QUEUED', 'RUNNING', 'RETRYING'].includes(job.status)
  ));
  const discoveryRunning = dispatchingDiscovery || Boolean(discoveryJob);

  const runContentDiscovery = async () => {
    if (!state.scan?.id || discoveryRunning) return;
    if (discoveryProfile === 'exposure' && !window.confirm(
      'Run the exposure profile? It sends bounded GET requests for commonly exposed files on verified in-scope live URLs. Only continue when you are authorized to assess these targets.',
    )) return;
    setDispatchingDiscovery(true);
    setDiscoveryError(null);
    try {
      await apiClient.post(`/scans/${state.scan.id}/content-discovery`, {
        profile: discoveryProfile,
      });
    } catch (error: unknown) {
      setDiscoveryError(errorMessage(error, 'Failed to start content discovery.'));
    } finally {
      setDispatchingDiscovery(false);
    }
  };

  // Build a tech_name → version map from version_detector findings
  const versionMap = new Map<string, string>();
  versionFindings.forEach(f => {
    const nd = f.normalized_data || {};
    const tech = (nd.technology as string) || '';
    const ver = (nd.version as string) || '';
    if (tech && ver) versionMap.set(tech.toLowerCase(), ver);
  });

  const total = technologies.length + httpHeaders.length + historicalUrls.length + waybackSnapshots.length + cves.length + vulnerabilities.length + tlsAssessments.length + crawlTotal + contentDiscoveries.length;

  const discoveryControls = (
    <div style={{ marginBottom: 16, padding: 14, background: 'var(--glass-bg)', border: '1px solid var(--glass-border)', borderRadius: 'var(--radius-lg)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <FolderSearch size={16} style={{ color: '#8b5cf6' }} />
        <div style={{ flex: 1, minWidth: 220 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-strong)' }}>Manual Content Discovery</div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
            Bounded GET-only checks on up to 5 verified live origins. Redirects and response-body storage are disabled.
          </div>
        </div>
        <select
          value={discoveryProfile}
          onChange={event => setDiscoveryProfile(event.target.value as 'common' | 'exposure')}
          disabled={discoveryRunning}
          style={{ padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-primary)', color: 'var(--text)', fontSize: 11 }}
        >
          <option value="common">Common paths (16)</option>
          <option value="exposure">Exposure checks (12)</option>
        </select>
        <button
          className="btn btn-secondary"
          onClick={runContentDiscovery}
          disabled={discoveryRunning || state.scan?.scan_mode !== 'active' || eligibleUrls.length === 0}
          title={state.scan?.scan_mode !== 'active' ? 'Requires an Active-mode scan' : eligibleUrls.length === 0 ? 'No verified in-scope live URLs' : 'Run manual content discovery'}
          style={{ padding: '7px 11px', fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 6 }}
        >
          {discoveryRunning ? <Loader2 size={12} className="spin" /> : <FolderSearch size={12} />}
          {discoveryRunning ? 'Running…' : 'Run manually'}
        </button>
      </div>
      <div style={{ marginTop: 7, fontSize: 10, color: 'var(--text-muted)' }}>
        Eligible URLs: {eligibleUrls.length}. Missing-page baselines suppress custom-404 responses; stored evidence contains hashes and metadata, never response bodies.
      </div>
      {discoveryError && <div style={{ marginTop: 7, color: '#ef4444', fontSize: 10 }}>{discoveryError}</div>}
    </div>
  );

  if (total === 0) {
    return (
      <div>
        {discoveryControls}
        <div className="ws-empty" style={{ padding: 32, textAlign: 'center' }}>
          <Globe size={32} style={{ color: 'var(--text-muted)', marginBottom: 12, opacity: 0.4 }} />
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 4 }}>
            No Web OSINT Data Yet
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 400, margin: '0 auto', lineHeight: 1.5 }}>
            Run a <strong>Deep Analysis</strong> on the main domain from the Infrastructure tab to populate
            web technologies and historical data, or run authorized active validation to populate TLS and scoped-crawl evidence.
          </p>
        </div>
      </div>
    );
  }

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="ws-infra" style={{ padding: 0 }}>
      {discoveryControls}
      {/* Summary bar */}
      <div style={{
        display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap',
      }}>
        <SummaryBadge icon={<Server size={13} />} label="Technologies" count={technologies.length} color="#22c55e" />
        <SummaryBadge icon={<Code size={13} />} label="HTTP Headers" count={httpHeaders.length} color="#3b82f6" />
        <SummaryBadge icon={<History size={13} />} label="Historical URLs" count={historicalUrls.length + waybackSnapshots.length} color="#f59e0b" />
        <SummaryBadge icon={<AlertTriangle size={13} />} label="Technology CVEs" count={cves.length} color="#ef4444" />
        <SummaryBadge icon={<AlertTriangle size={13} />} label="Active Findings" count={vulnerabilities.length} color="#f97316" />
        <SummaryBadge icon={<ShieldCheck size={13} />} label="TLS Endpoints" count={tlsAssessments.length} color="#14b8a6" />
        <SummaryBadge icon={<Globe size={13} />} label="Crawl Surface" count={crawlTotal} color="#8b5cf6" />
        <SummaryBadge icon={<FolderSearch size={13} />} label="Discovered Paths" count={contentDiscoveries.length} color="#a855f7" />
        {versionMap.size > 0 && (
          <SummaryBadge icon={<Server size={13} />} label="Versions Detected" count={versionMap.size} color="#22c55e" />
        )}
      </div>

      <Section
        title="Manual Content Discovery"
        count={contentDiscoveries.length}
        icon={<FolderSearch size={14} style={{ color: '#a855f7' }} />}
        expanded={expandedSections.contentDiscovery}
        onToggle={() => toggleSection('contentDiscovery')}
      >
        {contentDiscoveries.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {contentDiscoveries.map(finding => {
              const nd = finding.normalized_data || {};
              const severity = String(finding.severity || 'INFO');
              return (
                <div key={finding.id} style={{ padding: '7px 9px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-primary)', fontSize: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
                    <span className={`badge badge-${severity.toLowerCase()}`} style={{ fontSize: 8 }}>{severity}</span>
                    <a href={finding.entity_value} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' }}>
                      {finding.entity_value}
                    </a>
                    <span style={{ color: 'var(--text-muted)' }}>HTTP {String(nd.status_code ?? '?')}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{String(nd.content_length ?? 0)} bytes</span>
                    {nd.marker_id != null && <span className="badge badge-danger" style={{ fontSize: 8 }}>{String(nd.marker_id)}</span>}
                  </div>
                  <div style={{ color: 'var(--text-muted)', marginTop: 4 }}>
                    {String(nd.profile || 'common')} profile · {String(nd.confidence_reason || 'distinct from missing-path baseline')} · SHA-256 {String(nd.content_sha256 || '').slice(0, 12)}…
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>
            No manual content-discovery findings stored yet.
          </div>
        )}
      </Section>

      {/* ── Technologies (BuiltWith) ─────────────────────────────────── */}
      <Section
        title="Web Technologies (BuiltWith)"
        count={technologies.length}
        icon={<Server size={14} style={{ color: '#22c55e' }} />}
        expanded={expandedSections.technologies}
        onToggle={() => toggleSection('technologies')}
      >
        {technologies.length > 0 ? (
          <div>
            {(() => {
              const grouped: Record<string, Array<{ category: string; icon?: string; live: number }>> = {};
              technologies.forEach(t => {
                const nd = t.normalized_data || {};
                const group = (nd.group as string) || 'Other';
                if (!grouped[group]) grouped[group] = [];
                grouped[group].push({
                  category: String(nd.category || ''),
                  icon: nd.icon == null ? undefined : String(nd.icon),
                  live: Number(nd.live || 0),
                });
              });
              return Object.entries(grouped).map(([group, items]) => (
                <div key={group} style={{ marginBottom: 14 }}>
                  <div style={{
                    fontSize: 11, fontWeight: 600, color: 'var(--accent)', marginBottom: 6,
                    textTransform: 'uppercase', letterSpacing: '0.05em',
                  }}>
                    {group} <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({items.length})</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {items.map((item, i: number) => {
                      const cat = item.category as string || '';
                      const ver = versionMap.get(cat.toLowerCase());
                      return (
                        <div key={i} className="badge badge-info" style={{ fontSize: 10, padding: '4px 10px' }}>
                          {cat}
                          {ver ? (
                            <span style={{ marginLeft: 4, color: '#22c55e', fontWeight: 600 }}>
                              v{ver}
                            </span>
                          ) : null}
                          {item.icon != null && <span style={{ marginLeft: 3 }}>{String(item.icon)}</span>}
                          {item.live > 0 && <span style={{ color: '#10b981', marginLeft: 3 }}>●</span>}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ));
            })()}
          </div>
        ) : (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>
            No technology data found. Run deep analysis to discover the web stack.
          </div>
        )}
      </Section>

      {/* ── HTTP Headers ─────────────────────────────────────────────── */}
      <Section
        title="Active Validation Findings"
        count={vulnerabilities.length}
        icon={<AlertTriangle size={14} style={{ color: '#f97316' }} />}
        expanded={expandedSections.vulnerabilities}
        onToggle={() => toggleSection('vulnerabilities')}
      >
        {vulnerabilities.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {vulnerabilities.map((finding, i) => {
              const nd = finding.normalized_data || {};
              const sev = finding.severity || 'INFO';
              return (
                <div key={finding.id || i} style={{
                  padding: '8px 10px', borderRadius: 6,
                  background: 'var(--bg-primary)', border: '1px solid var(--border)',
                  fontSize: 10,
                }}>
                  <div className="flex items-center gap-2" style={{ marginBottom: 4 }}>
                    <span className={`badge badge-${sev === 'CRITICAL' || sev === 'HIGH' ? 'danger' : sev === 'MEDIUM' ? 'warning' : 'info'}`}>
                      {sev}
                    </span>
                    <strong style={{ color: 'var(--text-strong)' }}>{String(nd.name || nd.template_id || finding.entity_value)}</strong>
                  </div>
                  <div style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                    {String(nd.matched_at || finding.entity_value)}
                  </div>
                  {nd.description != null && (
                    <div style={{ color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.4 }}>
                      {String(nd.description).slice(0, 500)}
                    </div>
                  )}
                  {Array.isArray(nd.cve_ids) && nd.cve_ids.length > 0 && (
                    <div style={{ color: '#ef4444', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
                      {nd.cve_ids.join(', ')}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>
            No Nuclei or TLS posture findings. This stage is available only from scans created in Active mode.
          </div>
        )}
      </Section>

      <Section
        title="Scoped Crawl Surface"
        count={crawlTotal}
        icon={<Globe size={14} style={{ color: '#8b5cf6' }} />}
        expanded={expandedSections.crawl}
        onToggle={() => toggleSection('crawl')}
      >
        {crawlTotal > 0 ? (
          <div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
              {[
                ['Pages fetched', crawledPages.length],
                ['Endpoints', webEndpoints.length],
                ['Forms', webForms.length],
                ['Parameters', webParameters.length],
                ['JavaScript', javascriptAssets.length],
              ].map(([label, count]) => (
                <div key={String(label)} style={{
                  padding: '5px 9px', borderRadius: 5, background: 'var(--bg-primary)',
                  border: '1px solid var(--border)', fontSize: 10,
                }}>
                  <span style={{ color: 'var(--text-muted)' }}>{label}: </span>
                  <strong style={{ color: '#8b5cf6' }}>{count}</strong>
                </div>
              ))}
            </div>

            {crawledPages.slice(0, 50).map((finding, i) => {
              const nd = finding.normalized_data || {};
              const statusCode = Number(nd.status_code || 0);
              return (
                <div key={finding.id || i} style={{
                  padding: '7px 9px', marginBottom: 5, borderRadius: 5,
                  background: 'var(--bg-primary)', border: '1px solid var(--border)', fontSize: 10,
                }}>
                  <div className="flex items-center gap-2">
                    <span className={`badge badge-${statusCode >= 500 ? 'danger' : statusCode >= 400 ? 'warning' : 'success'}`}>
                      {String(nd.status_code || '?')}
                    </span>
                    <strong style={{ color: 'var(--text-strong)' }}>{String(nd.title || 'Untitled page')}</strong>
                    <span style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>depth {String(nd.depth ?? 0)}</span>
                  </div>
                  <div style={{ marginTop: 3, color: 'var(--accent)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                    {finding.entity_value}
                  </div>
                </div>
              );
            })}

            {webEndpoints.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 5 }}>
                  Discovered endpoints
                </div>
                {webEndpoints.slice(0, 100).map((finding, i) => {
                  const nd = finding.normalized_data || {};
                  const eligible = nd.crawl_eligible === true;
                  return (
                    <div key={finding.id || i} style={{
                      display: 'flex', alignItems: 'center', gap: 7, padding: '4px 7px',
                      marginBottom: 3, borderRadius: 4, background: 'var(--bg-primary)',
                      border: '1px solid var(--border)', fontSize: 9,
                    }}>
                      <span className={`badge badge-${eligible ? 'success' : 'info'}`}>
                        {eligible ? 'safe GET' : 'evidence only'}
                      </span>
                      <span style={{ color: 'var(--text-strong)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                        {finding.entity_value}
                      </span>
                      {!eligible && nd.crawl_reason != null && (
                        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>{String(nd.crawl_reason)}</span>
                      )}
                    </div>
                  );
                })}
                {webEndpoints.length > 100 && (
                  <div style={{ color: 'var(--text-muted)', fontSize: 9 }}>Showing 100 of {webEndpoints.length} endpoints.</div>
                )}
              </div>
            )}

            {webForms.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 5 }}>
                  Forms discovered — never submitted
                </div>
                {webForms.slice(0, 50).map((finding, i) => {
                  const nd = finding.normalized_data || {};
                  const fields = Array.isArray(nd.fields) ? nd.fields as Record<string, unknown>[] : [];
                  return (
                    <div key={finding.id || i} style={{
                      padding: '6px 8px', marginBottom: 4, borderRadius: 5,
                      background: 'var(--bg-primary)', border: '1px solid var(--border)', fontSize: 9,
                    }}>
                      <span className="badge badge-info">{String(nd.method || 'GET')}</span>
                      <span style={{ marginLeft: 6, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
                        {String(nd.action || finding.entity_value)}
                      </span>
                      {fields.length > 0 && (
                        <div style={{ marginTop: 4, color: 'var(--text-muted)' }}>
                          Fields: {fields.map(field => String(field.name || '?')).join(', ')}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {javascriptAssets.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 5 }}>
                  JavaScript assets queued for later analysis
                </div>
                {javascriptAssets.slice(0, 100).map((finding, i) => (
                  <div key={finding.id || i} style={{
                    padding: '4px 7px', marginBottom: 3, borderRadius: 4,
                    background: 'var(--bg-primary)', border: '1px solid var(--border)',
                    color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 9,
                    wordBreak: 'break-all',
                  }}>
                    {finding.entity_value}
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>
            No scoped-crawl results. Run active validation on an Active-mode scan with a verified live URL.
          </div>
        )}
      </Section>

      <Section
        title="TLS Posture"
        count={tlsAssessments.length}
        icon={<ShieldCheck size={14} style={{ color: '#14b8a6' }} />}
        expanded={expandedSections.tls}
        onToggle={() => toggleSection('tls')}
      >
        {tlsAssessments.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {tlsAssessments.map((finding, i) => {
              const nd = finding.normalized_data || {};
              const certificate = (nd.certificate || {}) as Record<string, unknown>;
              const protocols = (nd.supported_protocols || {}) as Record<string, unknown>;
              const issues = Array.isArray(nd.issues) ? nd.issues as Record<string, unknown>[] : [];
              return (
                <div key={finding.id || i} style={{
                  padding: '10px 12px', borderRadius: 6,
                  background: 'var(--bg-primary)', border: '1px solid var(--border)',
                  fontSize: 10,
                }}>
                  <div className="flex items-center gap-2" style={{ marginBottom: 7 }}>
                    <strong style={{ color: 'var(--text-strong)', fontFamily: 'var(--font-mono)' }}>
                      {finding.entity_value}
                    </strong>
                    <span className={`badge badge-${issues.length > 0 ? 'warning' : 'success'}`}>
                      {issues.length > 0 ? `${issues.length} issue${issues.length === 1 ? '' : 's'}` : 'No issues detected'}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1" style={{ marginBottom: 7 }}>
                    {Object.keys(protocols).map(protocol => (
                      <span key={protocol} className="badge badge-info">{protocol}</span>
                    ))}
                  </div>
                  <div style={{ color: 'var(--text-muted)', lineHeight: 1.6 }}>
                    <div><span style={{ color: 'var(--accent)' }}>Subject:</span> {String(certificate.subject || 'Unknown')}</div>
                    <div><span style={{ color: 'var(--accent)' }}>Issuer:</span> {String(certificate.issuer || 'Unknown')}</div>
                    <div>
                      <span style={{ color: 'var(--accent)' }}>Valid until:</span> {String(certificate.not_after || 'Unknown')}
                      {' · '}
                      <span style={{ color: certificate.hostname_valid === true ? '#10b981' : '#ef4444' }}>
                        {certificate.hostname_valid === true ? 'Hostname matches' : 'Hostname mismatch'}
                      </span>
                      {' · '}
                      <span style={{ color: certificate.chain_trusted === true ? '#10b981' : certificate.chain_trusted === false ? '#ef4444' : 'var(--text-muted)' }}>
                        {certificate.chain_trusted === true ? 'Public chain trusted' : certificate.chain_trusted === false ? 'Chain not trusted' : 'Trust not verified'}
                      </span>
                    </div>
                  </div>
                  {issues.length > 0 && (
                    <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 5 }}>
                      {issues.map((issue, issueIndex) => {
                        const severity = String(issue.severity || 'INFO');
                        return (
                          <div key={`${String(issue.code || 'issue')}-${issueIndex}`} style={{
                            padding: '6px 8px', borderRadius: 5,
                            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                          }}>
                            <span className={`badge badge-${severity === 'HIGH' || severity === 'CRITICAL' ? 'danger' : severity === 'MEDIUM' ? 'warning' : 'info'}`}>
                              {severity}
                            </span>
                            <strong style={{ marginLeft: 6, color: 'var(--text-strong)' }}>{String(issue.title || issue.code)}</strong>
                            <div style={{ marginTop: 3, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                              {String(issue.description || '')}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>
            No TLS assessment results. Run active validation on an Active-mode scan containing a live HTTPS asset.
          </div>
        )}
      </Section>

      <Section
        title="HTTP Response Headers"
        count={httpHeaders.length}
        icon={<Code size={14} style={{ color: '#3b82f6' }} />}
        expanded={expandedSections.httpHeaders}
        onToggle={() => toggleSection('httpHeaders')}
      >
        {httpHeaders.length > 0 ? (
          <div>
            {httpHeaders.map((h, i) => {
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
                  {nd.error != null && <div style={{ color: '#ef4444', marginBottom: 2 }}>{String(nd.error)}</div>}
                  {Object.entries(headers).map(([k, v]) => (
                    <div key={k} style={{ color: 'var(--text-muted)', lineHeight: 1.6 }}>
                      <span style={{ color: 'var(--accent)' }}>{k}:</span> {String(v).slice(0, 200)}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>
            No HTTP response headers captured.
          </div>
        )}
      </Section>

      {/* ── Historical URLs (Wayback Machine) ─────────────────────────── */}
      <Section
        title="Historical URLs (Wayback Machine)"
        count={historicalUrls.length + waybackSnapshots.length}
        icon={<History size={14} style={{ color: '#f59e0b' }} />}
        expanded={expandedSections.historicalUrls}
        onToggle={() => toggleSection('historicalUrls')}
      >
        {waybackSnapshots.length > 0 && (
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 4 }}>
              Latest Snapshot{waybackSnapshots.length > 1 ? 's' : ''}
            </div>
            {waybackSnapshots.map((s, i) => {
              const nd = s.normalized_data || {};
              return (
                <div key={i} style={{
                  padding: '6px 10px', marginBottom: 4, borderRadius: 6,
                  background: 'var(--bg-primary)', border: '1px solid var(--border)',
                  fontSize: 10, fontFamily: 'var(--font-mono)',
                }}>
                  <div style={{ color: 'var(--text-strong)' }}>
                    {String(nd.original_url || s.entity_value)}
                  </div>
                  <div style={{ color: 'var(--text-muted)', marginTop: 2 }}>
                    {nd.timestamp != null && <span>Archived: {String(nd.timestamp)}</span>}
                    {nd.wayback_url != null && (
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
        {historicalUrls.length > 0 && (
          <div>
            <div style={{
              fontSize: 11, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 4,
            }}>
              Archived Pages ({historicalUrls.length})
            </div>
            <div style={{ maxHeight: 400, overflowY: 'auto' }}>
              {historicalUrls.map((u, i) => {
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
                    <span style={{
                      color: 'var(--text-strong)', flex: 1,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>
                      {String(nd.original_url || u.entity_value)}
                    </span>
                    {nd.status_code != null && (
                      <span style={{
                        flexShrink: 0,
                        color: Number(nd.status_code) >= 400 ? '#ef4444' : '#10b981',
                      }}>
                        {String(nd.status_code)}
                      </span>
                    )}
                    {nd.wayback_url != null && (
                      <a href={String(nd.wayback_url)} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', flexShrink: 0 }}>↗</a>
                    )}
                    {nd.mime_type != null && (
                      <span className="badge" style={{ fontSize: 8, flexShrink: 0 }}>
                        {String(nd.mime_type).split('/')[1] || String(nd.mime_type)}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
        {historicalUrls.length === 0 && waybackSnapshots.length === 0 && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>
            No historical URLs found. Run deep analysis to discover Wayback Machine data.
          </div>
        )}
      </Section>

      {/* ── Technology CVEs ────────────────────────────────────────── */}
      <Section
        title="Technology CVEs (NVD Cross-Reference)"
        count={cves.length}
        icon={<AlertTriangle size={14} style={{ color: '#ef4444' }} />}
        expanded={expandedSections.cves}
        onToggle={() => toggleSection('cves')}
      >
        {cves.length > 0 ? (
          <div>
            {(() => {
              // Group by severity
              const grouped: Record<string, FindingRow[]> = {};
              const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
              cves.forEach(c => {
                const sev = c.severity || 'INFO';
                if (!grouped[sev]) grouped[sev] = [];
                grouped[sev].push(c);
              });
              return ORDER.map(sev => {
                const items = grouped[sev];
                if (!items || items.length === 0) return null;
                return (
                  <div key={sev} style={{ marginBottom: 12 }}>
                    <div style={{
                      fontSize: 11, fontWeight: 600, marginBottom: 4,
                      color: sev === 'CRITICAL' ? '#ef4444' : sev === 'HIGH' ? '#f97316' : sev === 'MEDIUM' ? '#eab308' : 'var(--text-muted)',
                      textTransform: 'uppercase', letterSpacing: '0.05em',
                    }}>
                      {sev} <span style={{ fontWeight: 400 }}>({items.length})</span>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                      {items.map((c, i: number) => {
                        const nd = c.normalized_data || {};
                        const cveId = c.entity_value;
                        const description = (nd.description as string) || '';
                        const techName = (nd.technology as string) || '';
                        return (
                          <div key={i} style={{
                            padding: '3px 8px', borderRadius: 4, fontSize: 10,
                            fontFamily: 'var(--font-mono)',
                            background: sev === 'CRITICAL' ? 'rgba(239,68,68,0.12)' : sev === 'HIGH' ? 'rgba(249,115,22,0.1)' : 'var(--bg-primary)',
                            border: `1px solid ${
                              sev === 'CRITICAL' ? 'rgba(239,68,68,0.3)' : sev === 'HIGH' ? 'rgba(249,115,22,0.25)' : 'var(--border)'
                            }`,
                          }}
                            title={description ? `${cveId}: ${description.slice(0, 300)}` : cveId}
                          >
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                              target="_blank"
                              rel="noreferrer"
                              style={{
                                color: sev === 'CRITICAL' ? '#ef4444' : sev === 'HIGH' ? '#f97316' : 'var(--text-strong)',
                                textDecoration: 'none',
                              }}
                              onClick={e => e.stopPropagation()}
                            >
                              {cveId}
                            </a>
                            {techName && (
                              <span style={{ color: 'var(--text-muted)', marginLeft: 4 }}>
                                ← {techName}
                              </span>
                            )}
                            {(nd.detected_version as string) && (
                              <span style={{
                                marginLeft: 4, padding: '1px 5px', borderRadius: 3,
                                background: 'rgba(34,197,94,0.12)', color: '#22c55e',
                                fontSize: 9, fontWeight: 600,
                              }}>
                                v{String(nd.detected_version)}
                              </span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              });
            })()}
          </div>
        ) : (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>
            No CVEs found from technology cross-referencing.
          </div>
        )}
      </Section>
    </div>
  );
}

/* ─── Sub-components ────────────────────────────────────────────────── */

function SummaryBadge({ icon, label, count, color }: {
  icon: React.ReactNode; label: string; count: number; color: string;
}) {
  return (
    <div style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      padding: '6px 12px', borderRadius: 8,
      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      fontSize: 12,
    }}>
      {icon}
      <span style={{ color: 'var(--text-muted)' }}>{label}:</span>
      <span style={{ color, fontWeight: 700 }}>{count}</span>
    </div>
  );
}

function Section({ title, count, icon, expanded, onToggle, children }: {
  title: string; count: number; icon: React.ReactNode;
  expanded: boolean; onToggle: () => void; children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom: 16, background: 'var(--bg-secondary)', borderRadius: 8, border: '1px solid var(--border)', overflow: 'hidden' }}>
      <div
        className="flex items-center gap-2"
        onClick={onToggle}
        style={{
          cursor: 'pointer', userSelect: 'none', padding: '10px 14px',
          background: 'var(--bg-primary)', borderBottom: expanded ? '1px solid var(--border)' : 'none',
        }}
      >
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        {icon}
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)', flex: 1 }}>
          {title}
        </span>
        <span style={{
          fontSize: 10, padding: '1px 6px', borderRadius: 10,
          background: 'var(--accent-dim)', color: 'var(--accent)', fontWeight: 600,
          minWidth: 18, textAlign: 'center',
        }}>
          {count}
        </span>
      </div>
      {expanded && (
        <div style={{ padding: '12px 14px' }}>
          {children}
        </div>
      )}
    </div>
  );
}
