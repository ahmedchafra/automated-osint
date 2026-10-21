import { useState } from 'react';
import { Server, Code, History, AlertTriangle, Globe, ChevronDown, ChevronRight } from 'lucide-react';
import { useScanWorkspace } from '../../context/ScanWorkspaceContext';

export function WebOsintTab() {
  const { state } = useScanWorkspace();
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    technologies: true,
    httpHeaders: false,
    historicalUrls: false,
    cves: true,
  });

  // ── Web recon findings ───────────────────────────────────────────────
  const technologies = state.findings.filter(f => f.entity_type === 'TECHNOLOGY');
  const httpHeaders = state.findings.filter(f => f.entity_type === 'HTTP_HEADER');
  const historicalUrls = state.findings.filter(f => f.entity_type === 'HISTORICAL_URL');
  const waybackSnapshots = state.findings.filter(f => f.entity_type === 'WAYBACK_SNAPSHOT');
  const cves = state.findings.filter(f => f.entity_type === 'CVE' && f.source_module === 'technology_cve');
  const versionFindings = state.findings.filter(f => f.entity_type === 'TECHNOLOGY_VERSION');

  // Build a tech_name → version map from version_detector findings
  const versionMap = new Map<string, string>();
  versionFindings.forEach(f => {
    const nd = f.normalized_data || {};
    const tech = (nd.technology as string) || '';
    const ver = (nd.version as string) || '';
    if (tech && ver) versionMap.set(tech.toLowerCase(), ver);
  });

  const total = technologies.length + httpHeaders.length + historicalUrls.length + waybackSnapshots.length + cves.length;

  if (total === 0) {
    return (
      <div className="ws-empty" style={{ padding: 32, textAlign: 'center' }}>
        <Globe size={32} style={{ color: 'var(--text-muted)', marginBottom: 12, opacity: 0.4 }} />
        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 4 }}>
          No Web OSINT Data Yet
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 400, margin: '0 auto', lineHeight: 1.5 }}>
          Run a <strong>Deep Analysis</strong> on the main domain from the Infrastructure tab to populate
          web technologies, HTTP headers, and historical URL data here.
        </p>
      </div>
    );
  }

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="ws-infra" style={{ padding: 0 }}>
      {/* Summary bar */}
      <div style={{
        display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap',
      }}>
        <SummaryBadge icon={<Server size={13} />} label="Technologies" count={technologies.length} color="#22c55e" />
        <SummaryBadge icon={<Code size={13} />} label="HTTP Headers" count={httpHeaders.length} color="#3b82f6" />
        <SummaryBadge icon={<History size={13} />} label="Historical URLs" count={historicalUrls.length + waybackSnapshots.length} color="#f59e0b" />
        <SummaryBadge icon={<AlertTriangle size={13} />} label="Technology CVEs" count={cves.length} color="#ef4444" />
        {versionMap.size > 0 && (
          <SummaryBadge icon={<Server size={13} />} label="Versions Detected" count={versionMap.size} color="#22c55e" />
        )}
      </div>

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
              const grouped: Record<string, any[]> = {};
              technologies.forEach(t => {
                const nd = t.normalized_data || {};
                const group = (nd.group as string) || 'Other';
                if (!grouped[group]) grouped[group] = [];
                grouped[group].push(nd);
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
                    {items.map((item: any, i: number) => {
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
                          {item.icon && <span style={{ marginLeft: 3 }}>{item.icon}</span>}
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
              const grouped: Record<string, any[]> = {};
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
                      {items.map((c: any, i: number) => {
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
