import { useState, useMemo } from 'react';
import { GitBranch, Key, FileCode, Loader2, ShieldCheck, ExternalLink, Copy } from 'lucide-react';
import { useScanWorkspace } from '../../context/ScanWorkspaceContext';
import apiClient from '../../api/client';

const SEVERITY_BG: Record<string, string> = {
  CRITICAL: 'var(--severity-critical, #b91c1c)',
  HIGH: 'var(--severity-high)',
  MEDIUM: 'var(--severity-medium)',
  LOW: 'var(--severity-low)',
  INFO: 'var(--severity-info, #64748b)',
};

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'badge-danger',
  HIGH: 'badge-danger',
  MEDIUM: 'badge-warning',
  LOW: 'badge-info',
  INFO: 'badge-info',
};

export function SecretsTab() {
  const { state } = useScanWorkspace();
  const [scanRunning, setScanRunning] = useState(false);
  const [scannedDomain, setScannedDomain] = useState<string | null>(null);
  const persistedScanRunning = state.jobs.some(job =>
    job.job_type === 'github_secrets_scan'
    && ['QUEUED', 'RUNNING', 'RETRYING'].includes(job.status)
  );
  const isScanRunning = scanRunning || persistedScanRunning;

  const repos = state.findings.filter(f => f.entity_type === 'GITHUB_REPO');
  const secrets = state.findings.filter(f => f.entity_type === 'LEAKED_SECRET');
  const baseDomain = state.scan?.target_domain || '';

  const secretTypes = useMemo(() => {
    const acc: Record<string, number> = {};
    for (const s of secrets) {
      const t = String(s.normalized_data?.secret_type ?? s.normalized_data?.type ?? 'UNKNOWN');
      acc[t] = (acc[t] || 0) + 1;
    }
    return acc;
  }, [secrets]);

  const severityCounts = useMemo(() => {
    const acc: Record<string, number> = {};
    for (const s of secrets) {
      acc[s.severity] = (acc[s.severity] || 0) + 1;
    }
    return acc;
  }, [secrets]);

  // Sort secrets: HIGH/CRITICAL first, then MEDIUM, then LOW/INFO
  const sortedSecrets = useMemo(() => {
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return [...secrets].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  }, [secrets]);

  const handleScanSecrets = async () => {
    if (!baseDomain || !state.scan?.id) return;
    setScanRunning(true);
    setScannedDomain(baseDomain);
    try {
      await apiClient.post(`/scans/${state.scan.id}/secrets-scan`, { domain: baseDomain });
    } catch (err: any) {
      console.error('Secrets scan failed:', err);
    } finally {
      setScanRunning(false);
    }
  };

  if (repos.length === 0 && secrets.length === 0 && !isScanRunning) {
    return (
      <div className="ws-empty" style={{ padding: '2rem' }}>
        <ShieldCheck size={32} style={{ marginBottom: 8, opacity: 0.4 }} />
        <div>No secret exposure data yet.</div>
        <div style={{ fontSize: 11, marginTop: 4, color: 'var(--text-muted)' }}>
          Scan GitHub for leaked API keys, tokens, and credentials associated with {baseDomain}.
        </div>
        <button
          className="ws-enrich-btn-primary"
          onClick={handleScanSecrets}
          disabled={!baseDomain}
          style={{
            marginTop: 12,
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '6px 16px', borderRadius: 6, fontSize: 12, fontWeight: 500, border: 'none',
            cursor: !baseDomain ? 'not-allowed' : 'pointer',
            opacity: !baseDomain ? 0.5 : 1,
            background: 'var(--accent)', color: '#fff',
          }}
        >
          <Key size={13} />
          Scan GitHub Secrets
        </button>
      </div>
    );
  }

  return (
    <div className="ws-secrets">
      {/* Header / scan panel */}
      <div style={{ marginBottom: 16, padding: '12px 16px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Key size={14} style={{ color: 'var(--accent)' }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)' }}>GitHub Secrets Vault</span>
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
              {secrets.length} secret{secrets.length === 1 ? '' : 's'} · {repos.length} repo{repos.length === 1 ? '' : 's'}
            </span>
          </div>
          <button
            className="ws-enrich-btn-primary"
            onClick={handleScanSecrets}
            disabled={isScanRunning}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '5px 14px', borderRadius: 6, fontSize: 12, fontWeight: 500, border: 'none',
              cursor: isScanRunning ? 'not-allowed' : 'pointer',
              opacity: isScanRunning ? 0.5 : 1,
              background: 'var(--accent)', color: '#fff',
            }}
          >
            {isScanRunning ? <Loader2 size={12} className="animate-spin" /> : <Key size={12} />}
            {isScanRunning ? 'Scanning...' : 'Scan Again'}
          </button>
        </div>
        {isScanRunning && (
          <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-muted)' }}>
            Scanning {scannedDomain} public repos for leaked secrets...
          </div>
        )}
      </div>

      {/* Severity summary chips */}
      {secrets.length > 0 && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
          {Object.entries(severityCounts)
            .sort(([a], [b]) => {
              const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
              return order.indexOf(a) - order.indexOf(b);
            })
            .map(([sev, count]) => (
              <div
                key={sev}
                style={{
                  padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                  background: SEVERITY_BG[sev] || 'var(--severity-info, #64748b)',
                  color: '#fff',
                }}
              >
                {count} {sev}
              </div>
            ))}
          <div style={{ flex: 1 }} />
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {Object.keys(secretTypes).length} type{Object.keys(secretTypes).length === 1 ? '' : 's'}
          </div>
        </div>
      )}

      {/* Type breakdown — pills */}
      {Object.keys(secretTypes).length > 0 && (
        <div style={{ display: 'flex', gap: 6, marginBottom: 16, flexWrap: 'wrap' }}>
          {Object.entries(secretTypes)
            .sort(([, a], [, b]) => b - a)
            .map(([t, n]) => (
              <span
                key={t}
                style={{
                  fontSize: 10, padding: '2px 8px', borderRadius: 4,
                  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                  color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                }}
              >
                {t} · {n}
              </span>
            ))}
        </div>
      )}

      {/* Secrets feed */}
      {sortedSecrets.length > 0 && (
        <>
          <h3 className="mb-3 flex items-center gap-2">
            <Key size={18} className="text-accent-danger" />
            Leaked Secrets ({sortedSecrets.length})
          </h3>
          <div className="ws-secrets-feed">
            {sortedSecrets.map(s => {
              const nd = (s.normalized_data || {}) as Record<string, any>;
              const secretType = String(nd.secret_type ?? nd.type ?? 'SECRET');
              const repoName = String(nd.repository ?? nd.repo ?? nd.repo_name ?? s.entity_value);
              const filePath = nd.file ?? nd.file_path;
              const fileUrl = nd.url ?? nd.file_url;
              const snippet = nd.snippet;
              return (
                <div key={s.id} className="ws-secret-card">
                  <div className="ws-secret-header">
                    <span className="ws-secret-type">{secretType}</span>
                    <span className={`badge ${SEVERITY_BADGE[s.severity] || 'badge-info'}`}>
                      {s.severity}
                    </span>
                  </div>
                  <div className="ws-secret-repo font-mono text-sm mb-2">
                    <GitBranch size={14} className="mr-1" />
                    {repoName}
                  </div>
                  {filePath != null && (
                    <div className="ws-secret-file font-mono text-xs text-gray mb-2">
                      <FileCode size={12} className="mr-1" />
                      {String(filePath)}
                    </div>
                  )}
                  {snippet != null && (
                    <div className="ws-code-block">
                      <code>{String(snippet)}</code>
                    </div>
                  )}
                  {fileUrl != null && (
                    <a
                      href={String(fileUrl)}
                      target="_blank"
                      rel="noreferrer"
                      className="text-accent text-xs mt-2 inline-flex items-center gap-3"
                    >
                      <span>
                        <ExternalLink size={11} className="mr-1" />
                        View on GitHub
                      </span>
                      <span
                        style={{ cursor: 'pointer', color: 'var(--text-muted)' }}
                        onClick={(e) => {
                          e.preventDefault();
                          navigator.clipboard?.writeText(String(fileUrl));
                        }}
                        title="Copy file URL"
                      >
                        <Copy size={11} className="mr-1" />
                        Copy URL
                      </span>
                    </a>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      {/* Repositories */}
      {repos.length > 0 && (
        <>
          <h3 className="mb-3 mt-6 flex items-center gap-2">
            <GitBranch size={18} className="text-accent-primary" />
            Related Repositories ({repos.length})
          </h3>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Repository</th>
                  <th>Stars</th>
                  <th>Language</th>
                </tr>
              </thead>
              <tbody>
                {repos.map(r => (
                  <tr key={r.id}>
                    <td className="font-mono" style={{ color: 'var(--text-strong)' }}>
                      {String(r.normalized_data?.name ?? r.entity_value)}
                    </td>
                    <td className="text-gray">{String(r.normalized_data?.stars ?? '—')}</td>
                    <td className="text-gray">{String(r.normalized_data?.language ?? '—')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
