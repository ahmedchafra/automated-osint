import { useMemo, useState } from 'react';
import { AlertTriangle, GitBranch, Key, Loader2, Search, ShieldCheck } from 'lucide-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useScanWorkspace } from '../../context/scan-workspace-state';
import apiClient from '../../api/client';
import { errorMessage } from '../../utils/errors';
import { GithubRepositoryTable } from './GithubRepositoryTable';
import { SecretExposureCard } from './SecretExposureCard';
import { toGithubRepository, toGithubSecret } from './githubEvidence';
import type { PaginatedFindings } from '../../types/api';

const ACTIVE = new Set(['QUEUED', 'RUNNING', 'RETRYING']);
const PAGE_SIZE = 25;
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function SecretsTab({ canModify = true }: { canModify?: boolean }) {
  const { state } = useScanWorkspace();
  const queryClient = useQueryClient();
  const [requestPending, setRequestPending] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [secretType, setSecretType] = useState('ALL');
  const [page, setPage] = useState(1);
  const [repoPage, setRepoPage] = useState(1);

  const githubJobs = state.jobs.filter(job => job.job_type === 'github_secrets_scan');
  const latestJob = githubJobs[0];
  const persistedRunning = githubJobs.some(job => ACTIVE.has(job.status));
  const isRunning = requestPending || persistedRunning;
  const scan = state.scan;
  const baseDomain = scan?.target_domain || '';
  const supportsDomainScan = Boolean(baseDomain) && scan?.target_type !== 'ip';
  const { data: secretResponse } = useQuery<PaginatedFindings>({
    queryKey: ['scanFindings', scan?.id, 'LEAKED_SECRET'],
    queryFn: async () => (await apiClient.get('/findings/', {
      params: { scan_id: scan?.id, entity_type: 'LEAKED_SECRET', limit: 5000 },
    })).data,
    enabled: Boolean(scan?.id),
    refetchInterval: isRunning ? 4_000 : false,
  });
  const { data: repositoryResponse } = useQuery<PaginatedFindings>({
    queryKey: ['scanFindings', scan?.id, 'GITHUB_REPO'],
    queryFn: async () => (await apiClient.get('/findings/', {
      params: { scan_id: scan?.id, entity_type: 'GITHUB_REPO', limit: 5000 },
    })).data,
    enabled: Boolean(scan?.id),
    refetchInterval: isRunning ? 4_000 : false,
  });

  const secrets = useMemo(
    () => (secretResponse?.items ?? state.findings.filter(finding => finding.entity_type === 'LEAKED_SECRET')).map(toGithubSecret),
    [secretResponse?.items, state.findings],
  );
  const repositories = useMemo(
    () => (repositoryResponse?.items ?? state.findings.filter(finding => finding.entity_type === 'GITHUB_REPO')).map(toGithubRepository),
    [repositoryResponse?.items, state.findings],
  );
  const secretTypes = useMemo(
    () => [...new Set(secrets.map(item => item.secretType))].sort(),
    [secrets],
  );
  const severityCounts = useMemo(() => Object.fromEntries(
    SEVERITY_ORDER.map(level => [level, secrets.filter(item => item.severity === level).length]),
  ), [secrets]);

  const filteredSecrets = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return secrets
      .filter(item => severity === 'ALL' || item.severity === severity)
      .filter(item => secretType === 'ALL' || item.secretType === secretType)
      .filter(item => !needle || `${item.repoName} ${item.filePath} ${item.secretType}`.toLowerCase().includes(needle))
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  }, [search, secretType, secrets, severity]);

  const secretPages = Math.max(1, Math.ceil(filteredSecrets.length / PAGE_SIZE));
  const currentPage = Math.min(page, secretPages);
  const visibleSecrets = filteredSecrets.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
  const repoPages = Math.max(1, Math.ceil(repositories.length / PAGE_SIZE));
  const currentRepoPage = Math.min(repoPage, repoPages);
  const visibleRepositories = repositories.slice((currentRepoPage - 1) * PAGE_SIZE, currentRepoPage * PAGE_SIZE);
  const hasLegacyEvidence = secrets.some(item => !item.classifierVersion)
    || repositories.some(item => !item.searchStrategy);

  const handleScan = async () => {
    if (!scan?.id || !supportsDomainScan || !canModify) return;
    setRequestPending(true);
    setRequestError(null);
    try {
      await apiClient.post(`/scans/${scan.id}/secrets-scan`, { domain: baseDomain });
      await queryClient.invalidateQueries({ queryKey: ['scanJobs', scan.id] });
    } catch (error) {
      setRequestError(errorMessage(error, 'Unable to start GitHub exposure search.'));
    } finally {
      setRequestPending(false);
    }
  };

  const failure = requestError || (latestJob?.status === 'FAILED' ? latestJob.error || 'GitHub exposure search failed.' : null);

  return (
    <div className="ws-secrets">
      <section className="workspace-panel ws-secrets-hero">
        <div className="workspace-panel-heading">
          <div>
            <span className="workspace-eyebrow">Public code intelligence</span>
            <h2>GitHub exposure review</h2>
          </div>
          {canModify && supportsDomainScan && (
            <button className="ws-enrich-btn-primary" onClick={handleScan} disabled={isRunning}>
              {isRunning ? <Loader2 size={13} className="animate-spin" /> : <Key size={13} />}
              {isRunning ? 'Searching…' : githubJobs.length ? 'Search again' : 'Search GitHub'}
            </button>
          )}
        </div>
        <p>
          Finds public repository files that combine credential indicators with the target name or domain.
          Matches are leads for manual validation—not proof that a credential is valid or owned by the target.
        </p>
        <div className="ws-secret-privacy">
          <ShieldCheck size={14} /> Secret values and file contents are intentionally not stored; only evidence metadata and GitHub links are retained.
        </div>
        {!canModify && <div className="ws-secret-note">Read-only access: you can review evidence but cannot launch collectors.</div>}
        {scan?.target_type === 'ip' && <div className="ws-secret-note">GitHub exposure search requires a domain target and is unavailable for IP-only scans.</div>}
        {hasLegacyEvidence && <div className="ws-secret-note"><AlertTriangle size={14} />Some stored results predate the exact-domain classifier and retain their historical score. Treat them as legacy leads; new scans use the stricter rules.</div>}
        {latestJob && (
          <div className="ws-secret-job">
            Latest run: <strong>{latestJob.status.toLowerCase()}</strong>
            {latestJob.input_value ? ` for ${latestJob.input_value}` : ''}
          </div>
        )}
        {failure && <div className="ws-secret-error" role="alert"><AlertTriangle size={14} />{failure}</div>}
      </section>

      <section className="workspace-panel">
        <div className="workspace-panel-heading">
          <div><span className="workspace-eyebrow">Potential exposure</span><h2>Credential indicators ({secretResponse?.total ?? secrets.length})</h2></div>
          <Key size={18} />
        </div>
        {secrets.length > 0 ? (
          <>
            <div className="ws-secret-severity-row">
              {SEVERITY_ORDER.filter(level => severityCounts[level]).map(level => (
                <button key={level} className={`severity-filter severity-${level.toLowerCase()}${severity === level ? ' active' : ''}`} onClick={() => { setSeverity(severity === level ? 'ALL' : level); setPage(1); }}>
                  {severityCounts[level]} {level}
                </button>
              ))}
            </div>
            <div className="ws-secret-filters">
              <label><Search size={14} /><input value={search} onChange={event => { setSearch(event.target.value); setPage(1); }} placeholder="Repository, file, or type" /></label>
              <select value={secretType} onChange={event => { setSecretType(event.target.value); setPage(1); }} aria-label="Secret type">
                <option value="ALL">All secret types</option>
                {secretTypes.map(type => <option value={type} key={type}>{type}</option>)}
              </select>
            </div>
            {visibleSecrets.length ? (
              <div className="ws-secrets-feed">{visibleSecrets.map(item => <SecretExposureCard key={item.id} evidence={item} />)}</div>
            ) : <div className="workspace-empty">No potential exposures match these filters.</div>}
            <Pagination page={currentPage} pages={secretPages} total={filteredSecrets.length} onChange={setPage} />
          </>
        ) : (
          <div className="workspace-empty">No GitHub credential indicators are stored for this scan.</div>
        )}
      </section>

      <section className="workspace-panel">
        <div className="workspace-panel-heading">
          <div><span className="workspace-eyebrow">Search context</span><h2>Related public repository matches ({repositoryResponse?.total ?? repositories.length})</h2></div>
          <GitBranch size={18} />
        </div>
        <p className="ws-secret-section-note">Name, description, or README search matches provide context only; they do not establish repository ownership.</p>
        {visibleRepositories.length
          ? <><GithubRepositoryTable repositories={visibleRepositories} /><Pagination page={currentRepoPage} pages={repoPages} total={repositories.length} onChange={setRepoPage} /></>
          : <div className="workspace-empty">No related repositories are stored for this scan.</div>}
      </section>
    </div>
  );
}

function Pagination({ page, pages, total, onChange }: { page: number; pages: number; total: number; onChange: (page: number) => void }) {
  if (pages <= 1) return null;
  return (
    <div className="evidence-pagination">
      <span>{total.toLocaleString()} results · page {page} of {pages}</span>
      <div><button disabled={page <= 1} onClick={() => onChange(page - 1)}>Previous</button><button disabled={page >= pages} onClick={() => onChange(page + 1)}>Next</button></div>
    </div>
  );
}
