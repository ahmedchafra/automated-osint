import { useState, useMemo, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, Search, Loader2, Zap, Mail, ShieldCheck, Key, Filter, X, Brain, Server, History, Code, Globe, Camera } from 'lucide-react';
import { useScanWorkspace } from '../../context/scan-workspace-state';
import type {
  AssetRecord,
  DomainDeepAnalysisProgress,
  EmailDeepAnalysisProgress,
} from '../../context/ScanWorkspaceContext';
import { SeverityBadge, type FindingRow } from '../FindingsTable';
import { DeepAnalysisProgress, type ProgressItem } from './DeepAnalysisProgress';
import apiClient from '../../api/client';
import { isAxiosError } from 'axios';

const PAGE_SIZE = 25;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function recordArray(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

interface ScreenshotEvidence {
  id: string;
  scan_id: string;
  asset_id?: string | null;
  url: string;
  sha256: string;
  width: number;
  height: number;
  page_title?: string | null;
  status_code?: number | null;
  capture_metadata: Record<string, unknown>;
  created_at: string;
  image_url: string;
}

interface AssetObservation {
  id: string;
  scan_id: string;
  asset_id: string;
  asset_type: string;
  canonical_value: string;
  state: string;
  source_module?: string | null;
  event_type: string;
  in_scope: boolean;
  wildcard_suspected: boolean;
  evidence: Record<string, unknown>;
  observed_at: string;
  created_at: string;
}

interface AssetObservationSummary {
  asset_id: string;
  observation_count: number;
  first_observed_at: string;
  last_observed_at: string;
}

function formatObservedAt(value?: string | null) {
  if (!value) return '—';
  return new Date(value).toLocaleString();
}

function ScreenshotImage({ scanId, evidence }: { scanId: string; evidence: ScreenshotEvidence }) {
  const { data: imageBlob, isLoading } = useQuery<Blob>({
    queryKey: ['screenshotImage', scanId, evidence.id],
    queryFn: async () => (
      await apiClient.get(`/scans/${scanId}/screenshots/${evidence.id}/image`, { responseType: 'blob' })
    ).data,
    staleTime: Infinity,
  });
  const imageUrl = useMemo(() => imageBlob ? URL.createObjectURL(imageBlob) : null, [imageBlob]);
  useEffect(() => () => { if (imageUrl) URL.revokeObjectURL(imageUrl); }, [imageUrl]);

  if (isLoading || !imageUrl) {
    return <div style={{ height: 135, display: 'grid', placeItems: 'center', color: 'var(--text-muted)' }}><Loader2 size={16} className="spin" /></div>;
  }
  return (
    <a
      href={imageUrl}
      target="_blank"
      rel="noopener noreferrer"
      title="Open full-size screenshot"
      style={{ display: 'block', cursor: 'zoom-in' }}
    >
      <img
        src={imageUrl}
        alt={`Screenshot of ${evidence.url}`}
        loading="lazy"
        style={{ width: '100%', height: 135, objectFit: 'cover', objectPosition: 'top', display: 'block' }}
      />
    </a>
  );
}

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
  const [includingAssetIds, setIncludingAssetIds] = useState<Set<string>>(new Set());
  const [scopeActionError, setScopeActionError] = useState<string | null>(null);
  const [screenshotError, setScreenshotError] = useState<string | null>(null);
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
  const screenshotRunning = activeJobs.some(job => job.job_type === 'screenshot_capture');

  const mainDomain = state.scan?.target_domain || '';
  const scanId = state.scan?.id;
  const candidateAssets = state.assets.filter(asset => asset.state === 'CANDIDATE');
  const resolvedAssets = state.assets.filter(asset => asset.state === 'RESOLVED');
  const liveAssets = state.assets.filter(asset => asset.state === 'LIVE');
  const wildcardAssets = state.assets.filter(asset => asset.wildcard_suspected);
  const excludedAssets = state.assets.filter(asset => !asset.in_scope);
  const liveUrls = liveAssets.filter(asset => asset.asset_type === 'URL');
  const captureEligibleUrls = liveUrls.filter(asset => asset.in_scope && !asset.wildcard_suspected);
  const domainAssetsByValue = useMemo(() => {
    const assets = new Map<string, AssetRecord>();
    for (const asset of state.assets) {
      if (asset.asset_type !== 'DOMAIN' && asset.asset_type !== 'SUBDOMAIN') continue;
      assets.set(asset.canonical_value.toLowerCase().replace(/\.$/, ''), asset);
    }
    return assets;
  }, [state.assets]);
  const { data: screenshots = [] } = useQuery<ScreenshotEvidence[]>({
    queryKey: ['scanScreenshots', scanId],
    queryFn: async () => (await apiClient.get(`/scans/${scanId}/screenshots`)).data,
    enabled: Boolean(scanId),
    refetchInterval: screenshotRunning ? 2_000 : 10_000,
  });
  const { data: assetObservations = [] } = useQuery<AssetObservation[]>({
    queryKey: ['scanAssetObservations', scanId],
    queryFn: async () => (
      await apiClient.get(`/scans/${scanId}/asset-observations`, {
        params: { limit: 12 },
      })
    ).data,
    enabled: Boolean(scanId),
    refetchInterval: activeJobs.length > 0 ? 2_000 : 10_000,
  });
  const { data: assetObservationSummaries = [] } = useQuery<AssetObservationSummary[]>({
    queryKey: ['scanAssetObservationSummary', scanId],
    queryFn: async () => (
      await apiClient.get(`/scans/${scanId}/asset-observation-summary`, {
        params: { limit: 5000 },
      })
    ).data,
    enabled: Boolean(scanId),
    refetchInterval: activeJobs.length > 0 ? 2_000 : 10_000,
  });
  const observationSummaryByAssetId = useMemo(() => {
    const summaries = new Map<string, { count: number; first: string; last: string }>();
    for (const summary of assetObservationSummaries) {
      summaries.set(summary.asset_id, {
        count: summary.observation_count,
        first: summary.first_observed_at,
        last: summary.last_observed_at,
      });
    }
    return summaries;
  }, [assetObservationSummaries]);
  const totalObservationCount = assetObservationSummaries.reduce(
    (total, summary) => total + summary.observation_count,
    0,
  );
  const getSeenSummary = (value: string) => {
    const asset = domainAssetsByValue.get(value.toLowerCase().replace(/\.$/, ''));
    const observations = asset ? observationSummaryByAssetId.get(asset.id) : undefined;
    return {
      first: observations?.first || asset?.created_at,
      last: observations?.last || asset?.last_observed_at,
      count: observations?.count || 0,
    };
  };
  const mainSeenSummary = getSeenSummary(mainDomain);
  const activeEligibleAssets = state.assets.filter(asset =>
    asset.in_scope
    && !asset.wildcard_suspected
    && (
      asset.state === 'RESOLVED'
      || asset.state === 'LIVE'
      || (asset.asset_type === 'SUBDOMAIN' && asset.state === 'CANDIDATE')
    )
    && ['DOMAIN', 'SUBDOMAIN', 'IP_ADDRESS', 'URL'].includes(asset.asset_type)
  );
  const subdomains = useMemo(() => {
    const byValue = new Map<string, {
      representative: FindingRow;
      sources: Set<string>;
      providers: Set<string>;
    }>();
    for (const finding of state.findings.filter(f => f.entity_type === 'SUBDOMAIN')) {
      const canonicalValue = finding.entity_value.toLowerCase().replace(/\.$/, '');
      const existing = byValue.get(canonicalValue);
      const normalizedSources = finding.normalized_data?.discovery_source_modules;
      const sources = Array.isArray(normalizedSources)
        ? normalizedSources.filter((value): value is string => typeof value === 'string')
        : [];
      if (finding.source_module) sources.push(finding.source_module);
      const normalizedProviders = finding.normalized_data?.provider_sources;
      const providers = Array.isArray(normalizedProviders)
        ? normalizedProviders.filter((value): value is string => typeof value === 'string')
        : [];
      if (typeof finding.normalized_data?.discovery_source === 'string') {
        providers.push(finding.normalized_data.discovery_source);
      }

      if (!existing) {
        byValue.set(canonicalValue, {
          representative: finding,
          sources: new Set(sources),
          providers: new Set(providers),
        });
        continue;
      }
      sources.forEach(source => existing.sources.add(source));
      providers.forEach(provider => existing.providers.add(provider));
      if (finding.source_module === 'dns_resolver') {
        existing.representative = finding;
      }
    }
    return Array.from(byValue.entries()).map(([canonicalValue, group]) => {
      const asset = domainAssetsByValue.get(canonicalValue);
      asset?.source_modules.forEach(source => group.sources.add(source));
      const merged: FindingRow = {
        ...group.representative,
        entity_value: canonicalValue,
        normalized_data: {
          ...(group.representative.normalized_data || {}),
          discovery_source_modules: Array.from(group.sources).sort(),
          provider_sources: Array.from(group.providers).sort(),
          wildcard_suspected: asset?.wildcard_suspected ?? false,
        },
      };
      return merged;
    });
  }, [state.findings, domainAssetsByValue]);
  const allIps = state.findings.filter(f => f.entity_type === 'IP_ADDRESS');
  const ports = state.findings.filter(f => f.entity_type === 'PORT_SERVICE');
  const cves = state.findings.filter(f => f.entity_type === 'CVE');
  const hostMeta = state.findings.filter(f => f.entity_type === 'HOST_METADATA');
  const tlsCerts = state.findings.filter(f => f.entity_type === 'TLS_CERT');
  const whoisData = state.findings.filter(f => f.entity_type === 'DOMAIN_METADATA' && f.source_module === 'whois_lookup');
  const rdapDomainData = state.findings.filter(f => f.entity_type === 'DOMAIN_METADATA' && f.source_module === 'rdap_lookup');
  const rdapNetworkData = state.findings.filter(f => f.entity_type === 'HOST_METADATA' && f.source_module === 'rdap_lookup');
  const dnsPosture = state.findings.filter(f => f.entity_type === 'DNS_POSTURE');
  const takeoverAssessments = state.findings.filter(f => f.entity_type === 'TAKEOVER_ASSESSMENT');
  const asnInfo = useMemo(() => {
    const records = state.findings.filter(f => f.entity_type === 'ASN_INFO');
    const ripeAsns = new Set(
      records.filter(f => f.source_module === 'ripestat').map(f => f.entity_value.toUpperCase()),
    );
    const unique = new Map<string, typeof records[number]>();
    for (const record of records) {
      if (record.source_module !== 'ripestat' && ripeAsns.has(record.entity_value.toUpperCase())) {
        continue;
      }
      const nd = record.normalized_data || {};
      const context = record.source_module === 'ripestat'
        ? String(nd.prefix || nd.ip || 'asn')
        : record.source_module;
      unique.set(`${record.entity_value.toUpperCase()}:${context}`, record);
    }
    return Array.from(unique.values());
  }, [state.findings]);
  // Web recon entity types (from deep analysis)
  const technologies = state.findings.filter(f => f.entity_type === 'TECHNOLOGY');
  const httpHeaders = state.findings.filter(f => f.entity_type === 'HTTP_HEADER');
  const historicalUrls = state.findings.filter(f => f.entity_type === 'HISTORICAL_URL');
  const waybackSnapshots = state.findings.filter(f => f.entity_type === 'WAYBACK_SNAPSHOT');
  const activeVulnerabilities = state.findings.filter(f => f.entity_type === 'VULNERABILITY');

  // Unique source modules from findings
  const sourceModules = useMemo(() => {
    const modules = new Set<string>();
    subdomains.forEach(subdomain => {
      const sources = subdomain.normalized_data?.discovery_source_modules;
      if (Array.isArray(sources)) {
        sources.forEach(source => {
          if (typeof source === 'string') modules.add(source);
        });
      } else if (subdomain.source_module) {
        modules.add(subdomain.source_module);
      }
    });
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
      result = result.filter(subdomain => {
        const sources = subdomain.normalized_data?.discovery_source_modules;
        return Array.isArray(sources)
          ? sources.includes(sourceFilter)
          : subdomain.source_module === sourceFilter;
      });
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
    } catch (err: unknown) {
      dispatch({
        type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED',
        payload: { error: err instanceof Error ? err.message : 'Deep analysis failed' },
      });
    }
  };

  const handleEmailDeepAnalysis = async () => {
    if (selectedEmails.size === 0 || !state.scan?.id) return;
    dispatch({ type: 'EMAIL_DEEP_ANALYSIS_STARTED', emails: Array.from(selectedEmails) });
    try {
      await apiClient.post(`/scans/${state.scan.id}/email-deep-analysis`, {
        emails: Array.from(selectedEmails),
      });
    } catch (err: unknown) {
      dispatch({
        type: 'EMAIL_DEEP_ANALYSIS_COMPLETED',
        payload: { error: err instanceof Error ? err.message : 'Email analysis failed' },
      });
    }
  };

  const handleEnrich = async (ip: string, provider: string = 'shodan') => {
    if (!state.scan?.id || effectiveEnrichingIps.has(ip)) return;
    setEnrichingIps(prev => new Set(prev).add(ip));
    try {
      await apiClient.post(`/scans/${state.scan.id}/shodan-enrich`, { ip, provider });
    } catch (err: unknown) {
      console.error('Enrich failed:', err);
    } finally {
      setEnrichingIps(prev => { const n = new Set(prev); n.delete(ip); return n; });
    }
  };

  const handleActiveValidation = async () => {
    if (!state.scan?.id || state.scan.scan_mode !== 'active' || activeValidationRunning) return;
    const confirmed = window.confirm(
      'Run Naabu, Nmap service detection, safe Nuclei templates, TLS posture checks, a bounded GET-only crawl, and non-invasive takeover verification against the scoped assets in this scan? No provider resource will be claimed. Only continue if you are authorized to test these targets.'
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

  const handleIncludeAsset = async (assetId: string) => {
    if (!state.scan?.id || includingAssetIds.has(assetId)) return;
    setIncludingAssetIds(previous => new Set(previous).add(assetId));
    setScopeActionError(null);
    try {
      const { data } = await apiClient.post(`/scans/${state.scan.id}/assets/${assetId}/include`);
      dispatch({
        type: 'ASSETS_UPDATED',
        assets: state.assets.map(asset => asset.id === assetId ? data : asset),
      });
    } catch (err: unknown) {
      if (isAxiosError<{ detail?: string }>(err)) {
        setScopeActionError(err.response?.data?.detail || err.message);
      } else {
        setScopeActionError(err instanceof Error ? err.message : 'Could not include asset');
      }
    } finally {
      setIncludingAssetIds(previous => {
        const next = new Set(previous);
        next.delete(assetId);
        return next;
      });
    }
  };

  const handleScreenshotCapture = async () => {
    if (!state.scan?.id || screenshotRunning || captureEligibleUrls.length === 0) return;
    if (!window.confirm(`Capture rendered evidence for up to ${captureEligibleUrls.length} verified live URL(s)?`)) return;
    setScreenshotError(null);
    try {
      await apiClient.post(`/scans/${state.scan.id}/screenshots/capture`);
    } catch (err: unknown) {
      if (isAxiosError<{ detail?: string }>(err)) {
        setScreenshotError(err.response?.data?.detail || err.message);
      } else {
        setScreenshotError(err instanceof Error ? err.message : 'Screenshot capture failed to start');
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

  const getDnsRecordsForSubdomain = (sub: string) => {
    const dnsFindings = subdomains.filter(f => f.entity_value === sub && f.source_module === 'dns_resolver');
    if (dnsFindings.length === 0) return null;
    return dnsFindings[0].normalized_data?.dns_records || null;
  };

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
              {state.scan?.scan_mode !== 'passive' && (
                <button
                  className="ws-enrich-btn"
                  disabled={screenshotRunning || captureEligibleUrls.length === 0}
                  onClick={handleScreenshotCapture}
                  title="Capture authenticated evidence images for verified in-scope live URLs"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, padding: '4px 8px' }}
                >
                  {screenshotRunning ? <Loader2 size={11} className="spin" /> : <Camera size={11} />}
                  {screenshotRunning ? 'Capturing screenshots' : 'Capture screenshots'}
                </button>
              )}
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
                  title="Run Naabu, Nmap, Nuclei, TLS, scoped crawling, and non-invasive takeover verification"
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
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(0, 1fr))', gap: 8 }}>
            {[
              ['Candidates', candidateAssets.length, 'var(--text-muted)'],
              ['Resolved', resolvedAssets.length, 'var(--severity-info)'],
              ['Live HTTP', liveUrls.length, '#10b981'],
              ['Wildcard', wildcardAssets.length, '#f59e0b'],
              ['Out of scope', excludedAssets.length, '#ef4444'],
              ['Observations', totalObservationCount, 'var(--accent)'],
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
          {assetObservations.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 7, fontSize: 11, color: 'var(--text-strong)', fontWeight: 600 }}>
                <History size={12} /> Latest Asset Observations
              </div>
              <div style={{ display: 'flex', gap: 7, overflowX: 'auto', paddingBottom: 3 }}>
                {assetObservations.slice(0, 12).map(observation => (
                  <div key={observation.id} style={{
                    minWidth: 190, maxWidth: 250, padding: '7px 9px', borderRadius: 6,
                    background: 'var(--bg-primary)', border: '1px solid var(--border)',
                  }}>
                    <div title={observation.canonical_value} style={{
                      fontSize: 10, color: 'var(--text-strong)', fontFamily: 'var(--font-mono)',
                      whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                    }}>
                      {observation.canonical_value}
                    </div>
                    <div style={{ marginTop: 4, display: 'flex', gap: 5, alignItems: 'center', flexWrap: 'wrap' }}>
                      <span className="badge" style={{ fontSize: 8 }}>{observation.event_type}</span>
                      <span style={{ fontSize: 8, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
                        {observation.source_module || 'baseline'}
                      </span>
                    </div>
                    <div style={{ marginTop: 4, fontSize: 8, color: 'var(--text-muted)' }}>
                      {formatObservedAt(observation.observed_at)}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
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
          {screenshotError && (
            <div style={{ marginTop: 8, fontSize: 10, color: '#ef4444' }}>{screenshotError}</div>
          )}
          {screenshots.length > 0 && scanId && (
            <div style={{ marginTop: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 7, fontSize: 11, color: 'var(--text-strong)', fontWeight: 600 }}>
                <Camera size={12} /> Screenshot Evidence ({screenshots.length})
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 9 }}>
                {screenshots.slice(0, 12).map(evidence => (
                  <div key={evidence.id} style={{ overflow: 'hidden', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-primary)' }}>
                    <ScreenshotImage scanId={scanId} evidence={evidence} />
                    <div style={{ padding: '7px 8px' }}>
                      <div title={evidence.page_title || evidence.url} style={{ fontSize: 10, color: 'var(--text-strong)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {evidence.page_title || evidence.url}
                      </div>
                      <div style={{ marginTop: 3, fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {evidence.status_code ? `[${evidence.status_code}] ` : ''}{evidence.url}
                      </div>
                      <div style={{ marginTop: 3, fontSize: 8, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        SHA-256 {evidence.sha256.slice(0, 12)}… · {new Date(evidence.created_at).toLocaleString()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {wildcardAssets.length > 0 && (
            <div style={{ marginTop: 8, fontSize: 10, color: '#f59e0b' }}>
              {wildcardAssets.length} wildcard-matching hostname{wildcardAssets.length === 1 ? '' : 's'} retained as evidence and excluded from service fan-out.
            </div>
          )}
          {excludedAssets.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ marginBottom: 6, fontSize: 10, color: 'var(--text-muted)' }}>
                Excluded assets are kept as evidence. Include only an asset you are authorized to contact.
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {excludedAssets.slice(0, 12).map(asset => (
                  <div key={asset.id} style={{
                    display: 'inline-flex', alignItems: 'center', gap: 6,
                    padding: '4px 7px', borderRadius: 4, fontSize: 10,
                    fontFamily: 'var(--font-mono)', color: '#ef4444',
                    background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
                  }} title={asset.scope_reason}>
                    <span>{asset.canonical_value}</span>
                    <button
                      type="button"
                      className="ws-enrich-btn"
                      disabled={includingAssetIds.has(asset.id) || activeValidationRunning}
                      onClick={() => handleIncludeAsset(asset.id)}
                      style={{ padding: '2px 5px', fontSize: 9 }}
                    >
                      {includingAssetIds.has(asset.id) ? 'Including…' : 'Include'}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
          {scopeActionError && (
            <div style={{ marginTop: 8, fontSize: 10, color: '#ef4444' }}>{scopeActionError}</div>
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

      {/* ── RDAP + legacy Whois Registration Info Card ─────────── */}
      {(rdapDomainData.length > 0 || whoisData.length > 0) && (() => {
        const whois = whoisData[0]?.normalized_data || {};
        const rdap = rdapDomainData[0]?.normalized_data || {};
        const nd = { ...whois, ...rdap };
        return (
          <div style={{
            marginBottom: 16, padding: '8px 14px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: 8, fontSize: 11,
          }}>
            <div className="flex items-center gap-2 mb-2" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-strong)' }}>
              <ShieldCheck size={13} /> Registration Info
              {rdapDomainData.length > 0 && (
                <span style={{ padding: '1px 5px', borderRadius: 4, background: 'var(--accent-dim)', color: 'var(--accent)', fontSize: 9 }}>RDAP</span>
              )}
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
              {nd.dnssec != null && <span>DNSSEC: <strong style={{ color: nd.dnssec ? '#10b981' : 'var(--text-muted)' }}>{nd.dnssec ? 'signed' : 'unsigned'}</strong></span>}
            </div>
            {Array.isArray(nd.status) && nd.status.length > 0 && (
              <div style={{ marginTop: 6, display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {nd.status.slice(0, 8).map(status => (
                  <span key={String(status)} style={{ padding: '1px 5px', borderRadius: 4, background: 'var(--bg-primary)', border: '1px solid var(--border)', fontSize: 9, fontFamily: 'var(--font-mono)' }}>
                    {String(status)}
                  </span>
                ))}
              </div>
            )}
            {rdap.rdap_server != null && (
              <div style={{ marginTop: 6, color: 'var(--text-muted)', fontSize: 9, fontFamily: 'var(--font-mono)' }}>
                Authoritative service: {String(rdap.rdap_server)}
              </div>
            )}
            {whois.raw_whois != null && (
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
                  }}>{String(whois.raw_whois)}</pre>
                )}
              </div>
            )}
          </div>
        );
      })()}

      {/* ── RDAP IP network ownership cards ────────────────────── */}
      {/* Passive recursive-DNS assessment of mail authentication, transport,
          certificate issuance, DNSSEC delegation, and zone delegation. */}
      {dnsPosture.map(record => {
        const nd = record.normalized_data || {};
        const controls = isRecord(nd.controls) ? nd.controls : {};
        const issues = Array.isArray(nd.issues) ? nd.issues.filter(isRecord) : [];
        const controlEntries = [
          ['SPF', controls.spf],
          ['DMARC', controls.dmarc],
          ['DKIM', controls.dkim],
          ['MTA-STS', controls.mta_sts],
          ['TLS-RPT', controls.tls_rpt],
          ['MX', controls.mx],
          ['DNSSEC', controls.dnssec],
          ['CAA', controls.caa],
          ['Delegation', controls.delegation],
        ] as const;
        const statusColor = (status: string) => {
          if (['strict', 'reject', 'observed', 'advertised', 'configured', 'delegated', 'healthy', 'null_mx'].includes(status)) return '#10b981';
          if (['invalid_multiple', 'invalid_policy', 'permissive', 'potentially_broken'].includes(status)) return '#ef4444';
          if (status === 'unknown') return 'var(--text-muted)';
          return '#f59e0b';
        };
        const controlDetail = (name: string, control: Record<string, unknown>) => {
          if (name === 'SPF' && control.all_mechanism) return String(control.all_mechanism);
          if (name === 'DMARC' && control.policy) return `p=${String(control.policy)}`;
          if (name === 'DKIM' && isRecord(control.selectors)) {
            const selectors = Object.keys(control.selectors);
            if (selectors.length > 0) return selectors.join(', ');
            if (Array.isArray(control.wildcard_records) && control.wildcard_records.length > 0) {
              return 'wildcard selector policy observed';
            }
            return 'common selectors checked';
          }
          if (name === 'MX' && typeof control.accepts_mail === 'boolean') {
            return control.accepts_mail ? 'mail accepted' : 'mail not accepted';
          }
          if (name === 'DNSSEC') return 'delegation state; signatures not validated';
          if (name === 'Delegation' && Array.isArray(control.nameservers)) {
            return `${control.nameservers.length} nameserver${control.nameservers.length === 1 ? '' : 's'}`;
          }
          if (Array.isArray(control.records)) return `${control.records.length} record${control.records.length === 1 ? '' : 's'}`;
          return '';
        };
        return (
          <div key={record.id} style={{
            marginBottom: 16, padding: '10px 14px',
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: 8, fontSize: 11,
          }}>
            <div className="flex items-center gap-2 mb-2" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-strong)', flexWrap: 'wrap' }}>
              <Mail size={13} /> DNS &amp; Email Posture
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontWeight: 500 }}>{record.entity_value}</span>
              <span style={{
                marginLeft: 'auto', padding: '2px 7px', borderRadius: 5,
                background: 'var(--accent-dim)', color: 'var(--accent)',
                fontFamily: 'var(--font-mono)', fontSize: 10,
              }}>
                Grade {String(nd.grade || '?')} · {String(nd.score ?? '?')}/100
              </span>
              <span style={{ color: nd.complete === false ? '#f59e0b' : '#10b981', fontSize: 9 }}>
                {nd.complete === false ? 'incomplete DNS responses' : 'complete'}
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(155px, 1fr))', gap: 6 }}>
              {controlEntries.map(([name, value]) => {
                const control = isRecord(value) ? value : {};
                const status = String(control.status || 'unknown');
                const detail = controlDetail(name, control);
                return (
                  <div key={name} style={{ padding: '6px 8px', borderRadius: 6, background: 'var(--bg-primary)', border: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 6 }}>
                      <strong style={{ color: 'var(--text-strong)', fontSize: 10 }}>{name}</strong>
                      <span style={{ color: statusColor(status), fontFamily: 'var(--font-mono)', fontSize: 9 }}>{status.replaceAll('_', ' ')}</span>
                    </div>
                    {detail && <div style={{ marginTop: 3, color: 'var(--text-muted)', fontSize: 9 }}>{detail}</div>}
                  </div>
                );
              })}
            </div>

            {issues.length > 0 && (
              <div style={{ marginTop: 8, display: 'grid', gap: 5 }}>
                {issues.map((issue, index) => (
                  <div key={`${String(issue.id || 'issue')}:${index}`} style={{ padding: '6px 8px', borderRadius: 6, background: 'var(--bg-primary)', border: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', gap: 7, alignItems: 'center', flexWrap: 'wrap' }}>
                      <SeverityBadge severity={String(issue.severity || 'INFO')} />
                      <strong style={{ color: 'var(--text-strong)', fontSize: 10 }}>{String(issue.title || issue.id || 'Posture observation')}</strong>
                    </div>
                    {issue.evidence != null && <div style={{ marginTop: 3, color: 'var(--text-muted)', fontSize: 9 }}>{String(issue.evidence)}</div>}
                    {issue.remediation != null && <div style={{ marginTop: 2, color: 'var(--text)', fontSize: 9 }}>Recommendation: {String(issue.remediation)}</div>}
                  </div>
                ))}
              </div>
            )}

            <div style={{ marginTop: 7, color: 'var(--text-muted)', fontSize: 9 }}>
              Passive recursive-DNS evidence only. DKIM selector discovery is non-exhaustive; MTA-STS policy content and DNSSEC signatures are not actively validated here.
            </div>
          </div>
        );
      })}

      {takeoverAssessments.length > 0 && (
        <div style={{
          marginBottom: 16, padding: '10px 14px',
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: 8, fontSize: 11,
        }}>
          <div className="flex items-center gap-2 mb-2" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-strong)', flexWrap: 'wrap' }}>
            <ShieldCheck size={13} /> Subdomain Takeover Evidence ({takeoverAssessments.length})
            <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 9 }}>
              DNS refresh + optional bounded GET; no claim attempted
            </span>
          </div>
          <div style={{ display: 'grid', gap: 7 }}>
            {takeoverAssessments.map(record => {
              const nd = record.normalized_data || {};
              const cnames = Array.isArray(nd.cnames) ? nd.cnames.map(String) : [];
              const httpEvidence = isRecord(nd.http_evidence) ? nd.http_evidence : null;
              const status = String(nd.status || 'unknown');
              const statusColor = status === 'provider_fingerprint_matched'
                ? '#ef4444'
                : status === 'probable_dangling_provider' ? '#f97316' : '#f59e0b';
              return (
                <div key={record.id} style={{
                  padding: '8px 10px', borderRadius: 6,
                  background: 'var(--bg-primary)', border: '1px solid var(--border)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
                    <SeverityBadge severity={record.severity} />
                    <strong style={{ color: 'var(--text-strong)', fontFamily: 'var(--font-mono)' }}>
                      {record.entity_value}
                    </strong>
                    {nd.provider != null && (
                      <span className="badge" style={{ fontSize: 8 }}>{String(nd.provider)}</span>
                    )}
                    <span style={{ marginLeft: 'auto', color: statusColor, fontFamily: 'var(--font-mono)', fontSize: 9 }}>
                      {status.replaceAll('_', ' ')}
                    </span>
                  </div>
                  {nd.summary != null && (
                    <div style={{ marginTop: 5, color: 'var(--text)', fontSize: 10 }}>{String(nd.summary)}</div>
                  )}
                  {cnames.length > 0 && (
                    <div style={{ marginTop: 4, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 9, wordBreak: 'break-all' }}>
                      CNAME {cnames.join(' → ')} · target {String(nd.cname_target_status || 'unknown')}
                    </div>
                  )}
                  {httpEvidence && (
                    <div style={{ marginTop: 4, color: 'var(--text-muted)', fontSize: 9 }}>
                      HTTP {String(httpEvidence.status_code || '?')}
                      {httpEvidence.matched_marker != null && ` · marker: ${String(httpEvidence.matched_marker)}`}
                      {httpEvidence.response_sha256 != null && ` · SHA-256 ${String(httpEvidence.response_sha256).slice(0, 12)}…`}
                    </div>
                  )}
                  {nd.remediation != null && (
                    <div style={{ marginTop: 5, color: 'var(--text)', fontSize: 9 }}>
                      Recommendation: {String(nd.remediation)}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: 7, color: 'var(--text-muted)', fontSize: 9 }}>
            A provider fingerprint is strong configuration evidence, not proof that the resource is claimable. Confirm ownership and provider rules manually before remediation.
          </div>
        </div>
      )}

      {rdapNetworkData.length > 0 && (
        <div style={{
          marginBottom: 16, padding: '8px 14px',
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: 8, fontSize: 11,
        }}>
          <div className="flex items-center gap-2 mb-2" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-strong)' }}>
            <Server size={13} /> IP Network Registration ({rdapNetworkData.length})
            <span style={{ padding: '1px 5px', borderRadius: 4, background: 'var(--accent-dim)', color: 'var(--accent)', fontSize: 9 }}>RDAP</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 7 }}>
            {rdapNetworkData.slice(0, 25).map(record => {
              const nd = record.normalized_data || {};
              return (
                <div key={record.id} style={{ padding: '7px 9px', borderRadius: 6, background: 'var(--bg-primary)', border: '1px solid var(--border)' }}>
                  <div style={{ color: 'var(--text-strong)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{record.entity_value}</div>
                  <div style={{ marginTop: 3, color: 'var(--text-muted)' }}>
                    {[nd.network_name, nd.organization, nd.country].filter(Boolean).map(String).join(' · ') || 'Registry network record'}
                  </div>
                  {(nd.start_address != null || nd.end_address != null) && (
                    <div style={{ marginTop: 3, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 9 }}>
                      {String(nd.start_address || '?')} – {String(nd.end_address || '?')}
                    </div>
                  )}
                  {nd.handle != null && (
                    <div style={{ marginTop: 3, color: 'var(--text-muted)', fontSize: 9 }}>Handle: {String(nd.handle)}</div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── ASN and BGP routing context ─────────────────────────── */}
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
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 7 }}>
            {asnInfo.slice(0, 25).map(a => {
              const nd = a.normalized_data || {};
              const visibility = nd.visibility_v4 && typeof nd.visibility_v4 === 'object'
                ? nd.visibility_v4 as Record<string, unknown>
                : null;
              const firstSeen = nd.first_seen && typeof nd.first_seen === 'object'
                ? nd.first_seen as Record<string, unknown>
                : null;
              const lastSeen = nd.last_seen && typeof nd.last_seen === 'object'
                ? nd.last_seen as Record<string, unknown>
                : null;
              const counts = nd.prefix_counts && typeof nd.prefix_counts === 'object'
                ? nd.prefix_counts as Record<string, unknown>
                : null;
              const prefixCountParts: string[] = [];
              for (const family of ['v4', 'v6']) {
                const familyCounts = counts?.[family];
                if (familyCounts && typeof familyCounts === 'object') {
                  const values = familyCounts as Record<string, unknown>;
                  prefixCountParts.push(
                    `${String(values.originating || 0)} ${family.toUpperCase()} origin / ${String(values.transiting || 0)} transit`,
                  );
                }
              }
              const contextKey = String(nd.prefix || nd.ip || a.source_module);
              return (
                <div key={`${a.entity_value}:${contextKey}`} style={{
                  padding: '8px 10px', borderRadius: 6,
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                }}>
                  <div className="flex items-center gap-2" style={{ flexWrap: 'wrap' }}>
                    <strong style={{ color: 'var(--text-strong)', fontFamily: 'var(--font-mono)' }}>{a.entity_value}</strong>
                    <span style={{ padding: '1px 5px', borderRadius: 4, background: 'var(--accent-dim)', color: 'var(--accent)', fontSize: 9 }}>
                      {a.source_module === 'ripestat' ? 'RIPEstat' : a.source_module}
                    </span>
                    {nd.announced != null && (
                      <span style={{ color: nd.announced ? '#10b981' : '#ef4444', fontSize: 9 }}>
                        {nd.announced ? 'announced' : 'not announced'}
                      </span>
                    )}
                  </div>
                  {nd.holder != null && (
                    <div style={{ marginTop: 4, color: 'var(--text)' }}>{String(nd.holder)}</div>
                  )}
                  <div style={{ marginTop: 4, display: 'flex', gap: 12, flexWrap: 'wrap', color: 'var(--text-muted)', fontSize: 9 }}>
                    {nd.ip != null && <span>IP: <strong style={{ fontFamily: 'var(--font-mono)' }}>{String(nd.ip)}</strong></span>}
                    {nd.prefix != null && <span>Prefix: <strong style={{ fontFamily: 'var(--font-mono)' }}>{String(nd.prefix)}</strong></span>}
                    {nd.registry != null && <span>Registry: <strong>{String(nd.registry)}</strong></span>}
                    {visibility && (
                      <span>BGP visibility: <strong>{String(visibility.ris_peers_seeing || 0)}/{String(visibility.total_ris_peers || 0)} peers</strong></span>
                    )}
                    {prefixCountParts.length > 0 && (
                      <span>RIS prefixes: <strong>{prefixCountParts.join(' · ')}</strong></span>
                    )}
                  </div>
                  {(firstSeen || lastSeen) && (
                    <div style={{ marginTop: 4, color: 'var(--text-muted)', fontSize: 9 }}>
                      {firstSeen?.time != null && <>First seen: {String(firstSeen.time).split('T')[0]}</>}
                      {firstSeen?.time != null && lastSeen?.time != null && <span> · </span>}
                      {lastSeen?.time != null && <>Last seen: {String(lastSeen.time).split('T')[0]}</>}
                    </div>
                  )}
                  {Array.isArray(nd.route_objects) && nd.route_objects.length > 0 && (
                    <div style={{ marginTop: 4, color: 'var(--text-muted)', fontSize: 9 }}>
                      Route objects: {nd.route_objects.map(String).join(', ')}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Historical archive evidence is collected during the initial scan,
          so it remains visible even when the deep-analysis drawer is closed. */}
      {historicalUrls.length > 0 && (
        <div style={{
          marginBottom: 16, padding: '8px 14px',
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: 8, fontSize: 11,
        }}>
          <div className="flex items-center gap-2 mb-2" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-strong)' }}>
            <History size={13} /> Historical Archive Evidence ({historicalUrls.length})
          </div>
          <div style={{ maxHeight: 260, overflowY: 'auto', display: 'grid', gap: 4 }}>
            {historicalUrls.slice(0, 50).map(record => {
              const nd = record.normalized_data || {};
              const archiveSource = String(
                nd.archive_source || (record.source_module === 'common_crawl' ? 'Common Crawl' : 'Wayback'),
              );
              const evidenceUrl = nd.wayback_url || nd.index_url;
              return (
                <div key={record.id} style={{
                  display: 'flex', gap: 8, alignItems: 'center',
                  padding: '5px 8px', borderRadius: 5,
                  background: 'var(--bg-primary)', border: '1px solid var(--border)',
                  fontSize: 9, fontFamily: 'var(--font-mono)',
                }}>
                  <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>
                    {nd.timestamp ? String(nd.timestamp).slice(0, 8) : '?'}
                  </span>
                  <span className="badge" style={{ fontSize: 8, flexShrink: 0 }}>{archiveSource}</span>
                  <span title={record.entity_value} style={{ color: 'var(--text-strong)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {record.entity_value}
                  </span>
                  {nd.status_code != null && <span style={{ color: '#10b981', flexShrink: 0 }}>{String(nd.status_code)}</span>}
                  {nd.mime_type != null && <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>{String(nd.mime_type)}</span>}
                  {Boolean(evidenceUrl) && (
                    <a href={String(evidenceUrl)} target="_blank" rel="noreferrer" title={`Open ${archiveSource} evidence`} style={{ color: 'var(--accent)', flexShrink: 0 }}>↗</a>
                  )}
                </div>
              );
            })}
          </div>
          {historicalUrls.length > 50 && (
            <div style={{ marginTop: 5, color: 'var(--text-muted)', fontSize: 9 }}>
              Showing 50 of {historicalUrls.length}; export JSON or CSV for the complete set.
            </div>
          )}
        </div>
      )}

      {/*** Web Recon card was removed from the main Infrastructure tab.
           Deep analysis results (technologies, HTTP headers, lookalikes,
           CVEs from technology_cve) are
           exclusively shown in the DeepAnalysisPanel below, scoped to the
           specific domain the analysis was run on. ***/}

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th style={{ width: 30 }}></th>
              <th>Subdomain</th>
              <th style={{ width: 170 }}>Sources</th>
              <th style={{ width: 180 }}>First / Last Seen</th>
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
                sourceModules={[]}
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
                wildcardSuspected={false}
                firstSeen={mainSeenSummary.first}
                lastSeen={mainSeenSummary.last}
                observationCount={mainSeenSummary.count}
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
              const seen = getSeenSummary(sub.entity_value);
              return (
                <SubdomainRow
                  key={sub.id}
                  subdomain={sub.entity_value}
                  sourceModules={Array.isArray(sub.normalized_data?.discovery_source_modules)
                    ? sub.normalized_data.discovery_source_modules.filter(
                      (value): value is string => typeof value === 'string',
                    )
                    : sub.source_module ? [sub.source_module] : []}
                  discoverySource={Array.isArray(sub.normalized_data?.provider_sources)
                    ? sub.normalized_data.provider_sources.filter(
                      (value): value is string => typeof value === 'string',
                    ).join(', ') || undefined
                    : typeof sub.normalized_data?.discovery_source === 'string'
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
                  wildcardSuspected={sub.normalized_data?.wildcard_suspected === true}
                  firstSeen={seen.first}
                  lastSeen={seen.last}
                  observationCount={seen.count}
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
        />
      )}
    </div>
  );
}

function SubdomainRow({ subdomain, sourceModules, discoverySource, ips, ports, cves, dnsRecords, hostMeta, tlsCerts, crtshCerts, expanded, onToggle, onDeepAnalysis, isDeepAnalyzing, hasDeepResults, onEnrich, enrichingIps, isMainDomain, wildcardSuspected, firstSeen, lastSeen, observationCount }: {
  subdomain: string;
  sourceModules: string[];
  discoverySource?: string;
  ips: string[];
  ports: FindingRow[];
  cves: FindingRow[];
  dnsRecords: Record<string, string[]> | null;
  hostMeta: FindingRow[];
  tlsCerts: FindingRow[];
  crtshCerts: FindingRow[];
  expanded: boolean;
  onToggle: () => void;
  onDeepAnalysis: () => void;
  isDeepAnalyzing: boolean;
  hasDeepResults: boolean;
  onEnrich: (ip: string, provider: string) => void;
  enrichingIps: Set<string>;
  isMainDomain?: boolean;
  wildcardSuspected?: boolean;
  firstSeen?: string;
  lastSeen?: string;
  observationCount: number;
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
            {wildcardSuspected && (
              <span style={{
                display: 'inline-block', marginLeft: 6, padding: '0 6px',
                borderRadius: 3, fontSize: 9, fontWeight: 600,
                background: 'rgba(245,158,11,0.14)', color: '#f59e0b',
                border: '1px solid rgba(245,158,11,0.3)',
                verticalAlign: 'middle',
              }}>WILDCARD</span>
            )}
          </div>
          {discoverySource && (
            <div style={{ fontSize: 9, color: 'var(--accent)', marginTop: 1 }}>
              via {discoverySource}
            </div>
          )}
        </td>
        <td style={{ verticalAlign: 'middle' }}>
          {sourceModules.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {sourceModules.slice(0, 3).map(source => (
                <span key={source} style={{
                  display: 'inline-block', padding: '1px 7px', borderRadius: 4,
                  fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 500,
                  background: 'var(--bg-primary)', border: '1px solid var(--border)',
                  color: 'var(--accent)',
                }}>{source}</span>
              ))}
              {sourceModules.length > 3 && (
                <span className="badge" style={{ fontSize: 9 }}>+{sourceModules.length - 3}</span>
              )}
            </div>
          ) : (
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>—</span>
          )}
        </td>
        <td style={{ verticalAlign: 'middle' }}>
          <div style={{ fontSize: 9, lineHeight: 1.45, color: 'var(--text-muted)' }}>
            <div title={formatObservedAt(firstSeen)}>
              First <span style={{ color: 'var(--text-strong)' }}>{formatObservedAt(firstSeen)}</span>
            </div>
            <div title={formatObservedAt(lastSeen)}>
              Last <span style={{ color: 'var(--text-strong)' }}>{formatObservedAt(lastSeen)}</span>
            </div>
            <div style={{ color: 'var(--accent)', marginTop: 1 }}>
              {observationCount} observation{observationCount === 1 ? '' : 's'}
            </div>
          </div>
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
          <td colSpan={8}>
            <div className="ws-infra-detail">

              {/* ── Source Attribution ───────────────────────────────── */}
              {discoverySource && (
                <div className="ws-infra-detail-item" style={{ padding: '4px 0' }}>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                    Discovered via <strong style={{ color: 'var(--accent)' }}>{discoverySource}</strong>
                    {sourceModules.length > 0 && <span> ({sourceModules.join(', ')})</span>}
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
                      const subj: Record<string, string> = isRecord(nd.subject)
                        ? Object.fromEntries(Object.entries(nd.subject).map(([key, value]) => [key, String(value)]))
                        : {};
                      const iss: Record<string, string> = isRecord(nd.issuer)
                        ? Object.fromEntries(Object.entries(nd.issuer).map(([key, value]) => [key, String(value)]))
                        : {};
                      const covered = Array.isArray(nd.subdomains_covered)
                        ? nd.subdomains_covered.map(String)
                        : [];
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
                          <div>Covers: {covered.join(', ').slice(0, 120)}</div>
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
                const asn = isRecord(hm.asn) ? hm.asn : null;

                // Group TLS certs by port
                const tlsByPort: Record<string, Array<Record<string, unknown>>> = {};
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
                          {hm.asn != null && <span>ASN: <strong>{
                            asn
                              ? (asn.number ? `${String(asn.number)}${asn.name ? ` - ${String(asn.name)}` : ''}` : JSON.stringify(asn))
                              : String(hm.asn)
                          }</strong></span>}
                          {hm.isp != null && <span>ISP: <strong>{String(hm.isp)}</strong></span>}
                          {hm.org != null && <span>Org: <strong>{String(hm.org)}</strong></span>}
                          {hm.os != null && <span>OS: <strong>{String(hm.os)}</strong></span>}
                          {hm.city != null && hm.country != null && <span>Location: <strong>{String(hm.city)}{hm.region ? `, ${String(hm.region)}` : ''}, {String(hm.country)}</strong></span>}
                          {hm.city != null && hm.country == null && <span>City: <strong>{String(hm.city)}</strong></span>}
                          {hm.country != null && hm.city == null && <span>Country: <strong>{String(hm.country)}</strong></span>}
                          {Array.isArray(hm.hostnames) && hm.hostnames.length > 0 && (
                            <span>Hostnames: <strong style={{ fontSize: 9 }}>{hm.hostnames.join(', ')}</strong></span>
                          )}
                          {Array.isArray(hm.tags) && hm.tags.length > 0 && (
                            <div style={{ width: '100%', marginTop: 2 }}>
                              <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>Tags: </span>
                              {hm.tags.map(String).map((tag) => (
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
                            if (nd.product) extra.push(String(nd.product));
                            if (nd.version) extra.push(String(nd.version));
                            if (nd.transport) extra.push(String(nd.transport));
                            return (
                              <span key={p.id} className="ws-port-pill" title={extra.length > 0 ? extra.join(' / ') : undefined}>
                                {port}
                                {nd.service_name != null && !nd.product && <span className="text-gray">/{String(nd.service_name)}</span>}
                                {nd.product != null && <span className="text-gray">/{String(nd.product)}</span>}
                                {nd.version != null && <span className="text-gray"> {String(nd.version)}</span>}
                              </span>
                            );
                          })}
                        </div>
                        {/* Banner / info detail for first few ports */}
                        {ipPorts.slice(0, 3).map(p => {
                          const nd = p.normalized_data || {};
                          const banner = String(nd.banner || nd.info || nd.data || '');
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
                            {certs.map((cert, ci: number) => {
                              const subj = isRecord(cert.subject) ? cert.subject : {};
                              const issuer = isRecord(cert.issuer) ? cert.issuer : {};
                              const subjStr = String(subj.CN || subj.commonName || subj.organization || JSON.stringify(subj));
                              const issStr = String(issuer.CN || issuer.commonName || issuer.organization || issuer.O || JSON.stringify(issuer));
                              const expires = cert.expires || cert.expiration || cert.validity_end || '';
                              const fp = cert.fingerprint || cert.fingerprint_sha256 || '';
                              const fpRecord = isRecord(fp) ? fp : null;
                              const fpStr = fpRecord ? String(fpRecord.sha256 || fpRecord.sha1 || JSON.stringify(fpRecord)) : String(fp);
                              const names = Array.isArray(cert.names) ? cert.names.map(String) : [];
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
  common_crawl: 'Common Crawl',
  dns_email_posture: 'DNS & Email Posture',
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

interface DeepAnalysisPanelProps {
  domain: string;
  harvesterMode: 'quick' | 'full' | 'auto';
  emails: FindingRow[];
  allEmails: FindingRow[];
  secrets: FindingRow[];
  repos: FindingRow[];
  lookalikes: FindingRow[];
  technologies: FindingRow[];
  httpHeaders: FindingRow[];
  historicalUrls: FindingRow[];
  waybackSnapshots: FindingRow[];
  selectedEmails: Set<string>;
  emailSearch: string;
  breaches: FindingRow[];
  emailPlatforms: FindingRow[];
  profiles: FindingRow[];
  domainAnalysisRunning: boolean;
  domainAnalysisProgress: DomainDeepAnalysisProgress[];
  emailAnalysisRunning: boolean;
  emailAnalysisProgress: EmailDeepAnalysisProgress[];
  onToggleEmail: (email: string) => void;
  onSelectAll: () => void;
  onDeselectAll: () => void;
  onEmailSearchChange: (value: string) => void;
  onEmailDeepAnalysis: () => void;
  onClose: () => void;
  getBreachCountForEmail: (email: string) => number;
  getPlatformsForEmail: (email: string) => FindingRow[];
  getProfilesForEmail: (email: string) => FindingRow[];
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
}: DeepAnalysisPanelProps) {
  const [sectionExpanded, setSectionExpanded] = useState<Record<string, boolean>>({
    emails: true, secrets: true, lookalikes: true, emailAnalysis: true,
    technologies: false, httpHeaders: false, waybackUrls: false,
  });

  // ── Domain-scoped deep analysis results ────────────────────────────
  // Deep analysis findings from different domains share the same scan's
  // findings pool. We scope each section to the current `domain` to
  // prevent cross-domain leakage (e.g. lookalikes for "utm.tn" showing
  // when the panel is open for "fsegt.utm.tn").
  function filterByDomain(findings: FindingRow[]): FindingRow[] {
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
      } catch {
        // Non-URL entity values are handled by the checks below.
      }
      // URL in normalized_data (e.g. original_url from wayback)
      for (const urlField of ['url', 'original_url']) {
        const val = nd[urlField];
        if (val) {
          try {
            const h = new URL(String(val)).hostname;
            if (h === domain || h.endsWith('.' + domain)) return true;
          } catch {
            // Ignore malformed evidence URLs and continue matching other fields.
          }
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
  const scopedEmailsFiltered = domain ? emails.filter((e) => {
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
            {scopedEmailsFiltered.map((email) => {
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
            const emailBreaches = breaches.filter((b) => {
              const nd = b.normalized_data || {};
              return nd.email === email || String(b.entity_value).startsWith(email);
            });
            const emailPlats = emailPlatforms.filter((p) => {
              const nd = p.normalized_data || {};
              return nd.email === email;
            });
            const emailProfs = profiles.filter((p) => {
              const nd = p.normalized_data || {};
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
                    {emailBreaches.map((b) => (
                      <div key={b.id} style={{
                        padding: '4px 8px', marginBottom: 2, background: 'var(--bg-secondary)',
                        borderRadius: 4, fontSize: 11, fontFamily: 'var(--font-mono)',
                        display: 'flex', justifyContent: 'space-between',
                      }}>
                        <span style={{ color: 'var(--text-strong)' }}>
                          {String(recordArray(b.normalized_data?.breaches)[0]?.name || b.normalized_data?.name || b.entity_value)}
                        </span>
                        <div className="flex gap-2">
                          {b.normalized_data?.risk_score != null && (
                            <span className="badge badge-danger" style={{ fontSize: 9 }}>
                              Risk: {String(b.normalized_data.risk_score)}
                            </span>
                          )}
                          {recordArray(b.normalized_data?.breaches).length > 0 && (
                            <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>
                              {recordArray(b.normalized_data?.breaches).length} breach{recordArray(b.normalized_data?.breaches).length > 1 ? 'es' : ''}
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
                      {emailPlats.map((p) => (
                        <div key={p.id} style={{
                          display: 'inline-flex', alignItems: 'center', gap: 3,
                          padding: '2px 6px', background: 'var(--bg-secondary)', borderRadius: 4,
                          fontSize: 10, fontFamily: 'var(--font-mono)',
                        }}>
                          {String(p.normalized_data?.platform || 'unknown')}
                          {p.normalized_data?.url != null && (
                            <a href={String(p.normalized_data.url)} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', fontSize: 10 }}>↗</a>
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
                      {emailProfs.map((p) => (
                        <div key={p.id} style={{
                          display: 'inline-flex', alignItems: 'center', gap: 3,
                          padding: '2px 6px', background: 'var(--bg-secondary)', borderRadius: 4,
                          fontSize: 10, fontFamily: 'var(--font-mono)',
                        }}>
                          {String(p.normalized_data?.platform || 'profile')}
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
                  {scopedSecrets.map((s) => (
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
                  {scopedRepos.map((r) => (
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
              {lookalikes.map((l) => {
                const d = l.normalized_data || {};
                const ips = Array.isArray(d.resolved_ips) ? d.resolved_ips.map(String) : [];
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
                      {d.permutation_type != null && <span className="badge badge-info">{String(d.permutation_type)}</span>}
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
                const grouped: Record<string, Array<{ category: string; live: number }>> = {};
                scopedTechnologies.forEach((t) => {
                  const nd = t.normalized_data || {};
                  const group = (nd.group as string) || 'Other';
                  if (!grouped[group]) grouped[group] = [];
                  grouped[group].push({
                    category: String(nd.category || ''),
                    live: Number(nd.live || 0),
                  });
                });
                return Object.entries(grouped).map(([group, items]) => (
                  <div key={group} style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      {group}
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {items.map((item, i: number) => (
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
              {scopedHttpHeaders.map((h, i: number) => {
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
          title="Historical URLs (Web Archives)"
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
                  {scopedWaybackSnapshots.map((s, i: number) => {
                    const nd = s.normalized_data || {};
                    return (
                      <div key={i} style={{
                        padding: '6px 10px', borderRadius: 6,
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
              {scopedHistoricalUrls.length > 0 && (
                <div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 4 }}>
                    Historical Pages ({scopedHistoricalUrls.length})
                  </div>
                  <div style={{ maxHeight: 300, overflowY: 'auto' }}>
                    {scopedHistoricalUrls.map((u, i: number) => {
                      const nd = u.normalized_data || {};
                      const archiveSource = String(
                        nd.archive_source || (u.source_module === 'common_crawl' ? 'Common Crawl' : 'Wayback'),
                      );
                      const evidenceUrl = nd.wayback_url || nd.index_url;
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
                          <span className="badge" style={{ fontSize: 8, flexShrink: 0 }}>{archiveSource}</span>
                          <span style={{ color: 'var(--text-strong)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {String(nd.original_url || u.entity_value)}
                          </span>
                          <span style={{ color: '#10b981', flexShrink: 0 }}>{String(nd.status_code || '')}</span>
                          {evidenceUrl != null && (
                            <a href={String(evidenceUrl)} target="_blank" rel="noreferrer" title={`Open ${archiveSource} evidence`} style={{ color: 'var(--accent)', flexShrink: 0 }}>↗</a>
                          )}
                          {nd.content_type != null && (
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
            const cc = getCollectorStatus(domainAnalysisProgress, 'common_crawl');
            if (wb === 'running' || cc === 'running') {
              return <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Loader2 size={10} className="animate-spin" />
                Fetching archived pages from Wayback Machine and Common Crawl...
              </div>;
            }
            if ((wb === 'done' || wb === 'error') && (cc === 'done' || cc === 'error')) {
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
