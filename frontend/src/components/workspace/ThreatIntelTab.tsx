import { useState, useMemo, useEffect } from 'react';
import { MessageCircle, Globe, Loader2, Search } from 'lucide-react';
import { useScanWorkspace } from '../../context/ScanWorkspaceContext';
import apiClient from '../../api/client';

export function ThreatIntelTab() {
  const { state, dispatch } = useScanWorkspace();
  const [selectedDomain, setSelectedDomain] = useState<string>(state.activeEnrichmentDomain || '');
  const [telegramKeyword, setTelegramKeyword] = useState<string>('');
  const [activeAction, setActiveAction] = useState<string | null>(null);

  // Sync with active enrichment domain (org scan target picker)
  useEffect(() => {
    if (state.activeEnrichmentDomain && !selectedDomain) {
      setSelectedDomain(state.activeEnrichmentDomain);
    }
  }, [state.activeEnrichmentDomain, selectedDomain]);

  // Threat Intel is the operations center: actions live here, and only
  // channels / messages / dark-web findings are displayed. Leaked secrets
  // and repos are owned by the Secrets tab — the two tabs used to
  // duplicate them, which was confusing.
  const telegramMsgs = state.findings.filter(f => f.entity_type === 'TELEGRAM_MESSAGE');
  const telegramChannels = state.findings.filter(f => f.entity_type === 'TELEGRAM_CHANNEL');
  const darkwebFindings = state.findings.filter(f =>
    f.entity_type === 'ONION_SITE' || f.entity_type === 'DARKWEB_MENTION'
  );
  const secrets = state.findings.filter(f => f.entity_type === 'LEAKED_SECRET');
  const repos = state.findings.filter(f => f.entity_type === 'GITHUB_REPO');

  const subdomains = useMemo(() =>
    state.findings.filter(f => f.entity_type === 'SUBDOMAIN').map(f => f.entity_value),
    [state.findings]
  );

  // Discovered org domains — include so they appear in the domain selector
  const orgDomains = useMemo(() =>
    state.findings.filter(f => f.entity_type === 'DOMAIN_METADATA').map(f => f.entity_value),
    [state.findings]
  );

  const baseDomain = state.scan?.target_domain || '';
  const domainKeyword = telegramKeyword || baseDomain.split('.')[0];

  const handleRunDnstwist = async () => {
    if (!selectedDomain || !state.scan?.id) return;
    setActiveAction('dnstwist');
    dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_STARTED', domain: selectedDomain });
    try {
      await apiClient.post(`/scans/${state.scan.id}/dnstwist`, { domain: selectedDomain });
    } catch (err: any) {
      console.error('dnstwist failed:', err);
    } finally {
      setActiveAction(null);
      dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED', payload: {} });
    }
  };

  const handleScanSecrets = async () => {
    if (!selectedDomain || !state.scan?.id) return;
    setActiveAction('secrets');
    dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_STARTED', domain: selectedDomain });
    try {
      await apiClient.post(`/scans/${state.scan.id}/domain-deep-analysis`, { domain: selectedDomain });
    } catch (err: any) {
      console.error('Secrets scan failed:', err);
    } finally {
      setActiveAction(null);
      dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED', payload: {} });
    }
  };

  const handleTelegramMonitor = async () => {
    if (!selectedDomain || !state.scan?.id) return;
    setActiveAction('telegram');
    dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_STARTED', domain: selectedDomain });
    try {
      await apiClient.post(`/scans/${state.scan.id}/telegram-monitor`, {
        domain: selectedDomain,
        keyword: domainKeyword,
      });
    } catch (err: any) {
      console.error('Telegram monitor failed:', err);
    } finally {
      setActiveAction(null);
      dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED', payload: {} });
    }
  };

  const handleAhmiaSearch = async () => {
    if (!selectedDomain || !state.scan?.id) return;
    setActiveAction('ahmia');
    dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_STARTED', domain: selectedDomain });
    try {
      await apiClient.post(`/scans/${state.scan.id}/ahmia-search`, { domain: selectedDomain });
    } catch (err: any) {
      // Endpoint may not exist yet — fall back gracefully
      console.warn('Ahmia search endpoint not available:', err?.response?.status);
    } finally {
      setActiveAction(null);
      dispatch({ type: 'DOMAIN_DEEP_ANALYSIS_COMPLETED', payload: {} });
    }
  };

  const hasTelegram = telegramMsgs.length > 0 || telegramChannels.length > 0;
  const hasDarkweb = darkwebFindings.length > 0;
  // Secrets/repos live in the Secrets tab — just hint that they're elsewhere
  // so the user knows the action button did something.
  const secretsElsewhere = secrets.length > 0 || repos.length > 0;
  const hasAnyData = hasTelegram || hasDarkweb;

  const domainOptions = [baseDomain, ...subdomains.filter(s => s !== baseDomain), ...orgDomains.filter(d => d !== baseDomain)];

  return (
    <div className="ws-threat-intel">
      {/* Action panel */}
      <div style={{ marginBottom: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <select
            value={selectedDomain}
            onChange={e => setSelectedDomain(e.target.value)}
            style={{
              padding: '6px 10px', borderRadius: 6, fontSize: 12, fontFamily: 'var(--font-mono)',
              background: 'var(--bg-primary)', border: '1px solid var(--border)', color: 'var(--text)', flex: 1,
            }}
          >
            <option value="">Select a domain...</option>
            {domainOptions.map(d => (
              <option key={d} value={d}>{d}{d === baseDomain ? ' (base)' : ''}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            className="ws-enrich-btn"
            disabled={!selectedDomain || activeAction !== null}
            onClick={handleScanSecrets}
            title="Scan GitHub for leaked secrets — results appear in the Secrets tab"
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '5px 12px', borderRadius: 6, fontSize: 11, fontWeight: 500,
              border: '1px solid var(--border)',
              cursor: (!selectedDomain || activeAction !== null) ? 'not-allowed' : 'pointer',
              opacity: (!selectedDomain || activeAction !== null) ? 0.5 : 1,
              background: 'var(--bg-secondary)', color: 'var(--text)',
            }}
          >
            {activeAction === 'secrets' ? <Loader2 size={11} className="animate-spin" /> : <Search size={11} />}
            Scan Secrets
          </button>
          <button
            className="ws-enrich-btn"
            disabled={!selectedDomain || activeAction !== null}
            onClick={handleRunDnstwist}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '5px 12px', borderRadius: 6, fontSize: 11, fontWeight: 500,
              border: '1px solid var(--border)',
              cursor: (!selectedDomain || activeAction !== null) ? 'not-allowed' : 'pointer',
              opacity: (!selectedDomain || activeAction !== null) ? 0.5 : 1,
              background: 'var(--bg-secondary)', color: 'var(--text)',
            }}
          >
            {activeAction === 'dnstwist' ? <Loader2 size={11} className="animate-spin" /> : <Search size={11} />}
            Run dnstwist
          </button>
          <button
            className="ws-enrich-btn"
            disabled={!selectedDomain || activeAction !== null}
            onClick={handleAhmiaSearch}
            title="Search Ahmia.fi for .onion mentions of the domain"
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '5px 12px', borderRadius: 6, fontSize: 11, fontWeight: 500,
              border: '1px solid var(--border)',
              cursor: (!selectedDomain || activeAction !== null) ? 'not-allowed' : 'pointer',
              opacity: (!selectedDomain || activeAction !== null) ? 0.5 : 1,
              background: 'var(--bg-secondary)', color: 'var(--text)',
            }}
          >
            {activeAction === 'ahmia' ? <Loader2 size={11} className="animate-spin" /> : <Globe size={11} />}
            Search Dark Web
          </button>
          <div style={{ flex: 1 }} />
          <input
            type="text"
            placeholder="Telegram keyword (optional)"
            value={telegramKeyword}
            onChange={e => setTelegramKeyword(e.target.value)}
            style={{
              padding: '5px 10px', borderRadius: 6, fontSize: 11, fontFamily: 'var(--font-mono)',
              background: 'var(--bg-primary)', border: '1px solid var(--border)', color: 'var(--text)',
              width: 180,
            }}
          />
          <button
            className="ws-enrich-btn"
            disabled={!selectedDomain || activeAction !== null}
            onClick={handleTelegramMonitor}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '5px 12px', borderRadius: 6, fontSize: 11, fontWeight: 500,
              border: '1px solid var(--border)',
              cursor: (!selectedDomain || activeAction !== null) ? 'not-allowed' : 'pointer',
              opacity: (!selectedDomain || activeAction !== null) ? 0.5 : 1,
              background: 'var(--bg-secondary)', color: 'var(--text)',
            }}
          >
            {activeAction === 'telegram' ? <Loader2 size={11} className="animate-spin" /> : <MessageCircle size={11} />}
            Monitor Telegram
          </button>
        </div>

        {activeAction && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {activeAction === 'secrets' && `Scanning ${selectedDomain} for leaked secrets...`}
            {activeAction === 'dnstwist' && `Generating lookalike permutations for ${selectedDomain}...`}
            {activeAction === 'telegram' && `Searching Telegram for "${domainKeyword}" mentions...`}
            {activeAction === 'ahmia' && `Searching Ahmia.fi for .onion mentions of ${selectedDomain}...`}
          </div>
        )}

        {secretsElsewhere && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>
            {secrets.length} leaked secret{secrets.length === 1 ? '' : 's'} and {repos.length} repo{repos.length === 1 ? '' : 's'} stored in the <strong>Secrets</strong> tab.
          </div>
        )}
      </div>

      {/* Empty state */}
      {!hasAnyData && !activeAction && (
        <div className="ws-empty">
          Select a domain above and run an action to populate this tab.
          <div style={{ fontSize: 11, marginTop: 6, color: 'var(--text-muted)' }}>
            Telegram: brand mentions across public channels. Dark Web: Ahmia.fi .onion search.
          </div>
        </div>
      )}

      {/* Telegram section */}
      {hasTelegram && (
        <div className="ws-ti-section">
          <h3 className="mb-3 flex items-center gap-2">
            <MessageCircle size={18} style={{ color: '#0088cc' }} />
            Telegram Mentions ({telegramMsgs.length})
          </h3>
          <div className="ws-telegram-feed">
            {telegramMsgs.map(m => (
              <div key={m.id} className="ws-telegram-msg">
                <div className="ws-telegram-meta">
                  <span className="font-medium" style={{ color: 'var(--text-strong)', fontSize: 13 }}>
                    {String(m.normalized_data?.channel_name ?? 'Unknown Channel')}
                  </span>
                  <span className="text-xs text-gray">{m.normalized_data?.date ? new Date(String(m.normalized_data.date)).toLocaleDateString() : ''}</span>
                </div>
                <div className="ws-telegram-text">{String(m.normalized_data?.message_text ?? m.entity_value)}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Dark Web section */}
      {hasDarkweb && (
        <div className="ws-ti-section" style={{ marginTop: 24 }}>
          <h3 className="mb-3 flex items-center gap-2">
            <Globe size={18} style={{ color: '#a78bfa' }} />
            Dark Web Ledger
          </h3>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Site / Source</th>
                  <th>Type</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {darkwebFindings.map(f => (
                  <tr key={f.id}>
                    <td className="font-mono" style={{ color: 'var(--text-strong)' }}>
                      {String(f.entity_value)}
                    </td>
                    <td>{String(f.entity_type)}</td>
                    <td>{(f.confidence * 100).toFixed(0)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Dark Web placeholder when nothing found yet */}
      {!hasDarkweb && (
        <div className="ws-ti-section" style={{ marginTop: 24 }}>
          <h3 className="mb-3 flex items-center gap-2">
            <Globe size={18} style={{ color: '#a78bfa' }} />
            Dark Web Ledger
            <span
              className="badge"
              style={{
                fontSize: 9,
                background: 'var(--bg-secondary)',
                color: 'var(--text-muted)',
                border: '1px solid var(--border)',
              }}
            >
              {activeAction === 'ahmia' ? 'SEARCHING' : 'READY'}
            </span>
          </h3>
          <div className="ws-coming-soon">
            <div className="ws-coming-soon-title">Ahmia.fi .onion search</div>
            <div className="ws-coming-soon-desc">
              Click "Search Dark Web" to query Ahmia for .onion sites mentioning this domain.
              Ahmia's HTTP API is reachable without Tor; only deep scraping requires the proxy.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
