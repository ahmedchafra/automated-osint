import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Shield, UserSearch, Mail, Loader2, Search, ChevronDown, ChevronUp,
  ExternalLink, AlertTriangle, Database, Globe, Calendar, KeyRound, Users, Link, Building2, Hash,
  Download,
} from 'lucide-react';
import { useScanWorkspace } from '../../context/ScanWorkspaceContext';
import { DeepAnalysisProgress, type ProgressItem } from './DeepAnalysisProgress';
import apiClient from '../../api/client';

// One finding's normalized_data shape varies by source, so we read fields
// defensively. BREACH findings from XposedOrNot carry `breaches[]` with
// name/breach_date/data_classes and a risk_score. EMAIL_PLATFORM from
// holehe carries platform/url/registered. PROFILE from maigret carries
// platform/url/username/tags.
type NormData = Record<string, any>;

function formatDate(iso: string | undefined | null): string {
  if (!iso) return '—';
  // XposedOrNot dates look like "2020-10-15" or "2020-10-15T00:00:00Z"
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString();
}

export function IdentityTab() {
  const { state, dispatch } = useScanWorkspace();
  const [selectedEmails, setSelectedEmails] = useState<Set<string>>(new Set());
  const [breachCheckRunning, setBreachCheckRunning] = useState(false);
  const [deepDiveEmail, setDeepDiveEmail] = useState<string | null>(null);
  const [deepDiveRunning, setDeepDiveRunning] = useState(false);
  const breachBaselineRef = useRef(0);
  const deepDiveBaselineRef = useRef(0);
  // expandedEmail: which email row is showing breach/platform details below
  const [expandedEmail, setExpandedEmail] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const emails = state.findings.filter(f => f.entity_type === 'EMAIL');
  const breaches = state.findings.filter(f => {
    if (f.entity_type !== 'BREACH') return false;
    // Only count findings that have actual breach details — skip empty stubs
    const list = (f.normalized_data as NormData)?.breaches;
    return Array.isArray(list) && list.length > 0;
  });
  const profiles = state.findings.filter(f => f.entity_type === 'PROFILE');
  const emailPlatforms = state.findings.filter(f => f.entity_type === 'EMAIL_PLATFORM');
  const domainMeta = state.findings.filter(f => f.entity_type === 'DOMAIN_METADATA');

  // All unique email strings: from EMAIL entity_type findings AND from
  // BREACH findings whose normalized_data or entity_value contains an email.
  const allEmails = useMemo(() => {
    const seen = new Set<string>();
    const result: string[] = [];
    for (const f of emails) {
      if (!seen.has(f.entity_value)) {
        seen.add(f.entity_value);
        result.push(f.entity_value);
      }
    }
    for (const b of breaches) {
      const nd = (b.normalized_data || {}) as NormData;
      const email = nd.email || String(b.entity_value).split('::')[0];
      if (email && !seen.has(email)) {
        seen.add(email);
        result.push(email);
      }
    }
    return result;
  }, [emails, breaches]);

  // Merge normalized_data across all EMAIL findings for each unique email.
  // hunter_domain contributes first_name, last_name, position, department,
  // type, seniority, linkedin, twitter, phone_number, sources.
  // theHarvester contributes source_section.
  const emailMeta = useMemo(() => {
    type EmailMeta = {
      firstName?: string; lastName?: string; position?: string; department?: string;
      type?: string; seniority?: string; linkedin?: string; twitter?: string;
      phoneNumber?: string; sourcesCount?: number; sourceModules: string[];
    };
    const map: Record<string, EmailMeta> = {};
    for (const f of emails) {
      const ev = f.entity_value;
      if (!map[ev]) map[ev] = { sourceModules: [] };
      const m = map[ev];
      const nd = (f.normalized_data || {}) as NormData;
      if (f.source_module && !m.sourceModules.includes(f.source_module)) {
        m.sourceModules.push(f.source_module);
      }
      if (nd.first_name && !m.firstName) m.firstName = nd.first_name;
      if (nd.last_name && !m.lastName) m.lastName = nd.last_name;
      if (nd.position && !m.position) m.position = nd.position;
      if (nd.department && !m.department) m.department = nd.department;
      if (nd.seniority && !m.seniority) m.seniority = nd.seniority;
      if (nd.type && !m.type) {
        m.type = String(nd.type) === 'personal' ? '🍎 Personal' : '📧 Generic';
      }
      if (nd.linkedin && !m.linkedin) m.linkedin = nd.linkedin;
      if (nd.twitter && !m.twitter) m.twitter = nd.twitter;
      if (nd.phone_number && !m.phoneNumber) m.phoneNumber = nd.phone_number;
      if (Array.isArray(nd.sources) && !m.sourcesCount) {
        m.sourcesCount = nd.sources.length;
      }
    }
    return map;
  }, [emails]);

  // Group findings by email so the detail panel can show them all at once
  // without re-filtering per-render.
  const breachesByEmail = useMemo(() => {
    const map: Record<string, typeof breaches> = {};
    for (const b of breaches) {
      const nd = (b.normalized_data || {}) as NormData;
      const email = nd.email || String(b.entity_value).split('::')[0];
      if (!email) continue;
      (map[email] ||= []).push(b);
    }
    return map;
  }, [breaches]);

  const platformsByEmail = useMemo(() => {
    const map: Record<string, typeof emailPlatforms> = {};
    for (const p of emailPlatforms) {
      const nd = (p.normalized_data || {}) as NormData;
      const email = nd.email;
      if (!email) continue;
      (map[email] ||= []).push(p);
    }
    return map;
  }, [emailPlatforms]);

  const profilesByUsername = useMemo(() => {
    const map: Record<string, typeof profiles> = {};
    for (const p of profiles) {
      const nd = (p.normalized_data || {}) as NormData;
      const username = nd.username;
      if (!username) continue;
      (map[username] ||= []).push(p);
    }
    return map;
  }, [profiles]);

  const breachCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const [email, list] of Object.entries(breachesByEmail)) {
      let total = 0;
      for (const b of list) {
        const nd = (b.normalized_data || {}) as NormData;
        const breachesArr = nd.breaches;
        if (Array.isArray(breachesArr) && breachesArr.length > 0) {
          total += breachesArr.length;
        } else if (nd.breach_name) {
          total += 1;
        } else {
          total += 1;
        }
      }
      counts[email] = total;
    }
    return counts;
  }, [breachesByEmail]);

  const platformCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const [email, list] of Object.entries(platformsByEmail)) {
      counts[email] = list.length;
    }
    return counts;
  }, [platformsByEmail]);

  const profileCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const [username, list] of Object.entries(profilesByUsername)) {
      counts[username] = list.length;
    }
    return counts;
  }, [profilesByUsername]);

  const toggleEmail = useCallback((email: string) => {
    setSelectedEmails(prev => {
      const next = new Set(prev);
      if (next.has(email)) next.delete(email);
      else next.add(email);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelectedEmails(new Set(allEmails));
  }, [allEmails]);

  const deselectAll = useCallback(() => {
    setSelectedEmails(new Set());
  }, []);

  const downloadEmailExport = useCallback(async (format: 'csv' | 'txt') => {
    if (!state.scan?.id) return;
    setExportError(null);
    try {
      const response = await apiClient.get(`/scans/${state.scan.id}/export/emails?format=${format}`, {
        responseType: 'blob',
      });
      const disposition = String(response.headers['content-disposition'] ?? '');
      const match = disposition.match(/filename=([^;]+)/);
      const filename = match ? match[1].replace(/"/g, '').trim() : `emails.${format}`;
      const contentType = String(response.headers['content-type'] ?? 'application/octet-stream');
      const blob = new Blob([response.data], { type: contentType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err.message || 'Export failed';
      setExportError(detail);
      console.error('Email export failed:', err);
    }
  }, [state.scan?.id]);

  const handleCheckBreaches = useCallback(async () => {
    if (selectedEmails.size === 0 || !state.scan?.id) return;
    breachBaselineRef.current = state.findings.length;
    setBreachCheckRunning(true);
    dispatch({ type: 'BREACH_CHECK_STARTED', emails: Array.from(selectedEmails) });
    try {
      // POST returns 202 Accepted — the Celery task runs in background.
      // Keep breachCheckRunning true until WS event or findings auto-refresh.
      await apiClient.post(`/scans/${state.scan.id}/check-breaches`, {
        emails: Array.from(selectedEmails),
      });
    } catch (err: any) {
      console.error('Breach check failed:', err);
      setBreachCheckRunning(false);
    }
    // DO NOT clear breachCheckRunning here — WS or findings-polling useEffect handles it
  }, [selectedEmails, state.scan?.id, state.findings.length, dispatch]);

  const handleDeepDive = async (email: string) => {
    if (!state.scan?.id) return;
    deepDiveBaselineRef.current = state.findings.length;
    setDeepDiveEmail(email);
    setDeepDiveRunning(true);
    dispatch({ type: 'EMAIL_DEEP_ANALYSIS_STARTED', emails: [email] });
    try {
      await apiClient.post(`/scans/${state.scan.id}/email-deep-analysis`, {
        emails: [email],
      });
    } catch (err: any) {
      console.error('Deep dive failed:', err);
      setDeepDiveEmail(null);
      setDeepDiveRunning(false);
    }
    // DO NOT clear running flags here — the auto-detect useEffect below handles it
  };

  const toggleExpand = (email: string) => {
    setExpandedEmail(prev => (prev === email ? null : email));
  };

  // Auto-detect when breach-check or deep-dive results arrive via 8s polling or WS.
  // The POST returns 202 immediately — the Celery task runs in background.
  // Once findings count grows beyond the baseline, clear the running state.
  useEffect(() => {
    if (breachCheckRunning && state.findings.length > breachBaselineRef.current) {
      setBreachCheckRunning(false);
      dispatch({ type: 'BREACH_CHECK_COMPLETED', payload: {} });
    }
  }, [state.findings.length, breachCheckRunning, dispatch]);

  useEffect(() => {
    if (deepDiveRunning && state.findings.length > deepDiveBaselineRef.current) {
      setDeepDiveEmail(null);
      setDeepDiveRunning(false);
      dispatch({ type: 'EMAIL_DEEP_ANALYSIS_COMPLETED', payload: {} });
    }
  }, [state.findings.length, deepDiveRunning, dispatch]);

  // Safety timeout: force-clear after 3 minutes so the UI never hangs forever
  useEffect(() => {
    if (!breachCheckRunning && !deepDiveRunning) return;
    const timer = setTimeout(() => {
      if (breachCheckRunning) {
        setBreachCheckRunning(false);
        dispatch({ type: 'BREACH_CHECK_COMPLETED', payload: {} });
      }
      if (deepDiveRunning) {
        setDeepDiveEmail(null);
        setDeepDiveRunning(false);
        dispatch({ type: 'EMAIL_DEEP_ANALYSIS_COMPLETED', payload: {} });
      }
    }, 180_000);
    return () => clearTimeout(timer);
  }, [breachCheckRunning, deepDiveRunning, dispatch]);

  // Sync context breach-check state → local state (WS may deliver completion)
  useEffect(() => {
    if (!state.breachCheckRunning && breachCheckRunning) {
      setBreachCheckRunning(false);
    }
  }, [state.breachCheckRunning, breachCheckRunning]);

  // Sync context email deep-analysis state → local state
  useEffect(() => {
    if (!state.emailDeepAnalysisRunning && deepDiveRunning) {
      setDeepDiveEmail(null);
      setDeepDiveRunning(false);
    }
  }, [state.emailDeepAnalysisRunning, deepDiveRunning]);

  if (allEmails.length === 0 && domainMeta.length === 0) {
    return (
      <div className="ws-empty">
        <Shield size={32} style={{ marginBottom: 8, opacity: 0.4 }} />
        <div>No identity data yet.</div>
        <div style={{ fontSize: 11, marginTop: 4 }}>
          Conduct a "Deep Analysis" on a domain in the Infrastructure tab to discover emails.
        </div>
      </div>
    );
  }

  const domainInfo = domainMeta[0];
  const expandedBreaches = expandedEmail ? breachesByEmail[expandedEmail] || [] : [];
  const expandedPlatforms = expandedEmail ? platformsByEmail[expandedEmail] || [] : [];
  const expandedProfiles = expandedEmail
    ? profilesByUsername[expandedEmail.split('@')[0]] || []
    : [];
  // Best risk score for the expanded email (if any breaches present)
  const expandedRisk = expandedBreaches.reduce((max, b) => {
    const r = Number((b.normalized_data as NormData)?.risk_score || 0);
    return r > max ? r : max;
  }, 0);
  // Each unique breach name across all BREACH findings for this email
  const expandedBreachNames = useMemo(() => {
    const names = new Set<string>();
    let totalBreachCount = 0;
    for (const b of expandedBreaches) {
      const nd = (b.normalized_data as NormData) || {};
      // xposedornot format: normalized_data.breaches[] array
      const list: any[] = nd.breaches || [];
      if (list.length > 0) {
        for (const detail of list) {
          const n = detail.name || detail.breach_name;
          if (n) names.add(n);
        }
      } else if (nd.breach_name) {
        // h8mail format: single breach_name string on normalized_data
        names.add(nd.breach_name);
      } else {
        // Fall back to entity_value suffix
        const suffix = String(b.entity_value).split('::')[1];
        if (suffix) names.add(suffix);
        // Track total breach_count from xposedornot for fallback
        totalBreachCount += Math.max(0, Number(nd.breach_count) || 0);
      }
    }
    // If we have a breach count but no names, generate placeholders
    // so the user can see something was found
    if (names.size === 0 && totalBreachCount > 0) {
      for (let i = 1; i <= totalBreachCount; i++) {
        names.add(`Breach #${i}`);
      }
    }
    return Array.from(names);
  }, [expandedBreaches]);

  return (
    <div className="ws-identity">
      {/* Loading banner for running tasks */}
      {(breachCheckRunning || deepDiveRunning || state.emailDeepAnalysisRunning || state.breachCheckRunning) && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          style={{
            marginBottom: 12, padding: '8px 14px',
            background: 'rgba(6,182,212,0.08)',
            border: '1px solid rgba(6,182,212,0.25)',
            borderRadius: 'var(--radius-lg)',
            display: 'flex', flexDirection: 'column', gap: 6,
            fontSize: 12, color: 'var(--accent)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Loader2 size={14} className="animate-spin" />
            <span>
              {(breachCheckRunning || state.breachCheckRunning)
                ? `Checking breaches for ${selectedEmails.size} email${selectedEmails.size > 1 ? 's' : ''}…`
                : deepDiveRunning
                  ? `Deep-diving ${deepDiveEmail}…`
                  : 'Email deep analysis in progress…'}
            </span>
          </div>

          {/* Per-email progress list */}
          {state.breachCheckProgress.length > 0 && (
            <div style={{ paddingLeft: 22, marginTop: 2 }}>
              {state.breachCheckProgress.map(p => {
                const isDone = p.status === 'done';
                return (
                  <div key={p.email} style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    fontSize: 11, fontFamily: 'var(--font-mono)',
                    color: isDone ? '#22c55e' : 'var(--accent)',
                    padding: '1px 0',
                  }}>
                    {isDone ? <span style={{ color: '#22c55e' }}>✓</span> : <Loader2 size={10} className="animate-spin" />}
                    <span>Email {p.index}/{p.total}: {p.email}</span>
                    {isDone && p.found !== undefined && (
                      <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
                        ({p.found} found)
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Per-collector progress (deep dive) */}
          {state.emailDeepAnalysisProgress.length > 0 && (
            <div style={{ marginTop: 6 }}>
              {(() => {
                // Build ProgressItems from the current email's collectors
                const EMAIL_LABEL_MAP: Record<string, string> = {
                  xposedornot_breach: 'XposedOrNot',
                  h8mail: 'h8mail',
                  holehe: 'Holehe',
                  maigret: 'Maigret',
                };
                const currentEmail = [...state.emailDeepAnalysisProgress]
                  .sort((a, b) => b.index - a.index)[0];
                if (!currentEmail) return null;

                const currentItems = state.emailDeepAnalysisProgress.filter(
                  p => p.index === currentEmail.index
                );
                const collectors = ['xposedornot_breach', 'h8mail', 'holehe', 'maigret'];
                const items: ProgressItem[] = collectors.map(name => {
                  const p = currentItems.find(x => x.collector === name);
                  return {
                    id: `email-${currentEmail.index}-${name}`,
                    label: EMAIL_LABEL_MAP[name] || name,
                    status: p ? (p.status === 'done' ? 'done' : p.status === 'error' ? 'error' : 'running') : 'pending',
                    findingsCount: p?.findings_count,
                    error: p?.error,
                    phase: `Email ${currentEmail.index}/${currentEmail.total}`,
                  };
                });

                return (
                  <DeepAnalysisProgress
                    running={deepDiveRunning || state.emailDeepAnalysisRunning}
                    items={items}
                    title={`Deep Dive: ${currentEmail.email}`}
                  />
                );
              })()}
            </div>
          )}
        </motion.div>
      )}

      {/* Domain metadata card */}
      {domainInfo && (
        <div style={{ marginBottom: 16, padding: 12, background: 'var(--glass-bg)', border: '1px solid var(--glass-border)', borderRadius: 'var(--radius-lg)' }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6, color: 'var(--text-strong)' }}>Domain Intelligence</div>
          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
            {Boolean((domainInfo.normalized_data as any)?.organization) && <div>Org: {String((domainInfo.normalized_data as any).organization)}</div>}
            {Boolean((domainInfo.normalized_data as any)?.email_pattern) && <div>Pattern: {String((domainInfo.normalized_data as any).email_pattern)}</div>}
            {(domainInfo.normalized_data as any)?.disposable !== undefined && <div>Disposable: {(domainInfo.normalized_data as any).disposable ? 'Yes' : 'No'}</div>}
            {(domainInfo.normalized_data as any)?.webmail !== undefined && <div>Webmail: {(domainInfo.normalized_data as any).webmail ? 'Yes' : 'No'}</div>}
          </div>
        </div>
      )}

      {/* Summary bar */}
      <div className="ws-identity-summary">
        <div className="ws-identity-stat">
          <Mail size={16} />
          <span>{allEmails.length} emails discovered</span>
        </div>
        <div className="ws-identity-stat">
          <Shield size={16} />
          <span>{breaches.length} breach records</span>
        </div>
        <div className="ws-identity-stat">
          <UserSearch size={16} />
          <span>{profiles.length + emailPlatforms.length} platform profiles</span>
        </div>
      </div>

      {/* Action bar */}
      {allEmails.length > 0 && (
        <div style={{ marginTop: 16, padding: '8px 12px', background: 'var(--bg-secondary)', borderRadius: 8, border: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {selectedEmails.size} of {allEmails.length} selected
          </span>
          <button className="ws-enrich-btn" onClick={selectAll} style={{ fontSize: 11, padding: '3px 8px' }}>
            Select All
          </button>
          <button className="ws-enrich-btn" onClick={deselectAll} style={{ fontSize: 11, padding: '3px 8px' }}>
            Deselect All
          </button>
          <div style={{ flex: 1 }} />
          <button
            className="ws-enrich-btn-primary"
            onClick={handleCheckBreaches}
            disabled={selectedEmails.size === 0 || breachCheckRunning}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 4,
              padding: '4px 12px', borderRadius: 6, fontSize: 11,
              fontWeight: 500, border: 'none',
              cursor: (selectedEmails.size === 0 || breachCheckRunning) ? 'not-allowed' : 'pointer',
              opacity: (selectedEmails.size === 0 || breachCheckRunning) ? 0.5 : 1,
              background: 'var(--accent)', color: '#fff',
            }}
          >
            {breachCheckRunning ? <Loader2 size={11} className="animate-spin" /> : <Shield size={11} />}
            Check Breaches on Selected
          </button>
          {state.scan?.id && (
            <div style={{ display: 'flex', gap: 4 }}>
              <button
                className="ws-enrich-btn"
                onClick={() => downloadEmailExport('csv')}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 3, padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 500, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', cursor: 'pointer' }}
                title="Export emails as CSV"
              >
                <Download size={10} /> CSV
              </button>
              <button
                className="ws-enrich-btn"
                onClick={() => downloadEmailExport('txt')}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 3, padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 500, border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text)', cursor: 'pointer' }}
                title="Export emails as plain text"
              >
                <Download size={10} /> TXT
              </button>
            </div>
          )}
        </div>
      )}

      {exportError && (
        <div style={{
          marginTop: 8, padding: '6px 10px', borderRadius: 6, fontSize: 11,
          background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)',
          color: '#fca5a5',
        }}>
          {exportError}
        </div>
      )}

      {/* Email list with checkboxes */}
      <div style={{ marginTop: 12 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-strong)', marginBottom: 8 }}>
          Email Addresses
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 320, overflowY: 'auto' }}>
          {allEmails.map(emailStr => {
            const breachCount = breachCounts[emailStr] || 0;
            const platformCount = platformCounts[emailStr] || 0;
            const username = emailStr.split('@')[0];
            const profileCount = profileCounts[username] || 0;
            const isSelected = selectedEmails.has(emailStr);
            const isDeepDiving = deepDiveEmail === emailStr && deepDiveRunning;
            const isExpanded = expandedEmail === emailStr;
            const hasDetails = breachCount > 0 || platformCount > 0 || profileCount > 0;
            return (
              <div key={emailStr}>
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '6px 10px', borderRadius: 6,
                  fontSize: 12, fontFamily: 'var(--font-mono)',
                  background: isSelected ? 'var(--accent-dim)' : 'var(--bg-primary)',
                  border: `1px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}`,
                  color: 'var(--text-strong)',
                }}>
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggleEmail(emailStr)}
                    style={{ cursor: 'pointer' }}
                  />
                  <Mail size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                  <span style={{ flex: 1 }}>{emailStr}</span>
                  {breachCount > 0 && (
                    <span
                      className="badge badge-danger"
                      style={{ fontSize: 9, cursor: hasDetails ? 'pointer' : 'default' }}
                      onClick={() => hasDetails && toggleExpand(emailStr)}
                      title="Show breach / platform / profile details"
                    >
                      {breachCount} breaches
                    </span>
                  )}
                  {platformCount > 0 && (
                    <span
                      className="badge badge-info"
                      style={{ fontSize: 9, cursor: hasDetails ? 'pointer' : 'default' }}
                      onClick={() => hasDetails && toggleExpand(emailStr)}
                      title="Show breach / platform / profile details"
                    >
                      {platformCount} platforms
                    </span>
                  )}
                  {profileCount > 0 && (
                    <span
                      className="badge"
                      style={{ fontSize: 9, background: 'var(--severity-low)', color: '#fff', cursor: hasDetails ? 'pointer' : 'default' }}
                      onClick={() => hasDetails && toggleExpand(emailStr)}
                      title="Show breach / platform / profile details"
                    >
                      {profileCount} profiles
                    </span>
                  )}
                  <button
                    className="ws-enrich-btn"
                    onClick={() => toggleExpand(emailStr)}
                    disabled={!hasDetails}
                    title={hasDetails ? (isExpanded ? 'Hide details' : 'Show details') : 'No details yet'}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: 2,
                      padding: '2px 6px', borderRadius: 4, fontSize: 10,
                      fontWeight: 500, border: '1px solid var(--border)',
                      cursor: !hasDetails ? 'not-allowed' : 'pointer',
                      opacity: !hasDetails ? 0.4 : 1,
                      background: 'var(--bg-secondary)', color: 'var(--text)',
                    }}
                  >
                    {isExpanded ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                  </button>
                  <button
                    className="ws-enrich-btn"
                    onClick={() => handleDeepDive(emailStr)}
                    disabled={isDeepDiving}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: 3,
                      padding: '2px 8px', borderRadius: 4, fontSize: 10,
                      fontWeight: 500, border: '1px solid var(--border)',
                      cursor: isDeepDiving ? 'not-allowed' : 'pointer',
                      opacity: isDeepDiving ? 0.5 : 1,
                      background: 'var(--bg-secondary)', color: 'var(--text)',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {isDeepDiving ? <Loader2 size={10} className="animate-spin" /> : <Search size={10} />}
                    Deep Dive
                  </button>
                </div>

                {/* Person metadata row (merged from hunter_domain + theHarvester) */}
                {emailMeta[emailStr] && (() => {
                  const meta = emailMeta[emailStr];
                  const name = [meta.firstName, meta.lastName].filter(Boolean).join(' ');
                  const hasPersonInfo = name || meta.position || meta.department || meta.type;
                  if (!hasPersonInfo && meta.sourceModules.length === 0 && meta.sourcesCount === undefined) return null;

                  const infoParts: string[] = [];
                  if (name) infoParts.push(name);
                  if (meta.position) infoParts.push(meta.position);
                  if (meta.department) infoParts.push(meta.department);
                  if (meta.seniority) infoParts.push(meta.seniority);

                  return (
                    <div style={{
                      display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap',
                      padding: '2px 10px 6px 36px',
                      fontSize: 11, color: 'var(--text-muted)',
                    }}>
                      {infoParts.length > 0 && (
                        <span style={{ color: 'var(--text-strong)' }}>
                          {infoParts.join(' · ')}
                        </span>
                      )}
                      {meta.type && (
                        <span style={{
                          padding: '1px 5px', borderRadius: 3, fontSize: 10,
                          background: 'rgba(34,197,94,0.1)', color: '#22c55e',
                          border: '1px solid rgba(34,197,94,0.2)',
                        }}>
                          {meta.type}
                        </span>
                      )}
                      {meta.phoneNumber && (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 2 }}>
                          📞 {meta.phoneNumber}
                        </span>
                      )}
                      {meta.sourcesCount !== undefined && (
                        <span>{meta.sourcesCount} {meta.sourcesCount === 1 ? 'source' : 'sources'}</span>
                      )}
                      {meta.linkedin && (
                        <a href={meta.linkedin} target="_blank" rel="noreferrer"
                           onClick={e => e.stopPropagation()}
                           style={{ color: '#0a66c2', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 2 }}>
                          <ExternalLink size={10} /> LinkedIn
                        </a>
                      )}
                      {meta.twitter && (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 2 }}>
                          🐦 @{meta.twitter}
                        </span>
                      )}
                      {meta.sourceModules.map(mod => {
                        const label = mod === 'hunter_domain' ? 'HUNTER' :
                                     mod === 'theharvester' ? 'theHarvester' :
                                     mod === 'h8mail' ? 'H8MAIL' :
                                     mod.toUpperCase();
                        return (
                          <span key={mod} style={{
                            padding: '1px 5px', borderRadius: 3, fontSize: 9,
                            background: 'var(--bg-secondary)', color: 'var(--text-muted)',
                            border: '1px solid var(--border)',
                          }}>
                            {label}
                          </span>
                        );
                      })}
                    </div>
                  );
                })()}

                {/* Expandable detail panel */}
                <AnimatePresence initial={false}>
                  {isExpanded && (
                    <EmailDetailPanel
                      email={emailStr}
                      breachRecords={expandedBreaches}
                      breachNames={expandedBreachNames}
                      platforms={expandedPlatforms}
                      profiles={expandedProfiles}
                      riskScore={expandedRisk}
                    />
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </div>

      {/* Hint */}
      <div style={{ marginTop: 12, padding: 12, background: 'var(--bg-secondary)', borderRadius: 8, border: '1px solid var(--border)' }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          <strong>Tip:</strong> Click a badge or the <ChevronDown size={10} style={{ display: 'inline', verticalAlign: 'middle' }} /> chevron to
          see details. Select emails above and click "Check Breaches", or "Deep Dive" a single email.
        </div>
        <div style={{ marginTop: 6, display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 10, color: 'var(--text-muted)' }}>
          <span><strong style={{ color: '#ef4444' }}>Breaches</strong> ← XposedOrNot + h8mail</span>
          <span><strong style={{ color: '#22c55e' }}>Platforms</strong> ← holehe (registered accounts via email)</span>
          <span><strong style={{ color: '#3b82f6' }}>Social Profiles</strong> ← maigret (username-based, 1000 sites)</span>
        </div>
      </div>
    </div>
  );
}

// --- Detail panel for one expanded email row -----------------------------

function EmailDetailPanel({
  email,
  breachRecords,
  breachNames,
  platforms,
  profiles,
  riskScore,
}: {
  email: string;
  breachRecords: any[];
  breachNames: string[];
  platforms: any[];
  profiles: any[];
  riskScore: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.18, ease: 'easeOut' }}
      style={{ overflow: 'hidden' }}
    >
      <div
        style={{
          marginTop: 2, marginBottom: 6,
          padding: 10, marginLeft: 24,
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderLeft: '2px solid var(--accent)',
          borderRadius: 6,
          fontSize: 11,
        }}
      >
        <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: 8, fontSize: 10 }}>
          {email}
        </div>

        {/* Breach section */}
        {breachRecords.length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <AlertTriangle size={12} style={{ color: 'var(--severity-high)' }} />
              <strong style={{ fontSize: 11 }}>Breaches ({breachNames.length})</strong>
              {riskScore > 0 && (
                <span
                  className="badge"
                  style={{
                    fontSize: 9,
                    background:
                      riskScore >= 80 ? 'var(--severity-critical, #b91c1c)'
                      : riskScore >= 50 ? 'var(--severity-high)'
                      : riskScore >= 20 ? 'var(--severity-medium)'
                      : 'var(--severity-low)',
                    color: '#fff',
                  }}
                >
                  Risk {riskScore}
                </span>
              )}
            </div>
            {breachNames.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                Breach count present but no per-breach details in payload.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {breachNames.map(name => {
                  // Find matching detail from xposedornot format (breaches[])
                  const isGeneric = name.startsWith('Breach #');
                  const detail = isGeneric ? null : (
                    breachRecords
                      .flatMap(b => ((b.normalized_data as NormData)?.breaches || []) as any[])
                      .find((d: any) => (d.name || d.breach_name) === name)
                    // Fall back to h8mail format (breach_name on normalized_data)
                    || breachRecords
                      .map(b => b.normalized_data as NormData)
                      .find(d => d.breach_name === name)
                    // Fall back to entity_value suffix
                    || breachRecords
                      .find(b => String(b.entity_value).split('::')[1] === name)
                  );
                  return (
                    <div
                      key={name}
                      style={{
                        padding: '8px 10px', borderRadius: 6,
                        background: 'var(--bg-primary)',
                        border: '1px solid var(--border)',
                        borderLeft: '3px solid ' + (
                          detail?.password_risk === 'plaintext' ? '#ef4444'
                          : detail?.password_risk?.includes('hash') ? '#f59e0b'
                          : 'var(--accent)'
                        ),
                        fontSize: 11,
                      }}
                    >
                      {/* Breach name + badge row */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                        <Database size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                        <span style={{ fontWeight: 600, color: 'var(--text-strong)' }}>{name}</span>
                        {detail?.verified && (
                          <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: '#166534', color: '#bbf7d0' }}>verified</span>
                        )}
                        {detail?.password_risk === 'plaintext' && (
                          <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 3, background: '#7f1d1d', color: '#fecaca' }}>PASSWORDS PLAINTEXT</span>
                        )}
                      </div>

                      {/* Description */}
                      {detail?.description && (
                        <div style={{ color: 'var(--text-muted)', fontSize: 10, marginBottom: 6, lineHeight: 1.4 }}>
                          {detail.description}
                        </div>
                      )}

                      {/* Detail chips row */}
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
                        {detail?.breach_date && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--text-muted)', fontSize: 10, padding: '1px 5px', background: 'var(--bg-secondary)', borderRadius: 3 }}>
                            <Calendar size={9} /> {formatDate(detail.breach_date)}
                          </span>
                        )}
                        {detail?.records_count > 0 && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--text-muted)', fontSize: 10, padding: '1px 5px', background: 'var(--bg-secondary)', borderRadius: 3 }}>
                            <Users size={9} /> {detail.records_count.toLocaleString()} records
                          </span>
                        )}
                        {detail?.industry && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--text-muted)', fontSize: 10, padding: '1px 5px', background: 'var(--bg-secondary)', borderRadius: 3 }}>
                            <Building2 size={9} /> {detail.industry}
                          </span>
                        )}
                        {Array.isArray(detail?.data_classes) && detail.data_classes.length > 0 && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--text-muted)', fontSize: 10, padding: '1px 5px', background: 'var(--bg-secondary)', borderRadius: 3 }}>
                            <Hash size={9} /> {detail.data_classes.join(', ')}
                          </span>
                        )}
                        {detail?.password_risk && detail.password_risk !== 'plaintext' && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--text-muted)', fontSize: 10, padding: '1px 5px', background: 'var(--bg-secondary)', borderRadius: 3 }}>
                            <KeyRound size={9} /> {detail.password_risk}
                          </span>
                        )}
                        {detail?.domain && (
                          <a href={`https://${detail.domain}`} target="_blank" rel="noreferrer"
                            style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--accent)', fontSize: 10, textDecoration: 'none', padding: '1px 5px', background: 'var(--bg-secondary)', borderRadius: 3 }}>
                            <Globe size={9} /> {detail.domain} <ExternalLink size={8} />
                          </a>
                        )}
                        {detail?.references && (
                          <a href={detail.references} target="_blank" rel="noreferrer"
                            style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--accent)', fontSize: 10, textDecoration: 'none', padding: '1px 5px', background: 'var(--bg-secondary)', borderRadius: 3 }}>
                            <Link size={9} /> Source <ExternalLink size={8} />
                          </a>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* Platforms section */}
        {platforms.length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <Globe size={12} style={{ color: 'var(--accent)' }} />
              <strong style={{ fontSize: 11 }}>Registered Platforms ({platforms.length})</strong>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {platforms.map(p => {
                const nd = (p.normalized_data || {}) as NormData;
                const platform = nd.platform || '—';
                const url = nd.url;
                const email = nd.email || '';
                const confirmed = nd.registered !== false;
                const titleStr = email ? `${email} → ${platform}` : platform;
                const content = (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                    <UserSearch size={9} style={{ opacity: 0.5 }} />
                    {platform}
                    {url && <ExternalLink size={9} />}
                    {confirmed && <span style={{ fontSize: 8, color: '#4ade80' }}>✓</span>}
                  </span>
                );
                return url ? (
                  <a
                    key={p.id}
                    href={url}
                    target="_blank"
                    rel="noreferrer"
                    title={titleStr}
                    style={{
                      padding: '2px 8px', borderRadius: 4,
                      background: 'var(--bg-primary)', border: '1px solid var(--border)',
                      color: 'var(--accent)', fontSize: 10, textDecoration: 'none',
                    }}
                  >
                    {content}
                  </a>
                ) : (
                  <span
                    key={p.id}
                    title={titleStr}
                    style={{
                      padding: '2px 8px', borderRadius: 4,
                      background: 'var(--bg-primary)', border: '1px solid var(--border)',
                      color: 'var(--text)', fontSize: 10,
                    }}
                  >
                    {content}
                  </span>
                );
              })}
            </div>
          </div>
        )}

        {/* Profiles section */}
        {profiles.length > 0 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <UserSearch size={12} style={{ color: 'var(--severity-low)' }} />
              <strong style={{ fontSize: 11 }}>Social Profiles ({profiles.length})</strong>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {profiles.map(p => {
                const nd = (p.normalized_data || {}) as NormData;
                const platform = nd.platform || '—';
                const url = nd.url;
                return (
                  <a
                    key={p.id}
                    href={url || '#'}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      padding: '2px 8px', borderRadius: 4,
                      background: 'var(--bg-primary)', border: '1px solid var(--border)',
                      color: 'var(--accent)', fontSize: 10, textDecoration: 'none',
                      display: 'inline-flex', alignItems: 'center', gap: 3,
                    }}
                  >
                    {platform} <ExternalLink size={9} />
                  </a>
                );
              })}
            </div>
          </div>
        )}

        {breachRecords.length === 0 && platforms.length === 0 && profiles.length === 0 && (
          <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
            No detailed findings for this email yet. Click "Deep Dive" to populate.
          </div>
        )}
      </div>
    </motion.div>
  );
}
