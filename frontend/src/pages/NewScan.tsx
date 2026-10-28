import { useState, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import apiClient from '../api/client';
import {
  Crosshair,
  Loader2,
  Shield,
  AlertTriangle,
  Zap,
  Globe,
  Server,
  Building2,
  CheckCircle2,
} from 'lucide-react';

type TargetType = 'domain' | 'ip' | 'organization';
type ScanMode = 'passive' | 'validated' | 'active';
type ScopePayload = {
  allowed_domains: string[];
  allowed_cidrs: string[];
  excluded_domains: string[];
  excluded_cidrs: string[];
  excluded_url_paths: string[];
  allowed_ports: number[];
  allow_subdomains: boolean;
  allow_resolved_ips: boolean;
};

const splitScopeValues = (value: string) => value
  .split(/[\n,]+/)
  .map(item => item.trim())
  .filter(Boolean);

const SCAN_MODES: { value: ScanMode; label: string; description: string }[] = [
  {
    value: 'passive',
    label: 'Passive',
    description: 'Third-party datasets only; no direct target validation.',
  },
  {
    value: 'validated',
    label: 'Validated',
    description: 'Adds DNS and low-impact HTTP liveness checks.',
  },
  {
    value: 'active',
    label: 'Active',
    description: 'Authorizes direct checks and future active modules.',
  },
];

const TARGET_TYPES: { value: TargetType; label: string; icon: typeof Globe; placeholder: string }[] = [
  { value: 'domain', label: 'Domain', icon: Globe, placeholder: 'example.com' },
  { value: 'ip', label: 'IP Address', icon: Server, placeholder: '8.8.8.8' },
  { value: 'organization', label: 'Organization', icon: Building2, placeholder: 'Acme Corp' },
];

const PIPELINE_PHASES: Record<TargetType, { label: string; description: string; colorVar: string }[]> = {
  domain: [
    {
      label: 'Phase 1 — Infrastructure',
      description: 'crt.sh · subfinder · Common Crawl · DNS/email posture · RDAP',
      colorVar: 'var(--severity-info)',
    },
    {
      label: 'Phase 2 — On Demand',
      description: 'Shodan Host · Censys · Hunter · dnstwist · GitHub secrets',
      colorVar: 'var(--severity-high)',
    },
  ],
  ip: [
    {
      label: 'Phase 1 — Reverse DNS & Ports',
      description: 'PTR lookup · Shodan InternetDB · RDAP · RIPEstat',
      colorVar: 'var(--severity-info)',
    },
    {
      label: 'Phase 2 — Service Intel',
      description: 'Shodan Host · Censys · NVD CVE',
      colorVar: 'var(--severity-high)',
    },
    {
      label: 'Phase 3 — Domain Convergence',
      description: 'If PTR finds a domain → crt.sh · Common Crawl · DNS/email posture',
      colorVar: 'var(--severity-critical)',
    },
  ],
  organization: [
    {
      label: 'Phase 1 — Domain Discovery',
      description: 'Search engines → find associated domains',
      colorVar: 'var(--severity-info)',
    },
    {
      label: 'Phase 2 — Infrastructure',
      description: 'crt.sh · subfinder · DNS/email posture · Shodan',
      colorVar: 'var(--severity-high)',
    },
    {
      label: 'Phase 3 — Identity & Search',
      description: 'Hunter · breach checks · dnstwist · GitHub secrets',
      colorVar: 'var(--severity-critical)',
    },
  ],
};

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const IP_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Auto-detect target type from user input. */
function detectTargetType(value: string): TargetType | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  if (IP_RE.test(trimmed)) {
    const octets = trimmed.split('.').map(Number);
    if (octets.every(o => o >= 0 && o <= 255)) return 'ip';
    return null; // invalid IP
  }

  if (DOMAIN_RE.test(trimmed)) return 'domain';

  // Anything else is treated as an organization name (must be 2+ chars)
  if (trimmed.length >= 2) return 'organization';
  return null;
}

/** Validate the input value for the given type. Returns an error message or null. */
function validateTarget(value: string, type: TargetType): string | null {
  const trimmed = value.trim();
  if (!trimmed) return 'A target value is required.';

  switch (type) {
    case 'domain':
      if (!DOMAIN_RE.test(trimmed)) return 'Invalid domain — expected format: example.com';
      break;
    case 'ip': {
      const match = trimmed.match(IP_RE);
      if (!match) return 'Invalid IP — expected format: 8.8.8.8';
      const octets = [match[1], match[2], match[3], match[4]].map(Number);
      if (!octets.every(o => o >= 0 && o <= 255)) return 'IP octets must be 0–255';
      break;
    }
    case 'organization':
      if (trimmed.length < 2) return 'Organization name must be at least 2 characters.';
      if (trimmed.length > 200) return 'Organization name is too long (max 200 characters).';
      break;
  }
  return null;
}

const TYPE_DETECT_HELP: Record<TargetType, string> = {
  domain: 'Auto-detected as domain',
  ip: 'Auto-detected as IP address',
  organization: 'Auto-detected as organization name',
};

function ProgressBar({ phaseLabel }: { phaseLabel?: string }) {
  return (
    <div className="ns-progress">
      <div className="ns-progress-bar">
        <div className="ns-progress-indeterminate" />
      </div>
      {phaseLabel && <span className="ns-progress-label">{phaseLabel}</span>}
    </div>
  );
}

export default function NewScan() {
  const navigate = useNavigate();
  const [targetType, setTargetType] = useState<TargetType>('domain');
  const [targetValue, setTargetValue] = useState('');
  const [scanMode, setScanMode] = useState<ScanMode>('validated');
  const [error, setError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);
  const [detectedType, setDetectedType] = useState<TargetType | null>(null);
  const [showScope, setShowScope] = useState(false);
  const [allowedDomains, setAllowedDomains] = useState('');
  const [allowedCidrs, setAllowedCidrs] = useState('');
  const [excludedDomains, setExcludedDomains] = useState('');
  const [excludedCidrs, setExcludedCidrs] = useState('');
  const [excludedPaths, setExcludedPaths] = useState('/logout\n/delete/*');
  const [allowedPorts, setAllowedPorts] = useState('');

  // Auto-detect type whenever value changes, but don't override manual selection
  const handleValueChange = useCallback((value: string) => {
    setTargetValue(value);
    const detected = detectTargetType(value);
    setDetectedType(detected);
  }, []);

  const TypeIcon = TARGET_TYPES.find(t => t.value === targetType)?.icon || Globe;
  const placeholder = TARGET_TYPES.find(t => t.value === targetType)?.placeholder || 'example.com';

  // Validate on blur or touched
  const validationError = useMemo(() => {
    if (!touched && !targetValue.trim()) return null;
    return validateTarget(targetValue, targetType);
  }, [targetValue, targetType, touched]);

  const mutation = useMutation({
    mutationFn: async ({ type, value, mode, scope }: { type: TargetType; value: string; mode: ScanMode; scope?: ScopePayload }) => {
      const endpoint = type === 'domain'
        ? '/scans/initial'
        : type === 'ip'
          ? '/scans/ip'
          : '/scans/organization';

      const payload = type === 'domain'
        ? { target_domain: value, scan_mode: mode, selected_vectors: ['INFRASTRUCTURE'], scope_manifest: scope }
        : { target_value: value, target_type: type, scan_mode: mode, selected_vectors: ['INFRASTRUCTURE'], scope_manifest: scope };

      const { data } = await apiClient.post(endpoint, payload);
      return data;
    },
    onSuccess: (data) => {
      navigate(`/scans/${data.scan.id}`);
    },
    onError: (err: unknown) => {
      const message =
        err instanceof Error
          ? err.message
          : 'Failed to launch scan. Check connectivity and try again.';
      setError(message);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);

    const ve = validateTarget(targetValue, targetType);
    if (ve) return; // inline validation will show the error

    const ports = splitScopeValues(allowedPorts).map(Number);
    if (showScope && ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) {
      setError('Allowed ports must be whole numbers between 1 and 65535.');
      return;
    }
    const scope = showScope ? {
      allowed_domains: splitScopeValues(allowedDomains),
      allowed_cidrs: splitScopeValues(allowedCidrs),
      excluded_domains: splitScopeValues(excludedDomains),
      excluded_cidrs: splitScopeValues(excludedCidrs),
      excluded_url_paths: splitScopeValues(excludedPaths),
      allowed_ports: ports,
      allow_subdomains: true,
      allow_resolved_ips: true,
    } : undefined;
    mutation.mutate({ type: targetType, value: targetValue.trim(), mode: scanMode, scope });
  };

  const isLoading = mutation.isPending;

  return (
    <div className="ns-hero">
      <motion.div
        className="ns-icon-wrap"
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.5, ease: 'easeOut' }}
      >
        <motion.div
          animate={{ scale: [1, 1.08, 1] }}
          transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
        >
          <Crosshair size={40} />
        </motion.div>
      </motion.div>

      <h1 className="ns-title">Launch Reconnaissance Operation</h1>
      <p className="ns-subtitle">
        Initiate a low-impact OSINT sweep across multiple intelligence vectors. Most sources
        are third-party datasets, while DNS and selected HTTP collectors may contact target
        infrastructure. Results stream into the workspace for manual pivot approval.
      </p>

      <form className="ns-form-card" onSubmit={handleSubmit}>
        <div className="ns-type-selector">
          {TARGET_TYPES.map((t) => {
            const Icon = t.icon;
            const isActive = targetType === t.value;
            return (
              <button
                key={t.value}
                type="button"
                className={`ns-type-btn ${isActive ? 'ns-type-btn-active' : ''}`}
                onClick={() => { setTargetType(t.value); setError(null); }}
                disabled={isLoading}
              >
                <Icon size={16} />
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>

        <div className="ns-input-row">
          <label htmlFor="target-value" className="ns-input-label">
            Target {targetType === 'domain' ? 'Domain' : targetType === 'ip' ? 'IP Address' : 'Name'}
          </label>
          <div className="ns-input-icon-wrapper">
            <TypeIcon size={18} className="ns-input-icon" />
            <input
              id="target-value"
              type="text"
              className={`form-input ns-input-with-icon ${validationError && touched ? 'ns-input-error' : ''}`}
              placeholder={placeholder}
              value={targetValue}
              onChange={(e) => handleValueChange(e.target.value)}
              onBlur={() => setTouched(true)}
              disabled={isLoading}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          {/* Auto-detect feedback */}
          {detectedType && detectedType !== targetType && !touched && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, marginTop: 6,
              fontSize: 11, color: 'var(--text-muted)',
            }}>
              <CheckCircle2 size={12} style={{ color: '#10b981' }} />
              <span>{TYPE_DETECT_HELP[detectedType]}: <strong>{detectedType}</strong></span>
              <button
                type="button"
                style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--accent)', fontSize: 11, padding: 0,
                  textDecoration: 'underline', textUnderlineOffset: 2,
                }}
                onClick={() => { setTargetType(detectedType); setDetectedType(null); }}
              >
                Switch
              </button>
            </div>
          )}
          {/* Inline validation */}
          {validationError && touched && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, marginTop: 6,
              fontSize: 11, color: 'var(--severity-critical)',
            }}>
              <AlertTriangle size={12} />
              <span>{validationError}</span>
            </div>
          )}
        </div>

        <div className="ns-input-row">
          <button
            type="button"
            className="ns-type-btn"
            onClick={() => setShowScope(value => !value)}
            disabled={isLoading}
            aria-expanded={showScope}
            style={{ width: '100%', justifyContent: 'space-between' }}
          >
            <span>Advanced target scope</span>
            <span>{showScope ? 'Hide' : 'Configure'}</span>
          </button>
          <div style={{ marginTop: 7, fontSize: 11, color: 'var(--text-muted)' }}>
            The submitted domain or IP is always included. Leave other allow-lists empty to keep the narrow default.
          </div>
          {showScope && (
            <div style={{ marginTop: 10, display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 10 }}>
              {[
                ['Additional allowed domains', allowedDomains, setAllowedDomains, 'trusted.example.com'],
                ['Allowed public CIDRs', allowedCidrs, setAllowedCidrs, '93.184.216.0/24'],
                ['Excluded domains', excludedDomains, setExcludedDomains, 'admin.example.com'],
                ['Excluded CIDRs', excludedCidrs, setExcludedCidrs, '93.184.216.25/32'],
                ['Excluded URL paths', excludedPaths, setExcludedPaths, '/logout\n/delete/*'],
                ['Allowed ports (optional)', allowedPorts, setAllowedPorts, '80, 443, 8443'],
              ].map(([label, value, setter, hint]) => (
                <label key={label as string} style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 10, color: 'var(--text-muted)' }}>
                  <span>{label as string}</span>
                  <textarea
                    className="form-input"
                    rows={2}
                    value={value as string}
                    onChange={event => (setter as React.Dispatch<React.SetStateAction<string>>)(event.target.value)}
                    placeholder={hint as string}
                    disabled={isLoading}
                    style={{ resize: 'vertical', minHeight: 54, fontFamily: 'var(--font-mono)', fontSize: 11 }}
                  />
                </label>
              ))}
              <div style={{ gridColumn: '1 / -1', fontSize: 10, lineHeight: 1.5, color: '#f59e0b' }}>
                Exclusions are safety boundaries, not useless assets. Sensitive admin surfaces can still be retained as evidence and manually included later. Logout and destructive paths stay excluded from automated browsing.
              </div>
            </div>
          )}
        </div>

        <div className="ns-input-row">
          <span className="ns-input-label">Interaction Mode</span>
          <div className="ns-type-selector" role="radiogroup" aria-label="Scan interaction mode">
            {SCAN_MODES.map((mode) => (
              <button
                key={mode.value}
                type="button"
                role="radio"
                aria-checked={scanMode === mode.value}
                className={`ns-type-btn ${scanMode === mode.value ? 'ns-type-btn-active' : ''}`}
                onClick={() => setScanMode(mode.value)}
                disabled={isLoading}
                title={mode.description}
              >
                <span>{mode.label}</span>
              </button>
            ))}
          </div>
          <div style={{ marginTop: 7, fontSize: 11, color: 'var(--text-muted)' }}>
            {SCAN_MODES.find((mode) => mode.value === scanMode)?.description}
          </div>
        </div>

        {error && !validationError && (
          <motion.div
            className="ns-error"
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
          >
            <AlertTriangle size={18} />
            <span>{error}</span>
          </motion.div>
        )}

        {isLoading && <ProgressBar phaseLabel="Dispatching scan agents…" />}

        <motion.button
          type="submit"
          className="ns-launch-btn"
          disabled={isLoading}
          whileHover={isLoading ? undefined : { scale: 1.02 }}
          whileTap={isLoading ? undefined : { scale: 0.97 }}
        >
          {isLoading ? (
            <>
              <Loader2 size={20} className="ns-spinner" />
              <span>Launching…</span>
            </>
          ) : (
            <>
              <Zap size={20} />
              <span>Launch Scan</span>
            </>
          )}
        </motion.button>
      </form>

      <div className="ns-pipeline">
        <h2 className="ns-pipeline-title">Operational Pipeline</h2>
        <div className="ns-pipeline-list">
          {PIPELINE_PHASES[targetType].map((phase, idx) => (
            <motion.div
              key={phase.label}
              className="ns-pipeline-item"
              style={{ borderLeftColor: phase.colorVar }}
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.15 * idx, duration: 0.35 }}
            >
              <span className="ns-pipeline-dot" style={{ background: phase.colorVar }} />
              <div className="ns-pipeline-content">
                <span className="ns-pipeline-label">{phase.label}</span>
                <span className="ns-pipeline-desc">{phase.description}</span>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      <div className="ns-note">
        <Shield size={16} />
        <span>
          Scans prioritize public and low-impact sources. Some DNS, HTTP, and account checks
          contact target-related services, so only scan targets you are authorized to investigate.
        </span>
      </div>
    </div>
  );
}
