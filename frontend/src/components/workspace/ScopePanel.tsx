import { useState } from 'react';
import { AlertTriangle, CheckCircle2, Edit3, Loader2, Shield } from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import apiClient from '../../api/client';
import { useScanWorkspace } from '../../context/scan-workspace-state';
import type { ScopeManifest, Scan } from '../../types/api';
import { errorMessage } from '../../utils/errors';

function lines(values: unknown): string {
  return Array.isArray(values) ? values.join('\n') : '';
}

function split(value: string): string[] {
  return [...new Set(value.split(/[\n,]/).map(item => item.trim()).filter(Boolean))];
}

export function ScopePanel({ canEdit }: { canEdit: boolean }) {
  const { state, dispatch } = useScanWorkspace();
  const queryClient = useQueryClient();
  const scan = state.scan;
  const manifest = scan?.scope_manifest ?? {};
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [form, setForm] = useState({
    allowedDomains: '', allowedCidrs: '', excludedDomains: '', excludedCidrs: '',
    excludedPaths: '', allowedPorts: '', allowSubdomains: true, allowResolvedIps: true,
  });

  const beginEditing = () => {
    setForm({
      allowedDomains: lines(manifest.allowed_domains),
      allowedCidrs: lines(manifest.allowed_cidrs),
      excludedDomains: lines(manifest.excluded_domains),
      excludedCidrs: lines(manifest.excluded_cidrs),
      excludedPaths: lines(manifest.excluded_url_paths),
      allowedPorts: Array.isArray(manifest.allowed_ports) ? manifest.allowed_ports.join(', ') : '',
      allowSubdomains: manifest.allow_subdomains !== false,
      allowResolvedIps: manifest.allow_resolved_ips !== false,
    });
    setError(null);
    setEditing(true);
  };

  const summary = [
    ['Allowed domains', (manifest.allowed_domains as unknown[] | undefined)?.length ?? 0],
    ['Allowed CIDRs', (manifest.allowed_cidrs as unknown[] | undefined)?.length ?? 0],
    ['Domain exclusions', (manifest.excluded_domains as unknown[] | undefined)?.length ?? 0],
    ['Path exclusions', (manifest.excluded_url_paths as unknown[] | undefined)?.length ?? 0],
    ['Manual inclusions', (manifest.included_assets as unknown[] | undefined)?.length ?? 0],
  ] as const;

  if (!scan) return null;

  const save = async () => {
    const ports = split(form.allowedPorts).map(value => Number(value));
    if (ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) {
      setError('Allowed ports must be whole numbers between 1 and 65535.');
      return;
    }
    const payload: ScopeManifest = {
      allowed_domains: split(form.allowedDomains),
      allowed_cidrs: split(form.allowedCidrs),
      excluded_domains: split(form.excludedDomains),
      excluded_cidrs: split(form.excludedCidrs),
      excluded_url_paths: split(form.excludedPaths),
      allowed_ports: ports,
      allow_subdomains: form.allowSubdomains,
      allow_resolved_ips: form.allowResolvedIps,
    };
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const { data } = await apiClient.put<Scan>(`/scans/${scan.id}/scope`, payload);
      dispatch({ type: 'SCAN_LOADED', scan: data });
      await queryClient.invalidateQueries({ queryKey: ['scanAssets', scan.id] });
      setEditing(false);
      setSaved(true);
      window.setTimeout(() => setSaved(false), 3000);
    } catch (caught) {
      setError(errorMessage(caught, 'Unable to update the scan scope.'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="workspace-panel scope-panel">
      <div className="workspace-panel-heading">
        <div>
          <span className="workspace-eyebrow">Safety boundary</span>
          <h2>Assessment scope</h2>
        </div>
        <div className="scope-heading-actions">
          {saved && <span className="scope-saved"><CheckCircle2 size={12} /> Updated</span>}
          {canEdit && !editing && (
            <button className="workspace-text-button" onClick={beginEditing}>
              <Edit3 size={12} /> Edit scope
            </button>
          )}
          <Shield size={18} />
        </div>
      </div>

      {!editing ? (
        <>
          <div className="scope-summary-grid">
            {summary.map(([label, value]) => (
              <div key={label}><strong>{value}</strong><span>{label}</span></div>
            ))}
          </div>
          <div className="scope-flags">
            <span className={manifest.allow_subdomains !== false ? 'scope-enabled' : ''}>Subdomains {manifest.allow_subdomains !== false ? 'allowed' : 'blocked'}</span>
            <span className={manifest.allow_resolved_ips !== false ? 'scope-enabled' : ''}>Resolved IPs {manifest.allow_resolved_ips !== false ? 'allowed' : 'blocked'}</span>
            <span>{Array.isArray(manifest.allowed_ports) && manifest.allowed_ports.length ? `${manifest.allowed_ports.length} allowed ports` : 'Default safe ports'}</span>
          </div>
        </>
      ) : (
        <div className="scope-editor">
          <div className="scope-editor-note"><AlertTriangle size={14} /> Saving immediately reclassifies the asset inventory and resets individual manual inclusions. Active validation must be idle.</div>
          <div className="scope-editor-grid">
            <ScopeField label="Allowed domains" value={form.allowedDomains} onChange={value => setForm(current => ({ ...current, allowedDomains: value }))} placeholder="example.com" />
            <ScopeField label="Allowed CIDRs" value={form.allowedCidrs} onChange={value => setForm(current => ({ ...current, allowedCidrs: value }))} placeholder="203.0.113.0/24" />
            <ScopeField label="Excluded domains" value={form.excludedDomains} onChange={value => setForm(current => ({ ...current, excludedDomains: value }))} placeholder="admin.example.com" />
            <ScopeField label="Excluded CIDRs" value={form.excludedCidrs} onChange={value => setForm(current => ({ ...current, excludedCidrs: value }))} placeholder="203.0.113.25/32" />
            <ScopeField label="Excluded URL paths" value={form.excludedPaths} onChange={value => setForm(current => ({ ...current, excludedPaths: value }))} placeholder={'/logout\n/delete/*'} />
            <ScopeField label="Allowed ports" value={form.allowedPorts} onChange={value => setForm(current => ({ ...current, allowedPorts: value }))} placeholder="80, 443, 8080" singleLine />
          </div>
          <div className="scope-checkboxes">
            <label><input type="checkbox" checked={form.allowSubdomains} onChange={event => setForm(current => ({ ...current, allowSubdomains: event.target.checked }))} /> Include subdomains</label>
            <label><input type="checkbox" checked={form.allowResolvedIps} onChange={event => setForm(current => ({ ...current, allowResolvedIps: event.target.checked }))} /> Include resolved public IPs</label>
          </div>
          {error && <div className="scope-error">{error}</div>}
          <div className="scope-editor-actions">
            <button className="btn btn-secondary" onClick={() => setEditing(false)} disabled={saving}>Cancel</button>
            <button className="btn btn-primary" onClick={save} disabled={saving}>
              {saving && <Loader2 size={13} className="spin" />} Save and reclassify
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

function ScopeField({ label, value, onChange, placeholder, singleLine = false }: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  singleLine?: boolean;
}) {
  return (
    <label className="scope-field">
      <span>{label}</span>
      {singleLine
        ? <input value={value} onChange={event => onChange(event.target.value)} placeholder={placeholder} />
        : <textarea value={value} onChange={event => onChange(event.target.value)} placeholder={placeholder} rows={3} />}
    </label>
  );
}
