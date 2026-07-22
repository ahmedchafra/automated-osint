import { X, ExternalLink, Loader2 } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useScanWorkspace } from '../../context/ScanWorkspaceContext';

interface Props {
  email: string | null;
  open: boolean;
  onClose: () => void;
}

export function PivotDrawer({ email, open, onClose }: Props) {
  const { state } = useScanWorkspace();

  if (!open || !email) return null;

  const emailFilter = (f: any) =>
    f.normalized_data?.email === email ||
    f.entity_value === email ||
    f.raw_data?.email === email;

  const allFindings = state.findings;
  const holeheFindings = allFindings.filter(
    (f) => emailFilter(f) && f.source_module === 'holehe'
  );
  const maigretFindings = allFindings.filter(
    (f) => emailFilter(f) && f.source_module === 'maigret'
  );
  const hibpFindings = allFindings.filter(
    (f) =>
      emailFilter(f) &&
      (f.source_module === 'hibp_breach' || f.source_module === 'xposedornot_breach')
  );

  const showEmpty =
    state.pivotStatus === 'done' &&
    holeheFindings.length === 0 &&
    maigretFindings.length === 0 &&
    hibpFindings.length === 0;

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            className="ws-drawer-overlay"
            onClick={onClose}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          />

          {/* Drawer Panel */}
          <motion.div
            className="ws-drawer"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring' as const, damping: 25, stiffness: 200 }}
          >
            {/* Sticky Header */}
            <div className="ws-drawer-header">
              <div>
                <div className="text-xs text-gray uppercase tracking-wider">
                  Pivot Sweep
                </div>
                <div
                  className="font-mono font-medium mt-1"
                  style={{ color: 'var(--text-strong)' }}
                >
                  {email}
                </div>
              </div>
              <button
                className="btn btn-outline"
                onClick={onClose}
                style={{ padding: '6px' }}
              >
                <X size={16} />
              </button>
            </div>

            {/* Loading State */}
            {state.pivotStatus === 'running' && (
              <div className="ws-drawer-loading">
                <Loader2 size={20} className="animate-spin" />
                <span>Running Holehe + Maigret + HIBP...</span>
              </div>
            )}

            {/* Error State */}
            {state.pivotStatus === 'error' && (
              <div className="ws-drawer-error">
                Pivot sweep failed. The backend worker may not be running.
              </div>
            )}

            {/* HIBP Breach Records */}
            {hibpFindings.length > 0 && (
              <div className="ws-drawer-section">
                <div className="ws-drawer-section-title">
                  Breach Records ({hibpFindings.length})
                </div>
                <div className="flex flex-col gap-2">
                  {hibpFindings.map((f) => (
                    <div key={f.id} className="ws-drawer-breach">
                      <div
                        className="font-medium"
                        style={{ color: 'var(--text-strong)', fontSize: 13 }}
                      >
                        {String(f.normalized_data?.name ?? f.normalized_data?.title ?? f.entity_value)}
                      </div>
                      <div className="text-xs text-gray mt-0.5">
                        {f.normalized_data?.breach_date != null &&
                          `Breach: ${String(f.normalized_data.breach_date)}`}
                        {f.normalized_data?.description != null && (
                          <span> — {String(f.normalized_data.description)}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Holehe Platform Registrations */}
            {holeheFindings.length > 0 && (
              <div className="ws-drawer-section">
                <div className="ws-drawer-section-title">
                  Platform Registrations ({holeheFindings.length})
                </div>
                <div className="ws-drawer-platform-grid">
                  {holeheFindings.map((f) => (
                    <div
                      key={f.id}
                      className="ws-drawer-platform"
                      title={f.entity_value}
                    >
                      <span className="ws-drawer-platform-dot" />
                      <span className="text-sm">
                        {String(f.normalized_data?.platform ?? f.entity_value)}
                      </span>
                      {f.normalized_data?.url != null && (
                        <a
                          href={String(f.normalized_data.url)}
                          target="_blank"
                          rel="noreferrer"
                          className="text-accent"
                        >
                          <ExternalLink size={12} />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Maigret Alias Profiles */}
            {maigretFindings.length > 0 && (
              <div className="ws-drawer-section">
                <div className="ws-drawer-section-title">
                  Alias Profiles ({maigretFindings.length})
                </div>
                <div className="ws-drawer-platform-grid">
                  {maigretFindings.map((f) => (
                    <div className="ws-drawer-platform" key={f.id}>
                      <span
                        className="ws-drawer-platform-dot"
                        style={{ background: 'var(--severity-info)' }}
                      />
                      <span className="text-sm">
                        {String(f.normalized_data?.platform ?? f.entity_value)}
                      </span>
                      {f.entity_value.startsWith('http') && (
                        <a
                          href={f.entity_value}
                          target="_blank"
                          rel="noreferrer"
                          className="text-accent"
                        >
                          <ExternalLink size={12} />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Empty State */}
            {showEmpty && (
              <div className="text-gray text-sm text-center py-4">
                No exposures found for this email.
              </div>
            )}
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
