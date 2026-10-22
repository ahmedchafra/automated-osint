import { useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Loader2, CheckCircle2, XCircle, Clock, Activity,
} from 'lucide-react';

/* ─── Types ─────────────────────────────────────────────────────────── */

interface ToolStatus {
  id: string;
  tool: string;
  status: 'running' | 'completed' | 'error' | 'timeout';
  target?: string;
  collected?: number;
  elapsed?: number;
  error?: string;
}

interface PhaseInfo {
  phase: string;
  phase_index: number;
  status: 'started' | 'completed';
}

interface PipelineProgressProps {
  tools: ToolStatus[];
  phases: PhaseInfo[];
  currentPhase: string;
  phaseOrder?: string[];
  findingsCount?: number;
}

/* ─── Tool metadata ─────────────────────────────────────────────────── */

const TOOL_META: Record<string, { label: string; phase: string }> = {
  crtsh: { label: 'crt.sh', phase: 'INFRASTRUCTURE' },
  subfinder: { label: 'subfinder', phase: 'INFRASTRUCTURE' },
  theharvester: { label: 'theHarvester', phase: 'INFRASTRUCTURE' },
  dns_resolver: { label: 'DNS Resolver', phase: 'INFRASTRUCTURE' },
  wildcard_dns: { label: 'Wildcard DNS Check', phase: 'INFRASTRUCTURE' },
  http_probe: { label: 'HTTP Liveness', phase: 'INFRASTRUCTURE' },
  web_surface: { label: 'Web Surface', phase: 'SERVICES' },
  shodan_internetdb: { label: 'Shodan InternetDB', phase: 'INFRASTRUCTURE' },
  shodan_host: { label: 'Shodan Host', phase: 'SERVICES' },
  censys_host: { label: 'Censys Host', phase: 'SERVICES' },
  nvd_cve: { label: 'NVD CVE', phase: 'SERVICES' },
  cisa_kev: { label: 'CISA KEV', phase: 'SERVICES' },
  hunter_domain: { label: 'Hunter.io', phase: 'IDENTITY' },
  xposedornot_breach: { label: 'XposedOrNot', phase: 'IDENTITY' },
  h8mail: { label: 'h8mail', phase: 'IDENTITY' },
  github_secrets: { label: 'GitHub Secrets', phase: 'SEARCH' },
  dnstwist: { label: 'dnstwist', phase: 'SEARCH' },
  serper_search: { label: 'Serper Search', phase: 'SEARCH' },
};

/* ─── Status icon helper ────────────────────────────────────────────── */

function statusIcon(status: string) {
  switch (status) {
    case 'running': return <Loader2 size={11} className="spin" style={{ color: 'var(--accent)' }} />;
    case 'completed': return <CheckCircle2 size={11} style={{ color: '#10b981' }} />;
    case 'error': return <XCircle size={11} style={{ color: '#ef4444' }} />;
    case 'timeout': return <Clock size={11} style={{ color: '#f59e0b' }} />;
    default: return null;
  }
}

/* ─── Component ─────────────────────────────────────────────────────── */

export function PipelineProgress({ tools, phases, currentPhase, phaseOrder, findingsCount }: PipelineProgressProps) {
  const displayPhases = phaseOrder && phaseOrder.length > 0
    ? phaseOrder
    : Array.from(new Set(phases.map(phase => phase.phase).concat(currentPhase || [])));
  const completedPhases = phases.filter(p => p.status === 'completed').length;

  // Pre-compute phase tool counts for display
  const phaseStats = useMemo(() => {
    const stats: Record<string, { total: number; done: number }> = {};
    for (const phase of displayPhases) {
      const phaseTools = tools.filter(t => {
        const meta = TOOL_META[t.tool] || { phase: '?' };
        return meta.phase === phase;
      });
      stats[phase] = {
        total: phaseTools.length,
        done: phaseTools.filter(t => t.status === 'completed').length,
      };
    }
    return stats;
  }, [tools, displayPhases]);

  return (
    <div
      className="pipeline-progress"
      style={{
        marginTop: 16, borderRadius: 'var(--radius-lg)',
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        overflow: 'hidden',
      }}
    >
      {/* Progress header bar */}
      <div
        style={{
          padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8,
          borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600,
          color: 'var(--text-strong)',
        }}
      >
        <Activity size={14} style={{ color: 'var(--accent)' }} />
        <span>Pipeline Progress</span>
        <span
          style={{
            marginLeft: 'auto', fontSize: 11, fontWeight: 500,
            color: 'var(--text-muted)',
          }}
        >
          Phase {Math.min(completedPhases + 1, Math.max(displayPhases.length, 1))}/{Math.max(displayPhases.length, 1)}
        </span>
        {findingsCount !== undefined && (
          <span
            style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 10,
              background: 'rgba(139,92,246,0.10)', border: '1px solid rgba(139,92,246,0.2)',
              color: '#8b5cf6', fontFamily: 'var(--font-mono)', fontWeight: 600,
            }}
          >
            {findingsCount.toLocaleString()} findings
          </span>
        )}
      </div>

      {/* Phase sections */}
      {displayPhases.map((phaseName, phaseIdx) => {
        const phaseInfo = phases.find(p => p.phase === phaseName);
        const isCompleted = phaseInfo?.status === 'completed';
        const isCurrent = currentPhase === phaseName;
        const phaseTools = tools.filter(t => {
          const meta = TOOL_META[t.tool] || { phase: '?' };
          return meta.phase === phaseName;
        });

        // Skip empty phases that aren't reached yet
        if (phaseTools.length === 0 && !isCompleted && !isCurrent) return null;

        return (
          <div
            key={phaseName}
            style={{
              borderBottom: phaseIdx < displayPhases.length - 1 ? '1px solid var(--border)' : 'none',
            }}
          >
            {/* Phase header */}
            <div
              style={{
                padding: '8px 16px', display: 'flex', alignItems: 'center', gap: 8,
                background: isCurrent ? 'rgba(139,92,246,0.04)' : 'transparent',
                fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
                letterSpacing: '0.05em', color: 'var(--text-muted)',
              }}
            >
              {isCompleted ? (
                <CheckCircle2 size={12} style={{ color: '#10b981' }} />
              ) : isCurrent ? (
                <Loader2 size={12} className="spin" style={{ color: 'var(--accent)' }} />
              ) : (
                <Clock size={12} style={{ color: 'var(--text-muted)' }} />
              )}
              <span>{phaseName}</span>
              {phaseStats[phaseName] && (
                <span
                  style={{
                    marginLeft: 'auto', fontSize: 10, fontWeight: 400,
                    textTransform: 'none', letterSpacing: 0,
                    color: 'var(--text-muted)',
                  }}
                >
                  {phaseStats[phaseName].done}/{phaseStats[phaseName].total} tools
                </span>
              )}
            </div>

            {/* Tools in this phase */}
            <AnimatePresence>
              {phaseTools.map(tool => {
                const meta = TOOL_META[tool.tool] || { label: tool.tool, phase: '?' };
                return (
                  <motion.div
                    key={tool.id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, height: 0 }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '6px 16px 6px 32px', fontSize: 12,
                      background: tool.status === 'running' ? 'rgba(139,92,246,0.02)' : 'transparent',
                    }}
                  >
                    {/* Status icon */}
                    <div
                      style={{
                        width: 14, display: 'flex', alignItems: 'center',
                        justifyContent: 'center', flexShrink: 0,
                      }}
                    >
                      {statusIcon(tool.status)}
                    </div>

                    {/* Name */}
                    <span style={{ flex: 1, color: 'var(--text-strong)', fontWeight: 500 }}>
                      {meta.label}
                    </span>

                    {/* Target (if different from main) */}
                    {tool.target && (
                      <span
                        style={{
                          fontSize: 10, color: 'var(--text-muted)',
                          fontFamily: 'var(--font-mono)', maxWidth: 200,
                          overflow: 'hidden', textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap', flexShrink: 1,
                        }}
                      >
                        {tool.target}
                      </span>
                    )}

                    {/* Meta row */}
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
                      {/* Elapsed time (only on completion) */}
                      {tool.elapsed !== undefined && tool.status === 'completed' && (
                        <span
                          style={{
                            fontSize: 10, color: 'var(--text-muted)',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          {tool.elapsed.toFixed(1)}s
                        </span>
                      )}
                      {/* Findings count badge */}
                      {tool.collected !== undefined && tool.collected > 0 && (
                        <span
                          style={{
                            fontSize: 10, padding: '1px 6px', borderRadius: 4,
                            background: 'rgba(16,185,129,0.08)', color: '#10b981',
                            fontFamily: 'var(--font-mono)', fontWeight: 600,
                          }}
                        >
                          {tool.collected.toLocaleString()}
                        </span>
                      )}
                      {/* Error message */}
                      {tool.error && (
                        <span
                          style={{
                            fontSize: 10, color: '#ef4444', maxWidth: 200,
                            overflow: 'hidden', textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {tool.error}
                        </span>
                      )}
                      {/* Running indicator */}
                      {tool.status === 'running' && (
                        <span style={{ fontSize: 10, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                          running...
                        </span>
                      )}
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        );
      })}
    </div>
  );
}
