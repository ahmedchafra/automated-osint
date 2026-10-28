import { useMemo, useRef, useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Loader2, CheckCircle2, XCircle, Clock, Activity,
} from 'lucide-react';

/* ─── Types ─────────────────────────────────────────────────────────── */

export interface ProgressItem {
  id: string;
  label: string;
  sublabel?: string;
  status: 'pending' | 'running' | 'done' | 'error';
  findingsCount?: number;
  error?: string;
  /** Optional phase heading — consecutive items with the same phase are grouped */
  phase?: string;
}

interface DeepAnalysisProgressProps {
  /** Whether the overall analysis is still running */
  running: boolean;
  /** Ordered list of progress items (collectors, steps, etc.) */
  items: ProgressItem[];
  /** Total findings so far (shown in header) */
  totalFindings?: number;
  /** Optional title override */
  title?: string;
}

/* ─── Status icon ──────────────────────────────────────────────────── */

function statusIcon(status: string, animate: boolean) {
  switch (status) {
    case 'running':
      return <Loader2 size={11} className={animate ? 'spin' : ''} style={{ color: 'var(--accent)' }} />;
    case 'done':
      return <CheckCircle2 size={11} style={{ color: '#10b981' }} />;
    case 'error':
      return <XCircle size={11} style={{ color: '#ef4444' }} />;
    case 'pending':
    default:
      return <Clock size={11} style={{ color: 'var(--text-muted)', opacity: 0.4 }} />;
  }
}

/* ─── Component ────────────────────────────────────────────────────── */

export function DeepAnalysisProgress({
  running, items, totalFindings, title,
}: DeepAnalysisProgressProps) {
  // ── Live elapsed timer ─────────────────────────────────────────────
  const startRef = useRef<number | null>(null);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!running) return;
    startRef.current = Date.now();
    const resetTimer = setTimeout(() => setElapsed(0), 0);
    const interval = setInterval(() => {
      if (startRef.current !== null) {
        setElapsed(Date.now() - startRef.current);
      }
    }, 1000);
    return () => {
      clearTimeout(resetTimer);
      clearInterval(interval);
    };
  }, [running]);

  // If not running but we have items, freeze the final elapsed time
  const displayElapsed = running ? elapsed : (
    items.length > 0 && items.some(i => i.status === 'done' || i.status === 'error')
      ? Math.round(elapsed / 1000) * 1000 // approximate
      : elapsed
  );

  // ── Compute overall stats ──────────────────────────────────────────
  const stats = useMemo(() => {
    const total = items.length;
    const done = items.filter(i => i.status === 'done' || i.status === 'error').length;
    const runningCount = items.filter(i => i.status === 'running').length;
    return { total, done, running: runningCount };
  }, [items]);

  // ── Group items by phase ───────────────────────────────────────────
  const groups = useMemo(() => {
    const g: { phase: string; items: ProgressItem[] }[] = [];
    for (const item of items) {
      const phase = item.phase || 'Collectors';
      const last = g[g.length - 1];
      if (last && last.phase === phase) {
        last.items.push(item);
      } else {
        g.push({ phase, items: [item] });
      }
    }
    return g;
  }, [items]);

  const elapsedStr = useMemo(() => {
    const s = Math.floor(displayElapsed / 1000);
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  }, [displayElapsed]);

  if (items.length === 0 && !running) return null;

  return (
    <div
      style={{
        borderRadius: 'var(--radius-lg)',
        background: 'var(--bg-secondary)',
        border: running ? '1px solid var(--accent)' : '1px solid var(--border)',
        overflow: 'hidden', marginBottom: 16,
      }}
    >
      {/* ── Header bar ─────────────────────────────────────────────── */}
      <div
        style={{
          padding: '8px 14px', display: 'flex', alignItems: 'center', gap: 8,
          borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600,
          color: 'var(--text-strong)',
        }}
      >
        <Activity size={14} style={{ color: running ? 'var(--accent)' : '#10b981' }} />
        <span>{title || (running ? 'Analysis in Progress' : 'Analysis Complete')}</span>

        {/* Elapsed */}
        <span style={{
          marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)',
        }}>
          {elapsedStr}
        </span>

        {/* Count badge */}
        {stats.done > 0 && (
          <span
            style={{
              fontSize: 10, padding: '1px 6px', borderRadius: 4,
              color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
            }}
          >
            {stats.done}/{stats.total}
          </span>
        )}

        {/* Findings badge */}
        {totalFindings !== undefined && totalFindings > 0 && (
          <span
            style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 10,
              background: 'rgba(139,92,246,0.10)', border: '1px solid rgba(139,92,246,0.2)',
              color: '#8b5cf6', fontFamily: 'var(--font-mono)', fontWeight: 600,
            }}
          >
            {totalFindings.toLocaleString()} findings
          </span>
        )}
      </div>

      {/* ── Overall progress bar ───────────────────────────────────── */}
      {stats.total > 0 && (
        <div style={{ height: 3, background: 'var(--border)', position: 'relative' }}>
          <motion.div
            style={{
              height: '100%', background: 'var(--accent)',
              borderRadius: '0 2px 2px 0',
            }}
            initial={{ width: 0 }}
            animate={{
              width: `${running
                ? Math.max(5, (stats.done / stats.total) * 100)
                : 100}%`,
            }}
            transition={{ duration: 0.4, ease: 'easeOut' }}
          />
        </div>
      )}

      {/* ── Phase groups ───────────────────────────────────────────── */}
      {groups.map((group) => (
        <div key={group.phase}>
          {/* Phase header */}
          {groups.length > 1 && (
            <div
              style={{
                padding: '6px 14px 2px', fontSize: 10, fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.05em',
                color: 'var(--text-muted)', opacity: 0.7,
              }}
            >
              {group.phase}
            </div>
          )}

          <AnimatePresence>
            {group.items.map((item) => (
              <motion.div
                key={item.id}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, height: 0 }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '5px 14px', fontSize: 12,
                  background: item.status === 'running'
                    ? 'rgba(139,92,246,0.03)' : 'transparent',
                }}
              >
                {/* Status icon */}
                <div style={{
                  width: 14, display: 'flex', alignItems: 'center',
                  justifyContent: 'center', flexShrink: 0,
                }}>
                  {statusIcon(item.status, running)}
                </div>

                {/* Label */}
                <span style={{
                  flex: 1, color: 'var(--text-strong)', fontWeight: 500,
                  display: 'flex', alignItems: 'center', gap: 4,
                }}>
                  {item.label}
                  {item.sublabel && (
                    <span style={{
                      fontSize: 10, color: 'var(--text-muted)',
                      fontFamily: 'var(--font-mono)', fontWeight: 400,
                    }}>
                      {item.sublabel}
                    </span>
                  )}
                </span>

                {/* Meta row */}
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
                  {/* Findings badge */}
                  {item.findingsCount !== undefined && item.findingsCount > 0 && (
                    <span
                      style={{
                        fontSize: 10, padding: '1px 6px', borderRadius: 4,
                        background: 'rgba(16,185,129,0.08)', color: '#10b981',
                        fontFamily: 'var(--font-mono)', fontWeight: 600,
                      }}
                    >
                      {item.findingsCount.toLocaleString()}
                    </span>
                  )}

                  {/* Error */}
                  {item.error && (
                    <span style={{
                      fontSize: 10, color: '#ef4444', maxWidth: 200,
                      overflow: 'hidden', textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}>
                      {item.error}
                    </span>
                  )}

                  {/* Running indicator */}
                  {item.status === 'running' && running && (
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                      running...
                    </span>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      ))}
    </div>
  );
}
