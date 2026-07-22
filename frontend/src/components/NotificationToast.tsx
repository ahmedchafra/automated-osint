import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle2, AlertTriangle, Info, X } from 'lucide-react';
import { useNotification, type NotificationItem } from '../context/NotificationContext';

const ICON_MAP: Record<NotificationItem['type'], typeof CheckCircle2> = {
  success: CheckCircle2,
  error: AlertTriangle,
  info: Info,
};

const COLOR_MAP: Record<NotificationItem['type'], { bg: string; border: string; color: string }> = {
  success: {
    bg: 'rgba(16,185,129,0.10)',
    border: 'rgba(16,185,129,0.25)',
    color: '#10b981',
  },
  error: {
    bg: 'rgba(239,68,68,0.10)',
    border: 'rgba(239,68,68,0.25)',
    color: '#ef4444',
  },
  info: {
    bg: 'rgba(59,130,246,0.10)',
    border: 'rgba(59,130,246,0.25)',
    color: '#3b82f6',
  },
};

export function NotificationToast() {
  const { notifications, dismissNotification } = useNotification();

  return (
    <div
      style={{
        position: 'fixed', bottom: 20, right: 20, zIndex: 9999,
        display: 'flex', flexDirection: 'column', gap: 8,
        maxWidth: 380, width: '100%', pointerEvents: 'none',
      }}
    >
      <AnimatePresence mode="popLayout">
        {notifications.map(n => {
          const Icon = ICON_MAP[n.type];
          const c = COLOR_MAP[n.type];
          return (
            <motion.div
              key={n.id}
              layout
              initial={{ opacity: 0, x: 80, scale: 0.95 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 80, scale: 0.95, transition: { duration: 0.2 } }}
              transition={{ type: 'spring', stiffness: 400, damping: 28 }}
              style={{
                pointerEvents: 'auto',
                padding: '12px 14px', borderRadius: 'var(--radius-lg)',
                background: 'var(--glass-bg)', backdropFilter: 'blur(16px)',
                border: '1px solid var(--glass-border)',
                boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
                display: 'flex', alignItems: 'flex-start', gap: 10,
              }}
            >
              <div style={{
                width: 28, height: 28, borderRadius: '50%',
                background: c.bg, border: `1px solid ${c.border}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0, marginTop: 1,
              }}>
                <Icon size={14} style={{ color: c.color }} />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-strong)', marginBottom: 2 }}>
                  {n.title}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.4, wordBreak: 'break-word' }}>
                  {n.message}
                </div>
              </div>
              <button
                onClick={() => dismissNotification(n.id)}
                style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--text-muted)', padding: 2, lineHeight: 1,
                  flexShrink: 0, marginTop: 2,
                }}
                title="Dismiss"
              >
                <X size={14} />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
