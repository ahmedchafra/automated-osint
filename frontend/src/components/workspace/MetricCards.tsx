import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { Globe, Server, Users, KeyRound } from 'lucide-react';
import type { FindingRow } from '../FindingsTable';

interface Props {
  findings: FindingRow[];
}

interface MetricCardConfig {
  label: string;
  value: number;
  icon: React.ComponentType<{ size?: number }>;
  color: string;
  glowColor: string;
  desc: (count: number) => string;
}

function SparklineBar({ height, color, active }: { height: number; color: string; active: boolean }) {
  return (
    <div
      style={{
        width: 4,
        height: `${height}%`,
        minHeight: 2,
        maxHeight: 100,
        borderRadius: 2,
        background: active ? color : 'var(--surface-3)',
        opacity: active ? 0.8 : 0.3,
        transition: 'all 0.3s ease',
      }}
    />
  );
}

function Sparkline({ count, color }: { count: number; color: string }) {
  const bars = useMemo(() => {
    const activeBars = Math.min(5, Math.max(1, Math.ceil(count / 2)));
    const heights = [35, 55, 45, 70, 60];
    return heights.map((h, i) => ({
      height: h,
      active: i < activeBars,
    }));
  }, [count]);

  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 20, marginTop: 6 }}>
      {bars.map((bar, i) => (
        <SparklineBar key={i} height={bar.height} color={color} active={bar.active} />
      ))}
    </div>
  );
}

export function MetricCards({ findings }: Props) {
  const subdomains = findings.filter(f => f.entity_type === 'SUBDOMAIN').length;
  const ports = findings.filter(f => f.entity_type === 'PORT_SERVICE').length;
  const cves = findings.filter(f => f.entity_type === 'CVE').length;
  const emails = findings.filter(f => f.entity_type === 'EMAIL').length;
  const breaches = findings.filter(f => f.entity_type === 'BREACH').length;
  const secrets = findings.filter(f => f.entity_type === 'LEAKED_SECRET' || f.entity_type === 'GITHUB_REPO').length;

  const cards: MetricCardConfig[] = [
    {
      label: 'Attack Surface',
      value: subdomains,
      icon: Globe,
      color: 'var(--severity-info)',
      glowColor: 'rgba(59, 130, 246, 0.15)',
      desc: (c: number) => `${c} subdomains mapped`,
    },
    {
      label: 'Threat Ledger',
      value: ports + cves,
      icon: Server,
      color: 'var(--severity-critical)',
      glowColor: 'rgba(244, 63, 94, 0.15)',
      desc: (c: number) => `${c} open ports & CVEs`,
    },
    {
      label: 'Identity Exposure',
      value: emails + breaches,
      icon: Users,
      color: 'var(--severity-high)',
      glowColor: 'rgba(245, 158, 11, 0.15)',
      desc: (c: number) => `${c} emails & breaches`,
    },
    {
      label: 'Secret Alarms',
      value: secrets,
      icon: KeyRound,
      color: '#8b5cf6',
      glowColor: 'rgba(139, 92, 246, 0.15)',
      desc: (c: number) => `${c} leaked secrets`,
    },
  ];

  return (
    <div className="ws-metrics">
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <motion.div
            key={card.label}
            className="ws-metric-card"
            style={{
              borderLeft: `3px solid ${card.color}`,
            }}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1, duration: 0.4, ease: 'easeOut' }}
          >
            <div
              className="ws-metric-icon"
              style={{
                background: card.glowColor,
                color: card.color,
              }}
            >
              <Icon size={22} />
            </div>
            <div style={{ flex: 1 }}>
              <div className="ws-metric-label">{card.label}</div>
              <motion.div
                className="ws-metric-value"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: i * 0.1 + 0.2, duration: 0.3 }}
              >
                {card.value}
              </motion.div>
              <div className="ws-metric-desc">{card.desc(card.value)}</div>
              <Sparkline count={card.value} color={card.color} />
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}
