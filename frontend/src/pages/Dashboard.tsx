import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Search,
  Zap,
  Shield,
  Globe,
  Server,
  Building2,
  TrendingUp,
  ArrowUpRight,
  ArrowDownRight,
  Radio,
  Crosshair,
  Layers,
} from 'lucide-react';
import apiClient from '../api/client';
import { Link } from 'react-router-dom';
import { formatDistanceToNow } from 'date-fns';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#f43f5e',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#10b981',
  INFO: '#3b82f6',
};

function Dashboard() {
  const { data: stats, isLoading, error } = useQuery({
    queryKey: ['dashboardStats'],
    queryFn: async () => {
      const response = await apiClient.get('/dashboard/stats');
      return response.data;
    },
    refetchInterval: 5000,
  });

  const { data: queueStats } = useQuery({
    queryKey: ['celeryQueue'],
    queryFn: async () => {
      const response = await apiClient.get('/dashboard/queue');
      return response.data;
    },
    refetchInterval: 5000,
  });

  const getChartData = (data: Record<string, number> | undefined) => {
    if (!data) return [];
    return Object.entries(data).map(([name, value]) => ({
      name,
      value: Number(value),
    }));
  };

  const severityChartData = getChartData(stats?.findings_by_severity);
  const vectorChartData = getChartData(stats?.findings_by_vector);

  const criticalCount =
    (stats?.findings_by_severity?.CRITICAL || 0) +
    (stats?.findings_by_severity?.HIGH || 0);

  const secureCount =
    (stats?.findings_by_severity?.LOW || 0) +
    (stats?.findings_by_severity?.INFO || 0);

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.08 },
    },
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.45, ease: [0.16, 1, 0.3, 1] as const },
    },
  };

  // ── Loading State ──────────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="ws-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          style={{
            width: 40,
            height: 40,
            borderRadius: '50%',
            border: '3px solid var(--surface-4)',
            borderTopColor: 'var(--accent)',
            boxShadow: '0 0 20px var(--accent-glow)',
          }}
        />
      </div>
    );
  }

  // ── Error State ────────────────────────────────────────────────
  if (error) {
    return (
      <div className="ws-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <div className="card card-glow-critical" style={{ textAlign: 'center', maxWidth: 420 }}>
          <AlertTriangle size={32} style={{ color: 'var(--severity-critical)', marginBottom: 'var(--space-3)' }} />
          <h2 style={{ color: 'var(--text-strong)', marginBottom: 'var(--space-2)' }}>
            Connection Lost
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
            Unable to reach the command center endpoint. Retrying automatically...
          </p>
        </div>
      </div>
    );
  }

  // ── Status badge helper ───────────────────────────────────────
  const getStatusBadge = (status: string) => {
    const map: Record<string, string> = {
      COMPLETED: 'badge-success',
      FAILED: 'badge-danger',
      RUNNING: 'badge-accent',
      PENDING: 'badge-warning',
    };
    const pulseClass = status === 'RUNNING' ? 'ws-pulse-online' : '';
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        {status === 'RUNNING' && <span className={pulseClass} style={{ width: 6, height: 6, borderRadius: '50%', display: 'inline-block' }} />}
        <span className={`badge ${map[status] || 'badge-warning'}`}>{status}</span>
      </span>
    );
  };

  // ── Custom tooltip for charts ─────────────────────────────────
  const CustomTooltip = ({ active, payload }: any) => {
    if (!active || !payload?.length) return null;
    return (
      <div style={{
        background: 'var(--glass-bg)',
        border: '1px solid var(--glass-border)',
        borderRadius: 'var(--radius-md)',
        padding: 'var(--space-2) var(--space-3)',
        backdropFilter: 'blur(12px)',
        fontSize: 'var(--text-sm)',
      }}>
        <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>{payload[0].name}</span>
        <span style={{ color: 'var(--text-strong)', fontWeight: 700, marginLeft: 8 }}>{payload[0].value}</span>
      </div>
    );
  };

  return (
    <motion.div
      className="ws-container"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* ── Header ─────────────────────────────────────────────── */}
      <div className="ws-header">
        <div className="ws-header-left">
          <Radio size={20} style={{ color: 'var(--severity-low)', filter: 'drop-shadow(0 0 6px var(--severity-low))' }} />
          <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', color: 'var(--text-strong)' }}>
            Command Center
          </h1>
          <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)', fontFamily: 'var(--font-mono)' }}>
            <span className="ws-pulse-online" style={{ width: 6, height: 6, borderRadius: '50%', display: 'inline-block', marginRight: 6 }} />
            Live
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: 'var(--text-muted)', fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)' }}>
          <Globe size={14} />
          <span>Auto-refresh 5s</span>
        </div>
      </div>

      {/* ── Metric Cards ───────────────────────────────────────── */}
      <div className="ws-metrics">
        {/* Total Scans */}
        <motion.div
          className="ws-metric-card"
          variants={cardVariants}
          style={{ borderLeft: '3px solid var(--accent)' }}
        >
          <div className="ws-metric-icon" style={{ background: 'var(--accent-soft)' }}>
            <Crosshair size={22} style={{ color: 'var(--accent)' }} />
          </div>
          <div>
            <div className="ws-metric-label">Total Scans</div>
            <div className="ws-metric-value" style={{ color: 'var(--accent)' }}>
              {stats?.total_scans || 0}
            </div>
            <div className="ws-metric-desc" style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 2 }}>
              <Activity size={12} />
              Reconnaissance operations
            </div>
          </div>
        </motion.div>

        {/* Total Findings */}
        <motion.div
          className="ws-metric-card"
          variants={cardVariants}
          style={{ borderLeft: '3px solid var(--severity-info)' }}
        >
          <div className="ws-metric-icon" style={{ background: 'rgba(59, 130, 246, 0.10)' }}>
            <Search size={22} style={{ color: 'var(--severity-info)' }} />
          </div>
          <div>
            <div className="ws-metric-label">Total Findings</div>
            <div className="ws-metric-value" style={{ color: 'var(--severity-info)' }}>
              {stats?.total_findings || 0}
            </div>
            <div className="ws-metric-desc" style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 2 }}>
              <TrendingUp size={12} />
              Across all vectors
            </div>
          </div>
        </motion.div>

        {/* Critical / High */}
        <motion.div
          className={`ws-metric-card ${criticalCount > 0 ? 'neon-critical' : ''}`}
          variants={cardVariants}
          style={{ borderLeft: '3px solid var(--severity-critical)' }}
        >
          <div className="ws-metric-icon" style={{ background: 'rgba(244, 63, 94, 0.10)' }}>
            <AlertTriangle size={22} style={{ color: 'var(--severity-critical)' }} />
          </div>
          <div>
            <div className="ws-metric-label">Critical / High</div>
            <div className="ws-metric-value" style={{ color: 'var(--severity-critical)' }}>
              {criticalCount}
            </div>
            <div className="ws-metric-desc" style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 2, color: criticalCount > 0 ? 'var(--severity-critical)' : 'var(--text-muted)' }}>
              {criticalCount > 0 ? <ArrowUpRight size={12} /> : <ArrowDownRight size={12} />}
              {criticalCount > 0 ? 'Requires attention' : 'No critical issues'}
            </div>
          </div>
        </motion.div>

        {/* Secure / Low */}
        <motion.div
          className="ws-metric-card"
          variants={cardVariants}
          style={{ borderLeft: '3px solid var(--severity-low)' }}
        >
          <div className="ws-metric-icon" style={{ background: 'rgba(16, 185, 129, 0.10)' }}>
            <Shield size={22} style={{ color: 'var(--severity-low)' }} />
          </div>
          <div>
            <div className="ws-metric-label">Secure / Low</div>
            <div className="ws-metric-value" style={{ color: 'var(--severity-low)' }}>
              {secureCount}
            </div>
            <div className="ws-metric-desc" style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 2 }}>
              <CheckCircle size={12} />
              Low-risk findings
            </div>
          </div>
        </motion.div>
      </div>

      {/* ── Scans by Type ──────────────────────────────────────────── */}
      <motion.div
        variants={cardVariants}
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 'var(--space-4)',
          marginBottom: 'var(--space-5)',
        }}
      >
        {[
          { type: 'domain', label: 'Domain', icon: Globe, count: stats?.scans_by_type?.domain || 0, color: 'var(--accent)' },
          { type: 'ip', label: 'IP Address', icon: Server, count: stats?.scans_by_type?.ip || 0, color: 'var(--severity-info)' },
          { type: 'organization', label: 'Organization', icon: Building2, count: stats?.scans_by_type?.organization || 0, color: 'var(--cyber-purple)' },
        ].map(({ type, label, icon: Icon, count, color }) => (
          <Link
            key={type}
            to={`/scans?type=${type}`}
            className="card"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-3)',
              textDecoration: 'none',
              borderLeft: `3px solid ${color}`,
              transition: 'all 0.25s ease',
            }}
          >
            <div style={{
              width: 40, height: 40, borderRadius: 'var(--radius-md)',
              background: `${color}15`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0,
            }}>
              <Icon size={20} style={{ color }} />
            </div>
            <div>
              <div style={{ fontWeight: 600, color: 'var(--text-strong)', fontSize: 'var(--text-sm)' }}>
                {label}
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                {count} scan{count !== 1 ? 's' : ''}
              </div>
            </div>
          </Link>
        ))}
      </motion.div>

      {/* ── Quick Actions ──────────────────────────────────────── */}
      <motion.div
        variants={cardVariants}
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 'var(--space-4)',
          marginBottom: 'var(--space-5)',
        }}
      >
        <Link
          to="/scans/new"
          className="card"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-3)',
            textDecoration: 'none',
            borderLeft: '3px solid var(--accent)',
            transition: 'all 0.25s ease',
          }}
        >
          <div style={{
            width: 40, height: 40, borderRadius: 'var(--radius-md)',
            background: 'var(--accent-soft)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Zap size={20} style={{ color: 'var(--accent)' }} />
          </div>
          <div>
            <div style={{ fontWeight: 600, color: 'var(--text-strong)', fontSize: 'var(--text-sm)' }}>
              Launch New Scan
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
              Start reconnaissance
            </div>
          </div>
        </Link>

        <Link
          to="/assistant"
          className="card"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-3)',
            textDecoration: 'none',
            borderLeft: '3px solid var(--cyber-purple)',
            transition: 'all 0.25s ease',
          }}
        >
          <div style={{
            width: 40, height: 40, borderRadius: 'var(--radius-md)',
            background: 'var(--cyber-purple-soft)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Activity size={20} style={{ color: 'var(--cyber-purple)' }} />
          </div>
          <div>
            <div style={{ fontWeight: 600, color: 'var(--text-strong)', fontSize: 'var(--text-sm)' }}>
              AI Assistant
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
              Intelligent analysis
            </div>
          </div>
        </Link>

        <Link
          to="/graph"
          className="card"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-3)',
            textDecoration: 'none',
            borderLeft: '3px solid var(--cyber-teal)',
            transition: 'all 0.25s ease',
          }}
        >
          <div style={{
            width: 40, height: 40, borderRadius: 'var(--radius-md)',
            background: 'var(--cyber-teal-soft)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Globe size={20} style={{ color: 'var(--cyber-teal)' }} />
          </div>
          <div>
            <div style={{ fontWeight: 600, color: 'var(--text-strong)', fontSize: 'var(--text-sm)' }}>
              Entity Graph
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
              Visualize connections
            </div>
          </div>
        </Link>
      </motion.div>

      {/* ── Charts Grid ────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-6" style={{ marginBottom: 'var(--space-6)' }}>
        {/* Donut: Findings by Severity */}
        <motion.div className="card" variants={cardVariants}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
            <h2 style={{ margin: 0, fontSize: 'var(--text-lg)' }}>Findings by Severity</h2>
            <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
              {Object.entries(SEVERITY_COLORS).map(([key, color]) => (
                <span key={key} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
                  {key}
                </span>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={severityChartData}
                cx="50%"
                cy="50%"
                innerRadius={65}
                outerRadius={105}
                paddingAngle={3}
                dataKey="value"
                nameKey="name"
                stroke="none"
              >
                {severityChartData.map((entry) => (
                  <Cell
                    key={`cell-${entry.name}`}
                    fill={SEVERITY_COLORS[entry.name] || '#71717a'}
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Bar: Findings by Vector */}
        <motion.div className="card" variants={cardVariants}>
          <h2 style={{ margin: 0, fontSize: 'var(--text-lg)', marginBottom: 'var(--space-4)' }}>
            Findings by Vector
          </h2>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart
              data={vectorChartData}
              margin={{ top: 10, right: 10, left: -10, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
              <XAxis
                dataKey="name"
                tick={{ fontSize: 11, fill: 'var(--text-muted)' }}
                axisLine={{ stroke: 'var(--border-subtle)' }}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 11, fill: 'var(--text-muted)' }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar
                dataKey="value"
                radius={[4, 4, 0, 0]}
                fill="var(--accent)"
                fillOpacity={0.85}
              />
            </BarChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      {/* ── Recent Scans Table ─────────────────────────────────── */}
      <motion.div variants={cardVariants}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
          <h2 style={{ margin: 0, fontSize: 'var(--text-lg)' }}>Recent Scans</h2>
          <Link to="/scans" style={{ fontSize: 'var(--text-sm)', color: 'var(--accent)' }}>
            View All
          </Link>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Started</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {stats?.recent_scans?.map((scan: any) => (
                <tr key={scan.id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-strong)', fontSize: 'var(--text-sm)' }}>
                        {scan.target_domain}
                      </span>
                      {scan.target_type && scan.target_type !== 'domain' && (
                        <span className="badge badge-info" style={{
                          fontSize: 9, padding: '1px 5px', textTransform: 'uppercase',
                          letterSpacing: '0.03em', opacity: 0.8,
                        }}>
                          {scan.target_type}
                        </span>
                      )}
                    </div>
                  </td>
                  <td>{getStatusBadge(scan.status)}</td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                      color: (scan.findings_count || 0) > 0 ? 'var(--severity-high)' : 'var(--text-muted)',
                      fontSize: 'var(--text-sm)',
                    }}>
                      {scan.findings_count || 0}
                    </span>
                  </td>
                  <td>
                    <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
                      {scan.created_at
                        ? formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })
                        : 'Unknown'}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <Link
                      to={`/scans/${scan.id}`}
                      className="btn btn-secondary"
                      style={{ padding: '4px 12px', fontSize: 'var(--text-xs)' }}
                    >
                      Details
                    </Link>
                  </td>
                </tr>
              ))}
              {(!stats?.recent_scans || stats.recent_scans.length === 0) && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: 'var(--space-8)', color: 'var(--text-muted)' }}>
                    <Search size={24} style={{ marginBottom: 'var(--space-2)', opacity: 0.4 }} />
                    <div>No scans found. Start a new scan to begin reconnaissance.</div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* ── Celery Worker Queue ─────────────────────────────────── */}
      <motion.div variants={cardVariants} style={{ marginTop: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
          <h2 style={{ margin: 0, fontSize: 'var(--text-lg)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Server size={18} style={{ color: 'var(--accent)' }} />
            Worker Queue
          </h2>
          {queueStats && (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {queueStats.worker_count > 0 ? `${queueStats.worker_count} worker${queueStats.worker_count !== 1 ? 's' : ''} connected` : 'No workers connected'}
            </span>
          )}
        </div>
        {queueStats ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            <div className="card" style={{ padding: '12px 16px', textAlign: 'center', borderLeft: '3px solid var(--accent)' }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-strong)' }}>{queueStats.worker_count || 0}</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Workers</div>
            </div>
            <div className="card" style={{ padding: '12px 16px', textAlign: 'center', borderLeft: `3px solid ${queueStats.active_task_count > 0 ? '#f59e0b' : 'var(--severity-low)'}` }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: queueStats.active_task_count > 0 ? '#f59e0b' : 'var(--text-strong)' }}>
                {queueStats.active_task_count || 0}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Active Tasks</div>
            </div>
            <div className="card" style={{ padding: '12px 16px', textAlign: 'center', borderLeft: `3px solid ${queueStats.reserved_task_count > 0 ? '#3b82f6' : 'var(--severity-low)'}` }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: queueStats.reserved_task_count > 0 ? '#3b82f6' : 'var(--text-strong)' }}>
                {queueStats.reserved_task_count || 0}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Queued</div>
            </div>
            <div className="card" style={{ padding: '12px 16px', textAlign: 'center', borderLeft: '3px solid var(--severity-info)' }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-strong)' }}>{queueStats.active_worker_count || 0}</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Busy Workers</div>
            </div>
          </div>
        ) : (
          <div className="card" style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
            <Layers size={24} style={{ opacity: 0.3, marginBottom: 8 }} />
            <div>Queue stats unavailable — Celery may not be connected.</div>
          </div>
        )}
      </motion.div>
    </motion.div>
  );
}

export default Dashboard;
