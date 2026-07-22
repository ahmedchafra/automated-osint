import { useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { formatDistanceToNow } from 'date-fns';
import apiClient from '../api/client';
import { ChevronRight, Filter, MapPin, Maximize2, Scan, X, ZoomIn, ZoomOut, Network, AlertTriangle } from 'lucide-react';
import type { FindingRow } from '../components/FindingsTable';
// cytoscape is loaded from a CDN in index.html and available as a global.
// The `external` entry in vite.config.ts keeps it out of the bundle.
/* eslint-disable @typescript-eslint/no-explicit-any */

/** Returns the cytoscape constructor if the CDN has loaded, null otherwise. */
function getCyInstance(): any {
  return (window as any).cytoscape ?? null;
}

interface EntityLink {
  id: string;
  source_finding_id: string;
  target_finding_id: string;
  link_type: 'RESOLVES_TO' | 'HAS_PORT' | 'HAS_VULNERABILITY' | 'MATCHES_CVE' | 'BREACHED_IN' | 'REFERENCES' | string;
  confidence: number;
}

const EDGE_COLORS: Record<string, string> = {
  RESOLVES_TO: '#4ade80',
  HAS_PORT: '#fbbf24',
  HAS_VULNERABILITY: '#f87171',
  MATCHES_CVE: '#ff7550',
  BREACHED_IN: '#c084fc',
  REFERENCES: '#64d2ff',
};

const SEVERITY_NODE_COLOR: Record<string, string> = {
  CRITICAL: '#ff453a',
  HIGH: '#ff9f0a',
  MEDIUM: '#ffd60a',
  LOW: '#30d158',
  INFO: '#64d2ff',
};

function EntityTypeBadge({ type }: { type: string }) {
  return (
    <span
      className="badge badge-accent"
      style={{ fontFamily: 'var(--font-mono)' }}
    >
      {type}
    </span>
  );
}

interface EntityGraphProps {
  scanId?: string;
}

/* ── Scan picker shown when no scan has been selected yet ────────────── */

interface ScanOption {
  id: string;
  target_domain: string;
  target_type: string;
  status: string;
  findings_count: number;
  created_at: string;
}

function ScanPicker({ navigate }: { navigate: ReturnType<typeof useNavigate> }) {
  const { data: scans, isLoading } = useQuery<ScanOption[]>({
    queryKey: ['graph-scan-picker'],
    queryFn: async () => {
      const res = await apiClient.get('/scans/?limit=50&skip=0');
      return res.data as ScanOption[];
    },
  });

  const recent = useMemo(() => (scans ?? []).slice(0, 25), [scans]);

  return (
    <div style={{ maxWidth: 800, margin: '0 auto' }}>
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        style={{ marginBottom: 'var(--space-6)' }}
      >
        <h1 style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
          <Network size={24} style={{ color: 'var(--accent)' }} />
          Entity Graph
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
          Select a scan below to visualise its entity relationships.
          The correlation engine connects subdomains to IPs, ports to
          services, emails to breaches, and more.
        </p>
      </motion.div>

      {isLoading ? (
        <div className="card text-center py-8" style={{ color: 'var(--text-muted)' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 12,
            padding: '16px 24px', background: 'var(--glass-bg)',
            borderRadius: 'var(--radius-lg)', border: '1px solid var(--glass-border)',
          }}>
            <div style={{
              width: 18, height: 18, borderRadius: '50%',
              border: '2px solid var(--border-medium)', borderTopColor: 'var(--accent)',
              animation: 'spin 0.8s linear infinite',
            }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>
              Loading scans&hellip;
            </span>
          </div>
        </div>
      ) : recent.length === 0 ? (
        <div className="card text-center py-8">
          <MapPin size={40} style={{ color: 'var(--text-muted)', margin: '0 auto 16px', opacity: 0.5 }} />
          <h3 className="mb-2">No scans yet</h3>
          <p className="text-gray" style={{ maxWidth: 400, margin: '0 auto 20px' }}>
            Launch your first reconnaissance operation, then come back here
            to explore the entity graph.
          </p>
          <button onClick={() => navigate('/scans/new')} className="btn btn-primary">
            <Scan size={14} />
            <span>New Scan</span>
          </button>
        </div>
      ) : (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="card"
          style={{ padding: 0, overflow: 'hidden' }}
        >
          <div className="table-container" style={{ border: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Created</th>
                  <th style={{ textAlign: 'right' }} />
                </tr>
              </thead>
              <tbody>
                {recent.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: 'var(--text-sm)' }}>
                        {s.target_domain}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-info" style={{ fontSize: 10, textTransform: 'uppercase' }}>
                        {s.target_type || 'domain'}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${
                        s.status === 'COMPLETED' ? 'badge-success' :
                        s.status === 'FAILED' ? 'badge-danger' :
                        s.status === 'RUNNING' ? 'badge-accent' : 'badge-warning'
                      }`}>{s.status}</span>
                    </td>
                    <td>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 'var(--text-sm)',
                        color: (s.findings_count || 0) > 0 ? 'var(--severity-high)' : 'var(--text-muted)',
                      }}>
                        {s.findings_count || 0}
                      </span>
                    </td>
                    <td style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                      {s.created_at
                        ? formatDistanceToNow(new Date(s.created_at), { addSuffix: true })
                        : '—'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-primary"
                        style={{ padding: '5px 14px', fontSize: 'var(--text-xs)' }}
                        onClick={() => navigate(`/graph/${s.id}`)}
                      >
                        <Network size={12} />
                        <span>Graph</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      )}
    </div>
  );
}

function EntityGraph({ scanId }: EntityGraphProps) {
  const navigate = useNavigate();
  const { scanId: routeScanId } = useParams<{ scanId: string }>();
  const actualScanId = scanId || routeScanId;
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null);
  const [layoutName, setLayoutName] = useState<'cose' | 'circle' | 'grid' | 'breadthfirst'>('cose');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [linkTypeFilter, setLinkTypeFilter] = useState<Set<string>>(new Set());
  const [cyLoaded, setCyLoaded] = useState(!!getCyInstance());

  /* If the cytoscape CDN hasn't loaded yet, poll a few times. The script
     tag is in index.html <head>, so it should be ready by the time React
     hydrates, but network-delayed CDNs can arrive after the first paint. */
  useEffect(() => {
    if (cyLoaded) return;
    const timer = setInterval(() => {
      if (getCyInstance()) {
        setCyLoaded(true);
        clearInterval(timer);
      }
    }, 200);
    // Stop after 10s so we don't poll forever
    const safety = setTimeout(() => clearInterval(timer), 10_000);
    return () => { clearInterval(timer); clearTimeout(safety); };
  }, [cyLoaded]);

  const { data: links, error: linksError } = useQuery<EntityLink[]>({
    queryKey: ['entity-links', actualScanId],
    queryFn: async () => {
      if (!actualScanId) return [];
      const response = await apiClient.get(`/links/?scan_id=${actualScanId}`);
      return response.data;
    },
    enabled: !!actualScanId,
  });

  const { data: findings, error: findingsError } = useQuery<FindingRow[]>({
    queryKey: ['scan-findings', actualScanId],
    queryFn: async () => {
      if (!actualScanId) return [];
      const response = await apiClient.get(`/findings/?scan_id=${actualScanId}&limit=1000`);
      return response.data.items ?? response.data;
    },
    enabled: !!actualScanId,
  });

  const availableLinkTypes = useMemo(() => {
    if (!links) return [] as string[];
    return Array.from(new Set(links.map((l) => l.link_type))).sort();
  }, [links]);

  useEffect(() => {
    if (linkTypeFilter.size === 0 && availableLinkTypes.length > 0) {
      setLinkTypeFilter(new Set(availableLinkTypes));
    }
  }, [availableLinkTypes, linkTypeFilter.size]);

  const findingsMap = useMemo(() => {
    const m = new Map<string, FindingRow>();
    (findings ?? []).forEach((f) => m.set(f.id, f));
    return m;
  }, [findings]);

  const filteredLinks = useMemo(
    () => (links ?? []).filter((l) => linkTypeFilter.size === 0 || linkTypeFilter.has(l.link_type)),
    [links, linkTypeFilter],
  );

  const selectedFinding = selectedNodeId ? findingsMap.get(selectedNodeId) ?? null : null;

  const selectedNeighborhood = useMemo(() => {
    if (!selectedNodeId || !filteredLinks) return null;
    const out: { kind: 'in' | 'out'; other: FindingRow | undefined; link: EntityLink }[] = [];
    for (const link of filteredLinks) {
      if (link.source_finding_id === selectedNodeId) {
        out.push({ kind: 'out', other: findingsMap.get(link.target_finding_id), link });
      } else if (link.target_finding_id === selectedNodeId) {
        out.push({ kind: 'in', other: findingsMap.get(link.source_finding_id), link });
      }
    }
    return out;
  }, [selectedNodeId, filteredLinks, findingsMap]);

  // Build / rebuild the graph whenever data, layout, or filter changes.
  useEffect(() => {
    if (!containerRef.current || !findings || !filteredLinks) return;

    const elements: { data: Record<string, unknown> }[] = [];
    const nodeIds = new Set<string>();

    filteredLinks.forEach((link) => {
      const src = findingsMap.get(link.source_finding_id);
      const tgt = findingsMap.get(link.target_finding_id);
      const sid = `n-${link.source_finding_id}`;
      const tid = `n-${link.target_finding_id}`;

      const nodeColor = (f: FindingRow | undefined) =>
        (f && SEVERITY_NODE_COLOR[f.severity]) || '#5b5b62';

      if (!nodeIds.has(sid)) {
        nodeIds.add(sid);
        elements.push({
          data: {
            id: sid,
            label: src ? `${src.entity_type}\n${src.entity_value}` : link.source_finding_id.slice(0, 8),
            color: nodeColor(src),
            findingId: link.source_finding_id,
          },
        });
      }
      if (!nodeIds.has(tid)) {
        nodeIds.add(tid);
        elements.push({
          data: {
            id: tid,
            label: tgt ? `${tgt.entity_type}\n${tgt.entity_value}` : link.target_finding_id.slice(0, 8),
            color: nodeColor(tgt),
            findingId: link.target_finding_id,
          },
        });
      }

      elements.push({
        data: {
          id: `e-${link.id}`,
          source: sid,
          target: tid,
          label: link.link_type,
          color: EDGE_COLORS[link.link_type] || '#666',
        },
      });
    });

    // Destroy previous instance before creating a new one.
    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }

    const cyConstructor = getCyInstance();
    if (!cyConstructor) return; // CDN not loaded yet — the polling effect catches this

    cyRef.current = cyConstructor({
      container: containerRef.current,
      elements,
      style: [
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'text-valign': 'center',
              'text-halign': 'center',
              'text-wrap': 'wrap',
              'text-max-width': 100,
              'font-size': 11,
              color: '#fafafa',
              'text-outline-width': 2,
              'text-outline-color': '#0a0a0b',
              'background-color': 'data(color)',
              'border-width': 1.5,
              'border-color': '#0a0a0b',
              'border-opacity': 0.6,
              width: 64,
              height: 36,
            },
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': 4,
              'border-color': 'var(--accent)',
              'border-opacity': 1,
              'background-blacken': -0.15,
              'overlay-color': 'var(--accent)',
              'overlay-opacity': 0.15,
            },
          },
          {
            selector: 'edge',
            style: {
              width: 1.8,
              'line-color': 'data(color)',
              'target-arrow-color': 'data(color)',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'font-size': 9,
              label: 'data(label)',
              'text-rotation': 'autorotate',
              'text-margin-y': -10,
              color: '#c8c8cd',
              'text-outline-color': '#0a0a0b',
              'text-outline-width': 2,
              opacity: 0.65,
            },
          },
        ],
        layout: { name: layoutName, animate: true, animationDuration: 500 } as any,
        wheelSensitivity: 0.2,
      });

      const cy = cyRef.current;
      cy.on('tap', 'node', (evt: { target: { id: () => string } }) => {
        const nodeId = evt.target.id();
        if (nodeId.startsWith('n-')) {
          setSelectedNodeId(nodeId.slice(2));
        }
      });
      cy.on('tap', (evt: { target: unknown }) => {
        // Tap on background (not a node) closes the side panel.
        if (evt.target === cy) setSelectedNodeId(null);
      });

    return () => {
      cyRef.current?.destroy();
      cyRef.current = null;
    };
  }, [links, findings, layoutName, filteredLinks, findingsMap]);

  if (!actualScanId) {
    return <ScanPicker navigate={navigate} />;
  }

  const isLoading = !links || !findings;
  const hasLinks = (links?.length ?? 0) > 0;
  const hasError = !!(linksError || findingsError);

  const toggleLinkType = (t: string) =>
    setLinkTypeFilter((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });

  const fitGraph = () => {
    if (!cyRef.current) return;
    (cyRef.current as unknown as { fit: (padding?: number) => void }).fit(60);
  };
  const zoomIn = () => {
    if (!cyRef.current) return;
    const cy = cyRef.current as unknown as { zoom: (z?: number) => number };
    cy.zoom(cy.zoom() * 1.25);
  };
  const zoomOut = () => {
    if (!cyRef.current) return;
    const cy = cyRef.current as unknown as { zoom: (z?: number) => number };
    cy.zoom(cy.zoom() * 0.8);
  };

  const panelVariants = {
    hidden: { opacity: 0, x: 30, scale: 0.96 },
    visible: {
      opacity: 1,
      x: 0,
      scale: 1,
      transition: { type: 'spring' as const, stiffness: 350, damping: 30 },
    },
    exit: {
      opacity: 0,
      x: 30,
      scale: 0.96,
      transition: { duration: 0.18 },
    },
  };

  const controlsVariants = {
    hidden: { opacity: 0, y: -12 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { type: 'spring' as const, stiffness: 300, damping: 25, staggerChildren: 0.04 },
    },
  };

  const chipVariants = {
    hidden: { opacity: 0, scale: 0.85 },
    visible: { opacity: 1, scale: 1, transition: { type: 'spring' as const, stiffness: 400, damping: 22 } },
  };

  return (
    <div>
      {/* Premium Header */}
      <motion.div
        initial={{ opacity: 0, y: -16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: 'var(--space-6)',
          flexWrap: 'wrap',
          gap: 'var(--space-4)',
        }}
      >
        <div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              marginBottom: 'var(--space-2)',
              fontSize: 'var(--text-sm)',
            }}
          >
            <Link
              to="/"
              style={{
                color: 'var(--text-muted)',
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-1)',
                transition: 'color 0.15s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--accent)')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
            >
              Dashboard
            </Link>
            <ChevronRight size={14} style={{ color: 'var(--text-disabled)' }} />
            <span style={{ color: 'var(--text-strong)', fontWeight: 500 }}>Entity Graph</span>
          </div>
          <h1
            style={{
              marginBottom: 'var(--space-1)',
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-3)',
            }}
          >
            <span style={{ color: 'var(--accent)' }}>
              <Network size={28} />
            </span>
            Entity Relationship Graph
          </h1>
          <div
            style={{
              fontSize: 'var(--text-sm)',
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              flexWrap: 'wrap',
            }}
          >
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
              {actualScanId.substring(0, 8)}
            </span>
            <span style={{ color: 'var(--text-disabled)' }}>|</span>
            <span>{filteredLinks.length} of {links?.length ?? 0} links</span>
            <span style={{ color: 'var(--text-disabled)' }}>|</span>
            <span>{findingsMap.size} nodes</span>
          </div>
        </div>

        <motion.div
          variants={controlsVariants}
          initial="hidden"
          animate="visible"
          style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '1px',
              background: 'var(--glass-bg)',
              border: '1px solid var(--glass-border)',
              borderRadius: 'var(--radius-md)',
              padding: '3px',
              backdropFilter: 'blur(8px)',
            }}
          >
            {(['cose', 'circle', 'grid', 'breadthfirst'] as const).map((layout) => (
              <motion.button
                key={layout}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.97 }}
                onClick={() => setLayoutName(layout)}
                style={{
                  padding: '6px 14px',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 500,
                  fontFamily: 'inherit',
                  cursor: 'pointer',
                  borderRadius: 'var(--radius-sm)',
                  border: 'none',
                  transition: 'all 0.2s ease',
                  background: layoutName === layout
                    ? 'linear-gradient(135deg, var(--accent), #0891b2)'
                    : 'transparent',
                  color: layoutName === layout ? '#fff' : 'var(--text-muted)',
                  boxShadow: layoutName === layout
                    ? '0 0 12px var(--accent-glow)'
                    : 'none',
                }}
              >
                {layout === 'cose'
                  ? 'Force'
                  : layout === 'breadthfirst'
                    ? 'Tree'
                    : layout.charAt(0).toUpperCase() + layout.slice(1)}
              </motion.button>
            ))}
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '1px',
              background: 'var(--glass-bg)',
              border: '1px solid var(--glass-border)',
              borderRadius: 'var(--radius-md)',
              padding: '3px',
              backdropFilter: 'blur(8px)',
            }}
          >
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.92 }}
              onClick={zoomIn}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 32,
                height: 32,
                background: 'transparent',
                border: 'none',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
              title="Zoom in"
            >
              <ZoomIn size={16} />
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.92 }}
              onClick={zoomOut}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 32,
                height: 32,
                background: 'transparent',
                border: 'none',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
              title="Zoom out"
            >
              <ZoomOut size={16} />
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.92 }}
              onClick={fitGraph}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 32,
                height: 32,
                background: 'transparent',
                border: 'none',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
              title="Fit to view"
            >
              <Maximize2 size={16} />
            </motion.button>
          </div>

          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => navigate(`/scans/${actualScanId}`)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              padding: '8px 16px',
              fontSize: 'var(--text-sm)',
              fontWeight: 500,
              fontFamily: 'inherit',
              cursor: 'pointer',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-medium)',
              background: 'var(--glass-bg)',
              color: 'var(--text)',
              backdropFilter: 'blur(8px)',
              transition: 'all 0.2s ease',
            }}
          >
            <Scan size={16} /> Detail
          </motion.button>
        </motion.div>
      </motion.div>

      {/* Filter Controls Panel */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.08 }}
        style={{
          background: 'var(--glass-bg)',
          border: '1px solid var(--glass-border)',
          borderRadius: 'var(--radius-lg)',
          padding: 'var(--space-4) var(--space-5)',
          marginBottom: 'var(--space-6)',
          backdropFilter: 'blur(12px)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Filter size={16} style={{ color: 'var(--accent)' }} />
            <h3 style={{ marginBottom: 0, fontSize: 'var(--text-sm)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
              Edge Types
            </h3>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.96 }}
              type="button"
              onClick={() => setLinkTypeFilter(new Set(availableLinkTypes))}
              style={{
                padding: '4px 12px',
                fontSize: 'var(--text-xs)',
                fontWeight: 500,
                fontFamily: 'inherit',
                cursor: 'pointer',
                borderRadius: 'var(--radius-full)',
                border: '1px solid var(--border-medium)',
                background: linkTypeFilter.size === availableLinkTypes.length
                  ? 'var(--accent-soft)'
                  : 'transparent',
                color: linkTypeFilter.size === availableLinkTypes.length
                  ? 'var(--accent)'
                  : 'var(--text-muted)',
                transition: 'all 0.2s ease',
              }}
            >
              All
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.96 }}
              type="button"
              onClick={() => setLinkTypeFilter(new Set())}
              style={{
                padding: '4px 12px',
                fontSize: 'var(--text-xs)',
                fontWeight: 500,
                fontFamily: 'inherit',
                cursor: 'pointer',
                borderRadius: 'var(--radius-full)',
                border: '1px solid var(--border-medium)',
                background: linkTypeFilter.size === 0
                  ? 'rgba(244,63,94,0.12)'
                  : 'transparent',
                color: linkTypeFilter.size === 0
                  ? 'var(--severity-critical)'
                  : 'var(--text-muted)',
                transition: 'all 0.2s ease',
              }}
            >
              None
            </motion.button>
          </div>
        </div>

        {availableLinkTypes.length === 0 ? (
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            No link types discovered yet
          </div>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)' }}>
            {availableLinkTypes.map((type) => {
              const active = linkTypeFilter.has(type);
              const color = EDGE_COLORS[type] || '#888';
              return (
                <motion.button
                  key={type}
                  type="button"
                  onClick={() => toggleLinkType(type)}
                  variants={chipVariants}
                  initial="hidden"
                  animate="visible"
                  whileHover={{ scale: 1.04, y: -1 }}
                  whileTap={{ scale: 0.96 }}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 'var(--space-2)',
                    padding: '5px 13px',
                    borderRadius: 'var(--radius-full)',
                    border: `1px solid ${active ? color : 'var(--border-medium)'}`,
                    background: active ? `${color}18` : 'transparent',
                    color: active ? color : 'var(--text-muted)',
                    fontSize: 'var(--text-sm)',
                    fontWeight: 500,
                    fontFamily: 'inherit',
                    cursor: 'pointer',
                    transition: 'all 0.2s ease',
                    boxShadow: active ? `0 0 8px ${color}30` : 'none',
                  }}
                >
                  <span
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      background: color,
                      display: 'inline-block',
                      boxShadow: active ? `0 0 6px ${color}` : 'none',
                    }}
                  />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                    {type.replace(/_/g, ' ')}
                  </span>
                </motion.button>
              );
            })}
          </div>
        )}
      </motion.div>

      {!cyLoaded && !getCyInstance() ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="card text-center py-8"
          style={{ color: 'var(--text-muted)' }}
        >
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 'var(--space-3)',
            padding: 'var(--space-4) var(--space-6)',
            background: 'var(--glass-bg)', borderRadius: 'var(--radius-lg)',
            border: '1px solid var(--glass-border)',
            backdropFilter: 'blur(12px)',
          }}>
            <div style={{
              width: 18, height: 18,
              border: '2px solid var(--border-medium)', borderTopColor: 'var(--accent)',
              borderRadius: '50%', animation: 'spin 0.8s linear infinite',
            }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>
              Loading graph renderer&hellip;
            </span>
          </div>
        </motion.div>
      ) : hasError ? (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="card text-center py-8"
        >
          <AlertTriangle size={32} style={{ color: 'var(--severity-critical)', marginBottom: 'var(--space-4)' }} />
          <h3 className="mb-2">Failed to load graph data</h3>
          <p className="text-gray" style={{ maxWidth: 480, margin: '0 auto' }}>
            The entity links API returned an error. This often happens when the
            JWT session isn't linked to an active scan — try opening a scan
            workspace first.
          </p>
        </motion.div>
      ) : isLoading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="card text-center py-8"
          style={{ color: 'var(--text-muted)' }}
        >
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 'var(--space-3)',
              padding: 'var(--space-4) var(--space-6)',
              background: 'var(--glass-bg)',
              borderRadius: 'var(--radius-lg)',
              border: '1px solid var(--glass-border)',
              backdropFilter: 'blur(12px)',
            }}
          >
            <div
              style={{
                width: 18,
                height: 18,
                border: '2px solid var(--border-medium)',
                borderTopColor: 'var(--accent)',
                borderRadius: '50%',
                animation: 'spin 0.8s linear infinite',
              }}
            />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>
              Loading graph data&hellip;
            </span>
          </div>
        </motion.div>
      )}

      {!isLoading && !hasLinks && !hasError && (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="card text-center py-8"
        >
          <MapPin size={32} style={{ color: 'var(--text-muted)', marginBottom: 'var(--space-4)' }} />
          <h3 className="mb-2">No entity relationships found</h3>
          <p className="text-gray" style={{ maxWidth: 480, margin: '0 auto' }}>
            Run a scan with at least two vectors — the correlation engine connects
            subdomains to IPs, ports to services, and emails to breaches.
          </p>
        </motion.div>
      )}

      {!isLoading && hasLinks && !hasError && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: selectedFinding ? '1fr 380px' : '1fr',
            gap: 'var(--space-6)',
            transition: 'grid-template-columns 300ms cubic-bezier(0.16, 1, 0.3, 1)',
          }}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
            style={{
              background: 'var(--glass-bg)',
              border: '1px solid var(--glass-border)',
              borderRadius: 'var(--radius-lg)',
              padding: 'var(--space-3)',
              minHeight: 640,
              backdropFilter: 'blur(12px)',
              position: 'relative',
              overflow: 'hidden',
            }}
          >
            {/* Decorative corner accents */}
            <div
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                width: 20,
                height: 20,
                borderTop: '2px solid var(--accent)',
                borderLeft: '2px solid var(--accent)',
                borderTopLeftRadius: 'var(--radius-lg)',
                opacity: 0.5,
              }}
            />
            <div
              style={{
                position: 'absolute',
                bottom: 0,
                right: 0,
                width: 20,
                height: 20,
                borderBottom: '2px solid var(--accent)',
                borderRight: '2px solid var(--accent)',
                borderBottomRightRadius: 'var(--radius-lg)',
                opacity: 0.5,
              }}
            />
            <div
              ref={containerRef}
              style={{
                width: '100%',
                height: '640px',
                borderRadius: 'var(--radius-md)',
                overflow: 'hidden',
                background: 'var(--surface-0)',
              }}
            />
            <div
              style={{
                marginTop: 'var(--space-3)',
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                gap: 'var(--space-4)',
                fontSize: 'var(--text-xs)',
                color: 'var(--text-muted)',
                padding: '0 var(--space-2)',
              }}
            >
              <span style={{ fontFamily: 'var(--font-mono)' }}>
                Click a node to inspect • scroll to zoom • drag to pan
              </span>
              {Object.entries(SEVERITY_NODE_COLOR).map(([sev, color]) => (
                <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <span
                    style={{
                      width: 10,
                      height: 10,
                      borderRadius: '50%',
                      background: color,
                      display: 'inline-block',
                      boxShadow: `0 0 6px ${color}50`,
                    }}
                  />
                  <span style={{ fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    {sev}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>

          <AnimatePresence mode="wait">
            {selectedFinding && (
              <motion.aside
                key={selectedFinding.id}
                variants={panelVariants}
                initial="hidden"
                animate="visible"
                exit="exit"
                style={{
                  alignSelf: 'start',
                  maxHeight: 'calc(100vh - 220px)',
                  overflowY: 'auto',
                  background: 'var(--glass-bg)',
                  border: '1px solid var(--glass-border)',
                  borderRadius: 'var(--radius-lg)',
                  padding: 'var(--space-5)',
                  backdropFilter: 'blur(12px)',
                  position: 'sticky',
                  top: 'var(--space-6)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
                  <h3 style={{ marginBottom: 0, fontSize: 'var(--text-lg)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <span
                      style={{
                        width: 8,
                        height: 8,
                        borderRadius: '50%',
                        background: SEVERITY_NODE_COLOR[selectedFinding.severity] || 'var(--accent)',
                        boxShadow: `0 0 8px ${SEVERITY_NODE_COLOR[selectedFinding.severity] || 'var(--accent)'}`,
                        display: 'inline-block',
                      }}
                    />
                    Node Detail
                  </h3>
                  <motion.button
                    whileHover={{ scale: 1.08, rotate: 90 }}
                    whileTap={{ scale: 0.9 }}
                    onClick={() => setSelectedNodeId(null)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      width: 28,
                      height: 28,
                      background: 'rgba(255,255,255,0.04)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-muted)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <X size={14} />
                  </motion.button>
                </div>

                <motion.div
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 }}
                  style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)', flexWrap: 'wrap' }}
                >
                  <EntityTypeBadge type={selectedFinding.entity_type} />
                  <span className={`severity-dot ${selectedFinding.severity.toLowerCase()}`} />
                  <span
                    className="badge"
                    style={{
                      background: `${SEVERITY_NODE_COLOR[selectedFinding.severity] ?? '#888'}22`,
                      color: SEVERITY_NODE_COLOR[selectedFinding.severity] ?? '#888',
                      borderColor: `${SEVERITY_NODE_COLOR[selectedFinding.severity] ?? '#888'}55`,
                    }}
                  >
                    {selectedFinding.severity}
                  </span>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.14 }}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-sm)',
                    background: 'var(--surface-0)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    padding: 'var(--space-3) var(--space-4)',
                    color: 'var(--text-strong)',
                    wordBreak: 'break-all',
                    whiteSpace: 'pre-wrap',
                    lineHeight: 'var(--leading-normal)',
                    marginBottom: 'var(--space-4)',
                  }}
                  title={selectedFinding.entity_value}
                >
                  {selectedFinding.entity_value}
                </motion.div>

                <motion.dl
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.18 }}
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'auto 1fr',
                    gap: 'var(--space-2) var(--space-3)',
                    fontSize: 'var(--text-sm)',
                    margin: 0,
                  }}
                >
                  <dt style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.05em', paddingTop: 2 }}>Vector</dt>
                  <dd style={{ color: 'var(--text-strong)', fontFamily: 'var(--font-mono)' }}>{selectedFinding.vector_type}</dd>
                  <dt style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.05em', paddingTop: 2 }}>Source</dt>
                  <dd style={{ color: 'var(--text-strong)', fontFamily: 'var(--font-mono)' }}>{selectedFinding.source_module}</dd>
                  <dt style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.05em', paddingTop: 2 }}>Confidence</dt>
                  <dd style={{ color: 'var(--text-strong)', fontFamily: 'var(--font-mono)' }}>{Math.round(selectedFinding.confidence * 100)}%</dd>
                </motion.dl>

                {selectedFinding.raw_data && Object.keys(selectedFinding.raw_data).length > 0 && (
                  <motion.details
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.22 }}
                    style={{ marginTop: 'var(--space-4)' }}
                  >
                    <summary
                      style={{
                        cursor: 'pointer',
                        fontSize: 'var(--text-sm)',
                        color: 'var(--text-muted)',
                        fontWeight: 500,
                        padding: 'var(--space-2) 0',
                        transition: 'color 0.15s ease',
                      }}
                    >
                      Raw data
                    </summary>
                    <pre
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 'var(--text-xs)',
                        background: 'var(--surface-0)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-md)',
                        padding: 'var(--space-3)',
                        maxHeight: 200,
                        overflow: 'auto',
                        color: 'var(--text)',
                        marginTop: 'var(--space-2)',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {JSON.stringify(selectedFinding.raw_data, null, 2)}
                    </pre>
                  </motion.details>
                )}

                {selectedFinding.normalized_data && Object.keys(selectedFinding.normalized_data).length > 0 && (
                  <motion.details
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.24 }}
                    style={{ marginTop: 'var(--space-2)' }}
                    open
                  >
                    <summary
                      style={{
                        cursor: 'pointer',
                        fontSize: 'var(--text-sm)',
                        color: 'var(--text-muted)',
                        fontWeight: 500,
                        padding: 'var(--space-2) 0',
                        transition: 'color 0.15s ease',
                      }}
                    >
                      Normalized
                    </summary>
                    <pre
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 'var(--text-xs)',
                        background: 'var(--surface-0)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-md)',
                        padding: 'var(--space-3)',
                        maxHeight: 200,
                        overflow: 'auto',
                        color: 'var(--text)',
                        marginTop: 'var(--space-2)',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {JSON.stringify(selectedFinding.normalized_data, null, 2)}
                    </pre>
                  </motion.details>
                )}

                {selectedNeighborhood && selectedNeighborhood.length > 0 && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.28 }}
                    style={{ marginTop: 'var(--space-5)' }}
                  >
                    <h4
                      style={{
                        fontSize: 'var(--text-xs)',
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.08em',
                        fontWeight: 600,
                        marginBottom: 'var(--space-3)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-2)',
                      }}
                    >
                      <span
                        style={{
                          width: 12,
                          height: 1,
                          background: 'var(--accent)',
                          display: 'inline-block',
                        }}
                      />
                      Connections ({selectedNeighborhood.length})
                    </h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                      {selectedNeighborhood.map((n, idx) => (
                        <motion.button
                          key={`${n.link.id}-${idx}`}
                          type="button"
                          onClick={() => n.other && setSelectedNodeId(n.other.id)}
                          whileHover={{ x: 4, borderColor: 'var(--border-medium)' }}
                          whileTap={{ scale: 0.98 }}
                          initial={{ opacity: 0, x: 16 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: 0.3 + idx * 0.04 }}
                          style={{
                            textAlign: 'left',
                            padding: 'var(--space-2) var(--space-3)',
                            background: 'rgba(255,255,255,0.02)',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-md)',
                            cursor: n.other ? 'pointer' : 'default',
                            transition: 'all 0.2s ease',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 'var(--space-1)',
                          }}
                        >
                          <div
                            style={{
                              fontSize: 'var(--text-xs)',
                              color: 'var(--text-muted)',
                              fontFamily: 'var(--font-mono)',
                              display: 'flex',
                              alignItems: 'center',
                              gap: 'var(--space-2)',
                            }}
                          >
                            <span style={{ color: n.kind === 'out' ? 'var(--accent)' : 'var(--cyber-purple)' }}>
                              {n.kind === 'out' ? '→' : '←'}
                            </span>
                            <span style={{ fontWeight: 500 }}>{n.link.link_type}</span>
                            <span style={{ marginLeft: 'auto', color: 'var(--text-strong)' }}>
                              {Math.round(n.link.confidence * 100)}%
                            </span>
                          </div>
                          <div
                            style={{
                              fontSize: 'var(--text-sm)',
                              color: 'var(--text-strong)',
                              wordBreak: 'break-all',
                            }}
                          >
                            {n.other ? `${n.other.entity_type}: ${n.other.entity_value}` : '(missing)'}
                          </div>
                        </motion.button>
                      ))}
                    </div>
                  </motion.div>
                )}
              </motion.aside>
            )}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
}

export default EntityGraph;
