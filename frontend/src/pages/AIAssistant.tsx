import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import apiClient from '../api/client';
import {
  ChevronRight,
  Copy,
  ExternalLink,
  Loader2,
  Sparkles,
  Wand2,
  Zap,
  Search,
  Terminal,
  Activity,
  ChevronDown,
} from 'lucide-react';

interface AIAssistantProps {
  scanId?: string;
}

interface AIQueryRecord {
  id: string;
  scan_id: string;
  user_prompt: string;
  generated_dork: string;
  model_used: string;
  search_results: Array<{
    title?: string;
    link?: string;
    snippet?: string;
    position?: number;
    url?: string;
  }>;
  created_at: string;
}

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.08, delayChildren: 0.1 },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 16, scale: 0.97 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { type: 'spring' as const, stiffness: 300, damping: 24 },
  },
};

import type { TargetAndTransition } from 'framer-motion';

const pulseGlow: { animate: TargetAndTransition } = {
  animate: {
    boxShadow: [
      '0 0 8px rgba(6, 182, 212, 0.25), 0 0 20px rgba(6, 182, 212, 0.08)',
      '0 0 16px rgba(6, 182, 212, 0.45), 0 0 40px rgba(6, 182, 212, 0.15)',
      '0 0 8px rgba(6, 182, 212, 0.25), 0 0 20px rgba(6, 182, 212, 0.08)',
    ],
    transition: { duration: 2, repeat: Infinity, ease: 'easeInOut' as const },
  },
};

function AIAssistant({ scanId }: AIAssistantProps) {
  const navigate = useNavigate();
  const { scanId: routeScanId } = useParams<{ scanId: string }>();
  const actualScanId = scanId || routeScanId;

  const [userPrompt, setUserPrompt] = useState('');
  const [generatedDork, setGeneratedDork] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedQueryId, setExpandedQueryId] = useState<string | null>(null);
  const [activeJob, setActiveJob] = useState<string | null>(null);
  const [copyFlash, setCopyFlash] = useState(false);
  const promptRef = useRef<HTMLTextAreaElement>(null);

  const { data: queries, refetch: refetchQueries } = useQuery<AIQueryRecord[]>({
    queryKey: ['ai-queries', actualScanId],
    queryFn: async () => {
      if (!actualScanId) return [];
      const response = await apiClient.get(`/ai/queries?scan_id=${actualScanId}&limit=50`);
      return response.data;
    },
    enabled: !!actualScanId,
    refetchInterval: () => (activeJob ? 2500 : false),
  });

  const { data: scan } = useQuery<{ status: string; target_domain: string }>({
    queryKey: ['scan', actualScanId],
    queryFn: async () => (await apiClient.get(`/scans/${actualScanId}`)).data,
    enabled: !!actualScanId,
    refetchInterval: (query) =>
      query.state.data?.status === 'RUNNING' ? 3000 : false,
  });

  const generate = useMutation({
    mutationFn: async (prompt: string) => {
      const response = await apiClient.post('/ai/generate-dork', { prompt });
      return response.data as { dork: string };
    },
    onSuccess: (data) => {
      setGeneratedDork(data.dork ?? '');
    },
  });

  const runSearch = useMutation({
    mutationFn: async (prompt: string) => {
      const response = await apiClient.post(`/scans/${actualScanId}/ai-dork`, { prompt });
      return response.data as { task_id: string; scan_id: string };
    },
    onSuccess: (data) => {
      setError(null);
      setActiveJob(data.task_id);
    },
    onError: (err: unknown) => {
      setError(extractError(err));
      setActiveJob(null);
    },
  });

  useEffect(() => {
    if (!activeJob || !queries) return;
    const matchingQuery = queries.find((q) => q.user_prompt.trim() === userPrompt.trim());
    if (matchingQuery && matchingQuery.search_results.length > 0) {
      const timer = window.setTimeout(() => {
        setActiveJob(null);
        setExpandedQueryId(matchingQuery.id);
        refetchQueries();
      }, 0);
      return () => window.clearTimeout(timer);
    }
  }, [queries, activeJob, userPrompt, refetchQueries]);

  const handleGenerate = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!userPrompt.trim()) {
      setError('Please describe what you want to find.');
      return;
    }
    setError(null);
    setIsGenerating(true);
    try {
      await generate.mutateAsync(userPrompt.trim());
    } catch (err) {
      setError(extractError(err));
    } finally {
      setIsGenerating(false);
    }
  };

  const handleRun = async () => {
    const prompt = userPrompt.trim();
    if (!prompt) {
      setError('Please describe what you want to find.');
      return;
    }
    let dork = generatedDork.trim();
    if (!dork) {
      try {
        setIsGenerating(true);
        const d = await generate.mutateAsync(prompt);
        dork = d.dork ?? '';
        setGeneratedDork(dork);
      } catch (err) {
        setError(extractError(err));
        setIsGenerating(false);
        return;
      } finally {
        setIsGenerating(false);
      }
    }
    await runSearch.mutateAsync(prompt);
  };

  const copyDork = () => {
    if (!generatedDork) return;
    navigator.clipboard.writeText(generatedDork).then(() => {
      setCopyFlash(true);
      setTimeout(() => setCopyFlash(false), 1500);
    });
  };

  const recent = useMemo(() => queries ?? [], [queries]);
  const suggestions = useMemo(() => {
    const target = scan?.target_domain || 'the target';
    return [
      `Find exposed login pages for ${target}`,
      `Find .git directories exposed on ${target}`,
      `Find admin panels on subdomains of ${target}`,
      `Find PDF documents linked to ${target} that may expose internal data`,
      `Find cloud storage linked to ${target}`,
    ];
  }, [scan?.target_domain]);

  if (!actualScanId) {
    return (
      <div style={{ maxWidth: 720, margin: '0 auto' }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="card text-center py-8"
          style={{
            background: 'var(--glass-bg)',
            border: '1px solid var(--glass-border)',
            backdropFilter: 'blur(12px)',
            borderRadius: 'var(--radius-xl)',
          }}
        >
          <motion.div
            animate={{ rotate: [0, 5, -5, 0] }}
            transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
          >
            <Zap size={40} style={{ color: 'var(--accent)', marginBottom: 'var(--space-4)' }} />
          </motion.div>
          <h2 style={{ color: 'var(--text-strong)' }}>AI Assistant</h2>
          <p className="text-gray mt-4">
            Please select or create a scan first to use the AI dork generator.
          </p>
          <div className="mt-6">
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => navigate('/')}
              className="btn btn-outline"
            >
              Go to Dashboard
            </motion.button>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      style={{ maxWidth: 960, margin: '0 auto' }}
    >
      {/* Header */}
      <motion.div
        variants={itemVariants}
        className="flex justify-between items-start mb-6 gap-4 flex-wrap"
      >
        <div>
          <div
            className="text-sm flex items-center gap-2 mb-2"
            style={{ color: 'var(--text-muted)' }}
          >
            <Terminal size={14} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              AI Dork Generator
            </span>
          </div>
          <h1 className="mb-2" style={{ color: 'var(--text-strong)' }}>
            <span style={{ color: 'var(--accent)' }}>/</span> Dork Command Center
          </h1>
          <p className="text-gray text-sm" style={{ color: 'var(--text-muted)' }}>
            Describe what you&apos;re hunting. We&apos;ll spin up a Google Dork, run it through Serper,
            and persist every result as a{' '}
            <code
              style={{
                fontFamily: 'var(--font-mono)',
                color: 'var(--accent)',
                background: 'var(--accent-soft)',
                padding: '1px 6px',
                borderRadius: 'var(--radius-sm)',
                fontSize: 12,
              }}
            >
              DORK_RESULT
            </code>{' '}
            finding.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <motion.span
            className={`badge ${
              scan?.status === 'COMPLETED'
                ? 'badge-success'
                : scan?.status === 'FAILED'
                ? 'badge-danger'
                : scan?.status === 'RUNNING'
                ? 'badge-warning'
                : 'badge-info'
            }`}
            animate={scan?.status === 'RUNNING' ? { opacity: [1, 0.6, 1] } : {}}
            transition={{ duration: 1.5, repeat: Infinity }}
          >
            <Activity size={10} style={{ marginRight: 4 }} />
            Scan {scan?.status ?? 'UNKNOWN'}
          </motion.span>
          <motion.button
            whileHover={{ scale: 1.04, x: 2 }}
            whileTap={{ scale: 0.96 }}
            onClick={() => navigate(`/scans/${actualScanId}`)}
            className="btn btn-outline"
            style={{
              background: 'var(--glass-bg)',
              border: '1px solid var(--glass-border)',
              backdropFilter: 'blur(12px)',
            }}
          >
            <ChevronRight size={14} /> Scan Detail
          </motion.button>
        </div>
      </motion.div>

      {/* Error */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, height: 0, marginBottom: 0 }}
            animate={{ opacity: 1, height: 'auto', marginBottom: 'var(--space-6)' }}
            exit={{ opacity: 0, height: 0, marginBottom: 0 }}
            transition={{ duration: 0.3 }}
            className="card"
            style={{
              borderColor: 'var(--severity-high)',
              background: 'rgba(245, 158, 11, 0.06)',
              boxShadow: 'var(--glow-high)',
              borderRadius: 'var(--radius-lg)',
              overflow: 'hidden',
            }}
          >
            <div className="flex items-start gap-3">
              <div
                style={{
                  width: 6,
                  alignSelf: 'stretch',
                  background: 'var(--severity-high)',
                  borderRadius: 'var(--radius-sm)',
                }}
              />
              <div style={{ padding: 'var(--space-3) 0' }}>
                <strong style={{ color: 'var(--severity-high)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                  ERROR
                </strong>
                <p style={{ marginTop: 'var(--space-2)', color: 'var(--text-strong)' }}>{error}</p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Form Card */}
      <motion.div
        variants={itemVariants}
        className="card mb-6"
        style={{
          background: 'var(--glass-bg)',
          border: '1px solid var(--glass-border)',
          backdropFilter: 'blur(12px)',
          borderRadius: 'var(--radius-xl)',
          boxShadow: '0 0 0 1px rgba(255,255,255,0.02) inset',
        }}
      >
        <form onSubmit={handleGenerate}>
          <div className="flex items-center gap-2 mb-4">
            <motion.div
              animate={{ rotate: [0, 15, -10, 0] }}
              transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
            >
              <Wand2 size={18} style={{ color: 'var(--accent)' }} />
            </motion.div>
            <h3 style={{ marginBottom: 0, color: 'var(--text-strong)' }}>Describe your recon goal</h3>
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="user-prompt" style={{ color: 'var(--text-muted)' }}>
              Prompt
            </label>
            <textarea
              ref={promptRef}
              id="user-prompt"
              className="form-input"
              rows={3}
              placeholder="e.g., Find exposed login pages for example.com"
              value={userPrompt}
              onChange={(e) => setUserPrompt(e.target.value)}
              style={{
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-medium)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-strong)',
                fontFamily: 'var(--font-mono)',
                resize: 'vertical',
              }}
            />
          </div>

          <div className="form-group">
            <label
              className="form-label"
              style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.06em' }}
            >
              Quick suggestions
            </label>
            <div className="flex flex-wrap gap-2">
              {suggestions.map((s, i) => (
                <motion.button
                  key={s}
                  type="button"
                  onClick={() => {
                    setUserPrompt(s);
                    promptRef.current?.focus();
                  }}
                  className="chip"
                  style={{
                    padding: '4px 12px',
                    background: 'var(--accent-soft)',
                    border: '1px solid var(--accent-ring)',
                    color: 'var(--accent)',
                    borderRadius: 'var(--radius-full)',
                    fontSize: 12,
                    fontFamily: 'var(--font-mono)',
                  }}
                  whileHover={{
                    scale: 1.05,
                    boxShadow: 'var(--glow-accent)',
                    background: 'rgba(6, 182, 212, 0.18)',
                  }}
                  whileTap={{ scale: 0.95 }}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 + i * 0.05 }}
                >
                  {s}
                </motion.button>
              ))}
            </div>
          </div>

          <div className="form-group">
            <label
              className="form-label"
              style={{ color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em' }}
            >
              Generated dork
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type="text"
                className="mono-block"
                style={{
                  paddingRight: 100,
                  fontFamily: 'var(--font-mono)',
                  fontSize: 13,
                  background: 'rgba(0,0,0,0.4)',
                  border: '1px solid var(--border-medium)',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--accent)',
                  caretColor: 'var(--accent)',
                }}
                value={generatedDork}
                onChange={(e) => setGeneratedDork(e.target.value)}
                placeholder="Generated dork will appear here…"
              />
              <motion.button
                type="button"
                onClick={copyDork}
                disabled={!generatedDork}
                className="btn"
                style={{
                  position: 'absolute',
                  right: 4,
                  top: 4,
                  padding: '4px 12px',
                  fontSize: 12,
                  background: copyFlash ? 'rgba(16, 185, 129, 0.15)' : 'var(--glass-bg)',
                  border: '1px solid var(--glass-border)',
                  borderRadius: 'var(--radius-sm)',
                  color: copyFlash ? 'var(--severity-low)' : 'var(--text-muted)',
                }}
                whileHover={generatedDork ? { scale: 1.05 } : {}}
                whileTap={generatedDork ? { scale: 0.95 } : {}}
              >
                <Copy size={13} style={{ marginRight: 4 }} />
                {copyFlash ? 'Copied!' : 'Copy'}
              </motion.button>
            </div>
          </div>

          <div className="flex items-center gap-3 mt-4 flex-wrap">
            <motion.button
              type="submit"
              className="btn"
              disabled={isGenerating || !userPrompt.trim()}
              style={{
                background: 'var(--glass-bg)',
                border: '1px solid var(--accent-ring)',
                color: 'var(--accent)',
                borderRadius: 'var(--radius-md)',
              }}
              whileHover={!isGenerating && userPrompt.trim() ? { scale: 1.03, boxShadow: 'var(--glow-accent)' } : {}}
              whileTap={!isGenerating && userPrompt.trim() ? { scale: 0.97 } : {}}
            >
              {isGenerating ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <Sparkles size={16} />
              )}
              Generate dork
            </motion.button>
            <motion.button
              type="button"
              className="btn btn-primary"
              disabled={!userPrompt.trim() || isGenerating || !!activeJob}
              onClick={handleRun}
              style={{
                boxShadow: activeJob ? 'var(--glow-accent)' : 'none',
                borderRadius: 'var(--radius-md)',
              }}
              whileHover={!(!userPrompt.trim() || isGenerating || activeJob) ? { scale: 1.03, boxShadow: '0 0 20px rgba(6, 182, 212, 0.5), 0 0 60px rgba(6, 182, 212, 0.15)' } : {}}
              whileTap={!(!userPrompt.trim() || isGenerating || activeJob) ? { scale: 0.97 } : {}}
              animate={activeJob ? pulseGlow.animate : {}}
            >
              {activeJob ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <Zap size={16} />
              )}
              {activeJob ? 'Running search…' : 'Run search & persist'}
            </motion.button>
            <motion.span
              className="text-xs"
              style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}
              animate={activeJob ? { opacity: [0.5, 1, 0.5] } : { opacity: 1 }}
              transition={activeJob ? { duration: 1.5, repeat: Infinity } : {}}
            >
              {activeJob
                ? 'Polling for results — usually under 10s.'
                : 'Results are saved as findings and shown below.'}
            </motion.span>
          </div>
        </form>
      </motion.div>

      {/* Query History Header */}
      <motion.div variants={itemVariants} className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Search size={16} style={{ color: 'var(--text-muted)' }} />
          <h2 style={{ marginBottom: 0, color: 'var(--text-strong)' }}>Query history</h2>
        </div>
        <span
          className="text-sm"
          style={{
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
            background: 'var(--glass-bg)',
            padding: '2px 10px',
            borderRadius: 'var(--radius-full)',
            border: '1px solid var(--glass-border)',
          }}
        >
          {recent.length} {recent.length === 1 ? 'query' : 'queries'}
        </span>
      </motion.div>

      {/* Empty State */}
      <AnimatePresence>
        {recent.length === 0 && !activeJob && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -10, scale: 0.95 }}
            transition={{ duration: 0.5, type: 'spring' as const, stiffness: 200, damping: 20 }}
            className="card text-center py-8"
            style={{
              background: 'var(--glass-bg)',
              border: '1px dashed var(--glass-border)',
              backdropFilter: 'blur(12px)',
              borderRadius: 'var(--radius-xl)',
            }}
          >
            <motion.div
              animate={{
                y: [0, -6, 0],
                rotate: [0, 3, -3, 0],
              }}
              transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
            >
              <Sparkles size={36} style={{ color: 'var(--accent)', opacity: 0.5, marginBottom: 'var(--space-3)' }} />
            </motion.div>
            <p style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
              No AI queries yet for this scan.
            </p>
            <p style={{ color: 'var(--text-disabled)', marginTop: 'var(--space-2)', fontSize: 12 }}>
              Run your first query above to begin reconnaissance.
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Query History List */}
      <motion.div className="flex flex-col gap-4">
        <AnimatePresence mode="popLayout">
          {recent.map((q, index) => {
            const isExpanded = expandedQueryId === q.id || recent.length === 1;
            const results = q.search_results ?? [];
            return (
              <motion.article
                key={q.id}
                layout
                initial={{ opacity: 0, y: 24, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -16, scale: 0.96 }}
                transition={{
                  type: 'spring' as const,
                  stiffness: 260,
                  damping: 22,
                  delay: index * 0.06,
                }}
                className="card"
                style={{
                  padding: 'var(--space-5)',
                  background: 'var(--glass-bg)',
                  border: '1px solid var(--glass-border)',
                  backdropFilter: 'blur(12px)',
                  borderRadius: 'var(--radius-lg)',
                  boxShadow: isExpanded ? 'var(--glow-accent)' : 'none',
                }}
              >
                <div className="flex justify-between items-start gap-4 flex-wrap">
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      className="text-xs"
                      style={{
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-muted)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--space-2)',
                      }}
                    >
                      <span style={{ color: 'var(--accent)' }}>#</span>
                      {new Date(q.created_at).toLocaleString()}
                      <span style={{ color: 'var(--border-medium)' }}>|</span>
                      <span style={{ color: 'var(--cyber-purple)' }}>{q.model_used}</span>
                    </div>
                    <p
                      style={{
                        color: 'var(--text-strong)',
                        marginTop: 'var(--space-2)',
                        fontWeight: 500,
                      }}
                    >
                      {q.user_prompt}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="badge badge-info">
                      {results.length} {results.length === 1 ? 'result' : 'results'}
                    </span>
                    <motion.button
                      type="button"
                      onClick={() => setExpandedQueryId(isExpanded ? null : q.id)}
                      className="btn btn-outline"
                      style={{
                        padding: '4px 12px',
                        fontSize: 12,
                        borderRadius: 'var(--radius-sm)',
                        background: isExpanded ? 'var(--accent-soft)' : 'var(--glass-bg)',
                        borderColor: isExpanded ? 'var(--accent-ring)' : 'var(--glass-border)',
                      }}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <ChevronDown
                        size={12}
                        style={{
                          marginRight: 4,
                          transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
                          transition: 'transform 0.3s ease',
                        }}
                      />
                      {isExpanded ? 'Collapse' : 'Expand'}
                    </motion.button>
                  </div>
                </div>

                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  transition={{ duration: 0.3 }}
                  className="mt-3"
                >
                  <div
                    className="text-xs"
                    style={{
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      fontWeight: 600,
                      color: 'var(--text-muted)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 10,
                    }}
                  >
                    Dork query
                  </div>
                  <motion.div
                    className="mono-block mt-2"
                    style={{
                      fontSize: 13,
                      padding: 'var(--space-3)',
                      background: 'rgba(0,0,0,0.4)',
                      border: '1px solid var(--border-medium)',
                      borderRadius: 'var(--radius-md)',
                      color: 'var(--accent)',
                      caretColor: 'var(--accent)',
                      position: 'relative',
                      overflow: 'hidden',
                    }}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.1 }}
                  >
                    <span style={{ color: 'var(--text-muted)', marginRight: 8 }}>$</span>
                    {q.generated_dork}
                  </motion.div>
                </motion.div>

                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.35, ease: 'easeInOut' }}
                      className="mt-3"
                      style={{ overflow: 'hidden' }}
                    >
                      <div
                        className="text-xs"
                        style={{
                          textTransform: 'uppercase',
                          letterSpacing: '0.06em',
                          fontWeight: 600,
                          color: 'var(--text-muted)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: 10,
                          marginBottom: 'var(--space-3)',
                        }}
                      >
                        Search results ({results.length})
                      </div>
                      {results.length === 0 ? (
                        <div
                          className="text-sm"
                          style={{
                            color: 'var(--text-muted)',
                            fontFamily: 'var(--font-mono)',
                            padding: 'var(--space-4)',
                            textAlign: 'center',
                            background: 'rgba(0,0,0,0.2)',
                            borderRadius: 'var(--radius-md)',
                          }}
                        >
                          No search results returned
                        </div>
                      ) : (
                        <ol style={{ listStyle: 'none', paddingLeft: 0 }}>
                          {results.map((r, idx) => (
                            <motion.li
                              key={`${q.id}-${idx}`}
                              initial={{ opacity: 0, x: -12 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: idx * 0.05, type: 'spring' as const, stiffness: 200, damping: 20 }}
                              style={{
                                marginBottom: 'var(--space-3)',
                                padding: 'var(--space-3)',
                                background: 'rgba(0,0,0,0.2)',
                                borderRadius: 'var(--radius-md)',
                                borderLeft: '2px solid var(--accent)',
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
                                <span
                                  style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: 11,
                                    color: 'var(--text-muted)',
                                    minWidth: 20,
                                    marginTop: 2,
                                  }}
                                >
                                  {String(idx + 1).padStart(2, '0')}
                                </span>
                                <div style={{ flex: 1 }}>
                                  <div style={{ fontWeight: 500 }}>
                                    <a
                                      href={r.link || r.url || '#'}
                                      target="_blank"
                                      rel="noreferrer noopener"
                                      style={{
                                        color: 'var(--accent)',
                                        textDecoration: 'none',
                                        fontWeight: 600,
                                      }}
                                    >
                                      {r.title || '(untitled)'}
                                    </a>
                                    <a
                                      href={r.link || r.url || '#'}
                                      target="_blank"
                                      rel="noreferrer noopener"
                                      style={{
                                        color: 'var(--text-muted)',
                                        marginLeft: 8,
                                        display: 'inline-flex',
                                      }}
                                      title="Open in new tab"
                                    >
                                      <ExternalLink size={12} />
                                    </a>
                                  </div>
                                  <div
                                    className="text-xs"
                                    style={{
                                      color: 'var(--text-muted)',
                                      fontFamily: 'var(--font-mono)',
                                      wordBreak: 'break-all',
                                      marginTop: 2,
                                    }}
                                  >
                                    {r.link || r.url}
                                  </div>
                                  {r.snippet && (
                                    <div
                                      className="text-sm"
                                      style={{
                                        color: 'var(--text)',
                                        marginTop: 'var(--space-2)',
                                        lineHeight: 1.5,
                                      }}
                                    >
                                      {r.snippet}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </motion.li>
                          ))}
                        </ol>
                      )}
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.article>
            );
          })}
        </AnimatePresence>
      </motion.div>
    </motion.div>
  );
}

function extractError(err: unknown): string {
  if (typeof err === 'object' && err !== null) {
    const e = err as { response?: { data?: { detail?: string } }; message?: string };
    if (e.response?.data?.detail) return e.response.data.detail;
    if (e.message) return e.message;
  }
  return 'Something went wrong';
}

export default AIAssistant;
