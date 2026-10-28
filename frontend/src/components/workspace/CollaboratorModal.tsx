import { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X, UserPlus, UserMinus, Shield, ShieldCheck, Search,
  Loader2, AlertCircle, CheckCircle2, Mail,
} from 'lucide-react';
import apiClient from '../../api/client';
import { errorMessage } from '../../utils/errors';

/* ─── Types ─────────────────────────────────────────────────────────── */

interface Collaborator {
  id: string;
  scan_id: string;
  user_id: string;
  username: string;
  permission: 'read' | 'modify';
  created_at: string;
}

interface SearchUser {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
}

interface CollaboratorModalProps {
  scanId: string;
  currentUserId: string;
  isOpen: boolean;
  onClose: () => void;
}

/* ─── Modal Overlay ─────────────────────────────────────────────────── */

function Overlay({ onClick }: { onClick: () => void }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.15 }}
      onClick={onClick}
      style={{
        position: 'fixed', inset: 0, zIndex: 999,
        background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)',
      }}
    />
  );
}

/* ─── Main Component ────────────────────────────────────────────────── */

export default function CollaboratorModal({ scanId, currentUserId, isOpen, onClose }: CollaboratorModalProps) {
  const [collaborators, setCollaborators] = useState<Collaborator[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchUser[]>([]);
  const [searching, setSearching] = useState(false);
  const [adding, setAdding] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Load current collaborators
  const loadCollaborators = useCallback(async () => {
    try {
      const { data } = await apiClient.get(`/scans/${scanId}/collaborators`);
      setCollaborators(data);
    } catch {
      // silently fail — the modal will just show empty
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    if (!isOpen) return;
    const initializeTimer = setTimeout(() => {
      setLoading(true);
      setMsg(null);
      setSearchQuery('');
      setSearchResults([]);
      void loadCollaborators();
    }, 0);
    const focusTimer = setTimeout(() => searchInputRef.current?.focus(), 200);
    return () => {
      clearTimeout(initializeTimer);
      clearTimeout(focusTimer);
    };
  }, [isOpen, loadCollaborators]);

  // Debounced user search
  const handleSearch = useCallback((value: string) => {
    setSearchQuery(value);
    if (debounceRef.current) clearTimeout(debounceRef.current);

    if (value.trim().length < 2) {
      setSearchResults([]);
      return;
    }

    debounceRef.current = setTimeout(async () => {
      setSearching(true);
      try {
        const { data } = await apiClient.get(`/users/search?q=${encodeURIComponent(value.trim())}&limit=8`);
        // Exclude current collaborators and the current user
        const collabUserIds = new Set(collaborators.map(c => c.user_id));
        collabUserIds.add(currentUserId);
        setSearchResults(data.filter((u: SearchUser) => !collabUserIds.has(u.id)));
      } catch {
        setSearchResults([]);
      } finally {
        setSearching(false);
      }
    }, 250);
  }, [collaborators, currentUserId]);

  // Add collaborator
  const handleAdd = async (userId: string, username: string, permission: 'read' | 'modify') => {
    setAdding(userId);
    setMsg(null);
    try {
      await apiClient.post(`/scans/${scanId}/collaborators`, {
        user_id: userId,
        permission,
      });
      setMsg({ ok: true, text: `Added ${username} as ${permission}` });
      setSearchResults(prev => prev.filter(u => u.id !== userId));
      await loadCollaborators();
    } catch (err: unknown) {
      setMsg({ ok: false, text: errorMessage(err, 'Failed to add collaborator') });
    } finally {
      setAdding(null);
    }
    setTimeout(() => setMsg(null), 3000);
  };

  // Update permission
  const handleUpdatePermission = async (userId: string, username: string, newPermission: 'read' | 'modify') => {
    setMsg(null);
    try {
      await apiClient.patch(`/scans/${scanId}/collaborators/${userId}`, {
        user_id: userId,
        permission: newPermission,
      });
      setMsg({ ok: true, text: `Changed ${username} to ${newPermission}` });
      await loadCollaborators();
    } catch (err: unknown) {
      setMsg({ ok: false, text: errorMessage(err, 'Failed to update permission') });
    }
    setTimeout(() => setMsg(null), 3000);
  };

  // Remove collaborator
  const handleRemove = async (userId: string, username: string) => {
    if (!window.confirm(`Remove ${username} from this scan?`)) return;
    setMsg(null);
    try {
      await apiClient.delete(`/scans/${scanId}/collaborators/${userId}`);
      setMsg({ ok: true, text: `Removed ${username}` });
      await loadCollaborators();
    } catch (err: unknown) {
      setMsg({ ok: false, text: errorMessage(err, 'Failed to remove collaborator') });
    }
    setTimeout(() => setMsg(null), 3000);
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <Overlay onClick={onClose} />
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
            style={{
              position: 'fixed', zIndex: 1000,
              top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
              width: 'min(480px, calc(100vw - 32px))',
              maxHeight: 'calc(100vh - 64px)',
              background: '#18181b', borderRadius: 16,
              border: '1px solid rgba(255,255,255,0.08)',
              boxShadow: '0 24px 80px rgba(0,0,0,0.5)',
              display: 'flex', flexDirection: 'column',
            }}
          >
            {/* Header */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '18px 20px 14px', borderBottom: '1px solid rgba(255,255,255,0.06)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Shield size={18} style={{ color: 'var(--accent)' }} />
                <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-strong)' }}>
                  Manage Access
                </span>
              </div>
              <button
                onClick={onClose}
                style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: '#71717a', padding: 4, borderRadius: 6,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}
                onMouseEnter={e => e.currentTarget.style.color = '#fff'}
                onMouseLeave={e => e.currentTarget.style.color = '#71717a'}
              >
                <X size={18} />
              </button>
            </div>

            {/* Body */}
            <div style={{ padding: '16px 20px 20px', overflowY: 'auto', flex: 1 }}>

              {/* Status messages */}
              {msg && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  style={{
                    marginBottom: 12, padding: '8px 12px', borderRadius: 8,
                    display: 'flex', alignItems: 'center', gap: 8, fontSize: 12,
                    background: msg.ok ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
                    border: `1px solid ${msg.ok ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
                    color: msg.ok ? '#10b981' : '#ef4444',
                  }}
                >
                  {msg.ok ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}
                  <span>{msg.text}</span>
                </motion.div>
              )}

              {/* Search to add users */}
              <div style={{ marginBottom: 16 }}>
                <label style={{
                  display: 'block', fontSize: 11, fontWeight: 500,
                  color: '#a1a1aa', marginBottom: 6, textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                }}>
                  Add People
                </label>
                <div style={{ position: 'relative' }}>
                  <Search size={14} style={{
                    position: 'absolute', left: 10, top: '50%',
                    transform: 'translateY(-50%)', color: '#52525b',
                    pointerEvents: 'none',
                  }} />
                  <input
                    ref={searchInputRef}
                    type="text"
                    placeholder="Search by username…"
                    value={searchQuery}
                    onChange={e => handleSearch(e.target.value)}
                    style={{
                      width: '100%', padding: '9px 32px 9px 32px',
                      background: 'rgba(255,255,255,0.04)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      borderRadius: 8, color: '#fff', fontSize: 13,
                      outline: 'none',
                    }}
                  />
                  {searching && (
                    <Loader2 size={14} className="spin" style={{
                      position: 'absolute', right: 10, top: '50%',
                      transform: 'translateY(-50%)', color: '#71717a',
                    }} />
                  )}
                </div>

                {/* Search results */}
                {searchResults.length > 0 && (
                  <motion.div
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    style={{
                      marginTop: 6, borderRadius: 8,
                      border: '1px solid rgba(255,255,255,0.06)',
                      overflow: 'hidden',
                    }}
                  >
                    {searchResults.map(user => (
                      <div
                        key={user.id}
                        style={{
                          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                          padding: '8px 12px',
                          borderBottom: '1px solid rgba(255,255,255,0.04)',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                          <div style={{
                            width: 26, height: 26, borderRadius: '50%',
                            background: 'rgba(6,182,212,0.12)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            flexShrink: 0,
                          }}>
                            <Mail size={12} style={{ color: 'var(--accent)' }} />
                          </div>
                          <div style={{ minWidth: 0 }}>
                            <div style={{ fontSize: 13, fontWeight: 500, color: '#e4e4e7' }}>
                              {user.username}
                            </div>
                            <div style={{ fontSize: 11, color: '#71717a', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {user.email}
                            </div>
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                          <button
                            className="btn btn-primary"
                            style={{ padding: '3px 8px', fontSize: 10 }}
                            onClick={() => handleAdd(user.id, user.username, 'read')}
                            disabled={adding === user.id}
                          >
                            {adding === user.id ? <Loader2 size={10} className="spin" /> : 'Read'}
                          </button>
                          <button
                            className="btn btn-primary"
                            style={{ padding: '3px 8px', fontSize: 10 }}
                            onClick={() => handleAdd(user.id, user.username, 'modify')}
                            disabled={adding === user.id}
                          >
                            {adding === user.id ? <Loader2 size={10} className="spin" /> : 'Modify'}
                          </button>
                        </div>
                      </div>
                    ))}
                  </motion.div>
                )}
                {searchQuery.trim().length >= 2 && !searching && searchResults.length === 0 && (
                  <div style={{ padding: '8px 0', fontSize: 12, color: '#71717a', textAlign: 'center' }}>
                    No users found matching "{searchQuery}"
                  </div>
                )}
              </div>

              {/* Current collaborators */}
              <div>
                <label style={{
                  display: 'block', fontSize: 11, fontWeight: 500,
                  color: '#a1a1aa', marginBottom: 8, textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                }}>
                  People with Access
                </label>
                {loading ? (
                  <div style={{ display: 'flex', justifyContent: 'center', padding: 20 }}>
                    <Loader2 size={18} className="spin" style={{ color: '#71717a' }} />
                  </div>
                ) : collaborators.length === 0 ? (
                  <div style={{
                    padding: '16px', textAlign: 'center', fontSize: 12,
                    color: '#71717a', borderRadius: 8,
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px dashed rgba(255,255,255,0.06)',
                  }}>
                    No collaborators yet. Search for users above to grant access.
                  </div>
                ) : (
                  <div style={{
                    borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)',
                    overflow: 'hidden',
                  }}>
                    {collaborators.map(collab => (
                      <div
                        key={collab.id}
                        style={{
                          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                          padding: '8px 12px',
                          borderBottom: '1px solid rgba(255,255,255,0.04)',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                          <div style={{
                            width: 26, height: 26, borderRadius: '50%',
                            background: 'rgba(6,182,212,0.12)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            flexShrink: 0,
                          }}>
                            <UserPlus size={12} style={{ color: 'var(--accent)' }} />
                          </div>
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 500, color: '#e4e4e7' }}>
                              {collab.username}
                            </div>
                            <div style={{ fontSize: 11, color: '#71717a' }}>
                              {collab.permission === 'modify' ? 'Can modify' : 'Can read'}
                            </div>
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                          {/* Toggle permission */}
                          <button
                            className="btn btn-secondary"
                            style={{
                              padding: '3px 8px', fontSize: 10,
                              color: collab.permission === 'modify' ? '#06b6d4' : '#a1a1aa',
                            }}
                            onClick={() => handleUpdatePermission(
                              collab.user_id,
                              collab.username,
                              collab.permission === 'read' ? 'modify' : 'read',
                            )}
                            title={collab.permission === 'read' ? 'Upgrade to modify' : 'Downgrade to read'}
                          >
                            <ShieldCheck size={10} />
                            <span>{collab.permission === 'read' ? '→ modify' : '→ read'}</span>
                          </button>
                          <button
                            className="btn btn-secondary"
                            style={{
                              padding: '3px 8px', fontSize: 10,
                              color: '#ef4444', borderColor: 'rgba(239,68,68,0.3)',
                            }}
                            onClick={() => handleRemove(collab.user_id, collab.username)}
                            title="Remove collaborator"
                          >
                            <UserMinus size={10} />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Footer */}
            <div style={{
              padding: '12px 20px', borderTop: '1px solid rgba(255,255,255,0.06)',
              display: 'flex', justifyContent: 'flex-end',
            }}>
              <button
                className="btn btn-secondary"
                onClick={onClose}
                style={{ padding: '8px 16px', fontSize: 12 }}
              >
                Done
              </button>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
