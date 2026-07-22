import { useState, type FormEvent } from 'react';
import { motion } from 'framer-motion';
import {
  User,
  Mail,
  Shield,
  Calendar,
  Lock,
  Eye,
  EyeOff,
  Loader2,
  CheckCircle2,
  AlertCircle,
  ChevronRight,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import apiClient from '../api/client';
import { useQuery } from '@tanstack/react-query';

export default function Settings() {
  const { user } = useAuth();

  /* ── Change password state ──────────────────────────────── */
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showOld, setShowOld] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);

  /* ── Profile load ────────────────────────────────────────── */
  const { data: profile, isLoading: profileLoading } = useQuery({
    queryKey: ['userProfile'],
    queryFn: async () => {
      const res = await apiClient.get('/auth/me');
      return res.data as {
        id: string;
        username: string;
        email: string;
        role: string;
        is_active: boolean;
        created_at: string | null;
      };
    },
    staleTime: 60_000,
  });

  const handlePasswordChange = async (e: FormEvent) => {
    e.preventDefault();
    setPwMsg(null);

    if (!oldPassword) {
      setPwMsg({ ok: false, text: 'Current password is required.' });
      return;
    }
    if (newPassword.length < 6) {
      setPwMsg({ ok: false, text: 'New password must be at least 6 characters.' });
      return;
    }
    if (newPassword !== confirmPassword) {
      setPwMsg({ ok: false, text: 'Passwords do not match.' });
      return;
    }

    setSubmitting(true);
    try {
      await apiClient.post('/auth/change-password', {
        old_password: oldPassword,
        new_password: newPassword,
      });
      setPwMsg({ ok: true, text: 'Password updated successfully.' });
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to update password.';
      setPwMsg({ ok: false, text: detail });
    } finally {
      setSubmitting(false);
    }
  };

  /* ── Role badge color ────────────────────────────────────── */
  const roleBadgeStyle: Record<string, { bg: string; border: string; color: string }> = {
    admin: { bg: 'rgba(6,182,212,0.10)', border: 'rgba(6,182,212,0.2)', color: '#06b6d4' },
    user: { bg: 'rgba(113,113,122,0.10)', border: 'rgba(113,113,122,0.2)', color: '#a1a1aa' },
  };

  const badge = roleBadgeStyle[profile?.role || 'user'] || roleBadgeStyle.user;

  return (
    <motion.div
      className="ws-container"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      {/* ── Header ────────────────────────────────────────────── */}
      <div className="ws-header">
        <div className="ws-header-left">
          <User size={20} style={{ color: 'var(--accent)' }} />
          <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', color: 'var(--text-strong)' }}>
            Settings
          </h1>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, maxWidth: 900 }}>

        {/* ── Account Info Card ────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="card"
          style={{ padding: 0, overflow: 'hidden' }}
        >
          <div style={{
            padding: '14px 20px', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <User size={16} style={{ color: 'var(--accent)' }} />
            <h2 style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-strong)' }}>
              Account Information
            </h2>
          </div>

          {profileLoading ? (
            <div style={{ padding: 32, display: 'flex', justifyContent: 'center' }}>
              <Loader2 size={20} className="spinner" style={{ color: 'var(--text-muted)' }} />
            </div>
          ) : (
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Username */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: '50%',
                  background: 'var(--accent-soft)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  <User size={16} style={{ color: 'var(--accent)' }} />
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 1 }}>Username</div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-strong)', fontFamily: 'var(--font-mono)' }}>
                    {profile?.username}
                  </div>
                </div>
              </div>

              {/* Email */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: '50%',
                  background: 'rgba(59,130,246,0.10)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  <Mail size={16} style={{ color: '#3b82f6' }} />
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 1 }}>Email</div>
                  <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-strong)' }}>
                    {profile?.email}
                  </div>
                </div>
              </div>

              {/* Role */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: '50%',
                  background: badge.bg,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                  border: `1px solid ${badge.border}`,
                }}>
                  <Shield size={16} style={{ color: badge.color }} />
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 1 }}>Role</div>
                  <span style={{
                    padding: '2px 10px', borderRadius: 'var(--radius-full)',
                    background: badge.bg, border: `1px solid ${badge.border}`,
                    color: badge.color, fontSize: 11, fontWeight: 600,
                    fontFamily: 'var(--font-mono)', textTransform: 'capitalize',
                  }}>
                    {profile?.role}
                  </span>
                </div>
              </div>

              {/* Created */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: '50%',
                  background: 'rgba(16,185,129,0.10)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  <Calendar size={16} style={{ color: '#10b981' }} />
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 1 }}>Member Since</div>
                  <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-strong)' }}>
                    {profile?.created_at
                      ? new Date(profile.created_at).toLocaleDateString('en-US', {
                          year: 'numeric', month: 'long', day: 'numeric',
                        })
                      : '—'}
                  </div>
                </div>
              </div>
            </div>
          )}
        </motion.div>

        {/* ── Change Password Card ─────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: 0.1 }}
          className="card"
          style={{ padding: 0, overflow: 'hidden' }}
        >
          <div style={{
            padding: '14px 20px', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <Lock size={16} style={{ color: 'var(--accent)' }} />
            <h2 style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-strong)' }}>
              Change Password
            </h2>
          </div>

          <form onSubmit={handlePasswordChange} style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Message banner */}
            {pwMsg && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                style={{
                  padding: '8px 12px', borderRadius: 'var(--radius-lg)',
                  display: 'flex', alignItems: 'center', gap: 8, fontSize: 12,
                  background: pwMsg.ok ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
                  border: `1px solid ${pwMsg.ok ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)'}`,
                  color: pwMsg.ok ? '#10b981' : '#ef4444',
                }}
              >
                {pwMsg.ok ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}
                <span>{pwMsg.text}</span>
              </motion.div>
            )}

            {/* Current password */}
            <div className="auth-field">
              <label htmlFor="old-password">Current Password</label>
              <div className="password-wrapper">
                <input
                  id="old-password"
                  type={showOld ? 'text' : 'password'}
                  placeholder="Enter current password"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  disabled={submitting}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowOld((s) => !s)}
                  tabIndex={-1}
                  aria-label={showOld ? 'Hide password' : 'Show password'}
                >
                  {showOld ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* New password */}
            <div className="auth-field">
              <label htmlFor="new-password">New Password</label>
              <div className="password-wrapper">
                <input
                  id="new-password"
                  type={showNew ? 'text' : 'password'}
                  placeholder="At least 6 characters"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  disabled={submitting}
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowNew((s) => !s)}
                  tabIndex={-1}
                  aria-label={showNew ? 'Hide password' : 'Show password'}
                >
                  {showNew ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Confirm new password */}
            <div className="auth-field">
              <label htmlFor="confirm-password">Confirm New Password</label>
              <input
                id="confirm-password"
                type="password"
                placeholder="Re-enter new password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={submitting}
                autoComplete="new-password"
              />
            </div>

            <button
              type="submit"
              className="auth-submit"
              disabled={submitting}
              style={{ width: '100%' }}
            >
              {submitting ? (
                <>
                  <Loader2 size={16} className="spinner" />
                  Updating password…
                </>
              ) : (
                <>
                  <span>Update Password</span>
                  <ChevronRight size={16} />
                </>
              )}
            </button>
          </form>
        </motion.div>

      </div>
    </motion.div>
  );
}
