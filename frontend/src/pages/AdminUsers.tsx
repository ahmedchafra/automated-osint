import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Shield, UserCog, Loader2, AlertTriangle, CheckCircle2,
  ShieldAlert, ShieldCheck, ToggleLeft, ToggleRight,
  Clock, UserPlus, Trash2,
} from 'lucide-react';
import apiClient from '../api/client';

interface UserRow {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export default function AdminUsers() {
  const queryClient = useQueryClient();
  const [actionMsg, setActionMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [deletingUser, setDeletingUser] = useState<string | null>(null);

  const { data: users, isLoading, error } = useQuery({
    queryKey: ['adminUsers'],
    queryFn: async () => {
      const res = await apiClient.get('/admin/users');
      return res.data as UserRow[];
    },
    refetchInterval: 15_000,
  });

  const { data: pendingUsers } = useQuery({
    queryKey: ['adminPendingUsers'],
    queryFn: async () => {
      const res = await apiClient.get('/admin/users/pending');
      return res.data as UserRow[];
    },
    refetchInterval: 10_000,
  });

  const handleToggleRole = async (userId: string, currentRole: string) => {
    const newRole = currentRole === 'admin' ? 'user' : 'admin';
    setActionMsg(null);
    try {
      await apiClient.patch(`/admin/users/${userId}/role`, { role: newRole });
      queryClient.invalidateQueries({ queryKey: ['adminUsers'] });
      setActionMsg({ ok: true, text: `Role changed to ${newRole}` });
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to update role';
      setActionMsg({ ok: false, text: detail });
    }
    setTimeout(() => setActionMsg(null), 4000);
  };

  const handleToggleStatus = async (userId: string, currentStatus: boolean) => {
    setActionMsg(null);
    try {
      await apiClient.patch(`/admin/users/${userId}/status`, { is_active: !currentStatus });
      queryClient.invalidateQueries({ queryKey: ['adminUsers'] });
      queryClient.invalidateQueries({ queryKey: ['adminPendingUsers'] });
      setActionMsg({
        ok: true,
        text: `User ${currentStatus ? 'deactivated' : 'activated'}`,
      });
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to update status';
      setActionMsg({ ok: false, text: detail });
    }
    setTimeout(() => setActionMsg(null), 4000);
  };

  const handleApprove = async (userId: string) => {
    setActionMsg(null);
    try {
      await apiClient.post(`/admin/users/${userId}/approve`);
      queryClient.invalidateQueries({ queryKey: ['adminUsers'] });
      queryClient.invalidateQueries({ queryKey: ['adminPendingUsers'] });
      setActionMsg({ ok: true, text: 'User approved and activated' });
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to approve user';
      setActionMsg({ ok: false, text: detail });
    }
    setTimeout(() => setActionMsg(null), 4000);
  };

  const handleDeleteUser = async (userId: string) => {
    setDeletingUser(userId);
    setActionMsg(null);
    try {
      await apiClient.delete(`/admin/users/${userId}`);
      queryClient.invalidateQueries({ queryKey: ['adminUsers'] });
      queryClient.invalidateQueries({ queryKey: ['adminPendingUsers'] });
      setActionMsg({ ok: true, text: 'User deleted' });
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to delete user';
      setActionMsg({ ok: false, text: detail });
    } finally {
      setDeletingUser(null);
    }
    setTimeout(() => setActionMsg(null), 4000);
  };

  if (isLoading) {
    return (
      <div className="ws-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          style={{
            width: 40, height: 40, borderRadius: '50%',
            border: '3px solid var(--surface-4)', borderTopColor: 'var(--accent)',
          }}
        />
      </div>
    );
  }

  if (error) {
    return (
      <div className="ws-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <div className="card card-glow-critical" style={{ textAlign: 'center', maxWidth: 420 }}>
          <AlertTriangle size={32} style={{ color: 'var(--severity-critical)', marginBottom: 'var(--space-3)' }} />
          <h2 style={{ color: 'var(--text-strong)', marginBottom: 'var(--space-2)' }}>Access Denied</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
            Only administrators can manage users.
          </p>
        </div>
      </div>
    );
  }

  const userList = users || [];
  const pendingList = pendingUsers || [];

  return (
    <motion.div
      className="ws-container"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      <div className="ws-header">
        <div className="ws-header-left">
          <Shield size={20} style={{ color: 'var(--accent)' }} />
          <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', color: 'var(--text-strong)' }}>
            User Management
          </h1>
        </div>
        <span style={{
          padding: '4px 12px', borderRadius: 'var(--radius-full)',
          background: 'rgba(6,182,212,0.10)', border: '1px solid rgba(6,182,212,0.2)',
          color: '#06b6d4', fontSize: 11, fontFamily: 'JetBrains Mono, monospace',
        }}>
          {userList.length} user{userList.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Action feedback */}
      {actionMsg && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          style={{
            marginBottom: 16, padding: '8px 14px', borderRadius: 'var(--radius-lg)',
            display: 'flex', alignItems: 'center', gap: 8, fontSize: 12,
            background: actionMsg.ok ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
            border: `1px solid ${actionMsg.ok ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)'}`,
            color: actionMsg.ok ? '#10b981' : '#ef4444',
          }}
        >
          {actionMsg.ok ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
          <span>{actionMsg.text}</span>
        </motion.div>
      )}

      {/* Pending Approvals Section */}
      {pendingList.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div className="ws-header" style={{ marginBottom: 12 }}>
            <div className="ws-header-left">
              <Clock size={16} style={{ color: '#fb923c' }} />
              <h2 style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-strong)' }}>
                Pending Approvals
              </h2>
            </div>
            <span className="badge badge-warning">{pendingList.length} pending</span>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Registered</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {pendingList.map(user => (
                  <tr key={user.id}>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-strong)', fontSize: 'var(--text-sm)' }}>
                        {user.username}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
                      {user.email}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
                      {user.created_at
                        ? new Date(user.created_at).toLocaleDateString()
                        : '—'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                        <button
                          className="btn btn-primary"
                          style={{ padding: '4px 12px', fontSize: 'var(--text-xs)' }}
                          onClick={() => handleApprove(user.id)}
                        >
                          <UserPlus size={12} />
                          <span>Approve</span>
                        </button>
                        <button
                          className="btn btn-secondary"
                          style={{
                            padding: '4px 8px', fontSize: 'var(--text-xs)',
                            color: '#ef4444', borderColor: 'rgba(239,68,68,0.3)',
                          }}
                          onClick={() => handleDeleteUser(user.id)}
                          disabled={deletingUser === user.id}
                          title="Delete user"
                        >
                          {deletingUser === user.id ? (
                            <Loader2 size={12} className="spin" />
                          ) : (
                            <Trash2 size={12} />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* All Users Section */}
      <div className="ws-header" style={{ marginBottom: 12 }}>
        <div className="ws-header-left">
          <UserCog size={16} style={{ color: 'var(--accent)' }} />
          <h2 style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-strong)' }}>
            All Users
          </h2>
        </div>
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {userList.map(user => (
              <tr key={user.id}>
                <td>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-strong)', fontSize: 'var(--text-sm)' }}>
                    {user.username}
                  </span>
                </td>
                <td style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
                  {user.email}
                </td>
                <td>
                  <span className={`badge ${user.role === 'admin' ? 'badge-accent' : 'badge-info'}`}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}
                  >
                    {user.role === 'admin' ? <ShieldAlert size={10} /> : <UserCog size={10} />}
                    {user.role}
                  </span>
                </td>
                <td>
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    padding: '2px 8px', borderRadius: 12, fontSize: 11, fontWeight: 500,
                    background: user.is_active ? 'rgba(16,185,129,0.10)' : 'rgba(113,113,122,0.10)',
                    color: user.is_active ? '#10b981' : '#71717a',
                    border: `1px solid ${user.is_active ? 'rgba(16,185,129,0.2)' : 'rgba(113,113,122,0.2)'}`,
                  }}>
                    {user.is_active ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
                  {user.created_at
                    ? new Date(user.created_at).toLocaleDateString()
                    : '—'}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: 'var(--text-xs)' }}
                      onClick={() => handleToggleRole(user.id, user.role)}
                      title={user.role === 'admin' ? 'Demote to user' : 'Promote to admin'}
                    >
                      {user.role === 'admin' ? <UserCog size={12} /> : <ShieldCheck size={12} />}
                    </button>
                    <button
                      className="btn btn-secondary"
                      style={{
                        padding: '4px 8px', fontSize: 'var(--text-xs)',
                        color: user.is_active ? '#fb923c' : '#10b981',
                      }}
                      onClick={() => handleToggleStatus(user.id, user.is_active)}
                      title={user.is_active ? 'Deactivate user' : 'Activate user'}
                    >
                      {user.is_active ? <ToggleRight size={12} /> : <ToggleLeft size={12} />}
                    </button>
                    <button
                      className="btn btn-secondary"
                      style={{
                        padding: '4px 8px', fontSize: 'var(--text-xs)',
                        color: '#ef4444', borderColor: 'rgba(239,68,68,0.3)',
                      }}
                      onClick={() => handleDeleteUser(user.id)}
                      disabled={deletingUser === user.id}
                      title="Delete user"
                    >
                      {deletingUser === user.id ? (
                        <Loader2 size={12} className="spin" />
                      ) : (
                        <Trash2 size={12} />
                      )}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.div>
  );
}
