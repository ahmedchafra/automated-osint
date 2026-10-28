import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Radio, Eye, EyeOff, Loader2, AlertCircle, ChevronRight, Clock } from 'lucide-react';
import { useAuth } from '../context/auth-state';
import { errorMessage } from '../utils/errors';

export default function Register() {
  const { register } = useAuth();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [registered, setRegistered] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');

    // Client-side validation
    if (!username.trim() || !email.trim() || !password) {
      setError('All fields are required.');
      return;
    }
    if (username.trim().length < 3) {
      setError('Username must be at least 3 characters.');
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setError('Please enter a valid email address.');
      return;
    }
    if (password.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }

    setIsSubmitting(true);
    try {
      await register(username.trim(), email.trim(), password);
      // Show pending approval message instead of redirecting
      setRegistered(true);
    } catch (err: unknown) {
      setError(errorMessage(err, 'Registration failed. Please try again.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (registered) {
    return (
      <div className="auth-page">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
          className="auth-card"
        >
          {/* Brand */}
          <div className="auth-brand">
            <div className="auth-logo">
              <Radio size={22} color="#06b6d4" />
            </div>
            <span className="auth-title">
              OWL<span style={{ color: '#71717a', fontWeight: 400 }}>OSINT</span>
            </span>
          </div>

          <div style={{ textAlign: 'center', padding: '1.5rem 0' }}>
            <div style={{
              width: 56, height: 56, borderRadius: '50%',
              background: 'rgba(6,182,212,0.10)',
              border: '1px solid rgba(6,182,212,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              margin: '0 auto 1.25rem',
            }}>
              <Clock size={28} color="#06b6d4" />
            </div>
            <h1 className="auth-heading">Account Created</h1>
            <p style={{
              color: 'var(--text-muted)', fontSize: 'var(--text-sm)',
              lineHeight: 1.6, maxWidth: 360, margin: '0 auto',
            }}>
              Your account has been created and is pending administrator approval.
              You will be able to log in once an administrator activates your account.
            </p>
            <Link
              to="/login"
              className="btn btn-primary"
              style={{ marginTop: '1.5rem', display: 'inline-flex' }}
            >
              <span>Return to Login</span>
              <ChevronRight size={16} />
            </Link>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className="auth-card"
      >
        {/* Brand */}
        <div className="auth-brand">
          <div className="auth-logo">
            <Radio size={22} color="#06b6d4" />
          </div>
          <span className="auth-title">
            OWL<span style={{ color: '#71717a', fontWeight: 400 }}>OSINT</span>
          </span>
        </div>

        <h1 className="auth-heading">Create Account</h1>
        <p className="auth-subtitle">
          Register to start performing OSINT scans.
        </p>

        {error && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="auth-error"
          >
            <AlertCircle size={14} />
            <span>{error}</span>
          </motion.div>
        )}

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="auth-field">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              placeholder="Choose a username (3-50 chars)"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              autoComplete="username"
              disabled={isSubmitting}
              maxLength={50}
              minLength={3}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              disabled={isSubmitting}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="password">Password</label>
            <div className="password-wrapper">
              <input
                id="password"
                type={showPw ? 'text' : 'password'}
                placeholder="At least 12 characters"
                minLength={12}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                disabled={isSubmitting}
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPw((s) => !s)}
                tabIndex={-1}
                aria-label={showPw ? 'Hide password' : 'Show password'}
              >
                {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <div className="auth-field">
            <label htmlFor="confirm">Confirm Password</label>
            <input
              id="confirm"
              type="password"
              placeholder="Re-enter your password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              disabled={isSubmitting}
            />
          </div>

          <button
            type="submit"
            className="auth-submit"
            disabled={isSubmitting}
          >
            {isSubmitting ? (
              <>
                <Loader2 size={16} className="spinner" />
                Creating account…
              </>
            ) : (
              <>
                <span>Create Account</span>
                <ChevronRight size={16} />
              </>
            )}
          </button>
        </form>

        <p className="auth-footer">
          Already have an account?{' '}
          <Link to="/login">Sign in</Link>
        </p>
      </motion.div>
    </div>
  );
}
