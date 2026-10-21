import { BrowserRouter, Routes, Route, Link, useLocation, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, LayoutDashboard, PlusCircle, Search, Zap, Radio, ChevronRight, Shield, Sliders } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanHistory from './pages/ScanHistory';
import ScanWorkspace from './pages/ScanWorkspace';
import ScanDetails from './pages/ScanDetails';
import Settings from './pages/Settings';
import AIAssistant from './pages/AIAssistant';
import EntityGraph from './pages/EntityGraph';
import Login from './pages/Login';
import Register from './pages/Register';
import AdminUsers from './pages/AdminUsers';
import ProtectedRoute from './components/ProtectedRoute';
import AdminRoute from './components/AdminRoute';
import { ScanWorkspaceProvider } from './context/ScanWorkspaceContext';
import { AuthProvider } from './context/AuthContext';
import { NotificationProvider } from './context/NotificationContext';
import { NotificationToast } from './components/NotificationToast';
import { useAuth } from './context/AuthContext';

const queryClient = new QueryClient();

function Sidebar({ user, onLogout }: { user?: any; onLogout?: () => void }) {
  const location = useLocation();
  const navItems = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/scans/new', label: 'New Scan', icon: PlusCircle },
    { to: '/scans', label: 'Scan History', icon: Search },
    { to: '/assistant', label: 'AI Assistant', icon: Zap },
    { to: '/settings', label: 'Settings', icon: Sliders },
    { to: '/graph', label: 'Entity Graph', icon: Activity },
  ];
  if (user?.role === 'admin') {
    navItems.push({ to: '/admin/users', label: 'Admin', icon: Shield });
  }

  return (
    <motion.aside
      initial={{ x: -60, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="sidebar"
    >
      <div className="sidebar-header">
        <div style={{
          width: 28, height: 28, borderRadius: 6,
          background: 'linear-gradient(135deg, var(--accent), #0891b2)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 0 12px rgba(6,182,212,0.25)'
        }}>
          <Radio size={14} color="#fff" />
        </div>
        <span>OWL<span style={{ color: '#71717a', fontWeight: 400, marginLeft: 4 }}>OSINT</span></span>
      </div>
      <nav className="sidebar-nav">
        {navItems.map(({ to, label, icon: Icon }) => {
          const isActive = to === '/'
            ? location.pathname === '/'
            : location.pathname.startsWith(to) && (to !== '/scans' || location.pathname === '/scans');
          return (
            <Link
              key={to}
              to={to}
              className={`nav-link ${isActive ? 'active' : ''}`}
            >
              <Icon size={18} />
              {label}
            </Link>
          );
        })}
      </nav>
      <div style={{ marginTop: 'auto', padding: '0.75rem 1rem', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
        {user ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
              <span className="ws-pulse ws-pulse-online" />
              <span style={{
                fontSize: 11, color: '#a1a1aa', fontFamily: 'JetBrains Mono, monospace',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>
                {user.username}
              </span>
            </div>
            <button
              onClick={onLogout}
              title="Sign out"
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                color: '#71717a', padding: '2px 6px', borderRadius: 4,
                fontSize: 11, fontFamily: 'JetBrains Mono, monospace',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = '#f43f5e')}
              onMouseLeave={(e) => (e.currentTarget.style.color = '#71717a')}
            >
              logout
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="ws-pulse ws-pulse-online" />
            <span style={{ fontSize: 11, color: '#71717a', fontFamily: 'JetBrains Mono, monospace' }}>
              SYSTEM ONLINE
            </span>
          </div>
        )}
      </div>
    </motion.aside>
  );
}

function Topbar() {
  return (
    <header className="topbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <ChevronRight size={14} color="var(--text-muted)" />
        <span style={{ fontSize: '0.8125rem', color: '#71717a', fontFamily: 'JetBrains Mono, monospace' }}>
          COMMAND CENTER v2.0
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="ws-pulse ws-pulse-online" />
          <span style={{ fontSize: 11, color: '#10b981', fontFamily: 'JetBrains Mono, monospace' }}>LIVE</span>
        </div>
        <span style={{
          padding: '3px 10px', borderRadius: 'var(--radius-full)',
          background: 'rgba(6,182,212,0.10)', border: '1px solid rgba(6,182,212,0.2)',
          color: '#06b6d4', fontSize: 11, fontFamily: 'JetBrains Mono, monospace',
          letterSpacing: '0.06em'
        }}>
          LOW-IMPACT MODE
        </span>
      </div>
    </header>
  );
}

function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const location = useLocation();
  const isAuthPage = location.pathname === '/login' || location.pathname === '/register';

  if (isAuthPage) {
    return <>{children}</>;
  }

  return (
    <div className="app-container">
      <Sidebar user={user} onLogout={logout} />
      <div className="main-content">
        <Topbar />
        <div className="page-content">
          <AnimatePresence mode="wait">
            <motion.div
              key={typeof children === 'object' ? 'page' : 'loading'}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.25 }}
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

function AppRoutes() {
  return (
    <Layout>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/scans/new" element={<ProtectedRoute><NewScan /></ProtectedRoute>} />
        <Route path="/scans" element={<ProtectedRoute><ScanHistory /></ProtectedRoute>} />
        <Route path="/scans/:id" element={
          <ProtectedRoute>
            <ScanWorkspaceProvider>
              <ScanWorkspace />
            </ScanWorkspaceProvider>
          </ProtectedRoute>
        } />
        <Route path="/scans/:id/details" element={<ProtectedRoute><ScanDetails /></ProtectedRoute>} />
        <Route path="/assistant" element={<ProtectedRoute><AIAssistant /></ProtectedRoute>} />
        <Route path="/assistant/:scanId" element={<ProtectedRoute><AIAssistant /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
        <Route path="/graph" element={<ProtectedRoute><EntityGraph /></ProtectedRoute>} />
        <Route path="/graph/:scanId" element={<ProtectedRoute><EntityGraph /></ProtectedRoute>} />
        <Route path="/admin/users" element={<AdminRoute><AdminUsers /></AdminRoute>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <NotificationProvider>
            <AppRoutes />
            <NotificationToast />
          </NotificationProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
