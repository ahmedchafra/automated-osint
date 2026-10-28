import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Link, useLocation, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, LayoutDashboard, PlusCircle, Search, Zap, Radio, Shield, Sliders } from 'lucide-react';
import ProtectedRoute from './components/ProtectedRoute';
import AdminRoute from './components/AdminRoute';
import { ScanWorkspaceProvider } from './context/ScanWorkspaceContext';
import { AuthProvider } from './context/AuthContext';
import { NotificationProvider } from './context/NotificationContext';
import { NotificationToast } from './components/NotificationToast';
import { useAuth, type User } from './context/auth-state';

const queryClient = new QueryClient();

const Dashboard = lazy(() => import('./pages/Dashboard'));
const NewScan = lazy(() => import('./pages/NewScan'));
const ScanHistory = lazy(() => import('./pages/ScanHistory'));
const ScanWorkspace = lazy(() => import('./pages/ScanWorkspace'));
const ScanDetails = lazy(() => import('./pages/ScanDetails'));
const Settings = lazy(() => import('./pages/Settings'));
const AIAssistant = lazy(() => import('./pages/AIAssistant'));
const EntityGraph = lazy(() => import('./pages/EntityGraph'));
const Login = lazy(() => import('./pages/Login'));
const Register = lazy(() => import('./pages/Register'));
const AdminUsers = lazy(() => import('./pages/AdminUsers'));

function RouteFallback() {
  return (
    <div style={{ minHeight: '40vh', display: 'grid', placeItems: 'center' }}>
      <Activity className="spin" size={24} style={{ color: 'var(--accent)' }} />
    </div>
  );
}

function Sidebar({ user, onLogout }: { user?: User | null; onLogout?: () => void }) {
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
        <div className="brand-mark">
          <Radio size={15} />
        </div>
        <div className="brand-copy">
          <strong>OWL OSINT</strong>
          <span>Investigation platform</span>
        </div>
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
      <div className="sidebar-account">
        {user ? (
          <div className="account-row">
            <div className="account-avatar">{user.username.slice(0, 1).toUpperCase()}</div>
            <div className="account-copy">
              <strong>{user.username}</strong>
              <span>{user.role}</span>
            </div>
            <button
              onClick={onLogout}
              title="Sign out"
              className="account-logout"
            >
              Sign out
            </button>
          </div>
        ) : (
          <div className="account-row">
            <span className="ws-pulse ws-pulse-online" />
            <span>Development environment</span>
          </div>
        )}
      </div>
    </motion.aside>
  );
}

function Topbar() {
  const location = useLocation();
  const pathname = location.pathname;
  const title = pathname === '/' ? 'Dashboard'
    : pathname === '/scans/new' ? 'New investigation'
      : pathname === '/scans' ? 'Scan history'
        : pathname.includes('/details') ? 'Scan details'
          : pathname.startsWith('/scans/') ? 'Investigation workspace'
            : pathname.startsWith('/assistant') ? 'AI assistant'
              : pathname.startsWith('/graph') ? 'Entity graph'
                : pathname.startsWith('/settings') ? 'Settings'
                  : pathname.startsWith('/admin') ? 'Administration'
                    : 'OWL OSINT';

  return (
    <header className="topbar">
      <div className="topbar-title">
        <span>Workspace</span>
        <strong>{title}</strong>
      </div>
      <div className="topbar-environment">
        <span className="environment-dot" />
        <span>Development</span>
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
      <Suspense fallback={<RouteFallback />}>
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
      </Suspense>
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
