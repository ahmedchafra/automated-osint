import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

// ── Global error logging ──────────────────────────────────────────────
// Log uncaught errors to help diagnose black-screen issues in production.
window.addEventListener('error', (event) => {
  console.error('[Global error]', event.error?.message || event.message, event.error?.stack?.split('\n').slice(0, 6).join('\n') || '');
});

window.addEventListener('unhandledrejection', (event) => {
  console.error('[Unhandled promise rejection]', event.reason?.message || String(event.reason));
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
