import axios from 'axios';
import type { AxiosError, InternalAxiosRequestConfig } from 'axios';

const API_KEY = import.meta.env.VITE_API_KEY || 'osint-local-dev-key-12345';
const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY,
  },
});

/* ── JWT token interceptor ────────────────────────────────────────────
 * Attaches Authorization: Bearer <token> from localStorage when
 * a JWT token exists. Falls back to X-API-Key (already on the client).
 */
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = localStorage.getItem('owl_osint_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
    // Remove the API key header when using JWT to avoid confusion
    delete config.headers['X-API-Key'];
  }
  return config;
});

/* ── 401 interceptor ──────────────────────────────────────────────────
 * If any response returns 401, clear the stored token so the user
 * is redirected to login on next page navigation.
 */
apiClient.interceptors.response.use(
  (res) => res,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('owl_osint_token');
    }
    return Promise.reject(error);
  }
);

/* ── Helpers ────────────────────────────────────────────────────────── */

export async function triggerPivotSweep(scanId: string, email: string) {
  return apiClient.post(`/scans/${scanId}/pivot`, { email });
}

export async function deleteScan(scanId: string) {
  return apiClient.delete(`/scans/${scanId}`);
}

export async function cancelScan(scanId: string) {
  return apiClient.post(`/scans/${scanId}/cancel`);
}

export async function triggerOrgInfra(scanId: string, domain: string) {
  return apiClient.post(`/scans/${scanId}/run-infra`, { domain });
}

export default apiClient;
