import { useState, useEffect, useCallback, type ReactNode } from 'react';
import apiClient from '../api/client';
import { AuthStateContext, type User } from './auth-state';

/* ── Types ─────────────────────────────────────────────────────────── */

/* ── Context ───────────────────────────────────────────────────────── */

const TOKEN_KEY = 'owl_osint_token';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() =>
    localStorage.getItem(TOKEN_KEY)
  );
  const [isLoading, setIsLoading] = useState(() => Boolean(localStorage.getItem(TOKEN_KEY)));

  /* On mount, validate existing token via /auth/me */
  useEffect(() => {
    let cancelled = false;
    const saved = localStorage.getItem(TOKEN_KEY);
    if (!saved) return;

    apiClient
      .get('/auth/me', {
        headers: { Authorization: `Bearer ${saved}` },
      })
      .then((res) => {
        if (!cancelled) {
          setUser(res.data);
          setToken(saved);
        }
      })
      .catch(() => {
        if (!cancelled) {
          localStorage.removeItem(TOKEN_KEY);
          setToken(null);
          setUser(null);
        }
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => { cancelled = true; };
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const res = await apiClient.post('/auth/login', { username, password });
    const { access_token } = res.data;
    localStorage.setItem(TOKEN_KEY, access_token);
    setToken(access_token);

    // Fetch user profile
    const meRes = await apiClient.get('/auth/me', {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    setUser(meRes.data);
  }, []);

  const register = useCallback(
    async (username: string, email: string, password: string) => {
      await apiClient.post('/auth/register', { username, email, password });
    },
    []
  );

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
  }, []);

  return (
    <AuthStateContext.Provider
      value={{
        user,
        token,
        isLoading,
        isAuthenticated: !!user && !!token,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthStateContext.Provider>
  );
}
