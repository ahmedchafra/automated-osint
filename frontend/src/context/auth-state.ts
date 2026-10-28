import { createContext, useContext } from 'react';

export interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => void;
}

export const AuthStateContext = createContext<AuthState | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthStateContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}
