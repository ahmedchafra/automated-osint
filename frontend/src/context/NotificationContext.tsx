import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';

export interface NotificationItem {
  id: string;
  type: 'success' | 'error' | 'info';
  title: string;
  message: string;
  timestamp: number;
}

interface NotificationContextValue {
  notifications: NotificationItem[];
  addNotification: (n: Omit<NotificationItem, 'id' | 'timestamp'>) => void;
  dismissNotification: (id: string) => void;
}

const NotificationContext = createContext<NotificationContextValue>({
  notifications: [],
  addNotification: () => {},
  dismissNotification: () => {},
});

let _nextId = 0;
const MAX_VISIBLE = 5;
const AUTO_DISMISS_MS = 8_000;

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);

  const addNotification = useCallback((n: Omit<NotificationItem, 'id' | 'timestamp'>) => {
    const id = `notif-${++_nextId}`;
    const item: NotificationItem = { ...n, id, timestamp: Date.now() };

    setNotifications(prev => {
      const next = [item, ...prev].slice(0, MAX_VISIBLE);
      return next;
    });

    // Auto-dismiss after 8s
    setTimeout(() => {
      setNotifications(prev => prev.filter(x => x.id !== id));
    }, AUTO_DISMISS_MS);
  }, []);

  const dismissNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(x => x.id !== id));
  }, []);

  return (
    <NotificationContext.Provider value={{ notifications, addNotification, dismissNotification }}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotification() {
  return useContext(NotificationContext);
}
