import { useState, useCallback, type ReactNode } from 'react';
import {
  NotificationStateContext,
  type NotificationItem,
} from './notification-state';

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
    <NotificationStateContext.Provider value={{ notifications, addNotification, dismissNotification }}>
      {children}
    </NotificationStateContext.Provider>
  );
}
