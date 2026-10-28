import { createContext, useContext } from 'react';

export interface NotificationItem {
  id: string;
  type: 'success' | 'error' | 'info';
  title: string;
  message: string;
  timestamp: number;
}

export interface NotificationContextValue {
  notifications: NotificationItem[];
  addNotification: (notification: Omit<NotificationItem, 'id' | 'timestamp'>) => void;
  dismissNotification: (id: string) => void;
}

export const NotificationStateContext = createContext<NotificationContextValue>({
  notifications: [],
  addNotification: () => undefined,
  dismissNotification: () => undefined,
});

export function useNotification() {
  return useContext(NotificationStateContext);
}
