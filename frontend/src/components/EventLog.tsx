
export type EventLevel = 'success' | 'info' | 'warning' | 'error';

export interface LogEvent {
  id: string;
  level: EventLevel;
  title: string;
  detail?: string;
  timestamp: string;
}

interface EventLogProps {
  events: LogEvent[];
  emptyMessage?: string;
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return iso;
  }
}

export function EventLog({ events, emptyMessage = 'No events yet.' }: EventLogProps) {
  if (events.length === 0) {
    return <div className="text-gray text-sm">{emptyMessage}</div>;
  }
  return (
    <div className="event-log">
      {events.map((event) => (
        <div key={event.id} className={`event-log-item ${event.level}`}>
          <span className="dot" />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="font-medium text-strong" style={{ color: 'var(--text-strong)' }}>
              {event.title}
           </div>
            {event.detail && (
              <div className="text-gray text-sm mt-1" style={{ wordBreak: 'break-word' }}>
                {event.detail}
             </div>
            )}
            <time className="mt-1">{formatTime(event.timestamp)}</time>
         </div>
       </div>
      ))}
   </div>
  );
}
