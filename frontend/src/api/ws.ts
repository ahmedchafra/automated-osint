/**
 * Open a WebSocket to the backend and invoke onMessage for each parsed event.
 * Auto-reconnects on close with exponential backoff (up to 5 retries) so a
 * flaky connection during a long-running scan doesn't permanently sever the
 * live progress feed.
 *
 * The returned WebSocket's `close()` permanently shuts down the connection
 * and prevents reconnection — call it in effect cleanup.
 */
export interface ScanEvent {
  event: string;
  scan_id: string;
  timestamp: string;
  [key: string]: unknown;
}

export function openScanWebSocket(
  scanId: string,
  onMessage: (event: ScanEvent) => void,
  onError?: (err: Event) => void,
): WebSocket {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const token = localStorage.getItem('owl_osint_token');
  const wsBase = (import.meta.env.VITE_WS_URL as string | undefined) ??
    `${wsProtocol}//${window.location.hostname}:8000`;

  const url = new URL(`${wsBase}/ws/scans/${scanId}`);

  let closed = false;
  let retries = 0;
  const MAX_RETRIES = 5;

  function createSocket(): WebSocket {
    const protocols = token ? [`bearer.${token}`] : undefined;
    const socket = new WebSocket(url.toString(), protocols);

    socket.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data) as ScanEvent;
        onMessage(parsed);
      } catch {
        // Ignore malformed frames; backend already wraps everything as JSON.
      }
    };

    socket.onerror = (err) => {
      if (onError) onError(err);
    };

    socket.onclose = () => {
      if (!closed && retries < MAX_RETRIES) {
        retries++;
        const delay = Math.min(1000 * 2 ** retries, 30000);
        setTimeout(createSocket, delay);
      }
    };

    return socket;
  }

  const socket = createSocket();
  const origClose = socket.close.bind(socket);
  socket.close = () => {
    closed = true;
    origClose();
  };

  return socket;
}
