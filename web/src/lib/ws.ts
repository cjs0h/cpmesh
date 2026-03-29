import { getAccessToken } from './auth';
import { api } from './api';

export type WSMessageHandler = (msg: { type: string; payload: any }) => void;

let socket: WebSocket | null = null;
let handlers: WSMessageHandler[] = [];
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectBackoff = 1000; // start at 1s
const MAX_BACKOFF = 30000;

export async function connectWS() {
  const token = getAccessToken();
  if (!token) return;

  try {
    // Get a short-lived, single-use ticket (avoids putting JWT in URL)
    const { ticket } = await api<{ ticket: string }>('/api/ws/ticket', { method: 'POST' });

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    socket = new WebSocket(`${proto}//${location.host}/ws?ticket=${ticket}`);

    socket.onopen = () => {
      reconnectBackoff = 1000; // reset on success
    };

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handlers.forEach((h) => h(msg));
      } catch { /* ignore bad messages */ }
    };

    socket.onclose = () => {
      socket = null;
      // Reconnect with exponential backoff
      reconnectTimer = setTimeout(connectWS, reconnectBackoff);
      reconnectBackoff = Math.min(reconnectBackoff * 2, MAX_BACKOFF);
    };

    socket.onerror = () => {
      socket?.close();
    };
  } catch {
    // Ticket request failed — retry with backoff
    reconnectTimer = setTimeout(connectWS, reconnectBackoff);
    reconnectBackoff = Math.min(reconnectBackoff * 2, MAX_BACKOFF);
  }
}

export function disconnectWS() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  socket?.close();
  socket = null;
}

export function onWSMessage(handler: WSMessageHandler): () => void {
  handlers.push(handler);
  return () => {
    handlers = handlers.filter((h) => h !== handler);
  };
}
