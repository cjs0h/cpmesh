import { getAccessToken } from './auth';
import { api } from './api';

export type WSMessageHandler = (msg: { type: string; payload: any }) => void;
export type WSStatus = 'offline' | 'connecting' | 'online' | 'reconnecting';
export type WSStatusHandler = (status: WSStatus) => void;

let socket: WebSocket | null = null;
let handlers: WSMessageHandler[] = [];
let statusHandlers: WSStatusHandler[] = [];
let status: WSStatus = 'offline';
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectBackoff = 1000; // start at 1s
const MAX_BACKOFF = 30000;

function setStatus(next: WSStatus) {
  if (status === next) return;
  status = next;
  statusHandlers.forEach((h) => h(next));
}

function scheduleReconnect() {
  setStatus('reconnecting');
  reconnectTimer = setTimeout(connectWS, reconnectBackoff);
  reconnectBackoff = Math.min(reconnectBackoff * 2, MAX_BACKOFF);
}

export async function connectWS() {
  const token = getAccessToken();
  if (!token) return;

  reconnectTimer = null;
  if (status !== 'reconnecting') setStatus('connecting');

  try {
    // Get a short-lived, single-use ticket (avoids putting JWT in URL)
    const { ticket } = await api<{ ticket: string }>('/api/ws/ticket', { method: 'POST' });

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    socket = new WebSocket(`${proto}//${location.host}/ws?ticket=${ticket}`);

    socket.onopen = () => {
      reconnectBackoff = 1000; // reset on success
      setStatus('online');
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
      scheduleReconnect();
    };

    socket.onerror = () => {
      socket?.close();
    };
  } catch {
    // Ticket request failed — retry with backoff
    scheduleReconnect();
  }
}

export function disconnectWS() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (socket) {
    // Detach first so the close handler does not schedule a reconnect.
    socket.onclose = null;
    socket.close();
    socket = null;
  }
  setStatus('offline');
}

export function getWSStatus(): WSStatus {
  return status;
}

export function onWSStatus(handler: WSStatusHandler): () => void {
  statusHandlers.push(handler);
  return () => {
    statusHandlers = statusHandlers.filter((h) => h !== handler);
  };
}

export function onWSMessage(handler: WSMessageHandler): () => void {
  handlers.push(handler);
  return () => {
    handlers = handlers.filter((h) => h !== handler);
  };
}
