import { getAccessToken, onSessionEnd } from './auth';
import { api } from './api';

export type WSMessageHandler = (msg: { type: string; payload?: unknown }) => void;
export type WSStatus = 'offline' | 'connecting' | 'online' | 'reconnecting';
export type WSStatusHandler = (status: WSStatus) => void;

let socket: WebSocket | null = null;
let handlers: WSMessageHandler[] = [];
let statusHandlers: WSStatusHandler[] = [];
let status: WSStatus = 'offline';
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectBackoff = 1000;
let generation = 0;
let attempting = false;
let ticketRequest: AbortController | null = null;
const MAX_BACKOFF = 30000;

function setStatus(next: WSStatus) {
  if (status === next) return;
  status = next;
  statusHandlers.forEach((handler) => handler(next));
}

function scheduleReconnect(attempt: number) {
  if (attempt !== generation || !getAccessToken()) return;
  setStatus('reconnecting');
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    if (attempt === generation) void connectWS();
  }, reconnectBackoff);
  reconnectBackoff = Math.min(reconnectBackoff * 2, MAX_BACKOFF);
}

export async function connectWS() {
  if (!getAccessToken() || attempting || socket) return;
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  const attempt = ++generation;
  attempting = true;
  const controller = new AbortController();
  ticketRequest = controller;
  if (status !== 'reconnecting') setStatus('connecting');
  try {
    const { ticket } = await api<{ ticket: string }>('/api/ws/ticket', { method: 'POST', signal: controller.signal });
    if (attempt !== generation || !getAccessToken()) return;
    if (typeof ticket !== 'string' || !ticket) throw new Error('Invalid WebSocket ticket');
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const current = new WebSocket(`${proto}//${location.host}/ws?ticket=${encodeURIComponent(ticket)}`);
    socket = current;
    const active = () => attempt === generation && socket === current;
    current.onopen = () => {
      if (!active()) return;
      reconnectBackoff = 1000;
      setStatus('online');
    };
    current.onmessage = (event) => {
      if (!active()) return;
      let value: unknown;
      try { value = JSON.parse(event.data); }
      catch { console.warn('Invalid WebSocket JSON'); return; }
      if (!value || typeof value !== 'object' || !('type' in value) || typeof value.type !== 'string') {
        console.warn('Invalid WebSocket envelope');
        return;
      }
      const message = { type: value.type, payload: 'payload' in value ? value.payload : undefined };
      handlers.forEach((handler) => handler(message));
    };
    current.onclose = () => {
      if (!active()) return;
      socket = null;
      scheduleReconnect(attempt);
    };
    current.onerror = () => { if (active()) current.close(); };
  } catch (error) {
    if (attempt !== generation) return;
    console.warn('WebSocket connection failed', error);
    scheduleReconnect(attempt);
  } finally {
    if (attempt === generation) { attempting = false; ticketRequest = null; }
  }
}

export function disconnectWS() {
  generation++;
  attempting = false;
  ticketRequest?.abort();
  ticketRequest = null;
  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = null;
  const previous = socket;
  socket = null;
  if (previous) {
    previous.onopen = previous.onmessage = previous.onclose = previous.onerror = null;
    previous.close();
  }
  setStatus('offline');
}

onSessionEnd(disconnectWS);
export function getWSStatus(): WSStatus { return status; }
export function onWSStatus(handler: WSStatusHandler): () => void {
  statusHandlers.push(handler);
  return () => { statusHandlers = statusHandlers.filter((h) => h !== handler); };
}
export function onWSMessage(handler: WSMessageHandler): () => void {
  handlers.push(handler);
  return () => { handlers = handlers.filter((h) => h !== handler); };
}
