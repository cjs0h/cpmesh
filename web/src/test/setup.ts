// Shared Vitest setup for the web dashboard.
//
// Tests run under Node, so the handful of browser globals the `lib/` modules rely
// on are provided here as small, deterministic fakes rather than via a full DOM.

import { beforeEach, vi } from 'vitest';

class MemoryStorage implements Storage {
  private store = new Map<string, string>();

  get length() {
    return this.store.size;
  }
  clear() {
    this.store.clear();
  }
  getItem(key: string) {
    return this.store.has(key) ? this.store.get(key)! : null;
  }
  key(index: number) {
    return Array.from(this.store.keys())[index] ?? null;
  }
  removeItem(key: string) {
    this.store.delete(key);
  }
  setItem(key: string, value: string) {
    this.store.set(key, String(value));
  }
}

/** Minimal `location` stand-in; `hash` assignments are recorded, not navigated. */
export function makeLocation(overrides: Partial<Location> = {}) {
  return {
    protocol: 'https:',
    host: 'cpmesh.test',
    hash: '',
    reload: vi.fn(),
    ...overrides,
  } as unknown as Location;
}

/**
 * Fake WebSocket that records constructor calls and exposes the handlers the
 * code under test installs, so tests can drive open/message/close events.
 */
export class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  url: string;
  readyState = FakeWebSocket.CONNECTING;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  close = vi.fn(() => {
    this.readyState = FakeWebSocket.CLOSED;
  });

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  static reset() {
    FakeWebSocket.instances = [];
  }
  static latest(): FakeWebSocket {
    const ws = FakeWebSocket.instances.at(-1);
    if (!ws) throw new Error('no WebSocket was constructed');
    return ws;
  }

  open() {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.({});
  }
  message(data: unknown) {
    this.onmessage?.({ data: typeof data === 'string' ? data : JSON.stringify(data) });
  }
  serverClose() {
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.({});
  }
  error() {
    this.onerror?.({});
  }
}

/** Builds a `fetch` mock that resolves with the given status and JSON body. */
export function jsonResponse(status: number, body: unknown, statusText = ''): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

beforeEach(() => {
  if (typeof document === 'undefined') {
    vi.stubGlobal('localStorage', new MemoryStorage());
    const location = makeLocation();
    vi.stubGlobal('location', location);
    vi.stubGlobal('window', { location });
  } else {
    localStorage.clear();
  }
  FakeWebSocket.reset();
  vi.stubGlobal('WebSocket', FakeWebSocket);
  vi.stubGlobal('fetch', vi.fn());
});
