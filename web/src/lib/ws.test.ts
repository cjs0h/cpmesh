import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { setTokens } from './auth';
import { FakeWebSocket, jsonResponse } from '../test/setup';

type WsModule = typeof import('./ws');

const fetchMock = () => fetch as unknown as Mock;

function mockTicket(ticket = 't-1') {
  fetchMock().mockResolvedValue(jsonResponse(200, { ticket }));
}

describe('WebSocket client', () => {
  // The module keeps its socket, handlers and backoff in module scope, so every
  // test gets a fresh instance.
  let ws: WsModule;

  beforeEach(async () => {
    vi.useFakeTimers();
    fetchMock().mockReset();
    vi.resetModules();
    ws = await import('./ws');
  });

  afterEach(() => {
    ws.disconnectWS();
    vi.useRealTimers();
  });

  it('does nothing when logged out', async () => {
    await ws.connectWS();
    expect(fetch).not.toHaveBeenCalled();
    expect(FakeWebSocket.instances).toHaveLength(0);
  });

  it('fetches a single-use ticket and connects with it instead of the JWT', async () => {
    setTokens('jwt-secret', 'r');
    mockTicket('ticket-abc');

    await ws.connectWS();

    const [url, init] = fetchMock().mock.calls[0];
    expect(url).toBe('/api/ws/ticket');
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer jwt-secret');
    const socket = FakeWebSocket.latest();
    expect(socket.url).toBe('wss://cpmesh.test/ws?ticket=ticket-abc');
    expect(socket.url).not.toContain('jwt-secret');
  });

  it('uses ws:// for plain http pages', async () => {
    setTokens('jwt', 'r');
    mockTicket();
    (location as unknown as { protocol: string }).protocol = 'http:';

    await ws.connectWS();

    expect(FakeWebSocket.latest().url).toBe('ws://cpmesh.test/ws?ticket=t-1');
  });

  it('dispatches parsed messages to all handlers and supports unsubscribe', async () => {
    setTokens('jwt', 'r');
    mockTicket();
    const a = vi.fn();
    const b = vi.fn();
    const unsubA = ws.onWSMessage(a);
    ws.onWSMessage(b);

    await ws.connectWS();
    const socket = FakeWebSocket.latest();
    socket.open();
    socket.message({ type: 'device_status', payload: { device_id: 'd1', online: true } });

    expect(a).toHaveBeenCalledWith({ type: 'device_status', payload: { device_id: 'd1', online: true } });
    expect(b).toHaveBeenCalledTimes(1);

    unsubA();
    socket.message({ type: 'pong', payload: {} });
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(2);

    // Malformed frames are ignored rather than thrown
    expect(() => socket.message('not json')).not.toThrow();
    expect(b).toHaveBeenCalledTimes(2);
  });

  it('reconnects with exponential backoff after the socket closes', async () => {
    setTokens('jwt', 'r');
    mockTicket();

    await ws.connectWS();
    expect(FakeWebSocket.instances).toHaveLength(1);

    // First close: reconnect after 1s
    FakeWebSocket.latest().serverClose();
    await vi.advanceTimersByTimeAsync(999);
    expect(FakeWebSocket.instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(FakeWebSocket.instances).toHaveLength(2);

    // Second close (never opened): backoff doubles to 2s
    FakeWebSocket.latest().serverClose();
    await vi.advanceTimersByTimeAsync(1999);
    expect(FakeWebSocket.instances).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(FakeWebSocket.instances).toHaveLength(3);

    // A successful open resets the backoff to 1s
    FakeWebSocket.latest().open();
    FakeWebSocket.latest().serverClose();
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeWebSocket.instances).toHaveLength(4);
  });

  it('caps the backoff at 30 seconds', async () => {
    setTokens('jwt', 'r');
    mockTicket();
    await ws.connectWS();

    // 1s, 2s, 4s, 8s, 16s, 30s, 30s ...
    const expected = [1000, 2000, 4000, 8000, 16000, 30000, 30000];
    for (const delay of expected) {
      const before = FakeWebSocket.instances.length;
      FakeWebSocket.latest().serverClose();
      await vi.advanceTimersByTimeAsync(delay - 1);
      expect(FakeWebSocket.instances).toHaveLength(before);
      await vi.advanceTimersByTimeAsync(1);
      expect(FakeWebSocket.instances).toHaveLength(before + 1);
    }
  });

  it('retries with backoff when the ticket request fails', async () => {
    setTokens('jwt', 'r');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(500, { error: 'boom' }))
      .mockResolvedValue(jsonResponse(200, { ticket: 't-2' }));

    await ws.connectWS();
    expect(FakeWebSocket.instances).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(FakeWebSocket.latest().url).toContain('ticket=t-2');
  });

  it('closes the socket on error so the close handler drives reconnection', async () => {
    setTokens('jwt', 'r');
    mockTicket();
    await ws.connectWS();
    const socket = FakeWebSocket.latest();
    socket.error();
    expect(socket.close).toHaveBeenCalledTimes(1);
  });

  it('disconnect closes an open socket', async () => {
    setTokens('jwt', 'r');
    mockTicket();
    await ws.connectWS();
    const socket = FakeWebSocket.latest();
    socket.open();

    ws.disconnectWS();
    expect(socket.close).toHaveBeenCalledTimes(1);
  });

  it('disconnect cancels a pending reconnect', async () => {
    setTokens('jwt', 'r');
    mockTicket();
    await ws.connectWS();
    FakeWebSocket.latest().serverClose(); // schedules a reconnect in 1s

    ws.disconnectWS();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('disconnect invalidates a pending ticket even when fetch ignores abort', async () => {
    setTokens('jwt', 'r');
    let resolve!: (response: Response) => void;
    fetchMock().mockReturnValueOnce(new Promise<Response>((done) => { resolve = done; }));
    const attempt = ws.connectWS();
    ws.disconnectWS();
    resolve(jsonResponse(200, { ticket: 'late' }));
    await attempt;
    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(ws.getWSStatus()).toBe('offline');
    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('ignores callbacks from a replaced socket and coalesces setup calls', async () => {
    setTokens('jwt', 'r');
    mockTicket();
    await Promise.all([ws.connectWS(), ws.connectWS()]);
    expect(FakeWebSocket.instances).toHaveLength(1);
    const stale = FakeWebSocket.latest();
    const lateOpen = stale.onopen;
    const lateClose = stale.onclose;
    ws.disconnectWS();
    await ws.connectWS();
    FakeWebSocket.latest().open();
    lateOpen?.({});
    lateClose?.({});
    expect(ws.getWSStatus()).toBe('online');
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it('reports connection status transitions to subscribers', async () => {
    setTokens('jwt', 'r');
    mockTicket();
    const seen: string[] = [];
    const unsub = ws.onWSStatus((s) => seen.push(s));
    expect(ws.getWSStatus()).toBe('offline');

    await ws.connectWS();
    expect(seen).toEqual(['connecting']);

    FakeWebSocket.latest().open();
    expect(ws.getWSStatus()).toBe('online');

    FakeWebSocket.latest().serverClose();
    expect(ws.getWSStatus()).toBe('reconnecting');

    // While a reconnect is pending the status stays "reconnecting" through the next attempt
    await vi.advanceTimersByTimeAsync(1000);
    expect(ws.getWSStatus()).toBe('reconnecting');
    FakeWebSocket.latest().open();
    expect(ws.getWSStatus()).toBe('online');

    ws.disconnectWS();
    expect(ws.getWSStatus()).toBe('offline');
    expect(seen).toEqual(['connecting', 'online', 'reconnecting', 'online', 'offline']);

    unsub();
    await ws.connectWS();
    expect(seen).toHaveLength(5);
  });

  it('does not emit duplicate status events', async () => {
    setTokens('jwt', 'r');
    fetchMock().mockResolvedValue(jsonResponse(500, { error: 'boom' }));
    const seen: string[] = [];
    ws.onWSStatus((s) => seen.push(s));

    await ws.connectWS(); // connecting -> reconnecting
    await vi.advanceTimersByTimeAsync(1000); // still reconnecting
    await vi.advanceTimersByTimeAsync(2000);
    expect(seen).toEqual(['connecting', 'reconnecting']);
  });
});
