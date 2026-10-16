import { once } from "node:events";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import type { AddressInfo, Socket } from "node:net";
import WebSocket, { WebSocketServer } from "ws";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WsClient } from "../src/ws.js";

const clients: WsClient[] = [];
const servers: WebSocketServer[] = [];
afterEach(async () => {
  clients.splice(0).forEach((client) => client.close());
  for (const server of servers.splice(0)) {
    server.clients.forEach((socket) => socket.terminate());
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
async function peer() {
  const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  server.on("headers", (headers) => { headers.push("X-Cpmesh-Protocol: 2"); });
  servers.push(server);
  await once(server, "listening");
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}
function client(timeout = 100) { const client = new WsClient(timeout); clients.push(client); return client; }
function payload() {
  return { request_id: randomUUID(), content_type: "text" as const, encrypted_data: "AA==", key_version: 1 };
}

describe("real WebSocket lifecycle and persistence acknowledgements", () => {
  it("refuses a legacy relay before sending any clipboard payload", async () => {
    const { server, url } = await peer();
    server.removeAllListeners("headers");
    let messages = 0;
    server.on("connection", (socket) => socket.on("message", () => { messages++; }));
    await expect(client().pushClipboard(url, "token", undefined, payload()))
      .rejects.toMatchObject({ code: "protocol_upgrade_required" });
    expect(messages).toBe(0);
  });
  it("close releases the transport and stale callbacks cannot clear a replacement", async () => {
    const { server, url } = await peer();
    const socket = client();
    const firstPeer = once(server, "connection");
    const old = await socket.ensureConnected(url, "token");
    const [remote] = await firstPeer as [WebSocket];
    const closed = once(remote, "close");
    socket.close();
    await closed;
    expect(server.clients.size).toBe(0);
    const next = await socket.ensureConnected(url, "new-token");
    old.emit("close", 1000, Buffer.alloc(0));
    expect(socket.isConnected).toBe(true);
    expect(next.readyState).toBe(WebSocket.OPEN);
    expect(server.clients.size).toBe(1);
  });

  it("close cancels an in-flight handshake", async () => {
    const http = createServer();
    let remote: Socket | undefined;
    let reached!: () => void;
    const upgraded = new Promise<void>((resolve) => { reached = resolve; });
    http.on("upgrade", (_request, socket) => { remote = socket; reached(); });
    http.listen(0, "127.0.0.1");
    await once(http, "listening");
    const socket = client();
    try {
      const attempt = socket.ensureConnected(`http://127.0.0.1:${(http.address() as AddressInfo).port}`, "token");
      const rejected = expect(attempt).rejects.toThrow("cancelled");
      await upgraded;
      socket.close();
      await rejected;
      expect(socket.isConnected).toBe(false);
    } finally {
      remote?.destroy();
      await new Promise<void>((resolve) => http.close(() => resolve()));
    }
  });

  it("never treats a discarded write as success", async () => {
    const { server, url } = await peer();
    let received = 0;
    server.on("connection", (socket) => socket.on("message", () => { received++; }));
    await expect(client(40).pushClipboard(url, "token", undefined, payload()))
      .rejects.toMatchObject({ code: "ack_timeout", uncertain: true });
    expect(received).toBe(1);
  });

  it("accepts only the correlated canonical ID and reports explicit rejection", async () => {
    const { server, url } = await peer();
    const entryId = randomUUID();
    server.on("connection", (socket) => socket.on("message", (raw) => {
      const message = JSON.parse(raw.toString());
      if (message.type !== "clipboard_push") return;
      const ack = { status: "accepted", request_id: message.payload.request_id, entry_id: entryId, created_at: "2026-01-01T00:00:00Z" };
      socket.send(JSON.stringify({ type: "clipboard_ack", payload: { ...ack, request_id: randomUUID() } }));
      socket.send(JSON.stringify({ type: "clipboard_ack", payload: message.payload.key_version === 1 ? ack : {
        status: "rejected", request_id: message.payload.request_id, code: "rotation_required", message: "rotate first",
      } }));
    }));
    const socket = client();
    const request = payload();
    const receipt = await socket.pushClipboard(url, "token", undefined, request);
    expect(receipt.entry_id).toBe(entryId);
    expect(receipt.request_id).toBe(request.request_id);
    await expect(socket.pushClipboard(url, "token", undefined, { ...payload(), key_version: 2 }))
      .rejects.toMatchObject({ code: "rotation_required", uncertain: false });
  });

  it("processes rotation requests instead of ignoring them", async () => {
    const { server, url } = await peer();
    const socket = client();
    socket.onKeyChange = vi.fn(async () => {});
    const connected = once(server, "connection");
    await socket.ensureConnected(url, "token");
    const [remote] = await connected as [WebSocket];
    remote.send(JSON.stringify({ type: "rotation_needed", payload: { reason: "device_revoked" } }));
    await vi.waitFor(() => expect(socket.onKeyChange).toHaveBeenCalledWith(true));
  });
});
