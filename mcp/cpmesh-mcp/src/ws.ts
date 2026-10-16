import { randomUUID } from "node:crypto";
import WebSocket from "ws";
import { clipboardAckSchema, type ClipboardPushPayload, type ClipboardReceipt } from "./protocol.js";

export class WsError extends Error {
  constructor(message: string, readonly code?: string, readonly uncertain = false) { super(message); }
}

interface Pending {
  resolve(receipt: ClipboardReceipt): void;
  reject(error: Error): void;
  timer: NodeJS.Timeout;
}

export class WsClient {
  private ws: WebSocket | null = null;
  private heartbeat: NodeJS.Timeout | null = null;
  private connecting: Promise<WebSocket> | null = null;
  private cancelConnect: (() => void) | null = null;
  private generation = 0;
  private connectionKey = "";
  private pending = new Map<string, Pending>();
  onKeyChange: ((rotate: boolean) => Promise<void>) | null = null;
  keyError: string | null = null;

  constructor(private readonly ackTimeoutMs = 10_000) {}

  get isConnected(): boolean { return this.ws?.readyState === WebSocket.OPEN; }

  ensureConnected(serverUrl: string, accessToken: string, fingerprint?: string): Promise<WebSocket> {
    const url = new URL(serverUrl);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.pathname = "/ws";
    url.search = "";
    url.hash = "";
    const key = `${url}\0${accessToken}\0${fingerprint ?? ""}`;
    if (key === this.connectionKey) {
      if (this.isConnected && this.ws) return Promise.resolve(this.ws);
      if (this.connecting) return this.connecting;
    }
    this.close();
    const generation = this.generation;
    this.connectionKey = key;
    const headers: Record<string, string> = { Authorization: "Bearer " + accessToken, "X-Cpmesh-Protocol": "2" };
    if (fingerprint) headers["X-Device-Fingerprint"] = fingerprint;
    const ws = new WebSocket(url, { headers, handshakeTimeout: 10_000, maxPayload: 36 * 1024 * 1024 });
    this.ws = ws;
    const current = () => this.generation === generation && this.ws === ws;
    const attempt = new Promise<WebSocket>((resolve, reject) => {
      let settled = false;
      let protocolAccepted = false;
      const fail = (error: Error) => {
        if (!settled) { settled = true; reject(error); }
      };
      this.cancelConnect = () => fail(new WsError("WebSocket connection cancelled"));
      ws.once("upgrade", (response) => {
        protocolAccepted = response.headers["x-cpmesh-protocol"] === "2";
        if (!protocolAccepted) {
          fail(new WsError("Server upgrade required: WebSocket protocol 2 was not confirmed", "protocol_upgrade_required"));
          ws.terminate();
        }
      });
      ws.on("error", (error) => {
        fail(new WsError(`WebSocket connect failed: ${error.message}`));
        if (current()) this.rejectPending(new WsError(`WebSocket transport failed: ${error.message}`, "transport_error", true));
      });
      ws.once("open", () => {
        if (!current() || !protocolAccepted) { ws.terminate(); fail(new WsError("Stale or unsupported WebSocket connection")); return; }
        settled = true;
        this.cancelConnect = null;
        this.heartbeat = setInterval(() => {
          if (current() && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "ping" }));
        }, 30_000);
        this.heartbeat.unref();
        resolve(ws);
      });
      ws.on("message", (raw) => {
        if (current()) this.handleMessage(raw.toString());
      });
      ws.once("close", () => {
        fail(new WsError("WebSocket closed during connection"));
        if (!current()) return;
        this.stopHeartbeat();
        this.ws = null;
        this.rejectPending(new WsError("WebSocket closed before persistence acknowledgement", "connection_closed", true));
      });
    });
    this.connecting = attempt;
    void attempt.finally(() => {
      if (this.connecting === attempt) { this.connecting = null; this.cancelConnect = null; }
    }).catch(() => { /* The original promise carries the connection failure. */ });
    return attempt;
  }

  private handleMessage(text: string): void {
    let value: unknown;
    try { value = JSON.parse(text); } catch { console.error("[cpmesh-mcp] Invalid relay JSON"); return; }
    if (!value || typeof value !== "object" || !("type" in value)) return;
    if (value.type === "clipboard_ack" && "payload" in value) {
      const parsed = clipboardAckSchema.safeParse(value.payload);
      if (!parsed.success) { console.error("[cpmesh-mcp] Invalid persistence acknowledgement"); return; }
      const ack = parsed.data;
      const pending = this.pending.get(ack.request_id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(ack.request_id);
      if (ack.status === "accepted") pending.resolve(ack);
      else pending.reject(new WsError(`${ack.code}: ${ack.message}`, ack.code, ack.code === "temporarily_unavailable"));
    } else if (value.type === "group_key_updated" || value.type === "rotation_needed") {
      const work = this.onKeyChange?.(value.type === "rotation_needed");
      if (work) void work.then(() => { this.keyError = null; }).catch((error: unknown) => {
        this.keyError = error instanceof Error ? error.message : String(error);
        console.error("[cpmesh-mcp] Key synchronization failed:", this.keyError);
      });
    }
  }

  async pushClipboard(
    serverUrl: string, accessToken: string, fingerprint: string | undefined, payload: ClipboardPushPayload,
  ): Promise<ClipboardReceipt> {
    const ws = await this.ensureConnected(serverUrl, accessToken, fingerprint);
    const requestId = (payload.request_id ?? randomUUID()).toLowerCase();
    if (this.pending.size >= 32 || this.pending.has(requestId)) throw new WsError("Clipboard queue full or request already pending");
    if (ws.bufferedAmount > 2 * 1024 * 1024) throw new WsError("WebSocket send buffer is full");
    return new Promise<ClipboardReceipt>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        reject(new WsError(`No persistence acknowledgement; delivery is unknown. Retry request_id ${requestId}.`, "ack_timeout", true));
      }, this.ackTimeoutMs);
      this.pending.set(requestId, { resolve, reject, timer });
      ws.send(JSON.stringify({ type: "clipboard_push", payload: { ...payload, request_id: requestId } }), (error) => {
        const pending = this.pending.get(requestId);
        if (error && pending) {
          clearTimeout(timer);
          this.pending.delete(requestId);
          pending.reject(new WsError(error.message, "transport_error", true));
        }
      });
    });
  }

  private stopHeartbeat(): void {
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = null;
  }

  private rejectPending(error: Error): void {
    for (const request of this.pending.values()) { clearTimeout(request.timer); request.reject(error); }
    this.pending.clear();
  }

  close(): void {
    const ws = this.ws;
    this.generation++;
    this.ws = null;
    this.connecting = null;
    this.connectionKey = "";
    const cancel = this.cancelConnect;
    this.cancelConnect = null;
    cancel?.();
    this.stopHeartbeat();
    this.rejectPending(new WsError("WebSocket closed before persistence acknowledgement", "connection_closed", true));
    if (!ws || ws.readyState === WebSocket.CLOSED) return;
    if (ws.readyState === WebSocket.CONNECTING) ws.terminate();
    else {
      ws.close();
      const deadline = setTimeout(() => { if (ws.readyState !== WebSocket.CLOSED) ws.terminate(); }, 250);
      deadline.unref();
    }
  }
}
