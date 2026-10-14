/**
 * WebSocket client for the cpmesh relay (mirrors desktop-tauri ws/connection.rs).
 *
 * Authenticates with an Authorization: Bearer header on the upgrade request
 * (same as the desktop client — keeps the JWT out of URLs/logs) and sends
 * the device fingerprint for opportunistic backfill.
 */

import WebSocket from "ws";
import {
  MSG_PING,
  MSG_ERROR,
  type ClipboardPushPayload,
  type ErrorPayload,
  type WsMessage,
} from "./protocol.js";

const HEARTBEAT_INTERVAL_MS = 30_000;

export class WsError extends Error {}

export class WsClient {
  private ws: WebSocket | null = null;
  private heartbeat: NodeJS.Timeout | null = null;
  private lastServerError: { code: string; message: string } | null = null;
  private connecting: Promise<WebSocket> | null = null;

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private wsUrl(serverUrl: string): string {
    const url = new URL(serverUrl);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.pathname = "/ws";
    return url.toString();
  }

  /** Lazily establishes (or re-establishes) the connection. */
  async ensureConnected(
    serverUrl: string,
    accessToken: string,
    fingerprint?: string,
  ): Promise<WebSocket> {
    if (this.isConnected && this.ws) return this.ws;
    if (this.connecting) return this.connecting;

    this.connecting = (async () => {
      this.close();

      const headers: Record<string, string> = {
        Authorization: `Bearer ${accessToken}`,
      };
      if (fingerprint) headers["X-Device-Fingerprint"] = fingerprint;

      const ws = new WebSocket(this.wsUrl(serverUrl), { headers });

      await new Promise<void>((resolve, reject) => {
        const onError = (err: Error) => reject(new WsError(`WebSocket connect failed: ${err.message}`));
        ws.once("open", () => {
          ws.removeListener("error", onError);
          resolve();
        });
        ws.once("error", onError);
      });

      ws.on("message", (raw: WebSocket.RawData) => {
        this.handleMessage(raw.toString());
      });
      ws.on("close", () => this.cleanup());

      this.ws = ws;
      this.startHeartbeat();
      return ws;
    })();

    try {
      return await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeat = setInterval(() => {
      if (this.isConnected && this.ws) {
        this.ws.send(JSON.stringify({ type: MSG_PING } satisfies WsMessage));
      }
    }, HEARTBEAT_INTERVAL_MS);
    this.heartbeat.unref?.();
  }

  private stopHeartbeat(): void {
    if (this.heartbeat) {
      clearInterval(this.heartbeat);
      this.heartbeat = null;
    }
  }

  private cleanup(): void {
    this.stopHeartbeat();
    this.ws = null;
  }

  private handleMessage(text: string): void {
    let msg: WsMessage;
    try {
      msg = JSON.parse(text) as WsMessage;
    } catch {
      return;
    }
    if (msg.type === MSG_ERROR) {
      const p = (msg.payload ?? {}) as Partial<ErrorPayload>;
      this.lastServerError = {
        code: p.code ?? "error",
        message: p.message ?? "unknown server error",
      };
    }
    // clipboard_new / device_status / group_key_updated are not needed by the
    // pull-based MCP tools: history reads go through the REST API.
  }

  /**
   * Sends a clipboard push. The server does not echo the broadcast back to the
   * pushing device, so delivery is confirmed by the absence of a server error
   * within a short window plus the successful WS write.
   */
  async pushClipboard(
    serverUrl: string,
    accessToken: string,
    fingerprint: string | undefined,
    payload: ClipboardPushPayload,
  ): Promise<void> {
    const ws = await this.ensureConnected(serverUrl, accessToken, fingerprint);
    this.lastServerError = null;

    ws.send(
      JSON.stringify({
        type: "clipboard_push",
        payload,
      } satisfies WsMessage),
    );

    // Give the server a brief window to reject the push with an error message.
    const deadline = Date.now() + 1500;
    while (Date.now() < deadline) {
      const err = this.lastServerError as unknown as {
        code: string;
        message: string;
      } | null;
      if (err) {
        throw new WsError(
          `server rejected clipboard push (${err.code}): ${err.message}`,
        );
      }
      await sleep(50);
    }
  }

  close(): void {
    this.cleanup();
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        // already closed
      }
      this.ws = null;
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
