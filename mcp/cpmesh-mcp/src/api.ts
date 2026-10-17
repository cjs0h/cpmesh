/**
 * REST API client for the cpmesh server (mirrors desktop-tauri api/client.rs).
 *
 * Requests carry this agent's OAuth access token. On a 401 the session is
 * refreshed once through /oauth/token: refresh tokens are single use, so
 * concurrent callers share one refresh and a pair already rotated by another
 * process sharing the profile is adopted instead of refreshing again.
 */

import type {
  ApprovalStatusResponse,
  ClipboardHistoryResponse,
  DeviceInfo,
  GroupKeyResponse,
  GroupKeysResponse,
  PublishEncryptionKeyRequest,
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  SasNonceRequest,
  StoreGroupKeyEntry,
  UserInfo,
} from "./protocol.js";
import { groupKeysSchema } from "./protocol.js";
import { OAuthError, missingScopeMessage, refreshTokens, type TokenSet } from "./oauth.js";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** Machine-readable error code (e.g. "insufficient_scope"), when the server sent one. */
    readonly code?: string,
    /** The whole JSON error body. */
    readonly body: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

/** The user did not allow this agent to do that (`403 insufficient_scope`); `scope` names what it needs. */
export class ScopeError extends ApiError {
  constructor(readonly scope: string | undefined) {
    super(403, missingScopeMessage(scope), "insufficient_scope", scope === undefined ? {} : { scope });
  }
}

/** Thrown when the session can no longer be refreshed: the user must sign in again. */
export class SessionExpiredError extends Error {}

/** The server could not refresh the session right now; the sign-in is kept for a later try. */
export class TemporarilyUnavailableError extends Error {}

export function signedOutMessage(reason?: string): string {
  return `The cpmesh sign-in ended${reason ? ` (${reason})` : ""}. Call cpmesh_login to sign in again with the browser.`;
}

/** Where the token pair is persisted, shared with any other process using the same profile. */
export interface TokenStore {
  /** The pair the profile holds now, or null when it holds none. Only this refresh token is ever presented. */
  load(): { access: string; refresh: string } | null;
  save(tokens: { access: string; refresh: string; scope?: string }): void;
  /** The server refused `refresh` for good (`invalid_grant`): the session is over. */
  signedOut?(refresh: string, reason: string): void;
}

/** The server will never accept this refresh token again. */
class RefreshRefused extends Error {}

/** A lost answer may hide a used refresh token; only a quick retry is a harmless race (10 s on the server). */
const QUICK_RETRY_MS = 5_000;

export class CpmeshApi {
  private baseUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  /** A refresh token the server refused; it must never be sent again. */
  private spentRefreshToken: string | null = null;
  private refreshing: Promise<boolean> | null = null;
  /** Why the last refresh failed for good. */
  private endReason: string | undefined;

  /** Persists rotated tokens; also consulted before refreshing (see refreshSession). */
  tokenStore: TokenStore | null = null;
  /** Waits between refresh retries (replaceable in tests). */
  wait: (ms: number) => Promise<void> = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  setTokens(access: string, refresh: string): void {
    this.accessToken = access || null;
    this.refreshToken = refresh || null;
  }

  get access(): string | null {
    return this.accessToken;
  }

  get refresh(): string | null {
    return this.refreshToken;
  }

  /** Why the last refresh was refused for good, if it was. */
  get signedOutReason(): string | undefined {
    return this.endReason;
  }

  // === Core request plumbing ===

  private async request<T>(
    path: string,
    opts: {
      method?: string;
      body?: unknown;
      auth?: boolean;
      /** Never refresh and retry (a single-use proof must not be replayed with another session). */
      noRefresh?: boolean;
    } = {},
    round = 0,
  ): Promise<T> {
    const { method = "GET", body, auth = true, noRefresh = false } = opts;
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const sentToken = auth ? this.accessToken : null;
    if (sentToken) {
      headers.Authorization = `Bearer ${sentToken}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30_000),
    });

    // A second round covers a stored pair whose access token had expired as well
    if (res.status === 401 && auth && !noRefresh && round < 2) {
      if (await this.refreshSession(sentToken)) return this.request<T>(path, opts, round + 1);
      throw new SessionExpiredError(signedOutMessage(this.endReason));
    }

    if (!res.ok) {
      throw await readError(res);
    }

    if (res.status === 204) return undefined as T;
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  /**
   * Gets a working access token after `rejectedAccess` was refused. Refresh
   * tokens are single use: presenting a used one again revokes this agent's
   * grant and removes its device. So concurrent callers share one refresh, a
   * pair already rotated by another process is adopted instead, and only the
   * refresh token the profile holds is ever sent: never one the server refused
   * or another client gave up.
   */
  refreshSession(rejectedAccess: string | null = this.accessToken): Promise<boolean> {
    this.refreshing ??= this.doRefresh(rejectedAccess).finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async doRefresh(rejectedAccess: string | null): Promise<boolean> {
    // Twice at most: once more after adopting a pair another process rotated meanwhile
    for (let attempt = 0; attempt < 2; attempt++) {
      if (this.tokenStore) {
        // The stored pair is authoritative. A token the profile no longer holds was used up, refused
        // or replaced elsewhere, and presenting it late would count as reuse and revoke this agent.
        const stored = this.tokenStore.load();
        if (!stored?.refresh || stored.refresh === this.spentRefreshToken) {
          if (this.refreshToken) this.spentRefreshToken = this.refreshToken;
          this.refreshToken = null;
          this.accessToken = null;
          this.endReason ??= "the sign-in ended or was replaced in another call or process using this profile";
          return false;
        }
        if (stored.refresh !== this.refreshToken) {
          this.accessToken = stored.access || null;
          this.refreshToken = stored.refresh;
        }
      }
      if (this.accessToken && this.accessToken !== rejectedAccess) return true;
      if (!this.refreshToken) return false;
      const presented = this.refreshToken;
      let tokens: TokenSet;
      try {
        tokens = await this.refreshWithRetries(presented);
      } catch (error) {
        if (!(error instanceof RefreshRefused)) throw error;
        this.spentRefreshToken = presented;
        this.refreshToken = null;
        this.accessToken = null;
        // Another process sharing the profile may have rotated it moments ago
        const stored = this.tokenStore?.load();
        if (stored?.refresh && stored.refresh !== presented) continue;
        this.endReason = error.message;
        this.tokenStore?.signedOut?.(presented, error.message);
        return false;
      }
      this.accessToken = tokens.access_token;
      this.refreshToken = tokens.refresh_token;
      this.tokenStore?.save({
        access: tokens.access_token,
        refresh: tokens.refresh_token,
        ...(tokens.scope !== undefined && { scope: tokens.scope }),
      });
      return true;
    }
    return false;
  }

  /**
   * One refresh at /oauth/token. `invalid_grant` ends the session; a server
   * that is temporarily unavailable or rate limiting is retried briefly and
   * the token kept; an answer lost on the way may hide a used token, so it is
   * retried at once or given up.
   */
  private async refreshWithRetries(presented: string): Promise<TokenSet> {
    for (let attempt = 0; ; attempt++) {
      const started = Date.now();
      try {
        return await refreshTokens(`${this.baseUrl}/oauth/token`, presented);
      } catch (error) {
        if (!(error instanceof OAuthError)) throw error;
        if (error.error === "invalid_grant") throw new RefreshRefused(error.description);
        // New tokens were issued but could not be read: the presented one is used up
        if (error.status === 200) throw new RefreshRefused("the server's answer to the refresh could not be read");
        const uncertain = (error.status === 0 && !error.extra.unsent) || error.status === 502 || error.status === 504 ||
          (error.status >= 500 && error.status !== 503);
        if (uncertain) {
          if (attempt === 0 && error.status !== 500 && Date.now() - started < QUICK_RETRY_MS) continue;
          throw new RefreshRefused("the sign-in could not be refreshed: the answer from the server was lost");
        }
        if (error.transient) {
          if (attempt < 2) {
            await this.wait(Math.min((error.extra.retryAfter ?? 1) * 1000, 10_000));
            continue;
          }
          throw new TemporarilyUnavailableError(
            `The cpmesh server could not refresh the sign-in right now (${error.description}); try again in a moment. ` +
              "This agent stays signed in.",
          );
        }
        throw new Error(`Refreshing the cpmesh sign-in failed (${error.error}: ${error.description}).`);
      }
    }
  }

  // === Device registration ===

  /**
   * Registers this device with proof of possession of its identity key (or
   * reconnects it: same key and fingerprint). The server answers with new
   * device-bound tokens of the same grant, which replace the current ones.
   */
  async registerDevice(
    req: RegisterDeviceRequest,
    signChallenge: (challenge: string) => string,
  ): Promise<RegisterDeviceResponse> {
    const challenge = await this.request<{ challenge: string }>("/api/devices/challenge", { method: "POST" });
    if (typeof challenge.challenge !== "string") throw new Error("Invalid device challenge");
    const resp = await this.request<RegisterDeviceResponse>("/api/devices", {
      method: "POST",
      body: { ...req, proof: { challenge: challenge.challenge, signature: signChallenge(challenge.challenge) } },
      // Never replay a single-use proof with a different bearer session.
      noRefresh: true,
    });
    if (!resp.refresh_token || !resp.access_token) throw new Error("Server did not return a device-bound session; update the server");
    this.accessToken = resp.access_token;
    this.refreshToken = resp.refresh_token;
    return resp;
  }

  // === Devices ===

  async getDevices(): Promise<DeviceInfo[]> {
    return this.request<DeviceInfo[]>("/api/devices");
  }

  async deleteDevice(deviceId: string): Promise<void> {
    await this.request(`/api/devices/${encodeURIComponent(deviceId)}`, {
      method: "DELETE",
    });
  }

  /** Identity keys plus the certified encryption keys of every device on the account. */
  async getDeviceKeys(): Promise<{ devices: DeviceInfo[] }> {
    return this.request<{ devices: DeviceInfo[] }>("/api/devices/keys");
  }

  /** Publishes (or re-publishes) this device's certified static encryption key; 204 on success. */
  async publishEncryptionKey(encryptionKey: Uint8Array, encryptionKeySig: Uint8Array): Promise<void> {
    const body: PublishEncryptionKeyRequest = {
      encryption_key: Buffer.from(encryptionKey).toString("base64"),
      encryption_key_sig: Buffer.from(encryptionKeySig).toString("base64"),
    };
    await this.request("/api/devices/me/encryption-key", { method: "PUT", body });
  }

  // === Group keys ===

  /** Legacy single-key endpoint; resolves to null on 404 (no group key yet). */
  async getGroupKey(): Promise<GroupKeyResponse | null> {
    try {
      return await this.request<GroupKeyResponse>("/api/group-key");
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null;
      throw e;
    }
  }

  async storeGroupKeys(entries: StoreGroupKeyEntry[]): Promise<void> {
    await this.request("/api/group-key", { method: "POST", body: entries });
  }

  async getCurrentGroupKeys(
    sinceVersion?: number,
  ): Promise<GroupKeysResponse> {
    const q =
      sinceVersion !== undefined ? `?since_version=${sinceVersion}` : "";
    return groupKeysSchema.parse(await this.request<unknown>(`/api/group-keys/current${q}`));
  }

  async rotateGroupKey(expected: number, version: number, wrappedKeys: StoreGroupKeyEntry[]): Promise<void> {
    await this.request("/api/group-keys/rotate", {
      method: "POST", body: { expected_current_version: expected, new_version: version, wrapped_keys: wrappedKeys },
    });
  }

  // === Approvals ===

  async getMyApprovalStatus(): Promise<ApprovalStatusResponse> {
    return this.request<ApprovalStatusResponse>("/api/device-approvals/me");
  }

  /** Pending side of pairing: contributes its 32-byte SAS nonce after seeing the approver's commitment; 204 on success. */
  async submitPendingNonce(sessionId: string, nonce: Uint8Array): Promise<void> {
    if (nonce.length !== 32) throw new Error("SAS nonce must be 32 bytes");
    const body: SasNonceRequest = { session_id: sessionId, nonce: Buffer.from(nonce).toString("base64") };
    await this.request("/api/device-approvals/me/nonce", { method: "POST", body });
  }

  // === Clipboard ===

  async getClipboardHistory(
    limit: number,
    offset: number,
  ): Promise<ClipboardHistoryResponse> {
    return this.request<ClipboardHistoryResponse>(
      `/api/clipboard?limit=${limit}&offset=${offset}`,
    );
  }

  async deleteClipboardEntry(entryId: string): Promise<void> {
    await this.request(`/api/clipboard/${encodeURIComponent(entryId)}`, {
      method: "DELETE",
    });
  }

  // === Account ===

  async getMe(): Promise<UserInfo> {
    return this.request<UserInfo>("/api/me");
  }
}

async function readError(res: Response): Promise<ApiError> {
  let body: Record<string, unknown> = {};
  try {
    const parsed: unknown = await res.json();
    if (parsed && typeof parsed === "object") body = parsed as Record<string, unknown>;
  } catch {
    // not JSON
  }
  const text = (value: unknown) => (typeof value === "string" && value ? value : undefined);
  if (res.status === 403 && body.code === "insufficient_scope") return new ScopeError(text(body.scope));
  return new ApiError(
    res.status,
    text(body.error) ?? text(body.message) ?? (res.statusText || `HTTP ${res.status}`),
    text(body.code),
    body,
  );
}
