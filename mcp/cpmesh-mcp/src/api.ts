/**
 * REST API client for the cpmesh server (mirrors desktop-tauri api/client.rs).
 */

import type {
  ApprovalStatusResponse,
  AuthResponse,
  ClipboardHistoryResponse,
  DeviceInfo,
  GroupKeyResponse,
  GroupKeysResponse,
  MfaChallenge,
  MfaVerifyResponse,
  PublishEncryptionKeyRequest,
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  SasNonceRequest,
  StoreGroupKeyEntry,
  UserInfo,
} from "./protocol.js";
import { groupKeysSchema } from "./protocol.js";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** Machine-readable error code (e.g. "mfa_locked"), when the server sent one. */
    readonly code?: string,
    /** The whole JSON error body. */
    readonly body: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

/** The password was right; the sign-in continues with a second factor. */
export class MfaRequiredError extends ApiError {
  constructor(
    error: ApiError,
    readonly challenge: MfaChallenge,
  ) {
    super(error.status, error.message, error.code, error.body);
  }
}

/** Thrown when the session can no longer be refreshed — user must log in again. */
export class SessionExpiredError extends Error {}

export const SESSION_EXPIRED_MESSAGE =
  "session expired — call cpmesh_login again (tokens could not be refreshed)";

/** Where the token pair is persisted, shared with any other process using the same session. */
export interface TokenStore {
  load(): { access: string; refresh: string } | null;
  save(access: string, refresh: string): void;
}

export class CpmeshApi {
  private baseUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  /** A refresh token the server reported already used; it must never be sent again. */
  private spentRefreshToken: string | null = null;
  private refreshing: Promise<boolean> | null = null;

  /** Persists rotated tokens; also consulted before refreshing (see refreshSession). */
  tokenStore: TokenStore | null = null;
  /**
   * Re-binds a just-refreshed access token to this device. The server issues
   * refreshed access tokens without a device, and device endpoints reject those.
   */
  rebind: ((api: CpmeshApi) => Promise<void>) | null = null;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  setTokens(access: string, refresh: string): void {
    this.accessToken = access;
    this.refreshToken = refresh;
  }

  get access(): string | null {
    return this.accessToken;
  }

  get refresh(): string | null {
    return this.refreshToken;
  }

  // === Core request plumbing ===

  private async request<T>(
    path: string,
    opts: {
      method?: string;
      body?: unknown;
      auth?: boolean;
      refreshed?: boolean;
      /** Sent instead of the session's access token, never refreshed (e.g. a sign-in ticket). */
      token?: string;
    } = {},
  ): Promise<T> {
    const { method = "GET", body, auth = true, refreshed = false, token } = opts;
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const sentToken = token ?? (auth ? this.accessToken : null);
    if (sentToken) {
      headers.Authorization = `Bearer ${sentToken}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30_000),
    });

    if (res.status === 401 && auth && token === undefined && !refreshed) {
      const ok = await this.refreshSession(sentToken);
      if (ok) return this.request<T>(path, { ...opts, refreshed: true });
      throw new SessionExpiredError(SESSION_EXPIRED_MESSAGE);
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
   * tokens are single-use: the server revokes the presented one, and seeing it
   * again counts as token theft and revokes every session of the user. So
   * concurrent callers share one refresh, and a pair already rotated by another
   * process sharing the session is adopted instead of refreshing again.
   */
  refreshSession(rejectedAccess: string | null = this.accessToken): Promise<boolean> {
    this.refreshing ??= this.doRefresh(rejectedAccess).finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async doRefresh(rejectedAccess: string | null): Promise<boolean> {
    const stored = this.tokenStore?.load();
    if (
      stored?.refresh &&
      stored.refresh !== this.refreshToken &&
      stored.refresh !== this.spentRefreshToken
    ) {
      this.accessToken = stored.access || null;
      this.refreshToken = stored.refresh;
    }
    if (this.accessToken && this.accessToken !== rejectedAccess) return true;
    if (!this.refreshToken) return false;

    let data: { access_token: string; refresh_token?: string };
    try {
      const res = await fetch(`${this.baseUrl}/api/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: this.refreshToken }),
        signal: AbortSignal.timeout(30_000),
      });
      if (res.status === 409) {
        // Another process sharing this session used the token moments ago. Adopt the
        // pair it saved; otherwise forget the spent token, because presenting it again
        // later would count as theft and revoke every session.
        const rotated = this.tokenStore?.load();
        if (rotated?.refresh && rotated.refresh !== this.refreshToken) {
          this.accessToken = rotated.access || null;
          this.refreshToken = rotated.refresh;
          return this.accessToken !== null;
        }
        this.spentRefreshToken = this.refreshToken;
        this.refreshToken = null;
        return false;
      }
      if (!res.ok) return false;
      data = (await res.json()) as typeof data;
    } catch {
      return false;
    }

    this.refreshToken = data.refresh_token ?? this.refreshToken;
    // Persist the rotated refresh token at once; an unbound access token is
    // never persisted, so a failed re-bind is retried by the next refresh.
    this.tokenStore?.save(this.rebind ? "" : data.access_token, this.refreshToken);
    this.accessToken = data.access_token;
    if (this.rebind) {
      try {
        await this.rebind(this);
      } catch {
        this.accessToken = null;
        return false;
      }
      this.tokenStore?.save(this.accessToken ?? "", this.refreshToken);
    }
    return true;
  }

  // === Auth ===

  /**
   * Password sign-in. Throws {@link MfaRequiredError} when the account continues
   * with a second factor (see {@link verifyMfa}).
   */
  async login(
    username: string,
    password: string,
    deviceName: string,
  ): Promise<AuthResponse> {
    try {
      return await this.request<AuthResponse>("/api/auth/login", {
        method: "POST",
        auth: false,
        body: { username, password, device_name: deviceName },
      });
    } catch (e) {
      const challenge =
        e instanceof ApiError && e.code === "mfa_required" ? mfaChallenge(e.body) : null;
      throw challenge ? new MfaRequiredError(e as ApiError, challenge) : e;
    }
  }

  /** Finishes a sign-in with a second factor; `ticket` is the challenge's mfa_token. */
  async verifyMfa(
    ticket: string,
    method: "totp" | "recovery",
    code: string,
  ): Promise<MfaVerifyResponse> {
    return this.request<MfaVerifyResponse>("/api/mfa/verify", {
      method: "POST",
      auth: false,
      token: ticket,
      body: { method, code },
    });
  }

  async registerDevice(
    req: RegisterDeviceRequest,
    signChallenge: (challenge: string) => string,
    opts: { retryOnExpiry?: boolean } = {},
  ): Promise<RegisterDeviceResponse> {
    const challenge = await this.request<{ challenge: string }>("/api/devices/challenge", {
      method: "POST", refreshed: opts.retryOnExpiry === false,
    });
    if (typeof challenge.challenge !== "string") throw new Error("Invalid device challenge");
    const resp = await this.request<RegisterDeviceResponse>("/api/devices", {
      method: "POST",
      body: { ...req, proof: { challenge: challenge.challenge, signature: signChallenge(challenge.challenge) } },
      // Never replay a single-use proof with a different bearer session.
      refreshed: true,
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
  return new ApiError(
    res.status,
    text(body.error) ?? text(body.message) ?? (res.statusText || `HTTP ${res.status}`),
    text(body.code),
    body,
  );
}

function mfaChallenge(body: Record<string, unknown>): MfaChallenge | null {
  if (typeof body.mfa_token !== "string" || !body.mfa_token) return null;
  return {
    mfa_token: body.mfa_token,
    stage: body.stage === "enroll" ? "enroll" : "verify",
    // The server always lists them; assume the usual ones if it did not
    methods: Array.isArray(body.methods)
      ? body.methods.filter((m): m is string => typeof m === "string")
      : ["totp", "recovery"],
  };
}
