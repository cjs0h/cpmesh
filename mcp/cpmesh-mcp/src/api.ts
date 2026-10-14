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
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  StoreGroupKeyEntry,
  UserInfo,
} from "./protocol.js";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Thrown when the session can no longer be refreshed — user must log in again. */
export class SessionExpiredError extends Error {}

export class CpmeshApi {
  private baseUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

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

  // === Core request plumbing ===

  private async request<T>(
    path: string,
    opts: {
      method?: string;
      body?: unknown;
      auth?: boolean;
      refreshed?: boolean;
    } = {},
  ): Promise<T> {
    const { method = "GET", body, auth = true, refreshed = false } = opts;
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth && this.accessToken) {
      headers.Authorization = `Bearer ${this.accessToken}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (res.status === 401 && auth && !refreshed) {
      const ok = await this.tryRefresh();
      if (ok) return this.request<T>(path, { ...opts, refreshed: true });
      throw new SessionExpiredError(
        "session expired — call cpmesh_login again (tokens could not be refreshed)",
      );
    }

    if (!res.ok) {
      throw new ApiError(res.status, await readErrorMessage(res));
    }

    if (res.status === 204) return undefined as T;
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  private async tryRefresh(): Promise<boolean> {
    if (!this.refreshToken) return false;
    try {
      const res = await fetch(`${this.baseUrl}/api/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: this.refreshToken }),
      });
      if (!res.ok) return false;
      const data = (await res.json()) as { access_token: string };
      // Keep the existing refresh token, mirroring the web client.
      this.accessToken = data.access_token;
      return true;
    } catch {
      return false;
    }
  }

  // === Auth ===

  async login(
    username: string,
    password: string,
    deviceName: string,
  ): Promise<AuthResponse> {
    return this.request<AuthResponse>("/api/auth/login", {
      method: "POST",
      auth: false,
      body: { username, password, device_name: deviceName },
    });
  }

  async registerDevice(
    req: RegisterDeviceRequest,
  ): Promise<RegisterDeviceResponse> {
    const resp = await this.request<RegisterDeviceResponse>("/api/devices", {
      method: "POST",
      body: req,
    });
    // The server returns a device-bound access token.
    this.accessToken = resp.access_token;
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

  async getDeviceKeys(): Promise<{ devices: DeviceInfo[] }> {
    return this.request<{ devices: DeviceInfo[] }>("/api/devices/keys");
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
    return this.request<GroupKeysResponse>(`/api/group-keys/current${q}`);
  }

  // === Approvals ===

  async getMyApprovalStatus(): Promise<ApprovalStatusResponse> {
    return this.request<ApprovalStatusResponse>("/api/device-approvals/me");
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

async function readErrorMessage(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string; message?: string };
    return body.error ?? body.message ?? res.statusText;
  } catch {
    return res.statusText;
  }
}
