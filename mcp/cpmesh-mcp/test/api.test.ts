/**
 * REST client tests with a mocked global fetch.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, CpmeshApi, SessionExpiredError } from "../src/api.js";

function mockFetch(handler: (url: string, init?: RequestInit) => { status: number; body: unknown }) {
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const { status, body } = handler(url, init);
    return new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  });
  return calls;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("CpmeshApi", () => {
  it("login posts credentials without auth header", async () => {
    const calls = mockFetch(() => ({
      status: 200,
      body: { access_token: "at", refresh_token: "rt", user_id: "u1" },
    }));
    const api = new CpmeshApi("https://srv");
    const res = await api.login("alice", "pw", "MCP Agent");
    expect(res.user_id).toBe("u1");
    expect(calls[0]!.url).toBe("https://srv/api/auth/login");
    const body = JSON.parse(calls[0]!.init!.body as string);
    expect(body).toEqual({ username: "alice", password: "pw", device_name: "MCP Agent" });
    expect((calls[0]!.init!.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("registerDevice switches to the device-bound token", async () => {
    const calls = mockFetch((url) =>
      url.includes("/api/devices")
        ? { status: 201, body: { device: { id: "d1", status: "pending", is_reregistration: false }, access_token: "device-token" } }
        : { status: 404, body: { error: "nf" } },
    );
    const api = new CpmeshApi("https://srv");
    api.setTokens("old", "refresh");
    const res = await api.registerDevice({
      name: "MCP",
      public_key: "cHVi",
      public_key_sig: "c2ln",
      fingerprint: "fp",
    });
    expect(res.device.id).toBe("d1");
    expect(api.access).toBe("device-token");
    expect((calls[0]!.init!.headers as Record<string, string>).Authorization).toBe("Bearer old");
  });

  it("surfaces server error messages as ApiError", async () => {
    mockFetch(() => ({ status: 401, body: { error: "invalid credentials" } }));
    const api = new CpmeshApi("https://srv");
    await expect(api.login("x", "y", "z")).rejects.toThrow(ApiError);
    await expect(api.login("x", "y", "z")).rejects.toThrow("invalid credentials");
  });

  it("refreshes the access token once on 401 and retries", async () => {
    let historyCalls = 0;
    mockFetch((url) => {
      if (url.includes("/api/auth/refresh")) {
        return { status: 200, body: { access_token: "fresh" } };
      }
      historyCalls++;
      if (historyCalls === 1) return { status: 401, body: { error: "expired" } };
      return { status: 200, body: { entries: [], has_more: false } };
    });
    const api = new CpmeshApi("https://srv");
    api.setTokens("stale", "refresh-token");
    const res = await api.getClipboardHistory(10, 0);
    expect(res.entries).toEqual([]);
    expect(api.access).toBe("fresh");
  });

  it("throws SessionExpiredError when refresh fails", async () => {
    mockFetch((url) =>
      url.includes("/api/auth/refresh")
        ? { status: 401, body: { error: "bad refresh" } }
        : { status: 401, body: { error: "expired" } },
    );
    const api = new CpmeshApi("https://srv");
    api.setTokens("stale", "refresh-token");
    await expect(api.getClipboardHistory(10, 0)).rejects.toThrow(SessionExpiredError);
  });

  it("getGroupKey resolves null on 404 (first device)", async () => {
    mockFetch(() => ({ status: 404, body: { error: "no group key" } }));
    const api = new CpmeshApi("https://srv");
    api.setTokens("t", "r");
    expect(await api.getGroupKey()).toBeNull();
  });

  it("rotates the refresh token, re-binds the new access token and persists the pair", async () => {
    const calls = mockFetch((url, init) => {
      if (url.endsWith("/api/auth/refresh")) {
        return { status: 200, body: { access_token: "unbound", refresh_token: "rt2" } };
      }
      const auth = (init?.headers as Record<string, string>).Authorization;
      if (url.endsWith("/api/devices") && init?.method === "POST") {
        return auth === "Bearer unbound"
          ? { status: 200, body: { device: { id: "d1", status: "approved", is_reregistration: false }, access_token: "bound" } }
          : { status: 401, body: { error: "expired" } };
      }
      return auth === "Bearer bound" ? { status: 200, body: [] } : { status: 401, body: { error: "expired" } };
    });
    const saved: [string, string][] = [];
    const api = new CpmeshApi("https://srv");
    api.setTokens("stale", "rt1");
    api.tokenStore = { load: () => null, save: (a, r) => void saved.push([a, r]) };
    api.rebind = async (a) => {
      await a.registerDevice(
        { name: "MCP", public_key: "cHVi", public_key_sig: "c2ln", fingerprint: "fp" },
        { retryOnExpiry: false },
      );
    };

    await expect(api.getDevices()).resolves.toEqual([]);
    const refreshCall = calls.find((c) => c.url.endsWith("/api/auth/refresh"))!;
    expect(JSON.parse(refreshCall.init!.body as string)).toEqual({ refresh_token: "rt1" });
    // The unbound access token is never persisted.
    expect(saved).toEqual([["", "rt2"], ["bound", "rt2"]]);
    expect(api.access).toBe("bound");
    expect(api.refresh).toBe("rt2");
  });

  it("shares one refresh between concurrent requests", async () => {
    let refreshCalls = 0;
    mockFetch((url, init) => {
      if (url.endsWith("/api/auth/refresh")) {
        refreshCalls++;
        return { status: 200, body: { access_token: "fresh", refresh_token: "rt2" } };
      }
      const auth = (init?.headers as Record<string, string>).Authorization;
      return auth === "Bearer fresh"
        ? { status: 200, body: { entries: [], has_more: false } }
        : { status: 401, body: { error: "expired" } };
    });
    const api = new CpmeshApi("https://srv");
    api.setTokens("stale", "rt1");
    await Promise.all([api.getClipboardHistory(10, 0), api.getClipboardHistory(10, 10)]);
    expect(refreshCalls).toBe(1);
    expect(api.refresh).toBe("rt2");
  });

  it("adopts tokens another process already rotated instead of reusing the spent refresh token", async () => {
    let refreshCalls = 0;
    mockFetch((url, init) => {
      if (url.endsWith("/api/auth/refresh")) {
        refreshCalls++;
        return { status: 401, body: { error: "session compromised, all sessions revoked" } };
      }
      const auth = (init?.headers as Record<string, string>).Authorization;
      return auth === "Bearer theirs" ? { status: 200, body: [] } : { status: 401, body: { error: "expired" } };
    });
    const api = new CpmeshApi("https://srv");
    api.setTokens("mine", "rt-spent");
    api.tokenStore = { load: () => ({ access: "theirs", refresh: "rt-rotated" }), save: vi.fn() };
    await expect(api.getDevices()).resolves.toEqual([]);
    expect(refreshCalls).toBe(0);
    expect(api.refresh).toBe("rt-rotated");
  });

  it("keeps the rotated refresh token when re-binding fails and drops the unbound access token", async () => {
    mockFetch((url) =>
      url.endsWith("/api/auth/refresh")
        ? { status: 200, body: { access_token: "unbound", refresh_token: "rt2" } }
        : { status: 401, body: { error: "expired" } },
    );
    const saved: [string, string][] = [];
    const api = new CpmeshApi("https://srv");
    api.setTokens("stale", "rt1");
    api.tokenStore = { load: () => null, save: (a, r) => void saved.push([a, r]) };
    api.rebind = async () => {
      throw new Error("offline");
    };
    await expect(api.getDevices()).rejects.toThrow(SessionExpiredError);
    expect(saved).toEqual([["", "rt2"]]);
    expect(api.refresh).toBe("rt2");
    expect(api.access).toBeNull();
  });
});
