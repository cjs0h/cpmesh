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
});
