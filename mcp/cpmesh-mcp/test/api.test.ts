/**
 * REST client tests with a mocked global fetch: OAuth refresh at /oauth/token
 * (single-use rotation, shared profiles, retries) and error mapping.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, CpmeshApi, ScopeError, SessionExpiredError, TemporarilyUnavailableError } from "../src/api.js";

type Reply = { status: number; body?: unknown; headers?: Record<string, string> } | Error;

function mockFetch(handler: (url: string, init?: RequestInit) => Reply) {
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const reply = handler(url, init);
    if (reply instanceof Error) throw reply;
    return new Response(reply.body === undefined ? null : JSON.stringify(reply.body), {
      status: reply.status,
      headers: { "Content-Type": "application/json", ...reply.headers },
    });
  }) as typeof fetch;
  return calls;
}

const form = (init?: RequestInit) => Object.fromEntries(new URLSearchParams(String(init?.body)));
const bearer = (init?: RequestInit) => (init?.headers as Record<string, string> | undefined)?.Authorization;
const USER = "00000000-0000-4000-8000-0000000000a1";
const GRANT = "00000000-0000-4000-8000-0000000000b1";
const tokens = (access: string, refresh: string, scope = "clipboard:read clipboard:write") => ({
  status: 200, body: { access_token: access, token_type: "Bearer", expires_in: 3600, refresh_token: refresh, scope, user_id: USER, grant_id: GRANT },
});
/** A network failure before anything was sent (the connection was refused). */
const refused = () => Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } });

function api(access = "stale", refresh = "rt1") {
  const client = new CpmeshApi("https://srv");
  client.setTokens(access, refresh);
  client.wait = async () => undefined;
  return client;
}

/** The profile's token pair as session.json keeps it, shared by every client using it. */
function profileStore(access = "stale", refresh = "rt1") {
  let pair = { access, refresh };
  const saved: unknown[] = [];
  return {
    saved,
    get pair() { return pair; },
    load: () => (pair.refresh ? pair : null),
    save: (next: { access: string; refresh: string; scope?: string }) => {
      saved.push(next);
      pair = { access: next.access, refresh: next.refresh };
    },
    signedOut: vi.fn((refresh: string) => {
      if (pair.refresh === refresh) pair = { access: "", refresh: "" };
    }),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("CpmeshApi", () => {
  it("registerDevice switches to the device-bound token", async () => {
    const calls = mockFetch((url) =>
      url.endsWith("/api/devices/challenge")
        ? { status: 200, body: { challenge: "session-challenge" } }
        : url.endsWith("/api/devices")
        ? { status: 201, body: { device: { id: "d1", status: "pending", is_reregistration: false }, access_token: "device-token", refresh_token: "device-refresh" } }
        : { status: 404, body: { error: "nf" } },
    );
    const client = api("old", "refresh");
    const res = await client.registerDevice({
      name: "MCP",
      public_key: "cHVi",
      public_key_sig: "c2ln",
      encryption_key: "ZW5j",
      encryption_key_sig: "ZW5jc2ln",
      fingerprint: "fp",
    }, () => "cHJvb2Y=");
    expect(res.device.id).toBe("d1");
    expect(client.access).toBe("device-token");
    expect(client.refresh).toBe("device-refresh");
    const body = JSON.parse(calls[1]!.init!.body as string);
    expect(body.proof).toEqual({ challenge: "session-challenge", signature: "cHJvb2Y=" });
    expect(body).toMatchObject({ encryption_key: "ZW5j", encryption_key_sig: "ZW5jc2ln" });
    expect(bearer(calls[0]!.init)).toBe("Bearer old");
  });

  it("publishes the certified encryption key and the pending SAS nonce as base64 bodies", async () => {
    const calls = mockFetch((url, init) =>
      url.endsWith("/api/devices/me/encryption-key") && init?.method === "PUT" ? { status: 204 }
        : url.endsWith("/api/device-approvals/me/nonce") && init?.method === "POST" ? { status: 204 }
        : { status: 404, body: { error: "nf" } },
    );
    const client = api("device-token", "refresh");
    const key = new Uint8Array(65).fill(4), sig = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    await expect(client.publishEncryptionKey(key, sig)).resolves.toBeUndefined();
    expect(JSON.parse(calls[0]!.init!.body as string)).toEqual({
      encryption_key: Buffer.from(key).toString("base64"), encryption_key_sig: Buffer.from(sig).toString("base64"),
    });
    const nonce = new Uint8Array(32).fill(7);
    await expect(client.submitPendingNonce("00000000-0000-4000-8000-000000000001", nonce)).resolves.toBeUndefined();
    expect(JSON.parse(calls[1]!.init!.body as string)).toEqual({
      session_id: "00000000-0000-4000-8000-000000000001", nonce: Buffer.from(nonce).toString("base64"),
    });
    await expect(client.submitPendingNonce("00000000-0000-4000-8000-000000000001", nonce.subarray(1))).rejects.toThrow("32 bytes");
    expect(calls).toHaveLength(2);
  });

  it("surfaces server error messages and codes as ApiError", async () => {
    mockFetch(() => ({ status: 409, body: { error: "maximum number of devices reached", code: "device_limit" } }));
    const error = await api("t", "r").getDevices().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 409, code: "device_limit", message: "maximum number of devices reached" });
  });

  it("maps insufficient_scope to a ScopeError naming the scope and how to re-authorize", async () => {
    mockFetch(() => ({
      status: 403,
      body: { error: "this agent needs one of these scopes: clipboard:read", code: "insufficient_scope", scope: "clipboard:read" },
      headers: { "WWW-Authenticate": 'Bearer error="insufficient_scope", scope="clipboard:read"' },
    }));
    const error = await api("t", "r").getClipboardHistory(10, 0).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ScopeError);
    expect(error).toMatchObject({ status: 403, code: "insufficient_scope", scope: "clipboard:read" });
    expect((error as Error).message).toMatch(/can't read the clipboard.*re-authorize the agent with read access.*cpmesh_login/);
  });

  it("refreshes once on 401 through /oauth/token (form-encoded, client_id, no bearer) and retries", async () => {
    let historyCalls = 0;
    const calls = mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) return tokens("fresh", "rt2");
      historyCalls++;
      return bearer(init) === "Bearer fresh" ? { status: 200, body: { entries: [], has_more: false } } : { status: 401, body: { error: "expired" } };
    });
    const client = api();
    const res = await client.getClipboardHistory(10, 0);
    expect(res.entries).toEqual([]);
    expect(historyCalls).toBe(2);
    expect(client.access).toBe("fresh");
    expect(client.refresh).toBe("rt2");
    const refresh = calls.find((c) => c.url === "https://srv/oauth/token")!;
    expect(form(refresh.init)).toEqual({ client_id: "cpmesh-mcp", grant_type: "refresh_token", refresh_token: "rt1" });
    expect((refresh.init!.headers as Record<string, string>)["Content-Type"]).toBe("application/x-www-form-urlencoded");
    expect(bearer(refresh.init)).toBeUndefined();
    expect(calls.some((c) => c.url.endsWith("/api/auth/refresh"))).toBe(false);
  });

  it("rotates the single-use refresh token and persists the pair with the granted scope", async () => {
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) return tokens("fresh", "rt2", "clipboard:write");
      return bearer(init) === "Bearer fresh" ? { status: 200, body: [] } : { status: 401, body: { error: "expired" } };
    });
    const client = api();
    const store = profileStore();
    client.tokenStore = store;
    await expect(client.getDevices()).resolves.toEqual([]);
    expect(store.saved).toEqual([{ access: "fresh", refresh: "rt2", scope: "clipboard:write" }]);
  });

  it("shares one refresh between concurrent requests", async () => {
    let refreshCalls = 0;
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) {
        refreshCalls++;
        return tokens("fresh", "rt2");
      }
      return bearer(init) === "Bearer fresh" ? { status: 200, body: { entries: [], has_more: false } } : { status: 401, body: { error: "expired" } };
    });
    const client = api();
    await Promise.all([client.getClipboardHistory(10, 0), client.getClipboardHistory(10, 10)]);
    expect(refreshCalls).toBe(1);
    expect(client.refresh).toBe("rt2");
  });

  it("adopts tokens another process already rotated instead of presenting the spent refresh token", async () => {
    let refreshCalls = 0;
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) {
        refreshCalls++;
        return { status: 400, body: { error: "invalid_grant", error_description: "the refresh token was used twice" } };
      }
      return bearer(init) === "Bearer theirs" ? { status: 200, body: [] } : { status: 401, body: { error: "expired" } };
    });
    const client = api("mine", "rt-spent");
    client.tokenStore = { load: () => ({ access: "theirs", refresh: "rt-rotated" }), save: vi.fn() };
    await expect(client.getDevices()).resolves.toEqual([]);
    expect(refreshCalls).toBe(0);
    expect(client.refresh).toBe("rt-rotated");
  });

  it("on invalid_grant, re-reads the stored session and adopts the pair another process rotated meanwhile", async () => {
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) {
        return { status: 400, body: { error: "invalid_grant", error_description: "the refresh token was already used" } };
      }
      return bearer(init) === "Bearer theirs" ? { status: 200, body: [] } : { status: 401, body: { error: "expired" } };
    });
    const client = api("mine", "rt-spent");
    let loads = 0;
    const signedOut = vi.fn();
    // Nothing newer is saved when the refresh starts; the other process saves just after
    client.tokenStore = {
      load: () => (++loads === 1 ? { access: "mine", refresh: "rt-spent" } : { access: "theirs", refresh: "rt-rotated" }),
      save: vi.fn(),
      signedOut,
    };
    await expect(client.getDevices()).resolves.toEqual([]);
    expect(client.refresh).toBe("rt-rotated");
    expect(signedOut).not.toHaveBeenCalled();
  });

  it("ends the session on invalid_grant, records it, and never presents that refresh token again", async () => {
    let refreshCalls = 0;
    mockFetch((url) => {
      if (url.endsWith("/oauth/token")) {
        refreshCalls++;
        return { status: 400, body: { error: "invalid_grant", error_description: "this agent's access was revoked; sign in again" } };
      }
      return { status: 401, body: { error: "this agent's access was revoked; sign in again", code: "invalid_token" } };
    });
    const client = api("mine", "rt-spent");
    const signedOut = vi.fn();
    client.tokenStore = { load: () => ({ access: "mine", refresh: "rt-spent" }), save: vi.fn(), signedOut };
    const error = await client.getDevices().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SessionExpiredError);
    expect((error as Error).message).toMatch(/access was revoked.*cpmesh_login/);
    await expect(client.getDevices()).rejects.toThrow(SessionExpiredError);
    expect(refreshCalls).toBe(1);
    expect(client.refresh).toBeNull();
    expect(signedOut).toHaveBeenCalledWith("rt-spent", "this agent's access was revoked; sign in again");
  });

  it("keeps the refresh token when the server is temporarily unavailable (503) and retries after Retry-After", async () => {
    let refreshCalls = 0;
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) {
        return ++refreshCalls === 1
          ? { status: 503, body: { error: "temporarily_unavailable", error_description: "temporarily unavailable, please retry" }, headers: { "Retry-After": "5" } }
          : tokens("fresh", "rt2");
      }
      return bearer(init) === "Bearer fresh" ? { status: 200, body: [] } : { status: 401, body: { error: "expired" } };
    });
    const client = api();
    const waits: number[] = [];
    client.wait = async (ms) => void waits.push(ms);
    await expect(client.getDevices()).resolves.toEqual([]);
    expect(refreshCalls).toBe(2);
    expect(waits).toEqual([5000]);
  });

  it("reports a server that stays unavailable without discarding the sign-in", async () => {
    const presented: string[] = [];
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) {
        presented.push(form(init).refresh_token!);
        return { status: 503, body: { error: "temporarily_unavailable", error_description: "temporarily unavailable, please retry" } };
      }
      return { status: 401, body: { error: "expired" } };
    });
    const client = api();
    const store = profileStore();
    client.tokenStore = store;
    await expect(client.getDevices()).rejects.toThrow(TemporarilyUnavailableError);
    expect(presented).toEqual(["rt1", "rt1", "rt1"]);
    expect(client.refresh).toBe("rt1");
    expect(store.pair.refresh).toBe("rt1");
    expect(store.signedOut).not.toHaveBeenCalled();
  });

  it("retries a refused connection and keeps the token", async () => {
    let refreshCalls = 0;
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) return ++refreshCalls < 3 ? refused() : tokens("fresh", "rt2");
      return bearer(init) === "Bearer fresh" ? { status: 200, body: [] } : { status: 401, body: { error: "expired" } };
    });
    const client = api();
    await expect(client.getDevices()).resolves.toEqual([]);
    expect(refreshCalls).toBe(3);
  });

  it("retries a lost answer once at once, then gives the token up rather than risk reuse", async () => {
    const presented: string[] = [];
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) {
        presented.push(form(init).refresh_token!);
        return Object.assign(new TypeError("fetch failed"), { cause: { code: "UND_ERR_SOCKET" } });
      }
      return { status: 401, body: { error: "expired" } };
    });
    const client = api();
    const store = profileStore();
    client.tokenStore = store;
    await expect(client.getDevices()).rejects.toThrow(SessionExpiredError);
    expect(presented).toEqual(["rt1", "rt1"]);
    expect(store.signedOut).toHaveBeenCalledWith("rt1", expect.stringMatching(/answer from the server was lost/));
    await expect(client.getDevices()).rejects.toThrow(SessionExpiredError);
    expect(presented).toHaveLength(2);
  });

  it("never presents a refresh token the profile gave up in another client, even one holding it in memory", async () => {
    const presented: string[] = [];
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) {
        presented.push(form(init).refresh_token!);
        // Used up by the server, but the new tokens were never issued
        return { status: 500, body: { error: "server_error", error_description: "internal error" } };
      }
      return { status: 401, body: { error: "expired" } };
    });
    const store = profileStore("shared-access", "R1");
    const first = api("shared-access", "R1");
    const second = api("shared-access", "R1");
    first.tokenStore = store;
    second.tokenStore = store;

    await expect(first.getDevices()).rejects.toThrow(SessionExpiredError);
    expect(store.pair.refresh).toBe("");
    const error = await second.getDevices().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SessionExpiredError);
    expect((error as Error).message).toMatch(/another call or process/);
    expect(presented).toEqual(["R1"]);
  });

  it("does not refresh with its own token when the profile holds no sign-in", async () => {
    const calls = mockFetch(() => ({ status: 401, body: { error: "expired" } }));
    const client = api("mine", "rt-mine");
    client.tokenStore = { load: () => null, save: vi.fn() };
    await expect(client.getDevices()).rejects.toThrow(SessionExpiredError);
    expect(calls.some((c) => c.url.endsWith("/oauth/token"))).toBe(false);
  });

  it("refreshes again when an adopted pair's access token has expired as well", async () => {
    mockFetch((url, init) => {
      if (url.endsWith("/oauth/token")) {
        return form(init).refresh_token === "rt-theirs" ? tokens("fresh", "rt3") : { status: 400, body: { error: "invalid_grant" } };
      }
      return bearer(init) === "Bearer fresh" ? { status: 200, body: [] } : { status: 401, body: { error: "expired" } };
    });
    const client = api("mine", "rt-old");
    client.tokenStore = { load: () => ({ access: "theirs-expired", refresh: "rt-theirs" }), save: vi.fn() };
    await expect(client.getDevices()).resolves.toEqual([]);
    expect(client.refresh).toBe("rt3");
  });

  it("getGroupKey resolves null on 404 (first device)", async () => {
    mockFetch(() => ({ status: 404, body: { error: "no group key" } }));
    expect(await api("t", "r").getGroupKey()).toBeNull();
  });
});
