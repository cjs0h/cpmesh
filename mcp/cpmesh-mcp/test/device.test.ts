/**
 * CpmeshDevice session flows against an in-memory fake of the cpmesh REST API.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CpmeshDevice } from "../src/device.js";
import { loadSession } from "../src/state.js";

interface FakeRequest {
  path: string;
  method: string;
  auth?: string;
  body?: Record<string, unknown>;
}

/**
 * Minimal server: login and refresh issue user-level tokens, device
 * registration issues device-bound ones, refresh tokens are single-use, and
 * the account has no other devices.
 */
function fakeServer() {
  const valid = new Set<string>();
  const requests: FakeRequest[] = [];
  let refreshToken = "refresh-1";
  let issued = 0;
  let bound = 0;

  globalThis.fetch = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const req: FakeRequest = {
      path: new URL(String(input)).pathname,
      method: init?.method ?? "GET",
      auth: (init?.headers as Record<string, string> | undefined)?.Authorization,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    };
    requests.push(req);
    const reply = (status: number, body?: unknown) =>
      new Response(body === undefined ? null : JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });

    if (req.path === "/api/auth/login") {
      valid.add("login-token");
      return reply(200, { access_token: "login-token", refresh_token: refreshToken, user_id: "u1" });
    }
    if (req.path === "/api/auth/refresh") {
      if (req.body?.refresh_token !== refreshToken) return reply(401, { error: "invalid refresh token" });
      refreshToken = `refresh-${++issued + 1}`;
      valid.add(`unbound-${issued}`);
      return reply(200, { access_token: `unbound-${issued}`, refresh_token: refreshToken });
    }
    const token = req.auth?.replace(/^Bearer /, "");
    if (!token || !valid.has(token)) return reply(401, { error: "invalid token" });

    if (req.path === "/api/devices" && req.method === "POST") {
      const deviceToken = `device-token-${++bound}`;
      valid.add(deviceToken);
      return reply(201, { device: { id: "d1", status: "approved", is_reregistration: false }, access_token: deviceToken });
    }
    if (req.path === "/api/group-key" && req.method === "GET") return reply(404, { error: "no group key" });
    if (req.path === "/api/group-key" && req.method === "POST") return reply(200, {});
    if (req.path === "/api/devices/keys") return reply(200, { devices: [] });
    if (req.path === "/api/devices") return reply(200, []);
    return reply(404, { error: `unexpected ${req.method} ${req.path}` });
  }) as typeof fetch;

  return { requests, valid };
}

const realFetch = globalThis.fetch;
let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "cpmesh-mcp-test-"));
  process.env.CPMESH_HOME = home;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  delete process.env.CPMESH_HOME;
  rmSync(home, { recursive: true, force: true });
});

describe("CpmeshDevice", () => {
  it("login registers the device with the login token and stores the device-bound session", async () => {
    const server = fakeServer();

    const res = await new CpmeshDevice().login("https://srv", "alice", "pw");

    expect(res.status).toBe("approved");
    const register = server.requests.find((r) => r.path === "/api/devices" && r.method === "POST");
    expect(register?.auth).toBe("Bearer login-token");
    const session = loadSession();
    expect(session).toMatchObject({ device_id: "d1", refresh_token: "refresh-1" });
    expect(session?.access_token).toMatch(/^device-token-/);
    expect(session?.fingerprint).toBe(register?.body?.fingerprint);
  });

  it("refreshes an expired session, re-binds it to the device and persists the rotated tokens", async () => {
    const server = fakeServer();
    await new CpmeshDevice().login("https://srv", "alice", "pw");
    const before = loadSession()!;
    server.valid.clear(); // every issued access token has expired

    await expect(new CpmeshDevice().listDevices()).resolves.toEqual([]);

    const refreshes = server.requests.filter((r) => r.path === "/api/auth/refresh");
    expect(refreshes.map((r) => r.body?.refresh_token)).toEqual(["refresh-1"]);
    const rebind = server.requests.filter((r) => r.path === "/api/devices" && r.method === "POST").at(-1);
    expect(rebind?.auth).toBe("Bearer unbound-1");
    expect(rebind?.body?.fingerprint).toBe(before.fingerprint);
    const after = loadSession()!;
    expect(after.refresh_token).toBe("refresh-2");
    expect(after.access_token).toMatch(/^device-token-/);
    expect(after.access_token).not.toBe(before.access_token);
  });
});
