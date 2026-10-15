/**
 * CpmeshDevice session flows against an in-memory fake of the cpmesh REST API.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
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
 * the account has no other devices. With `mfa`, the password is followed by an
 * authenticator code (123456).
 */
function fakeServer({ mfa = false } = {}) {
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
      if (mfa) {
        return reply(403, {
          error: "Two-factor authentication is required: enter the code from your authenticator app or use a passkey.",
          code: "mfa_required",
          mfa_token: "sign-in-ticket",
          stage: "verify",
          methods: ["totp", "recovery"],
        });
      }
      valid.add("login-token");
      return reply(200, { access_token: "login-token", refresh_token: refreshToken, user_id: "u1" });
    }
    if (req.path === "/api/mfa/verify") {
      if (!mfa || req.auth !== "Bearer sign-in-ticket") return reply(401, { error: "invalid or expired token; sign in again" });
      if (req.body?.code !== "123456") return reply(401, { error: "invalid authentication code" });
      valid.add("mfa-token");
      return reply(200, { access_token: "mfa-token", refresh_token: refreshToken });
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
    if (req.path === "/api/me") return reply(200, { id: "u1", username: "alice" });
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

  it("finishes a two-factor sign-in with the code, keeping the ticket in memory only", async () => {
    const server = fakeServer({ mfa: true });
    const device = new CpmeshDevice();

    const first = await device.login("https://srv", "alice", "pw");
    expect(first).toMatchObject({ status: "mfa_required", methods: ["totp", "recovery"] });
    expect(loadSession()).toBeNull();
    expect(await device.status()).toMatchObject({ logged_in: false, two_factor_code_needed: true });
    await expect(device.listDevices()).rejects.toMatchObject({
      nextStep: expect.stringMatching(/waiting for its two-factor code/),
    });
    expect(device.waitingSignIn()).toEqual({ serverUrl: "https://srv", username: "alice" });

    const done = await device.login("https://srv", "alice", undefined, "123 456");
    expect(done.status).toBe("approved");
    const register = server.requests.find((r) => r.path === "/api/devices" && r.method === "POST");
    expect(register?.auth).toBe("Bearer mfa-token");
    // The second-factor step does not return the user ID; the device fingerprint needs it
    expect(server.requests.some((r) => r.path === "/api/me")).toBe(true);
    expect(loadSession()).toMatchObject({ user_id: "u1", device_id: "d1", refresh_token: "refresh-1" });
    const fingerprint = loadSession()?.fingerprint;
    expect(register?.body?.fingerprint).toBe(fingerprint);
    expect(device.waitingSignIn()).toBeNull();
    const stored = readdirSync(home).map((f) => readFileSync(join(home, f), "latin1"));
    expect(stored.length).toBeGreaterThan(0);
    expect(stored.join("\n")).not.toContain("sign-in-ticket");

    // The same device identity as a sign-in without a second factor
    fakeServer();
    await new CpmeshDevice().login("https://srv", "alice", "pw");
    expect(loadSession()?.fingerprint).toBe(fingerprint);
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
