/**
 * Signing in (Authorizer): the device authorization grant polled at the
 * server's pace and kept across restarts, and the browser flow with PKCE
 * through the loopback redirect.
 */

import { mkdtempSync, rmSync, statSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Authorizer } from "../src/authorization.js";
import { pkceChallenge } from "../src/oauth.js";
import { loadAuthorization, statePaths } from "../src/state.js";

const SERVER = "https://cpmesh.test";
const USER = "00000000-0000-4000-8000-0000000000a1";
const GRANT = "00000000-0000-4000-8000-0000000000b1";

interface Poll {
  at: number;
  device_code: string;
}

/**
 * The OAuth endpoints of a cpmesh server. Device codes answer from `script`
 * (one answer per poll; the last one repeats); the clock is the test's.
 */
function oauthServer(clock: { now: () => number }, script: Array<{ error: string; interval?: number } | "approve"> = ["approve"]) {
  const polls: Poll[] = [];
  const revoked: string[] = [];
  const exchanges: Record<string, string>[] = [];
  let challenge: string | undefined;
  let deviceCodes = 0;
  globalThis.fetch = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    const form = Object.fromEntries(new URLSearchParams(String(init?.body ?? "")));
    if (url === `${SERVER}/.well-known/oauth-authorization-server`) {
      return json(200, {
        issuer: SERVER,
        authorization_endpoint: `${SERVER}/oauth/authorize`,
        token_endpoint: `${SERVER}/oauth/token`,
        device_authorization_endpoint: `${SERVER}/oauth/device_authorization`,
        revocation_endpoint: `${SERVER}/oauth/revoke`,
        code_challenge_methods_supported: ["S256"],
        authorization_response_iss_parameter_supported: true,
      });
    }
    if (url === `${SERVER}/oauth/device_authorization`) {
      const code = `device-code-${++deviceCodes}`;
      return json(200, {
        device_code: code, user_code: `BCDF-GHJ${deviceCodes}`, verification_uri: `${SERVER}/activate`,
        verification_uri_complete: `${SERVER}/activate?user_code=BCDF-GHJ${deviceCodes}`, expires_in: 600, interval: 5,
      });
    }
    if (url === `${SERVER}/oauth/token` && form.grant_type === "urn:ietf:params:oauth:grant-type:device_code") {
      polls.push({ at: clock.now(), device_code: form.device_code! });
      const answer = script[Math.min(polls.length - 1, script.length - 1)]!;
      if (answer !== "approve") return json(400, { error: answer.error, error_description: answer.error, ...(answer.interval && { interval: answer.interval }) });
      return json(200, tokenBody("device-access", "device-refresh", "clipboard:write"));
    }
    if (url === `${SERVER}/oauth/token` && form.grant_type === "authorization_code") {
      exchanges.push(form);
      if (pkceChallenge(form.code_verifier!) !== challenge) return json(400, { error: "invalid_grant", error_description: "code_verifier does not match" });
      return json(200, tokenBody("browser-access", "browser-refresh", "clipboard:read clipboard:write"));
    }
    if (url === `${SERVER}/oauth/revoke`) {
      revoked.push(form.token!);
      return new Response(null, { status: 200 });
    }
    return json(404, { error: "not_found" });
  }) as typeof fetch;
  return {
    polls, revoked, exchanges,
    /** The challenge the browser was sent with (what the consent page passes on). */
    setChallenge: (value: string) => { challenge = value; },
  };
}

function tokenBody(access: string, refresh: string, scope: string) {
  return { access_token: access, token_type: "Bearer", expires_in: 3600, refresh_token: refresh, scope, user_id: USER, grant_id: GRANT };
}

/** Time that only moves when the code under test sleeps. */
function fakeClock() {
  let offset = 0;
  return {
    now: () => Date.now() + offset,
    sleep: async (ms: number) => { offset += ms; },
  };
}

/** The user's browser: follows the consent with an approval straight to the loopback redirect. */
function browserThatApproves(server: ReturnType<typeof oauthServer>, change?: (params: URLSearchParams) => void) {
  return async (url: string) => {
    const authorize = new URL(url);
    server.setChallenge(authorize.searchParams.get("code_challenge")!);
    const params = new URLSearchParams({ code: "auth-code", state: authorize.searchParams.get("state")!, iss: SERVER });
    change?.(params);
    setImmediate(() => {
      request(`${authorize.searchParams.get("redirect_uri")}?${params}`).on("error", () => undefined).end();
    });
    return true;
  };
}

let home: string;
const realFetch = globalThis.fetch;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "cpmesh-auth-test-"));
  process.env.CPMESH_HOME = home;
});

afterEach(() => {
  vi.restoreAllMocks();
  globalThis.fetch = realFetch;
  delete process.env.CPMESH_HOME;
  rmSync(home, { recursive: true, force: true });
});

describe("device authorization", () => {
  it("returns at once with the link and code, and keeps the request in a private file", async () => {
    const clock = fakeClock();
    const server = oauthServer(clock);
    const pending = await new Authorizer({ ...clock, detect: () => ({ mode: "device", reason: "this MCP server runs over SSH" }) })
      .start({ serverUrl: SERVER, mode: "auto", agentName: "Agent via cpmesh-mcp on box" });

    expect(pending).toMatchObject({
      status: "authorization_pending", mode: "device", user_code: "BCDF-GHJ1", reason: "this MCP server runs over SSH",
      verification_uri: `${SERVER}/activate`, verification_uri_complete: `${SERVER}/activate?user_code=BCDF-GHJ1`,
    });
    expect(server.polls).toHaveLength(0);
    expect(loadAuthorization()).toMatchObject({ stage: "pending", device_code: "device-code-1", interval: 5 });
    if (process.platform !== "win32") expect(statSync(statePaths().authorization).mode & 0o777).toBe(0o600);
  });

  it("polls at the interval, slows down when told to, then saves the approved tokens", async () => {
    const clock = fakeClock();
    const server = oauthServer(clock, [
      { error: "authorization_pending" }, { error: "slow_down", interval: 10 }, { error: "authorization_pending" }, "approve",
    ]);
    const authorizer = new Authorizer({ ...clock, detect: () => ({ mode: "device" }) });
    await authorizer.start({ serverUrl: SERVER, mode: "device", agentName: "" });
    const started = clock.now();

    const result = await authorizer.complete(clock.now() + 120_000);

    expect(result).toMatchObject({ status: "authorized", server_url: SERVER, tokens: { refresh_token: "device-refresh", scope: "clipboard:write", grant_id: GRANT } });
    const gaps = server.polls.map((poll, i) => poll.at - (i === 0 ? started : server.polls[i - 1]!.at));
    // First poll after the interval; slow_down raises it to the server's value from then on
    expect(gaps.map((ms) => Math.round(ms / 1000))).toEqual([5, 5, 10, 10]);
    expect(loadAuthorization()).toMatchObject({ stage: "authorized", refresh_token: "device-refresh", user_id: USER, grant_id: GRANT });
  });

  it("returns the pending request when the deadline comes first, without polling early", async () => {
    const clock = fakeClock();
    const server = oauthServer(clock, [{ error: "authorization_pending" }]);
    const authorizer = new Authorizer({ ...clock });
    await authorizer.start({ serverUrl: SERVER, mode: "device", agentName: "" });

    await expect(authorizer.complete(clock.now())).resolves.toMatchObject({ status: "authorization_pending", user_code: "BCDF-GHJ1" });
    expect(server.polls).toHaveLength(0);
    await expect(authorizer.complete(clock.now() + 12_000)).resolves.toMatchObject({ status: "authorization_pending" });
    expect(server.polls).toHaveLength(2);
  });

  it("stops when the user denies or the code expires", async () => {
    const clock = fakeClock();
    oauthServer(clock, [{ error: "access_denied" }]);
    const denied = new Authorizer({ ...clock });
    await denied.start({ serverUrl: SERVER, mode: "device", agentName: "" });
    await expect(denied.complete(clock.now() + 60_000)).resolves.toMatchObject({ status: "access_denied" });
    expect(loadAuthorization()).toBeNull();

    oauthServer(clock, [{ error: "expired_token" }]);
    const expired = new Authorizer({ ...clock });
    await expired.start({ serverUrl: SERVER, mode: "device", agentName: "" });
    await expect(expired.complete(clock.now() + 60_000)).resolves.toMatchObject({ status: "expired_token" });
    expect(loadAuthorization()).toBeNull();

    // Past its lifetime the code is given up without asking the server
    const server = oauthServer(clock, [{ error: "authorization_pending" }]);
    const lapsed = new Authorizer({ ...clock });
    await lapsed.start({ serverUrl: SERVER, mode: "device", agentName: "" });
    await expect(lapsed.complete(clock.now() + 3_600_000)).resolves.toMatchObject({ status: "expired_token" });
    expect(server.polls.length).toBeLessThanOrEqual(120);
    expect(loadAuthorization()).toBeNull();
  });

  it("keeps polling after a restart, on the saved schedule and interval", async () => {
    const clock = fakeClock();
    const server = oauthServer(clock, [{ error: "slow_down", interval: 10 }, { error: "authorization_pending" }, "approve"]);
    await new Authorizer({ ...clock }).start({ serverUrl: SERVER, mode: "device", agentName: "" });
    await new Authorizer({ ...clock }).complete(clock.now() + 6_000);
    expect(server.polls).toHaveLength(1);
    expect(loadAuthorization()).toMatchObject({ stage: "pending", interval: 10 });

    // A new process: same request, no new code, and no poll before the saved time
    const restarted = new Authorizer({ ...clock });
    expect(restarted.peek()).toMatchObject({ status: "authorization_pending", mode: "device", user_code: "BCDF-GHJ1" });
    await expect(restarted.complete(clock.now() + 1_000)).resolves.toMatchObject({ status: "authorization_pending" });
    expect(server.polls).toHaveLength(1);
    await expect(restarted.complete(clock.now() + 60_000)).resolves.toMatchObject({ status: "authorized" });
    expect(server.polls.map((poll) => poll.device_code)).toEqual(["device-code-1", "device-code-1", "device-code-1"]);
    expect(server.polls[2]!.at - server.polls[1]!.at).toBeGreaterThanOrEqual(10_000);
  });

  it("shows the same request again instead of starting a second one", async () => {
    const clock = fakeClock();
    oauthServer(clock);
    const authorizer = new Authorizer({ ...clock });
    const first = await authorizer.start({ serverUrl: SERVER, mode: "device", agentName: "" });
    const again = await new Authorizer({ ...clock }).start({ serverUrl: SERVER, mode: "auto", agentName: "" });
    expect(again.user_code).toBe(first.user_code);
    expect(vi.mocked(globalThis.fetch).mock.calls.filter(([url]) => String(url).endsWith("/device_authorization"))).toHaveLength(1);
  });
});

describe("browser sign-in", () => {
  it("exchanges the callback's code with the PKCE verifier and saves the tokens", async () => {
    const clock = fakeClock();
    const server = oauthServer(clock);
    const authorizer = new Authorizer({ ...clock, detect: () => ({ mode: "browser" }), open: browserThatApproves(server) });

    const pending = await authorizer.start({ serverUrl: SERVER, mode: "auto", agentName: "Codex via cpmesh-mcp on laptop" });
    expect(pending).toMatchObject({ status: "authorization_pending", mode: "browser", browser_opened: true });
    const authorize = new URL(pending.verification_uri);
    expect(authorize.searchParams.get("scope")).toBeNull();
    expect(authorize.searchParams.get("agent_name")).toBe("Codex via cpmesh-mcp on laptop");

    const result = await authorizer.complete(Date.now() + 10_000);
    expect(result).toMatchObject({ status: "authorized", tokens: { refresh_token: "browser-refresh", scope: "clipboard:read clipboard:write" } });
    expect(server.exchanges).toHaveLength(1);
    expect(server.exchanges[0]).toMatchObject({
      client_id: "cpmesh-mcp", grant_type: "authorization_code", code: "auth-code", redirect_uri: authorize.searchParams.get("redirect_uri"),
    });
    expect(loadAuthorization()).toMatchObject({ stage: "authorized", refresh_token: "browser-refresh" });
  });

  it("refuses a callback from another issuer without exchanging its code", async () => {
    const clock = fakeClock();
    const server = oauthServer(clock);
    const authorizer = new Authorizer({
      ...clock, detect: () => ({ mode: "browser" }), open: browserThatApproves(server, (params) => params.set("iss", "https://evil.example")),
    });
    await authorizer.start({ serverUrl: SERVER, mode: "auto", agentName: "" });
    await expect(authorizer.complete(Date.now() + 10_000)).resolves.toMatchObject({ status: "failed", message: expect.stringMatching(/did not come from/) });
    expect(server.exchanges).toHaveLength(0);
    expect(loadAuthorization()).toBeNull();
  });

  it("falls back to the device flow when auto mode cannot open a browser, but not when the browser was asked for", async () => {
    const clock = fakeClock();
    oauthServer(clock);
    const auto = await new Authorizer({ ...clock, detect: () => ({ mode: "browser" }), open: async () => false })
      .start({ serverUrl: SERVER, mode: "auto", agentName: "" });
    expect(auto).toMatchObject({ mode: "device", user_code: "BCDF-GHJ1", reason: expect.stringMatching(/could not be opened/) });

    const authorizer = new Authorizer({ ...clock, open: async () => false });
    const browser = await authorizer.start({ serverUrl: SERVER, mode: "browser", agentName: "" });
    expect(browser).toMatchObject({ mode: "browser", browser_opened: false, verification_uri: expect.stringMatching(/\/oauth\/authorize\?/) });
    // The device request it replaced is gone
    expect(loadAuthorization()).toBeNull();
    authorizer.stop();
  });

  it("times out when nobody approves", async () => {
    const clock = fakeClock();
    oauthServer(clock);
    const authorizer = new Authorizer({ ...clock, open: async () => true, browserTimeoutMs: 50 });
    await authorizer.start({ serverUrl: SERVER, mode: "browser", agentName: "" });
    await expect(authorizer.complete(Date.now() + 5_000)).resolves.toMatchObject({ status: "expired_token" });
    expect(authorizer.peek()).toBeNull();
  });

  it("revokes approved tokens nobody used when the sign-in is cancelled", async () => {
    const clock = fakeClock();
    const server = oauthServer(clock);
    const authorizer = new Authorizer({ ...clock, open: browserThatApproves(server) });
    await authorizer.start({ serverUrl: SERVER, mode: "browser", agentName: "" });
    await expect(authorizer.complete(Date.now() + 10_000)).resolves.toMatchObject({ status: "authorized" });

    await authorizer.cancel();
    expect(server.revoked).toEqual(["browser-refresh"]);
    expect(loadAuthorization()).toBeNull();
  });
});
