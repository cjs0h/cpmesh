/**
 * Two-factor sign-in against a fake of the cpmesh sign-in endpoints.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CpmeshApi } from "../src/api.js";
import { SignInFlow, TICKET_LIFETIME_MS, codeMethod } from "../src/signin.js";

const TOTP = "123456";
const RECOVERY = "abcd-efgh-ijkl-mnop";

interface Request {
  path: string;
  auth?: string;
  body?: Record<string, unknown>;
}

/**
 * A correct password answers with a single-use sign-in ticket, unless
 * `tokensOnPassword` (servers without two-factor authentication). After three
 * wrong codes the second factor is locked.
 */
function fakeServer(
  opts: {
    stage?: "verify" | "enroll";
    methods?: string[];
    tokensOnPassword?: boolean;
    suspended?: boolean;
  } = {},
) {
  const requests: Request[] = [];
  const tickets = new Set<string>();
  let issued = 0;
  let failures = 0;
  let recoveryLeft = 10;

  globalThis.fetch = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const req: Request = {
      path: new URL(String(input)).pathname,
      auth: (init?.headers as Record<string, string> | undefined)?.Authorization,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    };
    requests.push(req);
    const reply = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

    if (req.path === "/api/auth/login") {
      if (req.body?.password !== "pw") return reply(401, { error: "invalid credentials" });
      if (opts.suspended) {
        return reply(403, { error: "This account is suspended. Contact your administrator.", code: "account_suspended" });
      }
      if (opts.tokensOnPassword) {
        return reply(200, { access_token: "at-password", refresh_token: "rt-password", user_id: "u1" });
      }
      const ticket = `ticket-${++issued}`;
      tickets.add(ticket);
      return reply(403, {
        error: "Two-factor authentication is required: enter the code from your authenticator app or use a passkey.",
        code: "mfa_required",
        mfa_token: ticket,
        stage: opts.stage ?? "verify",
        methods: opts.methods ?? ["totp", "webauthn", "recovery"],
        email_code_required: false,
        email_hint: null,
        passkeys_available: true,
      });
    }
    if (req.path === "/api/mfa/verify") {
      const ticket = req.auth?.replace(/^Bearer /, "") ?? "";
      if (!tickets.has(ticket)) return reply(401, { error: "invalid or expired token; sign in again" });
      if (failures >= 3) {
        return reply(429, { error: "Too many failed attempts. Try again in 15 minutes.", code: "mfa_locked" });
      }
      const { method, code } = req.body as { method: string; code: string };
      const ok =
        method === "totp"
          ? code === TOTP
          : code.toLowerCase().replace(/[\s-]/g, "") === RECOVERY.replace(/-/g, "");
      if (!ok) {
        failures++;
        return reply(401, { error: method === "totp" ? "invalid authentication code" : "invalid recovery code" });
      }
      tickets.delete(ticket);
      return reply(200, {
        access_token: `at-${ticket}`,
        refresh_token: `rt-${ticket}`,
        ...(method === "recovery" && { recovery_codes_remaining: --recoveryLeft }),
      });
    }
    return reply(404, { error: "not found" });
  }) as typeof fetch;

  return {
    requests,
    tickets,
    count: (path: string) => requests.filter((r) => r.path === path).length,
    verifications: () => requests.filter((r) => r.path === "/api/mfa/verify"),
  };
}

const realFetch = globalThis.fetch;
const account = { serverUrl: "https://srv", username: "alice", deviceName: "MCP Agent" };
let now = 0;
let signIns: SignInFlow;

/** Each cpmesh_login call uses a fresh API client, like CpmeshDevice.login. */
const signIn = (req: { password?: string; code?: string }) =>
  signIns.signIn(new CpmeshApi(account.serverUrl), { ...account, ...req });

beforeEach(() => {
  now = 1_000_000;
  signIns = new SignInFlow(() => now);
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("codeMethod", () => {
  it("sends six digits as an authenticator code and anything else as a recovery code", () => {
    expect(codeMethod(" 123 456 ")).toEqual({ method: "totp", code: "123456" });
    expect(codeMethod(" ABCD-efgh-ijkl-mnop ")).toEqual({ method: "recovery", code: "ABCD-efgh-ijkl-mnop" });
    expect(codeMethod("1234567")).toEqual({ method: "recovery", code: "1234567" });
  });
});

describe("SignInFlow", () => {
  it("asks for the code, then finishes the sign-in with it and without the password", async () => {
    const server = fakeServer();

    const first = await signIn({ password: "pw" });
    expect(first).toMatchObject({ status: "mfa_required", methods: ["totp", "recovery"] });
    expect(first.status === "mfa_required" && first.message).toMatch(
      /6-digit code from their authenticator app \(or one of their recovery codes\).*cpmesh_login again with the code/,
    );
    expect(JSON.stringify(first)).not.toContain("ticket-1");
    expect(signIns.waiting()).toEqual({ serverUrl: "https://srv", username: "alice" });

    now += 5 * 60_000;
    await expect(signIn({ code: "123 456" })).resolves.toEqual({
      status: "signed_in",
      auth: { access_token: "at-ticket-1", refresh_token: "rt-ticket-1" },
    });
    expect(server.verifications()).toEqual([
      { path: "/api/mfa/verify", auth: "Bearer ticket-1", body: { method: "totp", code: TOTP } },
    ]);
    expect(server.count("/api/auth/login")).toBe(1);
    expect(signIns.waiting()).toBeNull();
  });

  it("finishes in one call when the code comes with the password", async () => {
    const server = fakeServer();
    await expect(signIn({ password: "pw", code: TOTP })).resolves.toMatchObject({
      status: "signed_in",
      auth: { access_token: "at-ticket-1" },
    });
    expect(server.requests.map((r) => r.path)).toEqual(["/api/auth/login", "/api/mfa/verify"]);
  });

  it("accepts a recovery code and reports how many are left", async () => {
    const server = fakeServer();
    await signIn({ password: "pw" });
    await expect(signIn({ code: "ABCD-EFGH-IJKL-MNOP" })).resolves.toMatchObject({
      status: "signed_in",
      recoveryCodesRemaining: 9,
    });
    expect(server.verifications()[0]?.body).toEqual({ method: "recovery", code: "ABCD-EFGH-IJKL-MNOP" });
  });

  it("keeps the sign-in after a wrong code so the user can try again", async () => {
    const server = fakeServer();
    await signIn({ password: "pw" });
    await expect(signIn({ code: "000000" })).rejects.toThrow(
      /^The code was not accepted \(invalid authentication code\)\. Ask the user for a new code/,
    );
    await expect(signIn({ code: TOTP })).resolves.toMatchObject({ status: "signed_in" });
    expect(server.count("/api/auth/login")).toBe(1);
  });

  it("needs the password again once the sign-in expired", async () => {
    const server = fakeServer();
    await signIn({ password: "pw" });
    now += TICKET_LIFETIME_MS;

    expect(signIns.waiting()).toBeNull();
    await expect(signIn({ code: TOTP })).rejects.toThrow(/expired.*password and a new code/);
    expect(server.verifications()).toEqual([]);

    await expect(signIn({ password: "pw", code: TOTP })).resolves.toMatchObject({
      auth: { access_token: "at-ticket-2" },
    });
  });

  it("signs in again with the password when the server no longer accepts the ticket", async () => {
    const server = fakeServer();
    await signIn({ password: "pw" });
    server.tickets.clear();

    await expect(signIn({ password: "pw", code: TOTP })).resolves.toMatchObject({
      auth: { access_token: "at-ticket-2" },
    });
    expect(server.verifications().map((r) => r.auth)).toEqual(["Bearer ticket-1", "Bearer ticket-2"]);

    await signIn({ password: "pw" });
    server.tickets.clear();
    await expect(signIn({ code: TOTP })).rejects.toThrow(/expired.*password and a new code/);
  });

  it("explains that two-factor authentication must be set up on the web dashboard first", async () => {
    fakeServer({ stage: "enroll", methods: ["totp", "webauthn"] });
    await expect(signIn({ password: "pw" })).rejects.toThrow(
      /not set up yet.*sign in on the web dashboard at https:\/\/srv\/#\/login and set up an authenticator app/,
    );
    expect(signIns.waiting()).toBeNull();
  });

  it("explains that passkeys cannot be used", async () => {
    fakeServer({ methods: ["webauthn"] });
    await expect(signIn({ password: "pw" })).rejects.toThrow(
      /only second factor is a passkey.*add an authenticator app on the web dashboard \(https:\/\/srv\/#\/settings/,
    );
    expect(signIns.waiting()).toBeNull();
  });

  it("asks accounts with a passkey and recovery codes for a recovery code", async () => {
    const server = fakeServer({ methods: ["webauthn", "recovery"] });
    const first = await signIn({ password: "pw" });
    expect(first).toMatchObject({ status: "mfa_required", methods: ["recovery"] });
    expect(first.status === "mfa_required" && first.message).toMatch(/passkey.*one of their recovery codes/);

    await expect(signIn({ code: TOTP })).rejects.toThrow(/takes a recovery code, not a 6-digit code/);
    expect(server.verifications()).toEqual([]);
    await expect(signIn({ code: RECOVERY })).resolves.toMatchObject({ status: "signed_in" });
  });

  it("reports wrong passwords, suspended accounts and locked sign-ins readably", async () => {
    fakeServer();
    await expect(signIn({ password: "wrong" })).rejects.toThrow("invalid credentials");

    fakeServer({ suspended: true });
    await expect(signIn({ password: "pw" })).rejects.toThrow(/account is suspended/);

    fakeServer();
    await signIn({ password: "pw" });
    for (let i = 0; i < 3; i++) await expect(signIn({ code: "000000" })).rejects.toThrow(/not accepted/);
    await expect(signIn({ code: TOTP })).rejects.toThrow(
      "Too many failed attempts. Try again in 15 minutes. After that, call cpmesh_login again with the password and a new code.",
    );
    expect(signIns.waiting()).toBeNull();
  });

  it("works with servers that return tokens for the password alone", async () => {
    const server = fakeServer({ tokensOnPassword: true });
    await expect(signIn({ password: "pw", code: TOTP })).resolves.toEqual({
      status: "signed_in",
      auth: { access_token: "at-password", refresh_token: "rt-password", user_id: "u1" },
    });
    expect(server.verifications()).toEqual([]);
  });

  it("asks for the password when no sign-in is waiting for a code", async () => {
    fakeServer();
    await expect(signIn({ code: TOTP })).rejects.toThrow(
      /No sign-in for "alice" is waiting for a two-factor code: call cpmesh_login with the password and the code/,
    );
    await expect(signIn({})).rejects.toThrow(/^No password/);
  });

  it("repeats the request for the code while the sign-in is waiting", async () => {
    const server = fakeServer();
    await signIn({ password: "pw" });
    now += 6 * 60_000;
    const again = await signIn({});
    expect(again).toMatchObject({ status: "mfa_required" });
    expect(again.status === "mfa_required" && again.message).toMatch(/for the next 4 minutes/);
    expect(server.count("/api/auth/login")).toBe(1);
  });

  it("matches the waiting sign-in by server and account", async () => {
    fakeServer();
    await signIn({ password: "pw" });
    expect(signIns.waiting("https://srv/", " ALICE ")).toEqual({ serverUrl: "https://srv", username: "alice" });
    expect(signIns.waiting(undefined, "alice")).not.toBeNull();
    expect(signIns.waiting("https://other")).toBeNull();
    expect(signIns.waiting(undefined, "bob")).toBeNull();
    signIns.clear();
    expect(signIns.waiting()).toBeNull();
  });
});
