/**
 * CpmeshDevice flows against an in-memory fake of the cpmesh server
 * (protocol 3 with OAuth for agents): browser-approved sign-in through the
 * device authorization grant, registration with a certified encryption key,
 * token refresh at /oauth/token, scopes, sign-out with revocation, the 0.2
 * profile upgrade, committed-SAS pairing, signed pushes, and authenticated
 * reads with a replay guard.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ScopeError, SessionExpiredError } from "../src/api.js";
import { Authorizer } from "../src/authorization.js";
import { CpmeshDevice, DeviceNotReadyError } from "../src/device.js";
import { loadAuthorization, loadMembership, loadSession, statePaths } from "../src/state.js";
import {
  DeviceKeys, ENCRYPTION_PEM_TAG, KeyPair, Keyring, clipboardDataAad, clipboardSignatureTranscript, fromBase64,
  pairingFingerprint, sasCode, sasCommitment, signedWraps, toBase64, verifyEncryptionKey, type WrapTarget,
} from "../src/crypto.js";
import { openEntry, sealEntry, verifyEntrySignature } from "../src/entry.js";
import { pinVerified } from "../src/membership.js";
import { WsError } from "../src/ws.js";
import type { ApprovalStatusResponse, ClipboardEntry, ClipboardPushPayload, DeviceInfo, StoreGroupKeyEntry } from "../src/protocol.js";

interface FakeRequest {
  path: string;
  method: string;
  auth?: string;
  body?: Record<string, unknown>;
}

const SERVER = "https://srv";
const DEVICE_ID = "00000000-0000-4000-8000-00000000000d";
const USER_ID = "00000000-0000-4000-8000-0000000000a1";
const OTHER_USER = "00000000-0000-4000-8000-0000000000a2";
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const READ_WRITE = "clipboard:read clipboard:write";

/**
 * Minimal cpmesh server for an agent: OAuth metadata, the device
 * authorization grant (approved on the first poll unless `state.approve`
 * says otherwise), single-use refresh tokens at /oauth/token, revocation, and
 * the device and clipboard API with the scope policy. Registration binds the
 * grant to the device (a newer grant supersedes the older one) and returns
 * device-bound tokens of the same grant, which refreshes keep. `state` is
 * mutable so a test can drive approvals, sessions, listings, keys and history.
 */
function fakeServer({ deviceStatus = "approved" as "approved" | "pending", scope = READ_WRITE } = {}) {
  const requests: FakeRequest[] = [];
  const access = new Map<string, { grant: string; device?: string }>();
  const refresh = new Map<string, { grant: string; device?: string; used: boolean }>();
  let issued = 0;
  let grantCount = 0;
  let deviceCodes = 0;
  const state = {
    status: deviceStatus,
    /** What the user approves for the next sign-in, and with which account. */
    scope,
    userId: USER_ID,
    approve: true as boolean | "deny",
    grants: new Map<string, { user: string; scope: string; revoked: boolean; signedOut: boolean; device?: string }>(),
    revokedTokens: [] as string[],
    registration: undefined as Record<string, unknown> | undefined,
    publishedEncryptionKey: undefined as { encryption_key: string; encryption_key_sig: string } | undefined,
    approval: { status: deviceStatus } as ApprovalStatusResponse,
    pendingNonce: undefined as Uint8Array | undefined,
    /** Devices listed by /api/devices/keys in addition to this one. */
    peers: [] as DeviceInfo[],
    groupKeys: new Map<number, { wraps: StoreGroupKeyEntry[]; from: { id: string; key: string } }>(),
    entries: [] as ClipboardEntry[],
  };
  const issue = (grant: string, device?: string) => {
    const n = ++issued;
    access.set(`access-${n}`, { grant, device });
    refresh.set(`refresh-${n}`, { grant, device, used: false });
    return { access: `access-${n}`, refresh: `refresh-${n}` };
  };
  const live = (grant: string) => {
    const g = state.grants.get(grant);
    return g !== undefined && !g.revoked && !g.signedOut;
  };
  const ownListing = (): DeviceInfo => ({
    id: DEVICE_ID, name: "MCP", online: true, status: state.status,
    public_key: state.registration?.public_key as string | undefined,
    encryption_key: state.publishedEncryptionKey?.encryption_key,
    encryption_key_sig: state.publishedEncryptionKey?.encryption_key_sig,
  });

  globalThis.fetch = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const raw = typeof init?.body === "string" ? init.body : undefined;
    const req: FakeRequest = {
      path: url.pathname,
      method: init?.method ?? "GET",
      auth: headers.Authorization,
      body: raw === undefined ? undefined
        : headers["Content-Type"] === "application/x-www-form-urlencoded" ? Object.fromEntries(new URLSearchParams(raw)) : JSON.parse(raw),
    };
    requests.push(req);
    const reply = (status: number, body?: unknown) =>
      new Response(body === undefined ? null : JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    const form = (req.body ?? {}) as Record<string, string>;

    if (req.path === "/.well-known/oauth-authorization-server") {
      return reply(200, {
        issuer: SERVER, authorization_endpoint: `${SERVER}/oauth/authorize`, token_endpoint: `${SERVER}/oauth/token`,
        device_authorization_endpoint: `${SERVER}/oauth/device_authorization`, revocation_endpoint: `${SERVER}/oauth/revoke`,
        code_challenge_methods_supported: ["S256"], authorization_response_iss_parameter_supported: true,
      });
    }
    if (req.path === "/oauth/device_authorization") {
      const n = ++deviceCodes;
      return reply(200, {
        device_code: `device-code-${n}`, user_code: `BCDF-GHJ${n}`, verification_uri: `${SERVER}/activate`,
        verification_uri_complete: `${SERVER}/activate?user_code=BCDF-GHJ${n}`, expires_in: 600, interval: 5,
      });
    }
    if (req.path === "/oauth/token") {
      if (form.client_id !== "cpmesh-mcp") return reply(400, { error: "invalid_client" });
      const tokens = (grant: string, pair: { access: string; refresh: string }) => ({
        access_token: pair.access, token_type: "Bearer", expires_in: 3600, refresh_token: pair.refresh,
        scope: state.grants.get(grant)!.scope, user_id: state.grants.get(grant)!.user, grant_id: grant,
      });
      if (form.grant_type === DEVICE_GRANT) {
        if (state.approve === "deny") return reply(400, { error: "access_denied", error_description: "the user denied the request" });
        if (!state.approve) return reply(400, { error: "authorization_pending", error_description: "waiting for the user to approve" });
        const grant = `00000000-0000-4000-8000-${String(++grantCount).padStart(12, "0")}`;
        state.grants.set(grant, { user: state.userId, scope: state.scope, revoked: false, signedOut: false });
        return reply(200, tokens(grant, issue(grant)));
      }
      if (form.grant_type === "refresh_token") {
        const entry = refresh.get(form.refresh_token!);
        if (!entry || entry.used || !live(entry.grant)) {
          return reply(400, { error: "invalid_grant", error_description: "the account signed out everywhere; sign in again" });
        }
        entry.used = true;
        return reply(200, tokens(entry.grant, issue(entry.grant, entry.device)));
      }
      return reply(400, { error: "unsupported_grant_type" });
    }
    if (req.path === "/oauth/revoke") {
      state.revokedTokens.push(form.token!);
      const entry = refresh.get(form.token!) ?? access.get(form.token!);
      const grant = entry && state.grants.get(entry.grant);
      if (grant) grant.revoked = true;
      return reply(200);
    }
    if (req.path.startsWith("/api/auth/") || req.path.startsWith("/api/mfa/")) return reply(410, { error: "agents never use this" });

    const token = req.auth?.replace(/^Bearer /, "");
    const session = token === undefined ? undefined : access.get(token);
    if (!session || !live(session.grant)) return reply(401, { error: "this agent's access was revoked; sign in again", code: "invalid_token" });
    const grant = state.grants.get(session.grant)!;
    const missing = (needed: string) =>
      grant.scope.split(" ").includes(needed) ? null
        : reply(403, { error: `this agent needs one of these scopes: ${needed}`, code: "insufficient_scope", scope: needed });

    if (req.path === "/api/devices/challenge") return reply(200, { challenge: `challenge-${issued}` });
    if (req.path === "/api/devices" && req.method === "POST") {
      state.registration = req.body;
      const { encryption_key, encryption_key_sig } = req.body as Record<string, string | undefined>;
      if (encryption_key && encryption_key_sig) state.publishedEncryptionKey = { encryption_key, encryption_key_sig };
      // The device moves to this grant; the grant it had before is superseded
      for (const [id, other] of state.grants) if (id !== session.grant && other.device === DEVICE_ID) other.revoked = true;
      grant.device = DEVICE_ID;
      const pair = issue(session.grant, DEVICE_ID);
      return reply(201, { device: { id: DEVICE_ID, status: state.status, is_reregistration: false }, access_token: pair.access, refresh_token: pair.refresh });
    }
    if (req.path === "/api/devices/me/encryption-key" && req.method === "PUT") {
      state.publishedEncryptionKey = req.body as { encryption_key: string; encryption_key_sig: string };
      return reply(204);
    }
    if (req.path === "/api/device-approvals/me" && req.method === "GET") {
      return reply(200, { ...state.approval, status: state.status, pending_nonce: state.pendingNonce && toBase64(state.pendingNonce) });
    }
    if (req.path === "/api/device-approvals/me/nonce" && req.method === "POST") {
      const nonce = fromBase64(req.body?.nonce as string);
      if (nonce.length !== 32 || req.body?.session_id !== state.approval.session_id) return reply(409, { error: "no active approval session accepts this nonce" });
      state.pendingNonce = nonce;
      return reply(204);
    }
    if (state.status !== "approved") return reply(403, { error: "device not approved" });
    if (req.path === "/api/group-keys/current" && req.method === "GET") {
      if (state.groupKeys.size === 0) return reply(404, { error: "no group key" });
      const since = Number(url.searchParams.get("since_version") ?? 0);
      const current = Math.max(...state.groupKeys.keys());
      const keys = [...state.groupKeys].filter(([version]) => version > since).map(([version, { wraps, from }]) => {
        const wrap = wraps.find((w) => w.device_id === DEVICE_ID)!;
        return { version, encrypted_key: wrap.encrypted_key, from_device_id: from.id, from_public_key: from.key, membership: wraps[0]!.membership };
      });
      return reply(200, { current_version: current, rotation_required: false, keys });
    }
    if (req.path === "/api/group-keys/rotate" && req.method === "POST") {
      const { new_version, wrapped_keys } = req.body as { new_version: number; wrapped_keys: StoreGroupKeyEntry[] };
      state.groupKeys.set(new_version, { wraps: wrapped_keys, from: { id: DEVICE_ID, key: state.registration!.public_key as string } });
      return reply(200, {});
    }
    if (req.path === "/api/devices/keys") return reply(200, { devices: [ownListing(), ...state.peers] });
    if (req.path === "/api/me") return reply(200, { id: USER_ID, username: "alice" });
    if (req.path === "/api/devices" && req.method === "GET") return reply(200, [ownListing(), ...state.peers]);
    if (req.path.startsWith("/api/devices/") && req.method === "DELETE") return missing("devices:manage") ?? reply(204);
    if (req.path === "/api/clipboard" && req.method === "GET") {
      return missing("clipboard:read") ?? reply(200, { entries: state.entries, has_more: false });
    }
    if (req.path.startsWith("/api/clipboard/") && req.method === "DELETE") return missing("clipboard:delete") ?? reply(204);
    return reply(404, { error: `unexpected ${req.method} ${req.path}` });
  }) as typeof fetch;

  return {
    requests, state,
    /** Every access token expires (as an hour later). */
    expireAccessTokens: () => access.clear(),
    /** The user signed out everywhere: the grants stay, their sessions end. */
    signOutEverywhere: () => { for (const grant of state.grants.values()) grant.signedOut = true; },
    /** Tokens of every kind the server saw in requests. */
    presentedTokens: () => requests.flatMap((r) => [r.auth?.replace(/^Bearer /, ""), (r.body as Record<string, unknown> | undefined)?.refresh_token]),
  };
}

/** A device whose sign-in polls on a clock that only moves when the test (or a wait) moves it. */
function newDevice() {
  let offset = 0;
  const clock = { now: () => Date.now() + offset, sleep: async (ms: number) => { offset += ms; } };
  const device = new CpmeshDevice({
    authorizer: new Authorizer({ ...clock, detect: () => ({ mode: "device" }), open: async () => false }),
  });
  return Object.assign(device, { clock });
}

/**
 * Signs in like an agent whose user approves at once: cpmesh_login, the poll
 * interval passes, then cpmesh_status finishes the sign-in and registers the
 * device (without syncing keys, like the first status call). Returns that status.
 */
async function signIn(device: ReturnType<typeof newDevice>) {
  const started = await device.login({ serverUrl: SERVER, mode: "device", clientName: "Test Client" });
  expect(started.status).toBe("authorization_pending");
  await device.clock.sleep(5_000);
  return device.status();
}

/** Another mesh device as the relay lists it, with its own keys for sealing/wrapping. */
function peerDevice(name: string) {
  const keys = DeviceKeys.generate();
  const id = randomUUID();
  const listing: DeviceInfo = {
    id, name, online: true, status: "approved", public_key: toBase64(keys.identity.publicKeyBytes()),
    encryption_key: toBase64(keys.encryption.publicKeyBytes()), encryption_key_sig: toBase64(keys.certifyEncryptionKey()),
  };
  const target: WrapTarget = { identity: { id, public_key: listing.public_key! }, encryptionKey: keys.encryption.publicKeyBytes() };
  return { keys, id, listing, target };
}

/** The MCP device's own keys, read back from its state directory. */
function ownKeys(): DeviceKeys {
  const paths = statePaths();
  return new DeviceKeys(KeyPair.load(paths.deviceKey), KeyPair.load(paths.encryptionKey, ENCRYPTION_PEM_TAG));
}

function entryFrom(sender: { id: string; listing: DeviceInfo }, sealed: ReturnType<typeof sealEntry>, context: { requestId: string; sentAt: number }, id = randomUUID()): ClipboardEntry {
  return {
    id, user_id: USER_ID, device_id: sender.id, device_name: sender.listing.name, content_type: "text",
    encrypted_data: toBase64(sealed.encryptedData), metadata: toBase64(sealed.metadata), created_at: "2026-01-01T00:00:00Z",
    key_version: sealed.keyVersion, request_id: context.requestId, sent_at: context.sentAt, sender_signature: toBase64(sealed.signature),
  };
}

/** Receipts for pushes without a relay WebSocket; the payload is captured for inspection. */
function captureWs(device: CpmeshDevice) {
  const payloads: ClipboardPushPayload[] = [];
  vi.spyOn(device.ws, "pushClipboard").mockImplementation(async (_url, _token, _fp, payload) => {
    payloads.push(payload);
    return { status: "accepted", request_id: payload.request_id!, entry_id: randomUUID(), created_at: "2026-01-01T00:00:00Z" };
  });
  return payloads;
}

const realFetch = globalThis.fetch;
let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "cpmesh-mcp-test-"));
  process.env.CPMESH_HOME = home;
  delete process.env.CPMESH_SERVER_URL;
});

afterEach(() => {
  vi.restoreAllMocks();
  globalThis.fetch = realFetch;
  delete process.env.CPMESH_HOME;
  rmSync(home, { recursive: true, force: true });
});

describe("CpmeshDevice", () => {
  it("signs in with an approval in the browser, registers with proof of possession and a certified key, and keeps the grant", async () => {
    const server = fakeServer();
    const device = newDevice();

    const started = await device.login({ serverUrl: `${SERVER}/`, mode: "device", clientName: "Test Client" });
    expect(started).toMatchObject({
      status: "authorization_pending", mode: "device", user_code: "BCDF-GHJ1",
      verification_uri_complete: `${SERVER}/activate?user_code=BCDF-GHJ1`,
      message: expect.stringMatching(/BCDF-GHJ1.*cpmesh_wait_for_approval/s),
    });
    const authorize = server.requests.find((r) => r.path === "/oauth/device_authorization")!;
    expect(authorize.body).toEqual({ client_id: "cpmesh-mcp", agent_name: expect.stringMatching(/^Test Client via cpmesh-mcp on .+/) });
    expect(authorize.body?.scope).toBeUndefined();
    expect(loadSession()).toBeNull();
    expect(await device.status()).toMatchObject({
      logged_in: false, authorization: { user_code: "BCDF-GHJ1" }, next_step: expect.stringMatching(/BCDF-GHJ1.*cpmesh_wait_for_approval/s),
    });

    const approved = await device.waitForApproval(60_000);
    expect(approved).toMatchObject({ approved: true, status: "approved" });
    const poll = server.requests.find((r) => r.path === "/oauth/token")!;
    expect(poll.body).toEqual({ client_id: "cpmesh-mcp", grant_type: DEVICE_GRANT, device_code: "device-code-1" });
    expect(poll.auth).toBeUndefined();

    const register = server.requests.find((r) => r.path === "/api/devices" && r.method === "POST")!;
    expect(register.auth).toBe("Bearer access-1");
    const session = loadSession()!;
    expect(session).toMatchObject({
      server_url: SERVER, user_id: USER_ID, device_id: DEVICE_ID, device_status: "approved",
      grant_id: "00000000-0000-4000-8000-000000000001", client_id: "cpmesh-mcp", scope: READ_WRITE,
      access_token: "access-2", refresh_token: "refresh-2",
    });
    expect(session.fingerprint).toBe(register.body?.fingerprint);
    expect(loadAuthorization()).toBeNull();
    // Two distinct key files; the encryption key is certified by the identity key.
    const keys = ownKeys();
    const body = register.body as Record<string, string>;
    expect(fromBase64(body.public_key!)).toEqual(keys.identity.publicKeyBytes());
    expect(fromBase64(body.encryption_key!)).toEqual(keys.encryption.publicKeyBytes());
    expect(body.encryption_key).not.toBe(body.public_key);
    expect(verifyEncryptionKey(fromBase64(body.public_key!), fromBase64(body.encryption_key!), fromBase64(body.encryption_key_sig!)))
      .toEqual(keys.encryption.publicKeyBytes());
    expect(readFileSync(statePaths().encryptionKey, "utf8")).toContain(`-----BEGIN ${ENCRYPTION_PEM_TAG}-----`);
    expect(server.requests.some((r) => r.path.startsWith("/api/auth/"))).toBe(false);
  });

  it("reports a pending sign-in, a denial, and an approval with another account without touching the profile", async () => {
    const server = fakeServer();
    server.state.approve = false;
    const device = newDevice();
    await device.login({ serverUrl: SERVER, mode: "device" });
    await expect(device.waitForApproval(5_000)).resolves.toMatchObject({
      approved: false, status: "authorization_pending", authorization: { user_code: "BCDF-GHJ1" },
    });
    await expect(device.listDevices()).rejects.toMatchObject({ nextStep: expect.stringMatching(/BCDF-GHJ1/) });

    server.state.approve = "deny";
    await expect(device.waitForApproval(60_000)).resolves.toMatchObject({
      approved: false, status: "access_denied", message: expect.stringMatching(/denied.*cpmesh_login/s),
    });
    expect(loadAuthorization()).toBeNull();

    // Signed in as alice; the user then approves a new sign-in with another account
    server.state.approve = true;
    await signIn(device);
    const before = loadSession()!;
    server.state.userId = OTHER_USER;
    await device.login({ serverUrl: SERVER, mode: "device" });
    await device.clock.sleep(5_000);
    await expect(device.waitForApproval(60_000)).rejects.toThrow(/different cpmesh account.*revoked/s);
    expect(server.state.revokedTokens).toEqual(["refresh-3"]);
    expect(loadSession()).toEqual(before);
    expect(loadAuthorization()).toBeNull();
  });

  it("refreshes an expired session at /oauth/token without registering again, and saves the rotated tokens", async () => {
    const server = fakeServer();
    await signIn(newDevice());
    const before = loadSession()!;
    server.expireAccessTokens();

    await expect(newDevice().listDevices()).resolves.toHaveLength(1);

    const refreshes = server.requests.filter((r) => r.path === "/oauth/token" && r.body?.grant_type === "refresh_token");
    expect(refreshes.map((r) => r.body?.refresh_token)).toEqual([before.refresh_token]);
    expect(server.requests.filter((r) => r.path === "/api/devices" && r.method === "POST")).toHaveLength(1);
    const after = loadSession()!;
    expect(after.refresh_token).not.toBe(before.refresh_token);
    expect(after).toMatchObject({ grant_id: before.grant_id, device_id: DEVICE_ID, scope: READ_WRITE });
  });

  it("shares rotated tokens with another process using the profile instead of presenting a used refresh token", async () => {
    const server = fakeServer();
    const first = newDevice();
    await signIn(first);
    await first.ensureReady();
    const second = newDevice();
    await second.ensureReady();
    server.expireAccessTokens();

    await first.getClipboard(); // rotates the refresh token
    await second.getClipboard(); // its cached session must adopt the rotated pair

    const presented = server.requests
      .filter((r) => r.path === "/oauth/token" && r.body?.grant_type === "refresh_token")
      .map((r) => r.body?.refresh_token);
    expect(presented).toHaveLength(1);
    expect(server.state.grants.get(loadSession()!.grant_id!)?.revoked).toBe(false);
  });

  it("keeps the profile when the sign-in ends, and signs in again without new pairing", async () => {
    const server = fakeServer();
    const device = newDevice();
    await signIn(device);
    const first = loadSession()!;
    const identity = ownKeys().identity.publicKeyBytes();
    server.signOutEverywhere();
    server.expireAccessTokens();

    const error = await device.listDevices().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SessionExpiredError);
    expect((error as Error).message).toMatch(/sign-in ended.*cpmesh_login/s);
    expect(loadSession()).toMatchObject({ access_token: "", refresh_token: "", device_id: DEVICE_ID, signed_out: expect.any(String) });
    expect(await device.status()).toMatchObject({
      logged_in: false, profile: { device_id: DEVICE_ID }, next_step: expect.stringMatching(/cpmesh_login/),
    });

    const status = await signIn(device);
    expect(status).toMatchObject({ logged_in: true, device_status: "approved", device_id: DEVICE_ID });
    const second = loadSession()!;
    expect(second.grant_id).not.toBe(first.grant_id);
    expect(second.signed_out).toBeUndefined();
    expect(ownKeys().identity.publicKeyBytes()).toEqual(identity);
    expect(fromBase64(server.state.registration!.public_key as string)).toEqual(identity);
    expect(server.state.registration!.fingerprint).toBe(first.fingerprint);
  });

  it("treats a 0.2 profile as signed out, never uses its tokens, and moves its device to the new sign-in", async () => {
    const server = fakeServer();
    const paths = statePaths();
    const keys = DeviceKeys.loadOrGenerate(paths.deviceKey, paths.encryptionKey);
    const created = "2025-06-01T00:00:00.000Z";
    writeFileSync(paths.session, JSON.stringify({
      server_url: "https://srv/", user_id: USER_ID, device_id: DEVICE_ID, device_name: "MCP Agent - old-host",
      device_status: "approved", fingerprint: "fingerprint-from-0.2", access_token: "first-party-access",
      refresh_token: "first-party-refresh", created_at: created,
    }), { mode: 0o600 });
    const device = newDevice();

    expect(await device.status()).toMatchObject({
      logged_in: false, profile: { device_id: DEVICE_ID, signed_out: expect.stringMatching(/0\.2/) },
      next_step: expect.stringMatching(/0\.2.*cpmesh_login.*keeps its keys and pairing/s),
    });
    const error = await device.getClipboard().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(DeviceNotReadyError);
    expect((error as DeviceNotReadyError).nextStep).toMatch(/cpmesh_login/);

    const status = await signIn(device);
    expect(status).toMatchObject({ logged_in: true, device_status: "approved", device_id: DEVICE_ID });
    const register = server.requests.find((r) => r.path === "/api/devices" && r.method === "POST")!;
    expect(fromBase64(register.body!.public_key as string)).toEqual(keys.identity.publicKeyBytes());
    expect(register.body!.fingerprint).toBe("fingerprint-from-0.2");
    expect(loadSession()).toMatchObject({
      device_id: DEVICE_ID, device_name: "MCP Agent - old-host", created_at: created, grant_id: expect.any(String), scope: READ_WRITE,
    });
    expect(server.presentedTokens()).not.toContain("first-party-access");
    expect(server.presentedTokens()).not.toContain("first-party-refresh");
    expect(server.requests.some((r) => r.path.startsWith("/api/auth/"))).toBe(false);
  });

  it("refuses to sign in to another server than the profile's", async () => {
    fakeServer();
    await signIn(newDevice());
    await expect(newDevice().login({ serverUrl: "https://other.example", mode: "device" })).rejects.toThrow(/cpmesh_logout first/);
  });

  it("signs out by revoking the grant with the refresh token, then wipes the profile", async () => {
    const server = fakeServer();
    const device = newDevice();
    await signIn(device);
    const session = loadSession()!;

    const message = await device.logout();

    expect(message).toMatch(/revoked on the server.*removed its device/s);
    const revoke = server.requests.find((r) => r.path === "/oauth/revoke")!;
    expect(revoke.body).toMatchObject({ client_id: "cpmesh-mcp", token: session.refresh_token });
    expect(revoke.auth).toBeUndefined();
    expect(server.state.grants.get(session.grant_id!)?.revoked).toBe(true);
    for (const file of [paths().session, paths().deviceKey, paths().encryptionKey, paths().authorization]) expect(existsSync(file)).toBe(false);
    expect(await device.status()).toMatchObject({ logged_in: false });
  });

  it("revokes an approval no device used yet when signing out", async () => {
    const server = fakeServer();
    const device = newDevice();
    await device.login({ serverUrl: SERVER, mode: "device" });
    // Approved and saved, but the registration never ran (e.g. the process stopped)
    await device.clock.sleep(5_000);
    server.state.status = "approved";
    const authorizer = (device as unknown as { authorizer: Authorizer }).authorizer;
    await authorizer.complete(Date.now() + 60_000);
    expect(loadAuthorization()).toMatchObject({ stage: "authorized" });

    await device.logout();
    expect(server.state.revokedTokens).toEqual(["refresh-1"]);
    expect(loadAuthorization()).toBeNull();
  });

  describe("scopes", () => {
    it("lets a send-only agent push and tells it how to get read access", async () => {
      const server = fakeServer({ scope: "clipboard:write" });
      const device = newDevice();
      await signIn(device);
      const payloads = captureWs(device);

      await expect(device.pushText("send only")).resolves.toMatchObject({ persisted: true });
      expect(payloads).toHaveLength(1);
      for (const read of [() => device.getClipboard(), () => device.getLatestClipboard(), () => device.searchClipboard("x")]) {
        const error = await read().catch((e: unknown) => e);
        expect(error).toBeInstanceOf(ScopeError);
        expect((error as Error).message).toMatch(/can only send.*re-authorize the agent with read access.*cpmesh_login/s);
      }
      await expect(device.deleteClipboardEntry(randomUUID())).rejects.toThrow(/clipboard:delete.*off by default/s);
      await expect(device.removeDevice(randomUUID())).rejects.toThrow(/devices:manage/);
      expect(server.requests.some((r) => r.path === "/api/clipboard" || r.method === "DELETE")).toBe(false);
    });

    it("maps the relay's refusals to the same messages", async () => {
      const server = fakeServer({ scope: READ_WRITE });
      const device = newDevice();
      await signIn(device);
      await device.ensureReady();
      // The session claims more than the server grants (e.g. reduced elsewhere)
      server.state.grants.get(loadSession()!.grant_id!)!.scope = "clipboard:write";
      await expect(device.getClipboard()).rejects.toThrow(/re-authorize the agent with read access/);

      vi.spyOn(device.ws, "pushClipboard").mockRejectedValue(new WsError("insufficient_scope: this agent may not push", "insufficient_scope"));
      const error = await device.pushText("hello").catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ScopeError);
      expect((error as Error).message).toMatch(/send access/);
    });

    it("allows deleting entries and removing devices only with those scopes", async () => {
      fakeServer({ scope: `${READ_WRITE} clipboard:delete devices:manage` });
      const device = newDevice();
      await signIn(device);
      await expect(device.deleteClipboardEntry(randomUUID())).resolves.toBeUndefined();
    });
  });

  it("publishes the local encryption key when the relay lists another one, then bootstraps a v3 mesh", async () => {
    const server = fakeServer();
    await signIn(newDevice());
    const stale = DeviceKeys.generate();
    server.state.publishedEncryptionKey = { encryption_key: toBase64(stale.encryption.publicKeyBytes()), encryption_key_sig: toBase64(stale.certifyEncryptionKey()) };

    const ready = await newDevice().ensureReady();

    const publish = server.requests.filter((r) => r.path === "/api/devices/me/encryption-key");
    expect(publish).toHaveLength(1);
    expect(server.state.publishedEncryptionKey.encryption_key).toBe(toBase64(ownKeys().encryption.publicKeyBytes()));
    expect(ready.keyring.currentVersion).toBe(1);
    const rotate = server.requests.find((r) => r.path === "/api/group-keys/rotate")!;
    const wraps = (rotate.body as { wrapped_keys: StoreGroupKeyEntry[] }).wrapped_keys;
    expect(wraps).toHaveLength(1);
    expect(fromBase64(wraps[0]!.encrypted_key)).toHaveLength(125);
    expect(loadMembership()).toMatchObject({ version: 1, pins: { [DEVICE_ID]: toBase64(ownKeys().identity.publicKeyBytes()) } });

    // A matching listing is left alone on the next process start.
    await newDevice().ensureReady();
    expect(server.requests.filter((r) => r.path === "/api/devices/me/encryption-key")).toHaveLength(1);
  });

  it("signs every pushed entry over its context and both ciphertexts", async () => {
    fakeServer();
    const device = newDevice();
    await signIn(device);
    const payloads = captureWs(device);
    const before = Date.now();

    const result = await device.pushText("hello mesh");

    expect(result).toMatchObject({ sent: true, persisted: true, key_version: 1, size: 10 });
    const payload = payloads[0]!;
    expect(payload.request_id).toBe(result.request_id);
    expect(payload.sent_at).toBeGreaterThanOrEqual(before);
    expect(payload.sent_at).toBeLessThanOrEqual(Date.now());
    const keys = ownKeys();
    const context = { keyVersion: 1, contentType: "text" as const, senderId: DEVICE_ID, requestId: payload.request_id!, sentAt: payload.sent_at! };
    const encryptedData = fromBase64(payload.encrypted_data), metadata = fromBase64(payload.metadata!);
    expect(verifyEntrySignature(keys.identity.publicKeyBytes(), context, encryptedData, metadata, fromBase64(payload.sender_signature!))).toBe(true);
    expect(verifyEntrySignature(keys.identity.publicKeyBytes(), { ...context, sentAt: context.sentAt + 1 }, encryptedData, metadata, fromBase64(payload.sender_signature!))).toBe(false);
    // Any member holding the group key opens it only in that exact context.
    const ring = Keyring.load(statePaths().keyring, keys.identity.privateKey);
    const opened = openEntry(ring, context, encryptedData, metadata);
    expect(new TextDecoder().decode(opened.data)).toBe("hello mesh");
    expect(JSON.parse(new TextDecoder().decode(opened.metadataJson))).toEqual({ mime_type: "text/plain", size: 10 });
    expect(() => openEntry(ring, { ...context, contentType: "image" }, encryptedData, metadata)).toThrow();
    expect(() => ring.decryptPayload(encryptedData, 1, clipboardDataAad({ ...context, senderId: randomUUID() }))).toThrow();
    // Retrying the same request reuses the exact signed payload.
    await device.pushText("hello mesh", result.request_id);
    expect(payloads).toHaveLength(1);
  });

  describe("receiving entries", () => {
    async function meshWithPeer() {
      const server = fakeServer();
      const device = newDevice();
      await signIn(device);
      await device.ensureReady();
      const peer = peerDevice("Laptop");
      const stranger = peerDevice("Stranger");
      server.state.peers = [peer.listing, stranger.listing];
      // The peer is a verified member sharing the mesh key (as after an authenticated transition).
      pinVerified(peer.id, peer.listing.public_key!);
      const ring = Keyring.load(statePaths().keyring, ownKeys().identity.privateKey);
      const seal = (text: string, requestId = randomUUID(), sentAt = Date.now(), from = peer) => {
        const sealed = sealEntry(ring, from.keys.identity, { contentType: "text", senderId: from.id, requestId, sentAt }, new TextEncoder().encode(text),
          new TextEncoder().encode(JSON.stringify({ mime_type: "text/plain", size: text.length })));
        return { sealed, entry: entryFrom(from, sealed, { requestId, sentAt }) };
      };
      return { server, device, peer, stranger, ring, seal };
    }

    it("decrypts signed entries from verified members and rejects every relabelled, re-attributed or spliced variant", async () => {
      const { server, device, peer, stranger, ring, seal } = await meshWithPeer();
      const good = seal("from the laptop");
      const other = seal("another entry");
      const resign = (entry: ClipboardEntry, patch: Partial<ClipboardEntry>): ClipboardEntry => {
        // A sender re-signing a wrong context still cannot open the AAD-bound ciphertexts.
        const tampered = { ...entry, ...patch };
        const context = { keyVersion: tampered.key_version, contentType: tampered.content_type, senderId: tampered.device_id, requestId: tampered.request_id!, sentAt: tampered.sent_at! };
        const transcript = clipboardSignatureTranscript(context, fromBase64(tampered.encrypted_data), fromBase64(tampered.metadata));
        return { ...tampered, sender_signature: toBase64(peer.keys.identity.signMessage(transcript)) };
      };
      server.state.entries = [
        good.entry,
        { ...good.entry, id: "relay-content-type", content_type: "image" },
        { ...good.entry, id: "relay-sent-at", sent_at: good.entry.sent_at! + 1 },
        { ...good.entry, id: "relay-request", request_id: other.entry.request_id },
        { ...good.entry, id: "relay-sender", device_id: DEVICE_ID, device_name: "MCP" },
        { ...good.entry, id: "relay-unknown-sender", device_id: stranger.id, device_name: "Stranger" },
        { ...good.entry, id: "relay-signature", sender_signature: other.entry.sender_signature },
        { ...good.entry, id: "relay-metadata", metadata: other.entry.metadata },
        resign(good.entry, { id: "aad-content-type", content_type: "image" }),
        resign(good.entry, { id: "aad-key-version", key_version: 2 }),
        resign(good.entry, { id: "aad-request", request_id: other.entry.request_id }),
        resign(good.entry, { id: "aad-sent-at", sent_at: good.entry.sent_at! + 1 }),
        resign(good.entry, { id: "aad-metadata-splice", metadata: other.entry.metadata }),
        { ...seal("stranger danger", randomUUID(), Date.now(), stranger).entry, id: "unverified-sender" },
      ];

      const { items } = await device.getClipboard();

      expect(items[0]).toMatchObject({ id: good.entry.id, text: "from the laptop", decrypted: true, authenticated: true, size: 15, mime_type: "text/plain", request_id: good.entry.request_id, sent_at: good.entry.sent_at });
      for (const item of items.slice(1)) {
        expect(item, item.id).toMatchObject({ decrypted: false, authenticated: false });
        expect(item.text, item.id).toBeUndefined();
        expect(item.error, item.id).toMatch(
          item.id.endsWith("unverified-sender") || item.id.endsWith("unknown-sender") ? /not a verified member/
            : item.id.startsWith("relay-") ? /signature is invalid/
            : item.id === "aad-key-version" ? /no group key for version 2|decryption failed/ : /decryption failed/,
        );
      }
    });

    it("reads legacy unsigned entries for history only, flagged unauthenticated, and refuses them live", async () => {
      const { server, device, peer, ring } = await meshWithPeer();
      const data = new TextEncoder().encode("copied before the upgrade");
      const legacy: ClipboardEntry = {
        id: "legacy", user_id: "u1", device_id: peer.id, device_name: "Laptop", content_type: "text",
        encrypted_data: toBase64(ring.encryptPayload(data, new Uint8Array(0)).data),
        metadata: toBase64(ring.encryptPayload(new TextEncoder().encode(JSON.stringify({ mime_type: "text/plain", size: 25 })), new Uint8Array(0)).data),
        created_at: "2025-01-01T00:00:00Z", key_version: 1,
      };
      server.state.entries = [legacy];

      const { items } = await device.getClipboard();
      expect(items[0]).toMatchObject({ id: "legacy", text: "copied before the upgrade", decrypted: true, authenticated: false, mime_type: "text/plain" });
      expect(items[0]).not.toHaveProperty("request_id");

      await expect(device.acceptLiveEntry(legacy)).rejects.toThrow("not signed");
      expect(device.recentLiveEntries()).toEqual([]);
    });

    it("accepts live entries once per strictly increasing sender clock, persisted across processes", async () => {
      const { device, seal } = await meshWithPeer();
      const first = seal("one", randomUUID(), 1_700_000_000_500);
      const item = await device.acceptLiveEntry(first.entry);
      expect(item).toMatchObject({ text: "one", authenticated: true });
      expect(device.recentLiveEntries().map((i) => i.id)).toEqual([first.entry.id]);

      await expect(device.acceptLiveEntry({ ...first.entry, id: randomUUID() })).rejects.toThrow("replay");
      const older = seal("older", randomUUID(), 1_700_000_000_499);
      await expect(device.acceptLiveEntry(older.entry)).rejects.toThrow("replay");
      const tampered = seal("two", randomUUID(), 1_700_000_000_501);
      await expect(device.acceptLiveEntry({ ...tampered.entry, sent_at: 1_700_000_000_502 })).rejects.toThrow("signature is invalid");
      const newer = seal("two", randomUUID(), 1_700_000_000_501);
      await expect(device.acceptLiveEntry(newer.entry)).resolves.toMatchObject({ text: "two" });

      // Another process with the same state directory remembers the sender clock.
      await expect(new CpmeshDevice().acceptLiveEntry(newer.entry)).rejects.toThrow("replay");
      expect(JSON.parse(readFileSync(statePaths().senderClocks, "utf8"))).toEqual({ [first.entry.device_id]: 1_700_000_000_501 });
      // History reads are not subject to the replay guard.
      expect(device.recentLiveEntries()).toHaveLength(2);
    });
  });

  describe("pairing as the pending device", () => {
    async function pendingLogin() {
      const server = fakeServer({ deviceStatus: "pending" });
      const device = newDevice();
      const res = await signIn(device);
      expect(res).toMatchObject({ logged_in: true, device_status: "pending" });
      expect(res.pairing_session_id).toBeUndefined();
      const approver = peerDevice("Desktop");
      const approverNonce = new Uint8Array(randomBytes(32));
      const sessionId = randomUUID();
      server.state.approval = {
        pairing_version: 3, status: "pending", session_id: sessionId, approver_device_id: approver.id,
        approver_public_key: approver.listing.public_key, approver_commit: toBase64(sasCommitment(approverNonce)),
      };
      return { server, device, approver, approverNonce, sessionId };
    }

    it("contributes its nonce only after the commitment, derives the SAS from the opened commitment, and pins on a matching code", async () => {
      const { server, device, approver, approverNonce, sessionId } = await pendingLogin();

      let status = await device.status();
      expect(status).toMatchObject({ device_status: "pending", pairing_session_id: sessionId, pairing_code: undefined });
      const posted = server.requests.filter((r) => r.path === "/api/device-approvals/me/nonce");
      expect(posted).toHaveLength(1);
      expect(posted[0]!.body).toMatchObject({ session_id: sessionId });
      expect(server.state.pendingNonce).toHaveLength(32);
      await expect(device.confirmPairing(sessionId, "1234 5678")).rejects.toThrow("Wait until both devices show the same 8-digit code");
      expect(loadMembership().pins[approver.id]).toBeUndefined();

      // Polling again does not draw another nonce; the approver reveals, and both sides agree on the code.
      await device.status();
      expect(server.requests.filter((r) => r.path === "/api/device-approvals/me/nonce")).toHaveLength(1);
      server.state.approval.approver_nonce = toBase64(approverNonce);
      status = await device.status();
      const own = ownKeys().identity.publicKeyBytes();
      const expectedSas = sasCode(approverNonce, server.state.pendingNonce!, approver.keys.identity.publicKeyBytes(), own);
      expect(status.pairing_code).toBe(expectedSas);
      expect(status.pairing_code).toMatch(/^[0-9]{4} [0-9]{4}$/);
      expect(status.pairing_full_code).toBe(pairingFingerprint(own, approver.keys.identity.publicKeyBytes()));
      expect(status.next_step).toContain(expectedSas);

      const wrong = expectedSas.startsWith("0000") ? "1111 1111" : "0000 0000";
      await expect(device.confirmPairing(sessionId, wrong)).rejects.toThrow("does not match");
      await expect(device.confirmPairing(randomUUID(), expectedSas)).rejects.toThrow("missing or has expired");
      expect(loadMembership().pins[approver.id]).toBeUndefined();
      await expect(device.confirmPairing(sessionId, expectedSas.replace(" ", ""))).resolves.toMatch(/verified locally/);
      expect(loadMembership().pins[approver.id]).toBe(approver.listing.public_key);
      // The full 64-character code is accepted as the stronger manual check.
      await expect(device.confirmPairing(sessionId, status.pairing_full_code!.toLowerCase())).resolves.toMatch(/verified locally/);

      // Approval: the approver's wraps (to our certified encryption key) import under the pinned identity.
      const registered = server.state.registration as Record<string, string>;
      const ownTarget: WrapTarget = { identity: { id: DEVICE_ID, public_key: registered.public_key! }, encryptionKey: fromBase64(registered.encryption_key!) };
      const groupKey = new Uint8Array(randomBytes(32));
      const wraps = signedWraps(approver.keys.identity, approver.id, 1, groupKey, [approver.target, ownTarget]);
      server.state.groupKeys.set(1, { wraps, from: { id: approver.id, key: approver.listing.public_key! } });
      server.state.peers = [approver.listing];
      server.state.status = "approved";
      const approved = await device.waitForApproval(5_000);
      expect(approved).toMatchObject({ approved: true, status: "approved" });
      expect(loadSession()?.device_status).toBe("approved");
      const ring = Keyring.load(statePaths().keyring, ownKeys().identity.privateKey);
      expect(ring.keyForVersion(1)).toEqual(groupKey);
      expect(loadMembership()).toMatchObject({ version: 1, pins: { [approver.id]: approver.listing.public_key, [DEVICE_ID]: registered.public_key } });
    });

    it("aborts when the commitment changes, does not open, the identity changes, or the pairing protocol is old", async () => {
      const { server, device, approver, approverNonce, sessionId } = await pendingLogin();
      await device.status();
      const original = { ...server.state.approval };

      server.state.approval.approver_commit = toBase64(sasCommitment(new Uint8Array(randomBytes(32))));
      await expect(device.status()).rejects.toThrow("Pairing commitment changed");
      server.state.approval = { ...original, approver_nonce: toBase64(new Uint8Array(randomBytes(32))) };
      await expect(device.status()).rejects.toThrow("does not match the revealed nonce");
      server.state.approval = { ...original, approver_public_key: peerDevice("Impostor").listing.public_key };
      await expect(device.status()).rejects.toThrow("Pairing identity changed");
      server.state.approval = { ...original, pairing_version: 2 };
      await expect(device.status()).rejects.toThrow("pairing protocol 3");
      // Nothing was pinned and the only nonce ever sent is the first one.
      expect(loadMembership().pins[approver.id]).toBeUndefined();
      expect(server.requests.filter((r) => r.path === "/api/device-approvals/me/nonce")).toHaveLength(1);

      // The honest state still completes once the real nonce arrives.
      server.state.approval = { ...original, approver_nonce: toBase64(approverNonce) };
      const status = await device.status();
      expect(status.pairing_code).toBe(sasCode(approverNonce, server.state.pendingNonce!, ownKeys().identity.publicKeyBytes(), approver.keys.identity.publicKeyBytes()));
      await expect(device.confirmPairing(sessionId, status.pairing_code as string)).resolves.toMatch(/verified locally/);
    });

    it("never pins when the relay claims approval without a pairing session", async () => {
      const server = fakeServer({ deviceStatus: "pending" });
      const device = newDevice();
      await signIn(device);
      server.state.status = "approved";
      server.state.approval = { status: "approved" };
      const result = await device.waitForApproval(5_000);
      expect(result).toMatchObject({ approved: false, status: "verification_required" });
      expect(loadMembership().pins).toEqual({});
    });
  });
});

function paths() {
  return statePaths();
}
