/**
 * CpmeshDevice session flows against an in-memory fake of the cpmesh REST API
 * (protocol 3): registration with a certified encryption key, committed-SAS
 * pairing, signed pushes, and authenticated reads with a replay guard.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CpmeshDevice } from "../src/device.js";
import { loadMembership, loadSession, statePaths } from "../src/state.js";
import {
  DeviceKeys, ENCRYPTION_PEM_TAG, KeyPair, Keyring, clipboardDataAad, clipboardSignatureTranscript, fromBase64,
  pairingFingerprint, sasCode, sasCommitment, signedWraps, toBase64, verifyEncryptionKey, type WrapTarget,
} from "../src/crypto.js";
import { openEntry, sealEntry, verifyEntrySignature } from "../src/entry.js";
import { pinVerified } from "../src/membership.js";
import type { ApprovalStatusResponse, ClipboardEntry, ClipboardPushPayload, DeviceInfo, StoreGroupKeyEntry } from "../src/protocol.js";

interface FakeRequest {
  path: string;
  method: string;
  auth?: string;
  body?: Record<string, unknown>;
}

const DEVICE_ID = "00000000-0000-4000-8000-00000000000d";

/**
 * Minimal relay: login and refresh issue user-level tokens, device
 * registration issues device-bound ones, refresh tokens are single-use.
 * `state` is mutable so a test can drive approval sessions, device listings,
 * stored group keys and clipboard history between calls.
 */
function fakeServer({ mfa = false, deviceStatus = "approved" as "approved" | "pending" } = {}) {
  const valid = new Set<string>();
  const requests: FakeRequest[] = [];
  let refreshToken = "refresh-1";
  let issued = 0;
  let bound = 0;
  const state = {
    status: deviceStatus,
    registration: undefined as Record<string, unknown> | undefined,
    publishedEncryptionKey: undefined as { encryption_key: string; encryption_key_sig: string } | undefined,
    approval: { status: deviceStatus } as ApprovalStatusResponse,
    pendingNonce: undefined as Uint8Array | undefined,
    /** Devices listed by /api/devices/keys in addition to this one. */
    peers: [] as DeviceInfo[],
    groupKeys: new Map<number, { wraps: StoreGroupKeyEntry[]; from: { id: string; key: string } }>(),
    entries: [] as ClipboardEntry[],
  };
  const ownListing = (): DeviceInfo => ({
    id: DEVICE_ID, name: "MCP", online: true, status: state.status,
    public_key: state.registration?.public_key as string | undefined,
    encryption_key: state.publishedEncryptionKey?.encryption_key,
    encryption_key_sig: state.publishedEncryptionKey?.encryption_key_sig,
  });

  globalThis.fetch = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const req: FakeRequest = {
      path: url.pathname,
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

    if (req.path === "/api/devices/challenge") return reply(200, { challenge: `challenge-${bound}` });
    if (req.path === "/api/devices" && req.method === "POST") {
      const deviceToken = `device-token-${++bound}`;
      valid.add(deviceToken);
      state.registration = req.body;
      const { encryption_key, encryption_key_sig } = req.body as Record<string, string | undefined>;
      if (encryption_key && encryption_key_sig) state.publishedEncryptionKey = { encryption_key, encryption_key_sig };
      return reply(201, { device: { id: DEVICE_ID, status: state.status, is_reregistration: false }, access_token: deviceToken, refresh_token: refreshToken });
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
    if (req.path === "/api/me") return reply(200, { id: "u1", username: "alice" });
    if (req.path === "/api/devices") return reply(200, [ownListing(), ...state.peers]);
    if (req.path === "/api/clipboard" && req.method === "GET") return reply(200, { entries: state.entries, has_more: false });
    return reply(404, { error: `unexpected ${req.method} ${req.path}` });
  }) as typeof fetch;

  return { requests, valid, state };
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
    id, user_id: "u1", device_id: sender.id, device_name: sender.listing.name, content_type: "text",
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
});

afterEach(() => {
  vi.restoreAllMocks();
  globalThis.fetch = realFetch;
  delete process.env.CPMESH_HOME;
  rmSync(home, { recursive: true, force: true });
});

describe("CpmeshDevice", () => {
  it("login registers the device with the login token, a certified encryption key, and stores the device-bound session", async () => {
    const server = fakeServer();

    const res = await new CpmeshDevice().login("https://srv", "alice", "pw");

    expect(res.status).toBe("approved");
    const register = server.requests.find((r) => r.path === "/api/devices" && r.method === "POST");
    expect(register?.auth).toBe("Bearer login-token");
    const session = loadSession();
    expect(session).toMatchObject({ device_id: DEVICE_ID, refresh_token: "refresh-1" });
    expect(session?.access_token).toMatch(/^device-token-/);
    expect(session?.fingerprint).toBe(register?.body?.fingerprint);
    // Two distinct key files; the encryption key is certified by the identity key.
    const keys = ownKeys();
    const body = register!.body as Record<string, string>;
    expect(fromBase64(body.public_key!)).toEqual(keys.identity.publicKeyBytes());
    expect(fromBase64(body.encryption_key!)).toEqual(keys.encryption.publicKeyBytes());
    expect(body.encryption_key).not.toBe(body.public_key);
    expect(verifyEncryptionKey(fromBase64(body.public_key!), fromBase64(body.encryption_key!), fromBase64(body.encryption_key_sig!)))
      .toEqual(keys.encryption.publicKeyBytes());
    expect(readFileSync(statePaths().encryptionKey, "utf8")).toContain(`-----BEGIN ${ENCRYPTION_PEM_TAG}-----`);
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
    expect(loadSession()).toMatchObject({ user_id: "u1", device_id: DEVICE_ID, refresh_token: "refresh-1" });
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

    await expect(new CpmeshDevice().listDevices()).resolves.toHaveLength(1);

    const refreshes = server.requests.filter((r) => r.path === "/api/auth/refresh");
    expect(refreshes.map((r) => r.body?.refresh_token)).toEqual(["refresh-1"]);
    const rebind = server.requests.filter((r) => r.path === "/api/devices" && r.method === "POST").at(-1);
    expect(rebind?.auth).toBe("Bearer unbound-1");
    expect(rebind?.body?.fingerprint).toBe(before.fingerprint);
    expect(rebind?.body?.encryption_key).toBe(toBase64(ownKeys().encryption.publicKeyBytes()));
    const after = loadSession()!;
    expect(after.refresh_token).toBe("refresh-2");
    expect(after.access_token).toMatch(/^device-token-/);
    expect(after.access_token).not.toBe(before.access_token);
  });

  it("publishes the local encryption key when the relay lists another one, then bootstraps a v3 mesh", async () => {
    const server = fakeServer();
    const device = new CpmeshDevice();
    await device.login("https://srv", "alice", "pw");
    const stale = DeviceKeys.generate();
    server.state.publishedEncryptionKey = { encryption_key: toBase64(stale.encryption.publicKeyBytes()), encryption_key_sig: toBase64(stale.certifyEncryptionKey()) };

    const ready = await device.ensureReady();

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
    await new CpmeshDevice().ensureReady();
    expect(server.requests.filter((r) => r.path === "/api/devices/me/encryption-key")).toHaveLength(1);
  });

  it("signs every pushed entry over its context and both ciphertexts", async () => {
    fakeServer();
    const device = new CpmeshDevice();
    await device.login("https://srv", "alice", "pw");
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
      const device = new CpmeshDevice();
      await device.login("https://srv", "alice", "pw");
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
      const device = new CpmeshDevice();
      const res = await device.login("https://srv", "alice", "pw");
      expect(res.status).toBe("pending");
      expect(res.pairing).toBeUndefined();
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
      const device = new CpmeshDevice();
      await device.login("https://srv", "alice", "pw");
      server.state.status = "approved";
      server.state.approval = { status: "approved" };
      const result = await device.waitForApproval(5_000);
      expect(result).toMatchObject({ approved: false, status: "verification_required" });
      expect(loadMembership().pins).toEqual({});
    });
  });
});
