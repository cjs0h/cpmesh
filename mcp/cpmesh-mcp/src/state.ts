/**
 * Persistent local state for the MCP device.
 *
 * Everything lives under $CPMESH_HOME (default ~/.cpmesh/mcp):
 *   device.key      — P-256 identity private key (PEM, 0600); signs only
 *   encryption.key  — P-256 static encryption private key (PEM, 0600); ECDH only
 *   keyring.enc     — encrypted group-key keyring (same format as desktop)
 *   session.json    — server URL, device identity, OAuth grant and tokens (0600)
 *   authorization.json — a sign-in in progress: the pending device authorization,
 *                     or tokens not yet bound to this device (0600)
 *   verified_keys.json — independently authenticated, versioned device membership
 *   sender_clocks.json — replay guard: newest accepted `sent_at` per sender device
 */

import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { writeSecretFile } from "./crypto.js";
import type { DeviceStatus } from "./protocol.js";
import { clipboardReceiptSchema } from "./protocol.js";
import { z } from "zod";
import lockfile from "proper-lockfile";

/** Serialize profile mutations across MCP processes, not just calls in one IDE.
 * The heartbeat keeps long HTTP operations from being mistaken for a dead owner. */
export async function withStateLock<T>(operation: () => Promise<T> | T): Promise<T> {
  const root = statePaths().root;
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const release = await lockfile.lock(root, {
    lockfilePath: join(root, ".state.lock"), realpath: false,
    stale: 60_000, update: 10_000,
    retries: { retries: 120, factor: 1, minTimeout: 250, maxTimeout: 250 },
  });
  try { return await operation(); } finally { await release(); }
}

export interface Session {
  server_url: string;
  user_id: string;
  device_id: string;
  device_name: string;
  device_status: DeviceStatus;
  /** Device fingerprint registered at sign-in; reused when the device registers again. */
  fingerprint?: string;
  /** Empty once the server refused to refresh the session (see `signed_out`). */
  access_token: string;
  refresh_token: string;
  created_at: string;
  /** The OAuth grant behind the tokens. Profiles of cpmesh-mcp 0.2 have none and count as signed out. */
  grant_id?: string;
  client_id?: string;
  /** What the user allowed this agent to do (space-separated scopes). */
  scope?: string;
  /** Why the session ended; the device keys and pairing are kept for signing in again. */
  signed_out?: string;
}

/** A session this version can use: signed in with OAuth and not signed out since. */
export function isSignedIn(session: Session | null): session is Session & { grant_id: string } {
  return session !== null && !!session.grant_id && !!session.refresh_token;
}

export interface StatePaths {
  root: string;
  deviceKey: string;
  encryptionKey: string;
  keyring: string;
  session: string;
  authorization: string;
  pinnedKeys: string;
  requests: string;
  senderClocks: string;
}

export function statePaths(): StatePaths {
  const root =
    process.env.CPMESH_HOME ?? join(homedir(), ".cpmesh", "mcp");
  return {
    root,
    deviceKey: join(root, "device.key"),
    encryptionKey: join(root, "encryption.key"),
    keyring: join(root, "keyring.enc"),
    session: join(root, "session.json"),
    authorization: join(root, "authorization.json"),
    pinnedKeys: join(root, "verified_keys.json"),
    requests: join(root, "clipboard_requests.json"),
    senderClocks: join(root, "sender_clocks.json"),
  };
}

export function loadSession(): Session | null {
  const paths = statePaths();
  if (!existsSync(paths.session)) return null;
  return z.object({
    server_url: z.string().url(), user_id: z.string(), device_id: z.string(),
    device_name: z.string(), device_status: z.enum(["pending", "approved", "rejected", "revoked"]),
    fingerprint: z.string().optional(), access_token: z.string(), refresh_token: z.string(), created_at: z.string(),
    grant_id: z.string().optional(), client_id: z.string().optional(), scope: z.string().optional(),
    signed_out: z.string().optional(),
  }).parse(JSON.parse(readFileSync(paths.session, "utf8")));
}

export function saveSession(session: Session): void {
  writeSecretFile(
    statePaths().session,
    Buffer.from(JSON.stringify(session, null, 2), "utf8"),
  );
}

export function updateSession(patch: Partial<Session>): Session | null {
  const current = loadSession();
  if (!current) return null;
  const next = { ...current, ...patch };
  saveSession(next);
  return next;
}

/** Wipes all local secrets (logout). */
export function clearAllState(): void {
  const paths = statePaths();
  for (const file of [
    paths.session, paths.authorization, paths.keyring, paths.deviceKey, paths.encryptionKey, paths.pinnedKeys,
    paths.requests, paths.senderClocks,
  ]) {
    if (existsSync(file)) rmSync(file);
  }
}

/** Forgets what belongs to a device registration that no longer exists (its unsent signed pushes). */
export function clearDeviceState(): void {
  const { requests } = statePaths();
  if (existsSync(requests)) rmSync(requests);
}

// === A sign-in in progress ===

const pendingAuthorizationSchema = z.object({
  stage: z.literal("pending"),
  server_url: z.string(),
  token_endpoint: z.string(),
  device_code: z.string().min(1),
  user_code: z.string(),
  verification_uri: z.string(),
  verification_uri_complete: z.string().optional(),
  /** Unix milliseconds. */
  expires_at: z.number(),
  /** Seconds to wait after each poll; grows with `slow_down`. */
  interval: z.number().int().positive(),
  /** Unix milliseconds; shared by every process polling this device code. */
  next_poll_at: z.number(),
  created_at: z.string(),
});
const authorizedSchema = z.object({
  stage: z.literal("authorized"),
  server_url: z.string(),
  access_token: z.string(),
  refresh_token: z.string().min(1),
  scope: z.string().optional(),
  user_id: z.string(),
  grant_id: z.string(),
  created_at: z.string(),
});
const authorizationSchema = z.discriminatedUnion("stage", [pendingAuthorizationSchema, authorizedSchema]);

/** A device authorization waiting for the user's approval (RFC 8628). */
export type PendingDeviceAuthorization = z.infer<typeof pendingAuthorizationSchema>;
/** Tokens of an approved sign-in that the device has not registered with yet. */
export type AuthorizedTokens = z.infer<typeof authorizedSchema>;
export type StoredAuthorization = PendingDeviceAuthorization | AuthorizedTokens;

export function loadAuthorization(): StoredAuthorization | null {
  const path = statePaths().authorization;
  if (!existsSync(path)) return null;
  try {
    return authorizationSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  } catch {
    console.error("[cpmesh-mcp] Ignoring an unreadable sign-in in progress (authorization.json)");
    return null;
  }
}

export function saveAuthorization(authorization: StoredAuthorization): void {
  writeSecretFile(statePaths().authorization, Buffer.from(JSON.stringify(authorization, null, 2), "utf8"));
}

export function clearAuthorization(): void {
  const { authorization } = statePaths();
  if (existsSync(authorization)) rmSync(authorization);
}

// The legacy TOFU file is never implicitly promoted to authenticated membership.

export function loadMembership(): {
  version: number; pins: Record<string, string>; revoked: Record<string, number>; rotation_required: boolean;
} {
  const path = statePaths().pinnedKeys;
  if (!existsSync(path)) return { version: 0, pins: {}, revoked: {}, rotation_required: false };
  return z.object({
    version: z.number().int().nonnegative(), pins: z.record(z.string()),
    revoked: z.record(z.number().int().positive()).default({}), rotation_required: z.boolean().default(false),
  })
    .parse(JSON.parse(readFileSync(path, "utf8")));
}

export function loadPinnedKeys(): Record<string, string> {
  const trust = loadMembership();
  return Object.fromEntries(Object.entries(trust.pins).filter(([id]) => trust.revoked[id] === undefined));
}

export function savePinnedKeys(keys: Record<string, string>): void {
  saveMembership(loadMembership().version, keys);
}

export function saveMembership(
  version: number, pins: Record<string, string>,
  revoked = loadMembership().revoked, rotationRequired = loadMembership().rotation_required,
): void {
  writeSecretFile(
    statePaths().pinnedKeys,
    Buffer.from(JSON.stringify({ version, pins, revoked, rotation_required: rotationRequired }), "utf8"),
  );
}

const savedPushSchema = z.object({
  hash: z.string().regex(/^[0-9a-f]{64}$/),
  payload: z.object({
    request_id: z.string().uuid().optional(), content_type: z.enum(["text", "image", "file"]),
    encrypted_data: z.string().max(2 * 1024 * 1024), metadata: z.string().max(16384).optional(),
    key_version: z.number().int().positive(),
    sent_at: z.number().int().positive().optional(), sender_signature: z.string().max(256).optional(),
  }),
  receipt: clipboardReceiptSchema.optional(),
});
export type SavedPush = z.infer<typeof savedPushSchema>;

export function loadPushes(deviceId: string): Map<string, SavedPush> {
  const path = statePaths().requests;
  if (!existsSync(path)) return new Map();
  if (statSync(path).size > 64 * 1024 * 1024) throw new Error("Clipboard request cache exceeds its limit");
  const cache = z.object({
    device_id: z.literal(deviceId), requests: z.array(z.tuple([z.string().uuid(), savedPushSchema])).max(32),
  }).parse(JSON.parse(readFileSync(path, "utf8")));
  for (const [id, request] of cache.requests) {
    if (request.payload.request_id !== id || (request.receipt && request.receipt.request_id !== id)) {
      throw new Error("Clipboard request cache has conflicting IDs");
    }
  }
  return new Map(cache.requests);
}

export function savePushes(deviceId: string, requests: Map<string, SavedPush>): void {
  writeSecretFile(statePaths().requests, Buffer.from(JSON.stringify({
    device_id: deviceId, requests: [...requests],
  })));
}

export class ReplayError extends Error {}

/**
 * Per-sender high-water mark of `sent_at`, so a relay cannot re-deliver an old
 * entry as new (mirrors the desktop ReplayGuard). Live entries must arrive with
 * strictly increasing sender clocks; history catch-up does not use this guard.
 */
export class ReplayGuard {
  private readonly lastSentAt: Record<string, number>;

  constructor(private readonly path: string = statePaths().senderClocks) {
    this.lastSentAt = existsSync(path)
      ? z.record(z.number().int().positive()).parse(JSON.parse(readFileSync(path, "utf8")))
      : {};
  }

  /** Accepts `sentAt` only if it is newer than everything seen from `deviceId`, then persists it. */
  accept(deviceId: string, sentAt: number): void {
    const last = this.lastSentAt[deviceId];
    if (!Number.isSafeInteger(sentAt) || sentAt <= 0 || (last !== undefined && sentAt <= last)) {
      throw new ReplayError("clipboard entry is a replay or arrived out of order");
    }
    this.lastSentAt[deviceId] = sentAt;
    writeSecretFile(this.path, Buffer.from(JSON.stringify(this.lastSentAt), "utf8"));
  }
}
