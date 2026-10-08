/**
 * Persistent local state for the MCP device.
 *
 * Everything lives under $CPMESH_HOME (default ~/.cpmesh/mcp):
 *   device.key      — ECDH P-256 device private key (PEM, 0600)
 *   keyring.enc     — encrypted group-key keyring (same format as desktop)
 *   session.json    — server URL, device identity, JWT tokens (0600)
 *   pinned_keys.json — TOFU pins of peer device public keys
 */

import { existsSync, readFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { writeSecretFile } from "./crypto.js";
import type { DeviceStatus } from "./protocol.js";

export interface Session {
  server_url: string;
  user_id: string;
  device_id: string;
  device_name: string;
  device_status: DeviceStatus;
  access_token: string;
  refresh_token: string;
  created_at: string;
}

export interface StatePaths {
  root: string;
  deviceKey: string;
  keyring: string;
  session: string;
  pinnedKeys: string;
}

export function statePaths(): StatePaths {
  const root =
    process.env.CPMESH_HOME ?? join(homedir(), ".cpmesh", "mcp");
  return {
    root,
    deviceKey: join(root, "device.key"),
    keyring: join(root, "keyring.enc"),
    session: join(root, "session.json"),
    pinnedKeys: join(root, "pinned_keys.json"),
  };
}

export function loadSession(): Session | null {
  const paths = statePaths();
  if (!existsSync(paths.session)) return null;
  try {
    return JSON.parse(readFileSync(paths.session, "utf8")) as Session;
  } catch {
    return null;
  }
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
  for (const file of [paths.session, paths.keyring, paths.deviceKey, paths.pinnedKeys]) {
    if (existsSync(file)) rmSync(file);
  }
}

// === TOFU key pins ===

export function loadPinnedKeys(): Record<string, string> {
  const paths = statePaths();
  if (!existsSync(paths.pinnedKeys)) return {};
  try {
    return JSON.parse(readFileSync(paths.pinnedKeys, "utf8")) as Record<string, string>;
  } catch {
    return {};
  }
}

export function savePinnedKeys(keys: Record<string, string>): void {
  writeSecretFile(
    statePaths().pinnedKeys,
    Buffer.from(JSON.stringify(keys, null, 2), "utf8"),
  );
}
