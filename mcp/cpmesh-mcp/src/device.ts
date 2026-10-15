/**
 * High-level orchestrator: makes this MCP server behave as a first-class
 * cpmesh device — keypair, registration, approval pairing, group-key sync,
 * and clipboard read/write over the E2E-encrypted channel.
 *
 * Mirrors the flows in desktop-tauri/src-tauri/src/commands.rs
 * (setup_and_login / setup_group_key / connect / sync_history).
 */

import { createHash } from "node:crypto";
import { hostname } from "node:os";
import {
  ApiError,
  CpmeshApi,
  SESSION_EXPIRED_MESSAGE,
  SessionExpiredError,
} from "./api.js";
import {
  KeyPair,
  Keyring,
  deriveApprovalCode,
  shortFingerprint,
} from "./crypto.js";
import {
  loadPinnedKeys,
  loadSession,
  savePinnedKeys,
  saveSession,
  statePaths,
  updateSession,
  clearAllState,
  type Session,
} from "./state.js";
import type {
  ApprovalStatusResponse,
  ClipboardEntry,
  ClipboardPushPayload,
  DeviceInfo,
  PlainEntry,
  RegisterDeviceRequest,
} from "./protocol.js";
import { SignInFlow, type Account } from "./signin.js";
import { WsClient, WsError } from "./ws.js";

const FINGERPRINT_SALT = "cpnet-device-fp-v1";

export class DeviceNotReadyError extends Error {
  constructor(
    message: string,
    readonly nextStep: string,
  ) {
    super(message);
  }
}

export class SecurityError extends Error {}

export interface ReadyState {
  session: Session;
  api: CpmeshApi;
  keypair: KeyPair;
  keyring: Keyring;
  fingerprint: string;
}

/** Decrypted entry view returned to MCP tools. */
export interface ClipboardItem {
  id: string;
  created_at: string;
  device_id: string;
  device_name: string;
  content_type: string;
  key_version: number;
  text?: string;
  size: number;
  mime_type?: string;
  filename?: string;
  decrypted: boolean;
}

export class CpmeshDevice {
  readonly ws = new WsClient();
  private cached: ReadyState | null = null;
  /** Keeps a sign-in that waits for its two-factor code (in memory only). */
  private readonly signIns = new SignInFlow();

  deviceName(): string {
    return `MCP Agent - ${hostname()}`;
  }

  /**
   * Stable device fingerprint. The desktop hashes a hardware ID; the MCP
   * server hashes the hostname, which is stable across reinstalls of the
   * package on the same machine.
   */
  private fingerprintFor(userId: string): string {
    const input = `${hostname()}:${userId}:${FINGERPRINT_SALT}`;
    return createHash("sha256").update(input, "utf8").digest("hex");
  }

  /** The fingerprint registered at login (sessions without one predate storing it). */
  private fingerprintOf(session: Session): string {
    return session.fingerprint ?? this.fingerprintFor(session.user_id);
  }

  private registrationFor(
    keypair: KeyPair,
    name: string,
    fingerprint: string,
  ): RegisterDeviceRequest {
    return {
      name,
      public_key: Buffer.from(keypair.publicKeyBytes()).toString("base64"),
      public_key_sig: Buffer.from(keypair.signPublicKey()).toString("base64"),
      fingerprint,
    };
  }

  // === Onboarding ===

  /** The account whose sign-in waits for a two-factor code (see {@link SignInFlow.waiting}). */
  waitingSignIn(serverUrl?: string, username?: string): Account | null {
    return this.signIns.waiting(serverUrl, username);
  }

  /**
   * Signs in and registers this device. With two-factor authentication the first
   * call (password, no code) resolves `mfa_required`; a later call with the code
   * finishes the sign-in, with or without the password.
   */
  async login(
    serverUrl: string,
    username: string,
    password?: string,
    mfaCode?: string,
  ): Promise<{
    status: string;
    approval_code?: string;
    methods?: string[];
    message: string;
  }> {
    if (!/^https?:\/\//i.test(serverUrl)) {
      throw new Error("Server URL must start with https:// or http://");
    }

    const deviceName = this.deviceName();
    const api = new CpmeshApi(serverUrl);
    const signedIn = await this.signIns.signIn(api, {
      serverUrl,
      username,
      password,
      code: mfaCode,
      deviceName,
    });
    if (signedIn.status === "mfa_required") {
      return { status: "mfa_required", methods: signedIn.methods, message: signedIn.message };
    }
    const { auth } = signedIn;
    api.setTokens(auth.access_token, auth.refresh_token);
    // Tokens from the second-factor step come without the user ID
    const userId = auth.user_id ?? (await api.getMe()).id;
    const fingerprint = this.fingerprintFor(userId);
    const recoveryNote =
      signedIn.recoveryCodesRemaining === undefined
        ? ""
        : `Signed in with a recovery code (${signedIn.recoveryCodesRemaining} left). `;

    const paths = statePaths();
    const keypair = KeyPair.loadOrGenerate(paths.deviceKey);

    const reg = await api.registerDevice(
      this.registrationFor(keypair, deviceName, fingerprint),
    );

    const deviceId = reg.device.id;
    const deviceStatus = reg.device.status;
    const keyring = new Keyring();

    if (deviceStatus === "approved") {
      // First device in the account is auto-approved; set up its group key.
      await this.setupGroupKey(api, keyring, keypair, deviceId);
    }

    const session: Session = {
      server_url: serverUrl,
      user_id: userId,
      device_id: deviceId,
      device_name: deviceName,
      device_status: deviceStatus,
      fingerprint,
      access_token: api.access ?? "",
      refresh_token: api.refresh ?? auth.refresh_token,
      created_at: new Date().toISOString(),
    };
    saveSession(session);
    this.cached = null;

    if (deviceStatus === "approved") {
      return {
        status: "approved",
        message: `${recoveryNote}Logged in and approved. Device "${deviceName}" is ready to sync.`,
      };
    }

    // Pending: derive the pairing code if an approver session is already live.
    const status = await api.getMyApprovalStatus();
    const code = this.derivePairingCode(keypair, status);
    return {
      status: "pending",
      approval_code: code,
      message:
        `${recoveryNote}Logged in. Device "${deviceName}" is PENDING approval. ` +
        (code
          ? `Pairing code: ${code}. Ask the user to confirm this code on one of their approved cpmesh devices, then call cpmesh_wait_for_approval.`
          : `Ask the user to start the approval for this device from an approved cpmesh device, then call cpmesh_wait_for_approval.`),
    };
  }

  private derivePairingCode(
    keypair: KeyPair,
    status: ApprovalStatusResponse,
  ): string | undefined {
    if (status.session_id && status.approver_public_key) {
      try {
        const approverPub = new Uint8Array(
          Buffer.from(status.approver_public_key, "base64"),
        );
        return deriveApprovalCode(
          keypair.privateKey,
          approverPub,
          keypair.publicKey,
        );
      } catch {
        return undefined;
      }
    }
    return undefined;
  }

  /**
   * Polls until this device is approved (or rejected/revoked), then syncs the
   * group key. Returns the final state.
   */
  async waitForApproval(
    timeoutMs = 180_000,
    onProgress?: (info: { status: string; code?: string }) => void,
  ): Promise<{ approved: boolean; status: string; approval_code?: string; message: string }> {
    const { api, keypair, session } = await this.requireSession();

    const deadline = Date.now() + timeoutMs;
    let lastCode: string | undefined;

    while (Date.now() < deadline) {
      const status = await api.getMyApprovalStatus();

      if (status.status === "approved") {
        const keyring = new Keyring();
        await this.setupGroupKey(api, keyring, keypair, session.device_id);
        updateSession({ device_status: "approved" });
        this.cached = null;
        return {
          approved: true,
          status: "approved",
          message: "Device approved and group key synced — cpmesh is ready.",
        };
      }

      if (status.status === "rejected" || status.status === "revoked") {
        return {
          approved: false,
          status: status.status,
          message: `Device was ${status.status}. Ask the user to re-approve this device or log in again with cpmesh_login.`,
        };
      }

      const code = this.derivePairingCode(keypair, status);
      if (code) lastCode = code;
      onProgress?.({ status: status.status, code });
      await sleep(2500);
    }

    return {
      approved: false,
      status: "pending",
      approval_code: lastCode,
      message:
        "Still pending approval. Ask the user to confirm the pairing code on an approved device, then call cpmesh_wait_for_approval again.",
    };
  }

  // === Readiness ===

  private twoFactorNextStep(): string | null {
    const waiting = this.signIns.waiting();
    return waiting
      ? `The sign-in as "${waiting.username}" is waiting for its two-factor code: ask the user for the current ` +
          "6-digit code from their authenticator app (or a recovery code) and call cpmesh_login with it."
      : null;
  }

  private async requireSession(): Promise<{
    api: CpmeshApi;
    keypair: KeyPair;
    session: Session;
  }> {
    const session = loadSession();
    if (!session) {
      throw new DeviceNotReadyError(
        "cpmesh is not logged in",
        this.twoFactorNextStep() ??
          "Call cpmesh_login with the user's server URL and credentials (or set CPMESH_SERVER_URL / CPMESH_USERNAME / CPMESH_PASSWORD).",
      );
    }
    const keypair = KeyPair.loadOrGenerate(statePaths().deviceKey);
    const api = this.buildApi(session, keypair);
    return { api, keypair, session };
  }

  /**
   * API client for a stored session. Refreshed tokens are persisted to the
   * session file (shared with other MCP processes using the same state
   * directory) and re-bound to this device: the server issues refreshed access
   * tokens without a device, and re-registering with the same key and
   * fingerprint is a plain reconnect that returns a device-bound token.
   */
  private buildApi(session: Session, keypair: KeyPair): CpmeshApi {
    const api = new CpmeshApi(session.server_url);
    api.setTokens(session.access_token, session.refresh_token);
    const sameDevice = (s: Session | null): s is Session =>
      s?.device_id === session.device_id;
    api.tokenStore = {
      load: () => {
        const s = loadSession();
        return sameDevice(s) ? { access: s.access_token, refresh: s.refresh_token } : null;
      },
      save: (access, refresh) => {
        const s = loadSession();
        if (sameDevice(s)) saveSession({ ...s, access_token: access, refresh_token: refresh });
      },
    };
    api.rebind = async (a) => {
      const reg = await a.registerDevice(
        this.registrationFor(keypair, session.device_name, this.fingerprintOf(session)),
        { retryOnExpiry: false },
      );
      if (reg.device.id !== session.device_id) {
        throw new Error("the server registered a different device while re-binding the session");
      }
    };
    return api;
  }

  async ensureReady(): Promise<ReadyState> {
    if (this.cached) return this.cached;
    const { api, keypair, session } = await this.requireSession();

    let deviceStatus = session.device_status;
    if (deviceStatus !== "approved") {
      // The device may have been approved since we last checked.
      const status = await api.getMyApprovalStatus();
      deviceStatus = status.status;
      if (deviceStatus !== session.device_status) {
        updateSession({ device_status: deviceStatus });
        session.device_status = deviceStatus;
      }
    }

    if (deviceStatus !== "approved") {
      const code = this.derivePairingCode(keypair, await api.getMyApprovalStatus());
      throw new DeviceNotReadyError(
        `device "${session.device_name}" is ${deviceStatus}`,
        code
          ? `Ask the user to confirm pairing code ${code} on an approved device, then call cpmesh_wait_for_approval.`
          : "Ask the user to approve this device from an approved cpmesh device, then call cpmesh_wait_for_approval.",
      );
    }

    // Load (or bootstrap) the group-key keyring.
    let keyring: Keyring;
    try {
      keyring = Keyring.load(statePaths().keyring, keypair.privateKey);
    } catch {
      keyring = new Keyring();
    }
    if (!keyring.hasGroupKey()) {
      await this.setupGroupKey(api, keyring, keypair, session.device_id);
    }

    const fingerprint = this.fingerprintOf(session);
    this.cached = { session, api, keypair, keyring, fingerprint };
    return this.cached;
  }

  // === Group key management ===

  /**
   * Establishes the group key: unwrap the existing one from another device,
   * or (first device in the account) create v1 and distribute wrapped copies.
   */
  private async setupGroupKey(
    api: CpmeshApi,
    keyring: Keyring,
    keypair: KeyPair,
    deviceId: string,
  ): Promise<void> {
    const gk = await api.getGroupKey();

    if (gk) {
      const peerPub = new Uint8Array(Buffer.from(gk.from_public_key, "base64"));

      if (gk.from_public_key_sig) {
        const sig = new Uint8Array(Buffer.from(gk.from_public_key_sig, "base64"));
        if (!KeyPair.verifyPublicKeySignature(peerPub, sig)) {
          throw new SecurityError(
            `SECURITY: sender device ${gk.from_device_id} key signature invalid (possible MITM). Aborting group key import.`,
          );
        }
      }

      this.verifyAndPin(gk.from_device_id, peerPub);

      keyring.decryptFromDevice(
        new Uint8Array(Buffer.from(gk.encrypted_key, "base64")),
        keypair.privateKey,
        peerPub,
        gk.version,
      );
    } else {
      // First device — generate group key v1 and wrap it for every other
      // approved device (there are none on a fresh account, but handle it).
      keyring.initGroupKey();
      const keysResp = await api.getDeviceKeys();
      const entries = [];
      for (const dev of keysResp.devices) {
        if (dev.id === deviceId || dev.status !== "approved" || !dev.public_key) {
          continue;
        }
        const peerPub = new Uint8Array(Buffer.from(dev.public_key, "base64"));
        if (dev.public_key_sig) {
          const sig = new Uint8Array(Buffer.from(dev.public_key_sig, "base64"));
          if (!KeyPair.verifyPublicKeySignature(peerPub, sig)) {
            continue; // skip devices with invalid key signatures
          }
        }
        this.verifyAndPin(dev.id, peerPub);
        entries.push({
          device_id: dev.id,
          encrypted_key: Buffer.from(
            keyring.encryptForDevice(keypair.privateKey, peerPub),
          ).toString("base64"),
        });
      }
      // Always store, so version 1 is recorded server-side.
      await api.storeGroupKeys(entries);
    }

    keyring.save(statePaths().keyring, keypair.privateKey);
  }

  /** TOFU: verify a peer's pinned key, pin it if new, fail loudly on change. */
  private verifyAndPin(deviceId: string, publicKey: Uint8Array): void {
    const pins = loadPinnedKeys();
    const b64 = Buffer.from(publicKey).toString("base64");
    const pinned = pins[deviceId];
    if (pinned && pinned !== b64) {
      throw new SecurityError(
        `SECURITY: device ${deviceId} public key has CHANGED (was ${shortFingerprint(
          new Uint8Array(Buffer.from(pinned, "base64")),
        )}, now ${shortFingerprint(publicKey)}). This could indicate a ` +
          `man-in-the-middle attack. If the device was legitimately re-created, ` +
          `delete pinned_keys.json in the cpmesh MCP state directory and retry.`,
      );
    }
    if (!pinned) {
      pins[deviceId] = b64;
      savePinnedKeys(pins);
    }
  }

  /** Re-fetches and unwraps group keys (handles rotation by other devices). */
  async refreshGroupKeys(): Promise<number> {
    const { api, keypair, keyring } = await this.ensureReady();
    const resp = await api.getCurrentGroupKeys();
    for (const entry of resp.keys) {
      const peerPub = new Uint8Array(Buffer.from(entry.from_public_key, "base64"));
      if (entry.from_public_key_sig) {
        const sig = new Uint8Array(Buffer.from(entry.from_public_key_sig, "base64"));
        if (!KeyPair.verifyPublicKeySignature(peerPub, sig)) {
          continue;
        }
      }
      this.verifyAndPin(entry.from_device_id, peerPub);
      keyring.decryptFromDevice(
        new Uint8Array(Buffer.from(entry.encrypted_key, "base64")),
        keypair.privateKey,
        peerPub,
        entry.version,
      );
    }
    keyring.save(statePaths().keyring, keypair.privateKey);
    this.cached = null;
    return resp.current_version;
  }

  // === Clipboard ===

  async pushText(text: string): Promise<{
    sent: boolean;
    key_version: number;
    size: number;
  }> {
    const state = await this.ensureReady();
    const { keypair, keyring } = state;

    const data = new TextEncoder().encode(text);
    const { data: encrypted, keyVersion } = keyring.encryptPayload(data);

    const meta = JSON.stringify({
      mime_type: "text/plain",
      size: data.length,
    });
    const metaEncrypted = keyring.encryptPayload(new TextEncoder().encode(meta)).data;

    try {
      await this.wsPush(state, {
        content_type: "text",
        encrypted_data: Buffer.from(encrypted).toString("base64"),
        metadata: Buffer.from(metaEncrypted).toString("base64"),
        key_version: keyVersion,
      });
    } catch (e) {
      // If another device rotated the group key, our version may be stale.
      const msg = e instanceof Error ? e.message : String(e);
      if (/rotation|version/i.test(msg)) {
        await this.refreshGroupKeys();
        return this.pushTextAfterRotation(text, keypair);
      }
      throw e;
    }

    return { sent: true, key_version: keyVersion, size: data.length };
  }

  private async pushTextAfterRotation(
    text: string,
    _keypair: KeyPair,
  ): Promise<{ sent: boolean; key_version: number; size: number }> {
    const state = await this.ensureReady();
    const { keyring } = state;
    const data = new TextEncoder().encode(text);
    const { data: encrypted, keyVersion } = keyring.encryptPayload(data);
    const meta = JSON.stringify({ mime_type: "text/plain", size: data.length });
    const metaEncrypted = keyring.encryptPayload(new TextEncoder().encode(meta)).data;
    await this.wsPush(state, {
      content_type: "text",
      encrypted_data: Buffer.from(encrypted).toString("base64"),
      metadata: Buffer.from(metaEncrypted).toString("base64"),
      key_version: keyVersion,
    });
    return { sent: true, key_version: keyVersion, size: data.length };
  }

  /**
   * Pushes over the WebSocket. An expired access token makes the server reject
   * the upgrade with 401, so refresh the session once and retry.
   */
  private async wsPush(state: ReadyState, payload: ClipboardPushPayload): Promise<void> {
    const { session, api, fingerprint } = state;
    try {
      await this.ws.pushClipboard(session.server_url, api.access ?? "", fingerprint, payload);
    } catch (e) {
      if (!(e instanceof WsError) || !/\b401\b/.test(e.message)) throw e;
      if (!(await api.refreshSession(api.access))) {
        throw new SessionExpiredError(SESSION_EXPIRED_MESSAGE);
      }
      await this.ws.pushClipboard(session.server_url, api.access ?? "", fingerprint, payload);
    }
  }

  async getClipboard(
    limit = 20,
    offset = 0,
  ): Promise<{ items: ClipboardItem[]; has_more: boolean }> {
    const { api, keyring } = await this.ensureReady();
    const resp = await api.getClipboardHistory(limit, offset);
    const items = resp.entries.map((e) => this.decryptEntry(keyring, e));
    return { items, has_more: resp.has_more };
  }

  async getLatestClipboard(skipOwn = false): Promise<ClipboardItem | null> {
    const { session } = await this.ensureReady();
    const { items } = await this.getClipboard(20, 0);
    const filtered = skipOwn
      ? items.filter((i) => i.device_id !== session.device_id)
      : items;
    return filtered[0] ?? null;
  }

  async searchClipboard(
    query: string,
    limit = 10,
    maxScan = 200,
  ): Promise<ClipboardItem[]> {
    const matches: ClipboardItem[] = [];
    const needle = query.toLowerCase();
    let offset = 0;
    const pageSize = 50;
    while (offset < maxScan) {
      const { items, has_more } = await this.getClipboard(pageSize, offset);
      for (const item of items) {
        if (item.text && item.text.toLowerCase().includes(needle)) {
          matches.push(item);
          if (matches.length >= limit) return matches;
        }
      }
      if (!has_more) break;
      offset += pageSize;
    }
    return matches;
  }

  private decryptEntry(keyring: Keyring, entry: ClipboardEntry): ClipboardItem {
    const base: ClipboardItem = {
      id: entry.id,
      created_at: entry.created_at,
      device_id: entry.device_id,
      device_name: entry.device_name,
      content_type: entry.content_type,
      key_version: entry.key_version,
      size: 0,
      decrypted: false,
    };

    const encData = new Uint8Array(Buffer.from(entry.encrypted_data, "base64"));
    let data: Uint8Array;
    try {
      data = keyring.decryptPayload(encData, entry.key_version);
    } catch {
      try {
        data = keyring.decryptPayloadLegacy(encData, entry.key_version);
      } catch {
        return {
          ...base,
          text: undefined,
        };
      }
    }

    let size = data.length;
    let mimeType: string | undefined;
    let filename: string | undefined;
    if (entry.metadata) {
      try {
        const metaEnc = new Uint8Array(Buffer.from(entry.metadata, "base64"));
        const metaJson = keyring.decryptPayload(metaEnc, entry.key_version);
        const meta = JSON.parse(new TextDecoder().decode(metaJson)) as {
          size?: number;
          mime_type?: string;
          filename?: string;
        };
        size = meta.size ?? size;
        mimeType = meta.mime_type;
        filename = meta.filename;
      } catch {
        // metadata is optional
      }
    }

    const text =
      entry.content_type === "text" ? new TextDecoder().decode(data) : undefined;

    return {
      ...base,
      text,
      size,
      mime_type: mimeType,
      filename,
      decrypted: true,
    };
  }

  // === Devices & account ===

  async listDevices(): Promise<DeviceInfo[]> {
    const { api } = await this.ensureReady();
    return api.getDevices();
  }

  async removeDevice(deviceId: string, force = false): Promise<string> {
    const { session, api } = await this.ensureReady();
    if (deviceId === session.device_id && !force) {
      throw new Error(
        "Refusing to remove this MCP device's own registration (that would log the agent out). " +
          "Pass force=true if you really mean it, or tell the user to use cpmesh_logout instead.",
      );
    }
    await api.deleteDevice(deviceId);
    return `Device ${deviceId} removed.`;
  }

  async status(): Promise<Record<string, unknown>> {
    const session = loadSession();
    if (!session) {
      const twoFactor = this.twoFactorNextStep();
      return {
        logged_in: false,
        ...(twoFactor && { two_factor_code_needed: true }),
        next_step:
          twoFactor ??
          "Call cpmesh_login with the user's server URL and credentials (or set CPMESH_SERVER_URL / CPMESH_USERNAME / CPMESH_PASSWORD environment variables).",
      };
    }
    const keypair = KeyPair.loadOrGenerate(statePaths().deviceKey);
    const api = this.buildApi(session, keypair);
    const paths = statePaths();

    let approval: ApprovalStatusResponse | string;
    try {
      approval = await api.getMyApprovalStatus();
    } catch (e) {
      approval =
        e instanceof ApiError || e instanceof SessionExpiredError
          ? `unavailable: ${e.message}`
          : "unavailable";
    }

    let code: string | undefined;
    if (
      typeof approval !== "string" &&
      approval.status !== "approved" &&
      approval.session_id &&
      approval.approver_public_key
    ) {
      code = this.derivePairingCode(keypair, approval);
    }

    let keyVersion = 0;
    let keyringOk = false;
    try {
      const ring = Keyring.load(paths.keyring, keypair.privateKey);
      keyVersion = ring.currentVersion;
      keyringOk = ring.hasGroupKey();
    } catch {
      // no keyring yet
    }

    return {
      logged_in: true,
      server_url: session.server_url,
      user_id: session.user_id,
      device_id: session.device_id,
      device_name: session.device_name,
      device_status:
        typeof approval === "string" ? session.device_status : approval.status,
      approval_code: code,
      group_key_version: keyVersion,
      group_key_available: keyringOk,
      state_dir: paths.root,
      next_step:
        typeof approval === "string"
          ? "Session exists but the server could not be reached or the session expired — try cpmesh_login again."
        : approval.status !== "approved"
          ? (code
              ? `Ask the user to confirm pairing code ${code} on an approved device, then call cpmesh_wait_for_approval.`
              : "Ask the user to approve this device from an approved cpmesh device, then call cpmesh_wait_for_approval.")
          : !keyringOk
            ? "Approved but group key missing — it will be synced on the next tool call, or call cpmesh_wait_for_approval."
            : "Ready — clipboard tools are usable.",
    };
  }

  async logout(): Promise<string> {
    this.ws.close();
    this.cached = null;
    this.signIns.clear();
    clearAllState();
    return "Logged out. Local keys, keyring and session were wiped.";
  }
}

export function toPlainEntrySnapshot(entry: PlainEntry): Record<string, unknown> {
  return {
    id: entry.id,
    device_name: entry.device_name,
    content_type: entry.content_type,
    created_at: entry.created_at,
    size: entry.data.length,
    mime_type: entry.metadata.mime_type,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
