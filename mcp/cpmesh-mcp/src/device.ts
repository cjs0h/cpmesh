/**
 * High-level orchestrator: makes this MCP server behave as a first-class
 * cpmesh device — keypair, registration, approval pairing, group-key sync,
 * and clipboard read/write over the E2E-encrypted channel.
 *
 * Mirrors the flows in desktop-tauri/src-tauri/src/commands.rs
 * (setup_and_login / setup_group_key / connect / sync_history).
 */

import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
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
  fingerprintOfPublicKey,
} from "./crypto.js";
import {
  loadPinnedKeys,
  loadMembership,
  loadSession,
  saveSession,
  statePaths,
  updateSession,
  clearAllState,
  loadPushes,
  savePushes,
  type SavedPush,
  withStateLock,
  type Session,
} from "./state.js";
import type {
  ApprovalStatusResponse,
  ClipboardEntry,
  ClipboardPushPayload,
  DeviceInfo,
  PlainEntry,
  RegisterDeviceRequest,
  ClipboardReceipt,
} from "./protocol.js";
import { SignInFlow, type Account } from "./signin.js";
import { WsClient, WsError } from "./ws.js";
import { pinVerified, revokeDevice, rotateKeys, synchronizeKeys, SecurityError } from "./membership.js";
export { SecurityError } from "./membership.js";

const FINGERPRINT_SALT = "cpnet-device-fp-v1";
const PAIRING_NEXT_STEP = "Independently compare all 64 fingerprint characters on both devices. Use cpmesh_status for the pairing_session_id, obtain the confirmed fingerprint from the user, call cpmesh_confirm_pairing, then cpmesh_wait_for_approval.";

export class DeviceNotReadyError extends Error {
  constructor(
    message: string,
    readonly nextStep: string,
  ) {
    super(message);
  }
}

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

export interface PushResult {
  sent: boolean;
  persisted: boolean;
  delivery: "unconfirmed";
  entry_id: string;
  request_id: string;
  key_version: number;
  size: number;
}

export class CpmeshDevice {
  readonly ws = new WsClient();
  private cached: ReadyState | null = null;
  /** Keeps a sign-in that waits for its two-factor code (in memory only). */
  private readonly signIns = new SignInFlow();
  private pairing = new Map<string, { peerId: string; publicKey: string; fingerprint: string; expires: number }>();
  private keyWork: Promise<unknown> = Promise.resolve();
  private loading: Promise<ReadyState> | null = null;
  private closing = false;
  private sessionGeneration = 0;
  private pushes = new Map<string, SavedPush>();

  constructor() {
    this.ws.onKeyChange = async () => { await this.refreshGroupKeys(); };
  }

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
    return withStateLock(async () => {
    const previous = loadSession();
    if (previous && (previous.user_id !== userId || previous.server_url.replace(/\/+$/, "") !== serverUrl.replace(/\/+$/, ""))) {
      throw new Error("Log out before switching accounts; do not reuse another account's keyring");
    }
    this.sessionGeneration++;
    this.ws.close();
    const fingerprint = this.fingerprintFor(userId);
    const recoveryNote =
      signedIn.recoveryCodesRemaining === undefined
        ? ""
        : `Signed in with a recovery code (${signedIn.recoveryCodesRemaining} left). `;

    const paths = statePaths();
    const keypair = KeyPair.loadOrGenerate(paths.deviceKey);

    const reg = await api.registerDevice(
      this.registrationFor(keypair, deviceName, fingerprint),
      (challenge) => keypair.signDeviceChallenge(challenge),
    );

    const deviceId = reg.device.id;
    const deviceStatus = reg.device.status;
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
        message: `${recoveryNote}Logged in as "${deviceName}". Keys are restored and authenticated on the next clipboard call. Existing meshes may require cpmesh_verify_device.`,
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
          ? `Pairing fingerprint: ${code}. ${PAIRING_NEXT_STEP}`
          : `Ask the user to start the approval for this device from an approved cpmesh device, then call cpmesh_wait_for_approval.`),
    };
    });
  }

  private derivePairingCode(
    keypair: KeyPair,
    status: ApprovalStatusResponse,
  ): string | undefined {
    if (status.session_id && status.approver_public_key && status.approver_device_id) {
        if (status.pairing_version !== 2) throw new SecurityError("Update both clients and server before full-fingerprint pairing");
        const approverPub = new Uint8Array(
          Buffer.from(status.approver_public_key, "base64"),
        );
        const fingerprint = deriveApprovalCode(
          keypair.privateKey,
          approverPub,
          keypair.publicKey,
        );
        const old = this.pairing.get(status.session_id);
        if (old && (old.publicKey !== status.approver_public_key || old.peerId !== status.approver_device_id)) {
          throw new SecurityError("Pairing identity changed; do not approve");
        }
        if (!old) {
          this.pairing.clear();
          this.pairing.set(status.session_id, {
          peerId: status.approver_device_id, publicKey: status.approver_public_key,
          fingerprint, expires: Date.now() + 600_000,
          });
        }
        return fingerprint;
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
      if (this.closing) throw new Error("MCP connection closed");
      const status = await this.withSession(session, () => api.getMyApprovalStatus());

      if (status.status === "approved") {
        const pins = loadPinnedKeys();
        if (session.device_status !== "approved" && !Object.keys(pins).some((id) => id !== session.device_id)) {
          return {
            approved: false, status: "verification_required", approval_code: lastCode,
            message: "The relay says approved, but local trust is missing. Obtain the full fingerprint independently from the user, then call cpmesh_confirm_pairing (or cpmesh_verify_device after a restart).",
          };
        }
        await this.withSession(session, () => updateSession({ device_status: "approved" }));
        this.cached = null;
        await this.ensureReady();
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
        `Still pending approval. ${PAIRING_NEXT_STEP}`,
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
    const keypair = KeyPair.load(statePaths().deviceKey);
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
        (challenge) => keypair.signDeviceChallenge(challenge),
        { retryOnExpiry: false },
      );
      if (reg.device.id !== session.device_id) {
        throw new Error("the server registered a different device while re-binding the session");
      }
    };
    return api;
  }

  private async loadReady(): Promise<ReadyState> {
    const stored = loadSession();
    if (!stored) {
      this.ws.close();
      this.cached = null;
    } else if (this.cached && (stored.device_id !== this.cached.session.device_id ||
        stored.user_id !== this.cached.session.user_id || stored.server_url !== this.cached.session.server_url)) {
      this.ws.close();
      this.cached = null;
    }
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
          ? `Pairing fingerprint: ${code}. ${PAIRING_NEXT_STEP}`
          : "Ask the user to approve this device from an approved cpmesh device, then call cpmesh_wait_for_approval.",
      );
    }

    // Load (or bootstrap) the group-key keyring.
    const keyring = existsSync(statePaths().keyring)
      ? Keyring.load(statePaths().keyring, keypair.privateKey) : new Keyring();

    const fingerprint = this.fingerprintOf(session);
    this.cached = { session, api, keypair, keyring, fingerprint };
    return this.cached;
  }

  // === Group key management ===

  private sequenceKeys<T>(operation: () => Promise<T> | T): Promise<T> {
    if (this.closing) return Promise.reject(new Error("Signing out"));
    const session = loadSession();
    if (!session) {
      this.ws.close();
      this.cached = null;
      return Promise.reject(new DeviceNotReadyError("cpmesh is not logged in", this.twoFactorNextStep() ?? "Call cpmesh_login."));
    }
    const generation = this.sessionGeneration;
    const work = this.keyWork.then(() => withStateLock(async () => {
      if (this.closing || generation !== this.sessionGeneration || !sameDeviceSession(loadSession(), session)) {
        throw new Error("Session changed");
      }
      const result = await operation();
      if (this.closing || generation !== this.sessionGeneration) throw new Error("Session changed");
      return result;
    }));
    // Callers see failures; later key operations can still retry safely.
    this.keyWork = work.catch(() => undefined);
    return work;
  }

  private withSession<T>(session: Session, operation: () => Promise<T> | T): Promise<T> {
    return withStateLock(() => {
      const current = loadSession();
      if (this.closing || !sameDeviceSession(current, session)) {
        throw new Error("Session changed");
      }
      return operation();
    });
  }

  private syncReady(): Promise<ReadyState> {
    return this.sequenceKeys(async () => {
      this.loading ??= this.loadReady().finally(() => { this.loading = null; });
      const state = await this.loading;
      const { api, keypair, keyring, session } = state;
      const due = await synchronizeKeys(api, keyring, keypair, session.device_id);
      if (due) await rotateKeys(api, keyring, keypair, session.device_id);
      return state;
    });
  }

  async ensureReady(): Promise<ReadyState> { return this.syncReady(); }

  async refreshGroupKeys(): Promise<number> {
    return (await this.syncReady()).keyring.currentVersion;
  }

  async confirmPairing(sessionId: string, fingerprint: string): Promise<string> {
    return this.sequenceKeys(() => {
      const candidate = this.pairing.get(sessionId);
      if (!candidate || candidate.expires < Date.now() ||
          candidate.fingerprint !== normalizeFingerprint(fingerprint)) {
        throw new SecurityError("Pairing fingerprint/session does not match or has expired");
      }
      pinVerified(candidate.peerId, candidate.publicKey);
      return "Approver identity verified locally. Wait for approval on the other device.";
    });
  }

  async verifyDevice(deviceId: string, fingerprint: string): Promise<string> {
    const generation = this.sessionGeneration;
    const { api, session } = await this.requireSession();
    const peer = (await this.withSession(session, () => api.getDeviceKeys())).devices.find((d) => d.id === deviceId && d.status === "approved");
    if (!peer?.public_key) throw new Error("Approved peer device not found");
    const expected = normalizeFingerprint(fingerprint);
    if (expected.length !== 64 ||
        normalizeFingerprint(fingerprintOfPublicKey(Buffer.from(peer.public_key, "base64"))) !== expected) {
      throw new SecurityError("Full fingerprint does not match. Do not trust this device.");
    }
    const publicKey = peer.public_key;
    if (generation !== this.sessionGeneration) throw new Error("Session changed");
    return this.sequenceKeys(() => {
      if (!sameDeviceSession(loadSession(), session)) throw new Error("Session changed");
      pinVerified(deviceId, publicKey);
      return "Device identity verified. Future keys must be authorized by authenticated membership.";
    });
  }

  // === Clipboard ===

  async pushText(text: string, requestId: string = randomUUID()): Promise<PushResult> {
    requestId = requestId.toLowerCase();
    const generation = this.sessionGeneration;
    const state = await this.ensureReady();
    if (this.closing || generation !== this.sessionGeneration) throw new Error("Session changed");
    try {
      return await this.withSession(state.session, () => this.pushPrepared(state, text, requestId, generation));
    } catch (error) {
      if (error instanceof WsError && error.code === "rotation_required") {
        await this.refreshGroupKeys();
        throw new WsError(`Keys changed before acceptance; retry request_id ${requestId}`, "rotation_required");
      }
      throw error;
    }
  }

  private async pushPrepared(state: ReadyState, text: string, requestId: string, generation: number): Promise<PushResult> {
    const trust = loadMembership();
    if (trust.rotation_required || trust.version > state.keyring.currentVersion) {
      throw new WsError("Keys changed before encryption", "rotation_required");
    }
    this.pushes = loadPushes(state.session.device_id);
    const { keyring } = state;
    const data = new TextEncoder().encode(text);
    if (data.length > 1024 * 1024) throw new Error("Text exceeds 1 MiB");
    const hash = createHash("sha256").update(data).digest("hex");
    let pending = this.pushes.get(requestId);
    if (pending && pending.hash !== hash) throw new Error("request_id already belongs to different clipboard content");
    if (!pending) {
      if (this.pushes.size >= 32) {
        const completed = [...this.pushes].find(([, p]) => p.receipt !== undefined);
        if (!completed) throw new Error("Too many unacknowledged pushes; retry their request IDs first");
        this.pushes.delete(completed[0]);
      }
      const { data: encrypted, keyVersion } = keyring.encryptPayload(data);
      const metadata = keyring.encryptPayload(new TextEncoder().encode(JSON.stringify({ mime_type: "text/plain", size: data.length }))).data;
      pending = { hash, payload: {
        request_id: requestId,
        content_type: "text",
        encrypted_data: Buffer.from(encrypted).toString("base64"),
        metadata: Buffer.from(metadata).toString("base64"),
        key_version: keyVersion,
      } };
      this.pushes.set(requestId, pending);
      savePushes(state.session.device_id, this.pushes);
    }
    if (!pending.receipt) {
      for (let attempt = 0; attempt < 2; attempt++) {
        if (this.closing || generation !== this.sessionGeneration) throw new Error("Session changed");
        try {
          pending.receipt = await this.wsPush(state, pending.payload);
          if (this.closing || generation !== this.sessionGeneration) throw new Error("Session changed");
          savePushes(state.session.device_id, this.pushes);
          break;
        }
        catch (error) {
          if (this.closing || generation !== this.sessionGeneration) throw new Error("Session changed");
          if (error instanceof WsError && error.code === "rotation_required") {
            this.pushes.delete(requestId);
            savePushes(state.session.device_id, this.pushes);
            throw new WsError(`Keys rotated before acceptance; retry request_id ${requestId}`, "rotation_required");
          }
          if (!(error instanceof WsError && error.uncertain && attempt === 0)) throw error;
        }
      }
    }
    if (!pending.receipt) throw new Error(`Persistence is unknown; retry request_id ${requestId}`);
    return {
      sent: true, persisted: true, delivery: "unconfirmed",
      entry_id: pending.receipt.entry_id, request_id: requestId,
      key_version: pending.payload.key_version, size: data.length,
    };
  }

  /**
   * Pushes over the WebSocket. An expired access token makes the server reject
   * the upgrade with 401, so refresh the session once and retry.
   */
  private async wsPush(state: ReadyState, payload: ClipboardPushPayload): Promise<ClipboardReceipt> {
    const { session, api, fingerprint } = state;
    try {
      return await this.ws.pushClipboard(session.server_url, api.access ?? "", fingerprint, payload);
    } catch (e) {
      if (!(e instanceof WsError) || !/\b401\b/.test(e.message)) throw e;
      if (!(await api.refreshSession(api.access))) {
        throw new SessionExpiredError(SESSION_EXPIRED_MESSAGE);
      }
      return await this.ws.pushClipboard(session.server_url, api.access ?? "", fingerprint, payload);
    }
  }

  async getClipboard(
    limit = 20,
    offset = 0,
  ): Promise<{ items: ClipboardItem[]; has_more: boolean }> {
    const { api, keyring, session } = await this.ensureReady();
    const resp = await this.withSession(session, () => api.getClipboardHistory(limit, offset));
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
      if (items.length === 0) throw new Error("History pagination made no progress");
      offset += items.length;
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
    const { api, session } = await this.requireSession();
    return this.withSession(session, () => api.getDevices());
  }

  async deleteClipboardEntry(id: string): Promise<void> {
    const { api, session } = await this.requireSession();
    await this.withSession(session, () => api.deleteClipboardEntry(id));
  }

  async removeDevice(deviceId: string, force = false): Promise<string> {
    const generation = this.sessionGeneration;
    const { session, api } = await this.requireSession();
    if (deviceId === session.device_id && !force) {
      throw new Error(
        "Refusing to remove this MCP device's own registration (that would log the agent out). " +
          "Pass force=true if you really mean it, or tell the user to use cpmesh_logout instead.",
      );
    }
    if (generation !== this.sessionGeneration) throw new Error("Session changed");
    await this.sequenceKeys(async () => {
      revokeDevice(deviceId);
      await api.deleteDevice(deviceId);
      if (deviceId !== session.device_id) {
        const state = await this.loadReady();
        const due = await synchronizeKeys(state.api, state.keyring, state.keypair, session.device_id);
        if (due) await rotateKeys(state.api, state.keyring, state.keypair, session.device_id);
      }
    });
    if (deviceId === session.device_id) await this.logout();
    return `Device ${deviceId} removed.`;
  }

  async status(): Promise<Record<string, unknown>> {
    const session = loadSession();
    if (!session) {
      this.ws.close();
      this.cached = null;
      const twoFactor = this.twoFactorNextStep();
      return {
        logged_in: false,
        ...(twoFactor && { two_factor_code_needed: true }),
        next_step:
          twoFactor ??
          "Call cpmesh_login with the user's server URL and credentials (or set CPMESH_SERVER_URL / CPMESH_USERNAME / CPMESH_PASSWORD environment variables).",
      };
    }
    const keypair = KeyPair.load(statePaths().deviceKey);
    const api = this.buildApi(session, keypair);
    const paths = statePaths();

    let approval: ApprovalStatusResponse | string;
    try {
      approval = await this.withSession(session, () => api.getMyApprovalStatus());
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

    const ring = existsSync(paths.keyring) ? Keyring.load(paths.keyring, keypair.privateKey) : new Keyring();
    const keyVersion = ring.currentVersion;
    const keyringOk = ring.hasGroupKey();
    const pairing = [...this.pairing.entries()].at(-1);

    return {
      logged_in: true,
      server_url: session.server_url,
      user_id: session.user_id,
      device_id: session.device_id,
      device_name: session.device_name,
      device_status:
        typeof approval === "string" ? session.device_status : approval.status,
      approval_code: code ?? pairing?.[1].fingerprint,
      pairing_session_id: typeof approval === "string" ? pairing?.[0] : approval.session_id ?? pairing?.[0],
      own_fingerprint: fingerprintOfPublicKey(keypair.publicKeyBytes()),
      key_sync_error: this.ws.keyError,
      group_key_version: keyVersion,
      group_key_available: keyringOk,
      state_dir: paths.root,
      next_step:
        typeof approval === "string"
          ? "Session exists but the server could not be reached or the session expired — try cpmesh_login again."
        : approval.status !== "approved"
          ? (code
              ? `Pairing fingerprint: ${code}. ${PAIRING_NEXT_STEP}`
              : "Ask the user to approve this device from an approved cpmesh device, then call cpmesh_wait_for_approval.")
          : !keyringOk || loadMembership().version < keyVersion || loadMembership().rotation_required
            ? "Keys need authenticated synchronization. Complete any pending device removal; for an existing mesh, verify peers independently with cpmesh_verify_device, then retry."
            : "Ready — clipboard tools are usable.",
    };
  }

  async logout(): Promise<string> {
    this.closing = true;
    this.sessionGeneration++;
    this.ws.close();
    await this.keyWork;
    await withStateLock(() => {
    this.cached = null;
    this.signIns.clear();
    this.pairing.clear();
    this.pushes.clear();
    clearAllState();
    });
    this.closing = false;
    return "Logged out. Local keys, keyring and session were wiped.";
  }

  stop(): void {
    if (this.closing) return;
    this.closing = true;
    this.sessionGeneration++;
    this.ws.close();
    this.signIns.clear();
    this.cached = null;
  }

}

function normalizeFingerprint(value: string): string { return value.replace(/[\s:-]/g, "").toUpperCase(); }

function sameDeviceSession(current: Session | null, expected: Session): boolean {
  return current !== null && current.device_id === expected.device_id &&
    current.user_id === expected.user_id && current.server_url === expected.server_url;
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
