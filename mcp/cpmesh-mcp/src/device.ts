/**
 * High-level orchestrator: makes this MCP server behave as a first-class
 * cpmesh device (protocol v3) — identity + encryption keys, registration,
 * committed-SAS approval pairing, group-key sync, and signed, context-bound
 * clipboard read/write over the E2E-encrypted channel.
 *
 * Mirrors the flows in desktop-tauri/src-tauri/src/commands.rs
 * (setup_and_login / get_my_approval_status / confirm_pairing /
 * send_local_clipboard / authenticate_entry / sync_history) and key_sync.rs.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { hostname } from "node:os";
import {
  ApiError,
  CpmeshApi,
  SESSION_EXPIRED_MESSAGE,
  SessionExpiredError,
} from "./api.js";
import {
  DeviceKeys,
  KeyPair,
  Keyring,
  bytesEqual,
  fingerprintOfPublicKey,
  fromBase64,
  pairingFingerprint,
  sasCode,
  sasCommitment,
  toBase64,
} from "./crypto.js";
import { type EntryContext, openEntry, sealEntry, verifyEntrySignature } from "./entry.js";
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
  ReplayGuard,
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
import { PAIRING_VERSION } from "./protocol.js";
import { SignInFlow, type Account } from "./signin.js";
import { WsClient, WsError } from "./ws.js";
import {
  pinVerified, revokeDevice, rotateKeys, senderIdentityKey, synchronizeKeys, SecurityError,
} from "./membership.js";
export { SecurityError } from "./membership.js";

const FINGERPRINT_SALT = "cpnet-device-fp-v1";
const PAIRING_TTL_MS = 600_000;
const LIVE_FEED_LIMIT = 32;
const APPROVAL_NOT_STARTED = "Ask the user to start the approval for this device from an approved cpmesh device, then call cpmesh_wait_for_approval.";

/** What the agent sees of an approval session (pending side). */
export interface PairingView {
  session_id: string;
  /** 8-digit short authentication string ("1234 5678"), once both nonces are known. */
  pairing_code?: string;
  /** Full 64-character pairing code over both identity keys, for a stronger manual check. */
  pairing_full_code: string;
}

interface PairingCandidate {
  peerId: string;
  publicKey: string; // base64 identity key of the approver
  fingerprint: string; // full pairing code
  commit?: Uint8Array; // the approver's commitment, as first seen
  nonce?: Uint8Array; // our contribution, drawn once
  nonceSubmitted: boolean;
  sas?: string;
  expires: number;
}

function pairingNextStep(view: PairingView): string {
  return view.pairing_code
    ? `Both devices now show an 8-digit pairing code (ours: ${view.pairing_code}; full code ${view.pairing_full_code}). ` +
      "Ask the user to read the code shown on the approving device. If it matches, call cpmesh_confirm_pairing with the " +
      "session_id and the code the user read there (or the full 64-character code), then cpmesh_wait_for_approval. " +
      "Never confirm by echoing this server's own value."
    : "Pairing has started; the 8-digit code appears on both devices once the approving device reveals its nonce. " +
      "Poll cpmesh_status or cpmesh_wait_for_approval, then call cpmesh_confirm_pairing with the code the user reads on the approving device.";
}

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
  keys: DeviceKeys;
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
  request_id?: string;
  sent_at?: number;
  text?: string;
  size: number;
  mime_type?: string;
  filename?: string;
  decrypted: boolean;
  /** False for legacy unsigned entries (history display only) and for entries that could not be verified. */
  authenticated: boolean;
  /** Why the entry could not be authenticated or decrypted. */
  error?: string;
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
  private pairing = new Map<string, PairingCandidate>();
  private keyWork: Promise<unknown> = Promise.resolve();
  private loading: Promise<ReadyState> | null = null;
  private closing = false;
  private sessionGeneration = 0;
  private pushes = new Map<string, SavedPush>();
  /** Live entries accepted over the WebSocket (signature + replay guard), newest last. */
  private liveFeed: ClipboardItem[] = [];

  constructor() {
    this.ws.onKeyChange = async () => { await this.refreshGroupKeys(); };
    this.ws.onClipboardNew = async (entry) => { await this.acceptLiveEntry(entry); };
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
    keys: DeviceKeys,
    name: string,
    fingerprint: string,
  ): RegisterDeviceRequest {
    return {
      name,
      public_key: toBase64(keys.identity.publicKeyBytes()),
      public_key_sig: toBase64(keys.identity.signPublicKey()),
      encryption_key: toBase64(keys.encryption.publicKeyBytes()),
      encryption_key_sig: toBase64(keys.certifyEncryptionKey()),
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
    pairing?: PairingView;
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
    const keys = DeviceKeys.loadOrGenerate(paths.deviceKey, paths.encryptionKey);

    const reg = await api.registerDevice(
      this.registrationFor(keys, deviceName, fingerprint),
      (challenge) => keys.identity.signDeviceChallenge(challenge),
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

    // Pending: join the pairing session if an approver has already started one.
    // (Already under the state lock here, so the nonce goes out directly.)
    const status = await api.getMyApprovalStatus();
    const pairing = await this.updatePairing(keys, status, (id, nonce) => api.submitPendingNonce(id, nonce));
    return {
      status: "pending",
      pairing,
      message:
        `${recoveryNote}Logged in. Device "${deviceName}" is PENDING approval. ` +
        (pairing ? pairingNextStep(pairing) : APPROVAL_NOT_STARTED),
    };
    });
  }

  /**
   * Pending side of the committed-SAS pairing (mirrors the desktop's
   * get_my_approval_status). The relay is untrusted, so ordering is enforced
   * here: the approver's commitment is remembered as first seen and may never
   * change; our nonce is drawn once and only after that commitment exists; the
   * revealed approver nonce must open the remembered commitment.
   */
  private async updatePairing(
    keys: DeviceKeys,
    status: ApprovalStatusResponse,
    submitNonce: (sessionId: string, nonce: Uint8Array) => Promise<void>,
  ): Promise<PairingView | undefined> {
    const { session_id: sessionId, approver_public_key: approverKey, approver_device_id: approverId } = status;
    if (!sessionId || !approverKey || !approverId) return undefined;
    if (status.pairing_version !== PAIRING_VERSION) {
      throw new SecurityError(`Update the approving device and the relay to pairing protocol ${PAIRING_VERSION} before pairing`);
    }
    const approverPub = KeyPair.parsePublicKey(fromBase64(approverKey));
    const fingerprint = pairingFingerprint(keys.identity.publicKeyBytes(), approverPub);
    let candidate = this.pairing.get(sessionId);
    if (candidate && (candidate.publicKey !== approverKey || candidate.peerId !== approverId)) {
      throw new SecurityError("Pairing identity changed; do not approve this session");
    }
    if (!candidate) {
      // One session at a time; an expired candidate is kept as seen (confirmPairing refuses it) rather
      // than recreated, so a relay cannot obtain a fresh commitment slot for the same session.
      this.pairing.clear();
      candidate = { peerId: approverId, publicKey: approverKey, fingerprint, nonceSubmitted: false, expires: Date.now() + PAIRING_TTL_MS };
      this.pairing.set(sessionId, candidate);
    }
    if (status.approver_commit) {
      const commit = nonce32(status.approver_commit, "approver commitment");
      if (!candidate.commit) candidate.commit = commit;
      else if (!bytesEqual(candidate.commit, commit)) {
        throw new SecurityError("Pairing commitment changed; do not approve this session");
      }
      if (!candidate.nonceSubmitted) {
        // Draw once; resubmitting the same nonce after a lost response is idempotent on the relay.
        candidate.nonce ??= new Uint8Array(randomBytes(32));
        await submitNonce(sessionId, candidate.nonce);
        candidate.nonceSubmitted = true;
      }
    }
    if (!candidate.sas && status.approver_nonce && candidate.commit && candidate.nonce) {
      const approverNonce = nonce32(status.approver_nonce, "approver nonce");
      if (!bytesEqual(sasCommitment(approverNonce), candidate.commit)) {
        throw new SecurityError("Pairing commitment does not match the revealed nonce; do not approve this session");
      }
      candidate.sas = sasCode(approverNonce, candidate.nonce, keys.identity.publicKeyBytes(), approverPub);
    }
    return { session_id: sessionId, pairing_code: candidate.sas, pairing_full_code: fingerprint };
  }

  /** The most recent pairing session known locally, for status when the relay is unreachable. */
  private lastPairing(): PairingView | undefined {
    const latest = [...this.pairing.entries()].at(-1);
    if (!latest) return undefined;
    const [sessionId, candidate] = latest;
    return { session_id: sessionId, pairing_code: candidate.sas, pairing_full_code: candidate.fingerprint };
  }

  /**
   * Polls until this device is approved (or rejected/revoked), then syncs the
   * group key. Returns the final state.
   */
  async waitForApproval(
    timeoutMs = 180_000,
    onProgress?: (info: { status: string; pairing?: PairingView }) => void,
  ): Promise<{ approved: boolean; status: string; pairing?: PairingView; message: string }> {
    const { api, keys, session } = await this.requireSession();

    const deadline = Date.now() + timeoutMs;
    let pairing: PairingView | undefined;

    while (Date.now() < deadline) {
      if (this.closing) throw new Error("MCP connection closed");
      const status = await this.withSession(session, () => api.getMyApprovalStatus());

      if (status.status === "approved") {
        const pins = loadPinnedKeys();
        if (session.device_status !== "approved" && !Object.keys(pins).some((id) => id !== session.device_id)) {
          return {
            approved: false, status: "verification_required", pairing,
            message: "The relay says approved, but local trust is missing. Confirm the pairing code the user reads on the approving device with cpmesh_confirm_pairing (or verify that device's full fingerprint with cpmesh_verify_device after a restart).",
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

      pairing = await this.updatePairing(keys, status, (id, nonce) =>
        this.withSession(session, () => api.submitPendingNonce(id, nonce)));
      onProgress?.({ status: status.status, pairing });
      await sleep(2500);
    }

    return {
      approved: false,
      status: "pending",
      pairing,
      message: `Still pending approval. ${pairing ? pairingNextStep(pairing) : APPROVAL_NOT_STARTED}`,
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
    keys: DeviceKeys;
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
    const paths = statePaths();
    // The encryption key is created on first use for installs that predate protocol 3.
    const keys = DeviceKeys.load(paths.deviceKey, paths.encryptionKey);
    const api = this.buildApi(session, keys);
    return { api, keys, session };
  }

  /**
   * API client for a stored session. Refreshed tokens are persisted to the
   * session file (shared with other MCP processes using the same state
   * directory) and re-bound to this device: the server issues refreshed access
   * tokens without a device, and re-registering with the same key and
   * fingerprint is a plain reconnect that returns a device-bound token.
   */
  private buildApi(session: Session, keys: DeviceKeys): CpmeshApi {
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
        this.registrationFor(keys, session.device_name, this.fingerprintOf(session)),
        (challenge) => keys.identity.signDeviceChallenge(challenge),
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
    const { api, keys, session } = await this.requireSession();

    let deviceStatus = session.device_status;
    let approval: ApprovalStatusResponse | undefined;
    if (deviceStatus !== "approved") {
      // The device may have been approved since we last checked.
      approval = await api.getMyApprovalStatus();
      deviceStatus = approval.status;
      if (deviceStatus !== session.device_status) {
        updateSession({ device_status: deviceStatus });
        session.device_status = deviceStatus;
      }
    }

    if (deviceStatus !== "approved") {
      // Already under the state lock (sequenceKeys), so the nonce goes out directly.
      approval ??= await api.getMyApprovalStatus();
      const pairing = await this.updatePairing(keys, approval, (id, nonce) => api.submitPendingNonce(id, nonce));
      throw new DeviceNotReadyError(
        `device "${session.device_name}" is ${deviceStatus}`,
        pairing ? pairingNextStep(pairing) : APPROVAL_NOT_STARTED,
      );
    }

    // Peers wrap keys to the encryption key the relay lists for us; make sure it is ours.
    await this.publishEncryptionKey(api, keys, session.device_id);

    // Load (or bootstrap) the group-key keyring.
    const keyring = existsSync(statePaths().keyring)
      ? Keyring.load(statePaths().keyring, keys.identity.privateKey) : new Keyring();

    const fingerprint = this.fingerprintOf(session);
    this.cached = { session, api, keys, keyring, fingerprint };
    return this.cached;
  }

  /** Mirrors key_sync::publish_encryption_key: (re)publish only when the relay's listing differs. */
  private async publishEncryptionKey(api: CpmeshApi, keys: DeviceKeys, ownId: string): Promise<void> {
    const { devices } = await api.getDeviceKeys();
    const published = devices.find((device) => device.id === ownId)?.encryption_key;
    if (published === toBase64(keys.encryption.publicKeyBytes())) return;
    try {
      await api.publishEncryptionKey(keys.encryption.publicKeyBytes(), keys.certifyEncryptionKey());
    } catch (error) {
      throw new Error(`Could not publish the device encryption key: ${error instanceof Error ? error.message : String(error)}`);
    }
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
      const { api, keys, keyring, session } = state;
      const due = await synchronizeKeys(api, keyring, keys, session.device_id);
      if (due) await rotateKeys(api, keyring, keys, session.device_id);
      return state;
    });
  }

  async ensureReady(): Promise<ReadyState> { return this.syncReady(); }

  async refreshGroupKeys(): Promise<number> {
    return (await this.syncReady()).keyring.currentVersion;
  }

  /**
   * Pins the approver after the user compared the code shown on BOTH devices:
   * either the 8-digit short authentication string or the full 64-character
   * code. Nothing is pinned before our own SAS exists (mirrors confirm_pairing).
   */
  async confirmPairing(sessionId: string, code: string): Promise<string> {
    return this.sequenceKeys(() => {
      const candidate = this.pairing.get(sessionId);
      if (!candidate || candidate.expires < Date.now()) {
        throw new SecurityError("Pairing session is missing or has expired; start the approval again");
      }
      if (!candidate.sas) {
        throw new SecurityError("Wait until both devices show the same 8-digit code before confirming");
      }
      if (!codeMatches(candidate, code)) {
        throw new SecurityError("Pairing code does not match; do not approve this device");
      }
      pinVerified(candidate.peerId, candidate.publicKey);
      return "Approver identity verified locally. Wait for approval on the other device.";
    });
  }

  /** Explicit verification of an existing device by its identity-key fingerprint (unchanged in v3). */
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
    const { keyring, keys, session } = state;
    const data = new TextEncoder().encode(text);
    if (data.length > 1024 * 1024) throw new Error("Text exceeds 1 MiB");
    const hash = createHash("sha256").update(data).digest("hex");
    let pending = this.pushes.get(requestId);
    if (pending && pending.hash !== hash) throw new Error("request_id already belongs to different clipboard content");
    if (pending && !pending.receipt && !pending.payload.sender_signature) {
      // Sealed before protocol 3: the relay would reject it unsigned, so seal it again.
      this.pushes.delete(requestId);
      pending = undefined;
    }
    if (!pending) {
      if (this.pushes.size >= 32) {
        const completed = [...this.pushes].find(([, p]) => p.receipt !== undefined);
        if (!completed) throw new Error("Too many unacknowledged pushes; retry their request IDs first");
        this.pushes.delete(completed[0]);
      }
      // Both ciphertexts are bound to this context and the identity key signs it (send_local_clipboard).
      const sentAt = Date.now();
      const sealed = sealEntry(
        keyring, keys.identity,
        { contentType: "text", senderId: session.device_id, requestId, sentAt },
        data, new TextEncoder().encode(JSON.stringify({ mime_type: "text/plain", size: data.length })),
      );
      pending = { hash, payload: {
        request_id: requestId,
        content_type: "text",
        encrypted_data: toBase64(sealed.encryptedData),
        metadata: toBase64(sealed.metadata),
        key_version: sealed.keyVersion,
        sent_at: sentAt,
        sender_signature: toBase64(sealed.signature),
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
    const state = await this.ensureReady();
    const resp = await this.withSession(state.session, () => state.api.getClipboardHistory(limit, offset));
    const items: ClipboardItem[] = [];
    for (const entry of resp.entries) items.push(await this.decryptEntry(state, entry));
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

  /** History path: an entry that cannot be authenticated or opened is listed without content. */
  private async decryptEntry(state: ReadyState, entry: ClipboardEntry): Promise<ClipboardItem> {
    try {
      return await this.authenticateEntry(state, entry, false);
    } catch (error) {
      return {
        ...entryBase(entry), size: 0, decrypted: false, authenticated: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Live path (`clipboard_new` over the WebSocket): the entry must be signed by
   * a verified member and carry a strictly newer sender clock than anything
   * seen from that device; only then is it decrypted and kept in the live feed.
   */
  async acceptLiveEntry(entry: ClipboardEntry): Promise<ClipboardItem> {
    if (this.closing) throw new Error("Signing out");
    const state = this.cached ?? await this.ensureReady();
    const item = await this.authenticateEntry(state, entry, true);
    this.liveFeed.push(item);
    if (this.liveFeed.length > LIVE_FEED_LIMIT) this.liveFeed.splice(0, this.liveFeed.length - LIVE_FEED_LIMIT);
    console.error(`[cpmesh-mcp] Live clipboard entry ${item.id} from "${item.device_name}" authenticated`);
    return item;
  }

  /** Entries accepted on the live path since this process started, newest last. */
  recentLiveEntries(): ClipboardItem[] {
    return [...this.liveFeed];
  }

  /**
   * Verifies a relay-delivered entry before it is trusted (desktop:
   * authenticate_entry). The sender must be a pinned member whose identity key
   * signs the entry's context and both ciphertexts; live entries must also pass
   * the replay guard. Legacy unsigned entries are readable for history only and
   * flagged unauthenticated; on the live path they are rejected outright.
   */
  private async authenticateEntry(state: ReadyState, entry: ClipboardEntry, live: boolean): Promise<ClipboardItem> {
    const { keyring, api, session } = state;
    const encData = fromBase64(entry.encrypted_data);
    const metadataBytes = entry.metadata ? fromBase64(entry.metadata) : new Uint8Array(0);
    const item = (data: Uint8Array, metadataJson: Uint8Array, authenticated: boolean): ClipboardItem => {
      const meta = parseMetadata(metadataJson);
      return {
        ...entryBase(entry),
        text: entry.content_type === "text" ? new TextDecoder().decode(data) : undefined,
        size: meta.size ?? data.length, mime_type: meta.mime_type, filename: meta.filename,
        decrypted: true, authenticated,
      };
    };

    if (entry.request_id === undefined || entry.sent_at === undefined || entry.sender_signature === undefined) {
      if (live) throw new SecurityError("Entry is not signed; update the sending device to protocol 3");
      const data = keyring.decryptPayloadLegacy(encData, entry.key_version);
      let metadataJson: Uint8Array = new Uint8Array(0);
      if (metadataBytes.length > 0) {
        try { metadataJson = keyring.decryptPayloadLegacy(metadataBytes, entry.key_version); } catch { /* optional */ }
      }
      return item(data, metadataJson, false);
    }

    const context: EntryContext = {
      keyVersion: entry.key_version, contentType: entry.content_type, senderId: entry.device_id,
      requestId: entry.request_id, sentAt: entry.sent_at,
    };
    // The sender must be a member we pinned ourselves, not merely one the relay lists.
    const senderKey = await senderIdentityKey(entry.device_id, entry.key_version, async () =>
      (await this.withSession(session, () => api.getDeviceKeys())).devices);
    if (!verifyEntrySignature(senderKey, context, encData, metadataBytes, fromBase64(entry.sender_signature))) {
      throw new SecurityError("Sender signature is invalid");
    }
    if (live) {
      await this.withSession(session, () => new ReplayGuard().accept(entry.device_id, entry.sent_at!));
    }
    const { data, metadataJson } = openEntry(keyring, context, encData, metadataBytes);
    return item(data, metadataJson, true);
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
        const due = await synchronizeKeys(state.api, state.keyring, state.keys, session.device_id);
        if (due) await rotateKeys(state.api, state.keyring, state.keys, session.device_id);
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
    const paths = statePaths();
    const keys = DeviceKeys.load(paths.deviceKey, paths.encryptionKey);
    const api = this.buildApi(session, keys);

    let approval: ApprovalStatusResponse | string;
    try {
      approval = await this.withSession(session, () => api.getMyApprovalStatus());
    } catch (e) {
      approval =
        e instanceof ApiError || e instanceof SessionExpiredError
          ? `unavailable: ${e.message}`
          : "unavailable";
    }

    let pairing: PairingView | undefined;
    if (typeof approval === "string") {
      pairing = this.lastPairing();
    } else if (approval.status !== "approved") {
      pairing = await this.updatePairing(keys, approval, (id, nonce) =>
        this.withSession(session, () => api.submitPendingNonce(id, nonce)));
    }

    const ring = existsSync(paths.keyring) ? Keyring.load(paths.keyring, keys.identity.privateKey) : new Keyring();
    const keyVersion = ring.currentVersion;
    const keyringOk = ring.hasGroupKey();

    return {
      logged_in: true,
      protocol_version: PAIRING_VERSION,
      server_url: session.server_url,
      user_id: session.user_id,
      device_id: session.device_id,
      device_name: session.device_name,
      device_status:
        typeof approval === "string" ? session.device_status : approval.status,
      pairing_session_id: pairing?.session_id,
      pairing_code: pairing?.pairing_code,
      pairing_full_code: pairing?.pairing_full_code,
      own_fingerprint: fingerprintOfPublicKey(keys.identity.publicKeyBytes()),
      key_sync_error: this.ws.keyError,
      group_key_version: keyVersion,
      group_key_available: keyringOk,
      live_entries_received: this.liveFeed.length,
      state_dir: paths.root,
      next_step:
        typeof approval === "string"
          ? "Session exists but the server could not be reached or the session expired — try cpmesh_login again."
        : approval.status !== "approved"
          ? (pairing ? pairingNextStep(pairing) : APPROVAL_NOT_STARTED)
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
    this.liveFeed = [];
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

/** Accepts either the 8-digit short code or the full 64-character pairing code (desktop: code_matches). */
function codeMatches(candidate: PairingCandidate, entered: string): boolean {
  const normalized = normalizeFingerprint(entered);
  if (/^[0-9]{8}$/.test(normalized)) {
    return candidate.sas !== undefined && normalizeFingerprint(candidate.sas) === normalized;
  }
  return normalized.length === 64 && normalized === candidate.fingerprint;
}

function nonce32(value: string, what: string): Uint8Array {
  const bytes = fromBase64(value);
  if (bytes.length !== 32) throw new SecurityError(`Relay sent an invalid ${what}`);
  return bytes;
}

function entryBase(entry: ClipboardEntry): Pick<ClipboardItem,
  "id" | "created_at" | "device_id" | "device_name" | "content_type" | "key_version" | "request_id" | "sent_at"> {
  return {
    id: entry.id, created_at: entry.created_at, device_id: entry.device_id, device_name: entry.device_name,
    content_type: entry.content_type, key_version: entry.key_version,
    ...(entry.request_id !== undefined && { request_id: entry.request_id }),
    ...(entry.sent_at !== undefined && { sent_at: entry.sent_at }),
  };
}

/** Decrypted metadata JSON; anything malformed is ignored, metadata is optional. */
function parseMetadata(metadataJson: Uint8Array): { size?: number; mime_type?: string; filename?: string } {
  if (metadataJson.length === 0) return {};
  try {
    const parsed = JSON.parse(new TextDecoder().decode(metadataJson)) as Record<string, unknown>;
    return {
      size: typeof parsed.size === "number" ? parsed.size : undefined,
      mime_type: typeof parsed.mime_type === "string" ? parsed.mime_type : undefined,
      filename: typeof parsed.filename === "string" ? parsed.filename : undefined,
    };
  } catch {
    return {};
  }
}

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
    authenticated: entry.authenticated,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
