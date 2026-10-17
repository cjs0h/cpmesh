/**
 * High-level orchestrator: makes this MCP server behave as a first-class
 * cpmesh device (protocol v3) — identity + encryption keys, registration,
 * committed-SAS approval pairing, group-key sync, and signed, context-bound
 * clipboard read/write over the E2E-encrypted channel.
 *
 * The account sign-in is OAuth (see authorization.ts): the user approves the
 * agent on the cpmesh website, then the device registers with proof of
 * possession and pairs with a trusted device exactly as before.
 *
 * Mirrors the flows in desktop-tauri/src-tauri/src/commands.rs
 * (get_my_approval_status / confirm_pairing / send_local_clipboard /
 * authenticate_entry / sync_history) and key_sync.rs.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { hostname } from "node:os";
import {
  ApiError,
  CpmeshApi,
  ScopeError,
  SessionExpiredError,
  TemporarilyUnavailableError,
  signedOutMessage,
  type TokenStore,
} from "./api.js";
import {
  Authorizer,
  revokeWithRetry,
  type AuthorizationFailed,
  type PendingAuthorization,
  type SignInProgress,
} from "./authorization.js";
import type { SignInMode } from "./browser.js";
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
  CLIENT_ID,
  agentName,
  grants,
  normalizeServerUrl,
  sameServer,
  type Scope,
  type TokenSet,
} from "./oauth.js";
import {
  loadPinnedKeys,
  loadMembership,
  loadSession,
  saveSession,
  statePaths,
  updateSession,
  clearAllState,
  clearAuthorization,
  clearDeviceState,
  isSignedIn,
  loadAuthorization,
  saveAuthorization,
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
  RegisterDeviceResponse,
  ClipboardReceipt,
} from "./protocol.js";
import { PAIRING_VERSION } from "./protocol.js";
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

/** This device registered with an approved sign-in. */
export interface SignedIn {
  status: "approved" | "pending";
  pairing?: PairingView;
  message: string;
}

/** What cpmesh_login answers: a sign-in waiting for approval, or (finishing an approved one) the device's state. */
export type LoginResult = (PendingAuthorization & { message: string }) | SignedIn;

/** Where a sign-in in progress stands after being advanced. Null when none is in progress. */
type AdvanceResult = PendingAuthorization | AuthorizationFailed | SignedIn | null;

const isFailed = (value: AdvanceResult | SignInProgress): value is AuthorizationFailed =>
  value !== null && (value.status === "access_denied" || value.status === "expired_token" || value.status === "failed");

function minutesLeft(expiresAt: string): string {
  const minutes = Math.max(1, Math.round((Date.parse(expiresAt) - Date.now()) / 60_000));
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

/** How the user gets to the approval page of a pending sign-in. */
export function approvalInstructions(pending: PendingAuthorization): string {
  if (pending.mode === "device") {
    const link = pending.verification_uri_complete ?? pending.verification_uri;
    return (
      `Ask the user to open ${link} in any browser (or to go to ${pending.verification_uri} and enter the code ${pending.user_code}), ` +
      `sign in to cpmesh and approve this agent after checking that the page shows the code ${pending.user_code}.`
    );
  }
  return pending.browser_opened
    ? "A browser tab on this computer asks the user to sign in to cpmesh and approve this agent " +
        `(if no tab opened, ask them to open ${pending.verification_uri} in a browser on this computer).`
    : `Ask the user to open ${pending.verification_uri} in a browser on this computer, sign in to cpmesh and approve this agent.`;
}

/** What the agent should do to sign in, or to finish the sign-in in progress. */
function signInRequired(session: Session | null, progress: SignInProgress | AdvanceResult): string {
  if (progress?.status === "authorization_pending") {
    return `${approvalInstructions(progress)} Then call cpmesh_wait_for_approval.`;
  }
  if (progress?.status === "authorized") {
    return "The user approved the sign-in: call cpmesh_wait_for_approval to finish registering this device.";
  }
  if (progress && isFailed(progress)) return `${progress.message} Call cpmesh_login to start again.`;
  if (session && !session.grant_id) {
    return (
      "This profile was signed in by cpmesh-mcp 0.2 with a password, which is no longer supported. Call cpmesh_login " +
      "to sign in with the browser; this device keeps its keys and pairing."
    );
  }
  if (session) {
    return `${signedOutMessage(session.signed_out)} This device keeps its keys and pairing, unless it was removed from the account.`;
  }
  return (
    "Call cpmesh_login to sign in with the browser (pass server_url, https://cpmesh.com unless the user self-hosts, " +
    "or set CPMESH_SERVER_URL)."
  );
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
  /** The account sign-in (OAuth) in progress, if any. */
  private readonly authorizer: Authorizer;
  /** The sign-in being advanced (waiting, polling or registering), so calls take turns. */
  private advancing: Promise<unknown> | null = null;
  private pairing = new Map<string, PairingCandidate>();
  private keyWork: Promise<unknown> = Promise.resolve();
  private loading: Promise<ReadyState> | null = null;
  private closing = false;
  private sessionGeneration = 0;
  private pushes = new Map<string, SavedPush>();
  /** Live entries accepted over the WebSocket (signature + replay guard), newest last. */
  private liveFeed: ClipboardItem[] = [];
  /** Called when the user approved a sign-in (the MCP client may still show its link). */
  onAuthorized: (() => void) | null = null;

  constructor(options: { authorizer?: Authorizer } = {}) {
    this.authorizer = options.authorizer ?? new Authorizer();
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

  /**
   * Starts signing this agent in to cpmesh (OAuth) and returns at once with the
   * link for the user, without waiting for the approval: cpmesh_wait_for_approval
   * finishes the sign-in, then registers and pairs the device. Signing in again
   * while signed in re-authorizes the agent (e.g. with other scopes); the device
   * keeps its keys and pairing.
   */
  async login(request: { serverUrl?: string; mode?: "auto" | SignInMode; clientName?: string } = {}): Promise<LoginResult> {
    const profile = loadSession();
    const configured = (request.serverUrl?.trim() || undefined) ?? (process.env.CPMESH_SERVER_URL || undefined) ?? profile?.server_url;
    if (!configured) {
      throw new Error(
        "No server URL: pass server_url (https://cpmesh.com for the hosted service, or the user's own server) " +
          "or set CPMESH_SERVER_URL in the MCP server environment.",
      );
    }
    const serverUrl = normalizeServerUrl(configured);
    if (profile && !sameServer(profile.server_url, serverUrl)) {
      throw new Error(
        `This agent's cpmesh profile belongs to ${profile.server_url}. To sign in to ${serverUrl} instead, ` +
          "call cpmesh_logout first: it signs this agent out and wipes its local profile.",
      );
    }

    // An approved sign-in whose device registration did not finish needs no new approval
    const progress = this.authorizer.peek();
    if (progress?.status === "authorized" && sameServer(progress.server_url, serverUrl)) {
      try {
        const finished = await this.advanceAuthorization(Date.now());
        if (finished?.status === "approved" || finished?.status === "pending") return finished;
      } catch (error) {
        console.error("[cpmesh-mcp] Finishing the approved sign-in failed, starting a new one:", errorMessage(error));
      }
    }

    const pending = await this.authorizer.start({
      serverUrl,
      mode: request.mode ?? "auto",
      agentName: agentName(request.clientName, hostname()),
    });
    const why = pending.reason ? ` (device sign-in: ${pending.reason})` : "";
    const current = isSignedIn(profile)
      ? " Until the user approves, the current authorization keeps working; once approved, it is replaced."
      : profile
        ? " This device keeps its keys and pairing."
        : "";
    return {
      ...pending,
      message:
        `Sign-in started${why}. ${approvalInstructions(pending)} The request expires in ${minutesLeft(pending.expires_at)}. ` +
        `Then call cpmesh_wait_for_approval.${current}`,
    };
  }

  /**
   * Advances the sign-in in progress until `deadline` (Unix ms; now = no
   * waiting): the browser callback or device-code approval, then the device
   * registration. Calls take turns, so one approval registers once.
   */
  private advanceAuthorization(deadline: number): Promise<AdvanceResult> {
    const run = (this.advancing ?? Promise.resolve()).then(
      () => this.runAdvance(deadline),
      () => this.runAdvance(deadline),
    );
    const marker = run.then(() => undefined, () => undefined);
    this.advancing = marker;
    void marker.then(() => {
      if (this.advancing === marker) this.advancing = null;
    });
    return run;
  }

  private async runAdvance(deadline: number): Promise<AdvanceResult> {
    const state = await this.authorizer.complete(deadline);
    if (state?.status !== "authorized") return state;
    this.onAuthorized?.();
    return this.register(state.server_url, state.tokens);
  }

  /**
   * Registers this device with the approved tokens (proof of possession, as
   * before) and saves the session. An existing profile keeps its keys: the
   * server finds its device by key and moves it to the new grant, so it needs
   * no new pairing. The tokens stay saved until this succeeds.
   */
  private register(serverUrl: string, tokens: TokenSet): Promise<SignedIn> {
    return withStateLock(async () => {
      const stored = loadAuthorization();
      if (stored?.stage !== "authorized" || stored.grant_id !== tokens.grant_id) {
        // Registered (or cancelled) by another call or process meanwhile
        const current = loadSession();
        if (isSignedIn(current) && current.grant_id === tokens.grant_id) {
          return { status: current.device_status === "approved" ? "approved" : "pending", message: `Signed in as "${current.device_name}".` };
        }
        throw new Error("The sign-in was cancelled. Call cpmesh_login to start again.");
      }
      const previous = loadSession();
      if (previous && (previous.user_id !== tokens.user_id || !sameServer(previous.server_url, serverUrl))) {
        await revokeWithRetry(serverUrl, stored.refresh_token).catch(() => undefined);
        clearAuthorization();
        throw new Error(
          "The user approved the sign-in with a different cpmesh account than the one this agent's profile belongs to, " +
            "so it was revoked. Ask the user to sign in to the cpmesh website with the agent's account and call cpmesh_login " +
            "again, or call cpmesh_logout first to switch accounts.",
        );
      }
      this.sessionGeneration++;
      this.ws.close();
      this.cached = null;

      const paths = statePaths();
      const keys = DeviceKeys.loadOrGenerate(paths.deviceKey, paths.encryptionKey);
      const fingerprint = previous?.fingerprint ?? this.fingerprintFor(tokens.user_id);
      const name = previous?.device_name ?? this.deviceName();
      const api = new CpmeshApi(serverUrl);
      api.setTokens(stored.access_token, stored.refresh_token);
      api.tokenStore = approvedTokenStore(tokens.grant_id);
      let reg: RegisterDeviceResponse;
      try {
        reg = await api.registerDevice(
          this.registrationFor(keys, name, fingerprint),
          (challenge) => keys.identity.signDeviceChallenge(challenge),
        );
      } catch (error) {
        throw registrationError(error);
      }

      // The server registered a new device (the old one was removed): its unsent pushes are void
      const replaced = previous !== null && previous.device_id !== reg.device.id;
      if (replaced) {
        clearDeviceState();
        this.pairing.clear();
        this.pushes.clear();
      }
      const scope = stored.scope ?? tokens.scope;
      const session: Session = {
        server_url: serverUrl,
        user_id: tokens.user_id,
        device_id: reg.device.id,
        device_name: name,
        device_status: reg.device.status,
        fingerprint,
        access_token: api.access ?? "",
        refresh_token: api.refresh ?? "",
        created_at: previous && !replaced ? previous.created_at : new Date().toISOString(),
        grant_id: tokens.grant_id,
        client_id: CLIENT_ID,
        ...(scope !== undefined && { scope }),
      };
      saveSession(session);
      clearAuthorization();
      this.cached = null;
      const allowed = scope === undefined ? "" : ` The user allowed: ${scope || "nothing"}.`;

      if (reg.device.status === "approved") {
        return {
          status: "approved",
          message:
            `Signed in as "${session.device_name}".${allowed} Keys are restored and authenticated on the next clipboard call. ` +
            "Existing meshes may require cpmesh_verify_device.",
        };
      }

      // Pending: join the pairing session if an approver has already started one.
      // (Already under the state lock here, so the nonce goes out directly.)
      const sessionApi = this.buildApi(session);
      const status = await sessionApi.getMyApprovalStatus();
      const pairing = await this.updatePairing(keys, status, (id, nonce) => sessionApi.submitPendingNonce(id, nonce));
      return {
        status: "pending",
        pairing,
        message:
          `Signed in.${allowed} Device "${session.device_name}" is PENDING approval. ` +
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
   * Finishes whichever step is pending, in order: the sign-in (browser callback
   * or device-code approval), the device registration, then the pairing, which
   * is polled until this device is approved (or rejected/revoked) and the group
   * key synced. Returns the state reached by `timeoutMs`.
   */
  async waitForApproval(
    timeoutMs = 180_000,
    onProgress?: (info: { status: string; pairing?: PairingView }) => void,
  ): Promise<{
    approved: boolean; status: string; pairing?: PairingView; authorization?: PendingAuthorization; message: string;
  }> {
    const deadline = Date.now() + timeoutMs;
    const signIn = await this.advanceAuthorization(deadline);
    if (signIn?.status === "authorization_pending") {
      return {
        approved: false, status: "authorization_pending", authorization: signIn,
        message: `Still waiting for the user to approve the sign-in. ${approvalInstructions(signIn)} Then call cpmesh_wait_for_approval again.`,
      };
    }
    if (isFailed(signIn)) {
      return { approved: false, status: signIn.status, message: `${signIn.message} Call cpmesh_login to start again.` };
    }

    const { api, keys, session } = await this.requireSession();
    let pairing: PairingView | undefined;
    for (;;) {
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
          message: `Device was ${status.status}. Ask the user to re-approve this device, or call cpmesh_logout and then cpmesh_login to start over with fresh keys.`,
        };
      }

      pairing = await this.updatePairing(keys, status, (id, nonce) =>
        this.withSession(session, () => api.submitPendingNonce(id, nonce)));
      onProgress?.({ status: status.status, pairing });
      const left = deadline - Date.now();
      if (left <= 0) break;
      await sleep(Math.min(2500, left));
    }

    return {
      approved: false,
      status: "pending",
      pairing,
      message: `Still pending approval. ${pairing ? pairingNextStep(pairing) : APPROVAL_NOT_STARTED}`,
    };
  }

  // === Readiness ===

  /** What to do to (finish) signing in, for errors and status. */
  private signInNextStep(session: Session | null): string {
    return signInRequired(session, this.authorizer.peek());
  }

  private async requireSession(): Promise<{
    api: CpmeshApi;
    keys: DeviceKeys;
    session: Session;
  }> {
    const session = loadSession();
    if (!isSignedIn(session)) {
      throw new DeviceNotReadyError("cpmesh is not signed in", this.signInNextStep(session));
    }
    const paths = statePaths();
    // The encryption key is created on first use for installs that predate protocol 3.
    const keys = DeviceKeys.load(paths.deviceKey, paths.encryptionKey);
    const api = this.buildApi(session);
    return { api, keys, session };
  }

  /**
   * API client for a stored session. Rotated tokens are written back to the
   * session file, shared with other MCP processes using the same profile; a
   * refresh the server refuses ends the session there (the profile is kept, so
   * signing in again needs no new pairing). Refreshed agent tokens stay bound
   * to this device.
   */
  private buildApi(session: Session): CpmeshApi {
    const api = new CpmeshApi(session.server_url);
    api.setTokens(session.access_token, session.refresh_token);
    const sameDevice = (s: Session | null): s is Session => s?.device_id === session.device_id;
    api.tokenStore = {
      load: () => {
        const s = loadSession();
        return sameDevice(s) && s.refresh_token ? { access: s.access_token, refresh: s.refresh_token } : null;
      },
      save: ({ access, refresh, scope }) => {
        const s = loadSession();
        if (sameDevice(s)) {
          saveSession({ ...s, access_token: access, refresh_token: refresh, ...(scope !== undefined && { scope }), signed_out: undefined });
        }
      },
      signedOut: (refresh, reason) => {
        const s = loadSession();
        if (sameDevice(s) && s.refresh_token === refresh) {
          saveSession({ ...s, access_token: "", refresh_token: "", signed_out: reason });
        }
      },
    };
    return api;
  }

  /** Refuses early what the user did not allow this agent (the server enforces it too). */
  private requireScope(scope: Scope): void {
    const session = loadSession();
    if (isSignedIn(session) && !grants(session.scope, scope)) throw new ScopeError(scope);
  }

  private async loadReady(): Promise<ReadyState> {
    const stored = loadSession();
    if (!isSignedIn(stored)) {
      this.ws.close();
      this.cached = null;
    } else if (this.cached && (stored.device_id !== this.cached.session.device_id ||
        stored.user_id !== this.cached.session.user_id || stored.server_url !== this.cached.session.server_url ||
        stored.grant_id !== this.cached.session.grant_id)) {
      // Another account, device or authorization (signed in again): start from the stored session
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
    if (!isSignedIn(session)) {
      this.ws.close();
      this.cached = null;
      return Promise.reject(new DeviceNotReadyError("cpmesh is not signed in", this.signInNextStep(session)));
    }
    const generation = this.sessionGeneration;
    const work = this.keyWork.then(() => withStateLock(async () => {
      const current = loadSession();
      if (this.closing || generation !== this.sessionGeneration || !sameDeviceSession(current, session)) {
        throw new Error("Session changed");
      }
      if (!isSignedIn(current)) throw new SessionExpiredError(signedOutMessage(current?.signed_out));
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
      // A session that ended meanwhile must not send its tokens again
      if (!isSignedIn(current)) throw new SessionExpiredError(signedOutMessage(current?.signed_out));
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
    this.requireScope("clipboard:write");
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
      // The relay refused the push: this agent was authorized without clipboard:write
      if (error instanceof WsError && error.code === "insufficient_scope") throw new ScopeError("clipboard:write");
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
        throw new SessionExpiredError(signedOutMessage(api.signedOutReason));
      }
      return await this.ws.pushClipboard(session.server_url, api.access ?? "", fingerprint, payload);
    }
  }

  async getClipboard(
    limit = 20,
    offset = 0,
  ): Promise<{ items: ClipboardItem[]; has_more: boolean }> {
    this.requireScope("clipboard:read");
    const state = await this.ensureReady();
    const resp = await this.withSession(state.session, () => state.api.getClipboardHistory(limit, offset));
    const items: ClipboardItem[] = [];
    for (const entry of resp.entries) items.push(await this.decryptEntry(state, entry));
    return { items, has_more: resp.has_more };
  }

  async getLatestClipboard(skipOwn = false): Promise<ClipboardItem | null> {
    this.requireScope("clipboard:read");
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
    this.requireScope("clipboard:delete");
    const { api, session } = await this.requireSession();
    await this.withSession(session, () => api.deleteClipboardEntry(id));
  }

  async removeDevice(deviceId: string, force = false): Promise<string> {
    const generation = this.sessionGeneration;
    const { session, api } = await this.requireSession();
    if (deviceId === session.device_id) {
      if (!force) {
        throw new Error(
          "Refusing to remove this MCP device's own registration (that would sign the agent out). " +
            "Pass force=true if you really mean it, or tell the user to use cpmesh_logout instead.",
        );
      }
      // Signing out revokes this agent's grant, which removes its device
      return this.logout();
    }
    this.requireScope("devices:manage");
    if (generation !== this.sessionGeneration) throw new Error("Session changed");
    await this.sequenceKeys(async () => {
      revokeDevice(deviceId);
      await api.deleteDevice(deviceId);
      const state = await this.loadReady();
      const due = await synchronizeKeys(state.api, state.keyring, state.keys, session.device_id);
      if (due) await rotateKeys(state.api, state.keyring, state.keys, session.device_id);
    });
    return `Device ${deviceId} removed.`;
  }

  async status(): Promise<Record<string, unknown>> {
    // Move a sign-in in progress forward without waiting (one poll when due), unless a call is waiting on it
    let progress: SignInProgress | AdvanceResult;
    let signInError: string | undefined;
    if (this.advancing) {
      progress = this.authorizer.peek();
    } else {
      try {
        progress = await this.advanceAuthorization(Date.now());
      } catch (error) {
        signInError = errorMessage(error);
        progress = this.authorizer.peek();
      }
    }
    const signIn = {
      ...(progress?.status === "authorization_pending" && { authorization: progress }),
      ...(isFailed(progress) && { authorization_result: progress.status }),
      ...(signInError !== undefined && { authorization_error: signInError }),
    };

    let session = loadSession();
    if (!isSignedIn(session)) return this.signedOutStatus(session, progress, signInError, signIn);
    const paths = statePaths();
    const keys = DeviceKeys.load(paths.deviceKey, paths.encryptionKey);
    const api = this.buildApi(session);

    let approval: ApprovalStatusResponse | string;
    try {
      approval = await this.withSession(session, () => api.getMyApprovalStatus());
    } catch (e) {
      session = loadSession();
      // The server ended the session meanwhile
      if (e instanceof SessionExpiredError || !isSignedIn(session)) return this.signedOutStatus(session, progress, signInError, signIn);
      approval = e instanceof ApiError || e instanceof TemporarilyUnavailableError ? `unavailable: ${e.message}` : "unavailable";
    }

    let pairing: PairingView | undefined;
    if (typeof approval === "string") {
      pairing = this.lastPairing();
    } else if (approval.status !== "approved") {
      const current = session;
      pairing = await this.updatePairing(keys, approval, (id, nonce) =>
        this.withSession(current, () => api.submitPendingNonce(id, nonce)));
    }

    const ring = existsSync(paths.keyring) ? Keyring.load(paths.keyring, keys.identity.privateKey) : new Keyring();
    const keyVersion = ring.currentVersion;
    const keyringOk = ring.hasGroupKey();

    return {
      logged_in: true,
      protocol_version: PAIRING_VERSION,
      server_url: session.server_url,
      user_id: session.user_id,
      grant_id: session.grant_id,
      scope: session.scope,
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
      ...signIn,
      next_step:
        typeof approval === "string"
          ? `The cpmesh server could not be reached (${approval.replace(/^unavailable: ?/, "") || "no answer"}); try again shortly.`
        : approval.status !== "approved"
          ? (pairing ? pairingNextStep(pairing) : APPROVAL_NOT_STARTED)
          : !keyringOk || loadMembership().version < keyVersion || loadMembership().rotation_required
            ? "Keys need authenticated synchronization. Complete any pending device removal; for an existing mesh, verify peers independently with cpmesh_verify_device, then retry."
            : "Ready — clipboard tools are usable.",
    };
  }

  private signedOutStatus(
    session: Session | null,
    progress: SignInProgress | AdvanceResult,
    signInError: string | undefined,
    signIn: Record<string, unknown>,
  ): Record<string, unknown> {
    this.ws.close();
    this.cached = null;
    const profile = session && {
      server_url: session.server_url,
      device_id: session.device_id,
      device_name: session.device_name,
      signed_out: session.grant_id ? session.signed_out ?? "signed out" : "signed in by cpmesh-mcp 0.2 with a password",
    };
    return {
      logged_in: false,
      ...(profile && { profile }),
      ...signIn,
      next_step:
        signInError !== undefined && progress?.status === "authorized"
          ? `${signInError} Then call cpmesh_wait_for_approval to finish signing in.`
          : signInRequired(session, progress),
    };
  }

  /**
   * Signs this agent out: revokes its authorization on the server (which also
   * removes its device; the user's other devices rotate the group key) and
   * wipes the local profile. 0.2 kept the server enrollment instead.
   */
  async logout(): Promise<string> {
    this.closing = true;
    this.sessionGeneration++;
    this.ws.close();
    this.authorizer.stop();
    await this.keyWork;
    try {
      const note = await withStateLock(async () => {
        this.cached = null;
        this.pairing.clear();
        this.pushes.clear();
        this.liveFeed = [];
        const session = loadSession();
        await this.authorizer.cancel({ locked: true });
        const revoked = await revokeSession(session);
        clearAllState();
        return revoked;
      });
      return `Signed out.${note ? ` ${note}` : ""} Local keys, keyring and session were wiped.`;
    } finally {
      this.closing = false;
    }
  }

  stop(): void {
    if (this.closing) return;
    this.closing = true;
    this.sessionGeneration++;
    this.ws.close();
    this.authorizer.stop();
    this.cached = null;
  }

}

/** Revokes a session's grant for cpmesh_logout and says what happened on the server. */
async function revokeSession(session: Session | null): Promise<string> {
  if (!session) return "";
  if (!session.grant_id) {
    return `The device that cpmesh-mcp 0.2 registered ("${session.device_name}") stays on the account: remove it in the device ` +
      "list on a trusted device or on the cpmesh dashboard.";
  }
  if (!session.refresh_token) {
    return "This agent was already signed out, so its authorization could not be revoked from here: if it is still listed " +
      "under Connected agents on the cpmesh dashboard, revoke it there (that also removes its device).";
  }
  try {
    await revokeWithRetry(session.server_url, session.refresh_token);
    return "This agent's authorization was revoked on the server, which also removed its device from the account " +
      "(the user's other devices rotate the group key).";
  } catch (error) {
    return `The server could not revoke this agent's authorization (${errorMessage(error)}): revoke it under Connected ` +
      "agents on the cpmesh dashboard, which also removes its device.";
  }
}

/** Keeps tokens rotated while the device registers with them in the saved approval. */
function approvedTokenStore(grantId: string): TokenStore {
  const current = () => {
    const stored = loadAuthorization();
    return stored?.stage === "authorized" && stored.grant_id === grantId ? stored : null;
  };
  return {
    load: () => {
      const stored = current();
      return stored ? { access: stored.access_token, refresh: stored.refresh_token } : null;
    },
    save: ({ access, refresh, scope }) => {
      const stored = current();
      if (stored) saveAuthorization({ ...stored, access_token: access, refresh_token: refresh, ...(scope !== undefined && { scope }) });
    },
    signedOut: (refresh) => {
      if (current()?.refresh_token === refresh) clearAuthorization();
    },
  };
}

/** What to tell the agent when the device could not register with an approved sign-in. */
function registrationError(error: unknown): unknown {
  if (error instanceof ApiError && error.code === "grant_device_mismatch") {
    clearAuthorization();
    return new Error(
      "This approval belongs to another cpmesh device (this agent's keys changed since). Call cpmesh_login to approve this device again.",
    );
  }
  if (error instanceof ApiError && error.status === 409) {
    return new Error(
      `The device could not register: ${error.message}. Once that is fixed, call cpmesh_wait_for_approval to finish signing in ` +
        "(the approval is kept).",
    );
  }
  if (error instanceof ApiError && error.status === 403 && /revoked or rejected/.test(error.message)) {
    return new Error(
      "This device's keys were rejected or revoked on the account. Call cpmesh_logout to start over with fresh keys, then cpmesh_login.",
    );
  }
  return error;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
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
