/**
 * Wire types shared with the cpmesh server and desktop client.
 *
 * Mirrors crates/cpmesh-proto/src/models.rs. Field names and JSON shapes
 * must stay byte-compatible: Vec<u8> fields travel as base64 strings and
 * enums as their serde-renamed lowercase strings.
 */
import { z } from "zod";

/** WebSocket protocol: `X-Cpmesh-Protocol` in both directions; old peers get HTTP 426. */
export const PROTOCOL_VERSION = "3";
/** Pairing protocol: committed short authentication string (see crypto `sas*`). */
export const PAIRING_VERSION = 3;
/** Length of a v3 group-key wrap: ephemeral key(65) || nonce(12) || key(32) || tag(16). */
export const WRAP_V3_LEN = 65 + 12 + 32 + 16;
/** Length of a legacy static-static wrap: nonce(12) || key(32) || tag(16). */
export const WRAP_LEGACY_LEN = 12 + 32 + 16;

// === WebSocket message types ===

export const MSG_CLIPBOARD_PUSH = "clipboard_push";
export const MSG_CLIPBOARD_NEW = "clipboard_new";
export const MSG_CLIPBOARD_ACK = "clipboard_ack";
export const MSG_DEVICE_STATUS = "device_status";
export const MSG_GROUP_KEY_UPDATED = "group_key_updated";
export const MSG_ROTATION_NEEDED = "rotation_needed";
export const MSG_ERROR = "error";
export const MSG_PING = "ping";
export const MSG_PONG = "pong";

export type DeviceStatus = "pending" | "approved" | "rejected" | "revoked";
export type ContentType = "text" | "image" | "file";

export interface WsMessage {
  type: string;
  payload?: unknown;
}

/** Client → Server: push a new clipboard entry. */
export interface ClipboardPushPayload {
  request_id?: string;
  content_type: ContentType;
  encrypted_data: string; // base64
  metadata?: string; // base64 of encrypted metadata JSON
  key_version: number;
  /** Sender clock, Unix milliseconds. Bound into the AAD and the signature. */
  sent_at?: number;
  /** base64 DER ECDSA by the sender identity key over the clipboard signature transcript. */
  sender_signature?: string;
}

/** Server → Client: new clipboard entry broadcast. */
export interface ClipboardNewPayload {
  entry: ClipboardEntry;
}

export interface ErrorPayload {
  code: string;
  message: string;
}

// === API types ===

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user_id?: string;
}

/**
 * The 403 `mfa_required` answer to a correct password: a sign-in ticket for the
 * /api/mfa endpoints (valid 10 minutes, single use).
 */
export interface MfaChallenge {
  mfa_token: string;
  /** "enroll": the account has no second factor yet and must set one up first. */
  stage: "verify" | "enroll";
  /** verify: the methods the account has ("totp", "webauthn", "recovery"). */
  methods: string[];
}

export interface MfaVerifyResponse {
  access_token: string;
  refresh_token: string;
  /** Present when a recovery code was used. */
  recovery_codes_remaining?: number;
}

export interface RegisterDeviceRequest {
  name: string;
  public_key: string; // base64 SEC1 uncompressed
  public_key_sig?: string; // base64 DER ECDSA signature
  /** Static ECDH key, certified by the identity key (encryption key transcript). */
  encryption_key?: string; // base64 SEC1 uncompressed
  encryption_key_sig?: string; // base64 DER ECDSA signature
  fingerprint?: string;
  proof?: { challenge: string; signature: string };
}

/** Request body for PUT /api/devices/me/encryption-key. */
export interface PublishEncryptionKeyRequest {
  encryption_key: string; // base64
  encryption_key_sig: string; // base64
}

export interface DeviceInfo {
  id: string;
  name: string;
  public_key?: string; // base64
  public_key_sig?: string; // base64
  encryption_key?: string; // base64
  encryption_key_sig?: string; // base64
  last_seen?: string;
  online: boolean;
  status: DeviceStatus;
}

export interface RegisterDeviceResponse {
  device: { id: string; status: DeviceStatus; is_reregistration: boolean };
  access_token: string;
  refresh_token: string;
}

/** Encrypted clipboard entry as stored on the server. */
export interface ClipboardEntry {
  id: string;
  user_id: string;
  device_id: string;
  device_name: string;
  content_type: ContentType;
  encrypted_data: string; // base64
  metadata: string; // base64 of encrypted metadata JSON, may be empty
  created_at: string; // RFC3339
  key_version: number;
  /** Sender-chosen request ID; part of the signed context. Absent on legacy entries. */
  request_id?: string;
  sent_at?: number;
  sender_signature?: string; // base64
}

export interface ClipboardHistoryResponse {
  entries: ClipboardEntry[];
  has_more: boolean;
}

/** Decrypted clipboard metadata (itself encrypted in transit). */
export interface Metadata {
  filename?: string;
  mime_type?: string;
  size: number;
  width?: number;
  height?: number;
}

/** Decrypted clipboard entry. */
export interface PlainEntry {
  id: string;
  device_id: string;
  device_name: string;
  content_type: ContentType;
  data: Uint8Array;
  metadata: Metadata;
  created_at: string;
  /** False for legacy (pre-v3) entries whose sender could not be authenticated. */
  authenticated: boolean;
}

// === Group keys ===

export interface GroupKeyResponse {
  encrypted_key: string; // base64
  from_device_id: string;
  from_public_key: string; // base64
  from_public_key_sig?: string; // base64
  version: number;
  rotation_due_at?: string;
  membership?: KeyMembership | null;
}

export interface VersionedGroupKey {
  version: number;
  encrypted_key: string; // base64
  from_device_id: string;
  from_public_key: string; // base64
  from_public_key_sig?: string | null; // base64
  membership?: KeyMembership | null;
}

export interface GroupKeysResponse {
  current_version: number;
  keys: VersionedGroupKey[];
  rotation_due_at?: string;
  rotation_required?: boolean;
}

export interface StoreGroupKeyEntry {
  device_id: string;
  encrypted_key: string; // base64
  membership?: KeyMembership;
}

export interface DeviceIdentity { id: string; public_key: string }
export interface KeyMembership { members: DeviceIdentity[]; wrapped_key_hashes: Record<string, string>; signature: string }

// === Device approval ===

export interface PendingDeviceInfo {
  id: string;
  name: string;
  public_key: string; // base64
  public_key_sig?: string; // base64
  encryption_key?: string; // base64
  encryption_key_sig?: string; // base64
  created_at: string;
}

/** Request body for POST /api/device-approvals/{id}/begin. */
export interface BeginApprovalRequest {
  /** SAS commitment of the approver's nonce (base64). */
  commit: string;
}

/** Response for GET /api/device-approvals/{id}/session (approver polls for the pending nonce). */
export interface ApprovalSessionState {
  session_id: string;
  pending_nonce?: string; // base64
  approver_nonce?: string; // base64
  expires_at: string;
}

/** Request body for POST /api/device-approvals/me/nonce and /{id}/reveal. */
export interface SasNonceRequest {
  session_id: string;
  nonce: string; // base64, 32 bytes
}

export interface ApprovalStatusResponse {
  pairing_version?: number;
  status: DeviceStatus;
  approver_device_id?: string;
  approver_public_key?: string; // base64
  approver_public_key_sig?: string; // base64
  session_id?: string;
  /** SAS commitment of the approver's nonce (base64, 32 bytes). */
  approver_commit?: string;
  pending_nonce?: string; // base64
  approver_nonce?: string; // base64
}

export interface UserInfo {
  id: string;
  username: string;
  email?: string;
  full_name?: string;
}

const base64 = z.string().max(4096).regex(/^[A-Za-z0-9+/]*={0,2}$/).refine((value) => value.length % 4 === 0);
const identitySchema = z.object({ id: z.string().uuid().refine((id) => id === id.toLowerCase()), public_key: base64 });
const membershipSchema = z.object({
  members: z.array(identitySchema).min(1), signature: base64,
  wrapped_key_hashes: z.record(z.string().regex(/^[0-9a-f]{64}$/)),
});
export const groupKeysSchema = z.object({
  current_version: z.number().int().positive(),
  rotation_required: z.boolean().optional(),
  rotation_due_at: z.string().optional(),
  keys: z.array(z.object({
    version: z.number().int().positive(), encrypted_key: base64,
    from_device_id: z.string().uuid(), from_public_key: base64,
    from_public_key_sig: base64.nullish(), membership: membershipSchema.nullish(),
  })).max(100),
});
const canonicalUuid = z.string().uuid().refine((id) => id === id.toLowerCase());
/** Relay-delivered entry (history or `clipboard_new` broadcast). */
export const clipboardEntrySchema = z.object({
  id: z.string(), user_id: z.string().default(""), device_id: canonicalUuid, device_name: z.string().default(""),
  content_type: z.enum(["text", "image", "file"]), encrypted_data: z.string().max(48 * 1024 * 1024),
  metadata: z.string().max(65536).default(""), created_at: z.string(), key_version: z.number().int().positive(),
  request_id: canonicalUuid.optional(), sent_at: z.number().int().positive().optional(),
  sender_signature: base64.optional(),
});
export const clipboardNewSchema = z.object({ entry: clipboardEntrySchema });
export const clipboardReceiptSchema = z.object({
    status: z.literal("accepted"), request_id: z.string().uuid(), entry_id: z.string().uuid(),
    created_at: z.string().datetime({ offset: true }),
  });
export const clipboardAckSchema = z.discriminatedUnion("status", [
  clipboardReceiptSchema,
  z.object({
    status: z.literal("rejected"), request_id: z.string(), code: z.string(), message: z.string(),
  }),
]);
export type ClipboardAck = z.infer<typeof clipboardAckSchema>;
export type ClipboardReceipt = Extract<ClipboardAck, { status: "accepted" }>;
