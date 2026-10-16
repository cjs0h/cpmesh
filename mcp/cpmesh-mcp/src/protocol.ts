/**
 * Wire types shared with the cpmesh server and desktop client.
 *
 * Mirrors crates/cpmesh-proto/src/models.rs. Field names and JSON shapes
 * must stay byte-compatible: Vec<u8> fields travel as base64 strings and
 * enums as their serde-renamed lowercase strings.
 */
import { z } from "zod";

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
  fingerprint?: string;
  proof?: { challenge: string; signature: string };
}

export interface DeviceInfo {
  id: string;
  name: string;
  public_key?: string; // base64
  public_key_sig?: string; // base64
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
  created_at: string;
}

export interface ApprovalStatusResponse {
  pairing_version?: number;
  status: DeviceStatus;
  approver_device_id?: string;
  approver_public_key?: string; // base64
  approver_public_key_sig?: string; // base64
  session_id?: string;
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
