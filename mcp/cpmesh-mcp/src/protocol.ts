/**
 * Wire types shared with the cpmesh server and desktop client.
 *
 * Mirrors crates/cpmesh-proto/src/models.rs (and the duplicated copy in
 * desktop-tauri/src-tauri/src/proto/models.rs). Field names and JSON shapes
 * must stay byte-compatible: Vec<u8> fields travel as base64 strings and
 * enums as their serde-renamed lowercase strings.
 */

// === WebSocket message types ===

export const MSG_CLIPBOARD_PUSH = "clipboard_push";
export const MSG_CLIPBOARD_NEW = "clipboard_new";
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

export interface RegisterDeviceRequest {
  name: string;
  public_key: string; // base64 SEC1 uncompressed
  public_key_sig?: string; // base64 DER ECDSA signature
  fingerprint?: string;
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
}

export interface VersionedGroupKey {
  version: number;
  encrypted_key: string; // base64
  from_device_id: string;
  from_public_key: string; // base64
  from_public_key_sig?: string; // base64
}

export interface GroupKeysResponse {
  current_version: number;
  keys: VersionedGroupKey[];
  rotation_due_at?: string;
}

export interface StoreGroupKeyEntry {
  device_id: string;
  encrypted_key: string; // base64
}

// === Device approval ===

export interface PendingDeviceInfo {
  id: string;
  name: string;
  public_key: string; // base64
  public_key_sig?: string; // base64
  created_at: string;
}

export interface ApprovalStatusResponse {
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
