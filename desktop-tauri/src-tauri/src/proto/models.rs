use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// WebSocket message types — must match server constants.
pub const MSG_CLIPBOARD_PUSH: &str = "clipboard_push";
pub const MSG_CLIPBOARD_NEW: &str = "clipboard_new";
pub const MSG_DEVICE_STATUS: &str = "device_status";
pub const MSG_GROUP_KEY_UPDATED: &str = "group_key_updated";
pub const MSG_ERROR: &str = "error";
pub const MSG_PING: &str = "ping";
pub const MSG_PONG: &str = "pong";

/// Device approval status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "approved")]
    Approved,
    #[serde(rename = "rejected")]
    Rejected,
    #[serde(rename = "revoked")]
    Revoked,
}

impl std::fmt::Display for DeviceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceStatus::Pending => write!(f, "pending"),
            DeviceStatus::Approved => write!(f, "approved"),
            DeviceStatus::Rejected => write!(f, "rejected"),
            DeviceStatus::Revoked => write!(f, "revoked"),
        }
    }
}

impl DeviceStatus {
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "pending" => DeviceStatus::Pending,
            "approved" => DeviceStatus::Approved,
            "rejected" => DeviceStatus::Rejected,
            "revoked" => DeviceStatus::Revoked,
            _ => DeviceStatus::Pending,
        }
    }
}

fn default_device_status() -> DeviceStatus {
    DeviceStatus::Approved
}

fn default_key_version() -> i32 {
    1
}

/// Content type for clipboard entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContentType {
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "image")]
    Image,
    #[serde(rename = "file")]
    File,
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentType::Text => write!(f, "text"),
            ContentType::Image => write!(f, "image"),
            ContentType::File => write!(f, "file"),
        }
    }
}

/// Metadata for clipboard content (encrypted in transit).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<i32>,
}

// === WebSocket Messages ===

/// Envelope for all WebSocket messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct WsMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Client → Server: push a new clipboard entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClipboardPushPayload {
    pub content_type: ContentType,
    #[serde(with = "base64_serde")]
    pub encrypted_data: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(default = "default_key_version")]
    pub key_version: i32,
}

/// Server → Client: new clipboard entry broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardNewPayload {
    pub entry: ClipboardEntry,
}

/// Device online/offline status notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatusPayload {
    pub device_id: String,
    pub device_name: String,
    pub online: bool,
}

/// Error payload from server.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

// === API Request/Response Types ===

#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub password_confirm: String,
    pub email: String,
    pub full_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub device_name: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
    #[serde(with = "base64_serde")]
    pub public_key: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", with = "option_base64_serde")]
    pub public_key_sig: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "option_base64_serde")]
    pub public_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "option_base64_serde")]
    pub public_key_sig: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(default)]
    pub online: bool,
    #[serde(default = "default_device_status")]
    pub status: DeviceStatus,
}

#[derive(Debug, Deserialize)]
pub struct DeviceKeysResponse {
    pub devices: Vec<DeviceInfo>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceResponse {
    pub device: DeviceIdResponse,
    pub access_token: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceIdResponse {
    pub id: String,
    #[serde(default = "default_device_status")]
    pub status: DeviceStatus,
    #[serde(default)]
    #[allow(dead_code)]
    pub is_reregistration: bool,
}

/// Encrypted clipboard entry as stored on server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEntry {
    pub id: String,
    pub user_id: String,
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
    pub content_type: ContentType,
    #[serde(with = "base64_serde")]
    pub encrypted_data: Vec<u8>,
    #[serde(default)]
    pub metadata: String,
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_key_version")]
    pub key_version: i32,
}

/// Decrypted clipboard entry used locally on clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlainEntry {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub content_type: ContentType,
    #[serde(with = "base64_serde")]
    pub data: Vec<u8>,
    pub metadata: Metadata,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ClipboardHistoryResponse {
    pub entries: Vec<ClipboardEntry>,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct GroupKeyResponse {
    #[serde(with = "base64_serde")]
    pub encrypted_key: Vec<u8>,
    pub from_device_id: String,
    #[serde(with = "base64_serde")]
    pub from_public_key: Vec<u8>,
    #[serde(default, with = "option_base64_serde")]
    pub from_public_key_sig: Option<Vec<u8>>,
    #[serde(default = "default_key_version")]
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)]
    pub rotation_due_at: Option<DateTime<Utc>>,
}

/// A single versioned group key entry.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct VersionedGroupKey {
    pub version: i32,
    #[serde(with = "base64_serde")]
    pub encrypted_key: Vec<u8>,
    pub from_device_id: String,
    #[serde(with = "base64_serde")]
    pub from_public_key: Vec<u8>,
    #[serde(default, with = "option_base64_serde")]
    pub from_public_key_sig: Option<Vec<u8>>,
}

/// Response for GET /api/group-keys/current.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct GroupKeysResponse {
    pub current_version: i32,
    pub keys: Vec<VersionedGroupKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_due_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct StoreGroupKeyEntry {
    pub device_id: String,
    #[serde(with = "base64_serde")]
    pub encrypted_key: Vec<u8>,
}

/// Request body for POST /api/group-keys/rotate.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct RotateGroupKeyRequest {
    pub expected_current_version: i32,
    pub new_version: i32,
    pub wrapped_keys: Vec<StoreGroupKeyEntry>,
}

// === Device Approval Types ===

/// Pending device info returned by GET /api/device-approvals/pending.
#[derive(Debug, Deserialize)]
pub struct PendingDeviceInfo {
    pub id: String,
    pub name: String,
    #[serde(with = "base64_serde")]
    pub public_key: Vec<u8>,
    #[serde(default, with = "option_base64_serde")]
    #[allow(dead_code)]
    pub public_key_sig: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Response for POST /api/device-approvals/{id}/begin.
#[derive(Debug, Deserialize)]
pub struct ApprovalSessionResponse {
    pub session_id: String,
    #[allow(dead_code)]
    pub pending_device_id: String,
    #[serde(with = "base64_serde")]
    pub pending_public_key: Vec<u8>,
    #[serde(default, with = "option_base64_serde")]
    #[allow(dead_code)]
    pub pending_public_key_sig: Option<Vec<u8>>,
    pub expires_at: DateTime<Utc>,
}

/// Request body for POST /api/device-approvals/{id}/approve.
#[derive(Debug, Serialize)]
pub struct ApproveDeviceRequest {
    pub session_id: String,
    pub expected_current_version: i32,
    pub new_version: i32,
    pub wrapped_keys: Vec<StoreGroupKeyEntry>,
}

/// Response for GET /api/device-approvals/me.
#[derive(Debug, Deserialize)]
pub struct ApprovalStatusResponse {
    pub status: DeviceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)]
    pub approver_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "option_base64_serde")]
    pub approver_public_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "option_base64_serde")]
    #[allow(dead_code)]
    pub approver_public_key_sig: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResponse {
    pub update_available: bool,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub download_url: Option<String>,
    #[serde(default)]
    pub release_notes: Option<String>,
}

/// Serde helper for base64-encoding Vec<u8> in JSON.
pub mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Serde helper for base64-encoding Option<Vec<u8>> in JSON.
pub mod option_base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match data {
            Some(bytes) => s.serialize_str(&STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => STANDARD.decode(&s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
