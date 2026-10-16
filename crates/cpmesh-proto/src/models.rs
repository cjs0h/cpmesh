use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// WebSocket message types — must match between server and clients.
pub const PROTOCOL_VERSION: &str = "2";
pub const MSG_CLIPBOARD_PUSH: &str = "clipboard_push";
pub const MSG_CLIPBOARD_NEW: &str = "clipboard_new";
pub const MSG_CLIPBOARD_ACK: &str = "clipboard_ack";
pub const MSG_DEVICE_STATUS: &str = "device_status";
pub const MSG_GROUP_KEY_UPDATED: &str = "group_key_updated";
pub const MSG_ROTATION_NEEDED: &str = "rotation_needed";
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

impl std::str::FromStr for DeviceStatus {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "pending" => DeviceStatus::Pending,
            "approved" => DeviceStatus::Approved,
            "rejected" => DeviceStatus::Rejected,
            "revoked" => DeviceStatus::Revoked,
            _ => DeviceStatus::Pending,
        })
    }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardPushPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub content_type: ContentType,
    #[serde(with = "base64_serde")]
    pub encrypted_data: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(default = "default_key_version")]
    pub key_version: i32,
}

/// An acknowledgement means database persistence, not receipt by another device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ClipboardAck {
    Accepted {
        request_id: String,
        entry_id: String,
        created_at: DateTime<Utc>,
    },
    Rejected {
        request_id: String,
        code: String,
        message: String,
    },
}

impl ClipboardAck {
    pub fn request_id(&self) -> &str {
        match self {
            Self::Accepted { request_id, .. } | Self::Rejected { request_id, .. } => request_id,
        }
    }
}

pub const ENCRYPTION_OVERHEAD: usize = 16 + 12 + 16;
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_FILE_BYTES: usize = 25 * 1024 * 1024;

pub fn content_size_limit(content_type: &ContentType) -> usize {
    match content_type {
        ContentType::Text => 1024 * 1024,
        ContentType::Image => 10 * 1024 * 1024,
        ContentType::File => MAX_FILE_BYTES,
    }
}

fn default_key_version() -> i32 {
    1
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

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub password_confirm: String,
    pub email: String,
    pub full_name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mobile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub device_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
    #[serde(with = "base64_serde")]
    pub public_key: Vec<u8>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "option_base64_serde"
    )]
    pub public_key_sig: Option<Vec<u8>>,
    /// Stable device fingerprint: SHA-256 hex of platform hardware ID salted with user_id.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DeviceSessionProof>,
}

/// Single-use, session-bound proof of possession of the device's private key.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceSessionProof {
    pub challenge: String,
    #[serde(with = "base64_serde")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceChallengeResponse {
    pub challenge: String,
}

/// Domain separation prevents an untrusted relay from turning registration into
/// an oracle for signatures over mesh membership transitions.
pub fn device_proof_transcript(challenge: &str) -> Vec<u8> {
    format!("cpmesh-device-proof-v1\n{challenge}").into_bytes()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_base64_serde"
    )]
    pub public_key: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_base64_serde"
    )]
    pub public_key_sig: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(default)]
    pub online: bool,
    #[serde(default = "default_device_status")]
    pub status: DeviceStatus,
}

fn default_device_status() -> DeviceStatus {
    DeviceStatus::Approved
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceKeysResponse {
    pub devices: Vec<DeviceInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterDeviceResponse {
    pub device: DeviceIdResponse,
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceIdResponse {
    pub id: String,
    #[serde(default = "default_device_status")]
    pub status: DeviceStatus,
    /// True when the device was re-registered (same fingerprint, new keys).
    #[serde(default)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ClipboardHistoryResponse {
    pub entries: Vec<ClipboardEntry>,
    pub has_more: bool,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupKeyResponse {
    #[serde(with = "base64_serde")]
    pub encrypted_key: Vec<u8>,
    pub from_device_id: String,
    #[serde(with = "base64_serde")]
    pub from_public_key: Vec<u8>,
    #[serde(default, with = "option_base64_serde")]
    pub from_public_key_sig: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<KeyMembership>,
    #[serde(default = "default_key_version")]
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_due_at: Option<DateTime<Utc>>,
}

/// A single versioned group key entry for a device (used in multi-version responses).
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<KeyMembership>,
}

/// Response for GET /api/group-keys/current with optional since_version.
#[derive(Debug, Serialize, Deserialize)]
pub struct GroupKeysResponse {
    pub current_version: i32,
    pub keys: Vec<VersionedGroupKey>,
    #[serde(default)]
    pub rotation_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_due_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreGroupKeyEntry {
    pub device_id: String,
    #[serde(with = "base64_serde")]
    pub encrypted_key: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<KeyMembership>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub id: String,
    #[serde(with = "base64_serde")]
    pub public_key: Vec<u8>,
}

/// One signed manifest binds every member and recipient-specific wrap. It is sent
/// once per rotation, avoiding quadratic request size as subscription limits grow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMembership {
    pub members: Vec<DeviceIdentity>,
    pub wrapped_key_hashes: std::collections::BTreeMap<String, String>,
    #[serde(with = "base64_serde")]
    pub signature: Vec<u8>,
}

pub fn membership_transcript(
    version: i32,
    sender: &str,
    members: &[DeviceIdentity],
    hashes: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<u8>, &'static str> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    if version < 1
        || !canonical_device_id(sender)
        || members
            .iter()
            .any(|member| !canonical_device_id(&member.id))
        || hashes.len() != members.len()
        || hashes.values().any(|hash| {
            hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err("invalid wrapped-key commitments");
    }
    let mut transcript = format!("cpmesh-membership-v2\n{version}\n{sender}\n");
    let mut members: Vec<_> = members.iter().collect();
    members.sort_by(|a, b| a.id.cmp(&b.id));
    for member in members {
        transcript.push_str(&format!(
            "{}:{}:{}\n",
            member.id,
            STANDARD.encode(&member.public_key),
            hashes
                .get(&member.id)
                .ok_or("missing wrapped-key commitment")?,
        ));
    }
    Ok(transcript.into_bytes())
}

pub fn wrapped_key_hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn canonical_device_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

/// Request body for POST /api/group-keys/rotate and approval approve endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct RotateGroupKeyRequest {
    pub expected_current_version: i32,
    pub new_version: i32,
    pub wrapped_keys: Vec<StoreGroupKeyEntry>,
}

// === Device Approval Types ===

/// Response for GET /api/device-approvals/pending.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingDeviceInfo {
    pub id: String,
    pub name: String,
    #[serde(with = "base64_serde")]
    pub public_key: Vec<u8>,
    #[serde(default, with = "option_base64_serde")]
    pub public_key_sig: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Response for POST /api/device-approvals/{id}/begin.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalSessionResponse {
    #[serde(default)]
    pub pairing_version: u32,
    pub session_id: String,
    pub pending_device_id: String,
    #[serde(with = "base64_serde")]
    pub pending_public_key: Vec<u8>,
    #[serde(default, with = "option_base64_serde")]
    pub pending_public_key_sig: Option<Vec<u8>>,
    pub expires_at: DateTime<Utc>,
}

/// Request body for POST /api/device-approvals/{id}/approve.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApproveDeviceRequest {
    pub session_id: String,
    pub expected_current_version: i32,
    pub new_version: i32,
    pub wrapped_keys: Vec<StoreGroupKeyEntry>,
}

/// Response for GET /api/device-approvals/me (pending device checks its status).
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalStatusResponse {
    #[serde(default)]
    pub pairing_version: u32,
    pub status: DeviceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_device_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_base64_serde"
    )]
    pub approver_public_key: Option<Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_base64_serde"
    )]
    pub approver_public_key_sig: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Serde helper for base64-encoding Vec<u8> in JSON.
pub mod base64_serde {
    use base64::{Engine, engine::general_purpose::STANDARD};
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
    use base64::{Engine, engine::general_purpose::STANDARD};
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
            Some(s) => STANDARD
                .decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
