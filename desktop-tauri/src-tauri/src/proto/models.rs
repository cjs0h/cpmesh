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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn message_type_constants_match_server_protocol() {
        assert_eq!(MSG_CLIPBOARD_PUSH, "clipboard_push");
        assert_eq!(MSG_CLIPBOARD_NEW, "clipboard_new");
        assert_eq!(MSG_DEVICE_STATUS, "device_status");
        assert_eq!(MSG_GROUP_KEY_UPDATED, "group_key_updated");
        assert_eq!(MSG_ERROR, "error");
        assert_eq!(MSG_PING, "ping");
        assert_eq!(MSG_PONG, "pong");
    }

    #[test]
    fn device_status_serde_display_and_parse_agree() {
        for (status, text) in [
            (DeviceStatus::Pending, "pending"),
            (DeviceStatus::Approved, "approved"),
            (DeviceStatus::Rejected, "rejected"),
            (DeviceStatus::Revoked, "revoked"),
        ] {
            assert_eq!(status.to_string(), text);
            assert_eq!(
                serde_json::to_string(&status).unwrap(),
                format!("\"{text}\"")
            );
            assert_eq!(
                serde_json::from_str::<DeviceStatus>(&format!("\"{text}\"")).unwrap(),
                status
            );
            assert_eq!(DeviceStatus::from_str(text), status);
        }
        // Unknown strings are treated as the safest state
        assert_eq!(DeviceStatus::from_str("bogus"), DeviceStatus::Pending);
        assert!(serde_json::from_str::<DeviceStatus>("\"bogus\"").is_err());
    }

    #[test]
    fn content_type_serde_and_display() {
        for (ct, text) in [
            (ContentType::Text, "text"),
            (ContentType::Image, "image"),
            (ContentType::File, "file"),
        ] {
            assert_eq!(ct.to_string(), text);
            assert_eq!(serde_json::to_string(&ct).unwrap(), format!("\"{text}\""));
            assert_eq!(
                serde_json::from_str::<ContentType>(&format!("\"{text}\"")).unwrap(),
                ct
            );
        }
    }

    #[test]
    fn ws_message_uses_type_field_and_defaults_payload() {
        let msg: WsMessage = serde_json::from_str(r#"{"type":"ping"}"#).unwrap();
        assert_eq!(msg.msg_type, "ping");
        assert!(msg.payload.is_null());

        let out = serde_json::to_value(WsMessage {
            msg_type: MSG_PONG.into(),
            payload: serde_json::json!({"ok": true}),
        })
        .unwrap();
        assert_eq!(out["type"], "pong");
        assert_eq!(out["payload"]["ok"], true);
    }

    #[test]
    fn clipboard_push_payload_base64_and_key_version_default() {
        let payload = ClipboardPushPayload {
            content_type: ContentType::Text,
            encrypted_data: vec![0xde, 0xad, 0xbe, 0xef],
            metadata: None,
            key_version: 4,
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["encrypted_data"], "3q2+7w==");
        assert!(json.get("metadata").is_none(), "None metadata is omitted");
        assert_eq!(json["key_version"], 4);

        // Legacy servers omit key_version → defaults to 1
        let parsed: ClipboardPushPayload =
            serde_json::from_str(r#"{"content_type":"file","encrypted_data":"AQID"}"#).unwrap();
        assert_eq!(parsed.content_type, ContentType::File);
        assert_eq!(parsed.encrypted_data, vec![1, 2, 3]);
        assert_eq!(parsed.key_version, 1);
        assert!(parsed.metadata.is_none());
    }

    #[test]
    fn invalid_base64_is_a_deserialize_error() {
        assert!(
            serde_json::from_str::<ClipboardPushPayload>(
                r#"{"content_type":"text","encrypted_data":"!!not base64!!"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn clipboard_entry_roundtrip_with_timestamp() {
        let created = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let entry = ClipboardEntry {
            id: "e".into(),
            user_id: "u".into(),
            device_id: "d".into(),
            device_name: "n".into(),
            content_type: ContentType::Image,
            encrypted_data: vec![1, 2],
            metadata: "m".into(),
            created_at: created,
            key_version: 2,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ClipboardEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "e");
        assert_eq!(back.encrypted_data, vec![1, 2]);
        assert_eq!(back.created_at, created);
        assert_eq!(back.key_version, 2);

        // device_name / metadata / key_version are optional on the wire
        let minimal: ClipboardEntry = serde_json::from_str(
            r#"{"id":"e","user_id":"u","device_id":"d","content_type":"text",
                "encrypted_data":"","created_at":"2026-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(minimal.device_name, "");
        assert_eq!(minimal.metadata, "");
        assert_eq!(minimal.key_version, 1);
        assert!(minimal.encrypted_data.is_empty());
    }

    #[test]
    fn device_info_optional_base64_fields() {
        let info: DeviceInfo =
            serde_json::from_str(r#"{"id":"d","name":"Laptop","online":true}"#).unwrap();
        assert!(info.public_key.is_none());
        assert!(info.public_key_sig.is_none());
        assert_eq!(
            info.status,
            DeviceStatus::Approved,
            "status defaults to approved"
        );

        let info: DeviceInfo = serde_json::from_str(
            r#"{"id":"d","name":"Laptop","public_key":"BAEC","public_key_sig":null,"status":"pending"}"#,
        )
        .unwrap();
        assert_eq!(info.public_key, Some(vec![4, 1, 2]));
        assert!(info.public_key_sig.is_none());
        assert!(!info.online, "online defaults to false");
        assert_eq!(info.status, DeviceStatus::Pending);

        // Serialization omits None fields and encodes Some as base64
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["public_key"], "BAEC");
        assert!(json.get("public_key_sig").is_none());
        assert!(json.get("last_seen").is_none());
    }

    #[test]
    fn register_device_request_serializes_optional_fields() {
        let req = RegisterDeviceRequest {
            name: "Laptop".into(),
            public_key: vec![4, 0],
            public_key_sig: Some(vec![0x30]),
            fingerprint: Some("abc".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["public_key"], "BAA=");
        assert_eq!(json["public_key_sig"], "MA==");
        assert_eq!(json["fingerprint"], "abc");

        let req = RegisterDeviceRequest {
            name: "Laptop".into(),
            public_key: vec![],
            public_key_sig: None,
            fingerprint: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("public_key_sig").is_none());
        assert!(json.get("fingerprint").is_none());
    }

    #[test]
    fn register_device_response_defaults() {
        let resp: RegisterDeviceResponse =
            serde_json::from_str(r#"{"device":{"id":"d"},"access_token":"t"}"#).unwrap();
        assert_eq!(resp.device.id, "d");
        assert_eq!(resp.device.status, DeviceStatus::Approved);
        assert!(!resp.device.is_reregistration);
        assert_eq!(resp.access_token, "t");
    }

    #[test]
    fn update_check_response_tolerates_missing_fields() {
        let resp: UpdateCheckResponse =
            serde_json::from_str(r#"{"update_available":false}"#).unwrap();
        assert!(!resp.update_available);
        assert!(resp.version.is_none());
        assert!(resp.download_url.is_none());
        assert!(resp.release_notes.is_none());
    }

    #[test]
    fn metadata_defaults_and_omits_none() {
        let meta: Metadata = serde_json::from_str("{}").unwrap();
        assert_eq!(meta.size, 0);
        assert!(meta.filename.is_none());
        let json = serde_json::to_value(Metadata::default()).unwrap();
        assert_eq!(json, serde_json::json!({"size": 0}));
    }
}
