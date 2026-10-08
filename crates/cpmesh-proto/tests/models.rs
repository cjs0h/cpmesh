//! Wire-format tests for the shared protocol types.
//!
//! These guard the JSON shapes that the server, the desktop app and the web
//! dashboard all depend on: field names, base64 encoding of binary fields,
//! defaults for optional fields and the string representation of enums.

use chrono::{TimeZone, Utc};
use cpmesh_proto::models::*;
use serde_json::json;

#[test]
fn message_type_constants_are_stable() {
    assert_eq!(MSG_CLIPBOARD_PUSH, "clipboard_push");
    assert_eq!(MSG_CLIPBOARD_NEW, "clipboard_new");
    assert_eq!(MSG_DEVICE_STATUS, "device_status");
    assert_eq!(MSG_GROUP_KEY_UPDATED, "group_key_updated");
    assert_eq!(MSG_ROTATION_NEEDED, "rotation_needed");
    assert_eq!(MSG_ERROR, "error");
    assert_eq!(MSG_PING, "ping");
    assert_eq!(MSG_PONG, "pong");
}

#[test]
fn device_status_display_serde_and_from_str_agree() {
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
        assert_eq!(text.parse::<DeviceStatus>().unwrap(), status);
    }
    // Unknown strings parse to the most restrictive state
    assert_eq!(
        "bogus".parse::<DeviceStatus>().unwrap(),
        DeviceStatus::Pending
    );
    assert!(serde_json::from_str::<DeviceStatus>("\"bogus\"").is_err());
}

#[test]
fn content_type_display_and_serde() {
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
    assert!(serde_json::from_str::<ContentType>("\"video\"").is_err());
}

#[test]
fn metadata_omits_none_and_defaults_size() {
    let json = serde_json::to_value(Metadata::default()).unwrap();
    assert_eq!(json, json!({ "size": 0 }));

    let meta: Metadata = serde_json::from_str("{}").unwrap();
    assert_eq!(meta.size, 0);
    assert!(meta.filename.is_none() && meta.mime_type.is_none());
    assert!(meta.width.is_none() && meta.height.is_none());

    let full = Metadata {
        filename: Some("a.png".into()),
        mime_type: Some("image/png".into()),
        size: 12,
        width: Some(3),
        height: Some(4),
    };
    let json = serde_json::to_value(&full).unwrap();
    assert_eq!(
        json,
        json!({"filename":"a.png","mime_type":"image/png","size":12,"width":3,"height":4})
    );
}

#[test]
fn ws_message_envelope_uses_type_key_and_default_payload() {
    let msg: WsMessage = serde_json::from_str(r#"{"type":"ping"}"#).unwrap();
    assert_eq!(msg.msg_type, MSG_PING);
    assert!(msg.payload.is_null());

    let out = serde_json::to_value(WsMessage {
        msg_type: MSG_DEVICE_STATUS.into(),
        payload: json!(DeviceStatusPayload {
            device_id: "d1".into(),
            device_name: "Laptop".into(),
            online: true,
        }),
    })
    .unwrap();
    assert_eq!(
        out,
        json!({"type":"device_status","payload":{"device_id":"d1","device_name":"Laptop","online":true}})
    );
}

#[test]
fn clipboard_push_payload_wire_format() {
    let payload = ClipboardPushPayload {
        content_type: ContentType::Text,
        encrypted_data: vec![0xde, 0xad, 0xbe, 0xef],
        metadata: Some("bWV0YQ==".into()),
        key_version: 3,
    };
    let json = serde_json::to_value(&payload).unwrap();
    assert_eq!(
        json,
        json!({"content_type":"text","encrypted_data":"3q2+7w==","metadata":"bWV0YQ==","key_version":3})
    );

    // Older clients omit key_version and metadata
    let legacy: ClipboardPushPayload =
        serde_json::from_str(r#"{"content_type":"image","encrypted_data":"AQID"}"#).unwrap();
    assert_eq!(legacy.content_type, ContentType::Image);
    assert_eq!(legacy.encrypted_data, vec![1, 2, 3]);
    assert_eq!(legacy.key_version, 1);
    assert!(legacy.metadata.is_none());

    // metadata: None is omitted entirely
    let json = serde_json::to_value(ClipboardPushPayload {
        content_type: ContentType::File,
        encrypted_data: vec![],
        metadata: None,
        key_version: 1,
    })
    .unwrap();
    assert!(json.get("metadata").is_none());
    assert_eq!(json["encrypted_data"], "");
}

#[test]
fn invalid_base64_fails_deserialization() {
    let err = serde_json::from_str::<ClipboardPushPayload>(
        r#"{"content_type":"text","encrypted_data":"%%%"}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("Invalid"), "{err}");

    assert!(
        serde_json::from_str::<DeviceInfo>(r#"{"id":"d","name":"n","public_key":"***"}"#).is_err()
    );
}

#[test]
fn clipboard_entry_roundtrip_and_defaults() {
    let created = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let entry = ClipboardEntry {
        id: "e".into(),
        user_id: "u".into(),
        device_id: "d".into(),
        device_name: "n".into(),
        content_type: ContentType::Text,
        encrypted_data: vec![1, 2, 3],
        metadata: "m".into(),
        created_at: created,
        key_version: 2,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ClipboardEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.id, "e");
    assert_eq!(back.device_name, "n");
    assert_eq!(back.encrypted_data, vec![1, 2, 3]);
    assert_eq!(back.metadata, "m");
    assert_eq!(back.created_at, created);
    assert_eq!(back.key_version, 2);

    let minimal: ClipboardEntry = serde_json::from_value(json!({
        "id":"e","user_id":"u","device_id":"d","content_type":"file",
        "encrypted_data":"","created_at":"2026-01-01T00:00:00Z"
    }))
    .unwrap();
    assert_eq!(minimal.device_name, "");
    assert_eq!(minimal.metadata, "");
    assert_eq!(minimal.key_version, 1);
    assert_eq!(
        minimal.created_at,
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    );
}

#[test]
fn clipboard_new_payload_wraps_entry() {
    let payload: ClipboardNewPayload = serde_json::from_value(json!({
        "entry": {
            "id":"e","user_id":"u","device_id":"d","content_type":"text",
            "encrypted_data":"AA==","created_at":"2026-01-01T00:00:00Z"
        }
    }))
    .unwrap();
    assert_eq!(payload.entry.id, "e");
    assert_eq!(payload.entry.encrypted_data, vec![0]);
}

#[test]
fn plain_entry_encodes_data_as_base64() {
    let entry = PlainEntry {
        id: "p".into(),
        device_id: "d".into(),
        device_name: "n".into(),
        content_type: ContentType::Text,
        data: b"hello".to_vec(),
        metadata: Metadata::default(),
        created_at: Utc.timestamp_opt(0, 0).unwrap(),
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["data"], "aGVsbG8=");
    let back: PlainEntry = serde_json::from_value(json).unwrap();
    assert_eq!(back.data, b"hello");
}

#[test]
fn register_request_omits_absent_optionals_and_accepts_missing() {
    let req = RegisterRequest {
        username: "alice".into(),
        password: "Pass-w0rd!".into(),
        password_confirm: "Pass-w0rd!".into(),
        email: "a@example.com".into(),
        full_name: "Alice".into(),
        country: None,
        mobile: Some("+1555".into()),
    };
    let json = serde_json::to_value(&req).unwrap();
    assert!(json.get("country").is_none());
    assert_eq!(json["mobile"], "+1555");

    let parsed: RegisterRequest = serde_json::from_value(json!({
        "username":"a","password":"p","password_confirm":"p","email":"e","full_name":"f"
    }))
    .unwrap();
    assert!(parsed.country.is_none() && parsed.mobile.is_none());
}

#[test]
fn login_request_device_name_defaults_to_empty() {
    let req: LoginRequest = serde_json::from_str(r#"{"username":"a","password":"p"}"#).unwrap();
    assert_eq!(req.device_name, "");
}

#[test]
fn auth_response_user_id_optional() {
    let resp: AuthResponse =
        serde_json::from_str(r#"{"access_token":"a","refresh_token":"r"}"#).unwrap();
    assert!(resp.user_id.is_none());
    let json = serde_json::to_value(&resp).unwrap();
    assert!(json.get("user_id").is_none());
}

#[test]
fn register_device_request_binary_fields() {
    let req = RegisterDeviceRequest {
        name: "Laptop".into(),
        public_key: vec![4, 1, 2],
        public_key_sig: Some(vec![0x30, 0x44]),
        fingerprint: Some("fp".into()),
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(
        json,
        json!({"name":"Laptop","public_key":"BAEC","public_key_sig":"MEQ=","fingerprint":"fp"})
    );

    let parsed: RegisterDeviceRequest =
        serde_json::from_str(r#"{"name":"n","public_key":"BAEC"}"#).unwrap();
    assert_eq!(parsed.public_key, vec![4, 1, 2]);
    assert!(parsed.public_key_sig.is_none());
    assert!(parsed.fingerprint.is_none());
}

#[test]
fn device_info_defaults_and_optional_base64() {
    let info: DeviceInfo = serde_json::from_str(r#"{"id":"d","name":"Laptop"}"#).unwrap();
    assert!(info.public_key.is_none());
    assert!(info.public_key_sig.is_none());
    assert!(info.last_seen.is_none());
    assert!(!info.online);
    assert_eq!(info.status, DeviceStatus::Approved);

    let info: DeviceInfo = serde_json::from_value(json!({
        "id":"d","name":"Laptop","public_key":"BAEC","public_key_sig":null,
        "last_seen":"2026-01-01T00:00:00Z","online":true,"status":"revoked"
    }))
    .unwrap();
    assert_eq!(info.public_key, Some(vec![4, 1, 2]));
    assert!(info.public_key_sig.is_none());
    assert_eq!(info.last_seen.as_deref(), Some("2026-01-01T00:00:00Z"));
    assert!(info.online);
    assert_eq!(info.status, DeviceStatus::Revoked);

    let json = serde_json::to_value(&info).unwrap();
    assert_eq!(json["public_key"], "BAEC");
    assert!(json.get("public_key_sig").is_none());
    assert_eq!(json["status"], "revoked");
}

#[test]
fn register_device_response_defaults() {
    let resp: RegisterDeviceResponse =
        serde_json::from_str(r#"{"device":{"id":"d"},"access_token":"t"}"#).unwrap();
    assert_eq!(resp.device.id, "d");
    assert_eq!(resp.device.status, DeviceStatus::Approved);
    assert!(!resp.device.is_reregistration);

    let resp: RegisterDeviceResponse = serde_json::from_str(
        r#"{"device":{"id":"d","status":"pending","is_reregistration":true},"access_token":"t"}"#,
    )
    .unwrap();
    assert_eq!(resp.device.status, DeviceStatus::Pending);
    assert!(resp.device.is_reregistration);
}

#[test]
fn group_key_response_defaults() {
    let resp: GroupKeyResponse = serde_json::from_value(json!({
        "encrypted_key":"AQ==","from_device_id":"d","from_public_key":"BA=="
    }))
    .unwrap();
    assert_eq!(resp.encrypted_key, vec![1]);
    assert_eq!(resp.from_public_key, vec![4]);
    assert!(resp.from_public_key_sig.is_none());
    assert_eq!(resp.version, 1);
    assert!(resp.rotation_due_at.is_none());

    let json = serde_json::to_value(&resp).unwrap();
    assert!(json.get("rotation_due_at").is_none());
    // Option<Vec<u8>> without skip_serializing_if is emitted as null
    assert_eq!(json["from_public_key_sig"], serde_json::Value::Null);
}

#[test]
fn group_keys_response_and_rotate_request() {
    let due = Utc.with_ymd_and_hms(2026, 2, 3, 4, 5, 6).unwrap();
    let resp = GroupKeysResponse {
        current_version: 2,
        keys: vec![VersionedGroupKey {
            version: 2,
            encrypted_key: vec![9],
            from_device_id: "d".into(),
            from_public_key: vec![4],
            from_public_key_sig: None,
        }],
        rotation_due_at: Some(due),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["current_version"], 2);
    assert_eq!(json["keys"][0]["encrypted_key"], "CQ==");
    assert_eq!(json["rotation_due_at"], "2026-02-03T04:05:06Z");
    let back: GroupKeysResponse = serde_json::from_value(json).unwrap();
    assert_eq!(back.rotation_due_at, Some(due));
    assert_eq!(back.keys[0].from_public_key, vec![4]);

    let rotate: RotateGroupKeyRequest = serde_json::from_value(json!({
        "expected_current_version": 1,
        "new_version": 2,
        "wrapped_keys": [{"device_id":"d","encrypted_key":"AQID"}]
    }))
    .unwrap();
    assert_eq!(rotate.expected_current_version, 1);
    assert_eq!(rotate.new_version, 2);
    assert_eq!(rotate.wrapped_keys.len(), 1);
    assert_eq!(rotate.wrapped_keys[0].encrypted_key, vec![1, 2, 3]);
}

#[test]
fn approval_types_roundtrip() {
    let expires = Utc.with_ymd_and_hms(2026, 1, 1, 0, 10, 0).unwrap();
    let session = ApprovalSessionResponse {
        session_id: "s".into(),
        pending_device_id: "p".into(),
        pending_public_key: vec![4],
        pending_public_key_sig: Some(vec![0x30]),
        expires_at: expires,
    };
    let json = serde_json::to_value(&session).unwrap();
    assert_eq!(json["pending_public_key"], "BA==");
    assert_eq!(json["pending_public_key_sig"], "MA==");
    let back: ApprovalSessionResponse = serde_json::from_value(json).unwrap();
    assert_eq!(back.expires_at, expires);

    let status: ApprovalStatusResponse = serde_json::from_str(r#"{"status":"pending"}"#).unwrap();
    assert_eq!(status.status, DeviceStatus::Pending);
    assert!(status.approver_device_id.is_none());
    assert!(status.approver_public_key.is_none());
    assert!(status.session_id.is_none());
    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json, json!({"status":"pending"}));

    let approve: ApproveDeviceRequest = serde_json::from_value(json!({
        "session_id":"s","expected_current_version":1,"new_version":2,"wrapped_keys":[]
    }))
    .unwrap();
    assert_eq!(approve.session_id, "s");
    assert!(approve.wrapped_keys.is_empty());

    let pending: PendingDeviceInfo = serde_json::from_value(json!({
        "id":"p","name":"Phone","public_key":"BA==","created_at":"2026-01-01T00:00:00Z"
    }))
    .unwrap();
    assert_eq!(pending.public_key, vec![4]);
    assert!(pending.public_key_sig.is_none());
}

#[test]
fn error_payload_and_change_password() {
    let err: ErrorPayload =
        serde_json::from_str(r#"{"code":"quota","message":"too large"}"#).unwrap();
    assert_eq!(err.code, "quota");
    assert_eq!(err.message, "too large");

    let cp: ChangePasswordRequest =
        serde_json::from_str(r#"{"current_password":"a","new_password":"b"}"#).unwrap();
    assert_eq!(cp.current_password, "a");
    assert_eq!(cp.new_password, "b");
}

#[test]
fn base64_serde_helpers_roundtrip_edge_cases() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Wrapper {
        #[serde(with = "base64_serde")]
        data: Vec<u8>,
        #[serde(default, with = "option_base64_serde")]
        opt: Option<Vec<u8>>,
    }

    let w = Wrapper {
        data: vec![],
        opt: None,
    };
    let json = serde_json::to_value(&w).unwrap();
    assert_eq!(json, json!({"data":"","opt":null}));
    let back: Wrapper = serde_json::from_value(json).unwrap();
    assert!(back.data.is_empty());
    assert!(back.opt.is_none());

    let w = Wrapper {
        data: (0..=255).collect(),
        opt: Some(vec![255, 0]),
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: Wrapper = serde_json::from_str(&json).unwrap();
    assert_eq!(back.data, w.data);
    assert_eq!(back.opt, Some(vec![255, 0]));

    // Missing optional field deserializes to None thanks to #[serde(default)]
    let back: Wrapper = serde_json::from_str(r#"{"data":"AA=="}"#).unwrap();
    assert_eq!(back.data, vec![0]);
    assert!(back.opt.is_none());
}
