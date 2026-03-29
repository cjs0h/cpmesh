use std::sync::Arc;
use std::net::SocketAddr;
use axum::{extract::{ConnectInfo, Extension, Path, Query, State}, http::StatusCode, response::{IntoResponse, Response}};
use serde::Deserialize;
use serde_json::json;

use cpmesh_proto::models as proto;
use crate::AppState;
use crate::models::{AUDIT_DEVICE_REGISTER, AUDIT_DEVICE_DELETE, AUDIT_GROUP_KEY_ROTATE};
use super::middleware::{AuthClaims, extract_client_ip, json_error, json_response};

const MAX_DEVICES_PER_USER: usize = 10;

pub async fn handle_register_device(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<proto::RegisterDeviceRequest>,
) -> Response {
    if req.name.is_empty() || req.public_key.is_empty() {
        return json_error("name and public_key required", StatusCode::BAD_REQUEST);
    }

    // Verify public_key_sig if provided
    if req.public_key_sig.is_none() {
        return json_error("public_key_sig is required for device registration", StatusCode::BAD_REQUEST);
    }

    let existing = match state.db.get_devices_by_user(claims.user_id).await {
        Ok(d) => d,
        Err(_) => return json_error("failed to check device count", StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Check if this device already exists by fingerprint
    if let Some(ref fp) = req.fingerprint {
        if let Ok(Some(existing_device)) = state.db.get_device_by_fingerprint(claims.user_id, fp).await {
            let is_same_keys = existing_device.public_key == req.public_key;

            if is_same_keys {
                // Same device, same keys — simple reconnect: return existing device + new token
                let access_token = match state.auth.generate_access_token(claims.user_id, Some(existing_device.id)) {
                    Ok(t) => t,
                    Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
                };
                return json_response(StatusCode::OK, json!({
                    "device": {
                        "id": existing_device.id.to_string(),
                        "status": existing_device.status,
                        "is_reregistration": false,
                    },
                    "access_token": access_token,
                }));
            }

            // Same device, different keys (reinstall) — re-register
            // If this is the user's only device, auto-approve to prevent deadlock
            let status = if existing.len() <= 1 { "approved" } else { "pending" };

            let device = match state.db.reregister_device(
                existing_device.id, &req.name, &req.public_key, req.public_key_sig.as_deref(), status,
            ).await {
                Ok(d) => d,
                Err(_) => return json_error("failed to re-register device", StatusCode::INTERNAL_SERVER_ERROR),
            };

            let access_token = match state.auth.generate_access_token(claims.user_id, Some(device.id)) {
                Ok(t) => t,
                Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
            };

            // Audit log for re-registration
            let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
            let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).map(String::from);
            let pool = state.db.pool.clone();
            let uid = claims.user_id;
            let dev_id = device.id;
            let dev_name = device.name.clone();
            let dev_status = device.status.clone();
            let ip_str = ip.to_string();
            tokio::spawn(async move {
                let _ = sqlx::query(
                    "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
                )
                .bind(Some(uid))
                .bind(AUDIT_DEVICE_REGISTER)
                .bind(&ip_str)
                .bind(ua.as_deref())
                .bind(&json!({"device_id": dev_id.to_string(), "device_name": dev_name, "status": dev_status, "is_reregistration": true}))
                .execute(&pool)
                .await;
            });

            return json_response(StatusCode::OK, json!({
                "device": {
                    "id": device.id.to_string(),
                    "status": device.status,
                    "is_reregistration": true,
                },
                "access_token": access_token,
            }));
        }
    }

    // New device registration (no fingerprint match)
    let max_devices = match state.db.get_user_subscription(claims.user_id).await {
        Ok(sub) => sub.max_devices.unwrap_or(MAX_DEVICES_PER_USER as i32) as usize,
        Err(_) => MAX_DEVICES_PER_USER,
    };

    if existing.len() >= max_devices {
        return json_error("maximum number of devices reached for your subscription", StatusCode::CONFLICT);
    }

    // First device auto-approves; subsequent devices are pending
    let status = if existing.is_empty() { "approved" } else { "pending" };

    let device = match state.db.create_device(
        claims.user_id, &req.name, &req.public_key, req.public_key_sig.as_deref(), status, req.fingerprint.as_deref(),
    ).await {
        Ok(d) => d,
        Err(_) => return json_error("failed to register device", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let access_token = match state.auth.generate_access_token(claims.user_id, Some(device.id)) {
        Ok(t) => t,
        Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Audit log
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).map(String::from);
    let pool = state.db.pool.clone();
    let uid = claims.user_id;
    let dev_id = device.id;
    let dev_name = device.name.clone();
    let dev_status = device.status.clone();
    let ip_str = ip.to_string();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(Some(uid))
        .bind(AUDIT_DEVICE_REGISTER)
        .bind(&ip_str)
        .bind(ua.as_deref())
        .bind(&json!({"device_id": dev_id.to_string(), "device_name": dev_name, "status": dev_status}))
        .execute(&pool)
        .await;
    });

    json_response(StatusCode::CREATED, json!({
        "device": {
            "id": device.id.to_string(),
            "status": device.status,
            "is_reregistration": false,
        },
        "access_token": access_token,
    }))
}

pub async fn handle_list_devices(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    let devices = match state.db.get_devices_by_user(claims.user_id).await {
        Ok(d) => d,
        Err(_) => return json_error("failed to list devices", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let mut infos = Vec::new();
    for d in devices {
        let online = state.hub.is_device_online(&claims.user_id.to_string(), &d.id.to_string()).await;
        infos.push(json!({
            "id": d.id.to_string(),
            "name": d.name,
            "last_seen": d.last_seen.map(|t| t.to_rfc3339()),
            "online": online,
            "status": d.status,
        }));
    }
    json_response(StatusCode::OK, infos)
}

pub async fn handle_delete_device(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<uuid::Uuid>,
) -> Response {
    // Check if this was an approved device (for rotation trigger)
    let was_approved = state.db.get_device_by_id(device_id).await
        .map(|d| d.status == "approved")
        .unwrap_or(false);

    if let Err(_) = state.db.delete_device(device_id, claims.user_id).await {
        return json_error("device not found", StatusCode::NOT_FOUND);
    }

    // If the deleted device was approved, trigger immediate key rotation
    if was_approved {
        let msg = cpmesh_proto::models::WsMessage {
            msg_type: cpmesh_proto::models::MSG_ROTATION_NEEDED.to_string(),
            payload: json!({"reason": "device_revoked", "revoked_device_id": device_id.to_string()}),
        };
        state.hub.broadcast_to_user(&claims.user_id.to_string(), "", &msg).await;
    }

    // Audit log
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).map(String::from);
    let pool = state.db.pool.clone();
    let uid = claims.user_id;
    let ip_str = ip.to_string();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(Some(uid))
        .bind(AUDIT_DEVICE_DELETE)
        .bind(&ip_str)
        .bind(ua.as_deref())
        .bind(&json!({"device_id": device_id.to_string(), "was_approved": was_approved}))
        .execute(&pool)
        .await;
    });

    StatusCode::NO_CONTENT.into_response()
}

pub async fn handle_get_device_keys(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    let devices = match state.db.get_devices_by_user(claims.user_id).await {
        Ok(d) => d,
        Err(_) => return json_error("failed to get device keys", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let infos: Vec<proto::DeviceInfo> = devices.iter().map(|d| {
        proto::DeviceInfo {
            id: d.id.to_string(),
            name: d.name.clone(),
            public_key: Some(d.public_key.clone()),
            public_key_sig: d.public_key_sig.clone(),
            last_seen: None,
            online: false,
            status: proto::DeviceStatus::from_str(&d.status),
        }
    }).collect();

    json_response(StatusCode::OK, proto::DeviceKeysResponse { devices: infos })
}

// === Legacy group key endpoints (kept for backward compatibility during migration) ===

pub async fn handle_get_group_key(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    let device_id = match claims.device_id {
        Some(d) => d,
        None => return json_error("device context required (register a device first)", StatusCode::BAD_REQUEST),
    };

    // Try versioned keys first
    let current_version = state.db.get_current_group_key_version(claims.user_id).await.ok().flatten();

    if let Some(ref ver) = current_version {
        // Use versioned key system
        let device_key = match state.db.get_device_group_key(device_id, ver.version).await {
            Ok(k) => k,
            Err(_) => return json_error("no group key found for this version", StatusCode::NOT_FOUND),
        };

        let from_device = match state.db.get_device_by_id(device_key.from_device_id).await {
            Ok(d) => d,
            Err(_) => return json_error("sender device not found", StatusCode::INTERNAL_SERVER_ERROR),
        };

        return json_response(StatusCode::OK, proto::GroupKeyResponse {
            encrypted_key: device_key.encrypted_key,
            from_device_id: device_key.from_device_id.to_string(),
            from_public_key: from_device.public_key,
            from_public_key_sig: from_device.public_key_sig,
            version: ver.version,
            rotation_due_at: ver.rotation_due_at,
        });
    }

    // Fall back to legacy group_keys table
    let row = match state.db.get_group_key(device_id).await {
        Ok(r) => r,
        Err(_) => return json_error("no group key found", StatusCode::NOT_FOUND),
    };

    let from_device = match state.db.get_device_by_id(row.from_device_id).await {
        Ok(d) => d,
        Err(_) => return json_error("sender device not found", StatusCode::INTERNAL_SERVER_ERROR),
    };

    json_response(StatusCode::OK, proto::GroupKeyResponse {
        encrypted_key: row.encrypted_key,
        from_device_id: row.from_device_id.to_string(),
        from_public_key: from_device.public_key,
        from_public_key_sig: from_device.public_key_sig,
        version: 1,
        rotation_due_at: None,
    })
}

pub async fn handle_store_group_keys(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    axum::Json(req): axum::Json<Vec<proto::StoreGroupKeyEntry>>,
) -> Response {
    let device_id = match claims.device_id {
        Some(d) => d,
        None => return json_error("device context required", StatusCode::BAD_REQUEST),
    };

    // Verify all devices belong to this user
    let devices = match state.db.get_devices_by_user(claims.user_id).await {
        Ok(d) => d,
        Err(_) => return json_error("failed to verify devices", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let allowed: std::collections::HashSet<String> = devices.iter().map(|d| d.id.to_string()).collect();

    let mut keys = Vec::new();
    for entry in &req {
        if !allowed.contains(&entry.device_id) {
            return json_error(&format!("device {} does not belong to this account", entry.device_id), StatusCode::FORBIDDEN);
        }
        let did = match uuid::Uuid::parse_str(&entry.device_id) {
            Ok(d) => d,
            Err(_) => return json_error("invalid device_id", StatusCode::BAD_REQUEST),
        };
        keys.push((did, entry.encrypted_key.clone()));
    }

    // Store in both legacy and versioned tables for migration
    if let Err(_) = state.db.store_group_keys(device_id, &keys).await {
        return json_error("failed to store group keys", StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Also create version 1 if no versioned keys exist yet
    let current = state.db.get_current_group_key_version(claims.user_id).await.ok().flatten();
    if current.is_none() {
        let _ = state.db.rotate_group_key(
            claims.user_id, device_id, 0, 1, &keys,
            state.config.group_key_rotation_interval_hours,
        ).await;
    }

    // Notify other devices
    let msg = cpmesh_proto::models::WsMessage {
        msg_type: cpmesh_proto::models::MSG_GROUP_KEY_UPDATED.to_string(),
        payload: json!({"from_device_id": device_id.to_string()}),
    };
    state.hub.broadcast_to_user(&claims.user_id.to_string(), &device_id.to_string(), &msg).await;

    json_response(StatusCode::OK, json!({"message": "group keys stored"}))
}

// === Versioned group key endpoints ===

#[derive(Deserialize)]
pub struct GroupKeyQuery {
    pub since_version: Option<i32>,
}

/// GET /api/group-keys/current — returns current version + encrypted key(s) for the requesting device.
pub async fn handle_get_current_group_keys(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    Query(query): Query<GroupKeyQuery>,
) -> Response {
    let device_id = match claims.device_id {
        Some(d) => d,
        None => return json_error("device context required", StatusCode::BAD_REQUEST),
    };

    let current_version = match state.db.get_current_group_key_version(claims.user_id).await {
        Ok(Some(v)) => v,
        Ok(None) => return json_error("no group key version exists", StatusCode::NOT_FOUND),
        Err(_) => return json_error("failed to get key version", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let since = query.since_version.unwrap_or(current_version.version - 1);
    let device_keys = match state.db.get_device_group_keys_since(device_id, since).await {
        Ok(k) => k,
        Err(_) => return json_error("failed to get device keys", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let mut versioned_keys = Vec::new();
    for dk in device_keys {
        let from_device = state.db.get_device_by_id(dk.from_device_id).await.ok();
        versioned_keys.push(proto::VersionedGroupKey {
            version: dk.version,
            encrypted_key: dk.encrypted_key,
            from_device_id: dk.from_device_id.to_string(),
            from_public_key: from_device.as_ref().map(|d| d.public_key.clone()).unwrap_or_default(),
            from_public_key_sig: from_device.and_then(|d| d.public_key_sig),
        });
    }

    json_response(StatusCode::OK, proto::GroupKeysResponse {
        current_version: current_version.version,
        keys: versioned_keys,
        rotation_due_at: current_version.rotation_due_at,
    })
}

/// POST /api/group-keys/rotate — rotate group key with CAS.
pub async fn handle_rotate_group_key(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<proto::RotateGroupKeyRequest>,
) -> Response {
    let device_id = match claims.device_id {
        Some(d) => d,
        None => return json_error("device context required", StatusCode::BAD_REQUEST),
    };

    // Verify all wrapped_keys belong to approved devices of this user
    let approved = match state.db.get_approved_devices_by_user(claims.user_id).await {
        Ok(d) => d,
        Err(_) => return json_error("failed to get approved devices", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let approved_ids: std::collections::HashSet<String> = approved.iter().map(|d| d.id.to_string()).collect();
    for entry in &req.wrapped_keys {
        if !approved_ids.contains(&entry.device_id) {
            return json_error(&format!("device {} is not approved", entry.device_id), StatusCode::FORBIDDEN);
        }
    }

    let mut keys = Vec::new();
    for entry in &req.wrapped_keys {
        let did = match uuid::Uuid::parse_str(&entry.device_id) {
            Ok(d) => d,
            Err(_) => return json_error("invalid device_id", StatusCode::BAD_REQUEST),
        };
        keys.push((did, entry.encrypted_key.clone()));
    }

    let success = match state.db.rotate_group_key(
        claims.user_id,
        device_id,
        req.expected_current_version,
        req.new_version,
        &keys,
        state.config.group_key_rotation_interval_hours,
    ).await {
        Ok(s) => s,
        Err(e) => return json_error(&format!("rotation failed: {e}"), StatusCode::INTERNAL_SERVER_ERROR),
    };

    if !success {
        return json_error("version conflict — another rotation occurred, retry", StatusCode::CONFLICT);
    }

    // Notify all devices
    let msg = cpmesh_proto::models::WsMessage {
        msg_type: cpmesh_proto::models::MSG_GROUP_KEY_UPDATED.to_string(),
        payload: json!({"from_device_id": device_id.to_string(), "version": req.new_version}),
    };
    state.hub.broadcast_to_user(&claims.user_id.to_string(), &device_id.to_string(), &msg).await;

    // Audit
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).map(String::from);
    let pool = state.db.pool.clone();
    let uid = claims.user_id;
    let ip_str = ip.to_string();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(Some(uid))
        .bind(AUDIT_GROUP_KEY_ROTATE)
        .bind(&ip_str)
        .bind(ua.as_deref())
        .bind(&json!({"new_version": req.new_version, "device_id": device_id.to_string()}))
        .execute(&pool)
        .await;
    });

    json_response(StatusCode::OK, json!({"message": "key rotated", "version": req.new_version}))
}
