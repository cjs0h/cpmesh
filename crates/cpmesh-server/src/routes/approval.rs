use axum::{
    extract::{ConnectInfo, Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use super::middleware::{AuthClaims, extract_client_ip, json_error, json_response};
use crate::AppState;
use crate::models::{AUDIT_DEVICE_APPROVE, AUDIT_DEVICE_REJECT};
use cpmesh_proto::models as proto;

/// GET /api/device-approvals/pending — list pending devices (requires approved device).
pub async fn handle_list_pending(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    let devices = match state.db.get_pending_devices_by_user(claims.user_id).await {
        Ok(d) => d,
        Err(_) => {
            return json_error(
                "failed to list pending devices",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let infos: Vec<proto::PendingDeviceInfo> = devices
        .iter()
        .map(|d| proto::PendingDeviceInfo {
            id: d.id.to_string(),
            name: d.name.clone(),
            public_key: d.public_key.clone(),
            public_key_sig: d.public_key_sig.clone(),
            encryption_key: d.encryption_key.clone(),
            encryption_key_sig: d.encryption_key_sig.clone(),
            created_at: d.created_at,
        })
        .collect();

    json_response(StatusCode::OK, infos)
}

/// GET /api/device-approvals/me — pending device checks its own approval status.
/// This endpoint is accessible to pending devices (not gated by approved-device middleware).
pub async fn handle_my_approval_status(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    let device_id = match claims.device_id {
        Some(d) => d,
        None => return json_error("device context required", StatusCode::BAD_REQUEST),
    };

    let device = match state.db.get_device_by_id(device_id).await {
        Ok(d) => d,
        Err(_) => return json_error("device not found", StatusCode::NOT_FOUND),
    };

    // Check for an active approval session
    let session = state
        .db
        .get_approval_session(device_id)
        .await
        .unwrap_or(None);

    let (approver_device_id, approver_public_key, approver_public_key_sig, session_id) =
        if let Some(ref sess) = session {
            let approver = state
                .db
                .get_device_by_id(sess.approver_device_id)
                .await
                .ok();
            (
                Some(sess.approver_device_id.to_string()),
                approver.as_ref().map(|a| a.public_key.clone()),
                approver.and_then(|a| a.public_key_sig.clone()),
                Some(sess.id.to_string()),
            )
        } else {
            (None, None, None, None)
        };

    json_response(
        StatusCode::OK,
        proto::ApprovalStatusResponse {
            pairing_version: proto::PAIRING_VERSION,
            status: device.status.parse().unwrap(),
            approver_device_id,
            approver_public_key,
            approver_public_key_sig,
            session_id,
            approver_commit: session.as_ref().and_then(|s| s.approver_commit.clone()),
            pending_nonce: session.as_ref().and_then(|s| s.pending_nonce.clone()),
            approver_nonce: session.as_ref().and_then(|s| s.approver_nonce.clone()),
        },
    )
}

/// POST /api/device-approvals/me/nonce — pending device contributes its SAS nonce
/// after seeing the approver's commitment.
pub async fn handle_pending_nonce(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    axum::Json(req): axum::Json<proto::SasNonceRequest>,
) -> Response {
    let Some(device_id) = claims.device_id else {
        return json_error("device context required", StatusCode::BAD_REQUEST);
    };
    let Ok(session_id) = uuid::Uuid::parse_str(&req.session_id) else {
        return json_error("invalid session_id", StatusCode::BAD_REQUEST);
    };
    if req.nonce.len() != 32 {
        return json_error("nonce must be 32 bytes", StatusCode::BAD_REQUEST);
    }
    match state
        .db
        .set_pending_nonce(session_id, device_id, &req.nonce)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => json_error(
            "no active approval session accepts this nonce",
            StatusCode::CONFLICT,
        ),
        Err(e) => super::middleware::ApiError::internal(e).into_response(),
    }
}

/// GET /api/device-approvals/{pending_device_id}/session — approver polls for the
/// pending device's nonce.
pub async fn handle_approval_session(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    Path(pending_device_id): Path<uuid::Uuid>,
) -> Response {
    let Some(approver_device_id) = claims.device_id else {
        return json_error("device context required", StatusCode::BAD_REQUEST);
    };
    let session = match state.db.get_approval_session(pending_device_id).await {
        Ok(Some(s)) if s.approver_device_id == approver_device_id => s,
        Ok(_) => {
            return json_error(
                "no active approval session for this device",
                StatusCode::NOT_FOUND,
            );
        }
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    };
    json_response(
        StatusCode::OK,
        proto::ApprovalSessionState {
            session_id: session.id.to_string(),
            pending_nonce: session.pending_nonce,
            approver_nonce: session.approver_nonce,
            expires_at: session.expires_at,
        },
    )
}

/// POST /api/device-approvals/{pending_device_id}/reveal — approver opens its
/// commitment once the pending nonce exists. The server checks the opening too,
/// although clients never rely on the relay for that.
pub async fn handle_reveal_nonce(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    Path(pending_device_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<proto::SasNonceRequest>,
) -> Response {
    let Some(approver_device_id) = claims.device_id else {
        return json_error("device context required", StatusCode::BAD_REQUEST);
    };
    let Ok(session_id) = uuid::Uuid::parse_str(&req.session_id) else {
        return json_error("invalid session_id", StatusCode::BAD_REQUEST);
    };
    let Ok(nonce) = <[u8; 32]>::try_from(req.nonce.as_slice()) else {
        return json_error("nonce must be 32 bytes", StatusCode::BAD_REQUEST);
    };
    let session = match state.db.get_approval_session(pending_device_id).await {
        Ok(Some(s)) if s.approver_device_id == approver_device_id && s.id == session_id => s,
        Ok(_) => {
            return json_error(
                "no active approval session for this device",
                StatusCode::NOT_FOUND,
            );
        }
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    };
    if session.approver_commit.as_deref() != Some(proto::sas_commitment(&nonce).as_slice()) {
        return json_error(
            "nonce does not open the commitment",
            StatusCode::BAD_REQUEST,
        );
    }
    if session.pending_nonce.is_none() {
        return json_error(
            "the pending device has not contributed its nonce yet",
            StatusCode::CONFLICT,
        );
    }
    match state
        .db
        .set_approver_nonce(session_id, approver_device_id, &nonce)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => json_error("approval session changed", StatusCode::CONFLICT),
        Err(e) => super::middleware::ApiError::internal(e).into_response(),
    }
}

/// POST /api/device-approvals/{pending_device_id}/begin — start approval session.
pub async fn handle_begin_approval(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    Path(pending_device_id): Path<uuid::Uuid>,
    headers: axum::http::HeaderMap,
    body: Option<axum::Json<proto::BeginApprovalRequest>>,
) -> Response {
    if headers
        .get("x-cpmesh-pairing")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok())
        != Some(proto::PAIRING_VERSION)
    {
        return json_error(
            "update your client: committed short-code pairing is required",
            StatusCode::UPGRADE_REQUIRED,
        );
    }
    let commit = match body {
        Some(axum::Json(req)) if req.commit.len() == 32 => req.commit,
        _ => return json_error("a 32-byte commit is required", StatusCode::BAD_REQUEST),
    };
    let approver_device_id = match claims.device_id {
        Some(d) => d,
        None => return json_error("device context required", StatusCode::BAD_REQUEST),
    };

    // Verify pending device belongs to same user and is pending
    let pending_device = match state.db.get_device_by_id(pending_device_id).await {
        Ok(d) => d,
        Err(_) => return json_error("device not found", StatusCode::NOT_FOUND),
    };

    if pending_device.user_id != claims.user_id {
        return json_error(
            "device does not belong to this account",
            StatusCode::FORBIDDEN,
        );
    }

    if pending_device.status != "pending" {
        return json_error(
            &format!("device is not pending (status: {})", pending_device.status),
            StatusCode::CONFLICT,
        );
    }

    // Create approval session (10 minute TTL)
    let session = match state
        .db
        .create_approval_session(pending_device_id, approver_device_id, 600, &commit)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return json_error(
                &format!("failed to create session: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    json_response(
        StatusCode::OK,
        proto::ApprovalSessionResponse {
            pairing_version: proto::PAIRING_VERSION,
            session_id: session.id.to_string(),
            pending_device_id: pending_device_id.to_string(),
            pending_public_key: pending_device.public_key,
            pending_public_key_sig: pending_device.public_key_sig,
            pending_encryption_key: pending_device.encryption_key,
            pending_encryption_key_sig: pending_device.encryption_key_sig,
            expires_at: session.expires_at,
        },
    )
}

/// POST /api/device-approvals/{pending_device_id}/approve — approve device + rotate key.
pub async fn handle_approve_device(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(pending_device_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<proto::ApproveDeviceRequest>,
) -> Response {
    let approver_device_id = match claims.device_id {
        Some(d) => d,
        None => return json_error("device context required", StatusCode::BAD_REQUEST),
    };

    // Validate session
    let session_id = match uuid::Uuid::parse_str(&req.session_id) {
        Ok(id) => id,
        Err(_) => return json_error("invalid session_id", StatusCode::BAD_REQUEST),
    };

    let session = match state.db.get_approval_session(pending_device_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return json_error(
                "no active approval session for this device",
                StatusCode::NOT_FOUND,
            );
        }
        Err(_) => return json_error("failed to check session", StatusCode::INTERNAL_SERVER_ERROR),
    };

    if session.id != session_id {
        return json_error("session_id mismatch", StatusCode::BAD_REQUEST);
    }

    if session.approver_device_id != approver_device_id {
        return json_error(
            "you are not the approver for this session",
            StatusCode::FORBIDDEN,
        );
    }

    // Verify pending device belongs to same user
    let pending_device = match state.db.get_device_by_id(pending_device_id).await {
        Ok(d) => d,
        Err(_) => return json_error("pending device not found", StatusCode::NOT_FOUND),
    };

    if pending_device.user_id != claims.user_id || pending_device.status != "pending" {
        return json_error("invalid pending device", StatusCode::BAD_REQUEST);
    }

    // Validate wrapped_keys covers all approved devices + the new device
    let mut approved_devices = match state.db.get_approved_devices_by_user(claims.user_id).await {
        Ok(d) => d,
        Err(_) => {
            return json_error(
                "failed to get approved devices",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let mut expected_device_ids: std::collections::HashSet<String> =
        approved_devices.iter().map(|d| d.id.to_string()).collect();
    expected_device_ids.insert(pending_device_id.to_string());

    let provided_device_ids: std::collections::HashSet<String> = req
        .wrapped_keys
        .iter()
        .map(|k| k.device_id.clone())
        .collect();

    if expected_device_ids != provided_device_ids {
        return json_error(
            "wrapped_keys must contain exactly one key for every approved device plus the newly approved device",
            StatusCode::BAD_REQUEST,
        );
    }

    approved_devices.push(pending_device.clone());
    if let Err(error) = super::devices::validate_memberships(
        &approved_devices,
        approver_device_id,
        req.new_version,
        &req.wrapped_keys,
    ) {
        return error.into_response();
    }

    // Atomically: rotate group key (CAS) + approve device
    let success = match state
        .db
        .commit_key_rotation(crate::db::KeyRotation {
            user_id: claims.user_id,
            from_device_id: approver_device_id,
            expected_current_version: req.expected_current_version,
            new_version: req.new_version,
            wrapped_keys: &req.wrapped_keys,
            rotation_interval_hours: state.config.group_key_rotation_interval_hours,
            approval: Some((pending_device_id, session.id)),
        })
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return json_error(
                &format!("failed to rotate key: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    if !success {
        return json_error(
            "version conflict — another rotation occurred, retry",
            StatusCode::CONFLICT,
        );
    }

    // Notify all devices about key update
    let msg = cpmesh_proto::models::WsMessage {
        msg_type: cpmesh_proto::models::MSG_GROUP_KEY_UPDATED.to_string(),
        payload: json!({"from_device_id": approver_device_id.to_string(), "version": req.new_version}),
    };
    state
        .hub
        .broadcast_to_user(&claims.user_id.to_string(), "", &msg)
        .await;

    // Audit log
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let pool = state.db.pool.clone();
    let uid = claims.user_id;
    let ip_str = ip.to_string();
    let dev_name = pending_device.name.clone();
    if let Err(error) = sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(Some(uid))
        .bind(AUDIT_DEVICE_APPROVE)
        .bind(&ip_str)
        .bind(ua.as_deref())
        .bind(json!({"pending_device_id": pending_device_id.to_string(), "device_name": dev_name, "new_key_version": req.new_version}))
        .execute(&pool)
        .await { tracing::warn!("Failed to persist audit entry: {error}"); }

    json_response(
        StatusCode::OK,
        json!({"message": "device approved", "version": req.new_version}),
    )
}

/// POST /api/device-approvals/{pending_device_id}/reject — reject a pending device.
pub async fn handle_reject_device(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(pending_device_id): Path<uuid::Uuid>,
) -> Response {
    let pending_device = match state.db.get_device_by_id(pending_device_id).await {
        Ok(d) => d,
        Err(_) => return json_error("device not found", StatusCode::NOT_FOUND),
    };

    if pending_device.user_id != claims.user_id || pending_device.status != "pending" {
        return json_error("invalid pending device", StatusCode::BAD_REQUEST);
    }

    if let Err(e) = state
        .db
        .update_device_status(pending_device_id, claims.user_id, "rejected", None)
        .await
    {
        return json_error(
            &format!("failed to reject device: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    // Audit log
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let pool = state.db.pool.clone();
    let uid = claims.user_id;
    let ip_str = ip.to_string();
    if let Err(error) = sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(Some(uid))
        .bind(AUDIT_DEVICE_REJECT)
        .bind(&ip_str)
        .bind(ua.as_deref())
        .bind(json!({"pending_device_id": pending_device_id.to_string()}))
        .execute(&pool)
        .await { tracing::warn!("Failed to persist audit entry: {error}"); }

    json_response(StatusCode::OK, json!({"message": "device rejected"}))
}
