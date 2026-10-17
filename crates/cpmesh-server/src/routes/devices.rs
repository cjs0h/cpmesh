use axum::{
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use super::auth_service::SessionGrant;
use super::middleware::{AuthClaims, extract_client_ip, json_error, json_response};
use crate::AppState;
use crate::audit::RequestMeta;
use crate::db::{GrantBinding, NewDevice};
use crate::models::{AUDIT_DEVICE_DELETE, AUDIT_DEVICE_REGISTER, AUDIT_GROUP_KEY_ROTATE};
use crate::oauth::grants::{RevokeReason, grant_revoked, record_revocation};
use cpmesh_proto::models as proto;

const MAX_DEVICES_PER_USER: usize = 10;

/// ECDSA-P256-SHA256 (DER) by a device identity key.
pub(crate) fn verify_device_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        public_key,
    )
    .verify(message, signature)
    .is_ok()
}

/// A validated `(encryption_key, encryption_key_sig)` pair.
pub(crate) type CertifiedEncryptionKey<'a> = (&'a [u8], &'a [u8]);

/// Checks an identity-certified encryption key: both fields present, a 65-byte
/// SEC1 point distinct from the identity key, and a valid certification.
pub(crate) fn validated_encryption_key<'a>(
    identity_key: &[u8],
    encryption_key: Option<&'a [u8]>,
    encryption_key_sig: Option<&'a [u8]>,
) -> Result<Option<CertifiedEncryptionKey<'a>>, &'static str> {
    match (encryption_key, encryption_key_sig) {
        (None, None) => Ok(None),
        (Some(key), Some(sig)) => {
            if key.len() != 65 || key[0] != 0x04 || key == identity_key {
                return Err("encryption_key must be a distinct uncompressed P-256 point");
            }
            if !verify_device_signature(
                identity_key,
                &proto::encryption_key_transcript(identity_key, key),
                sig,
            ) {
                return Err("encryption_key_sig is not a valid certification by public_key");
            }
            Ok(Some((key, sig)))
        }
        _ => Err("encryption_key and encryption_key_sig must be sent together"),
    }
}

pub async fn handle_device_challenge(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(token) = super::middleware::bearer_token(&headers) else {
        return json_error("missing session", StatusCode::UNAUTHORIZED);
    };
    match state.auth.issue_device_challenge(claims.user_id, &token) {
        Ok(challenge) => {
            json_response(StatusCode::OK, proto::DeviceChallengeResponse { challenge })
        }
        Err(e) => super::middleware::ApiError::internal(e).into_response(),
    }
}

pub async fn handle_register_device(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    meta: RequestMeta,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<proto::RegisterDeviceRequest>,
) -> Response {
    if req.name.is_empty() || req.name.len() > 255 || req.public_key.len() != 65 {
        return json_error(
            "valid name and P-256 public_key required",
            StatusCode::BAD_REQUEST,
        );
    }
    let encryption = match validated_encryption_key(
        &req.public_key,
        req.encryption_key.as_deref(),
        req.encryption_key_sig.as_deref(),
    ) {
        Ok(encryption) => encryption,
        Err(message) => return json_error(message, StatusCode::BAD_REQUEST),
    };

    let Some(proof) = &req.proof else {
        return json_error(
            "update your client: session-bound device proof is required",
            StatusCode::UPGRADE_REQUIRED,
        );
    };
    let Some(token) = super::middleware::bearer_token(&headers) else {
        return json_error("missing session", StatusCode::UNAUTHORIZED);
    };
    let (jti, exp) =
        match state
            .auth
            .validate_device_challenge(&proof.challenge, claims.user_id, &token)
        {
            Ok(proof) => proof,
            Err(_) => return json_error("invalid device challenge", StatusCode::UNAUTHORIZED),
        };
    if aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        &req.public_key,
    )
    .verify(
        &proto::device_proof_transcript(&proof.challenge),
        &proof.signature,
    )
    .is_err()
    {
        return json_error("invalid device proof", StatusCode::UNAUTHORIZED);
    }
    match state.auth.consume_once(&jti, claims.user_id, exp).await {
        Ok(true) => {}
        Ok(false) => return json_error("device challenge already used", StatusCode::UNAUTHORIZED),
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    }

    let existing = match state.db.get_devices_by_user(claims.user_id).await {
        Ok(d) => d,
        Err(_) => {
            return json_error(
                "failed to check device count",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    // A fingerprint is only a lookup hint, never an authorization credential.
    if let Some(device) = existing.iter().find(|d| {
        d.public_key == req.public_key
            || req
                .fingerprint
                .as_ref()
                .is_some_and(|fp| d.fingerprint.as_ref() == Some(fp))
    }) {
        if device.public_key != req.public_key {
            return json_error(
                "device keys changed; remove the old device and pair the replacement",
                StatusCode::CONFLICT,
            );
        }
        if device.status == "revoked" || device.status == "rejected" {
            return json_error("device is revoked or rejected", StatusCode::FORBIDDEN);
        }
        // An agent registers only the device of its own grant. Authorizing again moves
        // the agent's existing device to the new grant, without pairing it again.
        if let Some(agent) = claims.agent {
            match state
                .db
                .bind_oauth_grant_device(agent.grant_id, claims.user_id, device.id)
                .await
            {
                Ok(GrantBinding::Bound { superseded }) => {
                    if let Some(old_grant) = superseded {
                        // Its open sockets still run on the old grant
                        state
                            .hub
                            .disconnect_device(&claims.user_id.to_string(), &device.id.to_string())
                            .await;
                        record_revocation(
                            &state,
                            claims.user_id,
                            old_grant,
                            device.id,
                            RevokeReason::Superseded,
                            &meta,
                        )
                        .await;
                    }
                }
                Ok(GrantBinding::Unchanged) => {}
                Ok(GrantBinding::OtherDevice) => return grant_has_other_device(),
                Ok(GrantBinding::Revoked) => return grant_revoked().into_response(),
                Ok(GrantBinding::NoDevice) => {
                    return json_error("device is revoked or rejected", StatusCode::FORBIDDEN);
                }
                Err(e) => return super::middleware::ApiError::internal(e).into_response(),
            }
        }
        // An updated client re-registering with the same identity publishes its
        // encryption key here (the certification was verified above).
        if let Some((key, sig)) = encryption
            && device.encryption_key.as_deref() != Some(key)
            && let Err(e) = state
                .db
                .set_device_encryption_key(device.id, claims.user_id, key, sig)
                .await
        {
            return super::middleware::ApiError::internal(e).into_response();
        }
        let (access_token, refresh_token) = match state
            .auth
            .issue_session(&SessionGrant::from_claims(&claims).with_device(Some(device.id)))
        {
            Ok(tokens) => tokens,
            Err(e) => return super::middleware::ApiError::internal(e).into_response(),
        };
        return json_response(
            StatusCode::OK,
            json!({
                "device": {
                    "id": device.id.to_string(),
                    "status": device.status,
                    "is_reregistration": false,
                },
                "access_token": access_token,
                "refresh_token": refresh_token,
            }),
        );
    }

    // New device registration (no fingerprint match)
    let max_devices = match state.db.get_user_subscription(claims.user_id).await {
        Ok(sub) => sub.max_devices.unwrap_or(MAX_DEVICES_PER_USER as i32) as usize,
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    };

    if existing.len() >= max_devices {
        return json_error(
            "maximum number of devices reached for your subscription",
            StatusCode::CONFLICT,
        );
    }

    let device = match state
        .db
        .register_device(
            claims.user_id,
            &req,
            max_devices as i64,
            claims.agent.map(|agent| agent.grant_id),
        )
        .await
    {
        Ok(NewDevice::Registered(d)) => *d,
        Ok(NewDevice::LimitReached) => {
            return json_error("maximum number of devices reached", StatusCode::CONFLICT);
        }
        Ok(NewDevice::GrantRevoked) => return grant_revoked().into_response(),
        Ok(NewDevice::GrantHasDevice) => return grant_has_other_device(),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return json_error(
                "device registration changed; retry with a fresh proof",
                StatusCode::CONFLICT,
            );
        }
        Err(_) => {
            return json_error(
                "failed to register device",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let (access_token, refresh_token) = match state
        .auth
        .issue_session(&SessionGrant::from_claims(&claims).with_device(Some(device.id)))
    {
        Ok(t) => t,
        Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Audit log
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let pool = state.db.pool.clone();
    let uid = claims.user_id;
    let dev_id = device.id;
    let dev_name = device.name.clone();
    let dev_status = device.status.clone();
    let ip_str = ip.to_string();
    if let Err(error) = sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(Some(uid))
        .bind(AUDIT_DEVICE_REGISTER)
        .bind(&ip_str)
        .bind(ua.as_deref())
        .bind(json!({"device_id": dev_id.to_string(), "device_name": dev_name, "status": dev_status}))
        .execute(&pool)
        .await { tracing::warn!("Failed to persist audit entry: {error}"); }

    json_response(
        StatusCode::CREATED,
        json!({
            "device": {
                "id": device.id.to_string(),
                "status": device.status,
                "is_reregistration": false,
            },
            "access_token": access_token,
            "refresh_token": refresh_token,
        }),
    )
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
        let online = state
            .hub
            .is_device_online(&claims.user_id.to_string(), &d.id.to_string())
            .await;
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
    meta: RequestMeta,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<uuid::Uuid>,
) -> Response {
    match state.db.get_device_by_id(device_id).await {
        Ok(d) if d.user_id == claims.user_id => {}
        Ok(_) | Err(sqlx::Error::RowNotFound) => {
            return json_error("device not found", StatusCode::NOT_FOUND);
        }
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    }

    let removal = match state.db.delete_device(device_id, claims.user_id).await {
        Ok(removal) => removal,
        Err(_) => return json_error("device not found", StatusCode::NOT_FOUND),
    };
    let was_approved = removal.was_approved;
    device_removed(&state, claims.user_id, device_id, was_approved).await;

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
        .bind(AUDIT_DEVICE_DELETE)
        .bind(&ip_str)
        .bind(ua.as_deref())
        .bind(json!({"device_id": device_id.to_string(), "was_approved": was_approved}))
        .execute(&pool)
        .await { tracing::warn!("Failed to persist audit entry: {error}"); }
    if let Some(grant_id) = removal.revoked_grant {
        record_revocation(
            &state,
            claims.user_id,
            grant_id,
            device_id,
            RevokeReason::DeviceRemoved,
            &meta,
        )
        .await;
    }

    StatusCode::NO_CONTENT.into_response()
}

/// What follows removing a device, whatever removed it: its sockets close and, when it
/// was approved, the user's devices are asked to rotate the group key without it.
pub(crate) async fn device_removed(
    state: &AppState,
    user_id: uuid::Uuid,
    device_id: uuid::Uuid,
    was_approved: bool,
) {
    state
        .hub
        .disconnect_device(&user_id.to_string(), &device_id.to_string())
        .await;
    if was_approved {
        let msg = proto::WsMessage {
            msg_type: proto::MSG_ROTATION_NEEDED.to_string(),
            payload: json!({"reason": "device_revoked", "revoked_device_id": device_id.to_string()}),
        };
        state
            .hub
            .broadcast_to_user(&user_id.to_string(), "", &msg)
            .await;
    }
}

/// An agent's grant belongs to one device; another device needs a new authorization.
fn grant_has_other_device() -> Response {
    super::middleware::ApiError::coded(
        StatusCode::FORBIDDEN,
        "grant_device_mismatch",
        "this agent's authorization belongs to another device; authorize the agent again to register a new one",
    )
    .into_response()
}

pub async fn handle_get_device_keys(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    let devices = match state.db.get_devices_by_user(claims.user_id).await {
        Ok(d) => d,
        Err(_) => {
            return json_error(
                "failed to get device keys",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let infos: Vec<proto::DeviceInfo> = devices
        .iter()
        .map(|d| proto::DeviceInfo {
            id: d.id.to_string(),
            name: d.name.clone(),
            public_key: Some(d.public_key.clone()),
            public_key_sig: d.public_key_sig.clone(),
            encryption_key: d.encryption_key.clone(),
            encryption_key_sig: d.encryption_key_sig.clone(),
            last_seen: None,
            online: false,
            status: d.status.parse().unwrap(),
        })
        .collect();

    json_response(StatusCode::OK, proto::DeviceKeysResponse { devices: infos })
}

/// PUT /api/devices/me/encryption-key — publish or replace this device's
/// identity-certified encryption key. Open to pending devices so an approver can
/// wrap the group key for them.
pub async fn handle_publish_encryption_key(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    axum::Json(req): axum::Json<proto::PublishEncryptionKeyRequest>,
) -> Response {
    let Some(device_id) = claims.device_id else {
        return json_error("device context required", StatusCode::BAD_REQUEST);
    };
    let device = match state.db.get_device_by_id(device_id).await {
        Ok(d) if d.user_id == claims.user_id => d,
        Ok(_) | Err(sqlx::Error::RowNotFound) => {
            return json_error("device not found", StatusCode::NOT_FOUND);
        }
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    };
    let (key, sig) = match validated_encryption_key(
        &device.public_key,
        Some(&req.encryption_key),
        Some(&req.encryption_key_sig),
    ) {
        Ok(Some(pair)) => pair,
        Ok(None) => unreachable!("both fields are required by the request type"),
        Err(message) => return json_error(message, StatusCode::BAD_REQUEST),
    };
    match state
        .db
        .set_device_encryption_key(device_id, claims.user_id, key, sig)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => json_error("device not found", StatusCode::NOT_FOUND),
        Err(e) => super::middleware::ApiError::internal(e).into_response(),
    }
}

// === Legacy group key endpoints (kept for backward compatibility during migration) ===

pub async fn handle_get_group_key(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    let device_id = match claims.device_id {
        Some(d) => d,
        None => {
            return json_error(
                "device context required (register a device first)",
                StatusCode::BAD_REQUEST,
            );
        }
    };

    // Try versioned keys first
    let current_version = match state.db.get_current_group_key_version(claims.user_id).await {
        Ok(version) => version,
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    };

    if let Some(ref ver) = current_version {
        // Use versioned key system
        let device_key = match state
            .db
            .get_device_group_keys_since(device_id, ver.version - 1)
            .await
        {
            Ok(mut keys) if !keys.is_empty() => keys.remove(0),
            Ok(_) => {
                return json_error("no group key found for this version", StatusCode::NOT_FOUND);
            }
            Err(_) => {
                return json_error("no group key found for this version", StatusCode::NOT_FOUND);
            }
        };

        return json_response(
            StatusCode::OK,
            proto::GroupKeyResponse {
                encrypted_key: device_key.encrypted_key,
                from_device_id: device_key.from_device_id.to_string(),
                from_public_key: device_key.from_public_key,
                from_public_key_sig: device_key.from_public_key_sig,
                membership: device_key.membership.map(|m| m.0),
                version: ver.version,
                rotation_due_at: ver.rotation_due_at,
            },
        );
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

    json_response(
        StatusCode::OK,
        proto::GroupKeyResponse {
            encrypted_key: row.encrypted_key,
            from_device_id: row.from_device_id.to_string(),
            from_public_key: from_device.public_key,
            from_public_key_sig: from_device.public_key_sig,
            membership: None,
            version: 1,
            rotation_due_at: None,
        },
    )
}

pub async fn handle_store_group_keys(
    State(_state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    axum::Json(req): axum::Json<Vec<proto::StoreGroupKeyEntry>>,
) -> Response {
    let device_id = match claims.device_id {
        Some(d) => d,
        None => return json_error("device context required", StatusCode::BAD_REQUEST),
    };

    // Legacy distribution could overwrite arbitrary wraps without a membership transition.
    // Only the new, authenticated rotation endpoint may change mesh keys.
    let _ = req;
    let _ = device_id;
    json_error(
        "update your client: use authenticated group-key rotation",
        StatusCode::UPGRADE_REQUIRED,
    )
}

pub(crate) fn validate_memberships(
    devices: &[crate::models::Device],
    sender_id: uuid::Uuid,
    version: i32,
    keys: &[proto::StoreGroupKeyEntry],
) -> Result<(), super::middleware::ApiError> {
    use super::middleware::ApiError;
    let bad = || ApiError::new(StatusCode::BAD_REQUEST, "invalid key membership");
    let sender = devices.iter().find(|d| d.id == sender_id).ok_or_else(bad)?;
    if version < 1 || keys.len() != devices.len() {
        return Err(bad());
    }
    let proofs: Vec<_> = keys
        .iter()
        .filter_map(|key| key.membership.as_ref())
        .collect();
    let membership = match proofs.as_slice() {
        [membership] => *membership,
        [] => {
            return Err(ApiError::new(
                StatusCode::UPGRADE_REQUIRED,
                "update your client: authenticated membership is required",
            ));
        }
        _ => return Err(bad()),
    };
    if membership.members.len() != devices.len()
        || membership.wrapped_key_hashes.len() != devices.len()
    {
        return Err(bad());
    }
    let expected: std::collections::HashMap<_, _> = devices
        .iter()
        .map(|device| (device.id.to_string(), device.public_key.as_slice()))
        .collect();
    let mut member_ids = std::collections::HashSet::new();
    for member in &membership.members {
        if !member_ids.insert(&member.id)
            || expected.get(&member.id).copied() != Some(member.public_key.as_slice())
        {
            return Err(bad());
        }
    }
    let mut recipients = std::collections::HashSet::new();
    for key in keys {
        if !recipients.insert(&key.device_id)
            || !expected.contains_key(&key.device_id)
            || key.encrypted_key.len() != proto::WRAP_V3_LEN
            || membership.wrapped_key_hashes.get(&key.device_id)
                != Some(&proto::wrapped_key_hash(&key.encrypted_key))
        {
            return Err(bad());
        }
    }
    let transcript = proto::membership_transcript(
        version,
        &sender_id.to_string(),
        &membership.members,
        &membership.wrapped_key_hashes,
    )
    .map_err(|_| bad())?;
    if !verify_device_signature(&sender.public_key, &transcript, &membership.signature) {
        return Err(bad());
    }
    Ok(())
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
        Err(_) => {
            return json_error(
                "failed to get key version",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let since = query.since_version.unwrap_or(current_version.version - 1);
    let device_keys = match state.db.get_device_group_keys_since(device_id, since).await {
        Ok(k) => k,
        Err(_) => {
            return json_error(
                "failed to get device keys",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let versioned_keys = device_keys
        .into_iter()
        .map(|dk| proto::VersionedGroupKey {
            version: dk.version,
            encrypted_key: dk.encrypted_key,
            from_device_id: dk.from_device_id.to_string(),
            from_public_key: dk.from_public_key,
            from_public_key_sig: dk.from_public_key_sig,
            membership: dk.membership.map(|m| m.0),
        })
        .collect();
    let rotation_required = match state.db.rotation_required(claims.user_id).await {
        Ok(required) => required,
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    };

    json_response(
        StatusCode::OK,
        proto::GroupKeysResponse {
            current_version: current_version.version,
            keys: versioned_keys,
            rotation_required,
            rotation_due_at: current_version.rotation_due_at,
        },
    )
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
        Err(_) => {
            return json_error(
                "failed to get approved devices",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let approved_ids: std::collections::HashSet<String> =
        approved.iter().map(|d| d.id.to_string()).collect();
    for entry in &req.wrapped_keys {
        if !approved_ids.contains(&entry.device_id) {
            return json_error(
                &format!("device {} is not approved", entry.device_id),
                StatusCode::FORBIDDEN,
            );
        }
    }

    if let Err(error) =
        validate_memberships(&approved, device_id, req.new_version, &req.wrapped_keys)
    {
        return error.into_response();
    }

    let success = match state
        .db
        .commit_key_rotation(crate::db::KeyRotation {
            user_id: claims.user_id,
            from_device_id: device_id,
            expected_current_version: req.expected_current_version,
            new_version: req.new_version,
            wrapped_keys: &req.wrapped_keys,
            rotation_interval_hours: state.config.group_key_rotation_interval_hours,
            approval: None,
        })
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return json_error(
                &format!("rotation failed: {e}"),
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

    // Notify all devices
    let msg = cpmesh_proto::models::WsMessage {
        msg_type: cpmesh_proto::models::MSG_GROUP_KEY_UPDATED.to_string(),
        payload: json!({"from_device_id": device_id.to_string(), "version": req.new_version}),
    };
    state
        .hub
        .broadcast_to_user(&claims.user_id.to_string(), &device_id.to_string(), &msg)
        .await;

    // Audit
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
        .bind(AUDIT_GROUP_KEY_ROTATE)
        .bind(&ip_str)
        .bind(ua.as_deref())
        .bind(json!({"new_version": req.new_version, "device_id": device_id.to_string()}))
        .execute(&pool)
        .await { tracing::warn!("Failed to persist audit entry: {error}"); }

    json_response(
        StatusCode::OK,
        json!({"message": "key rotated", "version": req.new_version}),
    )
}
