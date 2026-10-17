use cpmesh_proto::models::{ClipboardPushPayload, StoreGroupKeyEntry};
use sha2::{Digest, Sha256};
use sqlx::types::Json;
use uuid::Uuid;

use super::{ClipboardEntryRow, Db};
use crate::models::{ClipboardMetadata, Device};

pub struct KeyRotation<'a> {
    pub user_id: Uuid,
    pub from_device_id: Uuid,
    pub expected_current_version: i32,
    pub new_version: i32,
    pub wrapped_keys: &'a [StoreGroupKeyEntry],
    pub rotation_interval_hours: i64,
    pub approval: Option<(Uuid, Uuid)>,
}

pub enum ClipboardWrite {
    Accepted {
        entry: ClipboardEntryRow,
        inserted: bool,
    },
    Rejected(&'static str),
    Replay {
        entry_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    },
}

/// The outcome of registering a new device.
pub enum NewDevice {
    Registered(Box<Device>),
    /// The account has as many devices as its plan allows.
    LimitReached,
    /// The agent grant registering it is revoked.
    GrantRevoked,
    /// The agent grant registering it already has a device (one per grant).
    GrantHasDevice,
}

impl Db {
    /// Registers a new device; the first device of an account is approved, later ones
    /// wait for approval. A device registered by an agent is bound to its grant.
    pub async fn register_device(
        &self,
        user_id: Uuid,
        req: &cpmesh_proto::models::RegisterDeviceRequest,
        max_devices: i64,
        grant_id: Option<Uuid>,
    ) -> Result<NewDevice, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        if let Some(grant_id) = grant_id {
            let grant: Option<(bool, bool)> = sqlx::query_as(
                "SELECT revoked_at IS NOT NULL, device_id IS NOT NULL FROM oauth_grants
                 WHERE id = $1 AND user_id = $2 FOR UPDATE",
            )
            .bind(grant_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
            match grant {
                None | Some((true, _)) => return Ok(NewDevice::GrantRevoked),
                Some((false, true)) => return Ok(NewDevice::GrantHasDevice),
                Some((false, false)) => {}
            }
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        if count >= max_devices {
            return Ok(NewDevice::LimitReached);
        }
        let status = if count == 0 { "approved" } else { "pending" };
        let device = sqlx::query_as::<_, Device>(
            "INSERT INTO devices (user_id, name, public_key, public_key_sig, status, fingerprint, approved_at, encryption_key, encryption_key_sig)
             VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $5 = 'approved' THEN NOW() ELSE NULL END, $7, $8) RETURNING *",
        ).bind(user_id).bind(&req.name).bind(&req.public_key).bind(&req.public_key_sig)
            .bind(status).bind(&req.fingerprint).bind(&req.encryption_key).bind(&req.encryption_key_sig)
            .fetch_one(&mut *tx).await?;
        if let Some(grant_id) = grant_id {
            sqlx::query("UPDATE oauth_grants SET device_id = $2 WHERE id = $1")
                .bind(grant_id)
                .bind(device.id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(NewDevice::Registered(Box::new(device)))
    }

    pub async fn rotation_required(&self, user_id: Uuid) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT min_key_version > COALESCE(
                (SELECT version FROM group_key_versions WHERE user_id = $1 AND is_current), 0)
             FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
    }

    /// The user lock serializes membership changes, rotations and clipboard commits.
    pub async fn commit_key_rotation(&self, p: KeyRotation<'_>) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(p.user_id)
            .fetch_one(&mut *tx)
            .await?;
        let actual: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) FROM group_key_versions WHERE user_id = $1",
        )
        .bind(p.user_id)
        .fetch_one(&mut *tx)
        .await?;
        if actual != p.expected_current_version || actual.checked_add(1) != Some(p.new_version) {
            return Ok(false);
        }
        let devices = sqlx::query_as::<_, Device>(
            "SELECT * FROM devices WHERE user_id = $1 AND (status = 'approved' OR id = $2)",
        )
        .bind(p.user_id)
        .bind(p.approval.map(|(id, _)| id))
        .fetch_all(&mut *tx)
        .await?;
        let Some(sender) = devices
            .iter()
            .find(|d| d.id == p.from_device_id && d.status == "approved")
        else {
            return Ok(false);
        };
        let ids: std::collections::HashSet<_> = p
            .wrapped_keys
            .iter()
            .map(|k| k.device_id.as_str())
            .collect();
        if ids.len() != p.wrapped_keys.len()
            || ids.len() != devices.len()
            || devices
                .iter()
                .any(|d| !ids.contains(d.id.to_string().as_str()))
        {
            return Ok(false);
        }
        if let Some((pending, session)) = p.approval {
            let valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM device_approval_sessions s
                 JOIN devices d ON d.id = s.pending_device_id
                 WHERE s.id = $1 AND s.pending_device_id = $2 AND s.approver_device_id = $3
                   AND s.status = 'pending' AND s.expires_at > NOW() AND d.status = 'pending')",
            )
            .bind(session)
            .bind(pending)
            .bind(p.from_device_id)
            .fetch_one(&mut *tx)
            .await?;
            if !valid {
                return Ok(false);
            }
            sqlx::query("UPDATE devices SET status = 'approved', approved_at = NOW(), approved_by_device_id = $2 WHERE id = $1")
                .bind(pending).bind(p.from_device_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE device_approval_sessions SET status = 'completed' WHERE id = $1")
                .bind(session)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "UPDATE group_key_versions SET is_current = FALSE WHERE user_id = $1 AND is_current",
        )
        .bind(p.user_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO group_key_versions (user_id, version, created_by_device_id, rotation_due_at, is_current, membership)
             VALUES ($1, $2, $3, $4, TRUE, $5)",
        ).bind(p.user_id).bind(p.new_version).bind(p.from_device_id)
            .bind(chrono::Utc::now() + chrono::Duration::hours(p.rotation_interval_hours))
            .bind(p.wrapped_keys.iter().find_map(|key| key.membership.as_ref()).map(Json))
            .execute(&mut *tx).await?;
        for key in p.wrapped_keys {
            let recipient = Uuid::parse_str(&key.device_id)
                .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
            sqlx::query(
                "INSERT INTO device_group_keys
                 (device_id, version, encrypted_key, from_device_id, from_public_key, from_public_key_sig)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            ).bind(recipient).bind(p.new_version).bind(&key.encrypted_key).bind(p.from_device_id)
                .bind(&sender.public_key).bind(&sender.public_key_sig).execute(&mut *tx).await?;
        }
        sqlx::query(
            "UPDATE users SET min_key_version = GREATEST(min_key_version, $2) WHERE id = $1",
        )
        .bind(p.user_id)
        .bind(p.new_version)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn persist_clipboard_push(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        request_id: Uuid,
        payload: &ClipboardPushPayload,
        max_history: Option<i32>,
        issued_at: u64,
    ) -> Result<ClipboardWrite, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let (minimum, revoked, suspended): (i32, i64, bool) = sqlx::query_as(
            "SELECT min_key_version, COALESCE(tokens_revoked_before, 0), suspended_at IS NOT NULL
             FROM users WHERE id = $1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        if suspended || (issued_at as i64) < revoked {
            return Ok(ClipboardWrite::Rejected("session_revoked"));
        }
        let approved: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND user_id = $2 AND status = 'approved')",
        ).bind(device_id).bind(user_id).fetch_one(&mut *tx).await?;
        if !approved {
            return Ok(ClipboardWrite::Rejected("device_revoked"));
        }
        let metadata = payload.metadata.as_deref().unwrap_or_default();
        let content_type = payload.content_type.to_string();
        let signature = payload.sender_signature.as_deref().unwrap_or_default();
        let mut hash = Sha256::new();
        for part in [
            content_type.as_bytes(),
            payload.encrypted_data.as_slice(),
            metadata.as_bytes(),
            signature,
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        hash.update(payload.key_version.to_be_bytes());
        hash.update(payload.sent_at.unwrap_or_default().to_be_bytes());
        let digest = hash.finalize().to_vec();
        let receipt: Option<(Uuid, chrono::DateTime<chrono::Utc>, Vec<u8>)> = sqlx::query_as(
            "SELECT entry_id, created_at, payload_hash FROM clipboard_requests
             WHERE user_id = $1 AND device_id = $2 AND request_id = $3",
        )
        .bind(user_id)
        .bind(device_id)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((entry_id, created_at, previous_hash)) = receipt {
            return Ok(if digest == previous_hash {
                ClipboardWrite::Replay {
                    entry_id,
                    created_at,
                }
            } else {
                ClipboardWrite::Rejected("request_id_conflict")
            });
        }
        if let Some(entry) = sqlx::query_as::<_, ClipboardEntryRow>(
            "SELECT * FROM clipboard_entries WHERE device_id = $1 AND request_id = $2",
        )
        .bind(device_id)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            if entry.encrypted_data != payload.encrypted_data
                || entry.metadata.as_deref().unwrap_or_default() != metadata
                || entry.key_version != payload.key_version
                || entry.content_type != payload.content_type.to_string()
                || entry.sent_at != payload.sent_at
                || entry.sender_signature.as_deref().unwrap_or_default() != signature
            {
                return Ok(ClipboardWrite::Rejected("request_id_conflict"));
            }
            return Ok(ClipboardWrite::Accepted {
                entry,
                inserted: false,
            });
        }
        let current: Option<i32> = sqlx::query_scalar(
            "SELECT version FROM group_key_versions WHERE user_id = $1 AND is_current",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        if current != Some(payload.key_version) || payload.key_version < minimum {
            return Ok(ClipboardWrite::Rejected("rotation_required"));
        }
        let entry = sqlx::query_as::<_, ClipboardEntryRow>(
            "INSERT INTO clipboard_entries (user_id, device_id, request_id, content_type, encrypted_data, metadata, key_version, sent_at, sender_signature)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *",
        ).bind(user_id).bind(device_id).bind(request_id).bind(payload.content_type.to_string())
            .bind(&payload.encrypted_data).bind(metadata).bind(payload.key_version)
            .bind(payload.sent_at).bind(&payload.sender_signature)
            .fetch_one(&mut *tx).await?;
        sqlx::query(
                "INSERT INTO clipboard_requests (user_id, device_id, request_id, entry_id, payload_hash, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            ).bind(user_id).bind(device_id).bind(request_id).bind(entry.id).bind(&digest).bind(entry.created_at)
                .execute(&mut *tx).await?;
        if let Some(limit) = max_history.filter(|n| *n > 0) {
            sqlx::query(
                "DELETE FROM clipboard_entries WHERE id IN
                 (SELECT id FROM clipboard_entries WHERE user_id = $1 ORDER BY created_at DESC, id DESC OFFSET $2)",
            ).bind(user_id).bind(i64::from(limit)).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(ClipboardWrite::Accepted {
            entry,
            inserted: true,
        })
    }

    pub async fn clipboard_metadata(
        &self,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ClipboardMetadata>, sqlx::Error> {
        sqlx::query_as(
            "SELECT e.id, e.device_id, d.name AS device_name, e.content_type,
                    OCTET_LENGTH(e.encrypted_data) AS encrypted_size, e.created_at, e.key_version
             FROM clipboard_entries e JOIN devices d ON d.id = e.device_id
             WHERE e.user_id = $1 ORDER BY e.created_at DESC, e.id DESC LIMIT $2 OFFSET $3",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
    }
}
