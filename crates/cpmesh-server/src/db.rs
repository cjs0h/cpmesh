use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::models::*;
use crate::pii::PiiService;

mod console;
mod mfa;
mod oauth;
mod relay;

pub use console::{AuditFilter, RoleChange, UserListFilter};
pub use mfa::{EmailCodeCheck, MfaSummary};
pub use oauth::{
    DeviceDecision, DevicePoll, GrantBinding, NewAuthorizationCode, NewDeviceCode, RemovedDevice,
    RevokedGrant,
};
pub use relay::{ClipboardWrite, KeyRotation, NewDevice};

/// What removing a device did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRemoval {
    /// The device was approved, so the group key must be rotated without it.
    pub was_approved: bool,
    /// The agent grant that was bound to the device, revoked with it.
    pub revoked_grant: Option<uuid::Uuid>,
}

/// Deletes a device of `user_id` in `tx`, which holds the user's row lock: revokes the
/// agent grant bound to it and, when it was approved, refuses writes until the group
/// key is rotated without it. `None` when the user has no such device.
async fn delete_locked_device(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    device_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> Result<Option<DeviceRemoval>, sqlx::Error> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM devices WHERE id = $1 AND user_id = $2 FOR UPDATE")
            .bind(device_id)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(status) = status else {
        return Ok(None);
    };
    let was_approved = status == "approved";
    if was_approved {
        sqlx::query(
            "UPDATE users SET min_key_version = GREATEST(min_key_version,
                COALESCE((SELECT MAX(version) FROM group_key_versions WHERE user_id = $1), 0) + 1)
             WHERE id = $1",
        )
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE group_key_versions SET rotation_due_at = NOW() WHERE user_id = $1 AND is_current",
        )
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    }
    let revoked_grant = revoke_device_grant(tx, device_id).await?;
    sqlx::query("DELETE FROM devices WHERE id = $1 AND user_id = $2")
        .bind(device_id)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    Ok(Some(DeviceRemoval {
        was_approved,
        revoked_grant,
    }))
}

/// Revokes the agent grant in force for a device, if there is one.
async fn revoke_device_grant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    device_id: uuid::Uuid,
) -> Result<Option<uuid::Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE oauth_grants SET revoked_at = NOW()
         WHERE device_id = $1 AND revoked_at IS NULL RETURNING id",
    )
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await
}

pub struct CreateUserParams<'a> {
    pub username: &'a str,
    pub password_hash: &'a str,
    pub email: &'a str,
    pub full_name: &'a str,
    pub country: Option<&'a str>,
    pub mobile: Option<&'a str>,
    pub pii: Option<&'a PiiService>,
}

pub struct CreateOidcUserParams<'a> {
    pub username: &'a str,
    pub email: &'a str,
    pub full_name: &'a str,
    pub provider: &'a str,
    pub provider_id: &'a str,
    pub avatar_url: Option<&'a str>,
    pub pii: Option<&'a PiiService>,
}

pub struct SubscriptionPlanParams<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub price: rust_decimal::Decimal,
    pub currency: &'a str,
    pub billing_period: &'a str,
    pub max_devices: i32,
    pub max_clipboard_history: i32,
    pub allowed_file_types: &'a serde_json::Value,
    pub is_active: bool,
    pub sort_order: i32,
}

pub struct DownloadLinkParams<'a> {
    pub name: &'a str,
    pub url: &'a str,
    pub platform: &'a str,
    pub arch: &'a str,
    pub format: &'a str,
    pub sort_order: i32,
    pub is_active: bool,
    pub release_id: Option<uuid::Uuid>,
}

pub struct AppReleaseParams<'a> {
    pub version: &'a str,
    pub platform: &'a str,
    pub arch: &'a str,
    pub download_url: &'a str,
    pub release_notes: &'a str,
    pub is_current: bool,
}

pub struct Db {
    pub pool: PgPool,
}

impl Db {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await?;
        Ok(Db { pool })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::raw_sql(SCHEMA).execute(&self.pool).await?;
        Ok(())
    }

    // === User operations ===

    pub async fn create_user(&self, params: CreateUserParams<'_>) -> Result<User, sqlx::Error> {
        let (enc_email, email_idx, enc_full_name, username_idx, enc_country, enc_mobile) =
            encrypt_user_fields(
                params.username,
                params.email,
                params.full_name,
                params.country,
                params.mobile,
                params.pii,
            );

        sqlx::query_as::<_, User>(
            "INSERT INTO users (username, password, email, email_idx, full_name, country, mobile, username_idx, email_verified, auth_provider)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, 'local')
             RETURNING *"
        )
        .bind(params.username)
        .bind(params.password_hash)
        .bind(&enc_email)
        .bind(&email_idx)
        .bind(&enc_full_name)
        .bind(&enc_country)
        .bind(&enc_mobile)
        .bind(&username_idx)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User, sqlx::Error> {
        let idx = username.trim().to_lowercase();
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE username_idx = $1")
            .bind(&idx)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn get_user_by_email(
        &self,
        email: &str,
        pii: Option<&PiiService>,
    ) -> Result<User, sqlx::Error> {
        let idx = if let Some(p) = pii {
            p.blind_index(email)
        } else {
            email.trim().to_lowercase()
        };
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email_idx = $1")
            .bind(&idx)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn get_user_by_id(&self, user_id: uuid::Uuid) -> Result<User, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
    }

    /// Find an OIDC user by provider+subject (using the blind-index column).
    pub async fn get_user_by_provider_id(
        &self,
        provider: &str,
        provider_id: &str,
        pii: Option<&PiiService>,
    ) -> Result<User, sqlx::Error> {
        let idx = if let Some(p) = pii {
            p.blind_index(provider_id)
        } else {
            provider_id.to_string()
        };
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE auth_provider = $1 AND auth_provider_id_idx = $2",
        )
        .bind(provider)
        .bind(&idx)
        .fetch_one(&self.pool)
        .await
    }

    /// Create a user from an OIDC provider. Email is auto-verified, no password.
    pub async fn create_oidc_user(
        &self,
        params: CreateOidcUserParams<'_>,
    ) -> Result<User, sqlx::Error> {
        let (enc_email, email_idx, enc_full_name, username_idx, _, _) = encrypt_user_fields(
            params.username,
            params.email,
            params.full_name,
            None,
            None,
            params.pii,
        );
        let enc_provider_id = if let Some(p) = params.pii {
            p.encrypt(params.provider_id).unwrap_or_default()
        } else {
            params.provider_id.to_string()
        };
        let provider_id_idx = if let Some(p) = params.pii {
            p.blind_index(params.provider_id)
        } else {
            params.provider_id.to_string()
        };

        sqlx::query_as::<_, User>(
            "INSERT INTO users (username, password, email, email_idx, full_name, email_verified, auth_provider, auth_provider_id, auth_provider_id_idx, avatar_url, username_idx)
             VALUES ($1, '', $2, $3, $4, TRUE, $5, $6, $7, $8, $9)
             RETURNING *"
        )
        .bind(params.username)
        .bind(&enc_email)
        .bind(&email_idx)
        .bind(&enc_full_name)
        .bind(params.provider)
        .bind(&enc_provider_id)
        .bind(&provider_id_idx)
        .bind(params.avatar_url)
        .bind(&username_idx)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn change_password(
        &self,
        user_id: uuid::Uuid,
        new_hash: &str,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query(
            "UPDATE users SET password = $1,
             tokens_revoked_before = GREATEST(COALESCE(tokens_revoked_before, 0),
                 FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT + 1)
             WHERE id = $2",
        )
        .bind(new_hash)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    pub async fn set_email_verified(
        &self,
        user_id: uuid::Uuid,
        verified: bool,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query("UPDATE users SET email_verified = $1 WHERE id = $2")
            .bind(verified)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    // === Admin user seeding ===

    pub async fn seed_admin(
        &self,
        username: &str,
        password_hash: &str,
        email: &str,
        pii: Option<&PiiService>,
    ) -> Result<(), sqlx::Error> {
        let username_idx = username.trim().to_lowercase();
        let (enc_email, email_idx) = if let Some(p) = pii {
            let enc = p.encrypt(email).unwrap_or_default();
            let idx = if email.is_empty() {
                String::new()
            } else {
                p.blind_index(email)
            };
            (enc, idx)
        } else {
            (email.to_string(), email.trim().to_lowercase())
        };
        let enc_full_name = if let Some(p) = pii {
            p.encrypt(username).unwrap_or_default()
        } else {
            username.to_string()
        };

        sqlx::query(
            "INSERT INTO users (username, password, is_admin, role, username_idx, email, email_idx, email_verified, auth_provider, full_name)
             VALUES ($1, $2, TRUE, 'owner', $3, $4, NULLIF($5,''), TRUE, 'local', $6)
             ON CONFLICT (username_idx) DO NOTHING"
        )
        .bind(username)
        .bind(password_hash)
        .bind(&username_idx)
        .bind(&enc_email)
        .bind(&email_idx)
        .bind(&enc_full_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // === Device operations ===

    pub async fn create_device(
        &self,
        user_id: uuid::Uuid,
        name: &str,
        public_key: &[u8],
        public_key_sig: Option<&[u8]>,
        status: &str,
        fingerprint: Option<&str>,
    ) -> Result<Device, sqlx::Error> {
        let approved_at = if status == "approved" {
            Some(chrono::Utc::now())
        } else {
            None
        };
        sqlx::query_as::<_, Device>(
            "INSERT INTO devices (user_id, name, public_key, public_key_sig, last_seen, status, approved_at, fingerprint)
             VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7)
             RETURNING *"
        )
        .bind(user_id)
        .bind(name)
        .bind(public_key)
        .bind(public_key_sig)
        .bind(status)
        .bind(approved_at)
        .bind(fingerprint)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_device_by_fingerprint(
        &self,
        user_id: uuid::Uuid,
        fingerprint: &str,
    ) -> Result<Option<Device>, sqlx::Error> {
        sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE user_id = $1 AND fingerprint = $2")
            .bind(user_id)
            .bind(fingerprint)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn reregister_device(
        &self,
        device_id: uuid::Uuid,
        name: &str,
        public_key: &[u8],
        public_key_sig: Option<&[u8]>,
        status: &str,
    ) -> Result<Device, sqlx::Error> {
        let approved_at = if status == "approved" {
            Some(chrono::Utc::now())
        } else {
            None
        };
        // Update device keys/name and reset approval state
        let device = sqlx::query_as::<_, Device>(
            "UPDATE devices SET name = $2, public_key = $3, public_key_sig = $4, status = $5,
             approved_at = $6, approved_by_device_id = NULL, last_seen = NOW()
             WHERE id = $1 RETURNING *",
        )
        .bind(device_id)
        .bind(name)
        .bind(public_key)
        .bind(public_key_sig)
        .bind(status)
        .bind(approved_at)
        .fetch_one(&self.pool)
        .await?;

        // Delete old group keys for this device (encrypted to old public key)
        sqlx::query("DELETE FROM device_group_keys WHERE device_id = $1")
            .bind(device_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM group_keys WHERE device_id = $1")
            .bind(device_id)
            .execute(&self.pool)
            .await?;

        Ok(device)
    }

    pub async fn set_device_fingerprint(
        &self,
        device_id: uuid::Uuid,
        user_id: uuid::Uuid,
        fingerprint: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE devices SET fingerprint = $1 WHERE id = $2 AND user_id = $3 AND fingerprint IS NULL"
        )
        .bind(fingerprint)
        .bind(device_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_devices_by_user(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Vec<Device>, sqlx::Error> {
        sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn get_device_by_id(&self, device_id: uuid::Uuid) -> Result<Device, sqlx::Error> {
        sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(&self.pool)
            .await
    }

    /// Removes a device. When it was approved, writes are refused until the group key
    /// is rotated without it; an agent grant bound to it is revoked with it.
    pub async fn delete_device(
        &self,
        device_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> Result<DeviceRemoval, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        let removal = delete_locked_device(&mut tx, device_id, user_id)
            .await?
            .ok_or(sqlx::Error::RowNotFound)?;
        tx.commit().await?;
        Ok(removal)
    }

    pub async fn update_device_last_seen(&self, device_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE devices SET last_seen = NOW() WHERE id = $1")
            .bind(device_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // === Clipboard operations ===

    pub async fn create_clipboard_entry(
        &self,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
        content_type: &str,
        encrypted_data: &[u8],
        metadata: &str,
        key_version: i32,
    ) -> Result<ClipboardEntryRow, sqlx::Error> {
        sqlx::query_as::<_, ClipboardEntryRow>(
            "INSERT INTO clipboard_entries (user_id, device_id, content_type, encrypted_data, metadata, key_version)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, user_id, device_id, content_type, encrypted_data, metadata, created_at, key_version"
        )
        .bind(user_id)
        .bind(device_id)
        .bind(content_type)
        .bind(encrypted_data)
        .bind(metadata)
        .bind(key_version)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_clipboard_history(
        &self,
        user_id: uuid::Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ClipboardEntryWithDevice>, sqlx::Error> {
        sqlx::query_as::<_, ClipboardEntryWithDevice>(
            "WITH page AS (
                 SELECT id, created_at, OCTET_LENGTH(encrypted_data) + COALESCE(OCTET_LENGTH(metadata), 0) AS size
                 FROM clipboard_entries WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3
             ), bounded AS (
                 SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC, id DESC) AS n,
                     SUM(size) OVER (ORDER BY created_at DESC, id DESC) AS bytes FROM page
             )
             SELECT e.id, e.user_id, e.device_id, d.name as device_name, e.content_type, e.encrypted_data, e.metadata, e.created_at, e.key_version,
                    e.request_id, e.sent_at, e.sender_signature
             FROM clipboard_entries e
             JOIN devices d ON d.id = e.device_id
             JOIN bounded b ON b.id = e.id
             WHERE b.bytes <= 33554432 OR b.n = 1
             ORDER BY e.created_at DESC, e.id DESC"
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn delete_clipboard_entry(
        &self,
        entry_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query("DELETE FROM clipboard_entries WHERE id = $1 AND user_id = $2")
            .bind(entry_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    pub async fn clear_clipboard_history(&self, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM clipboard_entries WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn count_user_clipboard_entries(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM clipboard_entries WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0)
    }

    pub async fn delete_oldest_clipboard_entries(
        &self,
        user_id: uuid::Uuid,
        count: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "DELETE FROM clipboard_entries WHERE id IN (
                SELECT id FROM clipboard_entries WHERE user_id = $1
                ORDER BY created_at ASC LIMIT $2
            )",
        )
        .bind(user_id)
        .bind(count)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // === Group key operations ===

    pub async fn store_group_keys(
        &self,
        from_device_id: uuid::Uuid,
        keys: &[(uuid::Uuid, Vec<u8>)],
    ) -> Result<(), sqlx::Error> {
        for (device_id, encrypted_key) in keys {
            sqlx::query(
                "INSERT INTO group_keys (device_id, encrypted_key, from_device_id, updated_at)
                 VALUES ($1, $2, $3, NOW())
                 ON CONFLICT (device_id) DO UPDATE
                 SET encrypted_key = EXCLUDED.encrypted_key,
                     from_device_id = EXCLUDED.from_device_id,
                     updated_at = NOW()",
            )
            .bind(device_id)
            .bind(encrypted_key)
            .bind(from_device_id)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn get_group_key(&self, device_id: uuid::Uuid) -> Result<GroupKeyRow, sqlx::Error> {
        sqlx::query_as::<_, GroupKeyRow>(
            "SELECT encrypted_key, from_device_id FROM group_keys WHERE device_id = $1",
        )
        .bind(device_id)
        .fetch_one(&self.pool)
        .await
    }

    // === Device approval operations ===

    pub async fn get_device_status(&self, device_id: uuid::Uuid) -> Result<String, sqlx::Error> {
        let row: (String,) = sqlx::query_as("SELECT status FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    pub async fn get_approved_devices_by_user(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Vec<Device>, sqlx::Error> {
        sqlx::query_as::<_, Device>(
            "SELECT * FROM devices WHERE user_id = $1 AND status = 'approved' ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_pending_devices_by_user(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Vec<Device>, sqlx::Error> {
        sqlx::query_as::<_, Device>(
            "SELECT * FROM devices WHERE user_id = $1 AND status = 'pending' ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    /// Sets a device's status. Rejecting or revoking a device also revokes the agent
    /// grant bound to it, which is returned.
    pub async fn update_device_status(
        &self,
        device_id: uuid::Uuid,
        user_id: uuid::Uuid,
        status: &str,
        approved_by: Option<uuid::Uuid>,
    ) -> Result<Option<uuid::Uuid>, sqlx::Error> {
        let approved_at = if status == "approved" {
            Some(chrono::Utc::now())
        } else {
            None
        };
        let mut tx = self.pool.begin().await?;
        // The user lock orders this with binding and revoking agent grants
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        let result = sqlx::query(
            "UPDATE devices SET status = $1, approved_at = COALESCE($2, approved_at), approved_by_device_id = COALESCE($3, approved_by_device_id) WHERE id = $4 AND user_id = $5"
        )
        .bind(status)
        .bind(approved_at)
        .bind(approved_by)
        .bind(device_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        let revoked_grant = if matches!(status, "rejected" | "revoked") {
            revoke_device_grant(&mut tx, device_id).await?
        } else {
            None
        };
        tx.commit().await?;
        Ok(revoked_grant)
    }

    pub async fn create_approval_session(
        &self,
        pending_device_id: uuid::Uuid,
        approver_device_id: uuid::Uuid,
        ttl_secs: i64,
        approver_commit: &[u8],
    ) -> Result<DeviceApprovalSession, sqlx::Error> {
        // Delete any existing session for this pending device first
        sqlx::query("DELETE FROM device_approval_sessions WHERE pending_device_id = $1")
            .bind(pending_device_id)
            .execute(&self.pool)
            .await?;

        sqlx::query_as::<_, DeviceApprovalSession>(
            "INSERT INTO device_approval_sessions (pending_device_id, approver_device_id, status, expires_at, approver_commit)
             VALUES ($1, $2, 'pending', NOW() + make_interval(secs => $3), $4)
             RETURNING *"
        )
        .bind(pending_device_id)
        .bind(approver_device_id)
        .bind(ttl_secs as f64)
        .bind(approver_commit)
        .fetch_one(&self.pool)
        .await
    }

    /// Pending device contributes its SAS nonce once; a different value later is a conflict.
    pub async fn set_pending_nonce(
        &self,
        session_id: uuid::Uuid,
        pending_device_id: uuid::Uuid,
        nonce: &[u8],
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE device_approval_sessions SET pending_nonce = $3
             WHERE id = $1 AND pending_device_id = $2 AND status = 'pending' AND expires_at > NOW()
               AND (pending_nonce IS NULL OR pending_nonce = $3)",
        )
        .bind(session_id)
        .bind(pending_device_id)
        .bind(nonce)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Approver opens its commitment; only after the pending nonce exists.
    pub async fn set_approver_nonce(
        &self,
        session_id: uuid::Uuid,
        approver_device_id: uuid::Uuid,
        nonce: &[u8],
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE device_approval_sessions SET approver_nonce = $3
             WHERE id = $1 AND approver_device_id = $2 AND status = 'pending' AND expires_at > NOW()
               AND pending_nonce IS NOT NULL AND (approver_nonce IS NULL OR approver_nonce = $3)",
        )
        .bind(session_id)
        .bind(approver_device_id)
        .bind(nonce)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Stores a device's identity-certified encryption key (verified by the caller).
    pub async fn set_device_encryption_key(
        &self,
        device_id: uuid::Uuid,
        user_id: uuid::Uuid,
        encryption_key: &[u8],
        encryption_key_sig: &[u8],
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE devices SET encryption_key = $3, encryption_key_sig = $4 WHERE id = $1 AND user_id = $2",
        )
        .bind(device_id)
        .bind(user_id)
        .bind(encryption_key)
        .bind(encryption_key_sig)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_approval_session(
        &self,
        pending_device_id: uuid::Uuid,
    ) -> Result<Option<DeviceApprovalSession>, sqlx::Error> {
        sqlx::query_as::<_, DeviceApprovalSession>(
            "SELECT * FROM device_approval_sessions WHERE pending_device_id = $1 AND status = 'pending' AND expires_at > NOW()"
        )
        .bind(pending_device_id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn complete_approval_session(
        &self,
        session_id: uuid::Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE device_approval_sessions SET status = 'completed' WHERE id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // === Versioned group key operations ===

    pub async fn get_current_group_key_version(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Option<GroupKeyVersion>, sqlx::Error> {
        sqlx::query_as::<_, GroupKeyVersion>(
            "SELECT * FROM group_key_versions WHERE user_id = $1 AND is_current = TRUE",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get_device_group_key(
        &self,
        device_id: uuid::Uuid,
        version: i32,
    ) -> Result<DeviceGroupKey, sqlx::Error> {
        sqlx::query_as::<_, DeviceGroupKey>(
            "SELECT * FROM device_group_keys WHERE device_id = $1 AND version = $2",
        )
        .bind(device_id)
        .bind(version)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn get_device_group_keys_since(
        &self,
        device_id: uuid::Uuid,
        since_version: i32,
    ) -> Result<Vec<DeviceGroupKeyWithSender>, sqlx::Error> {
        sqlx::query_as::<_, DeviceGroupKeyWithSender>(
            "SELECT k.version, k.encrypted_key, k.from_device_id,
                    COALESCE(k.from_public_key, d.public_key) AS from_public_key,
                    COALESCE(k.from_public_key_sig, d.public_key_sig) AS from_public_key_sig,
                    v.membership
             FROM device_group_keys k LEFT JOIN devices d ON d.id = k.from_device_id
             JOIN devices recipient ON recipient.id = k.device_id
             LEFT JOIN group_key_versions v ON v.user_id = recipient.user_id AND v.version = k.version
             WHERE k.device_id = $1 AND k.version > $2 ORDER BY k.version LIMIT 100",
        )
        .bind(device_id)
        .bind(since_version)
        .fetch_all(&self.pool)
        .await
    }

    /// Atomically create a new group key version and store wrapped keys for all devices.
    /// Uses CAS: only succeeds if expected_current_version matches the actual current version.
    /// Returns Ok(true) on success, Ok(false) on version mismatch (CAS failure).
    pub async fn rotate_group_key(
        &self,
        user_id: uuid::Uuid,
        from_device_id: uuid::Uuid,
        expected_current_version: i32,
        new_version: i32,
        wrapped_keys: &[(uuid::Uuid, Vec<u8>)],
        rotation_interval_hours: i64,
    ) -> Result<bool, sqlx::Error> {
        let keys: Vec<_> = wrapped_keys
            .iter()
            .map(|(id, key)| cpmesh_proto::models::StoreGroupKeyEntry {
                device_id: id.to_string(),
                encrypted_key: key.clone(),
                membership: None,
            })
            .collect();
        self.commit_key_rotation(KeyRotation {
            user_id,
            from_device_id,
            expected_current_version,
            new_version,
            wrapped_keys: &keys,
            rotation_interval_hours,
            approval: None,
        })
        .await
    }

    /// Check if rotation is due for a user.
    pub async fn is_rotation_due(&self, user_id: uuid::Uuid) -> Result<bool, sqlx::Error> {
        let row: Option<(bool,)> = sqlx::query_as(
            "SELECT rotation_due_at < NOW() FROM group_key_versions WHERE user_id = $1 AND is_current = TRUE"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(due,)| due).unwrap_or(false))
    }

    // === Subscription plans ===

    pub async fn list_subscription_plans(&self) -> Result<Vec<SubscriptionPlan>, sqlx::Error> {
        sqlx::query_as::<_, SubscriptionPlan>(
            "SELECT * FROM subscription_plans ORDER BY sort_order, created_at",
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn list_active_subscription_plans(
        &self,
    ) -> Result<Vec<SubscriptionPlan>, sqlx::Error> {
        sqlx::query_as::<_, SubscriptionPlan>(
            "SELECT * FROM subscription_plans WHERE is_active = TRUE ORDER BY sort_order, created_at"
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_subscription_plan(
        &self,
        plan_id: uuid::Uuid,
    ) -> Result<SubscriptionPlan, sqlx::Error> {
        sqlx::query_as::<_, SubscriptionPlan>("SELECT * FROM subscription_plans WHERE id = $1")
            .bind(plan_id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn create_subscription_plan(
        &self,
        params: &SubscriptionPlanParams<'_>,
    ) -> Result<SubscriptionPlan, sqlx::Error> {
        sqlx::query_as::<_, SubscriptionPlan>(
            "INSERT INTO subscription_plans (name, description, price, currency, billing_period, max_devices, max_clipboard_history, allowed_file_types, is_active, sort_order)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING *"
        )
        .bind(params.name)
        .bind(params.description)
        .bind(params.price)
        .bind(params.currency)
        .bind(params.billing_period)
        .bind(params.max_devices)
        .bind(params.max_clipboard_history)
        .bind(params.allowed_file_types)
        .bind(params.is_active)
        .bind(params.sort_order)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn update_subscription_plan(
        &self,
        id: uuid::Uuid,
        params: &SubscriptionPlanParams<'_>,
    ) -> Result<SubscriptionPlan, sqlx::Error> {
        sqlx::query_as::<_, SubscriptionPlan>(
            "UPDATE subscription_plans
             SET name=$1, description=$2, price=$3, currency=$4, billing_period=$5,
                 max_devices=$6, max_clipboard_history=$7, allowed_file_types=$8,
                 is_active=$9, sort_order=$10, updated_at=NOW()
             WHERE id=$11
             RETURNING *",
        )
        .bind(params.name)
        .bind(params.description)
        .bind(params.price)
        .bind(params.currency)
        .bind(params.billing_period)
        .bind(params.max_devices)
        .bind(params.max_clipboard_history)
        .bind(params.allowed_file_types)
        .bind(params.is_active)
        .bind(params.sort_order)
        .bind(id)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn delete_subscription_plan(&self, plan_id: uuid::Uuid) -> Result<(), String> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE subscription_plan_id = $1")
                .bind(plan_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| e.to_string())?;
        if count.0 > 0 {
            return Err(format!(
                "cannot delete plan: {} users are still assigned",
                count.0
            ));
        }
        let result = sqlx::query("DELETE FROM subscription_plans WHERE id = $1")
            .bind(plan_id)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        if result.rows_affected() == 0 {
            return Err("plan not found".to_string());
        }
        Ok(())
    }

    /// Fails with `RowNotFound` when the user does not exist.
    pub async fn assign_user_subscription(
        &self,
        user_id: uuid::Uuid,
        plan_id: uuid::Uuid,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query("UPDATE users SET subscription_plan_id = $1 WHERE id = $2")
            .bind(plan_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    /// Fails with `RowNotFound` when the user does not exist.
    pub async fn remove_user_subscription(&self, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        let result = sqlx::query("UPDATE users SET subscription_plan_id = NULL WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    pub async fn get_user_subscription(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<UserSubscriptionInfo, sqlx::Error> {
        let row = sqlx::query_as::<
            _,
            (
                Option<uuid::Uuid>,
                Option<String>,
                Option<String>,
                Option<rust_decimal::Decimal>,
                Option<String>,
                Option<String>,
                Option<i32>,
                Option<i32>,
                Option<serde_json::Value>,
            ),
        >(
            "SELECT sp.id, sp.name, sp.description, sp.price, sp.currency, sp.billing_period,
                    sp.max_devices, sp.max_clipboard_history, sp.allowed_file_types
             FROM users u
             JOIN subscription_plans sp ON sp.id = u.subscription_plan_id
             WHERE u.id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((
                plan_id,
                plan_name,
                plan_description,
                price,
                currency,
                billing_period,
                max_devices,
                max_clipboard_history,
                allowed_file_types,
            )) => {
                let file_types: Vec<String> = allowed_file_types
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_default();
                Ok(UserSubscriptionInfo {
                    plan_id,
                    plan_name,
                    plan_description,
                    price,
                    currency,
                    billing_period,
                    max_devices,
                    max_clipboard_history,
                    allowed_file_types: file_types,
                })
            }
            None => Ok(UserSubscriptionInfo::default()),
        }
    }

    // === Download links ===

    pub async fn list_download_links(&self) -> Result<Vec<DownloadLink>, sqlx::Error> {
        sqlx::query_as::<_, DownloadLink>(
            "SELECT * FROM download_links ORDER BY sort_order, created_at",
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn list_active_download_links(&self) -> Result<Vec<DownloadLink>, sqlx::Error> {
        sqlx::query_as::<_, DownloadLink>(
            "SELECT * FROM download_links WHERE is_active = TRUE ORDER BY sort_order, created_at",
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn create_download_link(
        &self,
        params: &DownloadLinkParams<'_>,
    ) -> Result<DownloadLink, sqlx::Error> {
        sqlx::query_as::<_, DownloadLink>(
            "INSERT INTO download_links (name, url, platform, arch, format, sort_order, is_active, release_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *"
        )
        .bind(params.name)
        .bind(params.url)
        .bind(params.platform)
        .bind(params.arch)
        .bind(params.format)
        .bind(params.sort_order)
        .bind(params.is_active)
        .bind(params.release_id)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn update_download_link(
        &self,
        id: uuid::Uuid,
        params: &DownloadLinkParams<'_>,
    ) -> Result<DownloadLink, sqlx::Error> {
        sqlx::query_as::<_, DownloadLink>(
            "UPDATE download_links SET name=$1, url=$2, platform=$3, arch=$4, format=$5, sort_order=$6, is_active=$7, release_id=$8, updated_at=NOW()
             WHERE id=$9 RETURNING *"
        )
        .bind(params.name)
        .bind(params.url)
        .bind(params.platform)
        .bind(params.arch)
        .bind(params.format)
        .bind(params.sort_order)
        .bind(params.is_active)
        .bind(params.release_id)
        .bind(id)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn delete_download_link(&self, id: uuid::Uuid) -> Result<(), sqlx::Error> {
        let result = sqlx::query("DELETE FROM download_links WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    pub async fn list_downloads_for_current_releases(
        &self,
    ) -> Result<Vec<DownloadLink>, sqlx::Error> {
        sqlx::query_as::<_, DownloadLink>(
            "SELECT dl.* FROM download_links dl
             INNER JOIN app_releases ar ON dl.release_id = ar.id
             WHERE ar.is_current = TRUE AND dl.is_active = TRUE
             ORDER BY dl.sort_order, dl.created_at",
        )
        .fetch_all(&self.pool)
        .await
    }

    // === App Releases ===

    pub async fn list_app_releases(&self) -> Result<Vec<AppRelease>, sqlx::Error> {
        sqlx::query_as::<_, AppRelease>("SELECT * FROM app_releases ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
    }

    pub async fn get_current_release(
        &self,
        platform: &str,
        arch: &str,
    ) -> Result<Option<AppRelease>, sqlx::Error> {
        let row = if arch.is_empty() {
            sqlx::query_as::<_, AppRelease>(
                "SELECT * FROM app_releases WHERE platform = $1 AND is_current = TRUE LIMIT 1",
            )
            .bind(platform)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, AppRelease>(
                "SELECT * FROM app_releases WHERE platform = $1 AND arch = $2 AND is_current = TRUE LIMIT 1"
            )
            .bind(platform)
            .bind(arch)
            .fetch_optional(&self.pool)
            .await?
        };
        Ok(row)
    }

    pub async fn create_app_release(
        &self,
        params: &AppReleaseParams<'_>,
    ) -> Result<AppRelease, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("LOCK TABLE app_releases IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        // Serialize the switch even when there is no previous release to lock.
        if params.is_current {
            sqlx::query("UPDATE app_releases SET is_current = FALSE, updated_at = NOW() WHERE platform = $1 AND arch = $2")
                .bind(params.platform).bind(params.arch)
                .execute(&mut *tx)
                .await?;
        }
        let release = sqlx::query_as::<_, AppRelease>(
            "INSERT INTO app_releases (version, platform, arch, download_url, release_notes, is_current)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *"
        )
        .bind(params.version)
        .bind(params.platform)
        .bind(params.arch)
        .bind(params.download_url)
        .bind(params.release_notes)
        .bind(params.is_current)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(release)
    }

    pub async fn update_app_release(
        &self,
        id: uuid::Uuid,
        params: &AppReleaseParams<'_>,
    ) -> Result<AppRelease, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("LOCK TABLE app_releases IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        if params.is_current {
            sqlx::query("UPDATE app_releases SET is_current = FALSE, updated_at = NOW() WHERE platform = $1 AND arch = $2 AND id != $3")
                .bind(params.platform).bind(params.arch).bind(id)
                .execute(&mut *tx)
                .await?;
        }
        let release = sqlx::query_as::<_, AppRelease>(
            "UPDATE app_releases SET version=$1, platform=$2, arch=$3, download_url=$4, release_notes=$5, is_current=$6, updated_at=NOW()
             WHERE id=$7 RETURNING *"
        )
        .bind(params.version)
        .bind(params.platform)
        .bind(params.arch)
        .bind(params.download_url)
        .bind(params.release_notes)
        .bind(params.is_current)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(release)
    }

    pub async fn delete_app_release(&self, id: uuid::Uuid) -> Result<(), sqlx::Error> {
        let result = sqlx::query("DELETE FROM app_releases WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    // === Admin operations ===

    pub async fn admin_delete_user(&self, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    // === Email verification ===

    pub async fn create_email_verification(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<String, sqlx::Error> {
        use rand::Rng;
        use sha2::{Digest, Sha256};

        let mut token_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);

        // Delete existing verifications for this user
        sqlx::query("DELETE FROM email_verifications WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        sqlx::query(
            "INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(user_id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(token)
    }

    pub async fn verify_email(&self, token: &str) -> Result<(), String> {
        use sha2::{Digest, Sha256};
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));

        let row = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid, DateTime<Utc>)>(
            "SELECT id, user_id, expires_at FROM email_verifications WHERE token_hash = $1",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        let (ver_id, user_id, expires_at) = row.ok_or("invalid verification token")?;

        if chrono::Utc::now() > expires_at {
            return Err("verification token has expired".to_string());
        }

        sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM email_verifications WHERE id = $1")
            .bind(ver_id)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    // === Token revocation ===

    pub async fn persist_revoked_token(
        &self,
        jti: &str,
        user_id: uuid::Uuid,
        expires_at: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO revoked_tokens (jti, user_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (jti) DO NOTHING"
        )
        .bind(jti)
        .bind(user_id)
        .bind(expires_at as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_token_revoked_db(&self, jti: &str) -> Result<bool, sqlx::Error> {
        let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM revoked_tokens WHERE jti = $1")
            .bind(jti)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn revoke_all_user_tokens(
        &self,
        user_id: uuid::Uuid,
        now_epoch: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET tokens_revoked_before = GREATEST(COALESCE(tokens_revoked_before, 0), $1) WHERE id = $2")
            .bind(now_epoch as i64)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn cleanup_expired_revoked_tokens(&self) -> Result<u64, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let result = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    // === Audit logging ===

    pub async fn write_audit_log(
        &self,
        user_id: Option<uuid::Uuid>,
        action: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        details: &serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(user_id)
        .bind(action)
        .bind(ip_address)
        .bind(user_agent)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_audit_logs(
        &self,
        limit: i64,
        offset: i64,
        user_id_filter: Option<uuid::Uuid>,
        action_filter: Option<&str>,
    ) -> Result<Vec<AuditLog>, sqlx::Error> {
        // Use a simple approach: query with all possible filters
        if let (Some(uid), Some(act)) = (user_id_filter, action_filter) {
            sqlx::query_as::<_, AuditLog>(
                "SELECT id, user_id, action, ip_address, user_agent, details, created_at FROM audit_logs WHERE user_id = $3 AND action = $4 ORDER BY created_at DESC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .bind(uid)
            .bind(act)
            .fetch_all(&self.pool)
            .await
        } else if let Some(uid) = user_id_filter {
            sqlx::query_as::<_, AuditLog>(
                "SELECT id, user_id, action, ip_address, user_agent, details, created_at FROM audit_logs WHERE user_id = $3 ORDER BY created_at DESC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .bind(uid)
            .fetch_all(&self.pool)
            .await
        } else if let Some(act) = action_filter {
            sqlx::query_as::<_, AuditLog>(
                "SELECT id, user_id, action, ip_address, user_agent, details, created_at FROM audit_logs WHERE action = $3 ORDER BY created_at DESC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .bind(act)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as::<_, AuditLog>(
                "SELECT id, user_id, action, ip_address, user_agent, details, created_at FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        }
    }
}

// === Helper types ===

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClipboardEntryRow {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub device_id: uuid::Uuid,
    pub content_type: String,
    pub encrypted_data: Vec<u8>,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
    pub key_version: i32,
    #[sqlx(default)]
    pub request_id: Option<uuid::Uuid>,
    #[sqlx(default)]
    pub sent_at: Option<i64>,
    #[sqlx(default)]
    pub sender_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClipboardEntryWithDevice {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub device_id: uuid::Uuid,
    pub device_name: String,
    pub content_type: String,
    pub encrypted_data: Vec<u8>,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
    pub key_version: i32,
    pub request_id: Option<uuid::Uuid>,
    pub sent_at: Option<i64>,
    pub sender_signature: Option<Vec<u8>>,
}

// === PII helper functions ===

fn encrypt_user_fields(
    username: &str,
    email: &str,
    full_name: &str,
    country: Option<&str>,
    mobile: Option<&str>,
    pii: Option<&PiiService>,
) -> (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
) {
    let username_idx = username.trim().to_lowercase();
    if let Some(p) = pii {
        let enc_email = p.encrypt(email).unwrap_or_default();
        let email_idx = p.blind_index(email);
        let enc_full_name = p.encrypt(full_name).unwrap_or_default();
        let enc_country = country.map(|c| p.encrypt(c).unwrap_or_default());
        let enc_mobile = mobile.map(|m| p.encrypt(m).unwrap_or_default());
        (
            enc_email,
            email_idx,
            enc_full_name,
            username_idx,
            enc_country,
            enc_mobile,
        )
    } else {
        let email_idx = email.trim().to_lowercase();
        (
            email.to_string(),
            email_idx,
            full_name.to_string(),
            username_idx,
            country.map(|s| s.to_string()),
            mobile.map(|s| s.to_string()),
        )
    }
}

fn decrypt_optional_field(value: Option<&str>, pii: Option<&PiiService>) -> String {
    match (value, pii) {
        (Some(v), Some(p)) => p.decrypt(v).unwrap_or_default(),
        (Some(v), None) => v.to_string(),
        _ => String::new(),
    }
}

pub fn detect_platform_arch_format(filename: &str) -> (String, String, String) {
    let lower = filename.to_lowercase();
    let platform =
        if lower.contains("windows") || lower.ends_with(".exe") || lower.ends_with(".msi") {
            "windows"
        } else if lower.contains("darwin") || lower.contains("macos") || lower.ends_with(".dmg") {
            "macos"
        } else if lower.contains("linux") || lower.ends_with(".deb") || lower.ends_with(".appimage")
        {
            "linux"
        } else if lower.ends_with(".apk") {
            "android"
        } else {
            "unknown"
        };

    let arch = if lower.contains("arm64") || lower.contains("aarch64") {
        "arm64"
    } else if lower.contains("amd64") || lower.contains("x86_64") || lower.contains("x64") {
        "amd64"
    } else if lower.contains("386") || lower.contains("i686") {
        "386"
    } else {
        ""
    };

    let format = if lower.ends_with(".msi") {
        "msi"
    } else if lower.ends_with(".exe") {
        "exe"
    } else if lower.ends_with(".dmg") {
        "dmg"
    } else if lower.ends_with(".deb") {
        "deb"
    } else if lower.ends_with(".appimage") {
        "appimage"
    } else if lower.ends_with(".apk") {
        "apk"
    } else if lower.ends_with(".tar.gz") {
        "tar.gz"
    } else if lower.ends_with(".zip") {
        "zip"
    } else {
        ""
    };

    (platform.to_string(), arch.to_string(), format.to_string())
}

mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

use chrono::DateTime;
use chrono::Utc;

const SCHEMA: &str = r#"
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        VARCHAR(255) UNIQUE NOT NULL,
    password        VARCHAR(255) NOT NULL,
    email           TEXT,
    email_idx       VARCHAR(64) UNIQUE,
    full_name       TEXT NOT NULL DEFAULT '',
    country         TEXT,
    mobile          TEXT,
    email_verified  BOOLEAN DEFAULT FALSE,
    auth_provider   VARCHAR(50) DEFAULT 'local',
    auth_provider_id TEXT,
    auth_provider_id_idx VARCHAR(64),
    avatar_url      TEXT,
    is_admin        BOOLEAN DEFAULT FALSE,
    subscription_plan_id UUID,
    username_idx    VARCHAR(64) UNIQUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS devices (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    public_key      BYTEA NOT NULL,
    public_key_sig  BYTEA,
    last_seen       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clipboard_entries (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    content_type    VARCHAR(50) NOT NULL,
    encrypted_data  BYTEA NOT NULL,
    metadata        TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_entries_user ON clipboard_entries(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS group_keys (
    device_id       UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    encrypted_key   BYTEA NOT NULL,
    from_device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Device approval status tracking
ALTER TABLE devices ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'approved';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS approved_by_device_id UUID REFERENCES devices(id) ON DELETE SET NULL;

-- Backfill existing devices as approved
UPDATE devices SET approved_at = created_at WHERE approved_at IS NULL AND status = 'approved';

-- Device approval sessions (one active per pending device)
CREATE TABLE IF NOT EXISTS device_approval_sessions (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pending_device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    approver_device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(pending_device_id)
);

-- Versioned group keys
CREATE TABLE IF NOT EXISTS group_key_versions (
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version             INT NOT NULL,
    created_by_device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    rotation_due_at     TIMESTAMPTZ,
    is_current          BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (user_id, version)
);

CREATE TABLE IF NOT EXISTS device_group_keys (
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    version             INT NOT NULL,
    encrypted_key       BYTEA NOT NULL,
    from_device_id      UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (device_id, version)
);

-- Migrate legacy group_keys to versioned tables (idempotent)
INSERT INTO group_key_versions (user_id, version, created_by_device_id, is_current)
SELECT DISTINCT d.user_id, 1, gk.from_device_id, TRUE
FROM group_keys gk JOIN devices d ON d.id = gk.device_id
ON CONFLICT (user_id, version) DO NOTHING;

INSERT INTO device_group_keys (device_id, version, encrypted_key, from_device_id, updated_at)
SELECT device_id, 1, encrypted_key, from_device_id, updated_at FROM group_keys
ON CONFLICT (device_id, version) DO NOTHING;

-- Clipboard entries: add key version
ALTER TABLE clipboard_entries ADD COLUMN IF NOT EXISTS key_version INT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS subscription_plans (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                  VARCHAR(255) NOT NULL,
    description           TEXT DEFAULT '',
    price                 DECIMAL(10,2) DEFAULT 0,
    currency              VARCHAR(10) DEFAULT 'USD',
    billing_period        VARCHAR(50) DEFAULT 'monthly',
    max_devices           INT DEFAULT 5,
    max_clipboard_history INT DEFAULT 100,
    allowed_file_types    JSONB DEFAULT '[]'::jsonb,
    is_active             BOOLEAN DEFAULT TRUE,
    sort_order            INT DEFAULT 0,
    created_at            TIMESTAMPTZ DEFAULT NOW(),
    updated_at            TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_subscription_plan_id_fkey;
DO $$ BEGIN
    ALTER TABLE users ADD CONSTRAINT users_subscription_plan_id_fkey
        FOREIGN KEY (subscription_plan_id) REFERENCES subscription_plans(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS download_links (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    url             TEXT NOT NULL,
    platform        VARCHAR(50) DEFAULT 'unknown',
    arch            VARCHAR(50) DEFAULT '',
    format          VARCHAR(50) DEFAULT '',
    sort_order      INT DEFAULT 0,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_auth_provider ON users(auth_provider, auth_provider_id_idx) WHERE auth_provider_id_idx IS NOT NULL;

CREATE TABLE IF NOT EXISTS email_verifications (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(64) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_email_verifications_token ON email_verifications(token_hash);
CREATE INDEX IF NOT EXISTS idx_email_verifications_user ON email_verifications(user_id);

-- Seed default subscription plans (only if table is empty)
INSERT INTO subscription_plans (name, description, price, currency, billing_period, max_devices, max_clipboard_history, allowed_file_types, is_active, sort_order)
SELECT * FROM (VALUES
  ('Free', 'Get started with basic clipboard sync across your devices.', 0::decimal, 'USD', 'monthly', 2, 50, '["text"]'::jsonb, true, 0),
  ('Pro', 'For power users who need more devices and full media support.', 5.99::decimal, 'USD', 'monthly', 10, 500, '["text","image","file"]'::jsonb, true, 1),
  ('Team', 'Unlimited sync for teams and professionals.', 12.99::decimal, 'USD', 'monthly', 50, 5000, '["text","image","file"]'::jsonb, true, 2)
) AS defaults(name, description, price, currency, billing_period, max_devices, max_clipboard_history, allowed_file_types, is_active, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM subscription_plans);

CREATE TABLE IF NOT EXISTS app_releases (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version         VARCHAR(50) NOT NULL,
    platform        VARCHAR(50) NOT NULL DEFAULT 'unknown',
    arch            VARCHAR(50) NOT NULL DEFAULT '',
    download_url    TEXT NOT NULL,
    release_notes   TEXT DEFAULT '',
    is_current      BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_app_releases_platform ON app_releases(platform, arch);

ALTER TABLE download_links ADD COLUMN IF NOT EXISTS release_id UUID REFERENCES app_releases(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_download_links_release ON download_links(release_id);

-- Revoked JWT tokens (persistent across restarts)
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         VARCHAR(64) PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  BIGINT NOT NULL,
    revoked_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- Per-user bulk token revocation timestamp
ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_revoked_before BIGINT DEFAULT 0;

-- Audit logs for security events
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(100) NOT NULL,
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    details     JSONB DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action, created_at DESC);

-- Stable device fingerprint for re-identification across reinstalls
ALTER TABLE devices ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64);
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_user_fingerprint
    ON devices(user_id, fingerprint) WHERE fingerprint IS NOT NULL;

-- Roles: 'user' for members; viewer, support, admin and owner are staff (see rbac.rs).
-- Admins from before roles existed become owners; is_admin mirrors "is staff".
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user';
UPDATE users SET role = 'owner' WHERE is_admin = TRUE AND role = 'user';
UPDATE users SET is_admin = (role <> 'user') WHERE is_admin IS DISTINCT FROM (role <> 'user');
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_reason TEXT;
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- Two-factor authentication: authenticator app (TOTP) state and lockout
CREATE TABLE IF NOT EXISTS user_mfa (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    totp_secret         TEXT,
    totp_pending_secret TEXT,
    totp_enabled_at     TIMESTAMPTZ,
    totp_last_step      BIGINT NOT NULL DEFAULT 0,
    failed_attempts     INT NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   VARCHAR(64) NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user ON mfa_recovery_codes(user_id);

-- Passkeys (WebAuthn credentials)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BYTEA NOT NULL UNIQUE,
    public_key      BYTEA NOT NULL,
    algorithm       INT NOT NULL,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    transports      JSONB NOT NULL DEFAULT '[]'::jsonb,
    name            VARCHAR(100) NOT NULL,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id);

-- Codes emailed to confirm an account before it sets up two-factor authentication
CREATE TABLE IF NOT EXISTS mfa_email_codes (
    user_id     UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    code_hash   VARCHAR(64) NOT NULL,
    attempts    INT NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- API tokens for automation such as the release workflow (only a hash is stored)
CREATE TABLE IF NOT EXISTS api_tokens (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         VARCHAR(100) NOT NULL,
    token_hash   VARCHAR(64) NOT NULL UNIQUE,
    token_prefix VARCHAR(16) NOT NULL,
    scopes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Settings changed from the admin console; they override environment defaults
CREATE TABLE IF NOT EXISTS app_settings (
    key         VARCHAR(100) PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- One row per user per day with activity, for active-user statistics
CREATE TABLE IF NOT EXISTS user_daily_activity (
    day      DATE NOT NULL,
    user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (day, user_id)
);

-- Admin actions name the account they affected
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_user_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_clipboard_entries_created ON clipboard_entries(created_at);

-- Checksums of installers uploaded to this server
ALTER TABLE download_links ADD COLUMN IF NOT EXISTS sha256 VARCHAR(64);
ALTER TABLE download_links ADD COLUMN IF NOT EXISTS size_bytes BIGINT;

-- Revocation stops writes until a new key excludes the removed device.
ALTER TABLE users ADD COLUMN IF NOT EXISTS min_key_version INT NOT NULL DEFAULT 1;
ALTER TABLE clipboard_entries ADD COLUMN IF NOT EXISTS request_id UUID;
CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_device_request
    ON clipboard_entries(device_id, request_id);
CREATE TABLE IF NOT EXISTS clipboard_requests (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    request_id UUID NOT NULL,
    entry_id UUID NOT NULL,
    payload_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (device_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_clipboard_requests_created ON clipboard_requests(created_at);

-- Preserve the sender identity with each wrap, including after the sender is removed.
ALTER TABLE device_group_keys ADD COLUMN IF NOT EXISTS from_public_key BYTEA;
ALTER TABLE device_group_keys ADD COLUMN IF NOT EXISTS from_public_key_sig BYTEA;
ALTER TABLE group_key_versions ADD COLUMN IF NOT EXISTS membership JSONB;
UPDATE device_group_keys k SET from_public_key = d.public_key, from_public_key_sig = d.public_key_sig
    FROM devices d WHERE d.id = k.from_device_id AND k.from_public_key IS NULL;
ALTER TABLE device_group_keys DROP CONSTRAINT IF EXISTS device_group_keys_from_device_id_fkey;

-- Repair pre-constraint duplicates deterministically before enforcing uniqueness.
WITH ranked AS (
    SELECT user_id, version, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY version DESC) AS n
    FROM group_key_versions WHERE is_current
)
UPDATE group_key_versions v SET is_current = FALSE FROM ranked r
    WHERE v.user_id = r.user_id AND v.version = r.version AND r.n > 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_current_group_key
    ON group_key_versions(user_id) WHERE is_current;

WITH ranked AS (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY platform, arch ORDER BY updated_at DESC, id DESC) AS n
    FROM app_releases WHERE is_current
)
UPDATE app_releases a SET is_current = FALSE FROM ranked r WHERE a.id = r.id AND r.n > 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_current_release
    ON app_releases(platform, arch) WHERE is_current;

-- Protocol v3: a separate, identity-certified ECDH key per device; signed clipboard
-- entries; committed short-authentication-string pairing.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS encryption_key BYTEA;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS encryption_key_sig BYTEA;
ALTER TABLE clipboard_entries ADD COLUMN IF NOT EXISTS sent_at BIGINT;
ALTER TABLE clipboard_entries ADD COLUMN IF NOT EXISTS sender_signature BYTEA;
ALTER TABLE device_approval_sessions ADD COLUMN IF NOT EXISTS approver_commit BYTEA;
ALTER TABLE device_approval_sessions ADD COLUMN IF NOT EXISTS pending_nonce BYTEA;
ALTER TABLE device_approval_sessions ADD COLUMN IF NOT EXISTS approver_nonce BYTEA;

-- OAuth for agents: one grant per agent authorization, bound to the agent's device once
-- it registers. Revoking a grant removes its device; removing the device revokes it.
CREATE TABLE IF NOT EXISTS oauth_grants (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id    TEXT NOT NULL,
    scopes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    device_id    UUID REFERENCES devices(id) ON DELETE SET NULL,
    agent_name   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_oauth_grants_user ON oauth_grants(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_oauth_grants_device ON oauth_grants(device_id);
-- At most one grant in force per device
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_grants_active_device
    ON oauth_grants(device_id) WHERE device_id IS NOT NULL AND revoked_at IS NULL;
-- When the user authorized the agent (epoch seconds), the start of every session of the
-- grant: signing out everywhere after it ends them (see oauth::consent::grant_status)
ALTER TABLE oauth_grants ADD COLUMN IF NOT EXISTS session_start BIGINT NOT NULL DEFAULT 0;

-- Codes of agents signing in: authorization codes (approved, exchanged once) and device
-- codes (RFC 8628) with their user codes. Only SHA-256 hashes of the codes are stored.
CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash      VARCHAR(64) PRIMARY KEY,
    kind           VARCHAR(20) NOT NULL CHECK (kind IN ('authorization_code', 'device_code')),
    user_code      VARCHAR(8),
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT,
    code_challenge TEXT,
    -- Requested while a device code is pending, then what the user approved
    scopes         JSONB NOT NULL DEFAULT '[]'::jsonb,
    status         VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    user_id        UUID REFERENCES users(id) ON DELETE CASCADE,
    -- The approving session was confirmed with a second factor
    mfa            BOOLEAN NOT NULL DEFAULT FALSE,
    -- When the user approved (epoch seconds): the start of the agent's sessions
    approved_at    BIGINT,
    requester_ip   VARCHAR(45),
    user_agent     TEXT,
    agent_name     TEXT NOT NULL DEFAULT '',
    interval_secs  INT NOT NULL DEFAULT 5,
    last_polled_at TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- A user code names a single pending request
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_codes_pending_user_code
    ON oauth_codes(user_code) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires_at);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TEST_PII_HMAC_KEY, TEST_PII_MASTER_KEY};

    fn pii() -> PiiService {
        PiiService::new(TEST_PII_MASTER_KEY, TEST_PII_HMAC_KEY).unwrap()
    }

    #[test]
    fn detect_platform_arch_format_from_filenames() {
        let cases = [
            ("cpmesh_0.1.0_x64-setup.exe", ("windows", "amd64", "exe")),
            ("cpmesh_0.1.0_x64_en-US.msi", ("windows", "amd64", "msi")),
            ("cpmesh_0.1.0_aarch64.dmg", ("macos", "arm64", "dmg")),
            ("cpmesh-darwin-amd64.tar.gz", ("macos", "amd64", "tar.gz")),
            ("cpmesh_0.1.0_amd64.deb", ("linux", "amd64", "deb")),
            (
                "cpmesh_0.1.0_arm64.AppImage",
                ("linux", "arm64", "appimage"),
            ),
            ("cpmesh-linux-386.zip", ("linux", "386", "zip")),
            ("cpmesh-i686-linux.zip", ("linux", "386", "zip")),
            ("cpmesh-release.apk", ("android", "", "apk")),
            ("README.txt", ("unknown", "", "")),
        ];
        for (name, (platform, arch, format)) in cases {
            assert_eq!(
                detect_platform_arch_format(name),
                (platform.to_string(), arch.to_string(), format.to_string()),
                "{name}"
            );
        }
    }

    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex::encode([0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex::encode([]), "");
    }

    #[test]
    fn user_fields_without_pii_are_plain_and_lowercased_indexes() {
        let (email, email_idx, full_name, username_idx, country, mobile) = encrypt_user_fields(
            " Alice ",
            "Alice@Example.COM",
            "Alice Liddell",
            Some("GB"),
            None,
            None,
        );
        assert_eq!(email, "Alice@Example.COM");
        assert_eq!(email_idx, "alice@example.com");
        assert_eq!(full_name, "Alice Liddell");
        assert_eq!(username_idx, "alice");
        assert_eq!(country.as_deref(), Some("GB"));
        assert!(mobile.is_none());
    }

    #[test]
    fn user_fields_with_pii_are_encrypted_and_blind_indexed() {
        let p = pii();
        let (email, email_idx, full_name, username_idx, country, mobile) = encrypt_user_fields(
            "Bob",
            "bob@example.com",
            "Bob Builder",
            Some("US"),
            Some("+1555"),
            Some(&p),
        );
        assert_ne!(email, "bob@example.com");
        assert_eq!(p.decrypt(&email).unwrap(), "bob@example.com");
        assert_eq!(email_idx, p.blind_index("bob@example.com"));
        assert_eq!(p.decrypt(&full_name).unwrap(), "Bob Builder");
        assert_eq!(username_idx, "bob", "usernames are indexed in the clear");
        assert_eq!(p.decrypt(&country.unwrap()).unwrap(), "US");
        assert_eq!(p.decrypt(&mobile.unwrap()).unwrap(), "+1555");
    }

    #[test]
    fn decrypt_optional_field_handles_all_combinations() {
        let p = pii();
        let enc = p.encrypt("hidden").unwrap();
        assert_eq!(decrypt_optional_field(Some(&enc), Some(&p)), "hidden");
        assert_eq!(decrypt_optional_field(Some("plain"), None), "plain");
        assert_eq!(decrypt_optional_field(None, Some(&p)), "");
        assert_eq!(decrypt_optional_field(None, None), "");
        // Undecryptable data degrades to an empty string rather than failing
        assert_eq!(decrypt_optional_field(Some("not-ciphertext"), Some(&p)), "");
    }

    #[test]
    fn schema_creates_every_table_the_code_queries() {
        for table in [
            "users",
            "devices",
            "clipboard_entries",
            "group_keys",
            "subscription_plans",
            "download_links",
            "app_releases",
            "email_verifications",
            "revoked_tokens",
            "audit_logs",
            "device_approval_sessions",
            "group_key_versions",
            "device_group_keys",
            "user_mfa",
            "mfa_recovery_codes",
            "webauthn_credentials",
            "mfa_email_codes",
            "api_tokens",
            "app_settings",
            "user_daily_activity",
            "oauth_grants",
            "oauth_codes",
        ] {
            assert!(
                SCHEMA.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
                "schema is missing table {table}"
            );
        }
    }
}
