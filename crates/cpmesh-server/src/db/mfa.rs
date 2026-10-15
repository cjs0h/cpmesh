//! Two-factor authentication storage: authenticator apps, recovery codes, passkeys and
//! emailed confirmation codes.

use chrono::{DateTime, Utc};

use super::Db;
use crate::models::{UserMfa, WebauthnCredential};

/// Which second factors an account has.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MfaSummary {
    pub totp: bool,
    pub passkeys: i64,
    pub recovery_codes: i64,
}

impl MfaSummary {
    /// The account has a second factor it can sign in with.
    pub fn enabled(&self) -> bool {
        self.totp || self.passkeys > 0
    }

    /// Number of sign-in methods (recovery codes are a fallback, not a method).
    pub fn methods(&self) -> i64 {
        i64::from(self.totp) + self.passkeys
    }
}

/// The outcome of checking an emailed code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailCodeCheck {
    Valid,
    Invalid,
    Expired,
    TooManyAttempts,
    Missing,
}

impl Db {
    pub async fn mfa_summary(&self, user_id: uuid::Uuid) -> Result<MfaSummary, sqlx::Error> {
        let (totp, passkeys, recovery_codes): (bool, i64, i64) = sqlx::query_as(
            "SELECT
                EXISTS (SELECT 1 FROM user_mfa WHERE user_id = $1 AND totp_secret IS NOT NULL),
                (SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1),
                (SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL)",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(MfaSummary {
            totp,
            passkeys,
            recovery_codes,
        })
    }

    pub async fn get_user_mfa(&self, user_id: uuid::Uuid) -> Result<Option<UserMfa>, sqlx::Error> {
        sqlx::query_as::<_, UserMfa>(
            "SELECT user_id, totp_secret, totp_pending_secret, totp_enabled_at, totp_last_step,
                    failed_attempts, locked_until
             FROM user_mfa WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    /// Stores a new (encrypted) authenticator secret until its first code confirms it.
    pub async fn set_pending_totp(
        &self,
        user_id: uuid::Uuid,
        encrypted_secret: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO user_mfa (user_id, totp_pending_secret) VALUES ($1, $2)
             ON CONFLICT (user_id) DO UPDATE SET totp_pending_secret = $2, updated_at = NOW()",
        )
        .bind(user_id)
        .bind(encrypted_secret)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Promotes the pending secret, recording the step of the code that confirmed it.
    pub async fn enable_totp(
        &self,
        user_id: uuid::Uuid,
        encrypted_secret: &str,
        step: i64,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query(
            "UPDATE user_mfa SET totp_secret = $2, totp_pending_secret = NULL,
                    totp_enabled_at = NOW(), totp_last_step = $3, updated_at = NOW()
             WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(encrypted_secret)
        .bind(step)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    pub async fn disable_totp(&self, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE user_mfa SET totp_secret = NULL, totp_pending_secret = NULL,
                    totp_enabled_at = NULL, updated_at = NOW()
             WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Records that the code of `step` was used. Returns `false` when that step (or a
    /// later one) was already used, so concurrent requests cannot both use a code.
    pub async fn record_totp_step(
        &self,
        user_id: uuid::Uuid,
        step: i64,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE user_mfa SET totp_last_step = $2, updated_at = NOW()
             WHERE user_id = $1 AND totp_last_step < $2",
        )
        .bind(user_id)
        .bind(step)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Counts a failed second-factor attempt. After `lock_after` consecutive failures the
    /// account's second factor is locked for `lock_secs`; returns whether that happened now.
    pub async fn record_mfa_failure(
        &self,
        user_id: uuid::Uuid,
        lock_after: i32,
        lock_secs: i64,
    ) -> Result<bool, sqlx::Error> {
        let (failures,): (i32,) = sqlx::query_as(
            "INSERT INTO user_mfa (user_id, failed_attempts) VALUES ($1, 1)
             ON CONFLICT (user_id) DO UPDATE SET failed_attempts = user_mfa.failed_attempts + 1,
                                                 updated_at = NOW()
             RETURNING failed_attempts",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        if failures < lock_after {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE user_mfa SET failed_attempts = 0,
                    locked_until = NOW() + make_interval(secs => $2), updated_at = NOW()
             WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(lock_secs as f64)
        .execute(&self.pool)
        .await?;
        Ok(true)
    }

    pub async fn clear_mfa_failures(&self, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE user_mfa SET failed_attempts = 0, locked_until = NULL
             WHERE user_id = $1 AND (failed_attempts <> 0 OR locked_until IS NOT NULL)",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// When the account's second factor is locked after failed attempts, until when.
    pub async fn mfa_locked_until(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
        let row: Option<(Option<DateTime<Utc>>,)> = sqlx::query_as(
            "SELECT locked_until FROM user_mfa WHERE user_id = $1 AND locked_until > NOW()",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(until,)| until))
    }

    /// Replaces every recovery code of the account with `hashes`.
    pub async fn replace_recovery_codes(
        &self,
        user_id: uuid::Uuid,
        hashes: &[String],
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for hash in hashes {
            sqlx::query("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)")
                .bind(user_id)
                .bind(hash)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await
    }

    /// Uses up a recovery code. Returns `false` when it is unknown or already used.
    pub async fn use_recovery_code(
        &self,
        user_id: uuid::Uuid,
        hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE mfa_recovery_codes SET used_at = NOW()
             WHERE id = (SELECT id FROM mfa_recovery_codes
                         WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
                         LIMIT 1 FOR UPDATE SKIP LOCKED)",
        )
        .bind(user_id)
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_webauthn_credentials(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Vec<WebauthnCredential>, sqlx::Error> {
        sqlx::query_as::<_, WebauthnCredential>(
            "SELECT id, user_id, credential_id, public_key, algorithm, sign_count, transports,
                    name, backup_eligible, created_at, last_used_at
             FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn add_webauthn_credential(
        &self,
        user_id: uuid::Uuid,
        credential: &crate::mfa::webauthn::NewCredential,
        name: &str,
    ) -> Result<WebauthnCredential, sqlx::Error> {
        sqlx::query_as::<_, WebauthnCredential>(
            "INSERT INTO webauthn_credentials
                (user_id, credential_id, public_key, algorithm, sign_count, transports, name, backup_eligible)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, user_id, credential_id, public_key, algorithm, sign_count, transports,
                       name, backup_eligible, created_at, last_used_at",
        )
        .bind(user_id)
        .bind(&credential.credential_id)
        .bind(&credential.public_key)
        .bind(credential.algorithm as i32)
        .bind(i64::from(credential.sign_count))
        .bind(serde_json::json!(credential.transports))
        .bind(name)
        .bind(credential.backup_eligible)
        .fetch_one(&self.pool)
        .await
    }

    /// Records a successful assertion. Returns `false` when another assertion moved the
    /// counter in the meantime, so a cloned authenticator cannot race the real one.
    pub async fn record_webauthn_use(
        &self,
        id: uuid::Uuid,
        previous_count: i64,
        sign_count: i64,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE webauthn_credentials SET sign_count = $3, last_used_at = NOW()
             WHERE id = $1 AND sign_count = $2",
        )
        .bind(id)
        .bind(previous_count)
        .bind(sign_count)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_webauthn_credential(
        &self,
        user_id: uuid::Uuid,
        id: uuid::Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn rename_webauthn_credential(
        &self,
        user_id: uuid::Uuid,
        id: uuid::Uuid,
        name: &str,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("UPDATE webauthn_credentials SET name = $1 WHERE id = $2 AND user_id = $3")
                .bind(name)
                .bind(id)
                .bind(user_id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Removes every second factor of an account (an administrator's reset).
    pub async fn reset_user_mfa(&self, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        for statement in [
            "DELETE FROM user_mfa WHERE user_id = $1",
            "DELETE FROM mfa_recovery_codes WHERE user_id = $1",
            "DELETE FROM webauthn_credentials WHERE user_id = $1",
            "DELETE FROM mfa_email_codes WHERE user_id = $1",
        ] {
            sqlx::query(statement)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await
    }

    /// Stores the hash of a freshly emailed code, replacing any earlier one.
    pub async fn store_email_code(
        &self,
        user_id: uuid::Uuid,
        code_hash: &str,
        ttl_secs: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO mfa_email_codes (user_id, code_hash, attempts, expires_at, created_at)
             VALUES ($1, $2, 0, NOW() + make_interval(secs => $3), NOW())
             ON CONFLICT (user_id) DO UPDATE
                SET code_hash = $2, attempts = 0,
                    expires_at = NOW() + make_interval(secs => $3), created_at = NOW()",
        )
        .bind(user_id)
        .bind(code_hash)
        .bind(ttl_secs as f64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// When the current emailed code was sent, if one is outstanding.
    pub async fn email_code_sent_at(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
        let row: Option<(Option<DateTime<Utc>>,)> = sqlx::query_as(
            "SELECT created_at FROM mfa_email_codes WHERE user_id = $1 AND expires_at > NOW()",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(at,)| at))
    }

    /// Checks an emailed code. A correct, expired or exhausted code is used up.
    pub async fn check_email_code(
        &self,
        user_id: uuid::Uuid,
        code_hash: &str,
        max_attempts: i32,
    ) -> Result<EmailCodeCheck, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, i32, bool)> = sqlx::query_as(
            "SELECT code_hash, attempts, expires_at <= NOW()
             FROM mfa_email_codes WHERE user_id = $1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((stored, attempts, expired)) = row else {
            return Ok(EmailCodeCheck::Missing);
        };

        let outcome = if expired {
            EmailCodeCheck::Expired
        } else if attempts >= max_attempts {
            EmailCodeCheck::TooManyAttempts
        } else if aws_lc_rs::constant_time::verify_slices_are_equal(
            stored.as_bytes(),
            code_hash.as_bytes(),
        )
        .is_ok()
        {
            EmailCodeCheck::Valid
        } else {
            EmailCodeCheck::Invalid
        };

        if outcome == EmailCodeCheck::Invalid {
            sqlx::query("UPDATE mfa_email_codes SET attempts = attempts + 1 WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query("DELETE FROM mfa_email_codes WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(outcome)
    }
}
