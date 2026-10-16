//! Agent grants (OAuth). Every change takes the user's row lock first, which orders it
//! with device registration and removal and with group key rotations.
//!
//! Also the codes agents sign in with: authorization codes and device codes (only
//! their SHA-256 hashes are stored).

use std::time::Duration;

use sqlx::types::Json;
use uuid::Uuid;

use super::{Db, delete_locked_device};
use crate::models::{OauthCode, OauthGrant, OauthGrantListing};
use crate::oauth::{SLOW_DOWN_STEP, Scopes};

/// The outcome of binding an existing device to a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantBinding {
    /// The grant is now bound to the device. `superseded` is the older grant the device
    /// was bound to, now revoked; the device itself stays, and so does its pairing.
    Bound { superseded: Option<Uuid> },
    /// The grant was already bound to this device.
    Unchanged,
    /// The grant is bound to another device (one grant per agent device).
    OtherDevice,
    /// The grant is revoked, or not one of the user's.
    Revoked,
    /// The user has no such device, or it was rejected or revoked.
    NoDevice,
}

/// A grant revoked by [`Db::revoke_oauth_grant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedGrant {
    pub client_id: String,
    /// The grant's device, removed with it.
    pub device: Option<RemovedDevice>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemovedDevice {
    pub id: Uuid,
    pub was_approved: bool,
}

impl Db {
    /// A new grant. `session_start` is when the user authorized the agent (epoch
    /// seconds), the session start recorded in every token of the grant.
    pub async fn create_oauth_grant(
        &self,
        user_id: Uuid,
        client_id: &str,
        scopes: Scopes,
        agent_name: &str,
        session_start: u64,
    ) -> Result<OauthGrant, sqlx::Error> {
        sqlx::query_as::<_, OauthGrant>(
            "INSERT INTO oauth_grants (user_id, client_id, scopes, agent_name, session_start)
             VALUES ($1, $2, $3, $4, $5) RETURNING *",
        )
        .bind(user_id)
        .bind(client_id)
        .bind(Json(scopes.names()))
        .bind(agent_name)
        .bind(session_start as i64)
        .fetch_one(&self.pool)
        .await
    }

    /// The user's grants in force (neither revoked nor superseded), newest first, with
    /// their devices.
    pub async fn list_oauth_grants(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OauthGrantListing>, sqlx::Error> {
        sqlx::query_as::<_, OauthGrantListing>(
            "SELECT g.id, g.client_id, g.agent_name, g.scopes, g.created_at, g.last_used_at,
                    g.session_start, d.id AS device_id, d.name AS device_name,
                    d.status AS device_status,
                    COALESCE(u.tokens_revoked_before, 0) AS tokens_revoked_before
             FROM oauth_grants g
             JOIN users u ON u.id = g.user_id
             LEFT JOIN devices d ON d.id = g.device_id
             WHERE g.user_id = $1 AND g.revoked_at IS NULL
             ORDER BY g.created_at DESC, g.id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_oauth_grant(&self, grant_id: Uuid) -> Result<Option<OauthGrant>, sqlx::Error> {
        sqlx::query_as::<_, OauthGrant>("SELECT * FROM oauth_grants WHERE id = $1")
            .bind(grant_id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn touch_oauth_grant(&self, grant_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE oauth_grants SET last_used_at = NOW() WHERE id = $1")
            .bind(grant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Binds a grant that has no device yet to an existing device of the user (an
    /// agent registering again with the same key, e.g. after authorizing anew). The
    /// device's previous grant, if any, is superseded.
    pub async fn bind_oauth_grant_device(
        &self,
        grant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
    ) -> Result<GrantBinding, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        let grant: Option<(Option<Uuid>, bool)> = sqlx::query_as(
            "SELECT device_id, revoked_at IS NOT NULL FROM oauth_grants
             WHERE id = $1 AND user_id = $2 FOR UPDATE",
        )
        .bind(grant_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let binding = match grant {
            None | Some((_, true)) => GrantBinding::Revoked,
            Some((Some(bound), false)) if bound == device_id => GrantBinding::Unchanged,
            Some((Some(_), false)) => GrantBinding::OtherDevice,
            Some((None, false)) => {
                let usable: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND user_id = $2
                       AND status NOT IN ('rejected', 'revoked'))",
                )
                .bind(device_id)
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
                if usable {
                    let superseded: Option<Uuid> = sqlx::query_scalar(
                        "UPDATE oauth_grants SET revoked_at = NOW()
                         WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
                         RETURNING id",
                    )
                    .bind(device_id)
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    sqlx::query("UPDATE oauth_grants SET device_id = $2 WHERE id = $1")
                        .bind(grant_id)
                        .bind(device_id)
                        .execute(&mut *tx)
                        .await?;
                    GrantBinding::Bound { superseded }
                } else {
                    GrantBinding::NoDevice
                }
            }
        };
        tx.commit().await?;
        Ok(binding)
    }

    /// Revokes a grant in force and deletes its device in the same transaction (see
    /// [`Db::delete_device`]). `None` when the user has no such grant in force.
    pub async fn revoke_oauth_grant(
        &self,
        grant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<RevokedGrant>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        let revoked: Option<(String, Option<Uuid>)> = sqlx::query_as(
            "UPDATE oauth_grants SET revoked_at = NOW()
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
             RETURNING client_id, device_id",
        )
        .bind(grant_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((client_id, device_id)) = revoked else {
            return Ok(None);
        };
        let mut device = None;
        if let Some(id) = device_id
            && let Some(removal) = delete_locked_device(&mut tx, id, user_id).await?
        {
            device = Some(RemovedDevice {
                id,
                was_approved: removal.was_approved,
            });
        }
        tx.commit().await?;
        Ok(Some(RevokedGrant { client_id, device }))
    }
}

/// An authorization code the user approved, to be exchanged once before it expires.
pub struct NewAuthorizationCode<'a> {
    pub code_hash: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub scopes: Scopes,
    pub agent_name: &'a str,
    pub user_id: Uuid,
    /// The approving session was confirmed with a second factor.
    pub mfa: bool,
    /// When the user approved (epoch seconds).
    pub approved_at: u64,
    pub ttl: Duration,
}

/// A device code waiting for the user's decision.
pub struct NewDeviceCode<'a> {
    pub code_hash: &'a str,
    /// Normalized: eight letters, no dash.
    pub user_code: &'a str,
    pub client_id: &'a str,
    /// What the agent asks for.
    pub scopes: Scopes,
    pub agent_name: &'a str,
    pub requester_ip: &'a str,
    pub user_agent: Option<&'a str>,
    pub interval: Duration,
    pub ttl: Duration,
}

/// The user's decision on a device code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceDecision {
    Approve {
        scopes: Scopes,
        /// The approving session was confirmed with a second factor.
        mfa: bool,
        /// When the user approved (epoch seconds).
        approved_at: u64,
    },
    Deny,
}

/// What an agent polling with a device code learns (RFC 8628 section 3.5).
#[derive(Debug)]
pub enum DevicePoll {
    /// No such device code (or it was used), or it was issued to another client.
    Unknown,
    Denied,
    Expired,
    /// Polled before its interval passed; the interval grew to `interval_secs`.
    SlowDown {
        interval_secs: i32,
    },
    Pending,
    /// Approved: the code is used up, and the agent signs in with it.
    Approved(Box<OauthCode>),
}

impl Db {
    pub async fn create_authorization_code(
        &self,
        code: &NewAuthorizationCode<'_>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO oauth_codes (code_hash, kind, client_id, redirect_uri, code_challenge,
                 scopes, status, user_id, mfa, approved_at, agent_name, expires_at)
             VALUES ($1, 'authorization_code', $2, $3, $4, $5, 'approved', $6, $7, $8, $9,
                 NOW() + make_interval(secs => $10))",
        )
        .bind(code.code_hash)
        .bind(code.client_id)
        .bind(code.redirect_uri)
        .bind(code.code_challenge)
        .bind(Json(code.scopes.names()))
        .bind(code.user_id)
        .bind(code.mfa)
        .bind(code.approved_at as i64)
        .bind(code.agent_name)
        .bind(code.ttl.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Takes an authorization code that has not expired. It is deleted whatever the
    /// caller then finds, so a code works at most once, even for concurrent requests.
    pub async fn take_authorization_code(
        &self,
        code_hash: &str,
    ) -> Result<Option<OauthCode>, sqlx::Error> {
        sqlx::query_as::<_, OauthCode>(
            "DELETE FROM oauth_codes
             WHERE code_hash = $1 AND kind = 'authorization_code' AND expires_at > NOW()
             RETURNING *",
        )
        .bind(code_hash)
        .fetch_optional(&self.pool)
        .await
    }

    /// Stores a device code. Fails with a unique violation when a pending request
    /// already has the user code; the caller picks another.
    pub async fn create_device_code(&self, code: &NewDeviceCode<'_>) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO oauth_codes (code_hash, kind, user_code, client_id, scopes, status,
                 requester_ip, user_agent, agent_name, interval_secs, expires_at)
             VALUES ($1, 'device_code', $2, $3, $4, 'pending', $5, $6, $7, $8,
                 NOW() + make_interval(secs => $9))",
        )
        .bind(code.code_hash)
        .bind(code.user_code)
        .bind(code.client_id)
        .bind(Json(code.scopes.names()))
        .bind(code.requester_ip)
        .bind(code.user_agent)
        .bind(code.agent_name)
        .bind(code.interval.as_secs() as i32)
        .bind(code.ttl.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The pending, unexpired request with this (normalized) user code.
    pub async fn find_pending_device_code(
        &self,
        user_code: &str,
    ) -> Result<Option<OauthCode>, sqlx::Error> {
        sqlx::query_as::<_, OauthCode>(
            "SELECT * FROM oauth_codes
             WHERE user_code = $1 AND kind = 'device_code' AND status = 'pending'
               AND expires_at > NOW()",
        )
        .bind(user_code)
        .fetch_optional(&self.pool)
        .await
    }

    /// Records `user_id`'s decision on a device code that is still pending and has not
    /// expired. `false` otherwise: there is one decision per code.
    pub async fn decide_device_code(
        &self,
        code_hash: &str,
        user_id: Uuid,
        decision: DeviceDecision,
    ) -> Result<bool, sqlx::Error> {
        let result = match decision {
            DeviceDecision::Approve {
                scopes,
                mfa,
                approved_at,
            } => {
                sqlx::query(
                    "UPDATE oauth_codes SET status = 'approved', user_id = $2, scopes = $3,
                         mfa = $4, approved_at = $5
                     WHERE code_hash = $1 AND kind = 'device_code' AND status = 'pending'
                       AND expires_at > NOW()",
                )
                .bind(code_hash)
                .bind(user_id)
                .bind(Json(scopes.names()))
                .bind(mfa)
                .bind(approved_at as i64)
                .execute(&self.pool)
                .await?
            }
            DeviceDecision::Deny => {
                sqlx::query(
                    "UPDATE oauth_codes SET status = 'denied', user_id = $2
                     WHERE code_hash = $1 AND kind = 'device_code' AND status = 'pending'
                       AND expires_at > NOW()",
                )
                .bind(code_hash)
                .bind(user_id)
                .execute(&self.pool)
                .await?
            }
        };
        Ok(result.rows_affected() == 1)
    }

    /// An agent polls with its device code (RFC 8628 section 3.4). Polls of one code are
    /// serialized, so an approved code is used once. Polling a pending code sooner than
    /// its interval allows grows the interval by [`SLOW_DOWN_STEP`].
    pub async fn poll_device_code(
        &self,
        code_hash: &str,
        client_id: &str,
    ) -> Result<DevicePoll, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, String, bool, bool)> = sqlx::query_as(
            "SELECT client_id, status, expires_at <= NOW(),
                    COALESCE(last_polled_at > NOW() - interval_secs * INTERVAL '1 second', FALSE)
             FROM oauth_codes WHERE code_hash = $1 AND kind = 'device_code' FOR UPDATE",
        )
        .bind(code_hash)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((owner, status, expired, too_soon)) = row else {
            return Ok(DevicePoll::Unknown);
        };
        if owner != client_id {
            return Ok(DevicePoll::Unknown);
        }
        let poll = match status.as_str() {
            "denied" => DevicePoll::Denied,
            _ if expired => DevicePoll::Expired,
            "approved" => DevicePoll::Approved(Box::new(
                sqlx::query_as::<_, OauthCode>(
                    "DELETE FROM oauth_codes WHERE code_hash = $1 RETURNING *",
                )
                .bind(code_hash)
                .fetch_one(&mut *tx)
                .await?,
            )),
            _ if too_soon => DevicePoll::SlowDown {
                interval_secs: sqlx::query_scalar(
                    "UPDATE oauth_codes SET interval_secs = interval_secs + $2,
                         last_polled_at = NOW()
                     WHERE code_hash = $1 RETURNING interval_secs",
                )
                .bind(code_hash)
                .bind(SLOW_DOWN_STEP.as_secs() as i32)
                .fetch_one(&mut *tx)
                .await?,
            },
            _ => {
                sqlx::query("UPDATE oauth_codes SET last_polled_at = NOW() WHERE code_hash = $1")
                    .bind(code_hash)
                    .execute(&mut *tx)
                    .await?;
                DevicePoll::Pending
            }
        };
        tx.commit().await?;
        Ok(poll)
    }

    /// Deletes codes that expired over an hour ago. Until then, an agent still polling
    /// with an expired device code is told it expired.
    pub async fn delete_expired_oauth_codes(&self) -> Result<u64, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM oauth_codes WHERE expires_at < NOW() - INTERVAL '1 hour'")
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected())
    }
}
