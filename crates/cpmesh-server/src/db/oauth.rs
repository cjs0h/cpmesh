//! Agent grants (OAuth). Every change takes the user's row lock first, which orders it
//! with device registration and removal and with group key rotations.

use sqlx::types::Json;
use uuid::Uuid;

use super::{Db, delete_locked_device};
use crate::models::OauthGrant;
use crate::oauth::Scopes;

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
    pub async fn create_oauth_grant(
        &self,
        user_id: Uuid,
        client_id: &str,
        scopes: Scopes,
        agent_name: &str,
    ) -> Result<OauthGrant, sqlx::Error> {
        sqlx::query_as::<_, OauthGrant>(
            "INSERT INTO oauth_grants (user_id, client_id, scopes, agent_name)
             VALUES ($1, $2, $3, $4) RETURNING *",
        )
        .bind(user_id)
        .bind(client_id)
        .bind(Json(scopes.names()))
        .bind(agent_name)
        .fetch_one(&self.pool)
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
