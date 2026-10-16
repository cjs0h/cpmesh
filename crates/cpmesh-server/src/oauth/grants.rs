//! Agent grants: one per agent authorization, bound to the agent's device once it
//! registers. Every agent request checks its grant. Revoking a grant removes its device
//! the way removing a device does, and removing or rejecting the device revokes the
//! grant (`db::delete_locked_device`, `Db::update_device_status`).

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use super::AgentClaims;
use crate::AppState;
use crate::audit::{self, RequestMeta};
use crate::models::{AUDIT_OAUTH_GRANT_REVOKE, OauthGrant};
use crate::routes::middleware::{ApiError, AuthClaims};

/// A grant's `last_used_at` is updated at most this often.
const TOUCH_INTERVAL: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

/// Why a grant was revoked, as recorded in the audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeReason {
    /// The user revoked the agent.
    User,
    /// The agent revoked its own token or signed out.
    Client,
    /// A refresh token of the grant was used twice.
    TokenReuse,
    /// The agent's device was bound to a newer grant (authorized again).
    Superseded,
    /// The grant's device was removed.
    DeviceRemoved,
    /// The grant's device was rejected.
    DeviceRejected,
}

impl RevokeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RevokeReason::User => "user",
            RevokeReason::Client => "client",
            RevokeReason::TokenReuse => "token_reuse",
            RevokeReason::Superseded => "superseded",
            RevokeReason::DeviceRemoved => "device_removed",
            RevokeReason::DeviceRejected => "device_rejected",
        }
    }
}

/// Whether `grant` still backs a session of `user_id` as `agent`: the same user and
/// client, not revoked, and bound to the session's device when the session has one.
pub fn grant_in_force(
    grant: &OauthGrant,
    user_id: Uuid,
    agent: &AgentClaims,
    device_id: Option<Uuid>,
) -> bool {
    grant.id == agent.grant_id
        && grant.user_id == user_id
        && grant.client_id == agent.client_id
        && grant.revoked_at.is_none()
        && device_id.is_none_or(|device| grant.device_id == Some(device))
}

/// Confirms an agent session's grant is still in force, and notes that it was used.
pub(crate) async fn check_grant(
    state: &AppState,
    claims: &AuthClaims,
    agent: &AgentClaims,
) -> Result<(), ApiError> {
    match state.db.get_oauth_grant(agent.grant_id).await {
        Ok(Some(grant)) if grant_in_force(&grant, claims.user_id, agent, claims.device_id) => {
            note_use(state, &grant);
            Ok(())
        }
        Ok(_) => Err(grant_revoked()),
        Err(e) => {
            tracing::warn!("Failed to look up agent grant: {e}");
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily unavailable, please retry",
            ))
        }
    }
}

/// Updates the grant's `last_used_at` in the background, at most every few minutes.
pub(crate) fn note_use(state: &AppState, grant: &OauthGrant) {
    if grant
        .last_used_at
        .is_some_and(|used| chrono::Utc::now() - used < TOUCH_INTERVAL)
    {
        return;
    }
    let db = crate::db::Db {
        pool: state.db.pool.clone(),
    };
    let id = grant.id;
    tokio::spawn(async move {
        if let Err(e) = db.touch_oauth_grant(id).await {
            tracing::warn!("Failed to note agent grant use: {e}");
        }
    });
}

/// `401` for a session whose grant was revoked (or never existed).
pub(crate) fn grant_revoked() -> ApiError {
    ApiError::coded(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "this agent's access was revoked; sign in again",
    )
    .with_challenge("Bearer error=\"invalid_token\"")
}

/// Revokes a grant and removes its device the same way removing a device does: in one
/// transaction with the grant, then its sockets close and, when it was approved, the
/// user's devices are asked to rotate the group key. Audited as `oauth.grant.revoke`.
/// Returns `false` when the user has no such grant in force.
pub async fn revoke_grant(
    state: &AppState,
    user_id: Uuid,
    grant_id: Uuid,
    reason: RevokeReason,
    meta: &RequestMeta,
) -> Result<bool, sqlx::Error> {
    let Some(revoked) = state.db.revoke_oauth_grant(grant_id, user_id).await? else {
        return Ok(false);
    };
    if let Some(device) = revoked.device {
        crate::routes::devices::device_removed(state, user_id, device.id, device.was_approved)
            .await;
    }
    audit::record(
        state,
        Some(user_id),
        None,
        AUDIT_OAUTH_GRANT_REVOKE,
        meta,
        json!({
            "grant_id": grant_id,
            "client_id": revoked.client_id,
            "reason": reason.as_str(),
            "device_id": revoked.device.map(|d| d.id),
            "was_approved": revoked.device.is_some_and(|d| d.was_approved),
        }),
    )
    .await;
    Ok(true)
}

/// Audits a grant that ended with its device (removed, rejected) or that a newer grant
/// superseded; the device change itself was already made.
pub(crate) async fn record_revocation(
    state: &AppState,
    user_id: Uuid,
    grant_id: Uuid,
    device_id: Uuid,
    reason: RevokeReason,
    meta: &RequestMeta,
) {
    audit::record(
        state,
        Some(user_id),
        None,
        AUDIT_OAUTH_GRANT_REVOKE,
        meta,
        json!({ "grant_id": grant_id, "reason": reason.as_str(), "device_id": device_id }),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{MCP_CLIENT_ID, Scope, Scopes};

    fn grant(user_id: Uuid, device_id: Option<Uuid>) -> OauthGrant {
        OauthGrant {
            id: Uuid::new_v4(),
            user_id,
            client_id: MCP_CLIENT_ID.into(),
            scopes: sqlx::types::Json(vec!["clipboard:read".into()]),
            device_id,
            agent_name: "Test agent".into(),
            created_at: chrono::Utc::now(),
            last_used_at: None,
            revoked_at: None,
            session_start: 0,
        }
    }

    #[test]
    fn grants_back_only_their_own_sessions() {
        let (user, device) = (Uuid::new_v4(), Uuid::new_v4());
        let bound = grant(user, Some(device));
        let agent = AgentClaims {
            client_id: MCP_CLIENT_ID,
            scopes: Scopes::of(&[Scope::ClipboardRead]),
            grant_id: bound.id,
        };
        assert_eq!(bound.scopes(), agent.scopes);
        assert!(grant_in_force(&bound, user, &agent, Some(device)));
        // Before registration the session has no device yet
        assert!(grant_in_force(&bound, user, &agent, None));

        assert!(!grant_in_force(
            &bound,
            Uuid::new_v4(),
            &agent,
            Some(device)
        ));
        assert!(!grant_in_force(&bound, user, &agent, Some(Uuid::new_v4())));
        let other = AgentClaims {
            grant_id: Uuid::new_v4(),
            ..agent
        };
        assert!(!grant_in_force(&bound, user, &other, Some(device)));
        let unbound = OauthGrant {
            id: bound.id,
            ..grant(user, None)
        };
        assert!(!grant_in_force(&unbound, user, &agent, Some(device)));
        let revoked = OauthGrant {
            revoked_at: Some(chrono::Utc::now()),
            ..bound.clone()
        };
        assert!(!grant_in_force(&revoked, user, &agent, Some(device)));
        let foreign_client = OauthGrant {
            client_id: "someone-else".into(),
            ..bound
        };
        assert!(!grant_in_force(&foreign_client, user, &agent, Some(device)));
    }
}
