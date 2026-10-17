//! The dashboard's side of agents signing in, for first-party sessions:
//!
//! - `POST /api/oauth/authorize`: the user approves or denies an authorization request
//!   (code flow) on the consent page, `/#/authorize`.
//! - `GET /api/oauth/device`, `POST /api/oauth/device/approve` and `.../deny`: the same
//!   for a device code, found by its user code (`/#/activate`).
//! - `GET /api/oauth/grants` and `DELETE /api/oauth/grants/{id}`: "Connected agents".
//!
//! Approving or denying needs a recent sign-in, confirmed with a second factor when the
//! account needs one. The coded errors are the desktop handoff's (`reauth_required`,
//! `mfa_required`), so the dashboard runs its usual step-up and retries. Nothing is
//! ever approved without the user's explicit request.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, TimeDelta, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::grants::{RevokeReason, revoke_grant};
use super::request::{self, Invalid};
use super::server::{error_redirect, no_store};
use super::{AGENT_REFRESH_TTL, AUTHORIZATION_CODE_TTL, Scopes, codes};
use crate::AppState;
use crate::audit::{self, RequestMeta};
use crate::db::{DeviceDecision, NewAuthorizationCode};
use crate::models::{
    AUDIT_OAUTH_DEVICE_APPROVE, AUDIT_OAUTH_DEVICE_DENY, OauthCode, OauthGrantListing,
};
use crate::routes::auth_service::now_epoch;
use crate::routes::middleware::{ApiError, AuthClaims, extract_client_ip};

fn bad_request(invalid: Invalid) -> ApiError {
    ApiError::coded(StatusCode::BAD_REQUEST, invalid.error, invalid.description)
}

fn unavailable(error: impl std::fmt::Display) -> ApiError {
    tracing::warn!("OAuth consent request failed: {error}");
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily unavailable, please retry",
    )
}

fn json_no_store(body: Value) -> Response {
    let mut response = Json(body).into_response();
    no_store(response.headers_mut());
    response
}

fn respond(result: Result<Value, ApiError>) -> Response {
    match result {
        Ok(body) => json_no_store(body),
        Err(error) => error.into_response(),
    }
}

/// Agents never approve agents or manage them (the scope policy refuses them on these
/// routes as well).
fn first_party(claims: &AuthClaims) -> Result<(), ApiError> {
    match claims.agent {
        Some(_) => Err(super::policy::insufficient_scope(None)),
        None => Ok(()),
    }
}

/// A session that may decide: signed in (or confirmed) within `RECENT_AUTH`, and
/// confirmed with a second factor when the account needs one.
async fn require_consent_session(state: &AppState, claims: &AuthClaims) -> Result<(), ApiError> {
    if !claims.authenticated_within(crate::mfa::RECENT_AUTH) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "reauth_required",
            "Confirm it's you to continue.",
        ));
    }
    let user = state
        .db
        .get_user_by_id(claims.user_id)
        .await
        .map_err(unavailable)?;
    if crate::mfa::required_for(&state.config, &user) && !claims.mfa {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "mfa_required",
            "Finish two-factor authentication first.",
        ));
    }
    Ok(())
}

// === Authorization code flow ===

/// The consent page's answer: the authorization request as `/#/authorize` received it,
/// what the user approved (`scope`) and the `decision` (`approve` or `deny`).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AuthorizeDecision {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    agent_name: Option<String>,
    decision: Option<String>,
}

/// `POST /api/oauth/authorize`: answers with `redirect_to`, the client's redirect URI
/// carrying either a single-use code or `error=access_denied`, plus `state` and `iss`.
pub async fn handle_authorize_decision(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    Json(body): Json<AuthorizeDecision>,
) -> Response {
    respond(
        authorize_decision(&state, &claims, body)
            .await
            .map(|redirect_to| json!({ "redirect_to": redirect_to })),
    )
}

async fn authorize_decision(
    state: &AppState,
    claims: &AuthClaims,
    body: AuthorizeDecision,
) -> Result<String, ApiError> {
    first_party(claims)?;
    let issuer = super::issuer(&state.config).ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "agents cannot sign in: this server has no BASE_URL configured",
        )
    })?;
    // The request comes back from the browser, so it is checked all over again
    let (client, redirect_uri) =
        request::redirect_target(body.client_id.as_deref(), body.redirect_uri.as_deref())
            .map_err(bad_request)?;
    let state_value = request::state(body.state.as_deref()).map_err(bad_request)?;
    let approve = match body.decision.as_deref() {
        Some("approve") => true,
        Some("deny") => false,
        _ => {
            return Err(bad_request(Invalid::request(
                "decision must be approve or deny",
            )));
        }
    };
    if !approve {
        require_consent_session(state, claims).await?;
        let denied = Invalid::new("access_denied", "the user denied the request");
        return Ok(error_redirect(
            &redirect_uri,
            issuer,
            Some(&state_value),
            &denied,
        ));
    }

    let code_challenge = request::code_challenge(
        body.code_challenge.as_deref(),
        body.code_challenge_method.as_deref(),
    )
    .map_err(bad_request)?;
    let scopes = request::approved_scopes(body.scope.as_deref()).map_err(bad_request)?;
    let agent_name = request::agent_name(body.agent_name.as_deref()).map_err(bad_request)?;
    require_consent_session(state, claims).await?;

    let code = codes::random_secret();
    state
        .db
        .create_authorization_code(&NewAuthorizationCode {
            code_hash: &codes::hash(&code),
            client_id: client.id,
            redirect_uri: &redirect_uri,
            code_challenge: &code_challenge,
            scopes,
            agent_name: &agent_name,
            user_id: claims.user_id,
            mfa: claims.mfa,
            approved_at: now_epoch(),
            ttl: AUTHORIZATION_CODE_TTL,
        })
        .await
        .map_err(unavailable)?;
    Ok(request::redirect_uri_with(
        &redirect_uri,
        &[("code", &code), ("state", &state_value), ("iss", issuer)],
    ))
}

// === Device authorization grant ===

/// Looking up and deciding user codes is limited per account and per address.
fn check_user_code_limits(state: &AppState, user_id: Uuid, ip: IpAddr) -> Result<(), ApiError> {
    let limits = &state.rate_limiters;
    if limits.user_code_user.check_key(&user_id).is_err()
        || limits.user_code_ip.check_key(&ip).is_err()
    {
        return Err(ApiError::coded(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests, please try again later",
        ));
    }
    Ok(())
}

fn device_code_not_found() -> ApiError {
    ApiError::coded(
        StatusCode::NOT_FOUND,
        "not_found",
        "This code is wrong or expired. Check it, or start signing in again from your agent.",
    )
}

/// The pending, unexpired request with the user code as typed (normalized).
async fn pending_device_code(
    state: &AppState,
    user_code: Option<&str>,
) -> Result<OauthCode, ApiError> {
    let user_code = user_code
        .and_then(codes::normalize_user_code)
        .ok_or_else(device_code_not_found)?;
    state
        .db
        .find_pending_device_code(&user_code)
        .await
        .map_err(unavailable)?
        .ok_or_else(device_code_not_found)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UserCodeQuery {
    user_code: Option<String>,
}

/// `GET /api/oauth/device?user_code=...`: what a pending request asks for and where
/// it came from, for the consent page.
pub async fn handle_device_lookup(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<UserCodeQuery>,
) -> Response {
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    respond(device_lookup(&state, &claims, ip, query.user_code.as_deref()).await)
}

async fn device_lookup(
    state: &AppState,
    claims: &AuthClaims,
    ip: IpAddr,
    user_code: Option<&str>,
) -> Result<Value, ApiError> {
    first_party(claims)?;
    check_user_code_limits(state, claims.user_id, ip)?;
    let code = pending_device_code(state, user_code).await?;
    Ok(json!({
        "user_code": code.user_code.as_deref().map(codes::display_user_code),
        "client_id": code.client_id,
        "client_name": super::client(&code.client_id).map(|client| client.name),
        "agent_name": code.agent_name,
        "scopes": code.scopes().names(),
        "requester_ip": code.requester_ip,
        "user_agent": code.user_agent,
        "created_at": code.created_at,
        "expires_at": code.expires_at,
    }))
}

/// `POST /api/oauth/device/approve` and `.../deny`: the user's decision on a user code.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DeviceDecisionBody {
    user_code: Option<String>,
    /// Approving: what the user approved, among the scopes the agent asked for.
    scope: Option<String>,
}

pub async fn handle_device_approve(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    meta: RequestMeta,
    Json(body): Json<DeviceDecisionBody>,
) -> Response {
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    respond(device_decision(&state, &claims, ip, &meta, body, true).await)
}

pub async fn handle_device_deny(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    meta: RequestMeta,
    Json(body): Json<DeviceDecisionBody>,
) -> Response {
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    respond(device_decision(&state, &claims, ip, &meta, body, false).await)
}

async fn device_decision(
    state: &AppState,
    claims: &AuthClaims,
    ip: IpAddr,
    meta: &RequestMeta,
    body: DeviceDecisionBody,
    approve: bool,
) -> Result<Value, ApiError> {
    first_party(claims)?;
    check_user_code_limits(state, claims.user_id, ip)?;
    let approved = if approve {
        Some(request::approved_scopes(body.scope.as_deref()).map_err(bad_request)?)
    } else {
        None
    };
    require_consent_session(state, claims).await?;
    let code = pending_device_code(state, body.user_code.as_deref()).await?;
    let decision = match approved {
        Some(scopes) => {
            let requested = code.scopes();
            if !requested.contains_all(scopes) {
                return Err(bad_request(Invalid::new(
                    "invalid_scope",
                    format!("the agent asked only for: {requested}"),
                )));
            }
            DeviceDecision::Approve {
                scopes,
                mfa: claims.mfa,
                approved_at: now_epoch(),
            }
        }
        None => DeviceDecision::Deny,
    };
    // One decision per code: a concurrent one may have come first
    let decided = state
        .db
        .decide_device_code(&code.code_hash, claims.user_id, decision)
        .await
        .map_err(unavailable)?;
    if !decided {
        return Err(device_code_not_found());
    }

    let (action, response) = match decision {
        DeviceDecision::Approve { scopes, .. } => (
            AUDIT_OAUTH_DEVICE_APPROVE,
            json!({ "status": "approved", "scope": scopes.to_string() }),
        ),
        DeviceDecision::Deny => (AUDIT_OAUTH_DEVICE_DENY, json!({ "status": "denied" })),
    };
    let mut details = json!({
        "client_id": code.client_id,
        "agent_name": code.agent_name,
        "requester_ip": code.requester_ip,
    });
    if let DeviceDecision::Approve { scopes, .. } = decision {
        details["scopes"] = json!(scopes.names());
    }
    audit::record(state, Some(claims.user_id), None, action, meta, details).await;
    Ok(response)
}

// === Connected agents ===

/// Whether a grant in force can still be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStatus {
    Active,
    /// Its sessions ended without the grant being revoked: the user signed out
    /// everywhere after authorizing the agent (changed the password, an administrator
    /// ended the sessions, or a first-party refresh token was used twice), or the agent
    /// did not refresh for longer than its refresh tokens last. Its device stays
    /// paired, and signing the agent in again moves the device to the new grant.
    SignedOut,
}

impl GrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            GrantStatus::Active => "active",
            GrantStatus::SignedOut => "signed_out",
        }
    }
}

/// How long after a grant was last used its newest refresh token has surely expired:
/// their lifetime, plus the delay in noting uses and the leeway on token expiry.
fn idle_limit() -> TimeDelta {
    TimeDelta::seconds(AGENT_REFRESH_TTL.as_secs() as i64) + TimeDelta::minutes(10)
}

pub fn grant_status(grant: &OauthGrantListing, now: DateTime<Utc>) -> GrantStatus {
    // As in check_session: sessions that started before a bulk revocation are over
    let revoked = grant.session_start < grant.tokens_revoked_before;
    let last_active = grant
        .last_used_at
        .map_or(grant.created_at, |used| used.max(grant.created_at));
    if revoked || now - last_active > idle_limit() {
        GrantStatus::SignedOut
    } else {
        GrantStatus::Active
    }
}

fn grant_json(grant: &OauthGrantListing, now: DateTime<Utc>) -> Value {
    json!({
        "id": grant.id,
        "client_id": grant.client_id,
        "client_name": super::client(&grant.client_id).map(|client| client.name),
        "agent_name": grant.agent_name,
        "scopes": Scopes::from_recorded(grant.scopes.iter().map(String::as_str)).names(),
        "device": grant.device_id.map(|id| json!({
            "id": id,
            "name": grant.device_name,
            "status": grant.device_status,
        })),
        "created_at": grant.created_at,
        "last_used_at": grant.last_used_at,
        "status": grant_status(grant, now).as_str(),
    })
}

/// `GET /api/oauth/grants`: the user's agents, newest first.
pub async fn handle_list_grants(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    if let Err(error) = first_party(&claims) {
        return error.into_response();
    }
    match state.db.list_oauth_grants(claims.user_id).await {
        Ok(grants) => {
            let now = Utc::now();
            Json(
                grants
                    .iter()
                    .map(|grant| grant_json(grant, now))
                    .collect::<Vec<_>>(),
            )
            .into_response()
        }
        Err(e) => unavailable(e).into_response(),
    }
}

/// `DELETE /api/oauth/grants/{id}`: revokes an agent, which removes its device.
pub async fn handle_revoke_grant(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    meta: RequestMeta,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(error) = first_party(&claims) {
        return error.into_response();
    }
    match revoke_grant(&state, claims.user_id, id, RevokeReason::User, &meta).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => {
            ApiError::coded(StatusCode::NOT_FOUND, "not_found", "no such agent").into_response()
        }
        Err(e) => unavailable(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(session_start: i64, revoked_before: i64, idle: TimeDelta) -> OauthGrantListing {
        let now = Utc::now();
        OauthGrantListing {
            id: Uuid::new_v4(),
            client_id: super::super::MCP_CLIENT_ID.into(),
            agent_name: String::new(),
            scopes: sqlx::types::Json(vec![]),
            created_at: now - TimeDelta::days(90),
            last_used_at: Some(now - idle),
            session_start,
            device_id: None,
            device_name: None,
            device_status: None,
            tokens_revoked_before: revoked_before,
        }
    }

    #[test]
    fn grants_are_signed_out_by_bulk_revocation_or_long_idleness() {
        let now = Utc::now();
        let recent = TimeDelta::hours(1);
        assert_eq!(
            grant_status(&listing(100, 0, recent), now),
            GrantStatus::Active
        );
        assert_eq!(
            grant_status(&listing(100, 100, recent), now),
            GrantStatus::Active
        );
        assert_eq!(
            grant_status(&listing(100, 101, recent), now),
            GrantStatus::SignedOut
        );
        assert_eq!(
            grant_status(&listing(100, 0, TimeDelta::days(30)), now),
            GrantStatus::Active
        );
        assert_eq!(
            grant_status(&listing(100, 0, TimeDelta::days(31)), now),
            GrantStatus::SignedOut
        );
        // Never used since it was created: its first tokens expired
        let mut unused = listing(100, 0, recent);
        unused.last_used_at = None;
        assert_eq!(grant_status(&unused, now), GrantStatus::SignedOut);
        unused.created_at = now;
        assert_eq!(grant_status(&unused, now), GrantStatus::Active);
    }
}
