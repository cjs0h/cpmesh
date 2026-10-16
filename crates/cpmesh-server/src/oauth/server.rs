//! The authorization server's own endpoints. Agents (and browsers an agent opened) call
//! them without bearer tokens:
//!
//! - `GET /.well-known/oauth-authorization-server`: metadata (RFC 8414).
//! - `GET /oauth/authorize`: checks an authorization request (code flow with PKCE) and
//!   sends the browser to the dashboard's consent page, `/#/authorize`.
//! - `POST /oauth/device_authorization` and `GET /activate`: the device authorization
//!   grant (RFC 8628), for agents without a browser on their machine.
//! - `POST /oauth/token`: exchanges authorization codes, device codes and refresh tokens.
//! - `POST /oauth/revoke`: an agent signs out (RFC 7009), which revokes its grant.
//!
//! Errors follow RFC 6749 section 5.2: JSON with `error` and `error_description`.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequest, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde_json::json;
use uuid::Uuid;

use super::codes;
use super::grants::{RevokeReason, revoke_grant};
use super::request::{self, Invalid, Params};
use super::{
    AgentClaims, Client, DEVICE_CODE_GRANT_TYPE, DEVICE_CODE_TTL, DEVICE_POLL_INTERVAL, Scope,
    Scopes,
};
use crate::AppState;
use crate::audit::{self, RequestMeta};
use crate::db::{DevicePoll, NewDeviceCode};
use crate::models::{AUDIT_OAUTH_GRANT_CREATE, OauthCode};
use crate::routes::auth::{RefreshError, Refresher, rotate_refresh_token};
use crate::routes::auth_service::{RefreshResult, SessionGrant};
use crate::routes::middleware::{IpRateLimiter, extract_client_ip};

/// An OAuth error response (RFC 6749 section 5.2), never cached.
#[derive(Debug)]
pub struct OAuthError {
    status: StatusCode,
    error: &'static str,
    description: Cow<'static, str>,
    /// With `slow_down`: the device code's polling interval from now on, in seconds.
    interval: Option<i32>,
    retry_after: Option<u64>,
}

impl OAuthError {
    pub fn new(
        status: StatusCode,
        error: &'static str,
        description: impl Into<Cow<'static, str>>,
    ) -> OAuthError {
        OAuthError {
            status,
            error,
            description: description.into(),
            interval: None,
            retry_after: None,
        }
    }

    fn bad_request(error: &'static str, description: impl Into<Cow<'static, str>>) -> OAuthError {
        OAuthError::new(StatusCode::BAD_REQUEST, error, description)
    }

    pub fn invalid_request(description: impl Into<Cow<'static, str>>) -> OAuthError {
        OAuthError::bad_request("invalid_request", description)
    }

    pub fn invalid_grant(description: impl Into<Cow<'static, str>>) -> OAuthError {
        OAuthError::bad_request("invalid_grant", description)
    }

    fn invalid_client() -> OAuthError {
        OAuthError::bad_request("invalid_client", "client_id is not registered")
    }

    /// An unexpected failure: logged, and reported without details.
    pub fn server_error(error: impl std::fmt::Display) -> OAuthError {
        tracing::warn!("OAuth request failed: {error}");
        OAuthError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        )
    }

    /// The database could not be reached: retry later.
    pub fn unavailable(error: impl std::fmt::Display) -> OAuthError {
        tracing::warn!("OAuth request could not be completed: {error}");
        OAuthError {
            retry_after: Some(5),
            ..OAuthError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "temporarily unavailable, please retry",
            )
        }
    }

    fn rate_limited(retry_after: u64) -> OAuthError {
        OAuthError {
            retry_after: Some(retry_after),
            ..OAuthError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "too many requests, please try again later",
            )
        }
    }

    /// Agents cannot sign in without an issuer identifier.
    fn not_configured() -> OAuthError {
        OAuthError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "agents cannot sign in: this server has no BASE_URL configured",
        )
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn error(&self) -> &'static str {
        self.error
    }
}

impl From<Invalid> for OAuthError {
    fn from(invalid: Invalid) -> OAuthError {
        OAuthError::bad_request(invalid.error, invalid.description)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.error, "error_description": self.description });
        if let Some(interval) = self.interval {
            body["interval"] = json!(interval);
        }
        let mut response = (self.status, Json(body)).into_response();
        no_store(response.headers_mut());
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

/// Responses with codes or tokens must not be cached (RFC 6749 section 5.1).
pub(crate) fn no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

/// The parameters of a POST to the token, revocation or device authorization endpoint,
/// sent as `application/x-www-form-urlencoded`. A repeated parameter is refused.
pub struct OAuthForm(pub Params);

impl<S: Send + Sync> FromRequest<S> for OAuthForm {
    type Rejection = OAuthError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Form(pairs) = Form::<Vec<(String, String)>>::from_request(req, state)
            .await
            .map_err(|_| {
                OAuthError::invalid_request(
                    "send the parameters as application/x-www-form-urlencoded",
                )
            })?;
        let params = Params::new(pairs);
        if let Some(name) = params.repeated() {
            return Err(OAuthError::invalid_request(format!(
                "{name} must not be repeated"
            )));
        }
        Ok(OAuthForm(params))
    }
}

fn required<'a>(params: &'a Params, name: &'static str) -> Result<&'a str, OAuthError> {
    params
        .get(name)
        .ok_or_else(|| OAuthError::invalid_request(format!("{name} is required")))
}

/// The registered client a request names (public clients identify with `client_id`).
fn client_of(params: &Params) -> Result<&'static Client, OAuthError> {
    super::client(required(params, "client_id")?).ok_or_else(OAuthError::invalid_client)
}

fn configured_issuer(state: &AppState) -> Result<&str, OAuthError> {
    super::issuer(&state.config).ok_or_else(OAuthError::not_configured)
}

fn check_limit(limiter: &IpRateLimiter, ip: &IpAddr) -> Result<(), OAuthError> {
    limiter.check_key(ip).map_err(|not_until| {
        OAuthError::rate_limited(not_until.quota().replenish_interval().as_secs().max(1))
    })
}

/// A `302 Found` to `location`.
fn found(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    match HeaderValue::from_str(location) {
        Ok(value) => {
            response.headers_mut().insert(header::LOCATION, value);
        }
        Err(e) => return OAuthError::server_error(e).into_response(),
    }
    no_store(response.headers_mut());
    response
}

// === Metadata ===

/// The authorization server's metadata (RFC 8414), served from `issuer`.
pub fn metadata(issuer: &str) -> serde_json::Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "device_authorization_endpoint": format!("{issuer}/oauth/device_authorization"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token", DEVICE_CODE_GRANT_TYPE],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": Scope::ALL.map(Scope::as_str),
        "authorization_response_iss_parameter_supported": true,
    })
}

/// `GET /.well-known/oauth-authorization-server`
pub async fn handle_metadata(State(state): State<Arc<AppState>>) -> Response {
    match configured_issuer(&state) {
        Ok(issuer) => Json(metadata(issuer)).into_response(),
        Err(error) => error.into_response(),
    }
}

// === Authorization endpoint ===

const UNKNOWN_CLIENT: &str = "The app that sent you here isn't registered with this server.";
const UNREGISTERED_REDIRECT: &str =
    "The app that sent you here asked to come back to an address this server doesn't allow.";
const NOT_CONFIGURED: &str =
    "Agents can't sign in to this server yet: its BASE_URL isn't configured.";
const UNREADABLE: &str = "The sign-in request couldn't be read.";

/// Refuses an authorization request that cannot be answered through a redirect (its
/// client or redirect URI is not registered): a page, never a redirect.
fn error_page(status: StatusCode, message: &'static str) -> Response {
    let page = format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in request not valid · cpmesh</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 34rem; margin: 18vh auto; padding: 0 1.5rem; color: #111; line-height: 1.5">
<h1 style="font-size: 1.25rem">This sign-in request isn't valid</h1>
<p>{message}</p>
<p style="color: #666">Nothing was shared. Start signing in again from your AI agent.</p>
</body>
</html>
"#
    );
    let mut response = (status, Html(page)).into_response();
    no_store(response.headers_mut());
    response
}

/// Answers an authorization request with an error through the client's redirect URI,
/// with the `state` it sent (when valid) and this server's issuer (RFC 9207).
fn authorization_error(
    redirect_uri: &str,
    issuer: &str,
    state: Option<&str>,
    invalid: Invalid,
) -> Response {
    found(&error_redirect(redirect_uri, issuer, state, &invalid))
}

/// The redirect URI with an authorization error response.
pub(crate) fn error_redirect(
    redirect_uri: &str,
    issuer: &str,
    state: Option<&str>,
    invalid: &Invalid,
) -> String {
    let mut pairs = vec![
        ("error", invalid.error),
        ("error_description", &*invalid.description),
    ];
    if let Some(state) = state {
        pairs.push(("state", state));
    }
    pairs.push(("iss", issuer));
    request::redirect_uri_with(redirect_uri, &pairs)
}

/// `GET /oauth/authorize`: checks an authorization request and sends the browser to
/// the consent page, which asks the user and calls `POST /api/oauth/authorize`.
pub async fn handle_authorize(State(state): State<Arc<AppState>>, uri: Uri) -> Response {
    let Some(issuer) = super::issuer(&state.config) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, NOT_CONFIGURED);
    };
    let params = match Query::<Vec<(String, String)>>::try_from_uri(&uri) {
        Ok(Query(pairs)) => Params::new(pairs),
        Err(_) => return error_page(StatusCode::BAD_REQUEST, UNREADABLE),
    };
    let (client, redirect_uri) =
        match request::redirect_target(params.get("client_id"), params.get("redirect_uri")) {
            Ok(target) => target,
            Err(invalid) if invalid.error == "invalid_client" => {
                return error_page(StatusCode::BAD_REQUEST, UNKNOWN_CLIENT);
            }
            Err(_) => return error_page(StatusCode::BAD_REQUEST, UNREGISTERED_REDIRECT),
        };

    // From here on, errors go back to the client
    let state_param = request::state(params.get("state"));
    let echoed = state_param.as_ref().ok().cloned();
    let fail = |invalid| authorization_error(&redirect_uri, issuer, echoed.as_deref(), invalid);
    if let Some(name) = params.repeated() {
        return fail(Invalid::request(format!("{name} must not be repeated")));
    }
    match params.get("response_type") {
        Some("code") => {}
        Some(_) => {
            return fail(Invalid::new(
                "unsupported_response_type",
                "response_type must be code",
            ));
        }
        None => return fail(Invalid::request("response_type is required")),
    }
    let checked = state_param.and_then(|state_value| {
        Ok((
            state_value,
            request::code_challenge(
                params.get("code_challenge"),
                params.get("code_challenge_method"),
            )?,
            request::requested_scopes(params.get("scope"))?,
            request::agent_name(params.get("agent_name"))?,
        ))
    });
    let (state_value, code_challenge, scopes, agent_name) = match checked {
        Ok(checked) => checked,
        Err(invalid) => return fail(invalid),
    };

    let scope = scopes.to_string();
    let mut pairs = vec![
        ("client_id", client.id),
        ("redirect_uri", redirect_uri.as_str()),
        ("response_type", "code"),
        ("state", state_value.as_str()),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", scope.as_str()),
    ];
    if !agent_name.is_empty() {
        pairs.push(("agent_name", agent_name.as_str()));
    }
    found(&format!("/#/authorize?{}", request::query_string(&pairs)))
}

// === Device authorization (RFC 8628) ===

/// `POST /oauth/device_authorization`: an agent without a browser starts signing in.
/// The user enters (or follows a link with) the user code on the dashboard.
pub async fn handle_device_authorization(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    meta: RequestMeta,
    OAuthForm(params): OAuthForm,
) -> Response {
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    match device_authorization(&state, ip, &meta, &params).await {
        Ok(body) => {
            let mut response = Json(body).into_response();
            no_store(response.headers_mut());
            response
        }
        Err(error) => error.into_response(),
    }
}

async fn device_authorization(
    state: &AppState,
    ip: IpAddr,
    meta: &RequestMeta,
    params: &Params,
) -> Result<serde_json::Value, OAuthError> {
    check_limit(&state.rate_limiters.oauth_device, &ip)?;
    let issuer = configured_issuer(state)?;
    let client = client_of(params)?;
    let scopes = request::requested_scopes(params.get("scope"))?;
    let agent_name = request::agent_name(params.get("agent_name"))?;

    let device_code = codes::random_secret();
    let code_hash = codes::hash(&device_code);
    let mut attempts = 0;
    let user_code = loop {
        let user_code = codes::random_user_code();
        let created = state
            .db
            .create_device_code(&NewDeviceCode {
                code_hash: &code_hash,
                user_code: &user_code,
                client_id: client.id,
                scopes,
                agent_name: &agent_name,
                requester_ip: &meta.ip,
                user_agent: meta.user_agent.as_deref(),
                interval: DEVICE_POLL_INTERVAL,
                ttl: DEVICE_CODE_TTL,
            })
            .await;
        match created {
            Ok(()) => break user_code,
            // Another pending request has this user code
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() && attempts < 5 => {
                attempts += 1;
            }
            Err(e) => return Err(OAuthError::unavailable(e)),
        }
    };

    let user_code = codes::display_user_code(&user_code);
    let verification_uri = format!("{issuer}/activate");
    Ok(json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri_complete": format!("{verification_uri}?user_code={user_code}"),
        "verification_uri": verification_uri,
        "expires_in": DEVICE_CODE_TTL.as_secs(),
        "interval": DEVICE_POLL_INTERVAL.as_secs(),
    }))
}

/// `GET /activate`: the verification URI. Sends the browser to the dashboard's page
/// for entering a user code, with the code when the link carried a well-formed one.
pub async fn handle_activate(uri: Uri) -> Response {
    let user_code = Query::<Vec<(String, String)>>::try_from_uri(&uri)
        .ok()
        .and_then(|Query(pairs)| pairs.into_iter().find(|(name, _)| name == "user_code"))
        .and_then(|(_, code)| codes::normalize_user_code(&code));
    match user_code {
        Some(code) => found(&format!(
            "/#/activate?user_code={}",
            codes::display_user_code(&code)
        )),
        None => found("/#/activate"),
    }
}

// === Token endpoint ===

/// Tokens issued to an agent (RFC 6749 section 5.1), plus the account and grant they
/// belong to.
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    scopes: Scopes,
    user_id: Uuid,
    grant_id: Uuid,
}

impl IntoResponse for TokenResponse {
    fn into_response(self) -> Response {
        let mut response = Json(json!({
            "access_token": self.access_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
            "refresh_token": self.refresh_token,
            "scope": self.scopes.to_string(),
            "user_id": self.user_id,
            "grant_id": self.grant_id,
        }))
        .into_response();
        no_store(response.headers_mut());
        response
    }
}

/// `POST /oauth/token`
pub async fn handle_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    meta: RequestMeta,
    OAuthForm(params): OAuthForm,
) -> Response {
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    match token(&state, ip, &meta, &params).await {
        Ok(tokens) => tokens.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn token(
    state: &AppState,
    ip: IpAddr,
    meta: &RequestMeta,
    params: &Params,
) -> Result<TokenResponse, OAuthError> {
    let grant_type = required(params, "grant_type")?;
    match grant_type {
        // Device polling has its own pace (slow_down), so it does not use up the
        // address's sign-in budget
        "authorization_code" | "refresh_token" => check_limit(&state.rate_limiters.refresh, &ip)?,
        DEVICE_CODE_GRANT_TYPE => {}
        _ => {
            return Err(OAuthError::bad_request(
                "unsupported_grant_type",
                format!(
                    "grant_type must be authorization_code, refresh_token or {DEVICE_CODE_GRANT_TYPE}"
                ),
            ));
        }
    }
    let client = client_of(params)?;
    match grant_type {
        "authorization_code" => authorization_code_grant(state, client, params, meta).await,
        "refresh_token" => refresh_token_grant(state, client, params, meta).await,
        _ => device_code_grant(state, client, params, meta).await,
    }
}

async fn authorization_code_grant(
    state: &AppState,
    client: &'static Client,
    params: &Params,
    meta: &RequestMeta,
) -> Result<TokenResponse, OAuthError> {
    let code = required(params, "code")?;
    let redirect_uri = required(params, "redirect_uri")?;
    let verifier = required(params, "code_verifier")?;
    if !codes::is_valid_code_verifier(verifier) {
        return Err(OAuthError::invalid_request(
            "code_verifier must be 43 to 128 unreserved characters",
        ));
    }
    let Some(code) = state
        .db
        .take_authorization_code(&codes::hash(code))
        .await
        .map_err(OAuthError::unavailable)?
    else {
        return Err(OAuthError::invalid_grant(
            "the authorization code is invalid, expired or already used",
        ));
    };
    // The code is used up now, whatever is wrong with the request
    if code.client_id != client.id {
        return Err(OAuthError::invalid_grant(
            "the authorization code was issued to another client",
        ));
    }
    if code.redirect_uri.as_deref() != Some(redirect_uri) {
        return Err(OAuthError::invalid_grant(
            "redirect_uri does not match the authorization request",
        ));
    }
    if !code
        .code_challenge
        .as_deref()
        .is_some_and(|challenge| codes::pkce_matches(verifier, challenge))
    {
        return Err(OAuthError::invalid_grant(
            "code_verifier does not match the code challenge",
        ));
    }
    sign_in(state, client, code, meta, "authorization_code").await
}

async fn device_code_grant(
    state: &AppState,
    client: &'static Client,
    params: &Params,
    meta: &RequestMeta,
) -> Result<TokenResponse, OAuthError> {
    let device_code = required(params, "device_code")?;
    let poll = state
        .db
        .poll_device_code(&codes::hash(device_code), client.id)
        .await
        .map_err(OAuthError::unavailable)?;
    match poll {
        DevicePoll::Unknown => Err(OAuthError::invalid_grant(
            "the device code is invalid or was already used",
        )),
        DevicePoll::Denied => Err(OAuthError::bad_request(
            "access_denied",
            "the user denied the request",
        )),
        DevicePoll::Expired => Err(OAuthError::bad_request(
            "expired_token",
            "the device code expired; start signing in again",
        )),
        DevicePoll::SlowDown { interval_secs } => Err(OAuthError {
            interval: Some(interval_secs),
            ..OAuthError::bad_request(
                "slow_down",
                format!("polling too often; wait {interval_secs} seconds between requests"),
            )
        }),
        DevicePoll::Pending => Err(OAuthError::bad_request(
            "authorization_pending",
            "waiting for the user to approve",
        )),
        DevicePoll::Approved(code) => sign_in(state, client, *code, meta, "device_code").await,
    }
}

/// Signs an agent in with an approved code: creates its grant and issues its tokens.
/// The agent's sessions start when the user approved, so signing out everywhere since
/// then also refuses the code.
async fn sign_in(
    state: &AppState,
    client: &'static Client,
    code: OauthCode,
    meta: &RequestMeta,
    flow: &'static str,
) -> Result<TokenResponse, OAuthError> {
    let (Some(user_id), Some(approved_at)) = (code.user_id, code.approved_at) else {
        return Err(OAuthError::server_error(
            "an approved OAuth code has no approval",
        ));
    };
    let user = match state.db.get_user_by_id(user_id).await {
        Ok(user) => user,
        Err(sqlx::Error::RowNotFound) => {
            return Err(OAuthError::invalid_grant("the account no longer exists"));
        }
        Err(e) => return Err(OAuthError::unavailable(e)),
    };
    if user.is_suspended() {
        return Err(OAuthError::invalid_grant("this account is suspended"));
    }
    if user.tokens_revoked_before.unwrap_or_default() > approved_at {
        return Err(OAuthError::invalid_grant(
            "the account signed out everywhere since approving; sign in again",
        ));
    }
    let scopes = code.scopes();
    if scopes.is_empty() {
        return Err(OAuthError::server_error(
            "an approved OAuth code has no scopes",
        ));
    }
    let approved_at = approved_at.max(0) as u64;
    let grant = state
        .db
        .create_oauth_grant(user.id, client.id, scopes, &code.agent_name, approved_at)
        .await
        .map_err(OAuthError::unavailable)?;
    let session = SessionGrant {
        user_id: user.id,
        device_id: None,
        mfa: code.mfa,
        auth_time: approved_at,
        session_start: approved_at,
        agent: Some(AgentClaims {
            client_id: client.id,
            scopes,
            grant_id: grant.id,
        }),
    };
    let (access_token, refresh_token) = state
        .auth
        .issue_session(&session)
        .map_err(OAuthError::server_error)?;
    audit::record(
        state,
        Some(user.id),
        None,
        AUDIT_OAUTH_GRANT_CREATE,
        meta,
        json!({
            "grant_id": grant.id,
            "client_id": client.id,
            "scopes": scopes.names(),
            "agent_name": code.agent_name,
            "flow": flow,
        }),
    )
    .await;
    audit::record_activity(state, user.id).await;
    Ok(TokenResponse {
        access_token,
        refresh_token,
        expires_in: state.auth.access_token_ttl().as_secs(),
        scopes,
        user_id: user.id,
        grant_id: grant.id,
    })
}

async fn refresh_token_grant(
    state: &AppState,
    client: &'static Client,
    params: &Params,
    meta: &RequestMeta,
) -> Result<TokenResponse, OAuthError> {
    let refresh_token = required(params, "refresh_token")?;
    // A refresh keeps the grant's scopes; asking for more than it has is refused
    if let Some(scope) = params.get("scope") {
        let asked = Scopes::parse(scope)
            .map_err(|unknown| OAuthError::bad_request("invalid_scope", unknown.to_string()))?;
        if let RefreshResult::Ok(claims, _, _) = state.auth.validate_refresh_token(refresh_token)
            && let Some(agent) = claims.agent
            && !agent.scopes.contains_all(asked)
        {
            return Err(OAuthError::bad_request(
                "invalid_scope",
                "scope exceeds what the user granted",
            ));
        }
    }
    let rotated = rotate_refresh_token(
        state,
        refresh_token,
        Refresher::Agent {
            client_id: client.id,
        },
        meta,
    )
    .await
    .map_err(refresh_error)?;
    let agent = rotated
        .grant
        .agent
        .ok_or_else(|| OAuthError::server_error("an agent refresh lost its agent"))?;
    Ok(TokenResponse {
        access_token: rotated.access_token,
        refresh_token: rotated.refresh_token,
        expires_in: state.auth.access_token_ttl().as_secs(),
        scopes: agent.scopes,
        user_id: rotated.grant.user_id,
        grant_id: agent.grant_id,
    })
}

fn refresh_error(error: RefreshError) -> OAuthError {
    let description = match error {
        RefreshError::Unavailable => {
            return OAuthError::unavailable("refresh token use could not be recorded");
        }
        RefreshError::Internal => return OAuthError::server_error("refreshed tokens not issued"),
        RefreshError::InvalidToken => "the refresh token is invalid or expired",
        RefreshError::WrongClient => "the refresh token was not issued to this client",
        RefreshError::SessionRevoked => "the account signed out everywhere; sign in again",
        RefreshError::AccountSuspended => "this account is suspended",
        RefreshError::DeviceMismatch
        | RefreshError::DeviceProofRequired
        | RefreshError::DeviceGone => "the agent's device was removed; sign in again",
        RefreshError::GrantRevoked => "this agent's access was revoked; sign in again",
        RefreshError::AlreadyUsed => "the refresh token was already used",
        RefreshError::Reused => {
            "the refresh token was used twice, so this agent's access was revoked; sign in again"
        }
    };
    OAuthError::invalid_grant(description)
}

// === Revocation (RFC 7009) ===

/// `POST /oauth/revoke`: an agent signs out with its access or refresh token, which
/// revokes its grant and removes its device. Tokens that are unknown, invalid,
/// expired or not the client's change nothing, and get the same answer.
pub async fn handle_revoke(
    State(state): State<Arc<AppState>>,
    meta: RequestMeta,
    OAuthForm(params): OAuthForm,
) -> Response {
    match revoke(&state, &meta, &params).await {
        Ok(()) => {
            let mut response = StatusCode::OK.into_response();
            no_store(response.headers_mut());
            response
        }
        Err(error) => error.into_response(),
    }
}

async fn revoke(state: &AppState, meta: &RequestMeta, params: &Params) -> Result<(), OAuthError> {
    let client = client_of(params)?;
    let token = required(params, "token")?;
    // Either kind of token will do, whatever token_type_hint says
    let claims = match state.auth.validate_access_token(token) {
        Ok(claims) => Some(claims),
        Err(_) => match state.auth.validate_refresh_token(token) {
            RefreshResult::Ok(claims, _, _) => Some(claims),
            RefreshResult::Invalid(_) => None,
        },
    };
    let Some((user_id, agent)) = claims.and_then(|claims| Some((claims.user_id, claims.agent?)))
    else {
        return Ok(());
    };
    if agent.client_id != client.id {
        return Ok(());
    }
    revoke_grant(state, user_id, agent.grant_id, RevokeReason::Client, meta)
        .await
        .map_err(OAuthError::unavailable)?;
    Ok(())
}
