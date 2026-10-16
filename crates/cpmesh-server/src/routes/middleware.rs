use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use serde_json::json;
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use crate::AppState;
use crate::oauth::AgentClaims;
use crate::oauth::policy::AgentAccess;
use crate::rbac::{self, Permission, Role};

pub type IpRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

pub fn build_rate_limiter(per_minute: u32) -> Arc<IpRateLimiter> {
    Arc::new(RateLimiter::keyed(Quota::per_minute(
        NonZeroU32::new(per_minute).expect("rate limit must be non-zero"),
    )))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthClaims {
    pub user_id: uuid::Uuid,
    pub device_id: Option<uuid::Uuid>,
    pub iat: u64,
    pub session_start: u64,
    /// The session was established with a second factor.
    pub mfa: bool,
    /// When the user last signed in or confirmed a second factor (0 when unknown).
    pub auth_time: u64,
    /// The agent (OAuth client) the session belongs to; `None` for first-party apps.
    pub agent: Option<AgentClaims>,
}

impl AuthClaims {
    pub fn session_started_at(&self) -> u64 {
        if self.session_start == 0 {
            self.iat
        } else {
            self.session_start.min(self.iat)
        }
    }

    /// Whether the user signed in or confirmed their second factor within `window`.
    pub fn authenticated_within(&self, window: std::time::Duration) -> bool {
        self.auth_time > 0
            && crate::routes::auth_service::now_epoch().saturating_sub(self.auth_time)
                <= window.as_secs()
    }
}

/// A refused request; becomes a JSON error response. Small, so helpers can return
/// `Result<T, ApiError>` cheaply and handlers convert it at the edge.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: Cow<'static, str>,
    code: Option<&'static str>,
    extra: Option<Box<serde_json::Value>>,
    /// RFC 6750 bearer challenge, sent as `WWW-Authenticate`.
    challenge: Option<Box<str>>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        ApiError {
            status,
            message: message.into(),
            code: None,
            extra: None,
            challenge: None,
        }
    }

    /// An error clients can recognize by its `code`.
    pub fn coded(
        status: StatusCode,
        code: &'static str,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        ApiError {
            code: Some(code),
            ..ApiError::new(status, message)
        }
    }

    /// Adds fields to the JSON body.
    pub fn with_extra(mut self, extra: serde_json::Value) -> Self {
        self.extra = Some(Box::new(extra));
        self
    }

    /// Sends `challenge` in the `WWW-Authenticate` header (RFC 6750 bearer errors).
    pub fn with_challenge(mut self, challenge: impl Into<Box<str>>) -> Self {
        self.challenge = Some(challenge.into());
        self
    }

    /// An unexpected failure: logged, and reported without details.
    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::warn!("request failed: {error}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn code(&self) -> Option<&'static str> {
        self.code
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let extra = self.extra.map(|e| *e).unwrap_or_else(|| json!({}));
        let mut response = match self.code {
            Some(code) => json_error_code(code, &self.message, self.status, extra),
            None => {
                let mut body = json!({"error": self.message});
                if let (Some(body), serde_json::Value::Object(extra)) =
                    (body.as_object_mut(), extra)
                {
                    body.extend(extra);
                }
                (self.status, axum::Json(body)).into_response()
            }
        };
        if let Some(challenge) = self.challenge
            && let Ok(value) = header::HeaderValue::from_str(&challenge)
        {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

pub(crate) type Rejection = ApiError;

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    match authenticate(&state, req.headers()).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(rejection) => rejection.into_response(),
    }
}

/// Validates the request's bearer token and confirms the session is still valid.
pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthClaims, Rejection> {
    let token = bearer_token(headers)
        .ok_or_else(|| Rejection::new(StatusCode::UNAUTHORIZED, "missing authorization token"))?;

    let claims = state
        .auth
        .validate_access_token(&token)
        .map_err(|_| Rejection::new(StatusCode::UNAUTHORIZED, "invalid or expired token"))?;

    check_session(state, &claims).await?;
    Ok(claims)
}

/// Confirms the user still exists, is not suspended, and has not revoked all sessions
/// since `claims` were issued; for an agent, also that its grant is still in force.
pub(crate) async fn check_session(state: &AppState, claims: &AuthClaims) -> Result<(), Rejection> {
    let user = state.db.get_user_by_id(claims.user_id).await.map_err(|_| {
        Rejection::new(
            StatusCode::UNAUTHORIZED,
            "user no longer exists, please re-register or log in again",
        )
    })?;
    // Check if token was issued before bulk revocation
    if let Some(revoked_before) = user.tokens_revoked_before
        && revoked_before > 0
        && (claims.session_started_at() as i64) < revoked_before
    {
        return Err(Rejection::new(
            StatusCode::UNAUTHORIZED,
            "session has been revoked, please log in again",
        ));
    }
    if user.is_suspended() {
        return Err(Rejection::coded(
            StatusCode::UNAUTHORIZED,
            "account_suspended",
            "this account is suspended",
        ));
    }
    if let Some(agent) = &claims.agent {
        crate::oauth::grants::check_grant(state, claims, agent).await?;
    }
    Ok(())
}

/// Middleware that requires the device to be in "approved" status.
/// Pending/rejected/revoked devices are blocked from most operations.
pub async fn approved_device_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let claims = match req.extensions().get::<AuthClaims>() {
        Some(c) => c.clone(),
        None => return json_error("unauthorized", StatusCode::UNAUTHORIZED),
    };

    // Agents may use their enrollment routes (such as /api/me) before approval
    let enrolling = claims.agent.is_some()
        && req.extensions().get::<AgentAccess>() == Some(&AgentAccess::Enrollment);
    if !enrolling && let Err(rejection) = require_approved_device(&state, &claims).await {
        return rejection.into_response();
    }

    next.run(req).await
}

/// Sessions bound to a device may only proceed once that device is approved. Agents
/// always need an approved device of their own.
pub(crate) async fn require_approved_device(
    state: &AppState,
    claims: &AuthClaims,
) -> Result<(), Rejection> {
    if let Some(device_id) = claims.device_id {
        match state.db.get_device_status(device_id).await {
            Ok(status) if status == "approved" => {}
            Ok(status) => {
                return Err(Rejection::new(
                    StatusCode::FORBIDDEN,
                    format!(
                        "device is not approved (status: {status}). Approval from another device is required."
                    ),
                ));
            }
            Err(_) => {
                return Err(Rejection::new(StatusCode::NOT_FOUND, "device not found"));
            }
        }
    } else if claims.agent.is_some() {
        return Err(crate::oauth::policy::device_required());
    }
    Ok(())
}

/// The staff member behind an admin request, and how they authenticated.
#[derive(Clone, Debug)]
pub struct AdminContext {
    pub user_id: uuid::Uuid,
    pub role: Role,
    /// The session's claims, or `None` when an API token was used.
    pub claims: Option<AuthClaims>,
    pub api_token_id: Option<uuid::Uuid>,
}

impl AdminContext {
    pub fn require(&self, permission: Permission) -> Result<(), ApiError> {
        if rbac::permits(self.role, permission) {
            Ok(())
        } else {
            Err(forbidden_for_role())
        }
    }

    /// Like [`Self::require`], for an action on the account of a user with `target` role.
    pub fn require_on(&self, permission: Permission, target: Role) -> Result<(), ApiError> {
        if rbac::permits_on_target(self.role, permission, target) {
            Ok(())
        } else {
            Err(forbidden_for_role())
        }
    }

    /// Sensitive actions need a recent sign-in or second-factor confirmation, and an
    /// interactive session (never an API token).
    pub fn require_recent_auth(&self) -> Result<(), ApiError> {
        match &self.claims {
            Some(claims) if claims.authenticated_within(crate::mfa::RECENT_AUTH) => Ok(()),
            Some(_) => Err(ApiError::coded(
                StatusCode::FORBIDDEN,
                "reauth_required",
                "Confirm it's you with your second factor to continue.",
            )),
            None => Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "API tokens cannot perform this action",
            )),
        }
    }
}

fn forbidden_for_role() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "your role does not allow this action",
    )
}

/// Admits staff whose session was established with a second factor. Runs after
/// [`auth_middleware`]; the role is read from the database on every request so a
/// demotion takes effect immediately.
pub async fn admin_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let claims = match req.extensions().get::<AuthClaims>() {
        Some(c) => c.clone(),
        None => return json_error("unauthorized", StatusCode::UNAUTHORIZED),
    };

    match staff_context(&state, claims).await {
        Ok(ctx) => {
            req.extensions_mut().insert(ctx);
            next.run(req).await
        }
        Err(error) => error.into_response(),
    }
}

async fn staff_context(state: &AppState, claims: AuthClaims) -> Result<AdminContext, ApiError> {
    // Agents never act as staff
    if claims.agent.is_some() {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    let user = match state.db.get_user_by_id(claims.user_id).await {
        Ok(user) => user,
        Err(_) => return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden")),
    };
    let role = user.role();
    if !role.is_staff() {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    if !claims.mfa {
        let enrolled = state
            .db
            .mfa_summary(user.id)
            .await
            .map(|s| s.enabled())
            .unwrap_or(false);
        let message = if enrolled {
            "Confirm your second factor to use the admin console."
        } else {
            "Set up two-factor authentication to use the admin console."
        };
        return Err(
            ApiError::coded(StatusCode::FORBIDDEN, "mfa_required", message)
                .with_extra(json!({ "enrolled": enrolled })),
        );
    }
    Ok(AdminContext {
        user_id: user.id,
        role,
        claims: Some(claims),
        api_token_id: None,
    })
}

/// Prefix of API tokens, which tells them apart from session JWTs.
pub const API_TOKEN_PREFIX: &str = "cpm_";
/// Scope for publishing releases and download links (the release workflow).
pub const SCOPE_RELEASES: &str = "releases:write";

/// For the release and download admin routes: a staff session (as
/// [`admin_middleware`]), or an API token with the releases scope.
pub async fn release_admin_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    if let Some(token) = bearer_token(req.headers())
        && token.starts_with(API_TOKEN_PREFIX)
    {
        return match api_token_context(&state, &token, SCOPE_RELEASES).await {
            Ok(ctx) => {
                req.extensions_mut().insert(ctx);
                next.run(req).await
            }
            Err(rejection) => rejection.into_response(),
        };
    }

    let claims = match authenticate(&state, req.headers()).await {
        Ok(claims) => claims,
        Err(rejection) => return rejection.into_response(),
    };
    match staff_context(&state, claims).await {
        Ok(ctx) => {
            req.extensions_mut().insert(ctx);
            next.run(req).await
        }
        Err(error) => error.into_response(),
    }
}

/// SHA-256 of an API token, as stored.
pub fn api_token_hash(token: &str) -> String {
    use sha2::Digest;
    crate::mfa::codes::hex(&sha2::Sha256::digest(token.as_bytes()))
}

async fn api_token_context(
    state: &AppState,
    token: &str,
    scope: &str,
) -> Result<AdminContext, Rejection> {
    let invalid = || Rejection::new(StatusCode::UNAUTHORIZED, "invalid or expired API token");
    let record = state
        .db
        .find_active_api_token(&api_token_hash(token))
        .await
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let scopes: Vec<String> = serde_json::from_value(record.scopes.clone()).unwrap_or_default();
    if !scopes.iter().any(|s| s == scope) {
        return Err(Rejection::new(
            StatusCode::FORBIDDEN,
            format!("this API token does not have the {scope} scope"),
        ));
    }
    // The token acts for its creator, who must still be allowed to do this
    let owner = state
        .db
        .get_user_by_id(record.user_id)
        .await
        .map_err(|_| invalid())?;
    let role = owner.role();
    if owner.is_suspended() || !rbac::permits(role, Permission::ManageContent) {
        return Err(Rejection::new(
            StatusCode::FORBIDDEN,
            "the owner of this API token can no longer manage releases",
        ));
    }
    let pool = state.db.pool.clone();
    let id = record.id;
    tokio::spawn(async move {
        let _ = crate::db::Db { pool }.touch_api_token(id).await;
    });
    Ok(AdminContext {
        user_id: owner.id,
        role,
        claims: None,
        api_token_id: Some(record.id),
    })
}

/// Who is using the two-factor endpoints: a signed-in session, or a sign-in waiting
/// for its second factor (holding a ticket from the login response).
#[derive(Clone, Debug)]
pub enum MfaPrincipal {
    Session(AuthClaims),
    SignIn(crate::routes::auth_service::MfaTicket),
}

impl MfaPrincipal {
    pub fn user_id(&self) -> uuid::Uuid {
        match self {
            MfaPrincipal::Session(claims) => claims.user_id,
            MfaPrincipal::SignIn(ticket) => ticket.user_id,
        }
    }
}

/// Accepts an access token or a sign-in ticket in the Authorization header.
pub async fn mfa_principal_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(token) = bearer_token(req.headers()) else {
        return json_error("missing authorization token", StatusCode::UNAUTHORIZED);
    };

    let principal = if let Ok(claims) = state.auth.validate_access_token(&token) {
        // Agents never manage the account's second factors
        if claims.agent.is_some() {
            return crate::oauth::policy::insufficient_scope(None).into_response();
        }
        if let Err(rejection) = check_session(&state, &claims).await {
            return rejection.into_response();
        }
        MfaPrincipal::Session(claims)
    } else if let Ok(ticket) = state.auth.validate_mfa_ticket(&token) {
        // Used tickets are recorded in the database, shared by every instance
        if state.auth.check_revoked_db_async(&ticket.jti).await {
            return json_error(
                "this sign-in was already completed; sign in again",
                StatusCode::UNAUTHORIZED,
            );
        }
        match state.db.get_user_by_id(ticket.user_id).await {
            Ok(user) if user.is_suspended() => {
                return Rejection::coded(
                    StatusCode::FORBIDDEN,
                    "account_suspended",
                    "this account is suspended",
                )
                .into_response();
            }
            Ok(_) => {}
            Err(_) => return json_error("user no longer exists", StatusCode::UNAUTHORIZED),
        }
        MfaPrincipal::SignIn(ticket)
    } else {
        return json_error(
            "invalid or expired token; sign in again",
            StatusCode::UNAUTHORIZED,
        );
    };

    req.extensions_mut().insert(principal);
    next.run(req).await
}

pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-Content-Type-Options",
        "nosniff"
            .parse()
            .expect("Failed to parse X-Content-Type-Options header"),
    );
    headers.insert(
        "X-Frame-Options",
        "DENY"
            .parse()
            .expect("Failed to parse X-Frame-Options header"),
    );
    headers.insert(
        "Referrer-Policy",
        "no-referrer"
            .parse()
            .expect("Failed to parse Referrer-Policy header"),
    );
    headers.insert(
        "X-XSS-Protection",
        "1; mode=block"
            .parse()
            .expect("Failed to parse X-XSS-Protection header"),
    );
    headers.insert(
        "Permissions-Policy",
        "clipboard-read=(self), clipboard-write=(self)"
            .parse()
            .expect("Failed to parse Permissions-Policy header"),
    );
    headers.insert(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains"
            .parse()
            .expect("Failed to parse Strict-Transport-Security header"),
    );
    headers.insert("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' wss: ws:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".parse().expect("Failed to parse Content-Security-Policy header"));
    response
}

/// Reads the bearer token from the Authorization header. Tokens are never accepted
/// from the query string, where they would end up in proxy and access logs; browser
/// WebSockets use a single-use ticket instead (see `websocket::ws_auth_middleware`).
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(str::to_string)
}

/// Extract real client IP, respecting X-Forwarded-For when trust_proxy is true.
pub fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    addr: &SocketAddr,
    trust_proxy: bool,
) -> IpAddr {
    if trust_proxy
        && let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first) = xff.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return ip;
    }
    addr.ip()
}

/// Rate limiting middleware for auth endpoints.
/// Selects the appropriate limiter based on request path.
pub async fn rate_limit_auth(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(req.headers(), &addr, state.config.trust_proxy_headers);
    let path = req.uri().path();
    let limiter = match path {
        "/api/auth/login" => &state.rate_limiters.login,
        "/api/auth/register" => &state.rate_limiters.register,
        _ if path.starts_with("/api/mfa/") => &state.rate_limiters.mfa,
        _ => &state.rate_limiters.refresh,
    };
    match limiter.check_key(&ip) {
        Ok(_) => next.run(req).await,
        Err(_) => json_error(
            "too many requests, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        ),
    }
}

pub fn json_error(message: &str, status: StatusCode) -> Response {
    (status, axum::Json(json!({"error": message}))).into_response()
}

/// An error clients recognize by `code`, with a readable `error` message and any
/// `extra` fields merged in.
pub fn json_error_code(
    code: &str,
    message: &str,
    status: StatusCode,
    extra: serde_json::Value,
) -> Response {
    let mut body = json!({"error": message, "code": code});
    if let (Some(body), serde_json::Value::Object(extra)) = (body.as_object_mut(), extra) {
        body.extend(extra);
    }
    (status, axum::Json(body)).into_response()
}

pub fn json_response<T: serde::Serialize>(status: StatusCode, data: T) -> Response {
    (status, axum::Json(data)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use axum::routing::get;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn addr(ip: &str) -> SocketAddr {
        format!("{ip}:5555").parse().unwrap()
    }

    #[test]
    fn client_ip_ignores_forwarded_header_when_proxy_untrusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, &addr("198.51.100.7"), false),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_uses_first_forwarded_entry_when_proxy_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", " 10.0.0.1 , 10.0.0.2".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, &addr("198.51.100.7"), true),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "2001:db8::1".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, &addr("198.51.100.7"), true),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_falls_back_on_missing_or_invalid_forwarded_header() {
        let headers = HeaderMap::new();
        assert_eq!(
            extract_client_ip(&headers, &addr("198.51.100.7"), true),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip, 10.0.0.2".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, &addr("198.51.100.7"), true),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn bearer_token_is_read_only_from_the_authorization_header() {
        let req = Request::builder()
            .uri("/ws?ticket=abc&token=from-query")
            .header(header::AUTHORIZATION, "Bearer from-header")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(bearer_token(req.headers()).as_deref(), Some("from-header"));

        // Query-string tokens would leak into proxy and access logs
        let req = Request::builder()
            .uri("/ws?ticket=abc&token=from-query")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(bearer_token(req.headers()), None);
    }

    #[test]
    fn bearer_token_rejects_non_bearer_schemes_and_missing() {
        let req = Request::builder()
            .uri("/api/me")
            .header(header::AUTHORIZATION, "Basic dXNlcjpwdw==")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(bearer_token(req.headers()), None);

        let req = Request::builder()
            .uri("/api/me?other=1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(bearer_token(req.headers()), None);

        // "Bearer" without a space is not a bearer token
        let req = Request::builder()
            .uri("/api/me")
            .header(header::AUTHORIZATION, "Bearertoken")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(bearer_token(req.headers()), None);
    }

    #[test]
    fn rate_limiter_allows_quota_then_denies_per_key() {
        let limiter = build_rate_limiter(3);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..3 {
            assert!(limiter.check_key(&a).is_ok());
        }
        assert!(
            limiter.check_key(&a).is_err(),
            "4th request within a minute is denied"
        );
        // Other keys have their own quota
        assert!(limiter.check_key(&b).is_ok());
    }

    #[tokio::test]
    async fn json_error_and_json_response_shapes() {
        let resp = json_error("nope", StatusCode::FORBIDDEN);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"error": "nope"})
        );

        let resp = json_response(StatusCode::CREATED, serde_json::json!({"id": 1}));
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"id": 1})
        );
    }

    #[tokio::test]
    async fn security_headers_are_added_to_every_response() {
        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(security_headers));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["x-xss-protection"], "1; mode=block");
        assert_eq!(
            h["strict-transport-security"],
            "max-age=63072000; includeSubDomains"
        );
        assert!(
            h["permissions-policy"]
                .to_str()
                .unwrap()
                .contains("clipboard-read=(self)")
        );
        let csp = h["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("connect-src 'self' wss: ws:"));
    }
}
