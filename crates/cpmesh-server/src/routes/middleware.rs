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
}

/// A refused request; becomes a JSON error response.
#[derive(Debug)]
pub(crate) struct Rejection {
    status: StatusCode,
    message: Cow<'static, str>,
}

impl Rejection {
    fn new(status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        Rejection {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        json_error(&self.message, self.status)
    }
}

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

/// Confirms the user still exists and has not revoked all sessions since `claims`
/// were issued.
pub(crate) async fn check_session(state: &AppState, claims: &AuthClaims) -> Result<(), Rejection> {
    match state.db.get_user_by_id(claims.user_id).await {
        Ok(user) => {
            // Check if token was issued before bulk revocation
            if let Some(revoked_before) = user.tokens_revoked_before
                && revoked_before > 0
                && (claims.iat as i64) < revoked_before
            {
                return Err(Rejection::new(
                    StatusCode::UNAUTHORIZED,
                    "session has been revoked, please log in again",
                ));
            }
            Ok(())
        }
        Err(_) => Err(Rejection::new(
            StatusCode::UNAUTHORIZED,
            "user no longer exists, please re-register or log in again",
        )),
    }
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

    if let Err(rejection) = require_approved_device(&state, &claims).await {
        return rejection.into_response();
    }

    next.run(req).await
}

/// Sessions bound to a device may only proceed once that device is approved.
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
    }
    Ok(())
}

pub async fn admin_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let claims = match req.extensions().get::<AuthClaims>() {
        Some(c) => c.clone(),
        None => return json_error("unauthorized", StatusCode::UNAUTHORIZED),
    };

    match state.db.get_user_by_id(claims.user_id).await {
        Ok(user) if user.is_admin => next.run(req).await,
        _ => json_error("forbidden", StatusCode::FORBIDDEN),
    }
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
fn bearer_token(headers: &HeaderMap) -> Option<String> {
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
    let limiter = match req.uri().path() {
        "/api/auth/login" => &state.rate_limiters.login,
        "/api/auth/register" => &state.rate_limiters.register,
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
