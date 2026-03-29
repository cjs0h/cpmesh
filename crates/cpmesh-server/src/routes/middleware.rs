use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use serde_json::json;

use crate::AppState;

pub type IpRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

pub fn build_rate_limiter(per_minute: u32) -> Arc<IpRateLimiter> {
    Arc::new(RateLimiter::keyed(
        Quota::per_minute(NonZeroU32::new(per_minute).expect("rate limit must be non-zero")),
    ))
}

#[derive(Clone)]
pub struct AuthClaims {
    pub user_id: uuid::Uuid,
    pub device_id: Option<uuid::Uuid>,
    pub iat: u64,
}

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = extract_token(&req);
    let token = match token {
        Some(t) => t,
        None => return json_error("missing authorization token", StatusCode::UNAUTHORIZED),
    };

    let claims = match state.auth.validate_access_token(&token) {
        Ok(c) => c,
        Err(_) => return json_error("invalid or expired token", StatusCode::UNAUTHORIZED),
    };

    // Verify user still exists and check bulk revocation
    match state.db.get_user_by_id(claims.user_id).await {
        Ok(user) => {
            // Check if token was issued before bulk revocation
            if let Some(revoked_before) = user.tokens_revoked_before {
                if revoked_before > 0 && (claims.iat as i64) < revoked_before {
                    return json_error("session has been revoked, please log in again", StatusCode::UNAUTHORIZED);
                }
            }
        }
        Err(_) => {
            return json_error("user no longer exists, please re-register or log in again", StatusCode::UNAUTHORIZED);
        }
    }

    req.extensions_mut().insert(claims);
    next.run(req).await
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

    if let Some(device_id) = claims.device_id {
        match state.db.get_device_status(device_id).await {
            Ok(status) if status == "approved" => {}
            Ok(status) => {
                return json_error(
                    &format!("device is not approved (status: {status}). Approval from another device is required."),
                    StatusCode::FORBIDDEN,
                );
            }
            Err(_) => {
                return json_error("device not found", StatusCode::NOT_FOUND);
            }
        }
    }

    next.run(req).await
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
    headers.insert("X-Content-Type-Options", "nosniff".parse().expect("Failed to parse X-Content-Type-Options header"));
    headers.insert("X-Frame-Options", "DENY".parse().expect("Failed to parse X-Frame-Options header"));
    headers.insert("Referrer-Policy", "no-referrer".parse().expect("Failed to parse Referrer-Policy header"));
    headers.insert("X-XSS-Protection", "1; mode=block".parse().expect("Failed to parse X-XSS-Protection header"));
    headers.insert("Permissions-Policy", "clipboard-read=(self), clipboard-write=(self)".parse().expect("Failed to parse Permissions-Policy header"));
    headers.insert("Strict-Transport-Security", "max-age=63072000; includeSubDomains".parse().expect("Failed to parse Strict-Transport-Security header"));
    headers.insert("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' wss: ws:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".parse().expect("Failed to parse Content-Security-Policy header"));
    response
}

fn extract_token(req: &Request) -> Option<String> {
    // Check Authorization header
    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    // Check query param (for WebSocket)
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(token) = pair.strip_prefix("token=") {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Extract real client IP, respecting X-Forwarded-For when trust_proxy is true.
pub fn extract_client_ip(headers: &axum::http::HeaderMap, addr: &SocketAddr, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
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
        Err(_) => json_error("too many requests, please try again later", StatusCode::TOO_MANY_REQUESTS),
    }
}

pub fn json_error(message: &str, status: StatusCode) -> Response {
    (status, axum::Json(json!({"error": message}))).into_response()
}

pub fn json_response<T: serde::Serialize>(status: StatusCode, data: T) -> Response {
    (status, axum::Json(data)).into_response()
}
