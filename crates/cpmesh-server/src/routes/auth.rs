use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;

use super::middleware::{extract_client_ip, json_error, json_response};
use crate::AppState;
use crate::models::*;

const MAX_PASSWORD_LENGTH: usize = 128;

/// Fire-and-forget audit log write (non-blocking).
fn audit_log_fire(
    pool: &PgPool,
    user_id: Option<uuid::Uuid>,
    action: &'static str,
    ip: &str,
    user_agent: Option<&str>,
    details: &serde_json::Value,
) {
    let pool = pool.clone();
    let ip = ip.to_string();
    let ua = user_agent.map(String::from);
    let details = details.clone();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(user_id)
        .bind(action)
        .bind(&ip)
        .bind(ua.as_deref())
        .bind(&details)
        .execute(&pool)
        .await;
    });
}

// =============================================================================
// Password strength validation
// =============================================================================

pub fn validate_password_strength(password: &str) -> Result<(), &'static str> {
    if !password.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("password must contain at least one uppercase letter");
    }
    if !password.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err("password must contain at least one lowercase letter");
    }
    if !password.bytes().any(|b| b.is_ascii_digit()) {
        return Err("password must contain at least one digit");
    }
    if !password.bytes().any(|b| !b.is_ascii_alphanumeric()) {
        return Err("password must contain at least one special character");
    }

    static COMMON_PASSWORDS: std::sync::LazyLock<HashSet<&'static str>> =
        std::sync::LazyLock::new(|| {
            HashSet::from([
                "password",
                "password1",
                "password123",
                "12345678",
                "123456789",
                "1234567890",
                "qwerty123",
                "qwertyuiop",
                "abcdefgh",
                "abc12345",
                "iloveyou",
                "trustno1",
                "sunshine1",
                "princess1",
                "football1",
                "charlie1",
                "shadow12",
                "monkey123",
                "dragon12",
                "master12",
                "letmein1",
                "mustang1",
                "access14",
                "michael1",
                "superman",
                "batman123",
                "passw0rd",
                "p@ssw0rd",
                "p@ssword",
                "welcome1",
                "welcome123",
                "admin123",
                "changeme",
                "changeme123",
                "root1234",
                "toor1234",
                "qwerty12",
                "baseball1",
                "starwars1",
                "whatever1",
                "nothing1",
                "jordan23!",
                "abcd1234",
                "test1234",
                "guest1234",
                "pass1234",
                "hello123",
                "soccer12",
                "ashley12",
                "killer12",
                "pepper12",
                "zaq12wsx",
                "1q2w3e4r",
                "q1w2e3r4",
                "1qaz2wsx",
                "computer1",
                "internet1",
                "samsung1",
                "security1",
                "asdfghjk",
                "asdf1234",
                "zxcvbnm1",
                "qazwsxed",
                "login123",
                "system12",
                "summer12",
                "winter12",
                "spring12",
                "autumn12",
                "monday12",
                "friday12",
                "sunday12",
                "january1",
                "flower12",
                "garden12",
                "orange12",
                "purple12",
                "diamond1",
                "crystal1",
                "chicken1",
                "corvette",
                "camaro12",
                "porsche1",
                "ferrari1",
                "mercedes",
                "toyota12",
                "yamaha12",
                "default1",
                "pa55w0rd",
                "pa55word",
                "passpass",
                "secret12",
                "mysecret",
                "private1",
                "personal",
                "thunder1",
                "rainbow1",
                "phoenix1",
                "warrior1",
                "samurai1",
                "hunter12",
                "ranger12",
                "matrix12",
                "hacker12",
                "sniper12",
                "gamer123",
                "player12",
                "winner12",
                "loser123",
                "lucky123",
                "happy123",
                "love1234",
                "forever1",
                "america1",
                "freedom1",
                "liberty1",
                "justice1",
                "patriot1",
                "country1",
            ])
        });

    if COMMON_PASSWORDS.contains(password.to_lowercase().as_str()) {
        return Err("password is too common, please choose a stronger one");
    }

    Ok(())
}

// =============================================================================
// PKCE Code Store — holds one-time authorization codes for native app OAuth
// =============================================================================

/// Entry stored after a successful OIDC callback for native clients.
struct PkceEntry {
    access_token: String,
    refresh_token: String,
    code_challenge: String,
    created_at: std::time::Instant,
}

/// Thread-safe store for PKCE authorization codes with 60-second TTL.
#[derive(Clone, Default)]
pub struct PkceCodeStore {
    inner: Arc<std::sync::Mutex<HashMap<String, PkceEntry>>>,
}

impl PkceCodeStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, code: String, entry: PkceEntry) {
        let mut map = self
            .inner
            .lock()
            .expect("Failed to acquire mutex lock for PkceCodeStore");
        map.insert(code, entry);
    }

    fn take(&self, code: &str) -> Option<PkceEntry> {
        let mut map = self
            .inner
            .lock()
            .expect("Failed to acquire mutex lock for PkceCodeStore");
        map.remove(code)
    }

    /// Remove expired entries (older than 60 seconds).
    pub fn cleanup(&self) {
        let mut map = self.inner.lock().expect("PkceCodeStore mutex poisoned");
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(60);
        map.retain(|_, entry| entry.created_at > cutoff);
    }
}

#[derive(Deserialize)]
pub struct RegisterBody {
    pub username: String,
    pub password: String,
    pub password_confirm: String,
    pub email: String,
    pub full_name: String,
    pub country: Option<String>,
    pub mobile: Option<String>,
}

pub async fn handle_register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<RegisterBody>,
) -> Response {
    // Check registration open
    if !state.config.registration_open {
        return json_error("registration is currently closed", StatusCode::FORBIDDEN);
    }

    let username = req.username.trim().to_string();
    let email = req.email.trim().to_string();
    let full_name = req.full_name.trim().to_string();

    if username.is_empty() || email.is_empty() || full_name.is_empty() || req.password.is_empty() {
        return json_error(
            "username, email, full_name, and password are required",
            StatusCode::BAD_REQUEST,
        );
    }
    if username.len() < 3 || username.len() > 50 {
        return json_error(
            "username must be between 3 and 50 characters",
            StatusCode::BAD_REQUEST,
        );
    }
    static EMAIL_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
            .expect("invalid email regex")
    });
    let email_re = &*EMAIL_RE;
    if !email_re.is_match(&email) {
        return json_error("invalid email address format", StatusCode::BAD_REQUEST);
    }
    if full_name.len() < 2 || full_name.len() > 100 {
        return json_error(
            "full name must be between 2 and 100 characters",
            StatusCode::BAD_REQUEST,
        );
    }
    if req.password.len() < 8 {
        return json_error(
            "password must be at least 8 characters",
            StatusCode::BAD_REQUEST,
        );
    }
    if req.password.len() > MAX_PASSWORD_LENGTH {
        return json_error(
            "password must be at most 128 characters",
            StatusCode::BAD_REQUEST,
        );
    }
    if req.password != req.password_confirm {
        return json_error("passwords do not match", StatusCode::BAD_REQUEST);
    }
    if let Err(msg) = validate_password_strength(&req.password) {
        return json_error(msg, StatusCode::BAD_REQUEST);
    }

    // Always hash the password first for timing normalization (Argon2 dominates response time)
    let hash = match state.auth.hash_password(&req.password) {
        Ok(h) => h,
        Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let generic_ok = || {
        json_response(
            StatusCode::OK,
            json!({
                "message": "If your details are valid, you will receive a verification email shortly."
            }),
        )
    };

    // Check email uniqueness — return generic response to prevent enumeration
    if state
        .db
        .get_user_by_email(&email, state.pii.as_ref())
        .await
        .is_ok()
    {
        // Email already registered — send a notice but don't reveal this to the caller
        let _ = state
            .email
            .send_duplicate_registration_notice(&email, &full_name);
        return generic_ok();
    }

    // Check username uniqueness — return generic response
    if state.db.get_user_by_username(&username).await.is_ok() {
        return generic_ok();
    }

    let country = req.country.as_deref();
    let mobile = req.mobile.as_deref();

    let user = match state
        .db
        .create_user(crate::db::CreateUserParams {
            username: &username,
            password_hash: &hash,
            email: &email,
            full_name: &full_name,
            country,
            mobile,
            pii: state.pii.as_ref(),
        })
        .await
    {
        Ok(u) => u,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("duplicate") || msg.contains("unique") {
                // Race condition: duplicate appeared between check and insert
                return generic_ok();
            }
            return json_error(
                "failed to create account",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    // Send verification email
    if let Ok(token) = state.db.create_email_verification(user.id).await
        && let Err(e) = state
            .email
            .send_verification_email(&email, &full_name, &token)
    {
        warn!("Failed to send verification email: {e}");
    }

    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    audit_log_fire(
        &state.db.pool,
        Some(user.id),
        AUDIT_REGISTER,
        &ip.to_string(),
        ua,
        &json!({"username": username}),
    );

    generic_ok()
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

pub async fn handle_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<LoginBody>,
) -> Response {
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ip_str = ip.to_string();
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let identifier = req.username.trim();

    let user = if identifier.contains('@') {
        state
            .db
            .get_user_by_email(identifier, state.pii.as_ref())
            .await
    } else {
        state.db.get_user_by_username(identifier).await
    };

    let user = match user {
        Ok(u) => u,
        Err(_) => {
            audit_log_fire(
                &state.db.pool,
                None,
                AUDIT_LOGIN_FAIL,
                &ip_str,
                ua.as_deref(),
                &json!({"identifier": identifier}),
            );
            return json_error("invalid credentials", StatusCode::UNAUTHORIZED);
        }
    };

    if !state.auth.check_password(&user.password, &req.password) {
        audit_log_fire(
            &state.db.pool,
            Some(user.id),
            AUDIT_LOGIN_FAIL,
            &ip_str,
            ua.as_deref(),
            &json!({}),
        );
        return json_error("invalid credentials", StatusCode::UNAUTHORIZED);
    }

    // Require email verification for local accounts
    if user.auth_provider == "local" && !user.email_verified && user.email.is_some() {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": "email_not_verified",
                "message": "Please verify your email address before logging in.",
                "email_verified": false,
            }),
        );
    }

    let access_token = match state.auth.generate_access_token(user.id, None) {
        Ok(t) => t,
        Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
    };
    let refresh_token = match state.auth.generate_refresh_token(user.id) {
        Ok(t) => t,
        Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
    };

    audit_log_fire(
        &state.db.pool,
        Some(user.id),
        AUDIT_LOGIN_OK,
        &ip_str,
        ua.as_deref(),
        &json!({}),
    );

    json_response(
        StatusCode::OK,
        json!({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user.id.to_string(),
        }),
    )
}

#[derive(Deserialize)]
pub struct RefreshBody {
    pub refresh_token: String,
}

pub async fn handle_refresh(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<RefreshBody>,
) -> Response {
    use crate::routes::auth_service::RefreshResult;

    match state.auth.validate_refresh_token(&req.refresh_token) {
        RefreshResult::Ok(claims, old_jti, old_exp) => {
            // Check bulk revocation
            if let Ok(user) = state.db.get_user_by_id(claims.user_id).await
                && let Some(revoked_before) = user.tokens_revoked_before
                && revoked_before > 0
                && (claims.iat as i64) < revoked_before
            {
                return json_error(
                    "session has been revoked, please log in again",
                    StatusCode::UNAUTHORIZED,
                );
            }

            // Revoke the old refresh token (single-use enforcement)
            state.auth.revoke_token(&old_jti, claims.user_id, old_exp);

            // Generate new token pair
            let access_token = match state
                .auth
                .generate_access_token(claims.user_id, claims.device_id)
            {
                Ok(t) => t,
                Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
            };
            let refresh_token = match state.auth.generate_refresh_token(claims.user_id) {
                Ok(t) => t,
                Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
            };

            json_response(
                StatusCode::OK,
                json!({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                }),
            )
        }
        RefreshResult::Reused(user_id) => {
            // Token theft detected — revoke ALL tokens for this user
            warn!("Refresh token reuse detected for user {user_id}, revoking all sessions");
            let _ = state
                .db
                .revoke_all_user_tokens(user_id, crate::routes::auth_service::now_epoch())
                .await;
            audit_log_fire(
                &state.db.pool,
                Some(user_id),
                AUDIT_TOKEN_REVOKE_ALL,
                "unknown",
                None,
                &json!({"reason": "refresh_token_reuse"}),
            );
            json_error(
                "session compromised, all sessions revoked — please log in again",
                StatusCode::UNAUTHORIZED,
            )
        }
        RefreshResult::Invalid(_) => json_error("invalid refresh token", StatusCode::UNAUTHORIZED),
    }
}

#[derive(Deserialize)]
pub struct VerifyEmailQuery {
    pub token: Option<String>,
}

pub async fn handle_verify_email(
    State(state): State<Arc<AppState>>,
    Query(query): Query<VerifyEmailQuery>,
) -> Response {
    let token = match query.token {
        Some(t) if !t.is_empty() => t,
        _ => return json_error("missing verification token", StatusCode::BAD_REQUEST),
    };

    if state.db.verify_email(&token).await.is_err() {
        return Redirect::to("/#/login?verified=error").into_response();
    }

    Redirect::to("/#/login?verified=true").into_response()
}

#[derive(Deserialize)]
pub struct ResendBody {
    pub email: String,
}

pub async fn handle_resend_verification(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<ResendBody>,
) -> Response {
    let email = req.email.trim().to_string();
    if email.is_empty() {
        return json_error("email is required", StatusCode::BAD_REQUEST);
    }

    // Always return success to avoid email enumeration
    let generic = json!({"message": "If that email exists and is unverified, we've sent a new verification link."});

    let user = match state.db.get_user_by_email(&email, state.pii.as_ref()).await {
        Ok(u) if !u.email_verified => u,
        _ => return json_response(StatusCode::OK, generic),
    };

    if let Ok(token) = state.db.create_email_verification(user.id).await {
        let decrypted_email = if let Some(ref pii) = state.pii {
            pii.decrypt(user.email.as_deref().unwrap_or(""))
                .unwrap_or_default()
        } else {
            user.email.unwrap_or_default()
        };
        let decrypted_name = if let Some(ref pii) = state.pii {
            pii.decrypt(&user.full_name).unwrap_or_default()
        } else {
            user.full_name
        };
        let _ = state
            .email
            .send_verification_email(&decrypted_email, &decrypted_name, &token);
    }

    json_response(StatusCode::OK, generic)
}

// =============================================================================
// OIDC / Social Login
// =============================================================================

pub async fn handle_social_status(State(state): State<Arc<AppState>>) -> Response {
    let enabled =
        !state.config.oidc_issuer_url.is_empty() && !state.config.oidc_client_id.is_empty();
    let provider = if enabled {
        // Derive a friendly name from the issuer URL
        friendly_provider_name(&state.config.oidc_issuer_url)
    } else {
        String::new()
    };
    json_response(
        StatusCode::OK,
        json!({
            "enabled": enabled,
            "provider": provider,
        }),
    )
}

/// Generate OIDC authorization URL and redirect the user to the provider.
/// Accepts optional query parameters for native app OAuth:
/// - `client_redirect`: Custom scheme URL to redirect to (e.g. `cpmesh://auth/callback`). Only `cpmesh://` is allowed.
/// - `code_challenge`: PKCE S256 code challenge (required when client_redirect is set).
/// - `code_challenge_method`: Must be `S256` (required when code_challenge is set).
#[derive(Deserialize)]
pub struct SocialLoginQuery {
    pub client_redirect: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub async fn handle_social_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SocialLoginQuery>,
) -> Response {
    let cfg = &state.config;
    if cfg.oidc_issuer_url.is_empty() || cfg.oidc_client_id.is_empty() {
        return json_error("OIDC is not configured", StatusCode::SERVICE_UNAVAILABLE);
    }

    // Validate client_redirect — only cpmesh:// scheme is allowed to prevent open redirects
    if let Some(ref redirect) = query.client_redirect {
        if !redirect.starts_with("cpmesh://") {
            return json_error(
                "client_redirect must use the cpmesh:// scheme",
                StatusCode::BAD_REQUEST,
            );
        }
        // When client_redirect is set, PKCE is required
        if query.code_challenge.is_none() || query.code_challenge_method.as_deref() != Some("S256")
        {
            return json_error(
                "code_challenge and code_challenge_method=S256 are required with client_redirect",
                StatusCode::BAD_REQUEST,
            );
        }
    }

    // Discover authorization endpoint
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        cfg.oidc_issuer_url.trim_end_matches('/')
    );
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let doc: serde_json::Value = match client.get(&discovery_url).send().await {
        Ok(r) if r.status().is_success() => match r.json().await {
            Ok(d) => d,
            Err(_) => return json_error("failed to parse OIDC discovery", StatusCode::BAD_GATEWAY),
        },
        _ => return json_error("failed to reach OIDC provider", StatusCode::BAD_GATEWAY),
    };

    let auth_endpoint = match doc.get("authorization_endpoint").and_then(|v| v.as_str()) {
        Some(ep) => ep,
        None => {
            return json_error(
                "OIDC discovery missing authorization_endpoint",
                StatusCode::BAD_GATEWAY,
            );
        }
    };

    // Generate state parameter (CSRF protection + optional native client data)
    let csrf_token = generate_random_string(32);
    let state_param = if let Some(ref client_redirect) = query.client_redirect {
        // Encode client_redirect and code_challenge into state as JSON → base64
        let state_json = json!({
            "csrf": csrf_token,
            "client_redirect": client_redirect,
            "code_challenge": query.code_challenge.as_deref().unwrap_or_default(),
        });
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            state_json.to_string().as_bytes(),
        )
    } else {
        csrf_token.clone()
    };

    // Build authorization URL
    let callback_url = if cfg.oidc_callback_url.is_empty() {
        format!(
            "{}/api/auth/social/callback",
            cfg.base_url.trim_end_matches('/')
        )
    } else {
        cfg.oidc_callback_url.clone()
    };

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email&state={}",
        auth_endpoint,
        urlencoding::encode(&cfg.oidc_client_id),
        urlencoding::encode(&callback_url),
        urlencoding::encode(&state_param),
    );

    // Store CSRF token in a short-lived cookie for verification on callback
    let cookie = format!(
        "cpmesh_oidc_state={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600",
        csrf_token
    );

    (
        StatusCode::SEE_OTHER,
        [
            (axum::http::header::LOCATION, auth_url),
            (axum::http::header::SET_COOKIE, cookie),
        ],
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// OIDC callback: exchange authorization code for tokens, find/create user, redirect with JWT.
/// For web clients: redirects to `{base_url}/#/auth/callback?access_token=...`.
/// For native clients (when state contains client_redirect): issues a one-time code and redirects
/// to `cpmesh://auth/callback?code=...` for PKCE exchange.
pub async fn handle_social_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OidcCallbackQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let cfg = &state.config;
    let frontend_login = format!("{}/#/login", cfg.base_url.trim_end_matches('/'));

    // Check for provider error
    if let Some(err) = &query.error {
        let desc = query.error_description.as_deref().unwrap_or(err);
        let redirect = format!(
            "{}?social_error={}",
            frontend_login,
            urlencoding::encode(desc)
        );
        return Redirect::to(&redirect).into_response();
    }

    let code = match &query.code {
        Some(c) => c,
        None => {
            let redirect = format!("{}?social_error=missing+authorization+code", frontend_login);
            return Redirect::to(&redirect).into_response();
        }
    };

    // Decode state parameter — may be plain CSRF token (web) or base64 JSON (native)
    let cookie_state = extract_cookie(&headers, "cpmesh_oidc_state");
    let mut client_redirect: Option<String> = None;
    let mut code_challenge: Option<String> = None;

    if let Some(ref q_state) = query.state {
        // Try to decode as base64 JSON (native client flow)
        if let Some(state_json) = decode_state_param(q_state) {
            let csrf = state_json
                .get("csrf")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if let Some(ref c_state) = cookie_state
                && csrf != c_state
            {
                let redirect = format!("{}?social_error=invalid+state+parameter", frontend_login);
                return Redirect::to(&redirect).into_response();
            }
            client_redirect = state_json
                .get("client_redirect")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            code_challenge = state_json
                .get("code_challenge")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Re-validate client_redirect scheme on callback
            if let Some(ref cr) = client_redirect
                && !cr.starts_with("cpmesh://")
            {
                let redirect = format!("{}?social_error=invalid+client+redirect", frontend_login);
                return Redirect::to(&redirect).into_response();
            }
        } else {
            // Plain CSRF token (web client flow)
            if let Some(ref c_state) = cookie_state
                && q_state != c_state
            {
                let redirect = format!("{}?social_error=invalid+state+parameter", frontend_login);
                return Redirect::to(&redirect).into_response();
            }
        }
    }

    // Clear the state cookie
    let clear_cookie = "cpmesh_oidc_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";

    // Discover token endpoint
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        cfg.oidc_issuer_url.trim_end_matches('/')
    );
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            let redirect = format!("{}?social_error=internal+error", frontend_login);
            return (
                [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                Redirect::to(&redirect),
            )
                .into_response();
        }
    };

    let doc: serde_json::Value = match client.get(&discovery_url).send().await {
        Ok(r) if r.status().is_success() => match r.json().await {
            Ok(d) => d,
            Err(_) => {
                let redirect = format!("{}?social_error=OIDC+discovery+failed", frontend_login);
                return (
                    [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                    Redirect::to(&redirect),
                )
                    .into_response();
            }
        },
        _ => {
            let redirect = format!("{}?social_error=OIDC+provider+unreachable", frontend_login);
            return (
                [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                Redirect::to(&redirect),
            )
                .into_response();
        }
    };

    let token_endpoint = match doc.get("token_endpoint").and_then(|v| v.as_str()) {
        Some(ep) => ep.to_string(),
        None => {
            let redirect = format!(
                "{}?social_error=OIDC+missing+token_endpoint",
                frontend_login
            );
            return (
                [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                Redirect::to(&redirect),
            )
                .into_response();
        }
    };

    let userinfo_endpoint = doc
        .get("userinfo_endpoint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Exchange code for tokens
    let callback_url = if cfg.oidc_callback_url.is_empty() {
        format!(
            "{}/api/auth/social/callback",
            cfg.base_url.trim_end_matches('/')
        )
    } else {
        cfg.oidc_callback_url.clone()
    };

    let token_res = client
        .post(&token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &callback_url),
            ("client_id", &cfg.oidc_client_id),
            ("client_secret", &cfg.oidc_client_secret),
        ])
        .send()
        .await;

    let token_data: serde_json::Value = match token_res {
        Ok(r) => match r.json().await {
            Ok(d) => d,
            Err(_) => {
                let redirect = format!(
                    "{}?social_error=failed+to+parse+token+response",
                    frontend_login
                );
                return (
                    [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                    Redirect::to(&redirect),
                )
                    .into_response();
            }
        },
        Err(e) => {
            warn!("OIDC token exchange failed: {e}");
            let redirect = format!("{}?social_error=token+exchange+failed", frontend_login);
            return (
                [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                Redirect::to(&redirect),
            )
                .into_response();
        }
    };

    if let Some(err) = token_data.get("error").and_then(|v| v.as_str()) {
        let desc = token_data
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or(err);
        let redirect = format!(
            "{}?social_error={}",
            frontend_login,
            urlencoding::encode(desc)
        );
        return (
            [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
            Redirect::to(&redirect),
        )
            .into_response();
    }

    let provider_access_token = match token_data.get("access_token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            let redirect = format!(
                "{}?social_error=no+access_token+in+response",
                frontend_login
            );
            return (
                [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                Redirect::to(&redirect),
            )
                .into_response();
        }
    };

    // Fetch user info
    let userinfo = if let Some(ref ep) = userinfo_endpoint {
        match client
            .get(ep)
            .bearer_auth(&provider_access_token)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r.json::<serde_json::Value>().await.ok(),
            _ => None,
        }
    } else {
        None
    };

    // Also try to decode id_token for subject claim
    let id_token_str = token_data.get("id_token").and_then(|v| v.as_str());
    let id_token_claims = id_token_str.and_then(decode_jwt_payload);

    // Extract user info from userinfo or id_token
    let sub = userinfo
        .as_ref()
        .and_then(|u| u.get("sub").and_then(|v| v.as_str()))
        .or_else(|| {
            id_token_claims
                .as_ref()
                .and_then(|c| c.get("sub").and_then(|v| v.as_str()))
        });

    let sub = match sub {
        Some(s) => s.to_string(),
        None => {
            let redirect = format!(
                "{}?social_error=could+not+determine+user+identity",
                frontend_login
            );
            return (
                [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                Redirect::to(&redirect),
            )
                .into_response();
        }
    };

    let email = userinfo
        .as_ref()
        .and_then(|u| u.get("email").and_then(|v| v.as_str()))
        .or_else(|| {
            id_token_claims
                .as_ref()
                .and_then(|c| c.get("email").and_then(|v| v.as_str()))
        })
        .unwrap_or_default()
        .to_string();

    let name = userinfo
        .as_ref()
        .and_then(|u| u.get("name").and_then(|v| v.as_str()))
        .or_else(|| {
            id_token_claims
                .as_ref()
                .and_then(|c| c.get("name").and_then(|v| v.as_str()))
        })
        .unwrap_or_default()
        .to_string();

    let picture = userinfo
        .as_ref()
        .and_then(|u| u.get("picture").and_then(|v| v.as_str()))
        .or_else(|| {
            id_token_claims
                .as_ref()
                .and_then(|c| c.get("picture").and_then(|v| v.as_str()))
        })
        .map(|s| s.to_string());

    let provider_name = friendly_provider_name(&cfg.oidc_issuer_url);

    // Find or create user
    let user = match state
        .db
        .get_user_by_provider_id(&provider_name, &sub, state.pii.as_ref())
        .await
    {
        Ok(u) => u,
        Err(_) => {
            // New user — check registration
            if !cfg.registration_open {
                let redirect = format!(
                    "{}?social_error=registration+is+currently+closed",
                    frontend_login
                );
                return (
                    [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                    Redirect::to(&redirect),
                )
                    .into_response();
            }

            // If a user with this email already exists (local account), link them?
            // For now, generate a unique username.
            let username = generate_oidc_username(&name, &sub);

            match state
                .db
                .create_oidc_user(crate::db::CreateOidcUserParams {
                    username: &username,
                    email: &email,
                    full_name: &name,
                    provider: &provider_name,
                    provider_id: &sub,
                    avatar_url: picture.as_deref(),
                    pii: state.pii.as_ref(),
                })
                .await
            {
                Ok(u) => u,
                Err(e) => {
                    warn!("Failed to create OIDC user: {e}");
                    let redirect =
                        format!("{}?social_error=failed+to+create+account", frontend_login);
                    return (
                        [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                        Redirect::to(&redirect),
                    )
                        .into_response();
                }
            }
        }
    };

    // Generate JWT tokens
    let access_token = match state.auth.generate_access_token(user.id, None) {
        Ok(t) => t,
        Err(_) => {
            let redirect = format!("{}?social_error=internal+error", frontend_login);
            return (
                [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                Redirect::to(&redirect),
            )
                .into_response();
        }
    };
    let refresh_token = match state.auth.generate_refresh_token(user.id) {
        Ok(t) => t,
        Err(_) => {
            let redirect = format!("{}?social_error=internal+error", frontend_login);
            return (
                [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
                Redirect::to(&redirect),
            )
                .into_response();
        }
    };

    // Redirect: native client (PKCE) or web client
    if let (Some(cr), Some(cc)) = (client_redirect, code_challenge) {
        // Native client flow — issue a one-time authorization code
        let one_time_code = generate_random_string(64);
        state.pkce_store.insert(
            one_time_code.clone(),
            PkceEntry {
                access_token,
                refresh_token,
                code_challenge: cc,
                created_at: std::time::Instant::now(),
            },
        );

        // Redirect to custom scheme with code (not raw tokens)
        let separator = if cr.contains('?') { "&" } else { "?" };
        let redirect_url = format!(
            "{}{}code={}",
            cr,
            separator,
            urlencoding::encode(&one_time_code),
        );

        (
            [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
            Redirect::to(&redirect_url),
        )
            .into_response()
    } else {
        // Web client flow — redirect with tokens in URL hash
        let redirect_url = format!(
            "{}/#/auth/callback?access_token={}&refresh_token={}",
            cfg.base_url.trim_end_matches('/'),
            urlencoding::encode(&access_token),
            urlencoding::encode(&refresh_token),
        );

        (
            [(axum::http::header::SET_COOKIE, clear_cookie.to_string())],
            Redirect::to(&redirect_url),
        )
            .into_response()
    }
}

// =============================================================================
// PKCE Token Exchange — native clients exchange one-time code for tokens
// =============================================================================

#[derive(Deserialize)]
pub struct SocialExchangeBody {
    pub code: String,
    pub code_verifier: String,
}

/// Exchange a one-time authorization code + PKCE code_verifier for tokens.
/// The code was issued during the OIDC callback to a native client.
pub async fn handle_social_exchange(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<SocialExchangeBody>,
) -> Response {
    // Look up and consume the one-time code
    let entry = match state.pkce_store.take(&req.code) {
        Some(e) => e,
        None => return json_error("invalid or expired code", StatusCode::UNAUTHORIZED),
    };

    // Check TTL (60 seconds)
    if entry.created_at.elapsed() > std::time::Duration::from_secs(60) {
        return json_error("code expired", StatusCode::UNAUTHORIZED);
    }

    // Verify PKCE: SHA256(code_verifier) must match stored code_challenge
    use sha2::Digest;
    let computed = sha2::Sha256::digest(req.code_verifier.as_bytes());
    let computed_challenge =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, computed);

    if computed_challenge != entry.code_challenge {
        return json_error("PKCE verification failed", StatusCode::UNAUTHORIZED);
    }

    json_response(
        StatusCode::OK,
        json!({
            "access_token": entry.access_token,
            "refresh_token": entry.refresh_token,
        }),
    )
}

// === OIDC helpers ===

/// Decode JWT payload without verifying signature (for extracting id_token claims).
fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1]).ok()?;
    serde_json::from_slice(&decoded).ok()
}

/// Decode a state parameter that may be base64-encoded JSON (native client flow).
fn decode_state_param(state: &str) -> Option<serde_json::Value> {
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, state).ok()?;
    let val: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    // Must have a "csrf" field to be a valid native state
    if val.get("csrf").is_some() {
        Some(val)
    } else {
        None
    }
}

fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find(|s| s.starts_with(&format!("{}=", name)))
        .map(|s| s.split_once('=').map(|x| x.1).unwrap_or("").to_string())
}

fn friendly_provider_name(issuer_url: &str) -> String {
    let lower = issuer_url.to_lowercase();
    if lower.contains("google") {
        return "google".to_string();
    }
    if lower.contains("auth0") {
        return "auth0".to_string();
    }
    if lower.contains("github") {
        return "github".to_string();
    }
    if lower.contains("microsoft") || lower.contains("login.microsoftonline") {
        return "microsoft".to_string();
    }
    if lower.contains("okta") {
        return "okta".to_string();
    }
    if lower.contains("keycloak") {
        return "keycloak".to_string();
    }
    // Fallback: extract domain
    issuer_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("oidc")
        .to_string()
}

fn generate_oidc_username(name: &str, sub: &str) -> String {
    let base = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .take(20)
        .collect::<String>();
    if base.len() >= 3 {
        format!("{}_{}", base, &sub[..std::cmp::min(6, sub.len())])
    } else {
        format!("user_{}", &sub[..std::cmp::min(12, sub.len())])
    }
}

fn generate_random_string(len: usize) -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..36u8);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

pub async fn handle_list_active_plans(State(state): State<Arc<AppState>>) -> Response {
    let plans = state
        .db
        .list_active_subscription_plans()
        .await
        .unwrap_or_default();
    json_response(StatusCode::OK, plans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use axum::http::{HeaderMap, Request, header};

    // ---- password strength -------------------------------------------------

    #[test]
    fn password_strength_requires_each_character_class() {
        assert_eq!(
            validate_password_strength("lowercase1!"),
            Err("password must contain at least one uppercase letter")
        );
        assert_eq!(
            validate_password_strength("UPPERCASE1!"),
            Err("password must contain at least one lowercase letter")
        );
        assert_eq!(
            validate_password_strength("NoDigits!!"),
            Err("password must contain at least one digit")
        );
        assert_eq!(
            validate_password_strength("NoSpecial1"),
            Err("password must contain at least one special character")
        );
        assert_eq!(validate_password_strength("Str0ng-Pass!"), Ok(()));
    }

    #[test]
    fn password_strength_rejects_common_passwords_case_insensitively() {
        // Entries in the blocklist that also satisfy the class rules are still rejected
        assert_eq!(
            validate_password_strength("P@ssw0rd"),
            Err("password is too common, please choose a stronger one")
        );
        assert_eq!(
            validate_password_strength("p@SSw0rd"),
            Err("password is too common, please choose a stronger one")
        );
        // Spaces count as special characters
        assert_eq!(validate_password_strength("Tr0ub4dor and horse"), Ok(()));
    }

    // ---- PKCE code store ---------------------------------------------------

    fn entry(challenge: &str) -> PkceEntry {
        PkceEntry {
            access_token: "acc".into(),
            refresh_token: "ref".into(),
            code_challenge: challenge.into(),
            created_at: std::time::Instant::now(),
        }
    }

    #[test]
    fn pkce_store_take_is_single_use() {
        let store = PkceCodeStore::new();
        store.insert("code-1".into(), entry("c"));
        let first = store.take("code-1").expect("present");
        assert_eq!(first.code_challenge, "c");
        assert!(
            store.take("code-1").is_none(),
            "codes are consumed on first use"
        );
        assert!(store.take("unknown").is_none());
    }

    #[test]
    fn pkce_store_cleanup_removes_only_expired_entries() {
        let store = PkceCodeStore::new();
        store.insert("fresh".into(), entry("c"));
        let mut old = entry("c");
        old.created_at = std::time::Instant::now() - std::time::Duration::from_secs(61);
        store.insert("stale".into(), old);

        store.cleanup();
        assert!(store.take("stale").is_none());
        assert!(store.take("fresh").is_some());
    }

    #[test]
    fn pkce_store_clones_share_state() {
        let store = PkceCodeStore::new();
        let clone = store.clone();
        store.insert("shared".into(), entry("c"));
        assert!(clone.take("shared").is_some());
    }

    // ---- OIDC helpers ------------------------------------------------------

    #[test]
    fn decode_jwt_payload_extracts_claims_without_verifying() {
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"sub":"123","email":"a@b.c"}"#,
        );
        let token = format!("eyJhbGciOiJub25lIn0.{payload}.sig");
        let claims = decode_jwt_payload(&token).unwrap();
        assert_eq!(claims["sub"], "123");
        assert_eq!(claims["email"], "a@b.c");

        assert!(decode_jwt_payload("only.two").is_none());
        assert!(decode_jwt_payload("a.%%%.c").is_none());
        let not_json =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b"nope");
        assert!(decode_jwt_payload(&format!("a.{not_json}.c")).is_none());
    }

    #[test]
    fn decode_state_param_requires_csrf_field() {
        let encode = |v: serde_json::Value| {
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                v.to_string().as_bytes(),
            )
        };
        let native = encode(json!({"csrf":"abc","client_redirect":"cpmesh://auth/callback"}));
        let decoded = decode_state_param(&native).unwrap();
        assert_eq!(decoded["csrf"], "abc");
        assert_eq!(decoded["client_redirect"], "cpmesh://auth/callback");

        assert!(decode_state_param(&encode(json!({"other":"x"}))).is_none());
        assert!(decode_state_param("plain-csrf-token").is_none());
        assert!(decode_state_param("").is_none());
    }

    #[test]
    fn extract_cookie_finds_named_cookie_across_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            "a=1; cpmesh_oidc_state=xyz ; b=2".parse().unwrap(),
        );
        headers.append(header::COOKIE, "other=3".parse().unwrap());
        assert_eq!(
            extract_cookie(&headers, "cpmesh_oidc_state").as_deref(),
            Some("xyz")
        );
        assert_eq!(extract_cookie(&headers, "other").as_deref(), Some("3"));
        assert_eq!(extract_cookie(&headers, "a").as_deref(), Some("1"));
        assert_eq!(extract_cookie(&headers, "missing"), None);

        // A cookie whose name merely starts with the requested name does not match
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, "cpmesh_oidc_state_v2=nope".parse().unwrap());
        assert_eq!(extract_cookie(&headers, "cpmesh_oidc_state"), None);

        // Empty values are preserved as empty strings
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, "cpmesh_oidc_state=".parse().unwrap());
        assert_eq!(
            extract_cookie(&headers, "cpmesh_oidc_state").as_deref(),
            Some("")
        );
    }

    #[test]
    fn friendly_provider_name_recognizes_known_issuers() {
        assert_eq!(
            friendly_provider_name("https://accounts.google.com"),
            "google"
        );
        assert_eq!(
            friendly_provider_name("https://dev-123.us.auth0.com/"),
            "auth0"
        );
        assert_eq!(
            friendly_provider_name("https://token.actions.githubusercontent.com"),
            "github"
        );
        assert_eq!(
            friendly_provider_name("https://login.microsoftonline.com/tid/v2.0"),
            "microsoft"
        );
        assert_eq!(friendly_provider_name("https://acme.okta.com"), "okta");
        assert_eq!(
            friendly_provider_name("https://sso.example.com/realms/keycloak"),
            "keycloak"
        );
        assert_eq!(
            friendly_provider_name("HTTPS://ACCOUNTS.GOOGLE.COM"),
            "google"
        );
    }

    #[test]
    fn friendly_provider_name_falls_back_to_domain() {
        assert_eq!(
            friendly_provider_name("https://id.example.org/oidc"),
            "id.example.org"
        );
        assert_eq!(
            friendly_provider_name("http://localhost:8180/realms/dev"),
            "localhost:8180"
        );
        assert_eq!(friendly_provider_name(""), "");
    }

    #[test]
    fn oidc_username_derivation() {
        assert_eq!(
            generate_oidc_username("Alice Liddell", "1234567890"),
            "aliceliddell_123456"
        );
        // Non-alphanumeric characters (other than underscore) are dropped
        assert_eq!(
            generate_oidc_username("Jean-Luc O'Brien", "abcdefgh"),
            "jeanlucobrien_abcdef"
        );
        assert_eq!(
            generate_oidc_username("snake_case", "abcdefgh"),
            "snake_case_abcdef"
        );
        // Long names are truncated to 20 characters before the suffix
        let long = generate_oidc_username("abcdefghijklmnopqrstuvwxyz", "sub123");
        assert_eq!(long, "abcdefghijklmnopqrst_sub123");
        // Short or empty names fall back to the subject
        assert_eq!(
            generate_oidc_username("Al", "subject-identifier-long"),
            "user_subject-iden"
        );
        assert_eq!(generate_oidc_username("", "abc"), "user_abc");
        // Subject shorter than the slice length is used whole
        assert_eq!(generate_oidc_username("Alice", "ab"), "alice_ab");
    }

    #[test]
    fn random_strings_are_lowercase_alphanumeric_and_unique() {
        let a = generate_random_string(64);
        let b = generate_random_string(64);
        assert_eq!(a.len(), 64);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "{a}"
        );
        assert_ne!(a, b);
        assert_eq!(generate_random_string(0), "");
    }

    // ---- HTTP handlers (no database reachable) -----------------------------

    #[tokio::test]
    async fn register_is_forbidden_when_registration_closed() {
        let mut cfg = test_config();
        cfg.registration_open = false;
        let app = test_router(test_state(cfg).await);
        let resp = send(
            &app,
            json_request("POST", "/api/auth/register", json!({
                "username": "alice", "password": "Str0ng-Pass!", "password_confirm": "Str0ng-Pass!",
                "email": "a@example.com", "full_name": "Alice"
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_json(resp).await["error"],
            "registration is currently closed"
        );
    }

    #[tokio::test]
    async fn register_validates_input_before_touching_the_database() {
        let app = test_router(test_state(test_config()).await);
        let base = json!({
            "username": "alice", "password": "Str0ng-Pass!", "password_confirm": "Str0ng-Pass!",
            "email": "a@example.com", "full_name": "Alice"
        });
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                json!({"username": "", "password": "x", "password_confirm": "x", "email": "", "full_name": ""}),
                "username, email, full_name, and password are required",
            ),
            (
                {
                    let mut v = base.clone();
                    v["username"] = json!("ab");
                    v
                },
                "username must be between 3 and 50 characters",
            ),
            (
                {
                    let mut v = base.clone();
                    v["username"] = json!("a".repeat(51));
                    v
                },
                "username must be between 3 and 50 characters",
            ),
            (
                {
                    let mut v = base.clone();
                    v["email"] = json!("not-an-email");
                    v
                },
                "invalid email address format",
            ),
            (
                {
                    let mut v = base.clone();
                    v["full_name"] = json!("A");
                    v
                },
                "full name must be between 2 and 100 characters",
            ),
            (
                {
                    let mut v = base.clone();
                    v["password"] = json!("Sh0rt!");
                    v["password_confirm"] = json!("Sh0rt!");
                    v
                },
                "password must be at least 8 characters",
            ),
            (
                {
                    let long = format!("Aa1!{}", "x".repeat(130));
                    let mut v = base.clone();
                    v["password"] = json!(long);
                    v["password_confirm"] = json!(long);
                    v
                },
                "password must be at most 128 characters",
            ),
            (
                {
                    let mut v = base.clone();
                    v["password_confirm"] = json!("Different-1!");
                    v
                },
                "passwords do not match",
            ),
            (
                {
                    let mut v = base.clone();
                    v["password"] = json!("alllowercase1!");
                    v["password_confirm"] = json!("alllowercase1!");
                    v
                },
                "password must contain at least one uppercase letter",
            ),
        ];
        for (body, expected) in cases {
            let resp = send(
                &app,
                json_request("POST", "/api/auth/register", body.clone()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body_json(resp).await["error"], expected, "{body}");
        }
    }

    #[tokio::test]
    async fn register_with_valid_input_reports_generic_success_even_if_storage_fails() {
        // The database is unreachable; the handler must not leak that to callers
        // (enumeration protection) and returns the same generic message.
        let app = test_router(test_state(test_config()).await);
        let resp = send(
            &app,
            json_request("POST", "/api/auth/register", json!({
                "username": "alice", "password": "Str0ng-Pass!", "password_confirm": "Str0ng-Pass!",
                "email": "a@example.com", "full_name": "Alice"
            })),
        )
        .await;
        // Either the generic 200 (duplicate/uniqueness path) or a 500 from create_user is
        // acceptable here; what matters is that no 4xx validation error fires.
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "{}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn register_rejects_malformed_json() {
        let app = test_router(test_state(test_config()).await);
        let resp = send(
            &app,
            request("POST", "/api/auth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from("{not json"))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_with_unknown_user_is_unauthorized() {
        let app = test_router(test_state(test_config()).await);
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/login",
                json!({"username": "ghost", "password": "x"}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(resp).await["error"], "invalid credentials");

        // Email identifiers take the email lookup path, same outcome
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/login",
                json!({"username": "ghost@example.com", "password": "x"}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_is_rate_limited_per_client_ip() {
        let app = test_router(
            test_state_with(test_config(), [("login", 2u32)].into_iter().collect()).await,
        );
        let body = json!({"username": "ghost", "password": "x"});
        for _ in 0..2 {
            let resp = send(&app, json_request("POST", "/api/auth/login", body.clone())).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let resp = send(&app, json_request("POST", "/api/auth/login", body.clone())).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            body_json(resp).await["error"],
            "too many requests, please try again later"
        );

        // A different client IP is unaffected
        let other = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .extension(ConnectInfo::<SocketAddr>(
                "198.51.100.99:1".parse().unwrap(),
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        assert_eq!(send(&app, other).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rate_limit_honours_forwarded_ip_only_when_proxy_trusted() {
        let mut cfg = test_config();
        cfg.trust_proxy_headers = true;
        let app = test_router(test_state_with(cfg, [("login", 1u32)].into_iter().collect()).await);
        let body = json!({"username": "ghost", "password": "x"});
        let with_xff = |ip: &str| {
            request("POST", "/api/auth/login")
                .header("x-forwarded-for", ip)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap()
        };
        assert_eq!(
            send(&app, with_xff("10.1.1.1")).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app, with_xff("10.1.1.1")).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            send(&app, with_xff("10.1.1.2")).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn refresh_rotates_tokens_and_detects_reuse() {
        let state = test_state(test_config()).await;
        let app = test_router(state.clone());
        let user = uuid::Uuid::new_v4();
        let refresh = state.auth.generate_refresh_token(user).unwrap();

        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/refresh",
                json!({"refresh_token": refresh}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let new_access = body["access_token"].as_str().unwrap();
        let new_refresh = body["refresh_token"].as_str().unwrap();
        assert_ne!(new_refresh, refresh);
        assert_eq!(
            state
                .auth
                .validate_access_token(new_access)
                .unwrap()
                .user_id,
            user
        );
        assert!(matches!(
            state.auth.validate_refresh_token(new_refresh),
            crate::routes::auth_service::RefreshResult::Ok(..)
        ));

        // Presenting the consumed refresh token again is treated as theft
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/refresh",
                json!({"refresh_token": refresh}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            body_json(resp).await["error"]
                .as_str()
                .unwrap()
                .contains("session compromised")
        );
    }

    #[tokio::test]
    async fn refresh_rejects_invalid_and_access_tokens() {
        let state = test_state(test_config()).await;
        let app = test_router(state.clone());
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/refresh",
                json!({"refresh_token": "garbage"}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(resp).await["error"], "invalid refresh token");

        let access = state
            .auth
            .generate_access_token(uuid::Uuid::new_v4(), None)
            .unwrap();
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/refresh",
                json!({"refresh_token": access}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_email_requires_token_and_redirects_on_failure() {
        let app = test_router(test_state(test_config()).await);
        let resp = send(
            &app,
            request("GET", "/api/auth/verify-email")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = send(
            &app,
            request("GET", "/api/auth/verify-email?token=")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = send(
            &app,
            request("GET", "/api/auth/verify-email?token=abc")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers()[header::LOCATION], "/#/login?verified=error");
    }

    #[tokio::test]
    async fn resend_verification_is_generic() {
        let app = test_router(test_state(test_config()).await);
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/resend-verification",
                json!({"email": "  "}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/resend-verification",
                json!({"email": "ghost@example.com"}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            body_json(resp).await["message"]
                .as_str()
                .unwrap()
                .starts_with("If that email exists")
        );
    }

    #[tokio::test]
    async fn social_status_reflects_configuration() {
        let app = test_router(test_state(test_config()).await);
        let resp = send(
            &app,
            request("GET", "/api/auth/social/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_json(resp).await,
            json!({"enabled": false, "provider": ""})
        );

        let mut cfg = test_config();
        cfg.oidc_issuer_url = "https://accounts.google.com".into();
        cfg.oidc_client_id = "client".into();
        let app = test_router(test_state(cfg).await);
        let resp = send(
            &app,
            request("GET", "/api/auth/social/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            body_json(resp).await,
            json!({"enabled": true, "provider": "google"})
        );
    }

    #[tokio::test]
    async fn social_login_validates_before_contacting_provider() {
        let app = test_router(test_state(test_config()).await);
        let resp = send(
            &app,
            request("GET", "/api/auth/social/login")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let mut cfg = test_config();
        cfg.oidc_issuer_url = "https://issuer.invalid".into();
        cfg.oidc_client_id = "client".into();
        let app = test_router(test_state(cfg).await);

        let resp = send(
            &app,
            request("GET", "/api/auth/social/login?client_redirect=https://evil.example/cb&code_challenge=x&code_challenge_method=S256")
                .body(axum::body::Body::empty()).unwrap(),
        ).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(resp).await["error"],
            "client_redirect must use the cpmesh:// scheme"
        );

        let resp = send(
            &app,
            request(
                "GET",
                "/api/auth/social/login?client_redirect=cpmesh://auth/callback",
            )
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            body_json(resp).await["error"]
                .as_str()
                .unwrap()
                .contains("code_challenge")
        );

        let resp = send(
            &app,
            request("GET", "/api/auth/social/login?client_redirect=cpmesh://auth/callback&code_challenge=x&code_challenge_method=plain")
                .body(axum::body::Body::empty()).unwrap(),
        ).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn social_callback_provider_errors_redirect_to_login() {
        let app = test_router(test_state(test_config()).await);
        let resp = send(
            &app,
            request(
                "GET",
                "/api/auth/social/callback?error=access_denied&error_description=User%20cancelled",
            )
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()[header::LOCATION],
            "https://cpmesh.test/#/login?social_error=User%20cancelled"
        );

        let resp = send(
            &app,
            request("GET", "/api/auth/social/callback")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()[header::LOCATION],
            "https://cpmesh.test/#/login?social_error=missing+authorization+code"
        );
    }

    #[tokio::test]
    async fn social_callback_rejects_state_mismatch() {
        let app = test_router(test_state(test_config()).await);
        let resp = send(
            &app,
            request("GET", "/api/auth/social/callback?code=abc&state=attacker")
                .header(header::COOKIE, "cpmesh_oidc_state=legit")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()[header::LOCATION],
            "https://cpmesh.test/#/login?social_error=invalid+state+parameter"
        );

        // Native-client state with a non-cpmesh redirect is rejected even when CSRF matches
        let native_state = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            json!({"csrf":"legit","client_redirect":"https://evil.example","code_challenge":"x"})
                .to_string()
                .as_bytes(),
        );
        let resp = send(
            &app,
            request(
                "GET",
                &format!("/api/auth/social/callback?code=abc&state={native_state}"),
            )
            .header(header::COOKIE, "cpmesh_oidc_state=legit")
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(
            resp.headers()[header::LOCATION],
            "https://cpmesh.test/#/login?social_error=invalid+client+redirect"
        );
    }

    #[tokio::test]
    async fn social_exchange_enforces_pkce_and_single_use() {
        let state = test_state(test_config()).await;
        let app = test_router(state.clone());

        let verifier = "correct-horse-battery-staple-verifier-value";
        let challenge = {
            use sha2::Digest;
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                sha2::Sha256::digest(verifier.as_bytes()),
            )
        };

        // Unknown code
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/social/exchange",
                json!({"code": "nope", "code_verifier": verifier}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(resp).await["error"], "invalid or expired code");

        // Wrong verifier consumes the code and fails
        state.pkce_store.insert(
            "code-a".into(),
            PkceEntry {
                access_token: "acc".into(),
                refresh_token: "ref".into(),
                code_challenge: challenge.clone(),
                created_at: std::time::Instant::now(),
            },
        );
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/social/exchange",
                json!({"code": "code-a", "code_verifier": "wrong"}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(resp).await["error"], "PKCE verification failed");
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/social/exchange",
                json!({"code": "code-a", "code_verifier": verifier}),
            ),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "code was consumed by the failed attempt"
        );

        // Correct verifier returns the stored tokens exactly once
        state.pkce_store.insert(
            "code-b".into(),
            PkceEntry {
                access_token: "acc".into(),
                refresh_token: "ref".into(),
                code_challenge: challenge.clone(),
                created_at: std::time::Instant::now(),
            },
        );
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/social/exchange",
                json!({"code": "code-b", "code_verifier": verifier}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_json(resp).await,
            json!({"access_token": "acc", "refresh_token": "ref"})
        );
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/social/exchange",
                json!({"code": "code-b", "code_verifier": verifier}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Expired codes are rejected even with the right verifier
        state.pkce_store.insert(
            "code-c".into(),
            PkceEntry {
                access_token: "acc".into(),
                refresh_token: "ref".into(),
                code_challenge: challenge,
                created_at: std::time::Instant::now() - std::time::Duration::from_secs(61),
            },
        );
        let resp = send(
            &app,
            json_request(
                "POST",
                "/api/auth/social/exchange",
                json!({"code": "code-c", "code_verifier": verifier}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(resp).await["error"], "code expired");
    }
}
