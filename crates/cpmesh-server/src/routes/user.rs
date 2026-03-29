use std::sync::Arc;
use std::net::SocketAddr;
use axum::{extract::{ConnectInfo, Extension, State}, http::StatusCode, response::Response};
use serde_json::json;

use crate::AppState;
use crate::models::AUDIT_PASSWORD_CHANGE;
use super::middleware::{AuthClaims, extract_client_ip, json_error, json_response};

pub async fn handle_get_me(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    let user = match state.db.get_user_by_id(claims.user_id).await {
        Ok(u) => u,
        Err(_) => return json_error("user not found", StatusCode::NOT_FOUND),
    };

    let (email, full_name, country, mobile) = decrypt_user_pii(&user, state.pii.as_ref());

    let mut resp = json!({
        "id": user.id.to_string(),
        "username": user.username,
        "email": email,
        "full_name": full_name,
        "email_verified": user.email_verified,
        "auth_provider": user.auth_provider,
        "is_admin": user.is_admin,
    });

    if let Some(c) = country {
        resp["country"] = json!(c);
    }
    if let Some(m) = mobile {
        resp["mobile"] = json!(m);
    }
    if let Some(ref url) = user.avatar_url {
        resp["avatar_url"] = json!(url);
    }

    json_response(StatusCode::OK, resp)
}

#[derive(serde::Deserialize)]
pub struct ChangePasswordBody {
    pub current_password: String,
    pub new_password: String,
}

pub async fn handle_change_password(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<ChangePasswordBody>,
) -> Response {
    if req.current_password.is_empty() || req.new_password.is_empty() {
        return json_error("current_password and new_password required", StatusCode::BAD_REQUEST);
    }
    if req.new_password.len() < 8 {
        return json_error("new password must be at least 8 characters", StatusCode::BAD_REQUEST);
    }
    if req.new_password.len() > 128 {
        return json_error("new password must be at most 128 characters", StatusCode::BAD_REQUEST);
    }
    if let Err(msg) = crate::routes::auth::validate_password_strength(&req.new_password) {
        return json_error(msg, StatusCode::BAD_REQUEST);
    }

    let user = match state.db.get_user_by_id(claims.user_id).await {
        Ok(u) => u,
        Err(_) => return json_error("user not found", StatusCode::NOT_FOUND),
    };

    if !state.auth.check_password(&user.password, &req.current_password) {
        return json_error("current password is incorrect", StatusCode::UNAUTHORIZED);
    }

    let hash = match state.auth.hash_password(&req.new_password) {
        Ok(h) => h,
        Err(_) => return json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR),
    };

    if let Err(_) = state.db.change_password(claims.user_id, &hash).await {
        return json_error("failed to change password", StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Audit log
    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers.get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok()).map(String::from);
    let pool = state.db.pool.clone();
    let uid = claims.user_id;
    let ip_str = ip.to_string();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(Some(uid))
        .bind(AUDIT_PASSWORD_CHANGE)
        .bind(&ip_str)
        .bind(ua.as_deref())
        .bind(&json!({}))
        .execute(&pool)
        .await;
    });

    json_response(StatusCode::OK, json!({"message": "password changed"}))
}

pub async fn handle_get_my_subscription(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    match state.db.get_user_subscription(claims.user_id).await {
        Ok(sub) => json_response(StatusCode::OK, sub),
        Err(_) => json_error("failed to get subscription", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn decrypt_user_pii(user: &crate::models::User, pii: Option<&crate::pii::PiiService>) -> (String, String, Option<String>, Option<String>) {
    if let Some(p) = pii {
        let email = user.email.as_deref().map(|e| p.decrypt(e).unwrap_or_default()).unwrap_or_default();
        let full_name = p.decrypt(&user.full_name).unwrap_or_default();
        let country = user.country.as_deref().map(|c| p.decrypt(c).unwrap_or_default());
        let mobile = user.mobile.as_deref().map(|m| p.decrypt(m).unwrap_or_default());
        (email, full_name, country, mobile)
    } else {
        (
            user.email.clone().unwrap_or_default(),
            user.full_name.clone(),
            user.country.clone(),
            user.mobile.clone(),
        )
    }
}
