use std::sync::Arc;
use std::net::SocketAddr;
use axum::{extract::{ConnectInfo, Extension, Multipart, Path, State}, http::StatusCode, response::{IntoResponse, Response}};
use serde_json::json;

use crate::AppState;
use crate::models::{AUDIT_ADMIN_DELETE_USER, AUDIT_ADMIN_ASSIGN_SUB, AUDIT_ADMIN_REMOVE_SUB};
use super::middleware::{AuthClaims, extract_client_ip, json_error, json_response};

/// Fire-and-forget audit log for admin actions.
fn admin_audit(pool: &sqlx::PgPool, admin_id: uuid::Uuid, action: &'static str, ip: &str, ua: Option<&str>, details: &serde_json::Value) {
    let pool = pool.clone();
    let ip = ip.to_string();
    let ua = ua.map(String::from);
    let details = details.clone();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(Some(admin_id))
        .bind(action)
        .bind(&ip)
        .bind(ua.as_deref())
        .bind(&details)
        .execute(&pool)
        .await;
    });
}

pub async fn handle_admin_list_users(
    State(state): State<Arc<AppState>>,
) -> Response {
    match state.db.admin_list_users(state.pii.as_ref()).await {
        Ok(users) => json_response(StatusCode::OK, users),
        Err(_) => json_error("failed to list users", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn handle_admin_get_stats(
    State(state): State<Arc<AppState>>,
) -> Response {
    match state.db.admin_get_stats().await {
        Ok(mut stats) => {
            stats.active_connections = state.hub.total_connections().await;
            json_response(StatusCode::OK, stats)
        }
        Err(_) => json_error("failed to get stats", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn handle_admin_delete_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    if user_id == claims.user_id {
        return json_error("cannot delete yourself", StatusCode::BAD_REQUEST);
    }
    if let Err(_) = state.db.admin_delete_user(user_id).await {
        return json_error("user not found", StatusCode::NOT_FOUND);
    }

    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    admin_audit(&state.db.pool, claims.user_id, AUDIT_ADMIN_DELETE_USER, &ip.to_string(), ua, &json!({"deleted_user_id": user_id.to_string()}));

    StatusCode::NO_CONTENT.into_response()
}

#[derive(serde::Deserialize)]
pub struct AssignSubscriptionBody {
    pub plan_id: String,
}

pub async fn handle_admin_assign_subscription(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<AssignSubscriptionBody>,
) -> Response {
    if req.plan_id.is_empty() {
        return json_error("plan_id is required", StatusCode::BAD_REQUEST);
    }
    let plan_id = match uuid::Uuid::parse_str(&req.plan_id) {
        Ok(id) => id,
        Err(_) => return json_error("invalid plan_id", StatusCode::BAD_REQUEST),
    };
    if state.db.get_subscription_plan(plan_id).await.is_err() {
        return json_error("plan not found", StatusCode::NOT_FOUND);
    }
    if let Err(_) = state.db.assign_user_subscription(user_id, plan_id).await {
        return json_error("failed to assign subscription", StatusCode::INTERNAL_SERVER_ERROR);
    }

    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    admin_audit(&state.db.pool, claims.user_id, AUDIT_ADMIN_ASSIGN_SUB, &ip.to_string(), ua, &json!({"target_user_id": user_id.to_string(), "plan_id": req.plan_id}));

    json_response(StatusCode::OK, json!({"message": "subscription assigned"}))
}

pub async fn handle_admin_remove_subscription(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    if let Err(_) = state.db.remove_user_subscription(user_id).await {
        return json_error("failed to remove subscription", StatusCode::INTERNAL_SERVER_ERROR);
    }

    let ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    admin_audit(&state.db.pool, claims.user_id, AUDIT_ADMIN_REMOVE_SUB, &ip.to_string(), ua, &json!({"target_user_id": user_id.to_string()}));

    json_response(StatusCode::OK, json!({"message": "subscription removed"}))
}

pub async fn handle_admin_verify_email(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    if let Err(_) = state.db.set_email_verified(user_id, true).await {
        return json_error("user not found", StatusCode::NOT_FOUND);
    }
    json_response(StatusCode::OK, json!({"message": "email verified"}))
}

// === Plan CRUD ===

pub async fn handle_admin_list_plans(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_subscription_plans().await {
        Ok(plans) => json_response(StatusCode::OK, plans),
        Err(_) => json_error("failed to list plans", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(serde::Deserialize)]
pub struct PlanBody {
    pub name: String,
    #[serde(default)] pub description: String,
    #[serde(default)] pub price: f64,
    #[serde(default = "default_currency")] pub currency: String,
    #[serde(default = "default_billing_period")] pub billing_period: String,
    #[serde(default = "default_max_devices")] pub max_devices: i32,
    #[serde(default = "default_max_history")] pub max_clipboard_history: i32,
    #[serde(default)] pub allowed_file_types: Vec<String>,
    #[serde(default = "default_true")] pub is_active: bool,
    #[serde(default)] pub sort_order: i32,
}
fn default_currency() -> String { "USD".to_string() }
fn default_billing_period() -> String { "monthly".to_string() }
fn default_max_devices() -> i32 { 5 }
fn default_max_history() -> i32 { 100 }
fn default_true() -> bool { true }

pub async fn handle_admin_create_plan(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<PlanBody>,
) -> Response {
    if req.name.is_empty() {
        return json_error("name is required", StatusCode::BAD_REQUEST);
    }
    let ft = serde_json::to_value(&req.allowed_file_types).unwrap_or_default();
    match state.db.create_subscription_plan(&req.name, &req.description, req.price, &req.currency, &req.billing_period, req.max_devices, req.max_clipboard_history, &ft, req.is_active, req.sort_order).await {
        Ok(plan) => json_response(StatusCode::CREATED, plan),
        Err(_) => json_error("failed to create plan", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn handle_admin_update_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<PlanBody>,
) -> Response {
    if req.name.is_empty() {
        return json_error("name is required", StatusCode::BAD_REQUEST);
    }
    let ft = serde_json::to_value(&req.allowed_file_types).unwrap_or_default();
    match state.db.update_subscription_plan(plan_id, &req.name, &req.description, req.price, &req.currency, &req.billing_period, req.max_devices, req.max_clipboard_history, &ft, req.is_active, req.sort_order).await {
        Ok(plan) => json_response(StatusCode::OK, plan),
        Err(_) => json_error("failed to update plan", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn handle_admin_delete_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<uuid::Uuid>,
) -> Response {
    match state.db.delete_subscription_plan(plan_id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => json_error(&e, StatusCode::CONFLICT),
    }
}

// === Download CRUD ===

pub async fn handle_admin_list_downloads(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_download_links().await {
        Ok(links) => json_response(StatusCode::OK, links),
        Err(_) => json_error("failed to list downloads", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(serde::Deserialize)]
pub struct DownloadBody {
    pub name: String,
    pub url: String,
    #[serde(default = "default_unknown")] pub platform: String,
    #[serde(default)] pub arch: String,
    #[serde(default)] pub format: String,
    #[serde(default)] pub sort_order: i32,
    #[serde(default = "default_true")] pub is_active: bool,
    #[serde(default)] pub release_id: Option<String>,
}
fn default_unknown() -> String { "unknown".to_string() }

pub async fn handle_admin_create_download(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<DownloadBody>,
) -> Response {
    if req.name.is_empty() || req.url.is_empty() {
        return json_error("name and url are required", StatusCode::BAD_REQUEST);
    }
    let release_id = req.release_id.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    match state.db.create_download_link(&req.name, &req.url, &req.platform, &req.arch, &req.format, req.sort_order, req.is_active, release_id).await {
        Ok(link) => json_response(StatusCode::CREATED, link),
        Err(_) => json_error("failed to create download link", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn handle_admin_update_download(
    State(state): State<Arc<AppState>>,
    Path(link_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<DownloadBody>,
) -> Response {
    if req.name.is_empty() || req.url.is_empty() {
        return json_error("name and url are required", StatusCode::BAD_REQUEST);
    }
    let release_id = req.release_id.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    match state.db.update_download_link(link_id, &req.name, &req.url, &req.platform, &req.arch, &req.format, req.sort_order, req.is_active, release_id).await {
        Ok(link) => json_response(StatusCode::OK, link),
        Err(_) => json_error("failed to update download link", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn handle_admin_delete_download(
    State(state): State<Arc<AppState>>,
    Path(link_id): Path<uuid::Uuid>,
) -> Response {
    if let Err(_) = state.db.delete_download_link(link_id).await {
        return json_error("download link not found", StatusCode::NOT_FOUND);
    }
    StatusCode::NO_CONTENT.into_response()
}

// === Test Connections ===

#[derive(serde::Deserialize)]
pub struct TestSmtpBody {
    pub to_email: String,
}

pub async fn handle_admin_test_smtp(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<TestSmtpBody>,
) -> Response {
    if req.to_email.is_empty() {
        return json_error("to_email is required", StatusCode::BAD_REQUEST);
    }

    match state.email.test_connection(&req.to_email) {
        Ok(_) => json_response(StatusCode::OK, json!({"message": "Test email sent successfully."})),
        Err(e) => json_response(StatusCode::OK, json!({"error": e})),
    }
}

pub async fn handle_admin_test_oidc(
    State(state): State<Arc<AppState>>,
) -> Response {
    let issuer_url = &state.config.oidc_issuer_url;

    if issuer_url.is_empty() {
        return json_response(StatusCode::OK, json!({"error": "OIDC_ISSUER_URL is not configured in env."}));
    }

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/'),
    );

    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(e) => return json_response(StatusCode::OK, json!({"error": format!("HTTP client error: {e}")})),
    };

    match client.get(&discovery_url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<serde_json::Value>().await {
                    Ok(doc) => {
                        let issuer = doc.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
                        let auth_ep = doc.get("authorization_endpoint").and_then(|v| v.as_str()).unwrap_or("");
                        json_response(StatusCode::OK, json!({
                            "message": "OIDC discovery successful.",
                            "issuer": issuer,
                            "authorization_endpoint": auth_ep,
                        }))
                    }
                    Err(e) => json_response(StatusCode::OK, json!({"error": format!("Failed to parse discovery document: {e}")})),
                }
            } else {
                json_response(StatusCode::OK, json!({"error": format!("Discovery endpoint returned HTTP {}", resp.status())}))
            }
        }
        Err(e) => json_response(StatusCode::OK, json!({"error": format!("Failed to connect to issuer: {e}")})),
    }
}

// === File Upload ===

pub async fn handle_admin_upload_binary(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Response {
    let downloads_dir = &state.config.downloads_dir;
    if downloads_dir.is_empty() {
        return json_error("DOWNLOADS_DIR not configured", StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Ensure directory exists
    if let Err(e) = tokio::fs::create_dir_all(downloads_dir).await {
        return json_error(&format!("cannot create downloads dir: {e}"), StatusCode::INTERNAL_SERVER_ERROR);
    }

    let mut uploaded = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let file_name = match field.file_name() {
            Some(name) => name.to_string(),
            None => continue,
        };

        // Sanitize filename
        if file_name.is_empty() || file_name.contains('/') || file_name.contains('\\') || file_name.contains("..") {
            return json_error("invalid filename", StatusCode::BAD_REQUEST);
        }

        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => return json_error(&format!("failed to read upload: {e}"), StatusCode::BAD_REQUEST),
        };

        // Max 500MB per file
        if data.len() > 500 * 1024 * 1024 {
            return json_error("file too large (max 500MB)", StatusCode::PAYLOAD_TOO_LARGE);
        }

        let dest = std::path::Path::new(downloads_dir).join(&file_name);
        if let Err(e) = tokio::fs::write(&dest, &data).await {
            return json_error(&format!("failed to write file: {e}"), StatusCode::INTERNAL_SERVER_ERROR);
        }

        // Auto-create download link entry
        let url = format!("/api/downloads/{}", file_name);
        let (platform, arch, format) = crate::db::detect_platform_arch_format(&file_name);
        let _ = state.db.create_download_link(&file_name, &url, &platform, &arch, &format, 0, true, None).await;

        uploaded.push(json!({
            "filename": file_name,
            "size": data.len(),
            "url": url,
        }));
    }

    if uploaded.is_empty() {
        return json_error("no files uploaded", StatusCode::BAD_REQUEST);
    }

    json_response(StatusCode::OK, json!({ "uploaded": uploaded }))
}

// === App Release CRUD ===

pub async fn handle_admin_list_releases(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_app_releases().await {
        Ok(releases) => json_response(StatusCode::OK, releases),
        Err(_) => json_error("failed to list releases", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(serde::Deserialize)]
pub struct ReleaseBody {
    pub version: String,
    #[serde(default = "default_unknown")] pub platform: String,
    #[serde(default)] pub arch: String,
    pub download_url: String,
    #[serde(default)] pub release_notes: String,
    #[serde(default)] pub is_current: bool,
}

pub async fn handle_admin_create_release(
    State(state): State<Arc<AppState>>,
    axum::Json(req): axum::Json<ReleaseBody>,
) -> Response {
    if req.version.is_empty() || req.download_url.is_empty() {
        return json_error("version and download_url are required", StatusCode::BAD_REQUEST);
    }
    match state.db.create_app_release(&req.version, &req.platform, &req.arch, &req.download_url, &req.release_notes, req.is_current).await {
        Ok(rel) => json_response(StatusCode::CREATED, rel),
        Err(_) => json_error("failed to create release", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn handle_admin_update_release(
    State(state): State<Arc<AppState>>,
    Path(release_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<ReleaseBody>,
) -> Response {
    if req.version.is_empty() || req.download_url.is_empty() {
        return json_error("version and download_url are required", StatusCode::BAD_REQUEST);
    }
    match state.db.update_app_release(release_id, &req.version, &req.platform, &req.arch, &req.download_url, &req.release_notes, req.is_current).await {
        Ok(rel) => json_response(StatusCode::OK, rel),
        Err(_) => json_error("failed to update release", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn handle_admin_delete_release(
    State(state): State<Arc<AppState>>,
    Path(release_id): Path<uuid::Uuid>,
) -> Response {
    if let Err(_) = state.db.delete_app_release(release_id).await {
        return json_error("release not found", StatusCode::NOT_FOUND);
    }
    StatusCode::NO_CONTENT.into_response()
}

// === Audit Logs ===

#[derive(serde::Deserialize)]
pub struct AuditLogQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub user_id: Option<String>,
    pub action: Option<String>,
}

pub async fn handle_admin_list_audit_logs(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<AuditLogQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(50).min(500);
    let offset = query.offset.unwrap_or(0);
    let user_id = query.user_id.as_deref().and_then(|s| uuid::Uuid::parse_str(s).ok());
    let action = query.action.as_deref();

    match state.db.list_audit_logs(limit, offset, user_id, action).await {
        Ok(logs) => json_response(StatusCode::OK, logs),
        Err(_) => json_error("failed to list audit logs", StatusCode::INTERNAL_SERVER_ERROR),
    }
}
