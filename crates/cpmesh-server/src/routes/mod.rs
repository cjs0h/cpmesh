pub mod admin;
pub mod approval;
pub mod auth;
pub mod auth_service;
pub mod clipboard;
pub mod devices;
pub mod downloads;
pub mod middleware;
pub mod user;
pub mod websocket;

#[cfg(test)]
mod tests;

use axum::http::{HeaderValue, Method};
use axum::{Router, extract::DefaultBodyLimit, middleware as axum_mw};
use std::sync::Arc;
use tower_http::cors::{AllowHeaders, Any, CorsLayer};

use crate::AppState;
use crate::spa::spa_handler;

pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = build_cors(&state.config.allowed_origins);

    // Rate-limited auth routes (login, register, refresh, resend-verification)
    let auth_limited = Router::new()
        .route(
            "/api/auth/register",
            axum::routing::post(auth::handle_register),
        )
        .route("/api/auth/login", axum::routing::post(auth::handle_login))
        .route(
            "/api/auth/refresh",
            axum::routing::post(auth::handle_refresh),
        )
        .route(
            "/api/auth/resend-verification",
            axum::routing::post(auth::handle_resend_verification),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::rate_limit_auth,
        ));

    // Non-rate-limited public auth routes
    let auth_open = Router::new()
        .route(
            "/api/auth/verify-email",
            axum::routing::get(auth::handle_verify_email),
        )
        .route(
            "/api/auth/social/status",
            axum::routing::get(auth::handle_social_status),
        )
        .route(
            "/api/auth/social/login",
            axum::routing::get(auth::handle_social_login),
        )
        .route(
            "/api/auth/social/callback",
            axum::routing::get(auth::handle_social_callback),
        )
        .route(
            "/api/auth/social/exchange",
            axum::routing::post(auth::handle_social_exchange),
        );

    // Other public routes
    let public = Router::new()
        .merge(auth_limited)
        .merge(auth_open)
        .route(
            "/api/downloads",
            axum::routing::get(downloads::handle_list_downloads),
        )
        .route(
            "/api/downloads/current",
            axum::routing::get(downloads::handle_list_current_release_downloads),
        )
        .route(
            "/api/downloads/{filename}",
            axum::routing::get(downloads::handle_download_file),
        )
        .route(
            "/api/updates/check",
            axum::routing::get(downloads::handle_check_update),
        )
        .route(
            "/api/plans",
            axum::routing::get(auth::handle_list_active_plans),
        );

    // Protected routes accessible to ALL authenticated devices (including pending)
    let protected_any_device = Router::new()
        .route(
            "/api/device-approvals/me",
            axum::routing::get(approval::handle_my_approval_status),
        )
        .route(
            "/api/devices",
            axum::routing::post(devices::handle_register_device),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    // Protected routes requiring APPROVED device status
    let protected_approved = Router::new()
        .route("/api/me", axum::routing::get(user::handle_get_me))
        .route(
            "/api/me/password",
            axum::routing::put(user::handle_change_password),
        )
        .route(
            "/api/me/subscription",
            axum::routing::get(user::handle_get_my_subscription),
        )
        .route(
            "/api/devices",
            axum::routing::get(devices::handle_list_devices),
        )
        .route(
            "/api/devices/{id}",
            axum::routing::delete(devices::handle_delete_device),
        )
        .route(
            "/api/devices/keys",
            axum::routing::get(devices::handle_get_device_keys),
        )
        // Legacy group key endpoints (backward compatibility)
        .route(
            "/api/group-key",
            axum::routing::get(devices::handle_get_group_key)
                .post(devices::handle_store_group_keys),
        )
        // Versioned group key endpoints
        .route(
            "/api/group-keys/current",
            axum::routing::get(devices::handle_get_current_group_keys),
        )
        .route(
            "/api/group-keys/rotate",
            axum::routing::post(devices::handle_rotate_group_key),
        )
        // Device approval endpoints (approver must be approved)
        .route(
            "/api/device-approvals/pending",
            axum::routing::get(approval::handle_list_pending),
        )
        .route(
            "/api/device-approvals/{pending_device_id}/begin",
            axum::routing::post(approval::handle_begin_approval),
        )
        .route(
            "/api/device-approvals/{pending_device_id}/approve",
            axum::routing::post(approval::handle_approve_device),
        )
        .route(
            "/api/device-approvals/{pending_device_id}/reject",
            axum::routing::post(approval::handle_reject_device),
        )
        // Clipboard
        .route(
            "/api/clipboard",
            axum::routing::get(clipboard::handle_get_clipboard_history)
                .delete(clipboard::handle_clear_clipboard),
        )
        .route(
            "/api/clipboard/{id}",
            axum::routing::delete(clipboard::handle_delete_clipboard_entry),
        )
        // WebSocket
        .route(
            "/api/ws/ticket",
            axum::routing::post(websocket::handle_ws_ticket),
        )
        .route("/ws", axum::routing::get(websocket::handle_ws_upgrade))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::approved_device_middleware,
        ))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    // Admin routes (protected + admin check)
    let admin_routes = Router::new()
        .route(
            "/api/admin/users",
            axum::routing::get(admin::handle_admin_list_users),
        )
        .route(
            "/api/admin/stats",
            axum::routing::get(admin::handle_admin_get_stats),
        )
        .route(
            "/api/admin/users/{id}",
            axum::routing::delete(admin::handle_admin_delete_user),
        )
        .route(
            "/api/admin/users/{id}/subscription",
            axum::routing::put(admin::handle_admin_assign_subscription)
                .delete(admin::handle_admin_remove_subscription),
        )
        .route(
            "/api/admin/users/{id}/verify-email",
            axum::routing::put(admin::handle_admin_verify_email),
        )
        .route(
            "/api/admin/plans",
            axum::routing::get(admin::handle_admin_list_plans)
                .post(admin::handle_admin_create_plan),
        )
        .route(
            "/api/admin/plans/{id}",
            axum::routing::put(admin::handle_admin_update_plan)
                .delete(admin::handle_admin_delete_plan),
        )
        .route(
            "/api/admin/downloads",
            axum::routing::get(admin::handle_admin_list_downloads)
                .post(admin::handle_admin_create_download),
        )
        .route(
            "/api/admin/downloads/{id}",
            axum::routing::put(admin::handle_admin_update_download)
                .delete(admin::handle_admin_delete_download),
        )
        .route(
            "/api/admin/downloads/upload",
            axum::routing::post(admin::handle_admin_upload_binary),
        )
        .layer(DefaultBodyLimit::max(500 * 1024 * 1024)) // 500MB for file uploads
        .route(
            "/api/admin/releases",
            axum::routing::get(admin::handle_admin_list_releases)
                .post(admin::handle_admin_create_release),
        )
        .route(
            "/api/admin/releases/{id}",
            axum::routing::put(admin::handle_admin_update_release)
                .delete(admin::handle_admin_delete_release),
        )
        .route(
            "/api/admin/test/smtp",
            axum::routing::post(admin::handle_admin_test_smtp),
        )
        .route(
            "/api/admin/test/oidc",
            axum::routing::post(admin::handle_admin_test_oidc),
        )
        .route(
            "/api/admin/audit-logs",
            axum::routing::get(admin::handle_admin_list_audit_logs),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::admin_middleware,
        ))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    Router::new()
        .merge(public)
        .merge(protected_any_device)
        .merge(protected_approved)
        .merge(admin_routes)
        .fallback(spa_handler)
        .layer(axum_mw::from_fn(middleware::security_headers))
        .layer(cors)
        .with_state(state)
}

fn build_cors(allowed_origins: &[String]) -> CorsLayer {
    if allowed_origins.is_empty() {
        return CorsLayer::new()
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers(Any);
    }

    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    // With credentials enabled, browsers (and tower-http) reject the `*` wildcard for
    // headers, so echo back whatever headers the preflight request asks for instead.
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(AllowHeaders::mirror_request())
        .allow_credentials(true)
}
