pub mod admin;
pub mod approval;
pub mod auth;
pub mod auth_service;
pub mod clipboard;
pub mod devices;
pub mod downloads;
pub mod mfa;
pub mod middleware;
pub mod settings;
pub mod user;
pub mod websocket;

#[cfg(test)]
mod flow_tests;
#[cfg(test)]
mod tests;

use axum::http::{HeaderValue, Method};
use axum::{Router, extract::DefaultBodyLimit, middleware as axum_mw};
use std::sync::Arc;
use tower_http::cors::{AllowHeaders, Any, CorsLayer};

use crate::AppState;
use crate::oauth;
use crate::spa::spa_handler;

/// Body limit of the installer upload route: room for an installer, its signature
/// and multipart framing (each file is capped while it streams to disk).
const UPLOAD_BODY_LIMIT: usize = 2 * admin::MAX_UPLOAD_BYTES as usize;

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
        )
        .route(
            "/api/settings",
            axum::routing::get(settings::handle_public_settings),
        );

    // Two-factor authentication: a session, or a sign-in waiting for its second factor
    let mfa_routes = Router::new()
        .route("/api/mfa", axum::routing::get(mfa::handle_status))
        .route(
            "/api/mfa/totp/setup",
            axum::routing::post(mfa::handle_totp_setup),
        )
        .route(
            "/api/mfa/totp",
            axum::routing::delete(mfa::handle_totp_disable),
        )
        .route(
            "/api/mfa/passkeys/options",
            axum::routing::post(mfa::handle_passkey_options),
        )
        .route(
            "/api/mfa/passkeys",
            axum::routing::post(mfa::handle_passkey_register),
        )
        .route(
            "/api/mfa/passkeys/{id}",
            axum::routing::delete(mfa::handle_passkey_delete).patch(mfa::handle_passkey_rename),
        )
        .route(
            "/api/mfa/verify/options",
            axum::routing::post(mfa::handle_verify_options),
        )
        .route(
            "/api/mfa/recovery-codes",
            axum::routing::post(mfa::handle_regenerate_recovery_codes),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::mfa_principal_middleware,
        ));

    // Endpoints that check codes are also rate limited per client address
    let mfa_code_routes = Router::new()
        .route("/api/mfa/verify", axum::routing::post(mfa::handle_verify))
        .route(
            "/api/mfa/totp/enable",
            axum::routing::post(mfa::handle_totp_enable),
        )
        .route(
            "/api/mfa/email-code",
            axum::routing::post(mfa::handle_send_email_code),
        )
        .route(
            "/api/mfa/email-code/verify",
            axum::routing::post(mfa::handle_verify_email_code),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::mfa_principal_middleware,
        ))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::rate_limit_auth,
        ));

    // Protected routes accessible to ALL authenticated devices (including pending)
    let protected_any_device = Router::new()
        .route(
            "/api/devices/challenge",
            axum::routing::post(devices::handle_device_challenge),
        )
        .route(
            "/api/device-approvals/me",
            axum::routing::get(approval::handle_my_approval_status),
        )
        .route(
            "/api/device-approvals/me/nonce",
            axum::routing::post(approval::handle_pending_nonce),
        )
        .route(
            "/api/devices",
            axum::routing::post(devices::handle_register_device),
        )
        .route(
            "/api/devices/me/encryption-key",
            axum::routing::put(devices::handle_publish_encryption_key),
        )
        // Hands a fresh web sign-in to the desktop app ("Sign in with browser")
        .route(
            "/api/auth/native-code",
            axum::routing::post(auth::handle_native_code),
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
            "/api/device-approvals/{pending_device_id}/session",
            axum::routing::get(approval::handle_approval_session),
        )
        .route(
            "/api/device-approvals/{pending_device_id}/reveal",
            axum::routing::post(approval::handle_reveal_nonce),
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
        // Single-use ticket for browser WebSockets
        .route(
            "/api/ws/ticket",
            axum::routing::post(websocket::handle_ws_ticket),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::approved_device_middleware,
        ))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    // WebSocket: authenticated by a bearer token or a single-use ticket
    let websocket = Router::new()
        .route("/ws", axum::routing::get(websocket::handle_ws_upgrade))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            websocket::ws_auth_middleware,
        ));

    // Admin console: staff sessions confirmed with a second factor
    let admin_routes = Router::new()
        .route(
            "/api/admin/users",
            axum::routing::get(admin::handle_admin_list_users),
        )
        .route(
            "/api/admin/users/{id}",
            axum::routing::get(admin::handle_admin_get_user)
                .delete(admin::handle_admin_delete_user),
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
            "/api/admin/users/{id}/resend-verification",
            axum::routing::post(admin::handle_admin_resend_verification),
        )
        .route(
            "/api/admin/users/{id}/suspend",
            axum::routing::post(admin::handle_admin_suspend_user),
        )
        .route(
            "/api/admin/users/{id}/unsuspend",
            axum::routing::post(admin::handle_admin_unsuspend_user),
        )
        .route(
            "/api/admin/users/{id}/revoke-sessions",
            axum::routing::post(admin::handle_admin_revoke_sessions),
        )
        .route(
            "/api/admin/users/{id}/role",
            axum::routing::put(admin::handle_admin_set_role),
        )
        .route(
            "/api/admin/users/{id}/mfa",
            axum::routing::delete(admin::handle_admin_reset_mfa),
        )
        .route(
            "/api/admin/stats",
            axum::routing::get(admin::handle_admin_get_stats),
        )
        .route(
            "/api/admin/audit-logs",
            axum::routing::get(admin::handle_admin_list_audit_logs),
        )
        .route(
            "/api/admin/audit-logs/actions",
            axum::routing::get(admin::handle_admin_audit_actions),
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
        // Installers are streamed to disk; only this route accepts large bodies
        .route(
            "/api/admin/downloads/upload",
            axum::routing::post(admin::handle_admin_upload_binary)
                .layer(DefaultBodyLimit::max(UPLOAD_BODY_LIMIT)),
        )
        .route(
            "/api/admin/settings",
            axum::routing::get(admin::handle_admin_get_settings)
                .put(admin::handle_admin_update_settings),
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
            "/api/admin/api-tokens",
            axum::routing::get(admin::handle_admin_list_api_tokens)
                .post(admin::handle_admin_create_api_token),
        )
        .route(
            "/api/admin/api-tokens/{id}",
            axum::routing::delete(admin::handle_admin_revoke_api_token),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::admin_middleware,
        ))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    // Release publishing: staff sessions, or an API token with the releases scope (CI)
    let release_routes = Router::new()
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
            "/api/admin/releases",
            axum::routing::get(admin::handle_admin_list_releases)
                .post(admin::handle_admin_create_release),
        )
        .route(
            "/api/admin/releases/{id}",
            axum::routing::put(admin::handle_admin_update_release)
                .delete(admin::handle_admin_delete_release),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::release_admin_middleware,
        ));

    // OAuth for agents: the authorization server's endpoints, which take no bearer
    // token. They limit their own rates: device polling must not use up the address's
    // sign-in budget.
    let oauth_server = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(oauth::server::handle_metadata),
        )
        .route(
            "/oauth/authorize",
            axum::routing::get(oauth::server::handle_authorize),
        )
        .route(
            "/oauth/token",
            axum::routing::post(oauth::server::handle_token),
        )
        .route(
            "/oauth/revoke",
            axum::routing::post(oauth::server::handle_revoke),
        )
        .route(
            "/oauth/device_authorization",
            axum::routing::post(oauth::server::handle_device_authorization),
        )
        .route(
            "/activate",
            axum::routing::get(oauth::server::handle_activate),
        );

    // Approving agents and the "Connected agents" list: first-party sessions
    let oauth_consent = Router::new()
        .route(
            "/api/oauth/authorize",
            axum::routing::post(oauth::consent::handle_authorize_decision),
        )
        .route(
            "/api/oauth/device",
            axum::routing::get(oauth::consent::handle_device_lookup),
        )
        .route(
            "/api/oauth/device/approve",
            axum::routing::post(oauth::consent::handle_device_approve),
        )
        .route(
            "/api/oauth/device/deny",
            axum::routing::post(oauth::consent::handle_device_deny),
        )
        .route(
            "/api/oauth/grants",
            axum::routing::get(oauth::consent::handle_list_grants),
        )
        .route(
            "/api/oauth/grants/{id}",
            axum::routing::delete(oauth::consent::handle_revoke_grant),
        )
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::approved_device_middleware,
        ))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    Router::new()
        .merge(public)
        .merge(protected_any_device)
        .merge(protected_approved)
        .merge(websocket)
        .merge(admin_routes)
        .merge(release_routes)
        .merge(mfa_routes)
        .merge(mfa_code_routes)
        .merge(oauth_server)
        .merge(oauth_consent)
        .fallback(spa_handler)
        // Default-deny for agent tokens. It wraps only the routes merged above, and sees
        // which one matched.
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            crate::oauth::policy::agent_policy_middleware,
        ))
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
