//! Admin console API (`/api/admin/*`).
//!
//! Every handler receives the [`AdminContext`] set up by the admin middleware (a
//! staff session confirmed with a second factor, or an API token for the release
//! routes), checks the permission it needs, and records what it changed in the
//! audit log. Sensitive actions also need a recent sign-in.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use axum::{
    extract::{Extension, Multipart, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use sha2::Digest;
use tokio::io::AsyncWriteExt;

use super::middleware::{
    API_TOKEN_PREFIX, AdminContext, ApiError, SCOPE_RELEASES, api_token_hash, json_error,
    json_response,
};
use crate::AppState;
use crate::audit::{self, RequestMeta};
use crate::db::{AuditFilter, RoleChange, UserListFilter};
use crate::models::*;
use crate::rbac::{Permission, Role};
use crate::settings::{self, Banner};

/// Largest installer accepted by the upload endpoint.
pub const MAX_UPLOAD_BYTES: u64 = 500 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 4096;

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::warn!("admin endpoint failed: {e}");
    json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR)
}

/// Returns early with the error response when a check fails.
macro_rules! check {
    ($e:expr) => {
        if let Err(error) = $e {
            return error.into_response();
        }
    };
}

async fn load_target(state: &AppState, user_id: uuid::Uuid) -> Result<User, ApiError> {
    match state.db.get_user_by_id(user_id).await {
        Ok(user) => Ok(user),
        Err(sqlx::Error::RowNotFound) => {
            Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"))
        }
        Err(e) => Err(ApiError::internal(e)),
    }
}

fn not_self(ctx: &AdminContext, target: uuid::Uuid, what: &str) -> Result<(), ApiError> {
    if ctx.user_id == target {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("you cannot {what} your own account"),
        ))
    } else {
        Ok(())
    }
}

/// Signs the user out everywhere: revokes their tokens and closes live connections.
async fn end_sessions(state: &AppState, user_id: uuid::Uuid) -> Result<(), ApiError> {
    state
        .db
        .revoke_all_user_tokens(user_id, crate::routes::auth_service::now_epoch())
        .await
        .map_err(ApiError::internal)?;
    state.hub.disconnect_user(&user_id.to_string()).await;
    Ok(())
}

// === Users ===

#[derive(Deserialize)]
pub struct UserListQuery {
    pub q: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
    pub plan_id: Option<uuid::Uuid>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

pub async fn handle_admin_list_users(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    Query(query): Query<UserListQuery>,
) -> Response {
    check!(ctx.require(Permission::View));
    let filter = UserListFilter {
        query: query.q.as_deref(),
        role: query.role.as_deref().filter(|r| !r.is_empty()),
        status: query.status.as_deref().filter(|s| !s.is_empty()),
        plan_id: query.plan_id,
        page: query.page.unwrap_or(1),
        per_page: query.per_page.unwrap_or(25),
    };
    match state.db.admin_list_users(&filter, state.pii.as_ref()).await {
        Ok(page) => json_response(StatusCode::OK, page),
        Err(e) => internal(e),
    }
}

pub async fn handle_admin_get_user(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    check!(ctx.require(Permission::View));
    let user = match state.db.admin_get_user(user_id, state.pii.as_ref()).await {
        Ok(Some(u)) => u,
        Ok(None) => return json_error("user not found", StatusCode::NOT_FOUND),
        Err(e) => return internal(e),
    };
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    let devices = match state.db.get_devices_by_user(user_id).await {
        Ok(d) => d,
        Err(e) => return internal(e),
    };
    let mut device_rows = Vec::with_capacity(devices.len());
    for d in &devices {
        device_rows.push(json!({
            "id": d.id,
            "name": d.name,
            "status": d.status,
            "last_seen": d.last_seen,
            "created_at": d.created_at,
            "online": state.hub.is_device_online(&user_id.to_string(), &d.id.to_string()).await,
        }));
    }
    let mfa = match state.db.mfa_summary(user_id).await {
        Ok(s) => s,
        Err(e) => return internal(e),
    };
    let (activity, _) = match state
        .db
        .list_audit_entries(&AuditFilter {
            user_id: Some(user_id),
            action: None,
            limit: 25,
            offset: 0,
        })
        .await
    {
        Ok(a) => a,
        Err(e) => return internal(e),
    };
    json_response(
        StatusCode::OK,
        json!({
            "user": user,
            "suspended_reason": target.suspended_reason,
            "devices": device_rows,
            "connections": state.hub.user_connection_count(&user_id.to_string()).await,
            "mfa": {
                "enabled": mfa.enabled(),
                "required": crate::mfa::required_for(&state.config, &target),
                "totp": mfa.totp,
                "passkeys": mfa.passkeys,
                "recovery_codes_remaining": mfa.recovery_codes,
            },
            "recent_activity": activity,
        }),
    )
}

pub async fn handle_admin_delete_user(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    check!(not_self(&ctx, user_id, "delete"));
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    check!(ctx.require_on(Permission::DeleteUsers, target.role()));
    check!(ctx.require_recent_auth());

    state.hub.disconnect_user(&user_id.to_string()).await;
    match state.db.admin_delete_user(user_id).await {
        Ok(()) => {}
        Err(sqlx::Error::RowNotFound) => {
            return json_error("user not found", StatusCode::NOT_FOUND);
        }
        Err(e) => return internal(e),
    }
    audit::record(
        &state,
        Some(ctx.user_id),
        None,
        AUDIT_ADMIN_DELETE_USER,
        &meta,
        json!({"deleted_user_id": user_id, "username": target.username, "role": target.role}),
    );
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
pub struct AssignSubscriptionBody {
    pub plan_id: String,
}

pub async fn handle_admin_assign_subscription(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<AssignSubscriptionBody>,
) -> Response {
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    check!(ctx.require_on(Permission::ManageUsers, target.role()));
    let plan_id = match uuid::Uuid::parse_str(req.plan_id.trim()) {
        Ok(id) => id,
        Err(_) => return json_error("invalid plan_id", StatusCode::BAD_REQUEST),
    };
    let plan = match state.db.get_subscription_plan(plan_id).await {
        Ok(p) => p,
        Err(sqlx::Error::RowNotFound) => {
            return json_error("plan not found", StatusCode::NOT_FOUND);
        }
        Err(e) => return internal(e),
    };
    match state.db.assign_user_subscription(user_id, plan_id).await {
        Ok(()) => {}
        Err(sqlx::Error::RowNotFound) => {
            return json_error("user not found", StatusCode::NOT_FOUND);
        }
        Err(e) => return internal(e),
    }
    audit::record(
        &state,
        Some(ctx.user_id),
        Some(user_id),
        AUDIT_ADMIN_ASSIGN_SUB,
        &meta,
        json!({"plan_id": plan_id, "plan_name": plan.name}),
    );
    json_response(StatusCode::OK, json!({"message": "subscription assigned"}))
}

pub async fn handle_admin_remove_subscription(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    check!(ctx.require_on(Permission::ManageUsers, target.role()));
    match state.db.remove_user_subscription(user_id).await {
        Ok(()) => {}
        Err(sqlx::Error::RowNotFound) => {
            return json_error("user not found", StatusCode::NOT_FOUND);
        }
        Err(e) => return internal(e),
    }
    audit::record(
        &state,
        Some(ctx.user_id),
        Some(user_id),
        AUDIT_ADMIN_REMOVE_SUB,
        &meta,
        json!({}),
    );
    json_response(StatusCode::OK, json!({"message": "subscription removed"}))
}

pub async fn handle_admin_verify_email(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    check!(ctx.require_on(Permission::ManageUsers, target.role()));
    if let Err(e) = state.db.set_email_verified(user_id, true).await {
        return internal(e);
    }
    audit::record(
        &state,
        Some(ctx.user_id),
        Some(user_id),
        AUDIT_ADMIN_VERIFY_EMAIL,
        &meta,
        json!({}),
    );
    json_response(StatusCode::OK, json!({"message": "email verified"}))
}

pub async fn handle_admin_resend_verification(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    check!(ctx.require_on(Permission::ManageUsers, target.role()));
    if target.email_verified {
        return json_error(
            "this email address is already verified",
            StatusCode::CONFLICT,
        );
    }
    if !state.email.is_configured() {
        return json_error("email is not configured", StatusCode::SERVICE_UNAVAILABLE);
    }
    let email = crate::mfa::user_email(&state, &target);
    if email.is_empty() {
        return json_error("this account has no email address", StatusCode::BAD_REQUEST);
    }
    let token = match state.db.create_email_verification(user_id).await {
        Ok(t) => t,
        Err(e) => return internal(e),
    };
    let name = crate::mfa::user_display_name(&state, &target);
    let mailer = state.clone();
    let sent = tokio::task::spawn_blocking(move || {
        mailer.email.send_verification_email(&email, &name, &token)
    })
    .await;
    match sent {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return json_error(
                &format!("could not send email: {e}"),
                StatusCode::BAD_GATEWAY,
            );
        }
        Err(e) => return internal(e),
    }
    audit::record(
        &state,
        Some(ctx.user_id),
        Some(user_id),
        AUDIT_ADMIN_RESEND_VERIFICATION,
        &meta,
        json!({}),
    );
    json_response(
        StatusCode::OK,
        json!({"message": "verification email sent"}),
    )
}

#[derive(Deserialize)]
pub struct SuspendBody {
    #[serde(default)]
    pub reason: String,
}

pub async fn handle_admin_suspend_user(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<SuspendBody>,
) -> Response {
    check!(not_self(&ctx, user_id, "suspend"));
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    check!(ctx.require_on(Permission::ManageUsers, target.role()));
    let reason: String = req.reason.trim().chars().take(500).collect();
    if let Err(e) = state.db.suspend_user(user_id, &reason).await {
        return internal(e);
    }
    check!(end_sessions(&state, user_id).await);
    audit::record(
        &state,
        Some(ctx.user_id),
        Some(user_id),
        AUDIT_ADMIN_SUSPEND,
        &meta,
        json!({"reason": reason}),
    );
    json_response(StatusCode::OK, json!({"message": "user suspended"}))
}

pub async fn handle_admin_unsuspend_user(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    check!(ctx.require_on(Permission::ManageUsers, target.role()));
    if let Err(e) = state.db.unsuspend_user(user_id).await {
        return internal(e);
    }
    audit::record(
        &state,
        Some(ctx.user_id),
        Some(user_id),
        AUDIT_ADMIN_UNSUSPEND,
        &meta,
        json!({}),
    );
    json_response(StatusCode::OK, json!({"message": "user reinstated"}))
}

pub async fn handle_admin_revoke_sessions(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    check!(ctx.require_on(Permission::ManageUsers, target.role()));
    check!(end_sessions(&state, user_id).await);
    audit::record(
        &state,
        Some(ctx.user_id),
        Some(user_id),
        AUDIT_ADMIN_REVOKE_SESSIONS,
        &meta,
        json!({}),
    );
    json_response(StatusCode::OK, json!({"message": "signed out everywhere"}))
}

#[derive(Deserialize)]
pub struct RoleBody {
    pub role: String,
}

pub async fn handle_admin_set_role(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<RoleBody>,
) -> Response {
    check!(ctx.require(Permission::ManageStaff));
    check!(not_self(&ctx, user_id, "change the role of"));
    check!(ctx.require_recent_auth());
    let Some(role) = Role::parse(req.role.trim()) else {
        return json_error(
            "role must be one of user, viewer, support, admin, owner",
            StatusCode::BAD_REQUEST,
        );
    };
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    match state.db.change_user_role(user_id, role).await {
        Ok(RoleChange::Changed) => {}
        Ok(RoleChange::NotFound) => return json_error("user not found", StatusCode::NOT_FOUND),
        Ok(RoleChange::LastOwner) => {
            return json_error("the server needs at least one owner", StatusCode::CONFLICT);
        }
        Err(e) => return internal(e),
    }
    audit::record(
        &state,
        Some(ctx.user_id),
        Some(user_id),
        AUDIT_ADMIN_SET_ROLE,
        &meta,
        json!({"from": target.role, "to": role.as_str()}),
    );
    json_response(
        StatusCode::OK,
        json!({"message": "role updated", "role": role}),
    )
}

pub async fn handle_admin_reset_mfa(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    check!(not_self(
        &ctx,
        user_id,
        "reset two-factor authentication of"
    ));
    let target = match load_target(&state, user_id).await {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };
    check!(ctx.require_on(Permission::ResetMfa, target.role()));
    check!(ctx.require_recent_auth());
    if let Err(e) = state.db.reset_user_mfa(user_id).await {
        return internal(e);
    }
    check!(end_sessions(&state, user_id).await);
    audit::record(
        &state,
        Some(ctx.user_id),
        Some(user_id),
        AUDIT_ADMIN_RESET_MFA,
        &meta,
        json!({}),
    );
    crate::mfa::notify(
        &state,
        &target,
        "Two-factor authentication was reset",
        "An administrator removed the two-factor authentication methods from your account and signed you out. You will set up a new method the next time you sign in.".into(),
    );
    json_response(
        StatusCode::OK,
        json!({"message": "two-factor authentication reset"}),
    )
}

// === Stats ===

pub async fn handle_admin_get_stats(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
) -> Response {
    check!(ctx.require(Permission::View));
    match state.db.admin_get_stats().await {
        Ok(mut stats) => {
            stats.active_connections = state.hub.total_connections().await;
            json_response(StatusCode::OK, stats)
        }
        Err(e) => internal(e),
    }
}

// === Audit log ===

#[derive(Deserialize)]
pub struct AuditLogQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub user_id: Option<String>,
    pub action: Option<String>,
}

pub async fn handle_admin_list_audit_logs(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    Query(query): Query<AuditLogQuery>,
) -> Response {
    check!(ctx.require(Permission::View));
    let user_id = match query.user_id.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => match uuid::Uuid::parse_str(s) {
            Ok(id) => Some(id),
            Err(_) => return json_error("invalid user_id", StatusCode::BAD_REQUEST),
        },
        None => None,
    };
    let filter = AuditFilter {
        user_id,
        action: query.action.as_deref().filter(|a| !a.is_empty()),
        limit: query.limit.unwrap_or(50),
        offset: query.offset.unwrap_or(0),
    };
    match state.db.list_audit_entries(&filter).await {
        Ok((items, total)) => {
            json_response(StatusCode::OK, json!({"items": items, "total": total}))
        }
        Err(e) => internal(e),
    }
}

pub async fn handle_admin_audit_actions(Extension(ctx): Extension<AdminContext>) -> Response {
    check!(ctx.require(Permission::View));
    json_response(StatusCode::OK, AUDIT_ACTIONS)
}

// === Plans ===

pub async fn handle_admin_list_plans(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
) -> Response {
    check!(ctx.require(Permission::View));
    match state.db.list_subscription_plans().await {
        Ok(plans) => json_response(StatusCode::OK, plans),
        Err(e) => internal(e),
    }
}

/// Accepts a price as a JSON number or string, keeping its exact decimal value.
fn de_price<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Decimal, D::Error> {
    use serde::de::Error;
    let text = match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s,
        serde_json::Value::Null => return Ok(Decimal::ZERO),
        _ => return Err(D::Error::custom("price must be a number")),
    };
    Decimal::from_str(text.trim())
        .or_else(|_| Decimal::from_scientific(text.trim()))
        .map_err(|_| D::Error::custom("price must be a number"))
}

#[derive(Deserialize)]
pub struct PlanBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, deserialize_with = "de_price")]
    pub price: Decimal,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default = "default_billing_period")]
    pub billing_period: String,
    #[serde(default = "default_max_devices")]
    pub max_devices: i32,
    #[serde(default = "default_max_history")]
    pub max_clipboard_history: i32,
    #[serde(default)]
    pub allowed_file_types: Vec<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub sort_order: i32,
}
fn default_currency() -> String {
    "USD".to_string()
}
fn default_billing_period() -> String {
    "monthly".to_string()
}
fn default_max_devices() -> i32 {
    5
}
fn default_max_history() -> i32 {
    100
}
fn default_true() -> bool {
    true
}

impl PlanBody {
    fn validate(&mut self) -> Result<(), &'static str> {
        self.name = self.name.trim().to_string();
        self.currency = self.currency.trim().to_uppercase();
        if self.name.is_empty() || self.name.chars().count() > 100 {
            return Err("name is required (100 characters at most)");
        }
        if self.description.chars().count() > 1000 {
            return Err("description is too long (1000 characters at most)");
        }
        if self.price.is_sign_negative() || self.price > Decimal::from(99_999_999) {
            return Err("price must be between 0 and 99999999");
        }
        self.price = self.price.round_dp(2);
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err("currency must be a three-letter code such as USD");
        }
        if self.billing_period.trim().is_empty() || self.billing_period.len() > 50 {
            return Err("billing_period is required");
        }
        if self.max_devices < 1 {
            return Err("max_devices must be at least 1");
        }
        if self.max_clipboard_history < 0 {
            return Err("max_clipboard_history cannot be negative");
        }
        let known = ["text", "image", "file"];
        if self
            .allowed_file_types
            .iter()
            .any(|t| !known.contains(&t.as_str()))
        {
            return Err("allowed_file_types may contain text, image and file");
        }
        Ok(())
    }

    fn params<'a>(
        &'a self,
        file_types: &'a serde_json::Value,
    ) -> crate::db::SubscriptionPlanParams<'a> {
        crate::db::SubscriptionPlanParams {
            name: &self.name,
            description: &self.description,
            price: self.price,
            currency: &self.currency,
            billing_period: self.billing_period.trim(),
            max_devices: self.max_devices,
            max_clipboard_history: self.max_clipboard_history,
            allowed_file_types: file_types,
            is_active: self.is_active,
            sort_order: self.sort_order,
        }
    }
}

pub async fn handle_admin_create_plan(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    axum::Json(mut req): axum::Json<PlanBody>,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    if let Err(msg) = req.validate() {
        return json_error(msg, StatusCode::BAD_REQUEST);
    }
    let file_types = json!(req.allowed_file_types);
    match state
        .db
        .create_subscription_plan(&req.params(&file_types))
        .await
    {
        Ok(plan) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_PLAN_CREATE,
                &meta,
                json!({"plan_id": plan.id, "name": plan.name}),
            );
            json_response(StatusCode::CREATED, plan)
        }
        Err(e) => internal(e),
    }
}

pub async fn handle_admin_update_plan(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(plan_id): Path<uuid::Uuid>,
    axum::Json(mut req): axum::Json<PlanBody>,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    if let Err(msg) = req.validate() {
        return json_error(msg, StatusCode::BAD_REQUEST);
    }
    let file_types = json!(req.allowed_file_types);
    match state
        .db
        .update_subscription_plan(plan_id, &req.params(&file_types))
        .await
    {
        Ok(plan) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_PLAN_UPDATE,
                &meta,
                json!({"plan_id": plan.id, "name": plan.name}),
            );
            json_response(StatusCode::OK, plan)
        }
        Err(sqlx::Error::RowNotFound) => json_error("plan not found", StatusCode::NOT_FOUND),
        Err(e) => internal(e),
    }
}

pub async fn handle_admin_delete_plan(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(plan_id): Path<uuid::Uuid>,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    match state.db.delete_subscription_plan(plan_id).await {
        Ok(_) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_PLAN_DELETE,
                &meta,
                json!({"plan_id": plan_id}),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) if e == "plan not found" => json_error(&e, StatusCode::NOT_FOUND),
        Err(e) => json_error(&e, StatusCode::CONFLICT),
    }
}

// === Download links ===

pub async fn handle_admin_list_downloads(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
) -> Response {
    check!(ctx.require(Permission::View));
    match state.db.list_download_links().await {
        Ok(links) => json_response(StatusCode::OK, links),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub struct DownloadBody {
    pub name: String,
    pub url: String,
    #[serde(default = "default_unknown")]
    pub platform: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub sort_order: i32,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub release_id: Option<String>,
}
fn default_unknown() -> String {
    "unknown".to_string()
}

fn url_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "this URL is not allowed: use https (or a file uploaded here) under one of the prefixes in DOWNLOAD_URL_PREFIXES",
    )
}

impl DownloadBody {
    fn validate(&self, state: &AppState) -> Result<Option<uuid::Uuid>, ApiError> {
        if self.name.trim().is_empty() || self.url.trim().is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "name and url are required",
            ));
        }
        if !state.config.download_url_allowed(self.url.trim()) {
            return Err(url_not_allowed());
        }
        match self
            .release_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            None => Ok(None),
            Some(s) => uuid::Uuid::parse_str(s)
                .map(Some)
                .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid release_id")),
        }
    }

    fn params(&self, release_id: Option<uuid::Uuid>) -> crate::db::DownloadLinkParams<'_> {
        crate::db::DownloadLinkParams {
            name: self.name.trim(),
            url: self.url.trim(),
            platform: &self.platform,
            arch: &self.arch,
            format: &self.format,
            sort_order: self.sort_order,
            is_active: self.is_active,
            release_id,
        }
    }
}

fn actor_details(ctx: &AdminContext, mut details: serde_json::Value) -> serde_json::Value {
    if let Some(token) = ctx.api_token_id {
        details["api_token_id"] = json!(token);
    }
    details
}

pub async fn handle_admin_create_download(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    axum::Json(req): axum::Json<DownloadBody>,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    let release_id = match req.validate(&state) {
        Ok(r) => r,
        Err(r) => return r.into_response(),
    };
    match state.db.create_download_link(&req.params(release_id)).await {
        Ok(link) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_DOWNLOAD_CREATE,
                &meta,
                actor_details(
                    &ctx,
                    json!({"download_id": link.id, "name": link.name, "url": link.url}),
                ),
            );
            json_response(StatusCode::CREATED, link)
        }
        Err(e) => internal(e),
    }
}

pub async fn handle_admin_update_download(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(link_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<DownloadBody>,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    let release_id = match req.validate(&state) {
        Ok(r) => r,
        Err(r) => return r.into_response(),
    };
    match state
        .db
        .update_download_link(link_id, &req.params(release_id))
        .await
    {
        Ok(link) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_DOWNLOAD_UPDATE,
                &meta,
                actor_details(
                    &ctx,
                    json!({"download_id": link.id, "name": link.name, "url": link.url}),
                ),
            );
            json_response(StatusCode::OK, link)
        }
        Err(sqlx::Error::RowNotFound) => {
            json_error("download link not found", StatusCode::NOT_FOUND)
        }
        Err(e) => internal(e),
    }
}

pub async fn handle_admin_delete_download(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(link_id): Path<uuid::Uuid>,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    match state.db.delete_download_link(link_id).await {
        Ok(()) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_DOWNLOAD_DELETE,
                &meta,
                actor_details(&ctx, json!({"download_id": link_id})),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(sqlx::Error::RowNotFound) => {
            json_error("download link not found", StatusCode::NOT_FOUND)
        }
        Err(e) => internal(e),
    }
}

// === Installer uploads ===

/// A file received into a temporary path in the downloads directory.
struct StagedUpload {
    file_name: String,
    temp_path: std::path::PathBuf,
    sha256: String,
    size: u64,
}

fn is_plain_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && !name.starts_with('.')
        && !name.contains(['/', '\\', '\0'])
        && !name.contains("..")
}

/// Checks an installer against the update key, as the apps' updater does: a valid
/// minisign signature whose trusted comment names this file.
pub fn verify_installer_signature(
    public_key: &str,
    path: &std::path::Path,
    signature: &str,
    file_name: &str,
) -> Result<(), String> {
    use base64::Engine;
    use std::io::Read;
    let decode = |text: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
    };
    let public_key = decode(public_key)
        .and_then(|t| minisign_verify::PublicKey::decode(&t).ok())
        .ok_or("UPDATER_PUBLIC_KEY is not a valid tauri signer public key")?;
    let signature = decode(signature)
        .and_then(|t| minisign_verify::Signature::decode(&t).ok())
        .ok_or_else(|| format!("{file_name}: the signature is malformed"))?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|_| format!("{file_name}: the signature is not from the update key"))?;
    let mut file = std::fs::File::open(path).map_err(|e| format!("read upload: {e}"))?;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("read upload: {e}"))?;
        if n == 0 {
            break;
        }
        verifier.update(&buffer[..n]);
    }
    verifier
        .finalize()
        .map_err(|_| format!("{file_name}: the signature does not match this file"))?;
    // "timestamp:<t>\tfile:<name>\tversion:<v>" (covered by the signature)
    let signed_name = signature
        .trusted_comment()
        .split('\t')
        .find_map(|field| field.strip_prefix("file:"));
    match signed_name {
        Some(name) if name != file_name => Err(format!(
            "{file_name}: the signature is for {name}, not this file"
        )),
        _ => Ok(()),
    }
}

fn read_failed(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        format!("failed to read upload: {e}"),
    )
}

async fn read_signature(
    field: &mut axum::extract::multipart::Field<'_>,
) -> Result<String, ApiError> {
    let mut text = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(read_failed)? {
        text.extend_from_slice(&chunk);
        if text.len() > MAX_SIGNATURE_BYTES {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "signature file is too large",
            ));
        }
    }
    String::from_utf8(text)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "signature is not text"))
}

async fn stage_file(
    dir: &std::path::Path,
    file_name: String,
    field: &mut axum::extract::multipart::Field<'_>,
) -> Result<StagedUpload, ApiError> {
    let temp_path = dir.join(format!(".upload-{}.part", uuid::Uuid::new_v4()));
    let mut file = tokio::fs::File::create(&temp_path)
        .await
        .map_err(|e| ApiError::internal(format!("create {}: {e}", temp_path.display())))?;
    let mut hasher = sha2::Sha256::new();
    let mut size: u64 = 0;
    let result: Result<(), ApiError> = async {
        while let Some(chunk) = field.chunk().await.map_err(read_failed)? {
            size += chunk.len() as u64;
            if size > MAX_UPLOAD_BYTES {
                return Err(ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "file too large (max 500 MB)",
                ));
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await.map_err(ApiError::internal)?;
        }
        file.flush().await.map_err(ApiError::internal)?;
        file.sync_all().await.map_err(ApiError::internal)?;
        Ok(())
    }
    .await;
    if let Err(response) = result {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(response);
    }
    Ok(StagedUpload {
        file_name,
        temp_path,
        sha256: crate::mfa::codes::hex(&hasher.finalize()),
        size,
    })
}

/// Uploads installers to the downloads directory, streaming them to disk. When
/// `UPDATER_PUBLIC_KEY` is set, each needs its `<file>.sig` (as a `signature` field or a
/// second file) and only files signed with the update key are accepted. Existing files
/// are only replaced with `replace=true`.
pub async fn handle_admin_upload_binary(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    mut multipart: Multipart,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    check!(ctx.require_recent_auth());
    let downloads_dir = std::path::PathBuf::from(&state.config.downloads_dir);
    if state.config.downloads_dir.is_empty() {
        return json_error(
            "DOWNLOADS_DIR not configured",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    if let Err(e) = tokio::fs::create_dir_all(&downloads_dir).await {
        return internal(format!("cannot create downloads dir: {e}"));
    }

    let mut staged: Vec<StagedUpload> = Vec::new();
    let mut signatures: HashMap<String, String> = HashMap::new();
    let mut replace = false;
    let mut failure: Option<Response> = None;

    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                failure = Some(json_error(
                    &format!("failed to read upload: {e}"),
                    StatusCode::BAD_REQUEST,
                ));
                break;
            }
        };
        let field_name = field.name().unwrap_or_default().to_string();
        if field_name == "replace" {
            replace = matches!(field.text().await.as_deref(), Ok("true") | Ok("1"));
            continue;
        }
        let Some(file_name) = field.file_name().map(str::to_string) else {
            continue;
        };
        if !is_plain_file_name(&file_name) {
            failure = Some(json_error("invalid filename", StatusCode::BAD_REQUEST));
            break;
        }
        // Signatures arrive as `signature` fields or as `<installer>.sig` files
        if field_name == "signature" || file_name.ends_with(".sig") {
            let installer = file_name.trim_end_matches(".sig").to_string();
            match read_signature(&mut field).await {
                Ok(text) => {
                    signatures.insert(installer, text);
                }
                Err(r) => {
                    failure = Some(r.into_response());
                    break;
                }
            }
            continue;
        }
        match stage_file(&downloads_dir, file_name, &mut field).await {
            Ok(upload) => staged.push(upload),
            Err(r) => {
                failure = Some(r.into_response());
                break;
            }
        }
    }

    let cleanup = |staged: &[StagedUpload]| {
        for upload in staged {
            let _ = std::fs::remove_file(&upload.temp_path);
        }
    };
    if let Some(response) = failure {
        cleanup(&staged);
        return response;
    }
    if staged.is_empty() {
        return json_error("no files uploaded", StatusCode::BAD_REQUEST);
    }

    let public_key = state.config.updater_public_key.clone();
    if !public_key.is_empty() {
        for upload in &staged {
            let Some(signature) = signatures.get(&upload.file_name).cloned() else {
                cleanup(&staged);
                return json_error(
                    &format!(
                        "{}: a signature is required (upload {}.sig made with the update key)",
                        upload.file_name, upload.file_name
                    ),
                    StatusCode::BAD_REQUEST,
                );
            };
            let (key, path, name) = (
                public_key.clone(),
                upload.temp_path.clone(),
                upload.file_name.clone(),
            );
            let checked = tokio::task::spawn_blocking(move || {
                verify_installer_signature(&key, &path, &signature, &name)
            })
            .await;
            match checked {
                Ok(Ok(())) => {}
                Ok(Err(msg)) => {
                    cleanup(&staged);
                    return json_error(&msg, StatusCode::BAD_REQUEST);
                }
                Err(e) => {
                    cleanup(&staged);
                    return internal(e);
                }
            }
        }
    }

    if !replace {
        for upload in &staged {
            if downloads_dir.join(&upload.file_name).exists() {
                cleanup(&staged);
                return json_error(
                    &format!(
                        "{} already exists; upload again with replace to overwrite it",
                        upload.file_name
                    ),
                    StatusCode::CONFLICT,
                );
            }
        }
    }

    let mut uploaded = Vec::new();
    for (i, upload) in staged.iter().enumerate() {
        let dest = downloads_dir.join(&upload.file_name);
        if let Err(e) = tokio::fs::rename(&upload.temp_path, &dest).await {
            cleanup(&staged[i..]);
            return internal(format!("store {}: {e}", upload.file_name));
        }
        let signature = signatures.get(&upload.file_name);
        let sig_path = downloads_dir.join(format!("{}.sig", upload.file_name));
        match signature {
            Some(sig) => {
                let _ = tokio::fs::write(&sig_path, sig).await;
            }
            // A stale signature must not sit next to a replaced installer
            None => {
                let _ = tokio::fs::remove_file(&sig_path).await;
            }
        }

        let url = format!("/api/downloads/{}", upload.file_name);
        let (platform, arch, format) = crate::db::detect_platform_arch_format(&upload.file_name);
        let link = state
            .db
            .upsert_uploaded_download(
                &crate::db::DownloadLinkParams {
                    name: &upload.file_name,
                    url: &url,
                    platform: &platform,
                    arch: &arch,
                    format: &format,
                    sort_order: 0,
                    is_active: true,
                    release_id: None,
                },
                &upload.sha256,
                upload.size as i64,
            )
            .await;
        if let Err(e) = link {
            tracing::warn!(
                "Uploaded {} but could not record its link: {e}",
                upload.file_name
            );
        }
        uploaded.push(json!({
            "filename": upload.file_name,
            "size": upload.size,
            "sha256": upload.sha256,
            "url": url,
            "signed": signature.is_some(),
        }));
    }

    audit::record(
        &state,
        Some(ctx.user_id),
        None,
        AUDIT_ADMIN_UPLOAD,
        &meta,
        json!({"files": uploaded, "replace": replace}),
    );
    json_response(StatusCode::OK, json!({ "uploaded": uploaded }))
}

// === App releases ===

pub async fn handle_admin_list_releases(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
) -> Response {
    check!(ctx.require(Permission::View));
    match state.db.list_app_releases().await {
        Ok(releases) => json_response(StatusCode::OK, releases),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub struct ReleaseBody {
    pub version: String,
    #[serde(default = "default_unknown")]
    pub platform: String,
    #[serde(default)]
    pub arch: String,
    pub download_url: String,
    #[serde(default)]
    pub release_notes: String,
    #[serde(default)]
    pub is_current: bool,
}

impl ReleaseBody {
    fn validate(&self, state: &AppState) -> Result<(), ApiError> {
        if self.version.trim().is_empty() || self.download_url.trim().is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "version and download_url are required",
            ));
        }
        if !state.config.download_url_allowed(self.download_url.trim()) {
            return Err(url_not_allowed());
        }
        Ok(())
    }

    fn params(&self) -> crate::db::AppReleaseParams<'_> {
        crate::db::AppReleaseParams {
            version: self.version.trim(),
            platform: &self.platform,
            arch: &self.arch,
            download_url: self.download_url.trim(),
            release_notes: &self.release_notes,
            is_current: self.is_current,
        }
    }
}

pub async fn handle_admin_create_release(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    axum::Json(req): axum::Json<ReleaseBody>,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    check!(req.validate(&state));
    match state.db.create_app_release(&req.params()).await {
        Ok(rel) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_RELEASE_CREATE,
                &meta,
                actor_details(
                    &ctx,
                    json!({"release_id": rel.id, "version": rel.version, "platform": rel.platform, "arch": rel.arch, "is_current": rel.is_current}),
                ),
            );
            json_response(StatusCode::CREATED, rel)
        }
        Err(e) => internal(e),
    }
}

pub async fn handle_admin_update_release(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(release_id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<ReleaseBody>,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    check!(req.validate(&state));
    match state.db.update_app_release(release_id, &req.params()).await {
        Ok(rel) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_RELEASE_UPDATE,
                &meta,
                actor_details(
                    &ctx,
                    json!({"release_id": rel.id, "version": rel.version, "platform": rel.platform, "arch": rel.arch, "is_current": rel.is_current}),
                ),
            );
            json_response(StatusCode::OK, rel)
        }
        Err(sqlx::Error::RowNotFound) => json_error("release not found", StatusCode::NOT_FOUND),
        Err(e) => internal(e),
    }
}

pub async fn handle_admin_delete_release(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(release_id): Path<uuid::Uuid>,
) -> Response {
    check!(ctx.require(Permission::ManageContent));
    match state.db.delete_app_release(release_id).await {
        Ok(()) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_RELEASE_DELETE,
                &meta,
                actor_details(&ctx, json!({"release_id": release_id})),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(sqlx::Error::RowNotFound) => json_error("release not found", StatusCode::NOT_FOUND),
        Err(e) => internal(e),
    }
}

// === Runtime settings ===

pub async fn handle_admin_get_settings(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
) -> Response {
    check!(ctx.require(Permission::View));
    let runtime = state.settings.get(&state.db).await;
    let cfg = &state.config;
    json_response(
        StatusCode::OK,
        json!({
            "registration_open": {
                "value": runtime.registration_open(cfg),
                "override": runtime.registration_open,
                "default": cfg.registration_open,
            },
            "banner": runtime.banner,
            "mfa_policy": match cfg.mfa_policy {
                crate::config::MfaPolicy::All => "all",
                crate::config::MfaPolicy::Staff => "staff",
            },
            "passkeys": {
                "enabled": cfg.passkeys_enabled(),
                "rp_id": cfg.webauthn_rp_id,
                "origins": cfg.webauthn_origins,
            },
            "uploads": {
                "signature_required": !cfg.updater_public_key.is_empty(),
                "downloads_dir_configured": !cfg.downloads_dir.is_empty(),
            },
            "download_url_prefixes": cfg.download_url_prefixes,
            "smtp_configured": state.email.is_configured(),
            "oidc_configured": !cfg.oidc_issuer_url.is_empty() && !cfg.oidc_client_id.is_empty(),
        }),
    )
}

/// Distinguishes a missing field (unchanged) from `null` (reset to the default).
fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
pub struct SettingsBody {
    #[serde(default, deserialize_with = "double_option")]
    pub registration_open: Option<Option<bool>>,
    #[serde(default, deserialize_with = "double_option")]
    pub banner: Option<Option<Banner>>,
}

pub async fn handle_admin_update_settings(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    axum::Json(req): axum::Json<SettingsBody>,
) -> Response {
    check!(ctx.require(Permission::ManageSettings));
    if let Some(Some(banner)) = &req.banner
        && let Err(msg) = banner.validate()
    {
        return json_error(msg, StatusCode::BAD_REQUEST);
    }

    let mut changed = serde_json::Map::new();
    if let Some(value) = req.registration_open {
        let json_value = value.map(serde_json::Value::Bool);
        if let Err(e) = state
            .db
            .put_setting(
                settings::KEY_REGISTRATION_OPEN,
                json_value.as_ref(),
                ctx.user_id,
            )
            .await
        {
            return internal(e);
        }
        changed.insert(settings::KEY_REGISTRATION_OPEN.into(), json!(value));
    }
    if let Some(value) = req.banner {
        let json_value = value
            .as_ref()
            .map(|b| json!({"message": b.message.trim(), "tone": b.tone}));
        if let Err(e) = state
            .db
            .put_setting(settings::KEY_BANNER, json_value.as_ref(), ctx.user_id)
            .await
        {
            return internal(e);
        }
        changed.insert(settings::KEY_BANNER.into(), json!(json_value));
    }
    state.settings.invalidate().await;

    if !changed.is_empty() {
        audit::record(
            &state,
            Some(ctx.user_id),
            None,
            AUDIT_ADMIN_SETTINGS_UPDATE,
            &meta,
            serde_json::Value::Object(changed),
        );
    }
    handle_admin_get_settings(State(state), Extension(ctx)).await
}

// === Integration checks ===

#[derive(Deserialize)]
pub struct TestSmtpBody {
    pub to_email: String,
}

pub async fn handle_admin_test_smtp(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    axum::Json(req): axum::Json<TestSmtpBody>,
) -> Response {
    check!(ctx.require(Permission::ManageSettings));
    let to = req.to_email.trim().to_string();
    if to.is_empty() {
        return json_error("to_email is required", StatusCode::BAD_REQUEST);
    }
    let mailer = state.clone();
    let recipient = to.clone();
    let result =
        tokio::task::spawn_blocking(move || mailer.email.test_connection(&recipient)).await;
    let outcome = match result {
        Ok(Ok(())) => json!({"message": "Test email sent successfully."}),
        Ok(Err(e)) => json!({"error": e}),
        Err(e) => return internal(e),
    };
    audit::record(
        &state,
        Some(ctx.user_id),
        None,
        AUDIT_ADMIN_TEST_SMTP,
        &meta,
        json!({"to": to, "ok": outcome.get("error").is_none()}),
    );
    json_response(StatusCode::OK, outcome)
}

pub async fn handle_admin_test_oidc(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
) -> Response {
    check!(ctx.require(Permission::ManageSettings));
    let outcome = oidc_discovery_check(&state.config.oidc_issuer_url).await;
    audit::record(
        &state,
        Some(ctx.user_id),
        None,
        AUDIT_ADMIN_TEST_OIDC,
        &meta,
        json!({"ok": outcome.get("error").is_none()}),
    );
    json_response(StatusCode::OK, outcome)
}

async fn oidc_discovery_check(issuer_url: &str) -> serde_json::Value {
    if issuer_url.is_empty() {
        return json!({"error": "OIDC_ISSUER_URL is not configured in env."});
    }
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/'),
    );
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({"error": format!("HTTP client error: {e}")}),
    };
    match client.get(&discovery_url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(doc) => json!({
                "message": "OIDC discovery successful.",
                "issuer": doc.get("issuer").and_then(|v| v.as_str()).unwrap_or(""),
                "authorization_endpoint": doc.get("authorization_endpoint").and_then(|v| v.as_str()).unwrap_or(""),
            }),
            Err(e) => json!({"error": format!("Failed to parse discovery document: {e}")}),
        },
        Ok(resp) => json!({"error": format!("Discovery endpoint returned HTTP {}", resp.status())}),
        Err(e) => json!({"error": format!("Failed to connect to issuer: {e}")}),
    }
}

// === API tokens ===

pub async fn handle_admin_list_api_tokens(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
) -> Response {
    check!(ctx.require(Permission::ManageApiTokens));
    match state.db.list_api_tokens().await {
        Ok(tokens) => json_response(StatusCode::OK, tokens),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub struct CreateApiTokenBody {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Days until the token expires (1 to 365); `null` for no expiry.
    #[serde(default = "default_token_days")]
    pub expires_in_days: Option<i64>,
}
fn default_token_days() -> Option<i64> {
    Some(90)
}

pub const API_TOKEN_SCOPES: [&str; 1] = [SCOPE_RELEASES];

pub async fn handle_admin_create_api_token(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    axum::Json(req): axum::Json<CreateApiTokenBody>,
) -> Response {
    check!(ctx.require(Permission::ManageApiTokens));
    check!(ctx.require_recent_auth());
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return json_error(
            "name is required (100 characters at most)",
            StatusCode::BAD_REQUEST,
        );
    }
    let scopes: Vec<&str> = API_TOKEN_SCOPES
        .into_iter()
        .filter(|s| req.scopes.iter().any(|r| r == s))
        .collect();
    if scopes.is_empty() || scopes.len() != req.scopes.len() {
        return json_error(
            &format!(
                "scopes must be chosen from: {}",
                API_TOKEN_SCOPES.join(", ")
            ),
            StatusCode::BAD_REQUEST,
        );
    }
    let expires_at = match req.expires_in_days {
        None => None,
        Some(days) if (1..=365).contains(&days) => {
            Some(chrono::Utc::now() + chrono::Duration::days(days))
        }
        Some(_) => {
            return json_error(
                "expires_in_days must be between 1 and 365",
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let mut secret = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut secret);
    let token = format!(
        "{API_TOKEN_PREFIX}{}",
        crate::mfa::webauthn::b64url(&secret)
    );
    let prefix: String = token.chars().take(12).collect();
    match state
        .db
        .create_api_token(
            ctx.user_id,
            name,
            &api_token_hash(&token),
            &prefix,
            &scopes,
            expires_at,
        )
        .await
    {
        Ok(record) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_API_TOKEN_CREATE,
                &meta,
                json!({"token_id": record.id, "name": record.name, "scopes": scopes}),
            );
            json_response(
                StatusCode::CREATED,
                json!({"token": token, "api_token": record}),
            )
        }
        Err(e) => internal(e),
    }
}

pub async fn handle_admin_revoke_api_token(
    State(state): State<Arc<AppState>>,
    Extension(ctx): Extension<AdminContext>,
    meta: RequestMeta,
    Path(token_id): Path<uuid::Uuid>,
) -> Response {
    check!(ctx.require(Permission::ManageApiTokens));
    match state.db.revoke_api_token(token_id).await {
        Ok(true) => {
            audit::record(
                &state,
                Some(ctx.user_id),
                None,
                AUDIT_ADMIN_API_TOKEN_REVOKE,
                &meta,
                json!({"token_id": token_id}),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => json_error("API token not found", StatusCode::NOT_FOUND),
        Err(e) => internal(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prices_keep_their_exact_decimal_value() {
        #[derive(Deserialize)]
        struct P {
            #[serde(deserialize_with = "de_price")]
            price: Decimal,
        }
        let parse = |v: serde_json::Value| serde_json::from_value::<P>(json!({"price": v}));
        assert_eq!(parse(json!(5.99)).unwrap().price.to_string(), "5.99");
        assert_eq!(parse(json!("12.30")).unwrap().price.to_string(), "12.30");
        assert_eq!(parse(json!(0)).unwrap().price, Decimal::ZERO);
        assert_eq!(parse(json!(null)).unwrap().price, Decimal::ZERO);
        assert!(parse(json!("free")).is_err());
        assert!(parse(json!([1])).is_err());
    }

    fn plan(price: &str, currency: &str) -> PlanBody {
        serde_json::from_value(json!({"name": " Pro ", "price": price, "currency": currency}))
            .unwrap()
    }

    #[test]
    fn plan_validation() {
        let mut ok = plan("5.999", "eur");
        ok.validate().unwrap();
        assert_eq!(ok.name, "Pro");
        assert_eq!(ok.currency, "EUR");
        assert_eq!(ok.price.to_string(), "6.00");

        assert!(plan("-1", "USD").validate().is_err());
        assert!(plan("1", "US").validate().is_err());
        assert!(plan("1", "U$D").validate().is_err());
        let mut bad = plan("1", "USD");
        bad.max_devices = 0;
        assert!(bad.validate().is_err());
        let mut bad = plan("1", "USD");
        bad.allowed_file_types = vec!["video".into()];
        assert!(bad.validate().is_err());
    }

    #[test]
    fn settings_body_tells_missing_from_null() {
        let body: SettingsBody = serde_json::from_value(json!({})).unwrap();
        assert!(body.registration_open.is_none() && body.banner.is_none());
        let body: SettingsBody =
            serde_json::from_value(json!({"registration_open": null, "banner": null})).unwrap();
        assert_eq!(body.registration_open, Some(None));
        assert_eq!(body.banner, Some(None));
        let body: SettingsBody = serde_json::from_value(
            json!({"registration_open": false, "banner": {"message": "Hi", "tone": "info"}}),
        )
        .unwrap();
        assert_eq!(body.registration_open, Some(Some(false)));
        assert_eq!(body.banner.unwrap().unwrap().message, "Hi");
    }

    #[test]
    fn plain_file_names_only() {
        assert!(is_plain_file_name("cpmesh-1.0.0-windows-amd64-setup.exe"));
        for bad in ["", ".hidden", "a/b", "a\\b", "..", "a..b", &"x".repeat(201)] {
            assert!(!is_plain_file_name(bad), "{bad}");
        }
    }

    // Fixtures from desktop-tauri/src-tauri/src/updater.rs (`tauri signer`, test keys only)
    const PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDE4OUE3NzlDRDkzQzdCN0YKUldSL2V6elpuSGVhR09QU0JUQ1NPb2ViQjczQ28xRFNMcU5yaG9BdVQyT3oya1JPOW8vYkZxR3IK";
    const OTHER_PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDE5OEYzNkUzNDBEREI5ODcKUldTSHVkMUE0emFQR2VnWWpJWkl4TTFEUmpJanBtODF4Q0tRNVZEVUV6ZXdURjNvbTlWVVdMNGsK";
    const INSTALLER: &[u8] = b"cpmesh test installer\n";
    const SIGNED_NAME: &str = "cpmesh-9.9.9-windows-amd64-setup.exe";
    const SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSL2V6elpuSGVhR09sYXRLUFAvajZnNGpYYzA1elVrdnkydENvelVzTjZHb092aW50bGVrUk1LL0NibXJMYU9xbkRmWjNNLzRYNEV2L2VnNjRESlJFV2tNaUNvN243bEE0PQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkyMDQzMjYxCWZpbGU6Y3BtZXNoLTkuOS45LXdpbmRvd3MtYW1kNjQtc2V0dXAuZXhlCXZlcnNpb246OS45LjkKK2hYYUcySkV4aTNkRU53dVZoMndxZFRoNThLME9uMFZHYnNrU0IrQnBoRll0T0JhTVozb0M4clNJTi90K1daSzhrWUdHM25WR01XSDhZTVJ5eHVUQ3c9PQo=";

    #[test]
    fn installer_signatures_are_checked_against_the_update_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("installer");
        std::fs::write(&path, INSTALLER).unwrap();

        verify_installer_signature(PUBLIC_KEY, &path, SIGNATURE, SIGNED_NAME).unwrap();

        let err = verify_installer_signature(OTHER_PUBLIC_KEY, &path, SIGNATURE, SIGNED_NAME)
            .unwrap_err();
        assert!(err.contains("not from the update key"), "{err}");

        let err = verify_installer_signature(
            PUBLIC_KEY,
            &path,
            SIGNATURE,
            "cpmesh-9.9.9-linux-amd64.deb",
        )
        .unwrap_err();
        assert!(err.contains("the signature is for"), "{err}");

        std::fs::write(&path, b"tampered installer\n").unwrap();
        let err =
            verify_installer_signature(PUBLIC_KEY, &path, SIGNATURE, SIGNED_NAME).unwrap_err();
        assert!(err.contains("does not match"), "{err}");

        let err =
            verify_installer_signature(PUBLIC_KEY, &path, "garbage", SIGNED_NAME).unwrap_err();
        assert!(err.contains("malformed"), "{err}");
        let err = verify_installer_signature("garbage", &path, SIGNATURE, SIGNED_NAME).unwrap_err();
        assert!(err.contains("UPDATER_PUBLIC_KEY"), "{err}");
    }
}
