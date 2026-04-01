use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub email_idx: Option<String>,
    pub full_name: String,
    pub country: Option<String>,
    pub mobile: Option<String>,
    pub email_verified: bool,
    pub auth_provider: String,
    pub auth_provider_id: Option<String>,
    pub auth_provider_id_idx: Option<String>,
    pub avatar_url: Option<String>,
    pub is_admin: bool,
    pub subscription_plan_id: Option<uuid::Uuid>,
    pub username_idx: Option<String>,
    pub created_at: DateTime<Utc>,
    pub tokens_revoked_before: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Device {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub name: String,
    pub public_key: Vec<u8>,
    pub public_key_sig: Option<Vec<u8>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_device_status")]
    pub status: String,
    pub approved_at: Option<DateTime<Utc>>,
    pub approved_by_device_id: Option<uuid::Uuid>,
    pub fingerprint: Option<String>,
}

fn default_device_status() -> String {
    "approved".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SubscriptionPlan {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: String,
    pub price: rust_decimal::Decimal,
    pub currency: String,
    pub billing_period: String,
    pub max_devices: i32,
    pub max_clipboard_history: i32,
    pub allowed_file_types: serde_json::Value,
    pub is_active: bool,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DownloadLink {
    pub id: uuid::Uuid,
    pub name: String,
    pub url: String,
    pub platform: String,
    pub arch: String,
    pub format: String,
    pub sort_order: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub release_id: Option<uuid::Uuid>,
}

#[derive(Debug, Serialize)]
pub struct AdminUserRow {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub full_name: String,
    pub email_verified: bool,
    pub auth_provider: String,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    pub device_count: i32,
    pub subscription_plan_id: Option<uuid::Uuid>,
    pub subscription_plan_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminStats {
    pub total_users: i64,
    pub total_devices: i64,
    pub total_entries: i64,
    pub active_connections: i64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UserSubscriptionInfo {
    pub plan_id: Option<uuid::Uuid>,
    pub plan_name: Option<String>,
    pub plan_description: Option<String>,
    pub price: Option<rust_decimal::Decimal>,
    pub currency: Option<String>,
    pub billing_period: Option<String>,
    pub max_devices: Option<i32>,
    pub max_clipboard_history: Option<i32>,
    pub allowed_file_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AppRelease {
    pub id: uuid::Uuid,
    pub version: String,
    pub platform: String,
    pub arch: String,
    pub download_url: String,
    pub release_notes: String,
    pub is_current: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct GroupKeyRow {
    pub encrypted_key: Vec<u8>,
    pub from_device_id: uuid::Uuid,
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceApprovalSession {
    pub id: uuid::Uuid,
    pub pending_device_id: uuid::Uuid,
    pub approver_device_id: uuid::Uuid,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct GroupKeyVersion {
    pub user_id: uuid::Uuid,
    pub version: i32,
    pub created_by_device_id: Option<uuid::Uuid>,
    pub created_at: DateTime<Utc>,
    pub rotation_due_at: Option<DateTime<Utc>>,
    pub is_current: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceGroupKey {
    pub device_id: uuid::Uuid,
    pub version: i32,
    pub encrypted_key: Vec<u8>,
    pub from_device_id: uuid::Uuid,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: uuid::Uuid,
    pub user_id: Option<uuid::Uuid>,
    pub action: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

// Audit action constants
pub const AUDIT_LOGIN_OK: &str = "login_success";
pub const AUDIT_LOGIN_FAIL: &str = "login_failure";
pub const AUDIT_REGISTER: &str = "register";
pub const AUDIT_PASSWORD_CHANGE: &str = "password_change";
pub const AUDIT_DEVICE_REGISTER: &str = "device_register";
pub const AUDIT_DEVICE_DELETE: &str = "device_delete";
pub const AUDIT_ADMIN_DELETE_USER: &str = "admin_delete_user";
pub const AUDIT_ADMIN_ASSIGN_SUB: &str = "admin_assign_subscription";
pub const AUDIT_ADMIN_REMOVE_SUB: &str = "admin_remove_subscription";
pub const AUDIT_TOKEN_REVOKE_ALL: &str = "token_revoke_all";
pub const AUDIT_DEVICE_APPROVE: &str = "device_approve";
pub const AUDIT_DEVICE_REJECT: &str = "device_reject";
pub const AUDIT_GROUP_KEY_ROTATE: &str = "group_key_rotate";
