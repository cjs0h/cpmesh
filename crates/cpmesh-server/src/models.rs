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
    /// "user" or a staff role (see [`crate::rbac::Role`]).
    pub role: String,
    pub suspended_at: Option<DateTime<Utc>>,
    pub suspended_reason: Option<String>,
}

impl User {
    pub fn role(&self) -> crate::rbac::Role {
        crate::rbac::Role::from_db(&self.role)
    }

    pub fn is_suspended(&self) -> bool {
        self.suspended_at.is_some()
    }
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
    /// Protocol v3: static ECDH key certified by `public_key` (the identity key).
    #[serde(default)]
    #[sqlx(default)]
    pub encryption_key: Option<Vec<u8>>,
    #[serde(default)]
    #[sqlx(default)]
    pub encryption_key_sig: Option<Vec<u8>>,
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
    /// SHA-256 of a file uploaded to this server, for users to check their download.
    pub sha256: Option<String>,
    pub size_bytes: Option<i64>,
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
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub device_count: i32,
    pub subscription_plan_id: Option<uuid::Uuid>,
    pub subscription_plan_name: Option<String>,
    pub suspended_at: Option<DateTime<Utc>>,
    pub mfa_enabled: bool,
    pub last_seen: Option<DateTime<Utc>>,
}

/// One page of a list.
#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AdminStats {
    pub total_users: i64,
    pub total_devices: i64,
    pub total_entries: i64,
    pub active_connections: i64,
    pub pending_devices: i64,
    pub suspended_users: i64,
    pub staff_users: i64,
    pub mfa_users: i64,
    pub active_users_1d: i64,
    pub active_users_7d: i64,
    pub active_users_30d: i64,
    /// On-disk size of stored (encrypted) clipboard data.
    pub storage_bytes: i64,
    pub signups: Vec<DailyCount>,
    pub active_users: Vec<DailyCount>,
    pub entries: Vec<DailyCount>,
    pub plans: Vec<PlanUsage>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DailyCount {
    /// `YYYY-MM-DD`
    pub day: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PlanUsage {
    pub plan_id: Option<uuid::Uuid>,
    pub name: String,
    pub users: i64,
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
    #[sqlx(default)]
    pub approver_commit: Option<Vec<u8>>,
    #[sqlx(default)]
    pub pending_nonce: Option<Vec<u8>>,
    #[sqlx(default)]
    pub approver_nonce: Option<Vec<u8>>,
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

#[derive(Debug, Clone, FromRow)]
pub struct DeviceGroupKeyWithSender {
    pub version: i32,
    pub encrypted_key: Vec<u8>,
    pub from_device_id: uuid::Uuid,
    pub from_public_key: Vec<u8>,
    pub from_public_key_sig: Option<Vec<u8>>,
    pub membership: Option<sqlx::types::Json<cpmesh_proto::models::KeyMembership>>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct ClipboardMetadata {
    pub id: uuid::Uuid,
    pub device_id: uuid::Uuid,
    pub device_name: String,
    pub content_type: String,
    pub encrypted_size: i32,
    pub created_at: DateTime<Utc>,
    pub key_version: i32,
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

/// An audit log entry with the names of the people involved, for the admin console.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLogRow {
    pub id: uuid::Uuid,
    pub user_id: Option<uuid::Uuid>,
    pub username: Option<String>,
    pub target_user_id: Option<uuid::Uuid>,
    pub target_username: Option<String>,
    pub action: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// A registered passkey.
#[derive(Debug, Clone, FromRow)]
pub struct WebauthnCredential {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: i32,
    pub sign_count: i64,
    pub transports: serde_json::Value,
    pub name: String,
    pub backup_eligible: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl WebauthnCredential {
    pub fn transport_list(&self) -> Vec<String> {
        serde_json::from_value(self.transports.clone()).unwrap_or_default()
    }
}

/// Second-factor state of an account.
#[derive(Debug, Clone, Default, FromRow)]
pub struct UserMfa {
    pub user_id: uuid::Uuid,
    /// Encrypted TOTP secret once enabled.
    pub totp_secret: Option<String>,
    /// Encrypted TOTP secret awaiting its first code.
    pub totp_pending_secret: Option<String>,
    pub totp_enabled_at: Option<DateTime<Utc>>,
    pub totp_last_step: i64,
    pub failed_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
}

/// An API token as listed in the admin console (the secret is never stored).
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ApiToken {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub username: Option<String>,
    pub name: String,
    pub token_prefix: String,
    pub scopes: serde_json::Value,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// An agent's authorization (OAuth grant). Bound to the agent's device once it
/// registers; one grant per agent device.
#[derive(Debug, Clone, FromRow)]
pub struct OauthGrant {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub client_id: String,
    pub scopes: sqlx::types::Json<Vec<String>>,
    pub device_id: Option<uuid::Uuid>,
    /// Name the agent reported for itself when authorized.
    pub agent_name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the user authorized the agent (epoch seconds): the start of every session
    /// of the grant, as recorded in its tokens.
    pub session_start: i64,
}

impl OauthGrant {
    pub fn scopes(&self) -> crate::oauth::Scopes {
        crate::oauth::Scopes::from_recorded(self.scopes.iter().map(String::as_str))
    }
}

/// A grant in force with what the "Connected agents" list shows about it.
#[derive(Debug, Clone, FromRow)]
pub struct OauthGrantListing {
    pub id: uuid::Uuid,
    pub client_id: String,
    pub agent_name: String,
    pub scopes: sqlx::types::Json<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub session_start: i64,
    pub device_id: Option<uuid::Uuid>,
    pub device_name: Option<String>,
    pub device_status: Option<String>,
    /// The user's bulk revocation time (`users.tokens_revoked_before`), 0 when none.
    pub tokens_revoked_before: i64,
}

/// An authorization code or a device code (only its hash is stored).
#[derive(Debug, Clone, FromRow)]
pub struct OauthCode {
    pub code_hash: String,
    /// `authorization_code` or `device_code`.
    pub kind: String,
    /// Device codes: the user code, normalized (eight letters).
    pub user_code: Option<String>,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    /// Requested while a device code is pending, then what the user approved.
    pub scopes: sqlx::types::Json<Vec<String>>,
    /// `pending`, `approved` or `denied`.
    pub status: String,
    /// Who approved (or denied).
    pub user_id: Option<uuid::Uuid>,
    /// The approving session was confirmed with a second factor.
    pub mfa: bool,
    /// When the user approved (epoch seconds).
    pub approved_at: Option<i64>,
    pub requester_ip: Option<String>,
    pub user_agent: Option<String>,
    pub agent_name: String,
    pub interval_secs: i32,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl OauthCode {
    pub fn scopes(&self) -> crate::oauth::Scopes {
        crate::oauth::Scopes::from_recorded(self.scopes.iter().map(String::as_str))
    }
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
// Two-factor authentication
pub const AUDIT_MFA_CHALLENGE: &str = "mfa_challenge";
pub const AUDIT_MFA_FAIL: &str = "mfa_failure";
pub const AUDIT_MFA_LOCKED: &str = "mfa_locked";
pub const AUDIT_MFA_STEP_UP: &str = "mfa_step_up";
pub const AUDIT_MFA_TOTP_ENABLE: &str = "mfa_totp_enabled";
pub const AUDIT_MFA_TOTP_DISABLE: &str = "mfa_totp_disabled";
pub const AUDIT_MFA_PASSKEY_ADD: &str = "mfa_passkey_added";
pub const AUDIT_MFA_PASSKEY_REMOVE: &str = "mfa_passkey_removed";
pub const AUDIT_MFA_RECOVERY_USED: &str = "mfa_recovery_code_used";
pub const AUDIT_MFA_RECOVERY_REGENERATE: &str = "mfa_recovery_codes_regenerated";
pub const AUDIT_MFA_EMAIL_CODE_SENT: &str = "mfa_email_code_sent";
// Admin console
pub const AUDIT_ADMIN_VERIFY_EMAIL: &str = "admin_verify_email";
pub const AUDIT_ADMIN_RESEND_VERIFICATION: &str = "admin_resend_verification";
pub const AUDIT_ADMIN_SUSPEND: &str = "admin_suspend_user";
pub const AUDIT_ADMIN_UNSUSPEND: &str = "admin_unsuspend_user";
pub const AUDIT_ADMIN_REVOKE_SESSIONS: &str = "admin_revoke_sessions";
pub const AUDIT_ADMIN_SET_ROLE: &str = "admin_set_role";
pub const AUDIT_ADMIN_RESET_MFA: &str = "admin_reset_mfa";
pub const AUDIT_ADMIN_PLAN_CREATE: &str = "admin_plan_create";
pub const AUDIT_ADMIN_PLAN_UPDATE: &str = "admin_plan_update";
pub const AUDIT_ADMIN_PLAN_DELETE: &str = "admin_plan_delete";
pub const AUDIT_ADMIN_DOWNLOAD_CREATE: &str = "admin_download_create";
pub const AUDIT_ADMIN_DOWNLOAD_UPDATE: &str = "admin_download_update";
pub const AUDIT_ADMIN_DOWNLOAD_DELETE: &str = "admin_download_delete";
pub const AUDIT_ADMIN_UPLOAD: &str = "admin_upload";
pub const AUDIT_ADMIN_RELEASE_CREATE: &str = "admin_release_create";
pub const AUDIT_ADMIN_RELEASE_UPDATE: &str = "admin_release_update";
pub const AUDIT_ADMIN_RELEASE_DELETE: &str = "admin_release_delete";
pub const AUDIT_ADMIN_SETTINGS_UPDATE: &str = "admin_settings_update";
pub const AUDIT_ADMIN_TEST_SMTP: &str = "admin_test_smtp";
pub const AUDIT_ADMIN_TEST_OIDC: &str = "admin_test_oidc";
pub const AUDIT_ADMIN_API_TOKEN_CREATE: &str = "admin_api_token_create";
pub const AUDIT_ADMIN_API_TOKEN_REVOKE: &str = "admin_api_token_revoke";
// OAuth for agents
pub const AUDIT_OAUTH_GRANT_CREATE: &str = "oauth.grant.create";
pub const AUDIT_OAUTH_GRANT_REVOKE: &str = "oauth.grant.revoke";
pub const AUDIT_OAUTH_DEVICE_APPROVE: &str = "oauth.device.approve";
pub const AUDIT_OAUTH_DEVICE_DENY: &str = "oauth.device.deny";
pub const AUDIT_OAUTH_TOKEN_REUSE: &str = "oauth.token.reuse";

/// Every audit action, for filtering in the admin console.
pub const AUDIT_ACTIONS: &[&str] = &[
    AUDIT_LOGIN_OK,
    AUDIT_LOGIN_FAIL,
    AUDIT_REGISTER,
    AUDIT_PASSWORD_CHANGE,
    AUDIT_DEVICE_REGISTER,
    AUDIT_DEVICE_DELETE,
    AUDIT_DEVICE_APPROVE,
    AUDIT_DEVICE_REJECT,
    AUDIT_GROUP_KEY_ROTATE,
    AUDIT_TOKEN_REVOKE_ALL,
    AUDIT_MFA_CHALLENGE,
    AUDIT_MFA_FAIL,
    AUDIT_MFA_LOCKED,
    AUDIT_MFA_STEP_UP,
    AUDIT_MFA_TOTP_ENABLE,
    AUDIT_MFA_TOTP_DISABLE,
    AUDIT_MFA_PASSKEY_ADD,
    AUDIT_MFA_PASSKEY_REMOVE,
    AUDIT_MFA_RECOVERY_USED,
    AUDIT_MFA_RECOVERY_REGENERATE,
    AUDIT_MFA_EMAIL_CODE_SENT,
    AUDIT_ADMIN_DELETE_USER,
    AUDIT_ADMIN_ASSIGN_SUB,
    AUDIT_ADMIN_REMOVE_SUB,
    AUDIT_ADMIN_VERIFY_EMAIL,
    AUDIT_ADMIN_RESEND_VERIFICATION,
    AUDIT_ADMIN_SUSPEND,
    AUDIT_ADMIN_UNSUSPEND,
    AUDIT_ADMIN_REVOKE_SESSIONS,
    AUDIT_ADMIN_SET_ROLE,
    AUDIT_ADMIN_RESET_MFA,
    AUDIT_ADMIN_PLAN_CREATE,
    AUDIT_ADMIN_PLAN_UPDATE,
    AUDIT_ADMIN_PLAN_DELETE,
    AUDIT_ADMIN_DOWNLOAD_CREATE,
    AUDIT_ADMIN_DOWNLOAD_UPDATE,
    AUDIT_ADMIN_DOWNLOAD_DELETE,
    AUDIT_ADMIN_UPLOAD,
    AUDIT_ADMIN_RELEASE_CREATE,
    AUDIT_ADMIN_RELEASE_UPDATE,
    AUDIT_ADMIN_RELEASE_DELETE,
    AUDIT_ADMIN_SETTINGS_UPDATE,
    AUDIT_ADMIN_TEST_SMTP,
    AUDIT_ADMIN_TEST_OIDC,
    AUDIT_ADMIN_API_TOKEN_CREATE,
    AUDIT_ADMIN_API_TOKEN_REVOKE,
    AUDIT_OAUTH_GRANT_CREATE,
    AUDIT_OAUTH_GRANT_REVOKE,
    AUDIT_OAUTH_DEVICE_APPROVE,
    AUDIT_OAUTH_DEVICE_DENY,
    AUDIT_OAUTH_TOKEN_REUSE,
];
