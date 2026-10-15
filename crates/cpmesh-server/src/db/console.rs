//! Queries behind the admin console: user management, statistics, the audit log,
//! runtime settings, API tokens and activity tracking.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, QueryBuilder};

use super::{Db, decrypt_optional_field};
use crate::models::*;
use crate::pii::PiiService;
use crate::rbac::Role;

/// Filters for the admin user list.
#[derive(Debug, Default)]
pub struct UserListFilter<'a> {
    /// A user ID, an exact email address, or part of a username.
    pub query: Option<&'a str>,
    /// A role name, or "staff" for every staff role.
    pub role: Option<&'a str>,
    /// "active", "suspended", "unverified" or "no_mfa".
    pub status: Option<&'a str>,
    pub plan_id: Option<uuid::Uuid>,
    pub page: i64,
    pub per_page: i64,
}

/// Filters for the audit log.
#[derive(Debug, Default)]
pub struct AuditFilter<'a> {
    /// Entries by or about this user.
    pub user_id: Option<uuid::Uuid>,
    pub action: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RoleChange {
    Changed,
    NotFound,
    /// The change would leave no owner.
    LastOwner,
}

#[derive(sqlx::FromRow)]
struct AdminUserDbRow {
    id: uuid::Uuid,
    username: String,
    email: Option<String>,
    full_name: String,
    email_verified: bool,
    auth_provider: String,
    role: String,
    created_at: DateTime<Utc>,
    device_count: i32,
    subscription_plan_id: Option<uuid::Uuid>,
    plan_name: Option<String>,
    suspended_at: Option<DateTime<Utc>>,
    mfa_enabled: bool,
    last_seen: Option<DateTime<Utc>>,
}

const USER_ROW_SELECT: &str = "SELECT u.id, u.username, u.email, u.full_name,
        COALESCE(u.email_verified, FALSE) AS email_verified,
        COALESCE(u.auth_provider, 'local') AS auth_provider, u.role, u.created_at,
        (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id)::int AS device_count,
        u.subscription_plan_id, sp.name AS plan_name, u.suspended_at,
        (EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.totp_secret IS NOT NULL)
         OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id)) AS mfa_enabled,
        (SELECT MAX(d.last_seen) FROM devices d WHERE d.user_id = u.id) AS last_seen
     FROM users u
     LEFT JOIN subscription_plans sp ON sp.id = u.subscription_plan_id";

const HAS_MFA: &str =
    "(EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.totp_secret IS NOT NULL)
     OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id))";

impl AdminUserDbRow {
    fn into_row(self, pii: Option<&PiiService>) -> AdminUserRow {
        let role = Role::from_db(&self.role);
        AdminUserRow {
            id: self.id,
            username: self.username,
            email: decrypt_optional_field(self.email.as_deref(), pii),
            full_name: decrypt_optional_field(Some(&self.full_name), pii),
            email_verified: self.email_verified,
            auth_provider: self.auth_provider,
            is_admin: role.is_staff(),
            role: role.as_str().to_string(),
            created_at: self.created_at,
            device_count: self.device_count,
            subscription_plan_id: self.subscription_plan_id,
            subscription_plan_name: self.plan_name,
            suspended_at: self.suspended_at,
            mfa_enabled: self.mfa_enabled,
            last_seen: self.last_seen,
        }
    }
}

/// Appends the WHERE clause for `filter`. Encrypted columns cannot be searched, so an
/// email only matches exactly (through its blind index).
fn push_user_filters(
    qb: &mut QueryBuilder<Postgres>,
    filter: &UserListFilter<'_>,
    pii: Option<&PiiService>,
) {
    qb.push(" WHERE TRUE");
    if let Some(q) = filter.query.map(str::trim).filter(|q| !q.is_empty()) {
        if let Ok(id) = uuid::Uuid::parse_str(q) {
            qb.push(" AND u.id = ").push_bind(id);
        } else if q.contains('@') {
            let email_idx = match pii {
                Some(p) => p.blind_index(q),
                None => q.to_lowercase(),
            };
            qb.push(" AND (u.email_idx = ")
                .push_bind(email_idx)
                .push(" OR u.username_idx = ")
                .push_bind(q.to_lowercase())
                .push(")");
        } else {
            let escaped = q
                .to_lowercase()
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            qb.push(" AND u.username_idx LIKE ")
                .push_bind(format!("%{escaped}%"));
        }
    }
    match filter.role {
        Some("staff") => {
            qb.push(" AND u.role <> 'user'");
        }
        Some(role) if Role::parse(role).is_some() => {
            qb.push(" AND u.role = ").push_bind(role.to_string());
        }
        _ => {}
    }
    match filter.status {
        Some("active") => {
            qb.push(" AND u.suspended_at IS NULL");
        }
        Some("suspended") => {
            qb.push(" AND u.suspended_at IS NOT NULL");
        }
        Some("unverified") => {
            qb.push(" AND COALESCE(u.email_verified, FALSE) = FALSE");
        }
        Some("no_mfa") => {
            qb.push(" AND NOT ").push(HAS_MFA);
        }
        _ => {}
    }
    if let Some(plan_id) = filter.plan_id {
        qb.push(" AND u.subscription_plan_id = ").push_bind(plan_id);
    }
}

impl Db {
    // === Users ===

    /// One page of users. Only the rows on the page have their PII decrypted.
    pub async fn admin_list_users(
        &self,
        filter: &UserListFilter<'_>,
        pii: Option<&PiiService>,
    ) -> Result<Page<AdminUserRow>, sqlx::Error> {
        let per_page = filter.per_page.clamp(1, 200);
        let page = filter.page.max(1);

        let mut count = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM users u");
        push_user_filters(&mut count, filter, pii);
        let (total,): (i64,) = count.build_query_as().fetch_one(&self.pool).await?;

        let mut list = QueryBuilder::<Postgres>::new(USER_ROW_SELECT);
        push_user_filters(&mut list, filter, pii);
        list.push(" ORDER BY u.created_at DESC, u.id LIMIT ")
            .push_bind(per_page)
            .push(" OFFSET ")
            .push_bind((page - 1) * per_page);
        let rows: Vec<AdminUserDbRow> = list.build_query_as().fetch_all(&self.pool).await?;

        Ok(Page {
            items: rows.into_iter().map(|r| r.into_row(pii)).collect(),
            total,
            page,
            per_page,
        })
    }

    pub async fn admin_get_user(
        &self,
        user_id: uuid::Uuid,
        pii: Option<&PiiService>,
    ) -> Result<Option<AdminUserRow>, sqlx::Error> {
        let mut qb = QueryBuilder::<Postgres>::new(USER_ROW_SELECT);
        qb.push(" WHERE u.id = ").push_bind(user_id);
        let row: Option<AdminUserDbRow> = qb.build_query_as().fetch_optional(&self.pool).await?;
        Ok(row.map(|r| r.into_row(pii)))
    }

    /// Changes a user's role, refusing to remove the last owner.
    pub async fn change_user_role(
        &self,
        user_id: uuid::Uuid,
        role: Role,
    ) -> Result<RoleChange, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Locking every owner row serializes concurrent demotions
        let owners: Vec<(uuid::Uuid,)> =
            sqlx::query_as("SELECT id FROM users WHERE role = 'owner' FOR UPDATE")
                .fetch_all(&mut *tx)
                .await?;
        let current: Option<(String,)> =
            sqlx::query_as("SELECT role FROM users WHERE id = $1 FOR UPDATE")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((current,)) = current else {
            return Ok(RoleChange::NotFound);
        };
        if current == Role::Owner.as_str() && role != Role::Owner && owners.len() <= 1 {
            return Ok(RoleChange::LastOwner);
        }
        sqlx::query("UPDATE users SET role = $1, is_admin = $2 WHERE id = $3")
            .bind(role.as_str())
            .bind(role.is_staff())
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(RoleChange::Changed)
    }

    pub async fn suspend_user(&self, user_id: uuid::Uuid, reason: &str) -> Result<(), sqlx::Error> {
        let result = sqlx::query(
            "UPDATE users SET suspended_at = COALESCE(suspended_at, NOW()), suspended_reason = $2
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    pub async fn unsuspend_user(&self, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        let result = sqlx::query(
            "UPDATE users SET suspended_at = NULL, suspended_reason = NULL WHERE id = $1",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    }

    // === Activity and statistics ===

    /// Notes that the user was active today.
    pub async fn record_activity(&self, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO user_daily_activity (day, user_id) VALUES (CURRENT_DATE, $1)
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn admin_get_stats(&self) -> Result<AdminStats, sqlx::Error> {
        #[allow(clippy::type_complexity)]
        let counts: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                (SELECT COUNT(*) FROM users),
                (SELECT COUNT(*) FROM devices),
                (SELECT COUNT(*) FROM clipboard_entries),
                (SELECT COUNT(*) FROM devices WHERE status = 'pending'),
                (SELECT COUNT(*) FROM users WHERE suspended_at IS NOT NULL),
                (SELECT COUNT(*) FROM users WHERE role <> 'user'),
                (SELECT COUNT(*) FROM users u WHERE (EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.totp_secret IS NOT NULL)
                     OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id))),
                (SELECT COUNT(DISTINCT user_id) FROM user_daily_activity WHERE day >= CURRENT_DATE),
                (SELECT COUNT(DISTINCT user_id) FROM user_daily_activity WHERE day > CURRENT_DATE - 7),
                (SELECT COUNT(DISTINCT user_id) FROM user_daily_activity WHERE day > CURRENT_DATE - 30),
                pg_total_relation_size('clipboard_entries')",
        )
        .fetch_one(&self.pool)
        .await?;

        let plans: Vec<(Option<uuid::Uuid>, String, i64)> = sqlx::query_as(
            "SELECT sp.id, COALESCE(sp.name, 'No plan'), COUNT(u.id)
             FROM users u LEFT JOIN subscription_plans sp ON sp.id = u.subscription_plan_id
             GROUP BY sp.id, sp.name ORDER BY COUNT(u.id) DESC, 2",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(AdminStats {
            total_users: counts.0,
            total_devices: counts.1,
            total_entries: counts.2,
            active_connections: 0,
            pending_devices: counts.3,
            suspended_users: counts.4,
            staff_users: counts.5,
            mfa_users: counts.6,
            active_users_1d: counts.7,
            active_users_7d: counts.8,
            active_users_30d: counts.9,
            storage_bytes: counts.10,
            signups: self
                .daily_series("SELECT created_at::date, COUNT(*) FROM users WHERE created_at >= CURRENT_DATE - 29 GROUP BY 1")
                .await?,
            active_users: self
                .daily_series("SELECT day, COUNT(*) FROM user_daily_activity WHERE day >= CURRENT_DATE - 29 GROUP BY 1")
                .await?,
            entries: self
                .daily_series("SELECT created_at::date, COUNT(*) FROM clipboard_entries WHERE created_at >= CURRENT_DATE - 29 GROUP BY 1")
                .await?,
            plans: plans
                .into_iter()
                .map(|(plan_id, name, users)| PlanUsage {
                    plan_id,
                    name,
                    users,
                })
                .collect(),
        })
    }

    /// Daily counts for the last 30 days (zero-filled) from `per_day`, a query returning
    /// `(date, count)` rows.
    async fn daily_series(&self, per_day: &'static str) -> Result<Vec<DailyCount>, sqlx::Error> {
        let rows: Vec<(String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT to_char(d.day, 'YYYY-MM-DD'), COALESCE(c.count, 0)
             FROM generate_series(CURRENT_DATE - 29, CURRENT_DATE, interval '1 day') AS d(day)
             LEFT JOIN ({per_day}) AS c(day, count) ON c.day = d.day::date
             ORDER BY d.day"
        )))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(day, count)| DailyCount { day, count })
            .collect())
    }

    // === Audit log ===

    /// Records an audit entry, optionally about another account.
    pub async fn write_audit_entry(
        &self,
        actor: Option<uuid::Uuid>,
        target: Option<uuid::Uuid>,
        action: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        details: &serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO audit_logs (user_id, target_user_id, action, ip_address, user_agent, details)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(actor)
        .bind(target)
        .bind(action)
        .bind(ip_address)
        .bind(user_agent)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Audit entries, newest first, with the total matching `filter`.
    pub async fn list_audit_entries(
        &self,
        filter: &AuditFilter<'_>,
    ) -> Result<(Vec<AuditLogRow>, i64), sqlx::Error> {
        let (total,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_logs a
             WHERE ($1::uuid IS NULL OR a.user_id = $1 OR a.target_user_id = $1)
               AND ($2::text IS NULL OR a.action = $2)",
        )
        .bind(filter.user_id)
        .bind(filter.action)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, AuditLogRow>(
            "SELECT a.id, a.user_id, au.username, a.target_user_id, tu.username AS target_username,
                    a.action, a.ip_address, a.user_agent, COALESCE(a.details, '{}'::jsonb) AS details,
                    a.created_at
             FROM audit_logs a
             LEFT JOIN users au ON au.id = a.user_id
             LEFT JOIN users tu ON tu.id = a.target_user_id
             WHERE ($1::uuid IS NULL OR a.user_id = $1 OR a.target_user_id = $1)
               AND ($2::text IS NULL OR a.action = $2)
             ORDER BY a.created_at DESC, a.id
             LIMIT $3 OFFSET $4",
        )
        .bind(filter.user_id)
        .bind(filter.action)
        .bind(filter.limit.clamp(1, 500))
        .bind(filter.offset.max(0))
        .fetch_all(&self.pool)
        .await?;
        Ok((rows, total))
    }

    // === Runtime settings ===

    pub async fn load_settings(&self) -> Result<Vec<(String, serde_json::Value)>, sqlx::Error> {
        sqlx::query_as("SELECT key, value FROM app_settings")
            .fetch_all(&self.pool)
            .await
    }

    /// Sets a setting, or removes it (back to the default) when `value` is `None`.
    pub async fn put_setting(
        &self,
        key: &str,
        value: Option<&serde_json::Value>,
        updated_by: uuid::Uuid,
    ) -> Result<(), sqlx::Error> {
        match value {
            Some(value) => {
                sqlx::query(
                    "INSERT INTO app_settings (key, value, updated_by, updated_at)
                     VALUES ($1, $2, $3, NOW())
                     ON CONFLICT (key) DO UPDATE SET value = $2, updated_by = $3, updated_at = NOW()",
                )
                .bind(key)
                .bind(value)
                .bind(updated_by)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM app_settings WHERE key = $1")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    // === API tokens ===

    pub async fn create_api_token(
        &self,
        user_id: uuid::Uuid,
        name: &str,
        token_hash: &str,
        token_prefix: &str,
        scopes: &[&str],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiToken, sqlx::Error> {
        sqlx::query_as::<_, ApiToken>(
            "WITH inserted AS (
                INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
             )
             SELECT i.id, i.user_id, u.username, i.name, i.token_prefix, i.scopes, i.expires_at,
                    i.last_used_at, i.revoked_at, i.created_at
             FROM inserted i LEFT JOIN users u ON u.id = i.user_id",
        )
        .bind(user_id)
        .bind(name)
        .bind(token_hash)
        .bind(token_prefix)
        .bind(serde_json::json!(scopes))
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn list_api_tokens(&self) -> Result<Vec<ApiToken>, sqlx::Error> {
        sqlx::query_as::<_, ApiToken>(
            "SELECT t.id, t.user_id, u.username, t.name, t.token_prefix, t.scopes, t.expires_at,
                    t.last_used_at, t.revoked_at, t.created_at
             FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id
             ORDER BY t.revoked_at IS NOT NULL, t.created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
    }

    /// The token with this hash, if it is neither revoked nor expired.
    pub async fn find_active_api_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<ApiToken>, sqlx::Error> {
        sqlx::query_as::<_, ApiToken>(
            "SELECT t.id, t.user_id, u.username, t.name, t.token_prefix, t.scopes, t.expires_at,
                    t.last_used_at, t.revoked_at, t.created_at
             FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = $1 AND t.revoked_at IS NULL
               AND (t.expires_at IS NULL OR t.expires_at > NOW())",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn touch_api_token(&self, id: uuid::Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Returns `false` when there is no such active token.
    pub async fn revoke_api_token(&self, id: uuid::Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    // === Uploaded installers ===

    pub async fn find_download_link_by_url(
        &self,
        url: &str,
    ) -> Result<Option<DownloadLink>, sqlx::Error> {
        sqlx::query_as::<_, DownloadLink>(
            "SELECT * FROM download_links WHERE url = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(url)
        .fetch_optional(&self.pool)
        .await
    }

    /// Records a file uploaded to this server: updates the link already pointing at it,
    /// or creates one.
    pub async fn upsert_uploaded_download(
        &self,
        params: &super::DownloadLinkParams<'_>,
        sha256: &str,
        size_bytes: i64,
    ) -> Result<DownloadLink, sqlx::Error> {
        if let Some(existing) = self.find_download_link_by_url(params.url).await? {
            return sqlx::query_as::<_, DownloadLink>(
                "UPDATE download_links SET sha256 = $2, size_bytes = $3, updated_at = NOW()
                 WHERE id = $1 RETURNING *",
            )
            .bind(existing.id)
            .bind(sha256)
            .bind(size_bytes)
            .fetch_one(&self.pool)
            .await;
        }
        sqlx::query_as::<_, DownloadLink>(
            "INSERT INTO download_links (name, url, platform, arch, format, sort_order, is_active, release_id, sha256, size_bytes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *",
        )
        .bind(params.name)
        .bind(params.url)
        .bind(params.platform)
        .bind(params.arch)
        .bind(params.format)
        .bind(params.sort_order)
        .bind(params.is_active)
        .bind(params.release_id)
        .bind(sha256)
        .bind(size_bytes)
        .fetch_one(&self.pool)
        .await
    }
}
