//! Audit logging shared by the route handlers.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::AppState;
use crate::routes::middleware::extract_client_ip;

/// Who made a request: client address (honouring trusted proxies) and user agent.
#[derive(Clone, Debug, Default)]
pub struct RequestMeta {
    pub ip: String,
    pub user_agent: Option<String>,
}

impl FromRequestParts<Arc<AppState>> for RequestMeta {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| {
                extract_client_ip(&parts.headers, addr, state.config.trust_proxy_headers)
                    .to_string()
            })
            .unwrap_or_else(|| "unknown".to_string());
        let user_agent = parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|ua| ua.chars().take(512).collect());
        Ok(RequestMeta { ip, user_agent })
    }
}

/// Writes an audit entry in the background; failures never affect the request.
pub fn record(
    state: &AppState,
    actor: Option<uuid::Uuid>,
    target: Option<uuid::Uuid>,
    action: &'static str,
    meta: &RequestMeta,
    details: serde_json::Value,
) {
    let pool = state.db.pool.clone();
    let meta = meta.clone();
    tokio::spawn(async move {
        let db = crate::db::Db { pool };
        if let Err(e) = db
            .write_audit_entry(
                actor,
                target,
                action,
                Some(&meta.ip),
                meta.user_agent.as_deref(),
                &details,
            )
            .await
        {
            tracing::warn!("Failed to write audit entry {action}: {e}");
        }
    });
}

/// Notes in the background that `user_id` was active today.
pub fn record_activity(state: &AppState, user_id: uuid::Uuid) {
    let pool = state.db.pool.clone();
    tokio::spawn(async move {
        let _ = crate::db::Db { pool }.record_activity(user_id).await;
    });
}
