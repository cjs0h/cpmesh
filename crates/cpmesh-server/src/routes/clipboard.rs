use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use super::middleware::{AuthClaims, json_error, json_response};
use crate::AppState;

#[derive(Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    #[serde(default)]
    pub metadata_only: bool,
}

pub async fn handle_get_clipboard_history(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let mut limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let sub = match state.db.get_user_subscription(claims.user_id).await {
        Ok(sub) => sub,
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    };
    if let Some(max_history) = sub.max_clipboard_history
        && max_history > 0
    {
        if offset >= max_history as i64 {
            return json_response(
                StatusCode::OK,
                json!({
                    "entries": [],
                    "has_more": false,
                }),
            );
        }
        if offset + limit > max_history as i64 {
            limit = max_history as i64 - offset;
        }
    }

    if query.metadata_only {
        return match state
            .db
            .clipboard_metadata(claims.user_id, limit + 1, offset)
            .await
        {
            Ok(mut entries) => {
                let has_more = entries.len() as i64 > limit
                    && sub
                        .max_clipboard_history
                        .filter(|n| *n > 0)
                        .is_none_or(|max| offset + limit < i64::from(max));
                entries.truncate(limit as usize);
                json_response(
                    StatusCode::OK,
                    json!({"entries": entries, "has_more": has_more}),
                )
            }
            Err(e) => super::middleware::ApiError::internal(e).into_response(),
        };
    }
    let entries = match state
        .db
        .get_clipboard_history(claims.user_id, limit + 1, offset)
        .await
    {
        Ok(e) => e,
        Err(_) => return json_error("failed to get history", StatusCode::INTERNAL_SERVER_ERROR),
    };

    let total = match state.db.count_user_clipboard_entries(claims.user_id).await {
        Ok(total) => total.min(
            sub.max_clipboard_history
                .filter(|n| *n > 0)
                .map(i64::from)
                .unwrap_or(i64::MAX),
        ),
        Err(e) => return super::middleware::ApiError::internal(e).into_response(),
    };
    let has_more = total > offset + (entries.len() as i64).min(limit);
    let entries: Vec<_> = entries.into_iter().take(limit as usize).map(|e| {
        json!({
            "id": e.id.to_string(),
            "user_id": e.user_id.to_string(),
            "device_id": e.device_id.to_string(),
            "device_name": e.device_name,
            "content_type": e.content_type,
            "encrypted_data": base64::engine::general_purpose::STANDARD.encode(&e.encrypted_data),
            "metadata": e.metadata.unwrap_or_default(),
            "created_at": e.created_at.to_rfc3339(),
            "key_version": e.key_version,
        })
    }).collect();

    json_response(
        StatusCode::OK,
        json!({
            "entries": entries,
            "has_more": has_more,
        }),
    )
}

pub async fn handle_delete_clipboard_entry(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    Path(entry_id): Path<uuid::Uuid>,
) -> Response {
    if state
        .db
        .delete_clipboard_entry(entry_id, claims.user_id)
        .await
        .is_err()
    {
        return json_error("entry not found", StatusCode::NOT_FOUND);
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn handle_clear_clipboard(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
) -> Response {
    if state
        .db
        .clear_clipboard_history(claims.user_id)
        .await
        .is_err()
    {
        return json_error("failed to clear history", StatusCode::INTERNAL_SERVER_ERROR);
    }
    StatusCode::NO_CONTENT.into_response()
}
