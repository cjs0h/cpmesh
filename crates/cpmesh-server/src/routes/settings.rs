//! Public runtime settings for clients (`GET /api/settings`).

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::Response};
use serde_json::json;

use super::middleware::json_response;
use crate::AppState;

/// What every client may know: whether sign-up is open, the announcement banner, and
/// which second factors this server supports.
pub async fn handle_public_settings(State(state): State<Arc<AppState>>) -> Response {
    let settings = state.settings.get(&state.db).await;
    json_response(
        StatusCode::OK,
        json!({
            "registration_open": settings.registration_open(&state.config),
            "banner": settings.banner,
            "passkeys_available": state.config.passkeys_enabled(),
            "mfa_required": state.config.mfa_policy == crate::config::MfaPolicy::All,
        }),
    )
}
