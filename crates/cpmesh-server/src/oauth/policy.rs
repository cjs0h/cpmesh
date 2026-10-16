//! What agent tokens may do.
//!
//! Default-deny: an agent token is refused with `403 insufficient_scope` on every route
//! [`AGENT_ROUTES`] does not list, whatever that route's own middleware would let a
//! first-party session do. [`agent_policy_middleware`] wraps every route of the router,
//! so it sees the matched route template. It verifies the token itself (signature,
//! expiry and type) and runs before the route's own authentication, which then checks
//! the session and its grant (`oauth::grants::check_grant`).
//!
//! On the WebSocket, `clipboard_push` needs `clipboard:write`, and a connection without
//! `clipboard:read` only receives the messages in [`SEND_ONLY_MESSAGES`].

use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cpmesh_proto::models::{
    MSG_CLIPBOARD_ACK, MSG_DEVICE_STATUS, MSG_GROUP_KEY_UPDATED, MSG_PONG, MSG_ROTATION_NEEDED,
};
use serde_json::json;

use super::{AgentClaims, Scope, Scopes};
use crate::AppState;
use crate::routes::middleware::{API_TOKEN_PREFIX, ApiError, bearer_token};

/// What an agent needs to use a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentAccess {
    /// Any agent session, also before its device is registered or approved:
    /// registering and pairing its device, and reading the account.
    Enrollment,
    /// An agent whose device is approved.
    PairedDevice,
    /// An agent whose device is approved, with at least one of these scopes.
    AnyScope(Scopes),
}

const READ: Scopes = Scopes::of(&[Scope::ClipboardRead]);
const READ_OR_WRITE: Scopes = Scopes::of(&[Scope::ClipboardRead, Scope::ClipboardWrite]);
const DELETE: Scopes = Scopes::of(&[Scope::ClipboardDelete]);
const MANAGE_DEVICES: Scopes = Scopes::of(&[Scope::DevicesManage]);

/// The routes agents may use, by method and route template as registered with the
/// router. Everything else is refused, including the account's password, subscription
/// and second factors, the admin console, WebSocket tickets, the desktop sign-in
/// handoff, clearing the whole history, the legacy group-key endpoints and every
/// approval step for another device.
pub static AGENT_ROUTES: &[(Method, &str, AgentAccess)] = &[
    (
        Method::POST,
        "/api/devices/challenge",
        AgentAccess::Enrollment,
    ),
    (Method::POST, "/api/devices", AgentAccess::Enrollment),
    (
        Method::PUT,
        "/api/devices/me/encryption-key",
        AgentAccess::Enrollment,
    ),
    (
        Method::GET,
        "/api/device-approvals/me",
        AgentAccess::Enrollment,
    ),
    (
        Method::POST,
        "/api/device-approvals/me/nonce",
        AgentAccess::Enrollment,
    ),
    (Method::GET, "/api/me", AgentAccess::Enrollment),
    (Method::GET, "/api/devices", AgentAccess::PairedDevice),
    (Method::GET, "/api/devices/keys", AgentAccess::PairedDevice),
    (
        Method::GET,
        "/api/group-keys/current",
        AgentAccess::PairedDevice,
    ),
    (
        Method::POST,
        "/api/group-keys/rotate",
        AgentAccess::PairedDevice,
    ),
    (Method::GET, "/api/clipboard", AgentAccess::AnyScope(READ)),
    // Without clipboard:read the socket carries no entries (see SEND_ONLY_MESSAGES)
    (Method::GET, "/ws", AgentAccess::AnyScope(READ_OR_WRITE)),
    (
        Method::DELETE,
        "/api/clipboard/{id}",
        AgentAccess::AnyScope(DELETE),
    ),
    (
        Method::DELETE,
        "/api/devices/{id}",
        AgentAccess::AnyScope(MANAGE_DEVICES),
    ),
];

/// What an agent needs to use `method` on the route template `route`, or `None` when
/// agents may not use it at all.
pub fn agent_access(method: &Method, route: &str) -> Option<AgentAccess> {
    // HEAD requests are answered by the GET handler
    let method = if method == Method::HEAD {
        &Method::GET
    } else {
        method
    };
    AGENT_ROUTES
        .iter()
        .find(|(m, r, _)| m == method && *r == route)
        .map(|(_, _, access)| *access)
}

/// Decides whether an agent session (`agent`, bound to `device_id` if any) may use
/// `route`, the matched route template (`None` when no route matched).
pub fn authorize(
    method: &Method,
    route: Option<&str>,
    agent: &AgentClaims,
    device_id: Option<uuid::Uuid>,
) -> Result<AgentAccess, ApiError> {
    let access = route
        .and_then(|route| agent_access(method, route))
        .ok_or_else(|| insufficient_scope(None))?;
    match access {
        AgentAccess::Enrollment => {}
        AgentAccess::PairedDevice => require_device(device_id)?,
        AgentAccess::AnyScope(scopes) => {
            if !agent.scopes.intersects(scopes) {
                return Err(insufficient_scope(Some(scopes)));
            }
            require_device(device_id)?;
        }
    }
    Ok(access)
}

/// Applies [`authorize`] to requests that carry an agent access token, and hands the
/// route's [`AgentAccess`] to the middleware behind it. Other requests pass untouched;
/// invalid tokens are refused by the route's own authentication.
pub async fn agent_policy_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let agent = bearer_token(req.headers())
        .filter(|token| !token.starts_with(API_TOKEN_PREFIX))
        .and_then(|token| state.auth.validate_access_token(&token).ok())
        .and_then(|claims| Some((claims.agent?, claims.device_id)));
    let Some((agent, device_id)) = agent else {
        return next.run(req).await;
    };
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    match authorize(req.method(), route, &agent, device_id) {
        Ok(access) => {
            req.extensions_mut().insert(access);
            next.run(req).await
        }
        Err(error) => error.into_response(),
    }
}

/// `403 insufficient_scope` with its RFC 6750 challenge, naming the scopes (any one of
/// them) that would allow the request, if any would.
pub(crate) fn insufficient_scope(needed: Option<Scopes>) -> ApiError {
    match needed {
        Some(scopes) => ApiError::coded(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            format!("this agent needs one of these scopes: {scopes}"),
        )
        .with_extra(json!({ "scope": scopes.to_string() }))
        .with_challenge(format!(
            "Bearer error=\"insufficient_scope\", scope=\"{scopes}\""
        )),
        None => ApiError::coded(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "agents cannot use this endpoint",
        )
        .with_challenge("Bearer error=\"insufficient_scope\""),
    }
}

/// Agents use the account through their own device, once it is paired.
pub(crate) fn device_required() -> ApiError {
    ApiError::coded(
        StatusCode::FORBIDDEN,
        "device_required",
        "register this agent's device and pair it with one of your devices first",
    )
}

fn require_device(device_id: Option<uuid::Uuid>) -> Result<(), ApiError> {
    match device_id {
        Some(_) => Ok(()),
        None => Err(device_required()),
    }
}

/// The WebSocket messages a connection without `clipboard:read` receives: the
/// acknowledgements of its own pushes and pings, and key, membership and device events.
/// Everything else is withheld, including entries and any message type added later
/// until it is classified here.
pub const SEND_ONLY_MESSAGES: &[&str] = &[
    MSG_CLIPBOARD_ACK,
    MSG_PONG,
    MSG_GROUP_KEY_UPDATED,
    MSG_ROTATION_NEEDED,
    MSG_DEVICE_STATUS,
];

/// Whether a connection that cannot read the clipboard may receive `msg_type`.
pub fn delivered_without_read(msg_type: &str) -> bool {
    SEND_ONLY_MESSAGES.contains(&msg_type)
}

/// Whether a session may receive clipboard entries: first-party sessions, and agents
/// with `clipboard:read`.
pub fn reads_clipboard(agent: Option<&AgentClaims>) -> bool {
    agent.is_none_or(|agent| agent.scopes.contains(Scope::ClipboardRead))
}

/// Whether a session may push clipboard entries: first-party sessions, and agents with
/// `clipboard:write`.
pub fn writes_clipboard(agent: Option<&AgentClaims>) -> bool {
    agent.is_none_or(|agent| agent.scopes.contains(Scope::ClipboardWrite))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(scopes: &[Scope]) -> AgentClaims {
        AgentClaims {
            client_id: crate::oauth::MCP_CLIENT_ID,
            scopes: Scopes::of(scopes),
            grant_id: uuid::Uuid::new_v4(),
        }
    }

    #[test]
    fn routes_are_listed_once_per_method() {
        for (i, (method, route, _)) in AGENT_ROUTES.iter().enumerate() {
            assert!(route.starts_with('/'), "{route}");
            assert!(
                !AGENT_ROUTES[..i]
                    .iter()
                    .any(|(m, r, _)| m == method && r == route),
                "{method} {route} is listed twice"
            );
        }
    }

    #[test]
    fn unlisted_routes_and_methods_are_refused() {
        let device = Some(uuid::Uuid::new_v4());
        let everything = agent(&Scope::ALL);
        for (method, route) in [
            (Method::DELETE, Some("/api/clipboard")),
            (Method::POST, Some("/api/group-key")),
            (Method::GET, Some("/api/group-key")),
            (Method::POST, Some("/api/ws/ticket")),
            (Method::POST, Some("/api/auth/native-code")),
            (
                Method::POST,
                Some("/api/device-approvals/{pending_device_id}/approve"),
            ),
            (Method::POST, Some("/api/me")),
            (Method::GET, None),
        ] {
            let error = authorize(&method, route, &everything, device).unwrap_err();
            assert_eq!(error.status(), StatusCode::FORBIDDEN, "{method} {route:?}");
            assert_eq!(error.code(), Some("insufficient_scope"));
        }
    }

    #[test]
    fn scoped_routes_need_one_of_their_scopes_and_a_device() {
        let device = Some(uuid::Uuid::new_v4());
        let ws = Some("/ws");
        for scopes in [&[Scope::ClipboardRead][..], &[Scope::ClipboardWrite]] {
            assert_eq!(
                authorize(&Method::GET, ws, &agent(scopes), device).ok(),
                Some(AgentAccess::AnyScope(READ_OR_WRITE))
            );
        }
        let error =
            authorize(&Method::GET, ws, &agent(&[Scope::DevicesManage]), device).unwrap_err();
        assert_eq!(error.code(), Some("insufficient_scope"));
        let error = authorize(&Method::GET, ws, &agent(&[Scope::ClipboardRead]), None).unwrap_err();
        assert_eq!(error.code(), Some("device_required"));

        let history = Some("/api/clipboard");
        assert!(
            authorize(
                &Method::GET,
                history,
                &agent(&[Scope::ClipboardWrite]),
                device
            )
            .is_err()
        );
        assert!(
            authorize(
                &Method::HEAD,
                history,
                &agent(&[Scope::ClipboardRead]),
                device
            )
            .is_ok()
        );
        let delete = Some("/api/clipboard/{id}");
        assert!(
            authorize(
                &Method::DELETE,
                delete,
                &agent(&[Scope::ClipboardRead]),
                device
            )
            .is_err()
        );
        assert!(
            authorize(
                &Method::DELETE,
                delete,
                &agent(&[Scope::ClipboardDelete]),
                device
            )
            .is_ok()
        );
        let remove = Some("/api/devices/{id}");
        assert!(
            authorize(
                &Method::DELETE,
                remove,
                &agent(&[Scope::ClipboardDelete]),
                device
            )
            .is_err()
        );
        assert!(
            authorize(
                &Method::DELETE,
                remove,
                &agent(&[Scope::DevicesManage]),
                device
            )
            .is_ok()
        );
    }

    #[test]
    fn enrollment_needs_no_device_and_no_scope() {
        let nothing = agent(&[]);
        for (method, route) in [
            (Method::GET, "/api/me"),
            (Method::POST, "/api/devices/challenge"),
            (Method::POST, "/api/devices"),
            (Method::PUT, "/api/devices/me/encryption-key"),
            (Method::GET, "/api/device-approvals/me"),
            (Method::POST, "/api/device-approvals/me/nonce"),
        ] {
            assert_eq!(
                authorize(&method, Some(route), &nothing, None).ok(),
                Some(AgentAccess::Enrollment),
                "{method} {route}"
            );
        }
        for (method, route) in [
            (Method::GET, "/api/devices"),
            (Method::GET, "/api/devices/keys"),
            (Method::GET, "/api/group-keys/current"),
            (Method::POST, "/api/group-keys/rotate"),
        ] {
            assert_eq!(
                authorize(&method, Some(route), &nothing, None)
                    .unwrap_err()
                    .code(),
                Some("device_required"),
                "{method} {route}"
            );
            assert!(authorize(&method, Some(route), &nothing, Some(uuid::Uuid::new_v4())).is_ok());
        }
    }

    #[test]
    fn send_only_connections_get_acks_and_key_events_but_no_entries() {
        for kind in SEND_ONLY_MESSAGES {
            assert!(delivered_without_read(kind));
        }
        for kind in ["clipboard_new", "clipboard_push", "error", "history", ""] {
            assert!(!delivered_without_read(kind), "{kind}");
        }
        assert!(reads_clipboard(None) && writes_clipboard(None));
        let send_only = agent(&[Scope::ClipboardWrite]);
        assert!(!reads_clipboard(Some(&send_only)) && writes_clipboard(Some(&send_only)));
        let read_only = agent(&[Scope::ClipboardRead]);
        assert!(reads_clipboard(Some(&read_only)) && !writes_clipboard(Some(&read_only)));
    }
}
