use axum::{
    extract::{
        ConnectInfo, Extension, Query, Request, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use super::middleware::{
    AuthClaims, authenticate, check_session, extract_client_ip, json_error, json_response,
    require_approved_device,
};
use crate::AppState;
use crate::ws::Client;
use cpmesh_proto::models::*;

/// How long a WebSocket ticket can be redeemed after it is issued.
const TICKET_TTL: Duration = Duration::from_secs(10);

/// Most WebSocket connections (devices and browser tabs) one user may hold.
const MAX_CONNECTIONS_PER_USER: usize = 10;

// WS ticket store (short-lived, single-use)
static TICKETS: LazyLock<Mutex<HashMap<String, WsTicket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct WsTicket {
    claims: AuthClaims,
    expires: Instant,
    client_ip: IpAddr,
}

/// Issues a single-use ticket that authenticates one WebSocket upgrade from
/// `client_ip` within [`TICKET_TTL`]. Browsers cannot set an Authorization header on
/// a WebSocket, so they present a ticket in the query string instead of their JWT.
pub(crate) async fn issue_ticket(claims: AuthClaims, client_ip: IpAddr) -> String {
    let mut ticket_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut ticket_bytes);
    let ticket: String = ticket_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let now = Instant::now();
    let mut tickets = TICKETS.lock().await;
    // Drop tickets that were never redeemed so they cannot accumulate
    tickets.retain(|_, t| t.expires > now);
    tickets.insert(
        ticket.clone(),
        WsTicket {
            claims,
            expires: now + TICKET_TTL,
            client_ip,
        },
    );
    ticket
}

/// Consumes a ticket, returning the session it was issued to.
async fn redeem_ticket(ticket: &str, client_ip: IpAddr) -> Option<AuthClaims> {
    let t = TICKETS.lock().await.remove(ticket)?;
    if Instant::now() > t.expires {
        return None;
    }
    if t.client_ip != client_ip {
        warn!("WS ticket presented from a different address than it was issued to");
        return None;
    }
    Some(t.claims)
}

pub async fn handle_ws_ticket(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    let client_ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);
    let ticket = issue_ticket(claims, client_ip).await;
    json_response(StatusCode::OK, json!({"ticket": ticket}))
}

#[derive(serde::Deserialize)]
pub struct WsQuery {
    pub ticket: Option<String>,
}

/// Authenticates WebSocket upgrades. Desktop and MCP clients send their access token
/// in the Authorization header; browsers present a ticket from `POST /api/ws/ticket`
/// in the query string. Sessions bound to a device need that device to be approved.
pub async fn ws_auth_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<WsQuery>,
    mut req: Request,
    next: Next,
) -> Response {
    let claims = if let Some(ticket) = query.ticket {
        let client_ip = extract_client_ip(req.headers(), &addr, state.config.trust_proxy_headers);
        let Some(claims) = redeem_ticket(&ticket, client_ip).await else {
            return json_error("invalid or expired ticket", StatusCode::UNAUTHORIZED);
        };
        // The account may have been deleted or signed out everywhere since issuance
        if let Err(rejection) = check_session(&state, &claims).await {
            return rejection.into_response();
        }
        claims
    } else {
        match authenticate(&state, req.headers()).await {
            Ok(claims) => claims,
            Err(rejection) => return rejection.into_response(),
        }
    };

    if let Err(rejection) = require_approved_device(&state, &claims).await {
        return rejection.into_response();
    }

    req.extensions_mut().insert(claims);
    next.run(req).await
}

/// The party on the other end of a WebSocket.
enum Peer {
    Device {
        id: uuid::Uuid,
        name: String,
    },
    /// A browser session (the web dashboard), which has no device or keys.
    Browser,
}

pub async fn handle_ws_upgrade(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let user_id = claims.user_id;

    if state.hub.user_connection_count(&user_id.to_string()).await >= MAX_CONNECTIONS_PER_USER {
        return json_error(
            "too many concurrent connections",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }

    let peer = match claims.device_id {
        Some(device_id) => {
            let name = state
                .db
                .get_device_by_id(device_id)
                .await
                .map(|d| d.name)
                .unwrap_or_default();

            // Opportunistic fingerprint backfill for devices that predate fingerprinting
            if let Some(fp) = headers
                .get("x-device-fingerprint")
                .and_then(|v| v.to_str().ok())
            {
                let _ = state
                    .db
                    .set_device_fingerprint(device_id, user_id, fp)
                    .await;
            }
            Peer::Device {
                id: device_id,
                name,
            }
        }
        None => Peer::Browser,
    };

    ws.on_upgrade(move |socket| handle_ws_connection(socket, state, user_id, peer))
}

async fn handle_ws_connection(
    socket: WebSocket,
    state: Arc<AppState>,
    user_id: uuid::Uuid,
    peer: Peer,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let uid = user_id.to_string();
    let conn_id = uuid::Uuid::new_v4();
    // Browser tabs register under their own connection ID so several can coexist
    let (hub_id, device_name, device_id) = match &peer {
        Peer::Device { id, name } => (id.to_string(), name.clone(), Some(*id)),
        Peer::Browser => (format!("web-{conn_id}"), String::new(), None),
    };

    let kick = Arc::new(tokio::sync::Notify::new());
    state
        .hub
        .register(Client {
            user_id: uid.clone(),
            device_id: hub_id.clone(),
            device_name,
            conn_id,
            announce: device_id.is_some(),
            tx: tx.clone(),
            kick: kick.clone(),
        })
        .await;
    crate::audit::record_activity(&state, user_id);

    // Prompt a device to rotate the group key when rotation is due
    if device_id.is_some()
        && let Ok(true) = state.db.is_rotation_due(user_id).await
    {
        let rotation_msg = serde_json::to_string(&WsMessage {
            msg_type: MSG_ROTATION_NEEDED.to_string(),
            payload: json!({"reason": "rotation_due"}),
        })
        .unwrap_or_default();
        let _ = tx.send(rotation_msg);
    }

    // Write pump: forward messages from hub to WebSocket, then close the socket once
    // every sender is gone (the hub dropped this client and the read pump finished)
    let mut write_handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(Message::Text(msg.into())).await.is_err() {
                return;
            }
        }
        let _ = ws_tx.send(Message::Close(None)).await;
    });

    // Read pump: handle messages from WebSocket until the client leaves or is kicked
    let mut kicked = false;
    loop {
        let msg = tokio::select! {
            msg = ws_rx.next() => match msg {
                Some(Ok(msg)) => msg,
                _ => break,
            },
            _ = kick.notified() => {
                kicked = true;
                break;
            }
        };
        match msg {
            Message::Text(text) => {
                let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) else {
                    continue;
                };
                match ws_msg.msg_type.as_str() {
                    // Only devices push clipboard entries; browser sessions hold no keys
                    MSG_CLIPBOARD_PUSH => {
                        if let Some(device_id) = device_id
                            && let Ok(payload) =
                                serde_json::from_value::<ClipboardPushPayload>(ws_msg.payload)
                        {
                            handle_clipboard_push(&state, user_id, device_id, payload).await;
                        }
                    }
                    MSG_PING => {
                        let pong = serde_json::to_string(&WsMessage {
                            msg_type: MSG_PONG.to_string(),
                            payload: json!({}),
                        })
                        .unwrap_or_default();
                        let _ = tx.send(pong);
                    }
                    _ => {}
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Cleanup
    if kicked {
        // Let the write pump flush and send a close frame before the socket drops
        drop(tx);
        if tokio::time::timeout(Duration::from_secs(2), &mut write_handle)
            .await
            .is_err()
        {
            write_handle.abort();
        }
    } else {
        state.hub.remove(&uid, &hub_id, conn_id).await;
        write_handle.abort();
    }
}

async fn handle_clipboard_push(
    state: &Arc<AppState>,
    user_id: uuid::Uuid,
    device_id: uuid::Uuid,
    payload: ClipboardPushPayload,
) {
    // Enforce subscription limits
    if let Ok(sub) = state.db.get_user_subscription(user_id).await {
        // Check allowed file types
        if !sub.allowed_file_types.is_empty() {
            let ct = payload.content_type.to_string();
            if !sub.allowed_file_types.contains(&ct) {
                warn!("File type {} not allowed for user {}", ct, user_id);
                return;
            }
        }
        // Check clipboard history limit
        if let Some(max_history) = sub.max_clipboard_history
            && max_history > 0
            && let Ok(count) = state.db.count_user_clipboard_entries(user_id).await
            && count >= max_history as i64
        {
            let _ = state
                .db
                .delete_oldest_clipboard_entries(user_id, count - max_history as i64 + 1)
                .await;
        }
    }

    let content_type = payload.content_type.to_string();
    let metadata = payload.metadata.unwrap_or_default();
    let key_version = payload.key_version;

    match state
        .db
        .create_clipboard_entry(
            user_id,
            device_id,
            &content_type,
            &payload.encrypted_data,
            &metadata,
            key_version,
        )
        .await
    {
        Ok(entry) => {
            let broadcast = WsMessage {
                msg_type: MSG_CLIPBOARD_NEW.to_string(),
                payload: json!({
                    "entry": {
                        "id": entry.id.to_string(),
                        "user_id": entry.user_id.to_string(),
                        "device_id": entry.device_id.to_string(),
                        "device_name": "",
                        "content_type": entry.content_type,
                        "encrypted_data": base64::engine::general_purpose::STANDARD.encode(&entry.encrypted_data),
                        "metadata": entry.metadata.unwrap_or_default(),
                        "created_at": entry.created_at.to_rfc3339(),
                        "key_version": entry.key_version,
                    }
                }),
            };
            state
                .hub
                .broadcast_to_user(&user_id.to_string(), &device_id.to_string(), &broadcast)
                .await;
        }
        Err(e) => {
            warn!("Failed to save clipboard entry: {e}");
        }
    }
}
