use axum::{
    extract::{
        ConnectInfo, Extension, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::Response,
};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use super::middleware::{AuthClaims, extract_client_ip, json_error, json_response};
use crate::AppState;
use crate::ws::Client;
use cpmesh_proto::models::*;

// WS ticket store (short-lived, single-use)
lazy_static::lazy_static! {
    static ref TICKETS: Mutex<HashMap<String, WsTicket>> = Mutex::new(HashMap::new());
}

struct WsTicket {
    user_id: uuid::Uuid,
    device_id: uuid::Uuid,
    expires: std::time::Instant,
    client_ip: IpAddr,
}

pub async fn handle_ws_ticket(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    let device_id = match claims.device_id {
        Some(d) => d,
        None => return json_error("device context required", StatusCode::BAD_REQUEST),
    };

    let client_ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);

    let mut ticket_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ticket_bytes);
    let ticket: String = ticket_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let mut tickets = TICKETS.lock().await;
    tickets.insert(
        ticket.clone(),
        WsTicket {
            user_id: claims.user_id,
            device_id,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(10),
            client_ip,
        },
    );

    json_response(StatusCode::OK, json!({"ticket": ticket}))
}

async fn validate_ticket(ticket: &str, client_ip: IpAddr) -> Option<(uuid::Uuid, uuid::Uuid)> {
    let mut tickets = TICKETS.lock().await;
    let t = tickets.remove(ticket)?;
    if std::time::Instant::now() > t.expires {
        return None;
    }
    if t.client_ip != client_ip {
        warn!(
            "WS ticket IP mismatch: expected {}, got {}",
            t.client_ip, client_ip
        );
        return None;
    }
    Some((t.user_id, t.device_id))
}

#[derive(serde::Deserialize)]
pub struct WsQuery {
    pub ticket: Option<String>,
}

pub async fn handle_ws_upgrade(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let client_ip = extract_client_ip(&headers, &addr, state.config.trust_proxy_headers);

    let (user_id, device_id) = if let Some(ref ticket) = query.ticket {
        match validate_ticket(ticket, client_ip).await {
            Some((uid, did)) => (uid, did),
            None => return json_error("invalid or expired ticket", StatusCode::UNAUTHORIZED),
        }
    } else {
        let did = match claims.device_id {
            Some(d) => d,
            None => return json_error("missing device context", StatusCode::BAD_REQUEST),
        };
        (claims.user_id, did)
    };

    // Enforce per-user connection limit
    if state.hub.user_connection_count(&user_id.to_string()).await >= 10 {
        return json_error(
            "too many concurrent connections",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }

    let device_name = state
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

    let state2 = state.clone();
    ws.on_upgrade(move |socket| {
        handle_ws_connection(socket, state2, user_id, device_id, device_name)
    })
}

async fn handle_ws_connection(
    socket: WebSocket,
    state: Arc<AppState>,
    user_id: uuid::Uuid,
    device_id: uuid::Uuid,
    device_name: String,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let client = Client {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        device_name: device_name.clone(),
        tx,
    };

    state.hub.register(client).await;

    // Check if rotation is due and prompt if so
    if let Ok(true) = state.db.is_rotation_due(user_id).await {
        let rotation_msg = serde_json::to_string(&WsMessage {
            msg_type: MSG_ROTATION_NEEDED.to_string(),
            payload: json!({"reason": "rotation_due"}),
        })
        .unwrap_or_default();

        let clients = state.hub.clients.read().await;
        if let Some(user_clients) = clients.get(&user_id.to_string()) {
            if let Some(client) = user_clients.get(&device_id.to_string()) {
                let _ = client.tx.send(rotation_msg);
            }
        }
    }

    let uid = user_id.to_string();
    let did = device_id.to_string();
    let dname = device_name.clone();

    // Write pump: forward messages from hub to WebSocket
    let _state_write = state.clone();
    let write_handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Read pump: handle messages from WebSocket
    {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Text(text) => {
                    let text_ref: &str = &text;
                    if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(text_ref) {
                        match ws_msg.msg_type.as_str() {
                            MSG_CLIPBOARD_PUSH => {
                                if let Ok(payload) =
                                    serde_json::from_value::<ClipboardPushPayload>(ws_msg.payload)
                                {
                                    handle_clipboard_push(&state, user_id, device_id, payload)
                                        .await;
                                }
                            }
                            MSG_PING => {
                                // Respond with pong (handled via the tx channel)
                                let pong = serde_json::to_string(&WsMessage {
                                    msg_type: MSG_PONG.to_string(),
                                    payload: json!({}),
                                })
                                .unwrap_or_default();

                                // Find and send directly
                                let clients = state.hub.clients.read().await;
                                if let Some(user_clients) = clients.get(&uid) {
                                    if let Some(client) = user_clients.get(&did) {
                                        let _ = client.tx.send(pong);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }

    // Cleanup
    state.hub.remove(&uid, &did, &dname).await;
    write_handle.abort();
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
        if let Some(max_history) = sub.max_clipboard_history {
            if max_history > 0 {
                if let Ok(count) = state.db.count_user_clipboard_entries(user_id).await {
                    if count >= max_history as i64 {
                        let _ = state
                            .db
                            .delete_oldest_clipboard_entries(
                                user_id,
                                count - max_history as i64 + 1,
                            )
                            .await;
                    }
                }
            }
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
