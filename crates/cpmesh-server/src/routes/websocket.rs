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
use crate::ws::{Client, QUEUE_CAPACITY, QueuedMessage};
use cpmesh_proto::models::*;

/// How long a WebSocket ticket can be redeemed after it is issued.
const TICKET_TTL: Duration = Duration::from_secs(10);

/// Most WebSocket connections (devices and browser tabs) one user may hold.
const MAX_CONNECTIONS_PER_USER: usize = 10;
const MAX_WIRE_BYTES: usize =
    (MAX_FILE_BYTES + ENCRYPTION_OVERHEAD).div_ceil(3) * 4 + MAX_METADATA_BYTES * 2 + 4096;
const SEND_DEADLINE: Duration = Duration::from_secs(5);
/// Sender clocks more than a day off are rejected explicitly rather than failing
/// silently on receivers' replay checks.
const CLOCK_SKEW_MS: i64 = 24 * 60 * 60 * 1000;
/// A DER P-256 signature is at most 72 bytes (96 base64 characters).
const MAX_SIGNATURE_CHARS: usize = 128;

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
    if claims.device_id.is_some()
        && headers
            .get("x-cpmesh-protocol")
            .and_then(|value| value.to_str().ok())
            != Some(PROTOCOL_VERSION)
    {
        return json_error(
            &format!("update your client: WebSocket protocol {PROTOCOL_VERSION} is required"),
            StatusCode::UPGRADE_REQUIRED,
        );
    }

    let replacing = if let Some(id) = claims.device_id {
        state
            .hub
            .is_device_online(&user_id.to_string(), &id.to_string())
            .await
    } else {
        false
    };
    if !replacing
        && state.hub.user_connection_count(&user_id.to_string()).await >= MAX_CONNECTIONS_PER_USER
    {
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

    let mut response = ws
        .max_message_size(MAX_WIRE_BYTES)
        .max_frame_size(MAX_WIRE_BYTES)
        .on_upgrade(move |socket| handle_ws_connection(socket, state, claims, peer));
    response.headers_mut().insert(
        "x-cpmesh-protocol",
        axum::http::HeaderValue::from_static(PROTOCOL_VERSION),
    );
    response
}

async fn handle_ws_connection(
    socket: WebSocket,
    state: Arc<AppState>,
    claims: AuthClaims,
    peer: Peer,
) {
    let user_id = claims.user_id;
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Arc<QueuedMessage>>(QUEUE_CAPACITY);

    let uid = user_id.to_string();
    let conn_id = uuid::Uuid::new_v4();
    // Browser tabs register under their own connection ID so several can coexist
    let (hub_id, device_name, device_id) = match &peer {
        Peer::Device { id, name } => (id.to_string(), name.clone(), Some(*id)),
        Peer::Browser => (format!("web-{conn_id}"), String::new(), None),
    };

    let kick = tokio_util::sync::CancellationToken::new();
    let registered = state
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
    if !registered {
        return;
    }
    // Close the authentication/upgrade race with deletion, suspension and revocation.
    if check_session(&state, &claims).await.is_err()
        || require_approved_device(&state, &claims).await.is_err()
    {
        state.hub.disconnect_device(&uid, &hub_id).await;
        return;
    }
    crate::audit::record_activity(&state, user_id).await;

    // Prompt a device to rotate the group key when rotation is due
    if device_id.is_some()
        && let Ok(true) = state.db.is_rotation_due(user_id).await
    {
        let rotation_msg = serde_json::to_string(&WsMessage {
            msg_type: MSG_ROTATION_NEEDED.to_string(),
            payload: json!({"reason": "rotation_due"}),
        })
        .unwrap_or_default();
        let _ = tx.try_send(QueuedMessage::control(rotation_msg));
    }

    // Write pump: forward messages from hub to WebSocket, then close the socket once
    // every sender is gone (the hub dropped this client and the read pump finished)
    let writer_kick = kick.clone();
    let mut write_handle = tokio::spawn(async move {
        let mut in_flight = None;
        loop {
            tokio::select! {
                biased;
                _ = writer_kick.cancelled() => break,
                msg = rx.recv() => {
                    let Some(msg) = msg else { break; };
                    in_flight = Some(msg.clone());
                    tokio::select! {
                        biased;
                        _ = writer_kick.cancelled() => break,
                        result = tokio::time::timeout(SEND_DEADLINE, ws_tx.send(Message::Text(msg.text.clone()))) => {
                            if !matches!(result, Ok(Ok(()))) {
                                writer_kick.cancel();
                                break;
                            }
                            in_flight = None;
                        }
                    }
                }
            }
        }
        let _ =
            tokio::time::timeout(Duration::from_secs(1), ws_tx.send(Message::Close(None))).await;
        // A partial frame can retain its bytes while closing; account for them
        // until the sink, not merely its send future, has been dropped.
        drop(ws_tx);
        drop(in_flight);
    });

    // Read pump: handle messages from WebSocket until the client leaves or is kicked
    let mut kicked = false;
    loop {
        let msg = tokio::select! {
            msg = ws_rx.next() => match msg {
                Some(Ok(msg)) => msg,
                _ => break,
            },
            _ = kick.cancelled() => {
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
                        let request_id = ws_msg
                            .payload
                            .get("request_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .chars()
                            .take(64)
                            .collect::<String>();
                        let ack = if let Err(code) = validate_push_wire(&ws_msg.payload) {
                            rejected(&request_id, code)
                        } else if let Some(device_id) = device_id {
                            match serde_json::from_value::<ClipboardPushPayload>(ws_msg.payload) {
                                Ok(payload) => {
                                    handle_clipboard_push(&state, &claims, device_id, payload).await
                                }
                                Err(_) => rejected(&request_id, "invalid_payload"),
                            }
                        } else {
                            rejected(&request_id, "device_required")
                        };
                        let response = WsMessage {
                            msg_type: MSG_CLIPBOARD_ACK.into(),
                            payload: json!(ack),
                        };
                        if tx
                            .try_send(QueuedMessage::control(
                                serde_json::to_string(&response).expect("serializable ack"),
                            ))
                            .is_err()
                        {
                            kick.cancel();
                        }
                    }
                    MSG_PING => {
                        let pong = serde_json::to_string(&WsMessage {
                            msg_type: MSG_PONG.to_string(),
                            payload: json!({}),
                        })
                        .unwrap_or_default();
                        if tx.try_send(QueuedMessage::control(pong)).is_err() {
                            kick.cancel();
                        }
                    }
                    _ => {}
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Cleanup
    state.hub.remove(&uid, &hub_id, conn_id).await;
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
        write_handle.abort();
    }
}

async fn handle_clipboard_push(
    state: &Arc<AppState>,
    claims: &AuthClaims,
    device_id: uuid::Uuid,
    payload: ClipboardPushPayload,
) -> ClipboardAck {
    let user_id = claims.user_id;
    let request_id = match payload.request_id.as_deref() {
        Some(id) => match uuid::Uuid::parse_str(id) {
            Ok(id) => id,
            Err(_) => return rejected(id, "invalid_request_id"),
        },
        None => return rejected("", "request_id_required"),
    };
    let id = request_id.to_string();
    if payload.encrypted_data.len()
        > content_size_limit(&payload.content_type) + ENCRYPTION_OVERHEAD
        || payload.encrypted_data.len() < ENCRYPTION_OVERHEAD
    {
        return rejected(&id, "payload_size");
    }
    // Protocol v3: the entry is signed by the sending device's identity key over
    // its context and ciphertexts. Receivers verify this themselves; the relay
    // checks it too so a stolen session token alone cannot inject entries.
    let (Some(sent_at), Some(signature)) = (payload.sent_at, payload.sender_signature.as_deref())
    else {
        return rejected(&id, "signature_required");
    };
    let now = chrono::Utc::now().timestamp_millis();
    if sent_at <= 0 || (now - sent_at).abs() > CLOCK_SKEW_MS {
        return rejected(&id, "clock_skew");
    }
    let metadata_bytes = match payload.metadata.as_deref() {
        Some(encoded) if !encoded.is_empty() => {
            match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(bytes) => bytes,
                Err(_) => return rejected(&id, "invalid_payload"),
            }
        }
        _ => Vec::new(),
    };
    let sender_key = match state.db.get_device_by_id(device_id).await {
        Ok(device) => device.public_key,
        Err(e) => {
            warn!(%user_id, "Failed to load sender identity: {e}");
            return rejected(&id, "temporarily_unavailable");
        }
    };
    let transcript = clipboard_signature_transcript(
        payload.key_version,
        &payload.content_type,
        &device_id.to_string(),
        &id,
        sent_at,
        &payload.encrypted_data,
        &metadata_bytes,
    );
    if !super::devices::verify_device_signature(&sender_key, &transcript, signature) {
        return rejected(&id, "invalid_signature");
    }
    let sub = match state.db.get_user_subscription(user_id).await {
        Ok(sub) => sub,
        Err(e) => {
            warn!(%user_id, "Failed to read clipboard limits: {e}");
            return rejected(&id, "temporarily_unavailable");
        }
    };
    if !sub.allowed_file_types.is_empty()
        && !sub
            .allowed_file_types
            .contains(&payload.content_type.to_string())
    {
        return rejected(&id, "content_type_not_allowed");
    }

    match state
        .db
        .persist_clipboard_push(
            user_id,
            device_id,
            request_id,
            &payload,
            sub.max_clipboard_history,
            claims.session_started_at(),
        )
        .await
    {
        Ok(crate::db::ClipboardWrite::Accepted { entry, inserted }) => {
            let ack = ClipboardAck::Accepted {
                request_id: id,
                entry_id: entry.id.to_string(),
                created_at: entry.created_at,
            };
            if !inserted {
                return ack;
            }
            let broadcast = WsMessage {
                msg_type: MSG_CLIPBOARD_NEW.to_string(),
                payload: json!({
                    "entry": {
                        "id": entry.id.to_string(),
                        "user_id": entry.user_id.to_string(),
                        "device_id": entry.device_id.to_string(),
                        "device_name": "",
                        "content_type": entry.content_type,
                        "encrypted_size": entry.encrypted_data.len(),
                        "encrypted_data": base64::engine::general_purpose::STANDARD.encode(&entry.encrypted_data),
                        "metadata": entry.metadata.unwrap_or_default(),
                        "created_at": entry.created_at.to_rfc3339(),
                        "key_version": entry.key_version,
                        "request_id": entry.request_id.map(|id| id.to_string()),
                        "sent_at": entry.sent_at,
                        "sender_signature": entry.sender_signature.map(|sig| base64::engine::general_purpose::STANDARD.encode(sig)),
                    }
                }),
            };
            state
                .hub
                .broadcast_to_user(&user_id.to_string(), &device_id.to_string(), &broadcast)
                .await;
            ack
        }
        Ok(crate::db::ClipboardWrite::Replay {
            entry_id,
            created_at,
        }) => ClipboardAck::Accepted {
            request_id: id,
            entry_id: entry_id.to_string(),
            created_at,
        },
        Ok(crate::db::ClipboardWrite::Rejected(code)) => rejected(&id, code),
        Err(e) => {
            warn!("Failed to save clipboard entry: {e}");
            rejected(&id, "temporarily_unavailable")
        }
    }
}

fn rejected(request_id: &str, code: &str) -> ClipboardAck {
    ClipboardAck::Rejected {
        request_id: request_id.to_string(),
        code: code.to_string(),
        message: if code == "temporarily_unavailable" {
            "Persistence could not be confirmed; retry the same request_id".into()
        } else {
            format!("Clipboard was not accepted: {code}")
        },
    }
}

fn validate_push_wire(value: &serde_json::Value) -> Result<(), &'static str> {
    let Some(request_id) = value.get("request_id").and_then(|value| value.as_str()) else {
        return Err("request_id_required");
    };
    if uuid::Uuid::parse_str(request_id).is_err() {
        return Err("invalid_request_id");
    }
    let content_type = match value.get("content_type").and_then(|v| v.as_str()) {
        Some("text") => ContentType::Text,
        Some("image") => ContentType::Image,
        Some("file") => ContentType::File,
        _ => return Err("invalid_content_type"),
    };
    let limit = (content_size_limit(&content_type) + ENCRYPTION_OVERHEAD).div_ceil(3) * 4;
    if value
        .get("encrypted_data")
        .and_then(|v| v.as_str())
        .is_none_or(|s| s.len() > limit)
        || value
            .get("metadata")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.len() > MAX_METADATA_BYTES)
        || value
            .get("sender_signature")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.len() > MAX_SIGNATURE_CHARS)
    {
        return Err("payload_size");
    }
    Ok(())
}

#[cfg(test)]
mod payload_tests {
    use super::*;

    #[test]
    fn enforces_content_and_metadata_limits_before_base64_decoding() {
        let limit = (content_size_limit(&ContentType::Text) + ENCRYPTION_OVERHEAD).div_ceil(3) * 4;
        let mut payload = json!({"request_id": uuid::Uuid::new_v4(), "content_type": "text", "encrypted_data": "A".repeat(limit)});
        assert!(validate_push_wire(&payload).is_ok());
        payload["encrypted_data"] = json!("A".repeat(limit + 1));
        assert_eq!(validate_push_wire(&payload), Err("payload_size"));
        payload["encrypted_data"] = json!("AA==");
        payload["metadata"] = json!("A".repeat(MAX_METADATA_BYTES + 1));
        assert_eq!(validate_push_wire(&payload), Err("payload_size"));
        payload["request_id"] = json!("x".repeat(1000));
        assert_eq!(validate_push_wire(&payload), Err("invalid_request_id"));
        assert_eq!(content_size_limit(&ContentType::Image), 10 * 1024 * 1024);
        assert_eq!(content_size_limit(&ContentType::File), 25 * 1024 * 1024);
    }
}
