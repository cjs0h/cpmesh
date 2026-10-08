use futures_util::{SinkExt, StreamExt};
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::proto::models::*;

const INITIAL_BACKOFF_MS: u64 = 1000;
const MAX_BACKOFF_MS: u64 = 60000;
const BACKOFF_FACTOR: f64 = 2.0;
const HEARTBEAT_INTERVAL_SECS: u64 = 30;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
type WsSource = futures_util::stream::SplitStream<WsStream>;
type WsHandshakeRequest = tokio_tungstenite::tungstenite::http::Request<()>;

/// Builds the WebSocket handshake request for `server_url`.
///
/// The HTTP(S) server URL is mapped to ws(s)://host/ws and the access token is sent
/// in the `Authorization` header rather than the URL, so it cannot leak into logs.
fn build_ws_request(
    server_url: &str,
    access_token: &str,
    fingerprint: Option<&str>,
) -> Result<WsHandshakeRequest, Box<dyn std::error::Error + Send + Sync>> {
    let mut url = Url::parse(server_url)?;
    let new_scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(new_scheme)
        .map_err(|_| format!("failed to set URL scheme to {new_scheme}"))?;
    url.set_path("/ws");
    url.set_query(None);
    url.set_fragment(None);

    let mut builder = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(url.as_str())
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Host", url.host_str().unwrap_or("localhost"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        );

    // Send fingerprint for opportunistic backfill of legacy devices
    if let Some(fp) = fingerprint {
        builder = builder.header("X-Device-Fingerprint", fp);
    }

    Ok(builder.body(())?)
}

/// Next reconnect delay: doubles each attempt, capped at [`MAX_BACKOFF_MS`].
fn next_backoff_ms(current_ms: u64) -> u64 {
    (((current_ms as f64) * BACKOFF_FACTOR) as u64).min(MAX_BACKOFF_MS)
}

/// Events emitted by the WebSocket connection.
#[derive(Debug, Clone)]
pub enum WsEvent {
    ClipboardNew(ClipboardNewPayload),
    DeviceStatus(DeviceStatusPayload),
    GroupKeyUpdated,
    Connected,
    Disconnected,
    Error(String),
}

/// Manages the WebSocket connection to the cpmesh server.
pub struct WsConnection {
    server_url: String,
    access_token: String,
    fingerprint: Option<String>,
    event_tx: mpsc::UnboundedSender<WsEvent>,
    outgoing_tx: mpsc::UnboundedSender<WsMessage>,
    outgoing_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<WsMessage>>>>,
    shutdown: Arc<Notify>,
}

impl WsConnection {
    pub fn new(
        server_url: &str,
        access_token: &str,
        fingerprint: Option<String>,
    ) -> (Self, mpsc::UnboundedReceiver<WsEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();

        let conn = WsConnection {
            server_url: server_url.to_string(),
            access_token: access_token.to_string(),
            fingerprint,
            event_tx,
            outgoing_tx,
            outgoing_rx: Arc::new(Mutex::new(Some(outgoing_rx))),
            shutdown: Arc::new(Notify::new()),
        };

        (conn, event_rx)
    }

    /// Sends a clipboard push message.
    pub fn send_clipboard(&self, payload: ClipboardPushPayload) -> Result<(), String> {
        let payload_json = serde_json::to_value(&payload).map_err(|e| format!("serialize: {e}"))?;
        let msg = WsMessage {
            msg_type: MSG_CLIPBOARD_PUSH.to_string(),
            payload: payload_json,
        };
        self.outgoing_tx
            .send(msg)
            .map_err(|_| "connection closed".to_string())
    }

    /// Sends a ping message.
    fn send_ping(tx: &mpsc::UnboundedSender<WsMessage>) {
        let msg = WsMessage {
            msg_type: MSG_PING.to_string(),
            payload: serde_json::Value::Null,
        };
        let _ = tx.send(msg);
    }

    /// Starts the connection with automatic reconnect.
    pub async fn connect_with_reconnect(self: Arc<Self>) {
        let mut outgoing_rx = self.outgoing_rx.lock().await.take();

        let mut backoff_ms = INITIAL_BACKOFF_MS;

        loop {
            match self.dial().await {
                Ok((mut write, mut read)) => {
                    backoff_ms = INITIAL_BACKOFF_MS;
                    let _ = self.event_tx.send(WsEvent::Connected);
                    info!("WebSocket connected");

                    // Heartbeat task
                    let outgoing_tx = self.outgoing_tx.clone();
                    let shutdown = self.shutdown.clone();
                    let heartbeat = tokio::spawn(async move {
                        let mut interval =
                            tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
                        loop {
                            tokio::select! {
                                _ = interval.tick() => {
                                    Self::send_ping(&outgoing_tx);
                                }
                                _ = shutdown.notified() => break,
                            }
                        }
                    });

                    // Read/write loop
                    let disconnected = loop {
                        tokio::select! {
                            // Incoming messages from server
                            msg = read.next() => {
                                match msg {
                                    Some(Ok(Message::Text(text))) => {
                                        self.handle_message(&text);
                                    }
                                    Some(Ok(Message::Close(_))) | None => {
                                        break false;
                                    }
                                    Some(Err(e)) => {
                                        warn!("WebSocket read error: {e}");
                                        break false;
                                    }
                                    _ => {} // Binary, Ping, Pong — ignore
                                }
                            }
                            // Outgoing messages to server
                            out = async {
                                if let Some(rx) = &mut outgoing_rx {
                                    rx.recv().await
                                } else {
                                    std::future::pending().await
                                }
                            } => {
                                if let Some(msg) = out {
                                    let json = serde_json::to_string(&msg).unwrap_or_default();
                                    if let Err(e) = write.send(Message::Text(json.into())).await {
                                        warn!("WebSocket write error: {e}");
                                        break false;
                                    }
                                }
                            }
                            // Shutdown signal
                            _ = self.shutdown.notified() => {
                                let _ = write.close().await;
                                break true;
                            }
                        }
                    };

                    heartbeat.abort();
                    let _ = self.event_tx.send(WsEvent::Disconnected);
                    info!("WebSocket disconnected");

                    if disconnected {
                        return; // intentional shutdown
                    }
                }
                Err(e) => {
                    warn!("WebSocket connect failed: {e}");
                    let _ = self.event_tx.send(WsEvent::Error(e.to_string()));
                }
            }

            // Backoff before reconnect
            info!("Reconnecting in {backoff_ms}ms...");
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                _ = self.shutdown.notified() => return,
            }
            backoff_ms = next_backoff_ms(backoff_ms);
        }
    }

    /// Shut down the connection permanently.
    pub fn close(&self) {
        self.shutdown.notify_waiters();
    }

    async fn dial(&self) -> Result<(WsSink, WsSource), Box<dyn std::error::Error + Send + Sync>> {
        let request = build_ws_request(
            &self.server_url,
            &self.access_token,
            self.fingerprint.as_deref(),
        )?;

        let (ws_stream, _) = tokio_tungstenite::connect_async(request).await?;
        Ok(ws_stream.split())
    }

    fn handle_message(&self, text: &str) {
        let msg: WsMessage = match serde_json::from_str(text) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to parse WS message: {e}");
                return;
            }
        };

        match msg.msg_type.as_str() {
            MSG_CLIPBOARD_NEW => {
                if let Ok(payload) = serde_json::from_value::<ClipboardNewPayload>(msg.payload) {
                    let _ = self.event_tx.send(WsEvent::ClipboardNew(payload));
                }
            }
            MSG_DEVICE_STATUS => {
                if let Ok(payload) = serde_json::from_value::<DeviceStatusPayload>(msg.payload) {
                    let _ = self.event_tx.send(WsEvent::DeviceStatus(payload));
                }
            }
            MSG_PONG => {} // heartbeat response, ignore
            MSG_GROUP_KEY_UPDATED => {
                info!("Group key updated by another device");
                let _ = self.event_tx.send(WsEvent::GroupKeyUpdated);
            }
            MSG_ERROR => {
                if let Ok(payload) = serde_json::from_value::<ErrorPayload>(msg.payload) {
                    let _ = self.event_tx.send(WsEvent::Error(format!(
                        "{}: {}",
                        payload.code, payload.message
                    )));
                }
            }
            _ => {
                warn!("Unknown WS message type: {}", msg.msg_type);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::error::TryRecvError;

    fn conn() -> (WsConnection, mpsc::UnboundedReceiver<WsEvent>) {
        WsConnection::new("https://cpmesh.example", "tok", None)
    }

    #[test]
    fn build_ws_request_maps_https_to_wss_and_sets_headers() {
        let req =
            build_ws_request("https://cpmesh.example:8443/", "secret-token", Some("fp-1")).unwrap();
        assert_eq!(req.uri().to_string(), "wss://cpmesh.example:8443/ws");
        let headers = req.headers();
        assert_eq!(headers["authorization"], "Bearer secret-token");
        assert_eq!(headers["host"], "cpmesh.example");
        assert_eq!(headers["upgrade"], "websocket");
        assert_eq!(headers["connection"], "Upgrade");
        assert_eq!(headers["sec-websocket-version"], "13");
        assert!(!headers["sec-websocket-key"].is_empty());
        assert_eq!(headers["x-device-fingerprint"], "fp-1");
    }

    #[test]
    fn build_ws_request_maps_http_to_ws_and_omits_fingerprint() {
        let req = build_ws_request("http://localhost:8080/some/base?x=1#frag", "t", None).unwrap();
        assert_eq!(req.uri().to_string(), "ws://localhost:8080/ws");
        assert!(req.headers().get("x-device-fingerprint").is_none());
    }

    #[test]
    fn build_ws_request_rejects_invalid_url() {
        assert!(build_ws_request("not a url", "t", None).is_err());
    }

    #[test]
    fn build_ws_request_never_puts_token_in_url() {
        let req = build_ws_request("https://cpmesh.example", "super-secret", None).unwrap();
        assert!(!req.uri().to_string().contains("super-secret"));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(next_backoff_ms(INITIAL_BACKOFF_MS), 2000);
        assert_eq!(next_backoff_ms(2000), 4000);
        assert_eq!(next_backoff_ms(40_000), MAX_BACKOFF_MS);
        assert_eq!(next_backoff_ms(MAX_BACKOFF_MS), MAX_BACKOFF_MS);
    }

    #[test]
    fn handle_message_dispatches_clipboard_new() {
        let (c, mut rx) = conn();
        let text = serde_json::json!({
            "type": MSG_CLIPBOARD_NEW,
            "payload": {
                "entry": {
                    "id": "e1", "user_id": "u1", "device_id": "d1", "device_name": "Laptop",
                    "content_type": "text", "encrypted_data": "AAEC", "metadata": "",
                    "created_at": "2026-01-01T00:00:00Z", "key_version": 2
                }
            }
        })
        .to_string();
        c.handle_message(&text);
        match rx.try_recv().unwrap() {
            WsEvent::ClipboardNew(p) => {
                assert_eq!(p.entry.id, "e1");
                assert_eq!(p.entry.device_name, "Laptop");
                assert_eq!(p.entry.content_type, ContentType::Text);
                assert_eq!(p.entry.encrypted_data, vec![0, 1, 2]);
                assert_eq!(p.entry.key_version, 2);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn handle_message_dispatches_device_status() {
        let (c, mut rx) = conn();
        c.handle_message(
            r#"{"type":"device_status","payload":{"device_id":"d2","device_name":"Phone","online":true}}"#,
        );
        match rx.try_recv().unwrap() {
            WsEvent::DeviceStatus(p) => {
                assert_eq!(p.device_id, "d2");
                assert_eq!(p.device_name, "Phone");
                assert!(p.online);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn handle_message_dispatches_group_key_updated_and_error() {
        let (c, mut rx) = conn();
        c.handle_message(r#"{"type":"group_key_updated"}"#);
        assert!(matches!(rx.try_recv().unwrap(), WsEvent::GroupKeyUpdated));

        c.handle_message(r#"{"type":"error","payload":{"code":"quota","message":"too big"}}"#);
        match rx.try_recv().unwrap() {
            WsEvent::Error(msg) => assert_eq!(msg, "quota: too big"),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn handle_message_ignores_pong_unknown_and_malformed() {
        let (c, mut rx) = conn();
        c.handle_message(r#"{"type":"pong","payload":{}}"#);
        c.handle_message(r#"{"type":"something_new","payload":{"a":1}}"#);
        c.handle_message("this is not json");
        // Payload that does not match the expected shape is dropped too
        c.handle_message(r#"{"type":"device_status","payload":{"nope":true}}"#);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn send_clipboard_enqueues_outgoing_message() {
        let (c, _rx) = conn();
        c.send_clipboard(ClipboardPushPayload {
            content_type: ContentType::Image,
            encrypted_data: vec![9, 8, 7],
            metadata: Some("bWV0YQ==".into()),
            key_version: 3,
        })
        .unwrap();

        let mut outgoing = c.outgoing_rx.lock().await.take().unwrap();
        let msg = outgoing.try_recv().unwrap();
        assert_eq!(msg.msg_type, MSG_CLIPBOARD_PUSH);
        assert_eq!(msg.payload["content_type"], "image");
        assert_eq!(msg.payload["encrypted_data"], "CQgH");
        assert_eq!(msg.payload["metadata"], "bWV0YQ==");
        assert_eq!(msg.payload["key_version"], 3);
    }

    #[tokio::test]
    async fn send_ping_enqueues_ping() {
        let (c, _rx) = conn();
        WsConnection::send_ping(&c.outgoing_tx);
        let mut outgoing = c.outgoing_rx.lock().await.take().unwrap();
        let msg = outgoing.try_recv().unwrap();
        assert_eq!(msg.msg_type, MSG_PING);
        assert!(msg.payload.is_null());
    }

    #[tokio::test]
    async fn send_clipboard_fails_after_receiver_dropped() {
        let (c, _rx) = conn();
        drop(c.outgoing_rx.lock().await.take());
        let err = c
            .send_clipboard(ClipboardPushPayload {
                content_type: ContentType::Text,
                encrypted_data: vec![],
                metadata: None,
                key_version: 1,
            })
            .unwrap_err();
        assert_eq!(err, "connection closed");
    }
}
