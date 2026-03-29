use futures_util::{SinkExt, StreamExt};
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::proto::models::*;

const INITIAL_BACKOFF_MS: u64 = 1000;
const MAX_BACKOFF_MS: u64 = 60000;
const BACKOFF_FACTOR: f64 = 2.0;
const HEARTBEAT_INTERVAL_SECS: u64 = 30;

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
        let payload_json =
            serde_json::to_value(&payload).map_err(|e| format!("serialize: {e}"))?;
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
            backoff_ms = ((backoff_ms as f64) * BACKOFF_FACTOR) as u64;
            if backoff_ms > MAX_BACKOFF_MS {
                backoff_ms = MAX_BACKOFF_MS;
            }
        }
    }

    /// Shut down the connection permanently.
    pub fn close(&self) {
        self.shutdown.notify_waiters();
    }

    async fn dial(
        &self,
    ) -> Result<
        (
            futures_util::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
                Message,
            >,
            futures_util::stream::SplitStream<
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
            >,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let mut url = Url::parse(&self.server_url)?;
        let new_scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(new_scheme)
            .map_err(|_| format!("failed to set URL scheme to {new_scheme}"))?;
        url.set_path("/ws");
        // Use Authorization header instead of URL query to prevent token leakage in logs
        let mut builder = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(url.as_str())
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Host", url.host_str().unwrap_or("localhost"))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", tokio_tungstenite::tungstenite::handshake::client::generate_key());

        // Send fingerprint for opportunistic backfill of legacy devices
        if let Some(ref fp) = self.fingerprint {
            builder = builder.header("X-Device-Fingerprint", fp.as_str());
        }

        let request = builder.body(())?;

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
                    let _ = self
                        .event_tx
                        .send(WsEvent::Error(format!("{}: {}", payload.code, payload.message)));
                }
            }
            _ => {
                warn!("Unknown WS message type: {}", msg.msg_type);
            }
        }
    }
}
