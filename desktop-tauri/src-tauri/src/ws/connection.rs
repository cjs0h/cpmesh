use futures_util::{SinkExt, StreamExt};
use log::{error, info, warn};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
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

/// Future returned by a [`TokenProvider`].
pub type TokenFuture = Pin<Box<dyn Future<Output = Option<String>> + Send>>;

/// Supplies the access token for each connection attempt. It is called with `true`
/// after the server rejected the previous token, to force a refresh, and returns
/// `None` once the session has ended.
pub type TokenProvider = Arc<dyn Fn(bool) -> TokenFuture + Send + Sync>;
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
        .header("X-Cpmesh-Protocol", PROTOCOL_VERSION)
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
    RotationNeeded,
    Connected,
    Disconnected,
    /// The session can no longer be refreshed; the connection has stopped.
    SessionExpired,
    Error(String),
}

/// Manages the WebSocket connection to the cpmesh server.
pub struct WsConnection {
    server_url: String,
    token_provider: TokenProvider,
    fingerprint: Option<String>,
    event_tx: mpsc::Sender<WsEvent>,
    outgoing_tx: mpsc::Sender<WsMessage>,
    outgoing_rx: Arc<Mutex<Option<mpsc::Receiver<WsMessage>>>>,
    shutdown: CancellationToken,
    pending: std::sync::Mutex<std::collections::HashMap<String, oneshot::Sender<ClipboardAck>>>,
}

#[derive(Debug)]
pub struct ClipboardReceipt {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl WsConnection {
    pub fn new(
        server_url: &str,
        token_provider: TokenProvider,
        fingerprint: Option<String>,
    ) -> (Self, mpsc::Receiver<WsEvent>) {
        let (event_tx, event_rx) = mpsc::channel(8);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(4);

        let conn = WsConnection {
            server_url: server_url.to_string(),
            token_provider,
            fingerprint,
            event_tx,
            outgoing_tx,
            outgoing_rx: Arc::new(Mutex::new(Some(outgoing_rx))),
            shutdown: CancellationToken::new(),
            pending: std::sync::Mutex::new(std::collections::HashMap::new()),
        };

        (conn, event_rx)
    }

    /// Sends a clipboard push message.
    pub async fn send_clipboard(
        &self,
        mut payload: ClipboardPushPayload,
    ) -> Result<ClipboardReceipt, String> {
        if self.is_closed() {
            return Err("connection closed".into());
        }
        let id = payload
            .request_id
            .get_or_insert_with(|| uuid::Uuid::new_v4().to_string())
            .clone();
        let payload_json = serde_json::to_value(&payload).map_err(|e| format!("serialize: {e}"))?;
        let msg = WsMessage {
            msg_type: MSG_CLIPBOARD_PUSH.to_string(),
            payload: payload_json,
        };
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self
                .pending
                .lock()
                .expect("pending clipboard lock poisoned");
            if pending.len() >= 32 || pending.contains_key(&id) {
                return Err("clipboard request already pending or queue full".into());
            }
            pending.insert(id.clone(), tx);
        }
        let sent = self.outgoing_tx.try_send(msg);
        let result = if sent.is_err() {
            Err("clipboard queue full or connection closed".into())
        } else {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => Err("connection closed before persistence acknowledgement".into()),
                ack = tokio::time::timeout(Duration::from_secs(10), rx) => match ack {
                    Ok(Ok(ClipboardAck::Accepted { entry_id, created_at, .. })) => Ok(ClipboardReceipt { id: entry_id, created_at }),
                    Ok(Ok(ClipboardAck::Rejected { code, message, .. })) => Err(format!("{code}: {message}")),
                    _ => Err("persistence acknowledgement timed out; delivery is unknown".into()),
                }
            }
        };
        self.pending
            .lock()
            .expect("pending clipboard lock poisoned")
            .remove(&id);
        result
    }

    /// Sends a ping message.
    fn send_ping(tx: &mpsc::Sender<WsMessage>) {
        let msg = WsMessage {
            msg_type: MSG_PING.to_string(),
            payload: serde_json::Value::Null,
        };
        let _ = tx.try_send(msg);
    }

    /// Starts the connection with automatic reconnect.
    pub async fn connect_with_reconnect(self: Arc<Self>) {
        let mut outgoing_rx = self.outgoing_rx.lock().await.take();
        if outgoing_rx.is_none() {
            return;
        }

        let mut backoff_ms = INITIAL_BACKOFF_MS;
        let mut force_refresh = false;

        loop {
            let token = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return,
                token = (self.token_provider)(force_refresh) => token,
            };
            let Some(access_token) = token else {
                warn!("Session has ended; not reconnecting");
                self.emit(WsEvent::SessionExpired);
                return;
            };
            force_refresh = false;

            let dialed = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return,
                result = self.dial(&access_token) => result,
            };
            match dialed {
                Ok((mut write, mut read)) => {
                    if self.is_closed() {
                        return;
                    }
                    backoff_ms = INITIAL_BACKOFF_MS;
                    self.emit(WsEvent::Connected);
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
                                _ = shutdown.cancelled() => break,
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
                                    if !matches!(tokio::time::timeout(Duration::from_secs(5), write.send(Message::Text(json.into()))).await, Ok(Ok(()))) {
                                        warn!("WebSocket write failed or timed out");
                                        break false;
                                    }
                                }
                            }
                            // Shutdown signal
                            _ = self.shutdown.cancelled() => {
                                let _ = tokio::time::timeout(Duration::from_secs(1), write.close()).await;
                                break true;
                            }
                        }
                    };

                    heartbeat.abort();
                    self.emit(WsEvent::Disconnected);
                    info!("WebSocket disconnected");

                    if disconnected {
                        return; // intentional shutdown
                    }
                }
                Err(e) => {
                    // An expired or revoked token: refresh before the next attempt
                    force_refresh = is_unauthorized(e.as_ref());
                    warn!("WebSocket connect failed: {e}");
                    self.emit(WsEvent::Error(e.to_string()));
                }
            }

            // Backoff before reconnect
            info!("Reconnecting in {backoff_ms}ms...");
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                _ = self.shutdown.cancelled() => return,
            }
            backoff_ms = next_backoff_ms(backoff_ms);
        }
    }

    /// Shut down the connection permanently.
    pub fn close(&self) {
        self.shutdown.cancel();
        self.pending
            .lock()
            .expect("pending clipboard lock poisoned")
            .clear();
    }

    pub fn is_closed(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    fn emit(&self, event: WsEvent) {
        if let Err(error) = self.event_tx.try_send(event) {
            if matches!(error, mpsc::error::TrySendError::Full(_)) {
                error!("Clipboard event queue full; reconnect to resume from history");
            }
            self.close();
        }
    }

    async fn dial(
        &self,
        access_token: &str,
    ) -> Result<(WsSink, WsSource), Box<dyn std::error::Error + Send + Sync>> {
        let request =
            build_ws_request(&self.server_url, access_token, self.fingerprint.as_deref())?;

        let (mut ws_stream, response) = tokio_tungstenite::connect_async(request).await?;
        if response
            .headers()
            .get("x-cpmesh-protocol")
            .and_then(|value| value.to_str().ok())
            != Some(PROTOCOL_VERSION)
        {
            let _ = tokio::time::timeout(Duration::from_secs(1), ws_stream.close(None)).await;
            return Err(format!(
                "Server upgrade required: WebSocket protocol {PROTOCOL_VERSION} was not confirmed"
            )
            .into());
        }
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
                    self.emit(WsEvent::ClipboardNew(payload));
                }
            }
            MSG_DEVICE_STATUS => {
                if let Ok(payload) = serde_json::from_value::<DeviceStatusPayload>(msg.payload) {
                    self.emit(WsEvent::DeviceStatus(payload));
                }
            }
            MSG_PONG => {} // heartbeat response, ignore
            MSG_GROUP_KEY_UPDATED => {
                info!("Group key updated by another device");
                self.emit(WsEvent::GroupKeyUpdated);
            }
            MSG_ROTATION_NEEDED => {
                self.emit(WsEvent::RotationNeeded);
            }
            MSG_CLIPBOARD_ACK => match serde_json::from_value::<ClipboardAck>(msg.payload) {
                Ok(ack) => {
                    if let Some(waiter) = self
                        .pending
                        .lock()
                        .expect("pending clipboard lock poisoned")
                        .remove(ack.request_id())
                    {
                        let _ = waiter.send(ack);
                    }
                }
                Err(e) => error!("Invalid clipboard acknowledgement: {e}"),
            },
            MSG_ERROR => {
                if let Ok(payload) = serde_json::from_value::<ErrorPayload>(msg.payload) {
                    self.emit(WsEvent::Error(format!(
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

/// Whether a failed handshake was refused for authentication (HTTP 401).
fn is_unauthorized(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    use tokio_tungstenite::tungstenite::{Error, http::StatusCode};
    matches!(
        error.downcast_ref::<Error>(),
        Some(Error::Http(response)) if response.status() == StatusCode::UNAUTHORIZED
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::error::TryRecvError;

    fn fixed_token(token: &'static str) -> TokenProvider {
        Arc::new(move |_| Box::pin(async move { Some(token.to_string()) }))
    }

    fn conn() -> (WsConnection, mpsc::Receiver<WsEvent>) {
        WsConnection::new("https://cpmesh.example", fixed_token("tok"), None)
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
    async fn clipboard_success_requires_correlated_persistence_ack() {
        let (c, _rx) = conn();
        let id = uuid::Uuid::new_v4().to_string();
        let send = c.send_clipboard(ClipboardPushPayload {
            request_id: Some(id.clone()),
            content_type: ContentType::Image,
            encrypted_data: vec![9, 8, 7],
            metadata: Some("bWV0YQ==".into()),
            key_version: 3,
            sent_at: None,
            sender_signature: None,
        });
        tokio::pin!(send);

        let mut outgoing = c.outgoing_rx.lock().await.take().unwrap();
        let msg = tokio::select! {
            _ = &mut send => panic!("write was mistaken for persistence"),
            msg = outgoing.recv() => msg.unwrap(),
        };
        assert_eq!(msg.msg_type, MSG_CLIPBOARD_PUSH);
        assert_eq!(msg.payload["content_type"], "image");
        assert_eq!(msg.payload["encrypted_data"], "CQgH");
        assert_eq!(msg.payload["metadata"], "bWV0YQ==");
        assert_eq!(msg.payload["key_version"], 3);
        let canonical_id = uuid::Uuid::new_v4().to_string();
        c.handle_message(&serde_json::json!({
            "type": MSG_CLIPBOARD_ACK,
            "payload": {"status":"accepted", "request_id":id, "entry_id":canonical_id, "created_at":"2026-01-01T00:00:00Z"},
        }).to_string());
        assert_eq!(send.await.unwrap().id, canonical_id);
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
                request_id: None,
                content_type: ContentType::Text,
                encrypted_data: vec![],
                metadata: None,
                key_version: 1,
                sent_at: None,
                sender_signature: None,
            })
            .await
            .unwrap_err();
        assert!(err.contains("connection closed"));
    }

    #[tokio::test]
    // The handshake callback's signature is dictated by tungstenite
    #[allow(clippy::result_large_err)]
    async fn rejected_token_is_refreshed_before_reconnecting() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
        use tokio_tungstenite::tungstenite::http;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let seen_tx = seen_tx.clone();
                tokio::spawn(async move {
                    let check = move |req: &Request,
                                      mut resp: Response|
                          -> Result<Response, ErrorResponse> {
                        let auth = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let accepted = auth == "Bearer fresh";
                        let _ = seen_tx.send(auth);
                        resp.headers_mut()
                            .insert("x-cpmesh-protocol", PROTOCOL_VERSION.parse().unwrap());
                        if accepted {
                            Ok(resp)
                        } else {
                            Err(http::Response::builder()
                                .status(http::StatusCode::UNAUTHORIZED)
                                .body(None)
                                .unwrap())
                        }
                    };
                    if let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, check).await {
                        while let Some(Ok(_)) = ws.next().await {}
                    }
                });
            }
        });

        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let provider: TokenProvider = Arc::new(move |force_refresh| {
            recorded.lock().unwrap().push(force_refresh);
            let token = if force_refresh { "fresh" } else { "stale" };
            Box::pin(async move { Some(token.to_string()) })
        });
        let (conn, mut events) = WsConnection::new(&url, provider, None);
        let conn = Arc::new(conn);
        let task = tokio::spawn(conn.clone().connect_with_reconnect());

        let connected = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(event) = events.recv().await {
                if matches!(event, WsEvent::Connected) {
                    return true;
                }
            }
            false
        })
        .await
        .expect("connects after refreshing the token");
        assert!(connected);
        assert_eq!(seen_rx.recv().await.unwrap(), "Bearer stale");
        assert_eq!(seen_rx.recv().await.unwrap(), "Bearer fresh");
        assert_eq!(*calls.lock().unwrap(), vec![false, true]);

        conn.close();
        task.abort();
    }

    #[tokio::test]
    async fn close_during_token_loading_is_durable_and_never_dials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let provider: TokenProvider = Arc::new(move |_| {
            let signal = signal.clone();
            Box::pin(async move {
                signal.notify_one();
                std::future::pending::<Option<String>>().await
            })
        });
        let (connection, mut events) = WsConnection::new(
            &format!("http://{}", listener.local_addr().unwrap()),
            provider,
            None,
        );
        let connection = Arc::new(connection);
        let task = tokio::spawn(connection.clone().connect_with_reconnect());
        entered.notified().await;
        connection.close();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(connection.is_closed());
        assert!(events.try_recv().is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn close_cancels_an_incomplete_websocket_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (connection, mut events) = WsConnection::new(
            &format!("http://{}", listener.local_addr().unwrap()),
            fixed_token("token"),
            None,
        );
        let connection = Arc::new(connection);
        let task = tokio::spawn(connection.clone().connect_with_reconnect());
        let (_unanswered_handshake, _) = listener.accept().await.unwrap();
        connection.close();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(events.try_recv().is_err());
    }

    #[tokio::test]
    async fn ended_session_stops_reconnecting() {
        let provider: TokenProvider = Arc::new(|_| Box::pin(async { None }));
        let (conn, mut events) = WsConnection::new("http://127.0.0.1:9", provider, None);
        let task = tokio::spawn(Arc::new(conn).connect_with_reconnect());

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the reconnect loop stops")
            .unwrap();
        assert!(matches!(events.recv().await, Some(WsEvent::SessionExpired)));
    }
}
