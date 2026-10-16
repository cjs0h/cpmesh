use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use cpmesh_proto::models::*;

use crate::AppState;

pub type UserId = String;
pub type DeviceId = String;
pub const QUEUE_CAPACITY: usize = 8;
const USER_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 10;

pub struct QueuedMessage {
    pub text: axum::extract::ws::Utf8Bytes,
    _permit: Option<OwnedSemaphorePermit>,
}

impl QueuedMessage {
    pub fn control(text: String) -> Arc<Self> {
        Arc::new(Self {
            text: text.into(),
            _permit: None,
        })
    }
}

pub struct Client {
    pub user_id: String,
    /// The device ID, or a per-connection ID for browser sessions.
    pub device_id: String,
    pub device_name: String,
    /// Identifies this connection, so cleanup of a stale connection cannot remove a
    /// newer connection of the same device.
    pub conn_id: uuid::Uuid,
    /// Whether the user's other devices are told when this client goes on- or offline.
    /// True for devices, false for browser sessions.
    pub announce: bool,
    /// Whether the connection receives clipboard entries. False for agents without
    /// `clipboard:read`, which only get `oauth::policy::SEND_ONLY_MESSAGES`.
    pub reads_clipboard: bool,
    pub tx: mpsc::Sender<Arc<QueuedMessage>>,
    /// Signalled to close the connection (account suspended, deleted or signed out).
    pub kick: CancellationToken,
}

#[derive(Default)]
pub struct Hub {
    pub clients: RwLock<HashMap<UserId, HashMap<DeviceId, Client>>>,
    budgets: RwLock<HashMap<UserId, Arc<Semaphore>>>,
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, client: Client) -> bool {
        let user_id = client.user_id.clone();
        let device_id = client.device_id.clone();
        let device_name = client.device_name.clone();
        let announce = client.announce;

        let mut clients = self.clients.write().await;
        let user_clients = clients.entry(user_id.clone()).or_default();
        if user_clients.len() >= MAX_CONNECTIONS && !user_clients.contains_key(&device_id) {
            client.kick.cancel();
            return false;
        }
        if let Some(old) = user_clients.insert(device_id.clone(), client) {
            old.kick.cancel();
        }
        self.budgets
            .write()
            .await
            .entry(user_id.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(USER_QUEUE_BYTES)));
        drop(clients);

        if announce {
            self.broadcast_device_status(&user_id, &device_id, &device_name, true)
                .await;
        }
        true
    }

    /// Removes connection `conn_id` of `device_id`. Does nothing if the device has
    /// reconnected since, so the newer connection keeps receiving messages.
    pub async fn remove(&self, user_id: &str, device_id: &str, conn_id: uuid::Uuid) {
        let removed = {
            let mut clients = self.clients.write().await;
            let Some(user_clients) = clients.get_mut(user_id) else {
                return;
            };
            if user_clients
                .get(device_id)
                .is_none_or(|c| c.conn_id != conn_id)
            {
                return;
            }
            let removed = user_clients.remove(device_id);
            if user_clients.is_empty() {
                clients.remove(user_id);
                let mut budgets = self.budgets.write().await;
                if budgets
                    .get(user_id)
                    .is_some_and(|budget| budget.available_permits() == USER_QUEUE_BYTES)
                {
                    budgets.remove(user_id);
                }
            }
            removed
        };

        if let Some(client) = removed
            && client.announce
        {
            self.broadcast_device_status(user_id, device_id, &client.device_name, false)
                .await;
        }
    }

    async fn broadcast_device_status(
        &self,
        user_id: &str,
        device_id: &str,
        device_name: &str,
        online: bool,
    ) {
        let msg = WsMessage {
            msg_type: MSG_DEVICE_STATUS.to_string(),
            payload: json!(DeviceStatusPayload {
                device_id: device_id.to_string(),
                device_name: device_name.to_string(),
                online,
            }),
        };
        self.broadcast_to_user(user_id, device_id, &msg).await;
    }

    pub async fn broadcast_to_user(&self, user_id: &str, exclude_device_id: &str, msg: &WsMessage) {
        let browser_message = if msg.msg_type == MSG_CLIPBOARD_NEW {
            let source = &msg.payload["entry"];
            let mut entry = serde_json::Map::new();
            for field in [
                "id",
                "device_id",
                "device_name",
                "content_type",
                "encrypted_size",
                "created_at",
                "key_version",
            ] {
                entry.insert(field.to_string(), source[field].clone());
            }
            Some(QueuedMessage::control(
                json!({
                    "type": MSG_CLIPBOARD_NEW, "payload": {"entry": entry},
                })
                .to_string(),
            ))
        } else {
            None
        };
        let data = match serde_json::to_string(msg) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to serialize broadcast message: {e}");
                return;
            }
        };
        let clients = self.clients.read().await;
        let budget = self.budgets.read().await.get(user_id).cloned();
        let Some(budget) = budget else {
            return;
        };
        let Ok(permit) = budget.try_acquire_many_owned(data.len() as u32) else {
            drop(clients);
            warn!(%user_id, "Relay byte budget exhausted; reconnect to resume from history");
            self.disconnect_user(user_id).await;
            return;
        };
        let message = Arc::new(QueuedMessage {
            text: data.into(),
            _permit: Some(permit),
        });
        let mut overflowed = Vec::new();
        let withheld_without_read = !crate::oauth::policy::delivered_without_read(&msg.msg_type);
        if let Some(user_clients) = clients.get(user_id) {
            for (device_id, client) in user_clients {
                if device_id == exclude_device_id
                    || (withheld_without_read && !client.reads_clipboard)
                {
                    continue;
                }
                let outgoing = if !client.announce {
                    browser_message.as_ref().unwrap_or(&message)
                } else {
                    &message
                };
                if client.tx.try_send(outgoing.clone()).is_err() {
                    warn!(%device_id, "Relay queue unavailable; disconnecting slow consumer");
                    client.kick.cancel();
                    overflowed.push((device_id.clone(), client.conn_id));
                }
            }
        }
        drop(clients);
        for (device, connection) in overflowed {
            Box::pin(self.remove(user_id, &device, connection)).await;
        }
    }

    /// Closes every connection of `user_id`, returning how many there were. Nobody is
    /// told the devices went offline: the user has no connection left to tell.
    pub async fn disconnect_user(&self, user_id: &str) -> usize {
        let mut all_clients = self.clients.write().await;
        let removed = all_clients.remove(user_id);
        {
            let mut budgets = self.budgets.write().await;
            if budgets
                .get(user_id)
                .is_some_and(|budget| budget.available_permits() == USER_QUEUE_BYTES)
            {
                budgets.remove(user_id);
            }
        }
        drop(all_clients);
        match removed {
            Some(clients) => {
                for client in clients.values() {
                    client.kick.cancel();
                }

                clients.len()
            }
            None => 0,
        }
    }

    pub async fn total_connections(&self) -> i64 {
        let clients = self.clients.read().await;
        clients.values().map(|uc| uc.len() as i64).sum()
    }

    pub async fn disconnect_device(&self, user_id: &str, device_id: &str) {
        let connection = {
            let clients = self.clients.read().await;
            clients
                .get(user_id)
                .and_then(|c| c.get(device_id))
                .map(|c| {
                    c.kick.cancel();
                    c.conn_id
                })
        };
        if let Some(connection) = connection {
            self.remove(user_id, device_id, connection).await;
        }
    }

    pub async fn is_device_online(&self, user_id: &str, device_id: &str) -> bool {
        let clients = self.clients.read().await;
        clients
            .get(user_id)
            .map(|uc| uc.contains_key(device_id))
            .unwrap_or(false)
    }

    pub async fn user_connection_count(&self, user_id: &str) -> usize {
        let clients = self.clients.read().await;
        clients.get(user_id).map(|uc| uc.len()).unwrap_or(0)
    }
}

/// Hourly housekeeping: idle send budgets, old request receipts and expired OAuth codes.
pub fn start_hub_cleanup(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            {
                let clients = state.hub.clients.read().await;
                state.hub.budgets.write().await.retain(|user, budget| {
                    clients.contains_key(user) || budget.available_permits() < USER_QUEUE_BYTES
                });
            }
            if let Err(error) = sqlx::query(
                "DELETE FROM clipboard_requests WHERE created_at < NOW() - INTERVAL '24 hours'",
            )
            .execute(&state.db.pool)
            .await
            {
                warn!("Failed to expire clipboard request receipts: {error}");
            }
            if let Err(error) = state.db.delete_expired_oauth_codes().await {
                warn!("Failed to delete expired OAuth codes: {error}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::error::TryRecvError;

    fn client(user: &str, device: &str) -> (Client, mpsc::Receiver<Arc<QueuedMessage>>) {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        (
            Client {
                user_id: user.to_string(),
                device_id: device.to_string(),
                device_name: format!("{device}-name"),
                conn_id: uuid::Uuid::new_v4(),
                announce: true,
                reads_clipboard: true,
                tx,
                kick: CancellationToken::new(),
            },
            rx,
        )
    }

    fn parse(raw: Arc<QueuedMessage>) -> WsMessage {
        serde_json::from_str(&raw.text).unwrap()
    }

    #[tokio::test]
    async fn slow_consumers_are_disconnected_instead_of_growing_the_queue() {
        let hub = Hub::new();
        let (client, _rx) = client("u", "slow");
        let kick = client.kick.clone();
        hub.register(client).await;
        let msg = WsMessage {
            msg_type: MSG_PING.into(),
            payload: json!({}),
        };
        for _ in 0..=QUEUE_CAPACITY {
            hub.broadcast_to_user("u", "", &msg).await;
        }
        assert!(kick.is_cancelled());
        assert_eq!(hub.user_connection_count("u").await, 0);
    }

    #[tokio::test]
    async fn per_user_byte_budget_and_connection_limit_are_enforced() {
        let hub = Hub::new();
        let mut receivers = Vec::new();
        for i in 0..MAX_CONNECTIONS {
            let (mut client, rx) = client("u", &i.to_string());
            client.announce = false;
            assert!(hub.register(client).await);
            receivers.push(rx);
        }
        let (extra, _rx) = client("u", "extra");
        assert!(!hub.register(extra).await);
        assert_eq!(hub.user_connection_count("u").await, MAX_CONNECTIONS);
        hub.budgets
            .write()
            .await
            .insert("u".into(), Arc::new(Semaphore::new(32)));
        hub.broadcast_to_user(
            "u",
            "",
            &WsMessage {
                msg_type: MSG_PING.into(),
                payload: json!({"data": "x".repeat(100)}),
            },
        )
        .await;
        assert_eq!(hub.user_connection_count("u").await, 0);
    }

    #[tokio::test]
    async fn register_notifies_other_devices_of_same_user_only() {
        let hub = Hub::new();
        let (a, mut rx_a) = client("u1", "a");
        let (b, mut rx_b) = client("u1", "b");
        let (other, mut rx_other) = client("u2", "x");
        hub.register(a).await;
        hub.register(other).await;
        // Nobody else was connected for u1 when `a` registered; u2 must not hear about u1.
        assert!(matches!(rx_a.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(rx_other.try_recv(), Err(TryRecvError::Empty)));

        hub.register(b).await;
        let msg = parse(rx_a.try_recv().unwrap());
        assert_eq!(msg.msg_type, MSG_DEVICE_STATUS);
        let payload: DeviceStatusPayload = serde_json::from_value(msg.payload).unwrap();
        assert_eq!(payload.device_id, "b");
        assert_eq!(payload.device_name, "b-name");
        assert!(payload.online);

        // The registering device does not receive its own status and other users hear nothing
        assert!(matches!(rx_b.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(rx_other.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn remove_notifies_offline_and_cleans_up_empty_users() {
        let hub = Hub::new();
        let (a, mut rx_a) = client("u1", "a");
        let (b, _rx_b) = client("u1", "b");
        let (conn_a, conn_b) = (a.conn_id, b.conn_id);
        hub.register(a).await;
        hub.register(b).await;
        let _ = rx_a.try_recv(); // b came online
        assert_eq!(hub.user_connection_count("u1").await, 2);

        hub.remove("u1", "b", conn_b).await;
        let msg = parse(rx_a.try_recv().unwrap());
        let payload: DeviceStatusPayload = serde_json::from_value(msg.payload).unwrap();
        assert_eq!(payload.device_id, "b");
        assert_eq!(payload.device_name, "b-name");
        assert!(!payload.online);
        assert!(!hub.is_device_online("u1", "b").await);
        assert!(hub.is_device_online("u1", "a").await);

        hub.remove("u1", "a", conn_a).await;
        assert_eq!(hub.user_connection_count("u1").await, 0);
        assert_eq!(hub.total_connections().await, 0);
        assert!(
            hub.clients.read().await.get("u1").is_none(),
            "empty user map is dropped"
        );

        // Removing something unknown is harmless
        hub.remove("nobody", "nothing", uuid::Uuid::new_v4()).await;
    }

    #[tokio::test]
    async fn stale_connection_cleanup_keeps_the_newer_connection() {
        let hub = Hub::new();
        let (watcher, mut rx_watcher) = client("u1", "w");
        let (old, _rx_old) = client("u1", "a");
        let (new, mut rx_new) = client("u1", "a");
        let old_conn = old.conn_id;
        hub.register(watcher).await;
        hub.register(old).await;
        // The device reconnects before the server notices its old connection died
        hub.register(new).await;
        while rx_watcher.try_recv().is_ok() {}

        hub.remove("u1", "a", old_conn).await;
        assert!(hub.is_device_online("u1", "a").await);
        assert!(
            matches!(rx_watcher.try_recv(), Err(TryRecvError::Empty)),
            "no offline notice for a device that is still connected"
        );

        let msg = WsMessage {
            msg_type: MSG_CLIPBOARD_NEW.to_string(),
            payload: json!({"entry": {"id": "e1"}}),
        };
        hub.broadcast_to_user("u1", "w", &msg).await;
        assert_eq!(
            parse(rx_new.try_recv().unwrap()).payload["entry"]["id"],
            "e1"
        );
    }

    #[tokio::test]
    async fn connections_without_clipboard_read_get_no_entries() {
        let hub = Hub::new();
        let (device, _rx_device) = client("u1", "a");
        let (mut agent, mut rx_agent) = client("u1", "agent");
        agent.reads_clipboard = false;
        hub.register(agent).await;
        hub.register(device).await;
        // Device events still reach it
        assert_eq!(
            parse(rx_agent.try_recv().unwrap()).msg_type,
            MSG_DEVICE_STATUS
        );

        for (kind, delivered) in [
            (MSG_CLIPBOARD_NEW, false),
            ("clipboard_history", false),
            (MSG_GROUP_KEY_UPDATED, true),
            (MSG_ROTATION_NEEDED, true),
        ] {
            let msg = WsMessage {
                msg_type: kind.into(),
                payload: json!({"entry": {"id": "e1"}}),
            };
            hub.broadcast_to_user("u1", "a", &msg).await;
            match rx_agent.try_recv() {
                Ok(msg) => assert!(delivered, "{kind} was delivered: {}", msg.text),
                Err(_) => assert!(!delivered, "{kind} was withheld"),
            }
        }
    }

    #[tokio::test]
    async fn browser_sessions_are_not_announced_as_devices() {
        let hub = Hub::new();
        let (device, mut rx_device) = client("u1", "a");
        let (mut browser, mut rx_browser) = client("u1", "web-1");
        browser.announce = false;
        let browser_conn = browser.conn_id;
        hub.register(device).await;
        hub.register(browser).await;
        assert!(matches!(rx_device.try_recv(), Err(TryRecvError::Empty)));

        // The browser still receives the user's broadcasts
        let msg = WsMessage {
            msg_type: MSG_CLIPBOARD_NEW.to_string(),
            payload: json!({"entry": {"id": "e1"}}),
        };
        hub.broadcast_to_user("u1", "a", &msg).await;
        assert_eq!(
            parse(rx_browser.try_recv().unwrap()).payload["entry"]["id"],
            "e1"
        );

        hub.remove("u1", "web-1", browser_conn).await;
        assert!(matches!(rx_device.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(hub.user_connection_count("u1").await, 1);
    }

    #[tokio::test]
    async fn broadcast_excludes_sender_and_other_users() {
        let hub = Hub::new();
        let (a, mut rx_a) = client("u1", "a");
        let (b, mut rx_b) = client("u1", "b");
        let (c, mut rx_c) = client("u1", "c");
        let (other, mut rx_other) = client("u2", "x");
        for cl in [a, b, c, other] {
            hub.register(cl).await;
        }
        // Drain the registration status messages
        while rx_a.try_recv().is_ok() {}
        while rx_b.try_recv().is_ok() {}
        while rx_c.try_recv().is_ok() {}
        while rx_other.try_recv().is_ok() {}

        let msg = WsMessage {
            msg_type: MSG_CLIPBOARD_NEW.to_string(),
            payload: json!({"entry": {"id": "e1"}}),
        };
        hub.broadcast_to_user("u1", "a", &msg).await;

        assert!(
            matches!(rx_a.try_recv(), Err(TryRecvError::Empty)),
            "sender excluded"
        );
        assert_eq!(parse(rx_b.try_recv().unwrap()).payload["entry"]["id"], "e1");
        assert_eq!(parse(rx_c.try_recv().unwrap()).payload["entry"]["id"], "e1");
        assert!(
            matches!(rx_other.try_recv(), Err(TryRecvError::Empty)),
            "other user excluded"
        );

        // Broadcasting to an unknown user is a no-op
        hub.broadcast_to_user("ghost", "", &msg).await;
    }

    #[tokio::test]
    async fn broadcast_survives_dropped_receivers() {
        let hub = Hub::new();
        let (a, rx_a) = client("u1", "a");
        let (b, mut rx_b) = client("u1", "b");
        hub.register(a).await;
        hub.register(b).await;
        drop(rx_a); // client a went away without being removed yet
        while rx_b.try_recv().is_ok() {}

        let msg = WsMessage {
            msg_type: MSG_PONG.to_string(),
            payload: json!({}),
        };
        hub.broadcast_to_user("u1", "", &msg).await;
        assert_eq!(parse(rx_b.try_recv().unwrap()).msg_type, MSG_PONG);
    }

    #[tokio::test]
    async fn counts_reflect_registrations() {
        let hub = Hub::new();
        assert_eq!(hub.total_connections().await, 0);
        assert_eq!(hub.user_connection_count("u1").await, 0);
        assert!(!hub.is_device_online("u1", "a").await);

        let (a, _ra) = client("u1", "a");
        let (b, _rb) = client("u1", "b");
        let (x, _rx) = client("u2", "x");
        hub.register(a).await;
        hub.register(b).await;
        hub.register(x).await;
        assert_eq!(hub.total_connections().await, 3);
        assert_eq!(hub.user_connection_count("u1").await, 2);
        assert_eq!(hub.user_connection_count("u2").await, 1);
        assert!(hub.is_device_online("u1", "a").await);
        assert!(!hub.is_device_online("u2", "a").await);
    }

    #[tokio::test]
    async fn disconnect_user_kicks_every_connection_of_that_user_only() {
        let hub = Hub::new();
        let (a, _ra) = client("u1", "a");
        let (b, _rb) = client("u1", "b");
        let (x, _rx) = client("u2", "x");
        let (kick_a, kick_b, kick_x) = (a.kick.clone(), b.kick.clone(), x.kick.clone());
        for c in [a, b, x] {
            hub.register(c).await;
        }

        assert_eq!(hub.disconnect_user("u1").await, 2);
        assert_eq!(hub.user_connection_count("u1").await, 0);
        assert_eq!(hub.user_connection_count("u2").await, 1);
        // The kicked connections are woken (a stored permit completes immediately)
        for kick in [kick_a, kick_b] {
            tokio::time::timeout(std::time::Duration::from_secs(1), kick.cancelled())
                .await
                .expect("connection was kicked");
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), kick_x.cancelled())
                .await
                .is_err(),
            "other users stay connected"
        );
        assert_eq!(hub.disconnect_user("u1").await, 0);
    }

    #[tokio::test]
    async fn re_registering_same_device_replaces_client() {
        let hub = Hub::new();
        let (a1, _r1) = client("u1", "a");
        let (a2, _r2) = client("u1", "a");
        hub.register(a1).await;
        hub.register(a2).await;
        assert_eq!(hub.user_connection_count("u1").await, 1);
    }
}
