use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::warn;

use cpmesh_proto::models::*;

use crate::AppState;

pub type UserId = String;
pub type DeviceId = String;

pub struct Client {
    pub user_id: String,
    pub device_id: String,
    pub device_name: String,
    pub tx: mpsc::UnboundedSender<String>,
}

#[derive(Default)]
pub struct Hub {
    pub clients: RwLock<HashMap<UserId, HashMap<DeviceId, Client>>>,
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, client: Client) {
        let user_id = client.user_id.clone();
        let device_id = client.device_id.clone();
        let device_name = client.device_name.clone();

        let mut clients = self.clients.write().await;
        clients
            .entry(user_id.clone())
            .or_default()
            .insert(device_id.clone(), client);
        drop(clients);

        // Notify other devices
        let msg = WsMessage {
            msg_type: MSG_DEVICE_STATUS.to_string(),
            payload: json!(DeviceStatusPayload {
                device_id: device_id.clone(),
                device_name,
                online: true,
            }),
        };
        self.broadcast_to_user(&user_id, &device_id, &msg).await;
    }

    pub async fn remove(&self, user_id: &str, device_id: &str, device_name: &str) {
        let mut clients = self.clients.write().await;
        if let Some(user_clients) = clients.get_mut(user_id) {
            user_clients.remove(device_id);
            if user_clients.is_empty() {
                clients.remove(user_id);
            }
        }
        drop(clients);

        let msg = WsMessage {
            msg_type: MSG_DEVICE_STATUS.to_string(),
            payload: json!(DeviceStatusPayload {
                device_id: device_id.to_string(),
                device_name: device_name.to_string(),
                online: false,
            }),
        };
        self.broadcast_to_user(user_id, device_id, &msg).await;
    }

    pub async fn broadcast_to_user(&self, user_id: &str, exclude_device_id: &str, msg: &WsMessage) {
        let data = match serde_json::to_string(msg) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to serialize broadcast message: {e}");
                return;
            }
        };
        let clients = self.clients.read().await;
        if let Some(user_clients) = clients.get(user_id) {
            for (device_id, client) in user_clients {
                if device_id == exclude_device_id {
                    continue;
                }
                if client.tx.send(data.clone()).is_err() {
                    warn!("Client {} buffer full, dropping message", device_id);
                }
            }
        }
    }

    pub async fn total_connections(&self) -> i64 {
        let clients = self.clients.read().await;
        clients.values().map(|uc| uc.len() as i64).sum()
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

pub fn start_hub_cleanup(_state: Arc<AppState>) {
    // Hub cleanup is handled by WebSocket connection drops
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::error::TryRecvError;

    fn client(user: &str, device: &str) -> (Client, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Client {
                user_id: user.to_string(),
                device_id: device.to_string(),
                device_name: format!("{device}-name"),
                tx,
            },
            rx,
        )
    }

    fn parse(raw: String) -> WsMessage {
        serde_json::from_str(&raw).unwrap()
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
        hub.register(a).await;
        hub.register(b).await;
        let _ = rx_a.try_recv(); // b came online
        assert_eq!(hub.user_connection_count("u1").await, 2);

        hub.remove("u1", "b", "b-name").await;
        let msg = parse(rx_a.try_recv().unwrap());
        let payload: DeviceStatusPayload = serde_json::from_value(msg.payload).unwrap();
        assert_eq!(payload.device_id, "b");
        assert!(!payload.online);
        assert!(!hub.is_device_online("u1", "b").await);
        assert!(hub.is_device_online("u1", "a").await);

        hub.remove("u1", "a", "a-name").await;
        assert_eq!(hub.user_connection_count("u1").await, 0);
        assert_eq!(hub.total_connections().await, 0);
        assert!(
            hub.clients.read().await.get("u1").is_none(),
            "empty user map is dropped"
        );

        // Removing something unknown is harmless
        hub.remove("nobody", "nothing", "n").await;
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
    async fn re_registering_same_device_replaces_client() {
        let hub = Hub::new();
        let (a1, _r1) = client("u1", "a");
        let (a2, _r2) = client("u1", "a");
        hub.register(a1).await;
        hub.register(a2).await;
        assert_eq!(hub.user_connection_count("u1").await, 1);
    }
}
