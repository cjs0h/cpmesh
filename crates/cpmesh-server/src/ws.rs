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

pub struct Hub {
    pub clients: RwLock<HashMap<UserId, HashMap<DeviceId, Client>>>,
}

impl Hub {
    pub fn new() -> Self {
        Hub {
            clients: RwLock::new(HashMap::new()),
        }
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
