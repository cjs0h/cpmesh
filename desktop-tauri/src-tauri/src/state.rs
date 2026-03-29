use serde::{Deserialize, Serialize};

/// Application connection state machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppState {
    NotConfigured,
    Disconnected,
    Connecting,
    Connected,
}

impl std::fmt::Display for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppState::NotConfigured => write!(f, "not_configured"),
            AppState::Disconnected => write!(f, "disconnected"),
            AppState::Connecting => write!(f, "connecting"),
            AppState::Connected => write!(f, "connected"),
        }
    }
}
