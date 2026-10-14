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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_matches_serde_snake_case() {
        for (state, text) in [
            (AppState::NotConfigured, "not_configured"),
            (AppState::Disconnected, "disconnected"),
            (AppState::Connecting, "connecting"),
            (AppState::Connected, "connected"),
        ] {
            assert_eq!(state.to_string(), text);
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{text}\"")
            );
            assert_eq!(
                serde_json::from_str::<AppState>(&format!("\"{text}\"")).unwrap(),
                state
            );
        }
    }

    #[test]
    fn unknown_state_is_rejected() {
        assert!(serde_json::from_str::<AppState>("\"online\"").is_err());
    }
}
