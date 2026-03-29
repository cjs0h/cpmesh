use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::secure_storage::SecureStore;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Secure storage error: {0}")]
    SecureStorage(#[from] crate::secure_storage::StoreError),
}

/// Non-sensitive configuration stored in plaintext JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server_url: String,
    pub user_id: String,
    pub device_id: String,
    pub device_name: String,
    #[serde(default = "default_true")]
    pub auto_connect: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default = "default_true")]
    pub notifications_enabled: bool,
    #[serde(default = "default_hotkey")]
    pub global_hotkey: String,
    /// Device status from server (pending/approved/rejected/revoked).
    #[serde(default = "default_status")]
    pub device_status: String,
}

fn default_true() -> bool {
    true
}

fn default_hotkey() -> String {
    "Ctrl+Shift+Space".to_string()
}

fn default_status() -> String {
    "approved".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            server_url: String::new(),
            user_id: String::new(),
            device_id: String::new(),
            device_name: hostname(),
            auto_connect: true,
            autostart: false,
            notifications_enabled: true,
            global_hotkey: default_hotkey(),
            device_status: default_status(),
        }
    }
}

impl AppConfig {
    /// Returns true if the app has been configured (has server URL + device ID).
    pub fn is_configured(&self) -> bool {
        !self.server_url.is_empty() && !self.device_id.is_empty()
    }

    pub fn load(config_dir: &Path) -> Result<Self, ConfigError> {
        let path = config_dir.join("config.json");
        let data = fs::read_to_string(&path)?;
        let config: AppConfig = serde_json::from_str(&data)?;

        // Migration: if the old config.json has tokens, load them and strip from file
        #[derive(Deserialize)]
        struct LegacyConfig {
            #[serde(default)]
            access_token: String,
            #[serde(default)]
            refresh_token: String,
        }
        if let Ok(legacy) = serde_json::from_str::<LegacyConfig>(&data) {
            if !legacy.access_token.is_empty() || !legacy.refresh_token.is_empty() {
                // Migrate tokens to secure storage
                let store = SecureStore::new("cpmesh", config_dir);
                if !legacy.access_token.is_empty() {
                    let _ = store.save("access_token", &legacy.access_token);
                }
                if !legacy.refresh_token.is_empty() {
                    let _ = store.save("refresh_token", &legacy.refresh_token);
                }
                // Re-save config without tokens
                config.save(config_dir)?;
            }
        }

        Ok(config)
    }

    pub fn save(&self, config_dir: &Path) -> Result<(), ConfigError> {
        fs::create_dir_all(config_dir)?;
        let data = serde_json::to_string_pretty(self)?;
        fs::write(config_dir.join("config.json"), data)?;
        Ok(())
    }

    pub fn key_path(config_dir: &Path) -> PathBuf {
        config_dir.join("device.key")
    }

    pub fn keyring_path(config_dir: &Path) -> PathBuf {
        config_dir.join("keyring.enc")
    }
}

/// Token management via secure storage.
pub struct TokenStore {
    store: SecureStore,
}

impl TokenStore {
    pub fn new(config_dir: &Path) -> Self {
        TokenStore {
            store: SecureStore::new("cpmesh", config_dir),
        }
    }

    pub fn save_tokens(&self, access: &str, refresh: &str) -> Result<(), ConfigError> {
        self.store.save("access_token", access)?;
        self.store.save("refresh_token", refresh)?;
        Ok(())
    }

    pub fn load_access_token(&self) -> Result<Option<String>, ConfigError> {
        Ok(self.store.load("access_token")?)
    }

    pub fn load_refresh_token(&self) -> Result<Option<String>, ConfigError> {
        Ok(self.store.load("refresh_token")?)
    }

    pub fn clear(&self) -> Result<(), ConfigError> {
        self.store.delete("access_token")?;
        self.store.delete("refresh_token")?;
        Ok(())
    }
}

/// Returns the platform config directory for cpmesh.
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cpmesh")
}

fn hostname() -> String {
    gethostname::gethostname()
        .to_string_lossy()
        .to_string()
}
