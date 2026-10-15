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
        Self::load_with_store(config_dir, &SecureStore::new("cpmesh", config_dir))
    }

    /// Loads the config, migrating any legacy plaintext tokens into `store`.
    pub fn load_with_store(config_dir: &Path, store: &SecureStore) -> Result<Self, ConfigError> {
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
        if let Ok(legacy) = serde_json::from_str::<LegacyConfig>(&data)
            && (!legacy.access_token.is_empty() || !legacy.refresh_token.is_empty())
        {
            // Migrate tokens to secure storage
            if !legacy.access_token.is_empty() {
                let _ = store.save("access_token", &legacy.access_token);
            }
            if !legacy.refresh_token.is_empty() {
                let _ = store.save("refresh_token", &legacy.refresh_token);
            }
            // Re-save config without tokens
            config.save(config_dir)?;
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
        Self::with_store(SecureStore::new("cpmesh", config_dir))
    }

    /// Wraps an explicitly constructed store (e.g. a file-only store).
    pub fn with_store(store: SecureStore) -> Self {
        TokenStore { store }
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

impl crate::api::client::TokenPersistence for TokenStore {
    fn save(&self, access: &str, refresh: &str) {
        if let Err(e) = self.save_tokens(access, refresh) {
            log::warn!("Failed to save refreshed tokens: {e}");
        }
    }

    fn load(&self) -> Option<(String, String)> {
        let access = self.load_access_token().ok().flatten()?;
        let refresh = self.load_refresh_token().ok().flatten()?;
        Some((access, refresh))
    }

    fn clear(&self) {
        if let Err(e) = TokenStore::clear(self) {
            log::warn!("Failed to clear tokens: {e}");
        }
    }
}

/// Returns the platform config directory for cpmesh.
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cpmesh")
}

fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_config_is_not_configured() {
        let cfg = AppConfig::default();
        assert!(!cfg.is_configured());
        assert!(cfg.auto_connect);
        assert!(!cfg.autostart);
        assert!(cfg.notifications_enabled);
        assert_eq!(cfg.global_hotkey, "Ctrl+Shift+Space");
        assert_eq!(cfg.device_status, "approved");
        assert_eq!(cfg.device_name, hostname());
    }

    #[test]
    fn is_configured_requires_server_url_and_device_id() {
        let mut cfg = AppConfig {
            server_url: "https://cpmesh.example".into(),
            ..AppConfig::default()
        };
        assert!(!cfg.is_configured());
        cfg.device_id = "dev-1".into();
        assert!(cfg.is_configured());
        cfg.server_url.clear();
        assert!(!cfg.is_configured());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let cfg = AppConfig {
            server_url: "https://cpmesh.example".into(),
            user_id: "u1".into(),
            device_id: "d1".into(),
            device_name: "Laptop".into(),
            auto_connect: false,
            autostart: true,
            notifications_enabled: false,
            global_hotkey: "Alt+V".into(),
            device_status: "pending".into(),
        };
        cfg.save(dir.path()).unwrap();
        assert!(dir.path().join("config.json").is_file());

        let loaded = AppConfig::load_with_store(
            dir.path(),
            &SecureStore::file_only("cpmesh-test", dir.path()),
        )
        .unwrap();
        assert_eq!(loaded.server_url, cfg.server_url);
        assert_eq!(loaded.user_id, "u1");
        assert_eq!(loaded.device_id, "d1");
        assert_eq!(loaded.device_name, "Laptop");
        assert!(!loaded.auto_connect);
        assert!(loaded.autostart);
        assert!(!loaded.notifications_enabled);
        assert_eq!(loaded.global_hotkey, "Alt+V");
        assert_eq!(loaded.device_status, "pending");
    }

    #[test]
    fn load_missing_file_is_io_error() {
        let dir = TempDir::new().unwrap();
        let err = AppConfig::load_with_store(
            dir.path(),
            &SecureStore::file_only("cpmesh-test", dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Io(_)));
    }

    #[test]
    fn load_invalid_json_is_json_error() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("config.json"), "{ not json").unwrap();
        let err = AppConfig::load_with_store(
            dir.path(),
            &SecureStore::file_only("cpmesh-test", dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Json(_)));
    }

    #[test]
    fn missing_optional_fields_use_defaults() {
        let dir = TempDir::new().unwrap();
        // Minimal config written by an older app version
        fs::write(
            dir.path().join("config.json"),
            r#"{"server_url":"https://s","user_id":"u","device_id":"d","device_name":"n"}"#,
        )
        .unwrap();
        let cfg = AppConfig::load_with_store(
            dir.path(),
            &SecureStore::file_only("cpmesh-test", dir.path()),
        )
        .unwrap();
        assert!(cfg.auto_connect);
        assert!(!cfg.autostart);
        assert!(cfg.notifications_enabled);
        assert_eq!(cfg.global_hotkey, default_hotkey());
        assert_eq!(cfg.device_status, default_status());
    }

    #[test]
    fn legacy_tokens_are_migrated_to_secure_store_and_stripped() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("config.json"),
            r#"{
                "server_url":"https://s","user_id":"u","device_id":"d","device_name":"n",
                "access_token":"legacy-access","refresh_token":"legacy-refresh"
            }"#,
        )
        .unwrap();

        let store = SecureStore::file_only("cpmesh-test", dir.path());
        let cfg = AppConfig::load_with_store(dir.path(), &store).unwrap();
        assert_eq!(cfg.server_url, "https://s");

        // Tokens moved into the secure store
        assert_eq!(
            store.load("access_token").unwrap().as_deref(),
            Some("legacy-access")
        );
        assert_eq!(
            store.load("refresh_token").unwrap().as_deref(),
            Some("legacy-refresh")
        );

        // ...and removed from the plaintext config file
        let rewritten = fs::read_to_string(dir.path().join("config.json")).unwrap();
        assert!(!rewritten.contains("legacy-access"));
        assert!(!rewritten.contains("legacy-refresh"));
        assert!(!rewritten.contains("access_token"));
        let reparsed: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        assert_eq!(reparsed["server_url"], "https://s");
    }

    #[test]
    fn config_without_legacy_tokens_is_not_rewritten() {
        let dir = TempDir::new().unwrap();
        let original =
            r#"{"server_url":"https://s","user_id":"u","device_id":"d","device_name":"n"}"#;
        fs::write(dir.path().join("config.json"), original).unwrap();
        let store = SecureStore::file_only("cpmesh-test", dir.path());
        AppConfig::load_with_store(dir.path(), &store).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("config.json")).unwrap(),
            original
        );
        assert_eq!(store.load("access_token").unwrap(), None);
    }

    #[test]
    fn token_store_roundtrip_and_clear() {
        let dir = TempDir::new().unwrap();
        let ts = TokenStore::with_store(SecureStore::file_only("cpmesh-test", dir.path()));
        assert_eq!(ts.load_access_token().unwrap(), None);
        assert_eq!(ts.load_refresh_token().unwrap(), None);

        ts.save_tokens("acc", "ref").unwrap();
        assert_eq!(ts.load_access_token().unwrap().as_deref(), Some("acc"));
        assert_eq!(ts.load_refresh_token().unwrap().as_deref(), Some("ref"));

        ts.clear().unwrap();
        assert_eq!(ts.load_access_token().unwrap(), None);
        assert_eq!(ts.load_refresh_token().unwrap(), None);
    }

    #[test]
    fn derived_paths_live_in_config_dir() {
        let dir = Path::new("/tmp/cpmesh-cfg");
        assert_eq!(AppConfig::key_path(dir), dir.join("device.key"));
        assert_eq!(AppConfig::keyring_path(dir), dir.join("keyring.enc"));
        assert!(config_dir().ends_with("cpmesh"));
    }
}
