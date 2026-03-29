use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Platform-specific secure storage for secrets (tokens, private keys).
///
/// Backends:
/// - Windows: DPAPI via `keyring` crate (Credential Manager)
/// - macOS:   Keychain via `keyring` crate
/// - Linux:   libsecret via `keyring` crate, with file-based fallback (0600 perms)
/// - Android: file-based (OS File-Based Encryption handles at-rest encryption)
/// - iOS:     file-based (app container encryption via OS)
pub struct SecureStore {
    service: String,
    config_dir: PathBuf,
}

impl SecureStore {
    pub fn new(service: &str, config_dir: &Path) -> Self {
        SecureStore {
            service: service.to_string(),
            config_dir: config_dir.to_path_buf(),
        }
    }

    /// Store a secret value.
    pub fn save(&self, key: &str, value: &str) -> Result<(), StoreError> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            return self.save_file(key, value);
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            // Try keyring first, fall back to file on failure
            match self.save_keyring(key, value) {
                Ok(()) => Ok(()),
                Err(e) => {
                    log::warn!("Keyring save failed ({e}), falling back to file storage");
                    self.save_file(key, value)
                }
            }
        }
    }

    /// Load a secret value. Returns None if not found.
    pub fn load(&self, key: &str) -> Result<Option<String>, StoreError> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            return self.load_file(key);
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            // Try keyring first, fall back to file
            match self.load_keyring(key) {
                Ok(Some(v)) => Ok(Some(v)),
                Ok(None) => self.load_file(key), // might be in file from a previous fallback
                Err(_) => self.load_file(key),
            }
        }
    }

    /// Delete a secret value.
    pub fn delete(&self, key: &str) -> Result<(), StoreError> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            return self.delete_file(key);
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            // Delete from both locations
            let _ = self.delete_keyring(key);
            let _ = self.delete_file(key);
            Ok(())
        }
    }

    // === Keyring backends (Windows DPAPI / macOS Keychain / Linux libsecret) ===

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn save_keyring(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| StoreError::Keyring(e.to_string()))?;
        entry.set_password(value)
            .map_err(|e| StoreError::Keyring(format!("save '{key}': {e}")))?;
        Ok(())
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn load_keyring(&self, key: &str) -> Result<Option<String>, StoreError> {
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| StoreError::Keyring(e.to_string()))?;
        match entry.get_password() {
            Ok(pw) => Ok(Some(pw)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StoreError::Keyring(format!("load '{key}': {e}"))),
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn delete_keyring(&self, key: &str) -> Result<(), StoreError> {
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| StoreError::Keyring(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(StoreError::Keyring(format!("delete '{key}': {e}"))),
        }
    }

    // === File-based fallback (used on mobile, and desktop when keyring unavailable) ===

    fn save_file(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let path = self.secret_file_path(key);
        std::fs::create_dir_all(&self.config_dir)?;
        std::fs::write(&path, value)?;
        // Restrict permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn load_file(&self, key: &str) -> Result<Option<String>, StoreError> {
        let path = self.secret_file_path(key);
        match std::fs::read_to_string(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn delete_file(&self, key: &str) -> Result<(), StoreError> {
        let path = self.secret_file_path(key);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn secret_file_path(&self, key: &str) -> PathBuf {
        self.config_dir.join(format!(".secret_{key}"))
    }
}
