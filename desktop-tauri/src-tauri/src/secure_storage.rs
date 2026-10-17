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
/// - Linux:   Secret Service via `keyring` crate, with file-based fallback (0600 perms)
/// - Android: file-based (OS File-Based Encryption handles at-rest encryption)
/// - iOS:     file-based (app container encryption via OS)
pub struct SecureStore {
    #[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
    service: String,
    config_dir: PathBuf,
    backend: Backend,
}

/// Where secrets are persisted. Only one variant is constructed per build: mobile
/// platforms and unit tests use files, desktop builds the OS credential store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum Backend {
    /// OS credential store first, falling back to files when it is unavailable.
    Keyring,
    /// Files in the config directory only.
    File,
}

impl SecureStore {
    /// Creates a store using the platform default backend. Unit tests always get the
    /// file backend: they must never read or overwrite a user's real credentials.
    pub fn new(service: &str, config_dir: &Path) -> Self {
        #[cfg(any(test, target_os = "android", target_os = "ios"))]
        let backend = Backend::File;
        #[cfg(not(any(test, target_os = "android", target_os = "ios")))]
        let backend = Backend::Keyring;

        Self::with_backend(service, config_dir, backend)
    }

    /// Creates a store that never touches the OS credential store.
    ///
    /// Useful for environments without a keyring daemon and for tests, which must
    /// not read or overwrite a user's real credentials.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn file_only(service: &str, config_dir: &Path) -> Self {
        Self::with_backend(service, config_dir, Backend::File)
    }

    fn with_backend(service: &str, config_dir: &Path, backend: Backend) -> Self {
        SecureStore {
            service: service.to_string(),
            config_dir: config_dir.to_path_buf(),
            backend,
        }
    }

    /// Store a secret value.
    pub fn save(&self, key: &str, value: &str) -> Result<(), StoreError> {
        match self.backend {
            Backend::File => self.save_file(key, value),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            Backend::Keyring => {
                // Try keyring first, fall back to file on failure
                match self.save_keyring(key, value) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        log::warn!("Keyring save failed ({e}), falling back to file storage");
                        self.save_file(key, value)
                    }
                }
            }
            #[cfg(any(target_os = "android", target_os = "ios"))]
            Backend::Keyring => self.save_file(key, value),
        }
    }

    /// Load a secret value. Returns None if not found.
    pub fn load(&self, key: &str) -> Result<Option<String>, StoreError> {
        match self.backend {
            Backend::File => self.load_file(key),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            Backend::Keyring => {
                // Try keyring first, fall back to file
                match self.load_keyring(key) {
                    Ok(Some(v)) => Ok(Some(v)),
                    Ok(None) => self.load_file(key), // might be in file from a previous fallback
                    Err(_) => self.load_file(key),
                }
            }
            #[cfg(any(target_os = "android", target_os = "ios"))]
            Backend::Keyring => self.load_file(key),
        }
    }

    /// Delete a secret value.
    pub fn delete(&self, key: &str) -> Result<(), StoreError> {
        match self.backend {
            Backend::File => self.delete_file(key),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            Backend::Keyring => {
                // Delete from both locations
                let _ = self.delete_keyring(key);
                let _ = self.delete_file(key);
                Ok(())
            }
            #[cfg(any(target_os = "android", target_os = "ios"))]
            Backend::Keyring => self.delete_file(key),
        }
    }

    // === Keyring backends (Windows DPAPI / macOS Keychain / Linux libsecret) ===

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn save_keyring(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| StoreError::Keyring(e.to_string()))?;
        entry
            .set_password(value)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store(dir: &TempDir) -> SecureStore {
        SecureStore::file_only("cpmesh-test", dir.path())
    }

    #[test]
    fn file_backend_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = store(&dir);

        assert_eq!(store.load("access_token").unwrap(), None);
        store.save("access_token", "tok-123").unwrap();
        assert_eq!(
            store.load("access_token").unwrap().as_deref(),
            Some("tok-123")
        );

        // Overwrite
        store.save("access_token", "tok-456").unwrap();
        assert_eq!(
            store.load("access_token").unwrap().as_deref(),
            Some("tok-456")
        );
    }

    #[test]
    fn file_backend_uses_hidden_file_in_config_dir() {
        let dir = TempDir::new().unwrap();
        let store = store(&dir);
        store.save("refresh_token", "r").unwrap();
        assert!(dir.path().join(".secret_refresh_token").is_file());
    }

    #[test]
    fn file_backend_creates_missing_config_dir() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("does").join("not").join("exist");
        let store = SecureStore::file_only("cpmesh-test", &nested);
        store.save("k", "v").unwrap();
        assert_eq!(store.load("k").unwrap().as_deref(), Some("v"));
    }

    #[test]
    fn file_backend_delete_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let store = store(&dir);
        store.save("k", "v").unwrap();
        store.delete("k").unwrap();
        assert_eq!(store.load("k").unwrap(), None);
        // Deleting a missing key is not an error
        store.delete("k").unwrap();
    }

    #[test]
    fn keys_are_isolated() {
        let dir = TempDir::new().unwrap();
        let store = store(&dir);
        store.save("a", "1").unwrap();
        store.save("b", "2").unwrap();
        assert_eq!(store.load("a").unwrap().as_deref(), Some("1"));
        assert_eq!(store.load("b").unwrap().as_deref(), Some("2"));
        store.delete("a").unwrap();
        assert_eq!(store.load("a").unwrap(), None);
        assert_eq!(store.load("b").unwrap().as_deref(), Some("2"));
    }

    #[cfg(unix)]
    #[test]
    fn file_backend_restricts_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let store = store(&dir);
        store.save("k", "v").unwrap();
        let mode = std::fs::metadata(dir.path().join(".secret_k"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn tests_never_use_the_real_credential_store() {
        let dir = TempDir::new().unwrap();
        let store = SecureStore::new("cpmesh-test", dir.path());
        assert_eq!(store.backend, Backend::File);
        assert_eq!(store.service, "cpmesh-test");
        store.save("k", "v").unwrap();
        assert!(dir.path().join(".secret_k").is_file());
    }
}
