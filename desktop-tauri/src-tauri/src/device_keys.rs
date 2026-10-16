//! Long-term device keys in the OS credential store.
//!
//! The identity and encryption private scalars live in [`SecureStore`] (Keychain,
//! Credential Manager, Secret Service; file fallback with 0600 permissions). A
//! plaintext `device_keys.json` records the matching PUBLIC keys so that a
//! credential-store read failure is reported instead of silently minting a new
//! identity, which would break the mesh. Legacy `device.key` PEM files are
//! imported once and then removed.

use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::crypto::keys::{DeviceKeys, KeyPair};
use crate::secure_storage::SecureStore;

const IDENTITY_KEY: &str = "device_identity_key";
const ENCRYPTION_KEY: &str = "device_encryption_key";

#[derive(Serialize, Deserialize, Default)]
struct PublicRecord {
    #[serde(default)]
    identity_public_key: Option<String>,
    #[serde(default)]
    encryption_public_key: Option<String>,
}

pub struct DeviceKeyStore {
    store: SecureStore,
    config_dir: PathBuf,
}

impl DeviceKeyStore {
    pub fn new(config_dir: &Path) -> Self {
        Self::with_store(config_dir, SecureStore::new("cpmesh", config_dir))
    }

    pub fn with_store(config_dir: &Path, store: SecureStore) -> Self {
        DeviceKeyStore {
            store,
            config_dir: config_dir.to_path_buf(),
        }
    }

    fn record_path(&self) -> PathBuf {
        self.config_dir.join("device_keys.json")
    }

    fn legacy_pem_path(&self) -> PathBuf {
        AppConfig::key_path(&self.config_dir)
    }

    /// True when this device already has an identity (in the store, recorded, or
    /// as a legacy PEM). Used to refuse connecting with a silently regenerated key.
    pub fn has_identity(&self) -> bool {
        self.read_record().identity_public_key.is_some()
            || self.legacy_pem_path().exists()
            || matches!(self.store.load(IDENTITY_KEY), Ok(Some(_)))
    }

    /// Loads the device keys, importing a legacy PEM and generating whatever is
    /// genuinely missing. Never regenerates a key the public record says exists.
    pub fn load_or_generate(&self) -> Result<DeviceKeys, String> {
        let mut record = self.read_record();
        let identity = match self.load_key(IDENTITY_KEY)? {
            Some(key) => key,
            None => match self.import_legacy_pem()? {
                Some(key) => key,
                None if record.identity_public_key.is_some() => {
                    return Err(
                        "The device identity key is in the OS credential store but could not be read. Unlock the credential store or restore a backup; do not generate a new identity."
                            .into(),
                    );
                }
                None => self.generate_key(IDENTITY_KEY)?,
            },
        };
        Self::check_record(record.identity_public_key.as_deref(), &identity, "identity")?;
        let encryption = match self.load_key(ENCRYPTION_KEY)? {
            Some(key) => key,
            None if record.encryption_public_key.is_some() => {
                return Err(
                    "The device encryption key is in the OS credential store but could not be read. Unlock the credential store or restore a backup."
                        .into(),
                );
            }
            None => self.generate_key(ENCRYPTION_KEY)?,
        };
        Self::check_record(
            record.encryption_public_key.as_deref(),
            &encryption,
            "encryption",
        )?;
        let keys = DeviceKeys {
            identity,
            encryption,
        };
        let identity_b64 = STANDARD.encode(keys.identity.public_key_bytes());
        let encryption_b64 = STANDARD.encode(keys.encryption.public_key_bytes());
        if record.identity_public_key.as_deref() != Some(&identity_b64)
            || record.encryption_public_key.as_deref() != Some(&encryption_b64)
        {
            record.identity_public_key = Some(identity_b64);
            record.encryption_public_key = Some(encryption_b64);
            crate::crypto::keys::write_private_file(
                &self.record_path(),
                &serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("write device key record: {e}"))?;
        }
        Ok(keys)
    }

    fn read_record(&self) -> PublicRecord {
        std::fs::read(self.record_path())
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default()
    }

    fn check_record(recorded: Option<&str>, key: &KeyPair, kind: &str) -> Result<(), String> {
        match recorded {
            Some(expected) if expected != STANDARD.encode(key.public_key_bytes()) => Err(format!(
                "The stored {kind} key does not match this device's recorded {kind} key; restore the matching backup instead of continuing with a different identity."
            )),
            _ => Ok(()),
        }
    }

    fn load_key(&self, name: &str) -> Result<Option<KeyPair>, String> {
        match self.store.load(name) {
            Ok(Some(encoded)) => {
                let scalar = zeroize::Zeroizing::new(
                    STANDARD
                        .decode(encoded.trim())
                        .map_err(|e| format!("corrupt {name}: {e}"))?,
                );
                KeyPair::from_scalar_bytes(&scalar)
                    .map(Some)
                    .map_err(|e| format!("corrupt {name}: {e}"))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("read {name}: {e}")),
        }
    }

    fn save_key(&self, name: &str, key: &KeyPair) -> Result<(), String> {
        let encoded = zeroize::Zeroizing::new(STANDARD.encode(key.scalar_bytes().as_ref()));
        self.store
            .save(name, &encoded)
            .map_err(|e| format!("save {name}: {e}"))?;
        // Read back before anything depends on the stored copy.
        match self.load_key(name)? {
            Some(stored) if stored.public_key_bytes() == key.public_key_bytes() => Ok(()),
            _ => Err(format!(
                "{name} could not be read back from the credential store"
            )),
        }
    }

    fn generate_key(&self, name: &str) -> Result<KeyPair, String> {
        let key = KeyPair::generate();
        self.save_key(name, &key)?;
        Ok(key)
    }

    /// Moves a pre-v3 `device.key` into the credential store; the PEM is removed
    /// only after the stored copy has been read back successfully.
    fn import_legacy_pem(&self) -> Result<Option<KeyPair>, String> {
        let path = self.legacy_pem_path();
        if !path.exists() {
            return Ok(None);
        }
        let private = KeyPair::load_private_key(&path).map_err(|e| e.to_string())?;
        let key = KeyPair {
            public: private.public_key(),
            private,
        };
        self.save_key(IDENTITY_KEY, &key)?;
        if let Err(e) = std::fs::remove_file(&path) {
            log::warn!(
                "Imported device.key into the credential store but could not remove it: {e}"
            );
        }
        Ok(Some(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store(dir: &TempDir) -> DeviceKeyStore {
        DeviceKeyStore::with_store(
            dir.path(),
            SecureStore::file_only("cpmesh-test", dir.path()),
        )
    }

    #[test]
    fn generates_distinct_keys_once_and_reloads_them() {
        let dir = TempDir::new().unwrap();
        assert!(!store(&dir).has_identity());
        let first = store(&dir).load_or_generate().unwrap();
        assert_ne!(
            first.identity.public_key_bytes(),
            first.encryption.public_key_bytes()
        );
        assert!(store(&dir).has_identity());
        let again = store(&dir).load_or_generate().unwrap();
        assert_eq!(
            first.identity.public_key_bytes(),
            again.identity.public_key_bytes()
        );
        assert_eq!(
            first.encryption.public_key_bytes(),
            again.encryption.public_key_bytes()
        );
        // The public record never contains private material.
        let record = std::fs::read_to_string(dir.path().join("device_keys.json")).unwrap();
        assert!(record.contains(&STANDARD.encode(first.identity.public_key_bytes())));
        assert!(!record.contains(&STANDARD.encode(first.identity.scalar_bytes().as_ref())));
    }

    #[test]
    fn imports_legacy_pem_and_removes_it() {
        let dir = TempDir::new().unwrap();
        let legacy = KeyPair::generate();
        legacy
            .save_private_key(&AppConfig::key_path(dir.path()))
            .unwrap();
        assert!(store(&dir).has_identity());
        let keys = store(&dir).load_or_generate().unwrap();
        assert_eq!(keys.identity.public_key_bytes(), legacy.public_key_bytes());
        assert!(!AppConfig::key_path(dir.path()).exists());
        // Still the same identity afterwards, now from the store.
        let again = store(&dir).load_or_generate().unwrap();
        assert_eq!(again.identity.public_key_bytes(), legacy.public_key_bytes());
    }

    #[test]
    fn unreadable_store_never_mints_a_new_identity() {
        let dir = TempDir::new().unwrap();
        let keys = store(&dir).load_or_generate().unwrap();
        // Simulate a credential store that lost (or refuses to return) the secrets.
        std::fs::remove_file(dir.path().join(".secret_device_identity_key")).unwrap();
        let err = store(&dir).load_or_generate().unwrap_err();
        assert!(err.contains("could not be read"), "{err}");
        assert!(store(&dir).has_identity());
        // The encryption key alone missing is reported too.
        let s = store(&dir);
        s.save_key(IDENTITY_KEY, &keys.identity).unwrap();
        std::fs::remove_file(dir.path().join(".secret_device_encryption_key")).unwrap();
        let err = s.load_or_generate().unwrap_err();
        assert!(err.contains("encryption key"), "{err}");
    }

    #[test]
    fn stored_key_must_match_the_recorded_public_key() {
        let dir = TempDir::new().unwrap();
        store(&dir).load_or_generate().unwrap();
        let s = store(&dir);
        s.save_key(IDENTITY_KEY, &KeyPair::generate()).unwrap();
        let err = s.load_or_generate().unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn corrupt_secret_is_an_error_not_a_new_key() {
        let dir = TempDir::new().unwrap();
        store(&dir).load_or_generate().unwrap();
        std::fs::write(
            dir.path().join(".secret_device_identity_key"),
            "not base64!",
        )
        .unwrap();
        assert!(store(&dir).load_or_generate().is_err());
    }
}
