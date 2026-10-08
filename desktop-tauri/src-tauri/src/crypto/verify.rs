use p256::PublicKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

use super::keys::public_key_to_bytes;

/// Error returned when a previously pinned key has changed (possible MITM).
#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("public key has changed since approval (possible MITM attack)")]
    KeyChanged,
    #[error("device has not been approved yet")]
    #[allow(dead_code)]
    NotPinned,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Implements explicit trust pinning for device public keys.
///
/// Unlike TOFU (trust-on-first-use), keys are ONLY pinned after:
/// 1. Successful device approval (8-digit code match confirmed)
/// 2. Legacy migration of an already-approved device
///
/// Key changes after pinning are hard failures (possible MITM).
pub struct KeyVerifier {
    pins: HashMap<String, String>, // device_id -> hex(SHA-256(public_key))
    file_path: PathBuf,
}

impl KeyVerifier {
    /// Creates a verifier that persists pinned keys to the given directory.
    pub fn new(config_dir: &Path) -> Result<Self, VerifyError> {
        let file_path = config_dir.join("pinned_keys.json");
        let mut kv = KeyVerifier {
            pins: HashMap::new(),
            file_path,
        };
        kv.load()?;
        Ok(kv)
    }

    /// Pin a device's public key after successful approval.
    /// This is the ONLY way to add a new pin (no auto-trust on first use).
    #[allow(dead_code)]
    pub fn pin_after_approval(
        &mut self,
        device_id: &str,
        public_key: &PublicKey,
    ) -> Result<(), VerifyError> {
        let hash = hash_public_key(public_key);
        self.pins.insert(device_id.to_string(), hash);
        self.save()
    }

    /// Verify a pinned device's public key hasn't changed.
    /// Returns Err(NotPinned) if the device was never approved.
    /// Returns Err(KeyChanged) if the key differs from the pinned value.
    #[allow(dead_code)]
    pub fn verify_pinned(
        &self,
        device_id: &str,
        public_key: &PublicKey,
    ) -> Result<(), VerifyError> {
        let hash = hash_public_key(public_key);
        match self.pins.get(device_id) {
            None => Err(VerifyError::NotPinned),
            Some(pinned) if *pinned == hash => Ok(()),
            Some(_) => Err(VerifyError::KeyChanged),
        }
    }

    /// Migrate a legacy device that was already approved under the old TOFU model.
    /// Pins the key if not already pinned. If already pinned, verifies the key matches.
    pub fn migrate_legacy(
        &mut self,
        device_id: &str,
        public_key: &PublicKey,
    ) -> Result<(), VerifyError> {
        let hash = hash_public_key(public_key);
        match self.pins.get(device_id) {
            None => {
                self.pins.insert(device_id.to_string(), hash);
                self.save()?;
                Ok(())
            }
            Some(pinned) if *pinned == hash => Ok(()),
            Some(_) => Err(VerifyError::KeyChanged),
        }
    }

    /// Check if a device is already pinned.
    #[allow(dead_code)]
    pub fn is_pinned(&self, device_id: &str) -> bool {
        self.pins.contains_key(device_id)
    }

    /// Remove a pin (e.g., when a device is deleted).
    #[allow(dead_code)]
    pub fn remove_pin(&mut self, device_id: &str) -> Result<(), VerifyError> {
        self.pins.remove(device_id);
        self.save()
    }

    fn load(&mut self) -> Result<(), VerifyError> {
        match fs::read_to_string(&self.file_path) {
            Ok(data) => {
                self.pins = serde_json::from_str(&data)?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self) -> Result<(), VerifyError> {
        if let Some(dir) = self.file_path.parent() {
            fs::create_dir_all(dir)?;
        }
        let data = serde_json::to_string_pretty(&self.pins)?;
        fs::write(&self.file_path, data)?;
        Ok(())
    }
}

fn hash_public_key(pub_key: &PublicKey) -> String {
    let hash = Sha256::digest(public_key_to_bytes(pub_key));
    hex::encode(hash)
}

// Inline hex encoding to avoid adding a dependency
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    use tempfile::TempDir;

    #[test]
    fn new_verifier_in_empty_dir_has_no_pins() {
        let dir = TempDir::new().unwrap();
        let kv = KeyVerifier::new(dir.path()).unwrap();
        assert!(!kv.is_pinned("dev-1"));
        // No file is created until something is pinned
        assert!(!dir.path().join("pinned_keys.json").exists());
    }

    #[test]
    fn verify_unpinned_device_is_not_pinned_error() {
        let dir = TempDir::new().unwrap();
        let kv = KeyVerifier::new(dir.path()).unwrap();
        let kp = KeyPair::generate();
        assert!(matches!(
            kv.verify_pinned("dev-1", &kp.public),
            Err(VerifyError::NotPinned)
        ));
    }

    #[test]
    fn pin_after_approval_then_verify() {
        let dir = TempDir::new().unwrap();
        let mut kv = KeyVerifier::new(dir.path()).unwrap();
        let kp = KeyPair::generate();

        kv.pin_after_approval("dev-1", &kp.public).unwrap();
        assert!(kv.is_pinned("dev-1"));
        kv.verify_pinned("dev-1", &kp.public).unwrap();

        // A different key for the same device is a hard failure
        let other = KeyPair::generate();
        assert!(matches!(
            kv.verify_pinned("dev-1", &other.public),
            Err(VerifyError::KeyChanged)
        ));
    }

    #[test]
    fn pins_persist_across_instances() {
        let dir = TempDir::new().unwrap();
        let kp = KeyPair::generate();
        {
            let mut kv = KeyVerifier::new(dir.path()).unwrap();
            kv.pin_after_approval("dev-1", &kp.public).unwrap();
        }
        assert!(dir.path().join("pinned_keys.json").is_file());

        let kv = KeyVerifier::new(dir.path()).unwrap();
        assert!(kv.is_pinned("dev-1"));
        kv.verify_pinned("dev-1", &kp.public).unwrap();
    }

    #[test]
    fn pinned_file_stores_sha256_hex_of_public_key() {
        let dir = TempDir::new().unwrap();
        let kp = KeyPair::generate();
        let mut kv = KeyVerifier::new(dir.path()).unwrap();
        kv.pin_after_approval("dev-1", &kp.public).unwrap();

        let raw = fs::read_to_string(dir.path().join("pinned_keys.json")).unwrap();
        let pins: HashMap<String, String> = serde_json::from_str(&raw).unwrap();
        let stored = &pins["dev-1"];
        assert_eq!(stored.len(), 64);
        assert_eq!(stored, &hash_public_key(&kp.public));
        assert_eq!(*stored, hex::encode(Sha256::digest(kp.public_key_bytes())));
    }

    #[test]
    fn migrate_legacy_pins_when_absent_and_verifies_when_present() {
        let dir = TempDir::new().unwrap();
        let mut kv = KeyVerifier::new(dir.path()).unwrap();
        let kp = KeyPair::generate();

        // First sight of a legacy device pins it
        kv.migrate_legacy("legacy", &kp.public).unwrap();
        assert!(kv.is_pinned("legacy"));

        // Same key again is fine
        kv.migrate_legacy("legacy", &kp.public).unwrap();

        // A changed key is rejected and the original pin is kept
        let other = KeyPair::generate();
        assert!(matches!(
            kv.migrate_legacy("legacy", &other.public),
            Err(VerifyError::KeyChanged)
        ));
        kv.verify_pinned("legacy", &kp.public).unwrap();
    }

    #[test]
    fn remove_pin_forgets_device_and_persists() {
        let dir = TempDir::new().unwrap();
        let kp = KeyPair::generate();
        let mut kv = KeyVerifier::new(dir.path()).unwrap();
        kv.pin_after_approval("dev-1", &kp.public).unwrap();
        kv.remove_pin("dev-1").unwrap();
        assert!(!kv.is_pinned("dev-1"));

        let reloaded = KeyVerifier::new(dir.path()).unwrap();
        assert!(!reloaded.is_pinned("dev-1"));
        // Removing an unknown pin is a no-op
        let mut reloaded = reloaded;
        reloaded.remove_pin("nope").unwrap();
    }

    #[test]
    fn corrupt_pin_file_is_a_json_error() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("pinned_keys.json"), "not json").unwrap();
        assert!(matches!(
            KeyVerifier::new(dir.path()),
            Err(VerifyError::Json(_))
        ));
    }

    #[test]
    fn new_creates_missing_config_dir_on_first_pin() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("fresh");
        let mut kv = KeyVerifier::new(&nested).unwrap();
        kv.pin_after_approval("dev-1", &KeyPair::generate().public)
            .unwrap();
        assert!(nested.join("pinned_keys.json").is_file());
    }
}
