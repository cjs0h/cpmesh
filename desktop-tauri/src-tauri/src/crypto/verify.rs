use p256::PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

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
    pub fn pin_after_approval(&mut self, device_id: &str, public_key: &PublicKey) -> Result<(), VerifyError> {
        let hash = hash_public_key(public_key);
        self.pins.insert(device_id.to_string(), hash);
        self.save()
    }

    /// Verify a pinned device's public key hasn't changed.
    /// Returns Err(NotPinned) if the device was never approved.
    /// Returns Err(KeyChanged) if the key differs from the pinned value.
    #[allow(dead_code)]
    pub fn verify_pinned(&self, device_id: &str, public_key: &PublicKey) -> Result<(), VerifyError> {
        let hash = hash_public_key(public_key);
        match self.pins.get(device_id) {
            None => Err(VerifyError::NotPinned),
            Some(pinned) if *pinned == hash => Ok(()),
            Some(_) => Err(VerifyError::KeyChanged),
        }
    }

    /// Migrate a legacy device that was already approved under the old TOFU model.
    /// Pins the key if not already pinned. If already pinned, verifies the key matches.
    pub fn migrate_legacy(&mut self, device_id: &str, public_key: &PublicKey) -> Result<(), VerifyError> {
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
    let bytes = pub_key.to_encoded_point(false);
    let hash = Sha256::digest(bytes.as_bytes());
    hex::encode(hash)
}

// Inline hex encoding to avoid adding a dependency
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}
