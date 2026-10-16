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
    #[error("device was revoked; register a new identity instead of re-admitting the old one")]
    Revoked,
    #[error("invalid persisted membership state")]
    InvalidState,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Implements explicit trust pinning for device public keys.
///
/// Unlike TOFU (trust-on-first-use), keys are ONLY pinned after:
/// 1. Explicit full-fingerprint comparison on both devices
/// 2. A membership transition signed by an already authenticated member
///
/// Key changes after pinning are hard failures (possible MITM).
pub struct KeyVerifier {
    pins: HashMap<String, String>, // device_id -> hex(SHA-256(public_key))
    version: i32,
    revoked: HashMap<String, i64>,
    rotation_required: bool,
    file_path: PathBuf,
}

impl KeyVerifier {
    /// Creates a verifier that persists pinned keys to the given directory.
    pub fn new(config_dir: &Path) -> Result<Self, VerifyError> {
        // Old TOFU pins are deliberately not imported as authenticated membership.
        let file_path = config_dir.join("verified_keys.json");
        let mut kv = KeyVerifier {
            pins: HashMap::new(),
            version: 0,
            revoked: HashMap::new(),
            rotation_required: false,
            file_path,
        };
        kv.load()?;
        Ok(kv)
    }

    /// Pin a device's public key after successful approval.
    /// Never call this based only on relay-provided approval status.
    #[allow(dead_code)]
    pub fn pin_after_approval(
        &mut self,
        device_id: &str,
        public_key: &PublicKey,
    ) -> Result<(), VerifyError> {
        if self.revoked.contains_key(device_id) {
            return Err(VerifyError::Revoked);
        }
        let hash = hash_public_key(public_key);
        if self.pins.get(device_id).is_some_and(|old| *old != hash) {
            return Err(VerifyError::KeyChanged);
        }
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
        if self.revoked.contains_key(device_id) {
            return Err(VerifyError::Revoked);
        }
        self.verify_identity(device_id, public_key)
    }

    pub fn verify_sender_at(
        &self,
        device_id: &str,
        key: &PublicKey,
        version: i32,
    ) -> Result<(), VerifyError> {
        if self
            .revoked
            .get(device_id)
            .is_some_and(|epoch| i64::from(version) >= *epoch)
        {
            return Err(VerifyError::Revoked);
        }
        self.verify_identity(device_id, key)
    }

    fn verify_identity(&self, device_id: &str, public_key: &PublicKey) -> Result<(), VerifyError> {
        let hash = hash_public_key(public_key);
        match self.pins.get(device_id) {
            None => Err(VerifyError::NotPinned),
            Some(pinned) if *pinned == hash => Ok(()),
            Some(_) => Err(VerifyError::KeyChanged),
        }
    }

    pub fn accept_membership(
        &mut self,
        version: i32,
        members: &[cpmesh_proto::models::DeviceIdentity],
    ) -> Result<(), VerifyError> {
        if version < self.version {
            return Ok(());
        }
        let mut pins = HashMap::new();
        for member in members {
            if self
                .revoked
                .get(&member.id)
                .is_some_and(|epoch| i64::from(version) >= *epoch)
            {
                return Err(VerifyError::Revoked);
            }
            let key = super::keys::KeyPair::parse_public_key(&member.public_key)
                .map_err(|_| VerifyError::KeyChanged)?;
            let hash = hash_public_key(&key);
            if self.pins.get(&member.id).is_some_and(|old| *old != hash)
                || pins.insert(member.id.clone(), hash).is_some()
            {
                return Err(VerifyError::KeyChanged);
            }
        }
        if version == self.version {
            let active: HashMap<_, _> = self
                .pins
                .iter()
                .filter(|(id, _)| !self.revoked.contains_key(*id))
                .map(|(id, hash)| (id.clone(), hash.clone()))
                .collect();
            if !self.rotation_required && pins != active {
                return Err(VerifyError::KeyChanged);
            }
            return Ok(());
        }
        for id in self.pins.keys() {
            if !pins.contains_key(id) {
                self.revoked.entry(id.clone()).or_insert(i64::from(version));
            }
        }
        self.pins.extend(pins);
        self.version = version;
        self.rotation_required = false;
        self.save()
    }

    /// Check if a device is already pinned.
    #[allow(dead_code)]
    pub fn is_pinned(&self, device_id: &str) -> bool {
        self.pins.contains_key(device_id) && !self.revoked.contains_key(device_id)
    }

    pub fn has_peer(&self, own_id: &str) -> bool {
        self.pins
            .keys()
            .any(|id| id != own_id && !self.revoked.contains_key(id))
    }

    pub fn membership_version(&self) -> i32 {
        self.version
    }

    pub fn rotation_required(&self) -> bool {
        self.rotation_required
    }

    /// Keep the identity for historical verification, but never admit it again.
    #[allow(dead_code)]
    pub fn remove_pin(&mut self, device_id: &str) -> Result<(), VerifyError> {
        self.revoked
            .entry(device_id.to_string())
            .or_insert(i64::from(self.version) + 1);
        self.rotation_required = true;
        self.save()
    }

    fn load(&mut self) -> Result<(), VerifyError> {
        match fs::read_to_string(&self.file_path) {
            Ok(data) => {
                #[derive(serde::Deserialize)]
                struct Saved {
                    version: i32,
                    pins: HashMap<String, String>,
                    #[serde(default)]
                    revoked: HashMap<String, i64>,
                    #[serde(default)]
                    rotation_required: bool,
                }
                let saved: Saved = serde_json::from_str(&data)?;
                if saved.version < 0 || saved.revoked.values().any(|epoch| *epoch < 1) {
                    return Err(VerifyError::InvalidState);
                }
                self.pins = saved.pins;
                self.version = saved.version;
                self.revoked = saved.revoked;
                self.rotation_required = saved.rotation_required;
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
        let data = serde_json::to_vec(&serde_json::json!({
            "version": self.version, "pins": self.pins, "revoked": self.revoked,
            "rotation_required": self.rotation_required,
        }))?;
        super::keys::write_private_file(&self.file_path, &data)?;
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
        assert!(!dir.path().join("verified_keys.json").exists());
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
    fn legacy_tofu_pins_are_not_silently_promoted_to_membership() {
        let dir = TempDir::new().unwrap();
        let pair = KeyPair::generate();
        fs::write(
            dir.path().join("pinned_keys.json"),
            serde_json::json!({
                "invented-relay-id": hash_public_key(&pair.public),
            })
            .to_string(),
        )
        .unwrap();
        let verifier = KeyVerifier::new(dir.path()).unwrap();
        assert!(matches!(
            verifier.verify_pinned("invented-relay-id", &pair.public),
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
        assert!(dir.path().join("verified_keys.json").is_file());

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

        let raw = fs::read_to_string(dir.path().join("verified_keys.json")).unwrap();
        let saved: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let pins: HashMap<String, String> = serde_json::from_value(saved["pins"].clone()).unwrap();
        let stored = &pins["dev-1"];
        assert_eq!(stored.len(), 64);
        assert_eq!(stored, &hash_public_key(&kp.public));
        assert_eq!(*stored, hex::encode(Sha256::digest(kp.public_key_bytes())));
    }

    #[test]
    fn explicit_verification_never_overwrites_an_existing_identity() {
        let dir = TempDir::new().unwrap();
        let mut kv = KeyVerifier::new(dir.path()).unwrap();
        let kp = KeyPair::generate();

        // First sight of a legacy device pins it
        kv.pin_after_approval("legacy", &kp.public).unwrap();
        assert!(kv.is_pinned("legacy"));

        // Same key again is fine
        kv.pin_after_approval("legacy", &kp.public).unwrap();

        // A changed key is rejected and the original pin is kept
        let other = KeyPair::generate();
        assert!(matches!(
            kv.pin_after_approval("legacy", &other.public),
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
        fs::write(dir.path().join("verified_keys.json"), "not json").unwrap();
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
        assert!(nested.join("verified_keys.json").is_file());
    }
}
