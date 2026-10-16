use p256::PublicKey;
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroize;

#[cfg(test)]
use super::encrypt::generate_group_key;
use super::encrypt::{
    CryptoError, decrypt, decrypt_group_key, derive_key_from_group_key, encrypt, encrypt_group_key,
    fill_random,
};
use super::keys::KeyPair;

/// A group key encrypted for a specific peer device: `(device_id, encrypted_key)`.
#[cfg(test)]
pub type WrappedKey = (String, Vec<u8>);

/// Manages versioned group keys for a user's devices.
/// Supports multiple key versions to allow decryption of historical clipboard entries
/// while ensuring forward secrecy for newly approved devices.
#[derive(Clone)]
pub struct KeyExchange {
    key_pair: KeyPair,
    pub current_version: i32,
    pub keys_by_version: BTreeMap<i32, Vec<u8>>,
}

impl Drop for KeyExchange {
    fn drop(&mut self) {
        for key in self.keys_by_version.values_mut() {
            key.zeroize();
        }
    }
}

impl KeyExchange {
    pub fn new(key_pair: KeyPair) -> Self {
        KeyExchange {
            key_pair,
            current_version: 0,
            keys_by_version: BTreeMap::new(),
        }
    }

    /// Generates a new group key as version 1 (called by the first device in an account).
    #[cfg(test)]
    pub fn init_group_key(&mut self) {
        let key = generate_group_key().to_vec();
        self.current_version = 1;
        self.keys_by_version.insert(1, key);
    }

    /// Add a key version to the keyring.
    pub fn add_key_version(&mut self, version: i32, key: Vec<u8>) -> Result<(), CryptoError> {
        if version < 1 || key.len() != 32 {
            return Err(CryptoError::Decrypt(
                "invalid group key version or length".into(),
            ));
        }
        if self
            .keys_by_version
            .get(&version)
            .is_some_and(|existing| *existing != key)
        {
            return Err(CryptoError::Decrypt(
                "refusing to replace existing key material".into(),
            ));
        }
        if version > self.current_version {
            self.current_version = version;
        }
        self.keys_by_version.insert(version, key);
        Ok(())
    }

    /// Returns true if any group key is available.
    #[cfg(test)]
    pub fn has_group_key(&self) -> bool {
        !self.keys_by_version.is_empty()
    }

    /// Returns the current group key (latest version).
    fn current_key(&self) -> Result<&[u8], CryptoError> {
        self.keys_by_version
            .get(&self.current_version)
            .map(|k| k.as_slice())
            .ok_or_else(|| CryptoError::Encrypt("no current group key".into()))
    }

    /// Returns the group key for a specific version.
    fn key_for_version(&self, version: i32) -> Result<&[u8], CryptoError> {
        self.keys_by_version
            .get(&version)
            .map(|k| k.as_slice())
            .ok_or_else(|| CryptoError::Decrypt(format!("no group key for version {version}")))
    }

    /// Encrypts the current group key for a specific device's public key.
    #[cfg(test)]
    pub fn encrypt_for_device(&self, peer_public_key: &PublicKey) -> Result<Vec<u8>, CryptoError> {
        let gk = self.current_key()?;
        encrypt_group_key(gk, &self.key_pair.private, peer_public_key)
    }

    /// Encrypts a specific key version for a device (used during rotation/approval).
    #[allow(dead_code)]
    pub fn encrypt_version_for_device(
        &self,
        version: i32,
        peer_public_key: &PublicKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let gk = self.key_for_version(version)?;
        encrypt_group_key(gk, &self.key_pair.private, peer_public_key)
    }

    /// Decrypts a group key received from another device and adds it at the given version.
    pub fn decrypt_from_device(
        &mut self,
        encrypted_key: &[u8],
        peer_public_key: &PublicKey,
        version: i32,
    ) -> Result<(), CryptoError> {
        let gk = decrypt_group_key(encrypted_key, &self.key_pair.private, peer_public_key)?;
        self.add_key_version(version, gk)
    }

    /// Generates the next group key version and returns wrapped keys for all provided devices.
    /// Returns `(new_version, wrapped_keys)`.
    #[cfg(test)]
    pub fn generate_next_version(
        &mut self,
        peer_devices: &[(String, PublicKey)],
    ) -> Result<(i32, Vec<WrappedKey>), CryptoError> {
        let new_version = self.current_version + 1;
        let new_key = generate_group_key().to_vec();

        let mut wrapped = Vec::new();
        for (device_id, pub_key) in peer_devices {
            let encrypted = encrypt_group_key(&new_key, &self.key_pair.private, pub_key)?;
            wrapped.push((device_id.clone(), encrypted));
        }

        self.add_key_version(new_version, new_key)?;
        Ok((new_version, wrapped))
    }

    /// Encrypts clipboard data with the current group key version.
    /// Returns (encrypted_data, key_version).
    pub fn encrypt_payload(&self, plaintext: &[u8]) -> Result<(Vec<u8>, i32), CryptoError> {
        let gk = self.current_key()?;
        let mut salt = [0u8; 16];
        fill_random(&mut salt);
        let key = derive_key_from_group_key(gk, &salt)?;
        let encrypted = encrypt(&key, plaintext)?;
        let mut result = Vec::with_capacity(16 + encrypted.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&encrypted);
        Ok((result, self.current_version))
    }

    /// Decrypts clipboard data using the key version specified.
    pub fn decrypt_payload(&self, ciphertext: &[u8], version: i32) -> Result<Vec<u8>, CryptoError> {
        let gk = self.key_for_version(version)?;
        if ciphertext.len() < 16 {
            return Err(CryptoError::CiphertextTooShort);
        }
        let salt = &ciphertext[..16];
        let encrypted = &ciphertext[16..];
        let key = derive_key_from_group_key(gk, salt)?;
        decrypt(&key, encrypted)
    }

    /// Backward-compatible: decrypt without explicit version (uses current version).
    pub fn decrypt_payload_legacy(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Try current version first, then try all versions
        if let Ok(result) = self.decrypt_payload(ciphertext, self.current_version) {
            return Ok(result);
        }
        for (&version, _) in self.keys_by_version.iter().rev() {
            if version == self.current_version {
                continue;
            }
            if let Ok(result) = self.decrypt_payload(ciphertext, version) {
                return Ok(result);
            }
        }
        Err(CryptoError::Decrypt(
            "no key version could decrypt this payload".into(),
        ))
    }

    /// Save the keyring to an encrypted file.
    /// KEK = HKDF(device_private_key_bytes, random_salt, "cpnet-keyring-v1")
    pub fn save_keyring(&self, path: &Path) -> Result<(), CryptoError> {
        use serde_json::json;

        let keyring_data = json!({
            "current_version": self.current_version,
            "keys": self.keys_by_version.iter().map(|(v, k)| {
                (v.to_string(), serde_json::Value::String(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k)))
            }).collect::<serde_json::Map<String, serde_json::Value>>(),
        });
        let plaintext = serde_json::to_vec(&keyring_data)
            .map_err(|e| CryptoError::Encrypt(format!("serialize keyring: {e}")))?;

        // Derive KEK from device private key
        let private_bytes = self.key_pair.private.to_bytes();
        let mut salt = [0u8; 16];
        fill_random(&mut salt);

        let kek =
            super::encrypt::derive_key_from_secret(&private_bytes, &salt, b"cpnet-keyring-v1")?;
        let encrypted = encrypt(&kek, &plaintext)?;

        // File format: [16-byte salt] + [encrypted keyring]
        let mut output = Vec::with_capacity(16 + encrypted.len());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&encrypted);

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| CryptoError::Encrypt(format!("create dir: {e}")))?;
        }
        super::keys::write_private_file(path, &output)
            .map_err(|e| CryptoError::Encrypt(format!("write keyring: {e}")))?;
        Ok(())
    }

    /// Load the keyring from an encrypted file.
    pub fn load_keyring(&mut self, path: &Path) -> Result<(), CryptoError> {
        let data =
            std::fs::read(path).map_err(|e| CryptoError::Decrypt(format!("read keyring: {e}")))?;
        if data.len() < 16 {
            return Err(CryptoError::CiphertextTooShort);
        }

        let salt = &data[..16];
        let encrypted = &data[16..];

        let private_bytes = self.key_pair.private.to_bytes();
        let kek =
            super::encrypt::derive_key_from_secret(&private_bytes, salt, b"cpnet-keyring-v1")?;
        let plaintext = decrypt(&kek, encrypted)?;

        #[derive(serde::Deserialize)]
        struct SavedKeyring {
            current_version: i32,
            keys: BTreeMap<i32, String>,
        }
        let keyring_data: SavedKeyring = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::Decrypt(format!("deserialize keyring: {e}")))?;

        let mut restored = BTreeMap::new();
        for (version, value) in keyring_data.keys {
            let key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
                .map_err(|e| CryptoError::Decrypt(format!("invalid saved key: {e}")))?;
            if version < 1
                || key.len() != 32
                || version > keyring_data.current_version
                || self
                    .keys_by_version
                    .get(&version)
                    .is_some_and(|existing| *existing != key)
            {
                return Err(CryptoError::Decrypt(
                    "invalid or conflicting saved keyring".into(),
                ));
            }
            restored.insert(version, key);
        }
        if !restored.contains_key(&keyring_data.current_version) {
            return Err(CryptoError::Decrypt(
                "saved keyring has no active key".into(),
            ));
        }
        for (version, key) in restored {
            self.add_key_version(version, key)?;
        }

        Ok(())
    }

    /// Returns a reference to the key pair.
    #[allow(dead_code)]
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_key_exchange_flow() {
        let kp_a = KeyPair::generate();
        let kp_b = KeyPair::generate();
        let pub_a = kp_a.public;
        let pub_b = kp_b.public;

        let mut exch_a = KeyExchange::new(kp_a);
        let mut exch_b = KeyExchange::new(kp_b);

        // Device A creates the group key
        exch_a.init_group_key();
        assert_eq!(exch_a.current_version, 1);

        // Device A encrypts group key for device B
        let enc_gk = exch_a.encrypt_for_device(&pub_b).unwrap();

        // Device B receives and decrypts
        exch_b.decrypt_from_device(&enc_gk, &pub_a, 1).unwrap();
        assert_eq!(exch_b.current_version, 1);

        // Both can encrypt/decrypt clipboard data
        let payload = b"Hello from device A";
        let (encrypted, version) = exch_a.encrypt_payload(payload).unwrap();
        assert_eq!(version, 1);
        let decrypted = exch_b.decrypt_payload(&encrypted, 1).unwrap();
        assert_eq!(payload.to_vec(), decrypted);

        // And the other direction
        let payload2 = b"Reply from device B";
        let (enc2, v2) = exch_b.encrypt_payload(payload2).unwrap();
        assert_eq!(v2, 1);
        let dec2 = exch_a.decrypt_payload(&enc2, 1).unwrap();
        assert_eq!(payload2.to_vec(), dec2);
    }

    #[test]
    fn test_versioned_key_rotation() {
        let kp_a = KeyPair::generate();
        let kp_b = KeyPair::generate();
        let pub_b = kp_b.public;

        let mut exch_a = KeyExchange::new(kp_a);
        exch_a.init_group_key();

        // Encrypt with v1
        let (enc_v1, v) = exch_a.encrypt_payload(b"version 1 data").unwrap();
        assert_eq!(v, 1);

        // Rotate to v2
        let peers = vec![("device-b".to_string(), pub_b)];
        let (new_version, _wrapped) = exch_a.generate_next_version(&peers).unwrap();
        assert_eq!(new_version, 2);
        assert_eq!(exch_a.current_version, 2);

        // New data uses v2
        let (enc_v2, v) = exch_a.encrypt_payload(b"version 2 data").unwrap();
        assert_eq!(v, 2);

        // Can still decrypt v1
        let dec_v1 = exch_a.decrypt_payload(&enc_v1, 1).unwrap();
        assert_eq!(dec_v1, b"version 1 data");

        // Can decrypt v2
        let dec_v2 = exch_a.decrypt_payload(&enc_v2, 2).unwrap();
        assert_eq!(dec_v2, b"version 2 data");
    }

    #[test]
    fn test_encrypt_without_group_key() {
        let kp = KeyPair::generate();
        let exch = KeyExchange::new(kp);
        assert!(!exch.has_group_key());
        assert!(exch.encrypt_payload(b"test").is_err());
        assert!(
            exch.decrypt_payload(b"0123456789abcdef_ciphertext", 1)
                .is_err()
        );
        assert!(
            exch.decrypt_payload_legacy(b"0123456789abcdef_ciphertext")
                .is_err()
        );
    }

    #[test]
    fn test_decrypt_payload_too_short() {
        let kp = KeyPair::generate();
        let mut exch = KeyExchange::new(kp);
        exch.init_group_key();
        assert!(matches!(
            exch.decrypt_payload(&[0u8; 15], 1),
            Err(CryptoError::CiphertextTooShort)
        ));
    }

    #[test]
    fn test_decrypt_payload_wrong_version_fails() {
        let kp = KeyPair::generate();
        let mut exch = KeyExchange::new(kp);
        exch.init_group_key();
        let (enc, v) = exch.encrypt_payload(b"hello").unwrap();
        assert_eq!(v, 1);
        // Version 2 does not exist in the keyring
        assert!(exch.decrypt_payload(&enc, 2).is_err());
    }

    #[test]
    fn test_decrypt_payload_legacy_tries_all_versions() {
        let kp = KeyPair::generate();
        let mut exch = KeyExchange::new(kp);
        exch.init_group_key();
        let (enc_v1, _) = exch.encrypt_payload(b"old data").unwrap();

        let peer = KeyPair::generate();
        exch.generate_next_version(&[("peer".to_string(), peer.public)])
            .unwrap();
        assert_eq!(exch.current_version, 2);

        // Legacy decrypt should fall back to v1 for data encrypted before rotation
        assert_eq!(exch.decrypt_payload_legacy(&enc_v1).unwrap(), b"old data");

        // And still handle current-version data
        let (enc_v2, _) = exch.encrypt_payload(b"new data").unwrap();
        assert_eq!(exch.decrypt_payload_legacy(&enc_v2).unwrap(), b"new data");
    }

    #[test]
    fn test_add_key_version_tracks_highest_version() {
        let kp = KeyPair::generate();
        let mut exch = KeyExchange::new(kp);
        exch.add_key_version(3, vec![3u8; 32]).unwrap();
        assert_eq!(exch.current_version, 3);
        // Adding an older version must not lower the current version
        exch.add_key_version(1, vec![1u8; 32]).unwrap();
        assert_eq!(exch.current_version, 3);
        assert_eq!(exch.keys_by_version.len(), 2);
    }

    #[test]
    fn test_generate_next_version_wraps_for_all_peers() {
        let kp_a = KeyPair::generate();
        let kp_b = KeyPair::generate();
        let kp_c = KeyPair::generate();
        let mut exch_a = KeyExchange::new(kp_a);
        exch_a.init_group_key();

        let peers = vec![
            ("device-b".to_string(), kp_b.public),
            ("device-c".to_string(), kp_c.public),
        ];
        let (version, wrapped) = exch_a.generate_next_version(&peers).unwrap();
        assert_eq!(version, 2);
        assert_eq!(wrapped.len(), 2);
        assert_eq!(wrapped[0].0, "device-b");
        assert_eq!(wrapped[1].0, "device-c");

        // Each peer can unwrap its copy and ends up with the same v2 key
        let pub_a = exch_a.key_pair().public;
        let mut exch_b = KeyExchange::new(kp_b);
        exch_b
            .decrypt_from_device(&wrapped[0].1, &pub_a, version)
            .unwrap();
        let mut exch_c = KeyExchange::new(kp_c);
        exch_c
            .decrypt_from_device(&wrapped[1].1, &pub_a, version)
            .unwrap();
        assert_eq!(exch_b.keys_by_version[&2], exch_c.keys_by_version[&2]);
        assert_eq!(exch_b.keys_by_version[&2], exch_a.keys_by_version[&2]);
    }

    #[test]
    fn test_encrypt_version_for_device() {
        let kp_a = KeyPair::generate();
        let kp_b = KeyPair::generate();
        let pub_a = kp_a.public;
        let pub_b = kp_b.public;
        let mut exch_a = KeyExchange::new(kp_a);
        exch_a.init_group_key();
        exch_a
            .generate_next_version(&[("b".to_string(), pub_b)])
            .unwrap();

        // Explicitly wrap the OLD version for device B
        let wrapped_v1 = exch_a.encrypt_version_for_device(1, &pub_b).unwrap();
        let mut exch_b = KeyExchange::new(kp_b);
        exch_b.decrypt_from_device(&wrapped_v1, &pub_a, 1).unwrap();
        assert_eq!(exch_b.keys_by_version[&1], exch_a.keys_by_version[&1]);

        // Unknown version is an error
        assert!(exch_a.encrypt_version_for_device(99, &pub_b).is_err());
    }

    #[test]
    fn test_decrypt_from_device_with_wrong_peer_key_fails() {
        let kp_a = KeyPair::generate();
        let kp_b = KeyPair::generate();
        let kp_mallory = KeyPair::generate();
        let pub_b = kp_b.public;
        let mut exch_a = KeyExchange::new(kp_a);
        exch_a.init_group_key();
        let wrapped = exch_a.encrypt_for_device(&pub_b).unwrap();

        let mut exch_b = KeyExchange::new(kp_b);
        // B believes the key came from Mallory — ECDH shared secret differs, decryption fails
        assert!(
            exch_b
                .decrypt_from_device(&wrapped, &kp_mallory.public, 1)
                .is_err()
        );
        assert!(!exch_b.has_group_key());
    }

    #[test]
    fn test_keyring_persistence() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("device.key");
        let keyring_path = dir.path().join("keyring.enc");

        // Same device key must be used to save and load the keyring
        let kp = KeyPair::load_or_generate(&key_path).unwrap();
        let mut exch = KeyExchange::new(kp);
        exch.init_group_key();

        // Rotate to create version 2
        let kp_b = KeyPair::generate();
        let peers = vec![("b".to_string(), kp_b.public)];
        exch.generate_next_version(&peers).unwrap();
        let (ciphertext, _) = exch.encrypt_payload(b"persisted").unwrap();

        exch.save_keyring(&keyring_path).unwrap();
        assert!(keyring_path.exists());

        // Load into a fresh KeyExchange backed by the same device key
        let kp_again = KeyPair::load_or_generate(&key_path).unwrap();
        let mut restored = KeyExchange::new(kp_again);
        assert!(!restored.has_group_key());
        restored.load_keyring(&keyring_path).unwrap();

        assert_eq!(restored.current_version, 2);
        assert_eq!(restored.keys_by_version, exch.keys_by_version);
        assert_eq!(
            restored.decrypt_payload(&ciphertext, 2).unwrap(),
            b"persisted"
        );
    }

    #[test]
    fn test_keyring_cannot_be_loaded_with_other_device_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let keyring_path = dir.path().join("keyring.enc");

        let mut exch = KeyExchange::new(KeyPair::generate());
        exch.init_group_key();
        exch.save_keyring(&keyring_path).unwrap();

        let mut other = KeyExchange::new(KeyPair::generate());
        assert!(other.load_keyring(&keyring_path).is_err());
        assert!(!other.has_group_key());
    }

    #[test]
    fn test_load_keyring_rejects_truncated_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let keyring_path = dir.path().join("keyring.enc");
        std::fs::write(&keyring_path, [0u8; 8]).unwrap();

        let mut exch = KeyExchange::new(KeyPair::generate());
        assert!(matches!(
            exch.load_keyring(&keyring_path),
            Err(CryptoError::CiphertextTooShort)
        ));
    }
}
