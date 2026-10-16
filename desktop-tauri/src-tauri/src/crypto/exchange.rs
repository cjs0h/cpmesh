use p256::PublicKey;
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroize;

#[cfg(test)]
use super::encrypt::generate_group_key;
#[cfg(test)]
use super::encrypt::wrap_group_key_v3;
use super::encrypt::{
    CryptoError, decrypt, decrypt_group_key, decrypt_with_aad, derive_key_from_group_key, encrypt,
    encrypt_with_aad, fill_random, unwrap_group_key_v3,
};
use super::keys::{DeviceKeys, KeyPair};

/// Manages versioned group keys for a user's devices.
/// Supports multiple key versions to allow decryption of historical clipboard entries
/// while ensuring forward secrecy for newly approved devices.
#[derive(Clone)]
pub struct KeyExchange {
    keys: DeviceKeys,
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
    pub fn new(keys: DeviceKeys) -> Self {
        KeyExchange {
            keys,
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

    /// Wraps a key version for one recipient's certified encryption key (v3,
    /// ephemeral-static). Production wraps go through `membership::signed_wraps`.
    #[cfg(test)]
    pub fn wrap_version_for(
        &self,
        version: i32,
        sender_id: &str,
        recipient_id: &str,
        recipient_encryption_key: &PublicKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let gk = self.key_for_version(version)?;
        wrap_group_key_v3(
            gk,
            recipient_encryption_key,
            &cpmesh_proto::models::wrap_aad(version, sender_id, recipient_id),
        )
    }

    /// Imports a wrap addressed to this device and records it at `version`.
    /// v3 wraps open with the encryption key; legacy 60-byte wraps (created before
    /// the upgrade) open with the identity key, as they always did.
    pub fn import_wrapped(
        &mut self,
        encrypted_key: &[u8],
        sender_identity_key: &PublicKey,
        sender_id: &str,
        own_id: &str,
        version: i32,
    ) -> Result<(), CryptoError> {
        let gk = match encrypted_key.len() {
            cpmesh_proto::models::WRAP_V3_LEN => unwrap_group_key_v3(
                encrypted_key,
                &self.keys.encryption.private,
                &cpmesh_proto::models::wrap_aad(version, sender_id, own_id),
            )?,
            cpmesh_proto::models::WRAP_LEGACY_LEN => decrypt_group_key(
                encrypted_key,
                &self.keys.identity.private,
                sender_identity_key,
            )?,
            other => {
                return Err(CryptoError::Decrypt(format!(
                    "unexpected wrapped key length {other}"
                )));
            }
        };
        self.add_key_version(version, gk)
    }

    /// Encrypts clipboard data with the current group key version, bound to `aad`.
    /// Returns (encrypted_data, key_version).
    pub fn encrypt_payload(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, i32), CryptoError> {
        let gk = self.current_key()?;
        let mut salt = [0u8; 16];
        fill_random(&mut salt);
        let key = derive_key_from_group_key(gk, &salt)?;
        let encrypted = encrypt_with_aad(&key, plaintext, aad)?;
        let mut result = Vec::with_capacity(16 + encrypted.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&encrypted);
        Ok((result, self.current_version))
    }

    /// Decrypts clipboard data using the key version specified and the same `aad`.
    pub fn decrypt_payload(
        &self,
        ciphertext: &[u8],
        version: i32,
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let gk = self.key_for_version(version)?;
        if ciphertext.len() < 16 {
            return Err(CryptoError::CiphertextTooShort);
        }
        let salt = &ciphertext[..16];
        let encrypted = &ciphertext[16..];
        let key = derive_key_from_group_key(gk, salt)?;
        decrypt_with_aad(&key, encrypted, aad)
    }

    /// Legacy (pre-v3) entries carry no AAD and may be labelled with the wrong
    /// version: try the hint, then every version. Only for history display.
    pub fn decrypt_payload_legacy(
        &self,
        ciphertext: &[u8],
        version_hint: i32,
    ) -> Result<Vec<u8>, CryptoError> {
        if let Ok(result) = self.decrypt_payload(ciphertext, version_hint, &[]) {
            return Ok(result);
        }
        for (&version, _) in self.keys_by_version.iter().rev() {
            if version == version_hint {
                continue;
            }
            if let Ok(result) = self.decrypt_payload(ciphertext, version, &[]) {
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

        // Derive KEK from the identity private key
        let private_bytes = self.keys.identity.private.to_bytes();
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

        let private_bytes = self.keys.identity.private.to_bytes();
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

    /// The identity (signing) key pair.
    pub fn key_pair(&self) -> &KeyPair {
        &self.keys.identity
    }

    /// Both long-term keys.
    pub fn keys(&self) -> &DeviceKeys {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "00000000-0000-4000-8000-00000000000a";
    const B: &str = "00000000-0000-4000-8000-00000000000b";
    const C: &str = "00000000-0000-4000-8000-00000000000c";

    #[test]
    fn test_full_key_exchange_flow() {
        let keys_a = DeviceKeys::generate();
        let keys_b = DeviceKeys::generate();
        let id_a = keys_a.identity.public;
        let enc_b = keys_b.encryption.public;

        let mut exch_a = KeyExchange::new(keys_a);
        let mut exch_b = KeyExchange::new(keys_b);

        // Device A creates the group key and wraps it for B's encryption key
        exch_a.init_group_key();
        assert_eq!(exch_a.current_version, 1);
        let wrapped = exch_a.wrap_version_for(1, A, B, &enc_b).unwrap();
        assert_eq!(wrapped.len(), cpmesh_proto::models::WRAP_V3_LEN);

        // Device B receives and unwraps
        exch_b.import_wrapped(&wrapped, &id_a, A, B, 1).unwrap();
        assert_eq!(exch_b.current_version, 1);

        // Both can encrypt/decrypt clipboard data under the same AAD
        let aad = b"ctx";
        let (encrypted, version) = exch_a.encrypt_payload(b"Hello from device A", aad).unwrap();
        assert_eq!(version, 1);
        assert_eq!(
            exch_b.decrypt_payload(&encrypted, 1, aad).unwrap(),
            b"Hello from device A"
        );
        // …and a different AAD does not open it
        assert!(exch_b.decrypt_payload(&encrypted, 1, b"other").is_err());

        let (enc2, v2) = exch_b.encrypt_payload(b"Reply from device B", aad).unwrap();
        assert_eq!(v2, 1);
        assert_eq!(
            exch_a.decrypt_payload(&enc2, 1, aad).unwrap(),
            b"Reply from device B"
        );
    }

    #[test]
    fn wrap_is_bound_to_version_and_parties() {
        let keys_a = DeviceKeys::generate();
        let keys_b = DeviceKeys::generate();
        let id_a = keys_a.identity.public;
        let enc_b = keys_b.encryption.public;
        let mut exch_a = KeyExchange::new(keys_a);
        exch_a.init_group_key();
        let wrapped = exch_a.wrap_version_for(1, A, B, &enc_b).unwrap();

        let mut exch_b = KeyExchange::new(keys_b.clone());
        // Relabelled version, sender or recipient all fail to open.
        assert!(exch_b.import_wrapped(&wrapped, &id_a, A, B, 2).is_err());
        assert!(exch_b.import_wrapped(&wrapped, &id_a, C, B, 1).is_err());
        assert!(exch_b.import_wrapped(&wrapped, &id_a, A, C, 1).is_err());
        assert!(!exch_b.has_group_key());
        // The identity key cannot open a v3 wrap even if presented as the encryption key.
        let mut swapped = KeyExchange::new(DeviceKeys {
            identity: keys_b.encryption.clone(),
            encryption: keys_b.identity.clone(),
        });
        assert!(swapped.import_wrapped(&wrapped, &id_a, A, B, 1).is_err());
        exch_b.import_wrapped(&wrapped, &id_a, A, B, 1).unwrap();
        assert!(exch_b.has_group_key());
    }

    #[test]
    fn legacy_static_wraps_still_import_with_the_identity_key() {
        let keys_a = DeviceKeys::generate();
        let keys_b = DeviceKeys::generate();
        let group_key = generate_group_key();
        let legacy = super::super::encrypt::encrypt_group_key(
            &group_key,
            &keys_a.identity.private,
            &keys_b.identity.public,
        )
        .unwrap();
        assert_eq!(legacy.len(), cpmesh_proto::models::WRAP_LEGACY_LEN);
        let mut exch_b = KeyExchange::new(keys_b);
        exch_b
            .import_wrapped(&legacy, &keys_a.identity.public, A, B, 1)
            .unwrap();
        assert_eq!(exch_b.keys_by_version[&1], group_key);
        // Any other length is rejected outright.
        assert!(
            exch_b
                .import_wrapped(&[0u8; 61], &keys_a.identity.public, A, B, 2)
                .is_err()
        );
    }

    #[test]
    fn test_versioned_key_rotation() {
        let mut exch_a = KeyExchange::new(DeviceKeys::generate());
        exch_a.init_group_key();
        let (enc_v1, v) = exch_a.encrypt_payload(b"version 1 data", b"a").unwrap();
        assert_eq!(v, 1);

        exch_a
            .add_key_version(2, generate_group_key().to_vec())
            .unwrap();
        assert_eq!(exch_a.current_version, 2);
        let (enc_v2, v) = exch_a.encrypt_payload(b"version 2 data", b"a").unwrap();
        assert_eq!(v, 2);

        assert_eq!(
            exch_a.decrypt_payload(&enc_v1, 1, b"a").unwrap(),
            b"version 1 data"
        );
        assert_eq!(
            exch_a.decrypt_payload(&enc_v2, 2, b"a").unwrap(),
            b"version 2 data"
        );
        // The AAD pins the version: v1 data labelled v2 does not open.
        assert!(exch_a.decrypt_payload(&enc_v1, 2, b"a").is_err());
    }

    #[test]
    fn test_encrypt_without_group_key() {
        let exch = KeyExchange::new(DeviceKeys::generate());
        assert!(!exch.has_group_key());
        assert!(exch.encrypt_payload(b"test", b"").is_err());
        assert!(
            exch.decrypt_payload(b"0123456789abcdef_ciphertext", 1, b"")
                .is_err()
        );
        assert!(
            exch.decrypt_payload_legacy(b"0123456789abcdef_ciphertext", 1)
                .is_err()
        );
    }

    #[test]
    fn test_decrypt_payload_too_short() {
        let mut exch = KeyExchange::new(DeviceKeys::generate());
        exch.init_group_key();
        assert!(matches!(
            exch.decrypt_payload(&[0u8; 15], 1, b""),
            Err(CryptoError::CiphertextTooShort)
        ));
    }

    #[test]
    fn test_decrypt_payload_legacy_tries_all_versions() {
        let mut exch = KeyExchange::new(DeviceKeys::generate());
        exch.init_group_key();
        let (enc_v1, _) = exch.encrypt_payload(b"old data", b"").unwrap();
        exch.add_key_version(2, generate_group_key().to_vec())
            .unwrap();
        assert_eq!(exch.current_version, 2);
        assert_eq!(
            exch.decrypt_payload_legacy(&enc_v1, 2).unwrap(),
            b"old data"
        );
        let (enc_v2, _) = exch.encrypt_payload(b"new data", b"").unwrap();
        assert_eq!(
            exch.decrypt_payload_legacy(&enc_v2, 2).unwrap(),
            b"new data"
        );
        // v3 entries (non-empty AAD) are never opened by the legacy path.
        let (enc_aad, _) = exch.encrypt_payload(b"bound", b"ctx").unwrap();
        assert!(exch.decrypt_payload_legacy(&enc_aad, 2).is_err());
    }

    #[test]
    fn test_add_key_version_tracks_highest_version() {
        let mut exch = KeyExchange::new(DeviceKeys::generate());
        exch.add_key_version(3, vec![3u8; 32]).unwrap();
        assert_eq!(exch.current_version, 3);
        exch.add_key_version(1, vec![1u8; 32]).unwrap();
        assert_eq!(exch.current_version, 3);
        assert_eq!(exch.keys_by_version.len(), 2);
        assert!(exch.add_key_version(3, vec![4u8; 32]).is_err());
    }

    #[test]
    fn test_keyring_persistence() {
        let dir = tempfile::TempDir::new().unwrap();
        let keyring_path = dir.path().join("keyring.enc");
        let keys = DeviceKeys::generate();

        let mut exch = KeyExchange::new(keys.clone());
        exch.init_group_key();
        exch.add_key_version(2, generate_group_key().to_vec())
            .unwrap();
        let (ciphertext, _) = exch.encrypt_payload(b"persisted", b"p").unwrap();
        exch.save_keyring(&keyring_path).unwrap();
        assert!(keyring_path.exists());

        // The keyring is bound to the identity key; the encryption key may differ.
        let mut restored = KeyExchange::new(DeviceKeys {
            identity: keys.identity.clone(),
            encryption: KeyPair::generate(),
        });
        assert!(!restored.has_group_key());
        restored.load_keyring(&keyring_path).unwrap();
        assert_eq!(restored.current_version, 2);
        assert_eq!(restored.keys_by_version, exch.keys_by_version);
        assert_eq!(
            restored.decrypt_payload(&ciphertext, 2, b"p").unwrap(),
            b"persisted"
        );
    }

    #[test]
    fn test_keyring_cannot_be_loaded_with_other_device_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let keyring_path = dir.path().join("keyring.enc");
        let mut exch = KeyExchange::new(DeviceKeys::generate());
        exch.init_group_key();
        exch.save_keyring(&keyring_path).unwrap();
        let mut other = KeyExchange::new(DeviceKeys::generate());
        assert!(other.load_keyring(&keyring_path).is_err());
        assert!(!other.has_group_key());
    }

    #[test]
    fn test_load_keyring_rejects_truncated_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let keyring_path = dir.path().join("keyring.enc");
        std::fs::write(&keyring_path, [0u8; 8]).unwrap();
        let mut exch = KeyExchange::new(DeviceKeys::generate());
        assert!(matches!(
            exch.load_keyring(&keyring_path),
            Err(CryptoError::CiphertextTooShort)
        ));
    }
}
