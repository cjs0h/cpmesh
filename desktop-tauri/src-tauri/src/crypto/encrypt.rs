use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce};
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman};
use rand::TryRng;
use sha2::Sha256;
use thiserror::Error;

type GcmNonce = Nonce<Aes256Gcm>;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("HKDF derivation failed")]
    Hkdf,
    #[error("Encryption failed: {0}")]
    Encrypt(String),
    #[error("Decryption failed: {0}")]
    Decrypt(String),
    #[error("Ciphertext too short")]
    CiphertextTooShort,
}

/// Fills `buf` with bytes from the operating system's CSPRNG.
///
/// Used for nonces, salts and key material. Panics only if the OS RNG is
/// unavailable, which mirrors the behaviour of the former `OsRng`.
pub fn fill_random(buf: &mut [u8]) {
    rand::rngs::SysRng
        .try_fill_bytes(buf)
        .expect("operating system RNG failure");
}

/// Derives a shared AES-256 key from ECDH key exchange + HKDF.
/// Matches Go: DeriveSharedKey(privateKey, peerPublicKey, salt)
pub fn derive_shared_key(
    private_key: &SecretKey,
    peer_public_key: &PublicKey,
    salt: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let shared_secret =
        diffie_hellman(private_key.to_nonzero_scalar(), peer_public_key.as_affine());
    let secret_bytes = shared_secret.raw_secret_bytes();
    derive_key(secret_bytes, salt, b"cpmesh-clipboard-v1")
}

/// Derives an AES-256 key from a group key + salt.
/// Matches Go: DeriveKeyFromGroupKey(groupKey, salt)
pub fn derive_key_from_group_key(group_key: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    derive_key(group_key, salt, b"cpmesh-group-v1")
}

/// Derives an AES-256 key from arbitrary secret material + salt + info.
/// Used for keyring encryption KEK and other derived-key scenarios.
pub fn derive_key_from_secret(
    secret: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], CryptoError> {
    derive_key(secret, salt, info)
}

fn derive_key(secret: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key).map_err(|_| CryptoError::Hkdf)?;
    Ok(key)
}

/// Encrypts plaintext using AES-256-GCM.
/// Returns nonce (12 bytes) + ciphertext concatenated — matches Go Encrypt().
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::Encrypt(format!("create cipher: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    fill_random(&mut nonce_bytes);
    let nonce = GcmNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encrypt(format!("seal: {e}")))?;

    // Prepend nonce to ciphertext (same as Go: gcm.Seal(nonce, nonce, plaintext, nil))
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts data produced by encrypt() — nonce (12 bytes) + ciphertext.
/// Matches Go Decrypt().
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::CiphertextTooShort);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::Decrypt(format!("create cipher: {e}")))?;

    let nonce_arr: [u8; 12] = data[..12]
        .try_into()
        .map_err(|_| CryptoError::CiphertextTooShort)?;
    let nonce = GcmNonce::from(nonce_arr);
    let ciphertext = &data[12..];

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| CryptoError::Decrypt(format!("open: {e}")))
}

/// Generates a random 256-bit group key.
pub fn generate_group_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    fill_random(&mut key);
    key
}

/// Encrypts the group key for a specific device using ECDH shared key.
/// Matches Go: EncryptGroupKey(groupKey, privateKey, peerPublicKey)
pub fn encrypt_group_key(
    group_key: &[u8],
    private_key: &SecretKey,
    peer_public_key: &PublicKey,
) -> Result<Vec<u8>, CryptoError> {
    let shared_key = derive_shared_key(private_key, peer_public_key, b"group-key-wrap")?;
    encrypt(&shared_key, group_key)
}

/// Decrypts the group key received from another device.
/// Matches Go: DecryptGroupKey(encryptedGroupKey, privateKey, peerPublicKey)
pub fn decrypt_group_key(
    encrypted_group_key: &[u8],
    private_key: &SecretKey,
    peer_public_key: &PublicKey,
) -> Result<Vec<u8>, CryptoError> {
    let shared_key = derive_shared_key(private_key, peer_public_key, b"group-key-wrap")?;
    decrypt(&shared_key, encrypted_group_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let plaintext = b"Hello, cpmesh! This is a test message.";
        let encrypted = encrypt(&key, plaintext).unwrap();
        assert_ne!(&encrypted[12..], plaintext);
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let key = [0u8; 32];
        let plaintext = b"";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        key2[0] = 0xFF;
        let encrypted = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn test_decrypt_tampered() {
        let key = [0u8; 32];
        let mut encrypted = encrypt(&key, b"secret").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn test_ecdh_shared_key() {
        let kp_a = crate::crypto::keys::KeyPair::generate();
        let kp_b = crate::crypto::keys::KeyPair::generate();
        let salt = b"test-salt";
        let key_a = derive_shared_key(&kp_a.private, &kp_b.public, salt).unwrap();
        let key_b = derive_shared_key(&kp_b.private, &kp_a.public, salt).unwrap();
        assert_eq!(key_a, key_b);

        // Cross-device encrypt/decrypt
        let plaintext = b"cross-device clipboard content";
        let encrypted = encrypt(&key_a, plaintext).unwrap();
        let decrypted = decrypt(&key_b, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_group_key_encrypt_decrypt() {
        let kp_a = crate::crypto::keys::KeyPair::generate();
        let kp_b = crate::crypto::keys::KeyPair::generate();

        let group_key = generate_group_key();
        let encrypted = encrypt_group_key(&group_key, &kp_a.private, &kp_b.public).unwrap();
        let decrypted = decrypt_group_key(&encrypted, &kp_b.private, &kp_a.public).unwrap();
        assert_eq!(group_key.to_vec(), decrypted);

        // Both derive same payload key
        let pk_a = derive_key_from_group_key(&group_key, b"clipboard-payload").unwrap();
        let pk_b = derive_key_from_group_key(&decrypted, b"clipboard-payload").unwrap();
        assert_eq!(pk_a, pk_b);

        // Cross-device payload encrypt/decrypt
        let msg = b"shared clipboard text";
        let enc = encrypt(&pk_a, msg).unwrap();
        let dec = decrypt(&pk_b, &enc).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn test_large_payload() {
        let group_key = generate_group_key();
        let payload_key = derive_key_from_group_key(&group_key, b"clipboard-payload").unwrap();

        // 5MB payload
        let payload: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 256) as u8).collect();
        let encrypted = encrypt(&payload_key, &payload).unwrap();
        let decrypted = decrypt(&payload_key, &encrypted).unwrap();
        assert_eq!(payload, decrypted);
    }
}
