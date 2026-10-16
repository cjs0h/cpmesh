use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use hkdf::Hkdf;
use p256::elliptic_curve::Generate;
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
    encrypt_with_aad(key, plaintext, &[])
}

/// AES-256-GCM with associated data: the ciphertext only opens in the same
/// context (`aad`) it was sealed in. Layout: nonce(12) || ciphertext || tag(16).
pub fn encrypt_with_aad(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce_bytes = [0u8; 12];
    fill_random(&mut nonce_bytes);
    encrypt_with_nonce(key, &nonce_bytes, plaintext, aad)
}

/// Deterministic variant for golden vectors; callers must never reuse a nonce
/// under the same key.
pub fn encrypt_with_nonce(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::Encrypt(format!("create cipher: {e}")))?;
    let nonce = GcmNonce::from(*nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::Encrypt(format!("seal: {e}")))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts data produced by encrypt() — nonce (12 bytes) + ciphertext.
/// Matches Go Decrypt().
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    decrypt_with_aad(key, data, &[])
}

/// Opens nonce(12) || ciphertext || tag(16) sealed with [`encrypt_with_aad`].
pub fn decrypt_with_aad(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
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
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| CryptoError::Decrypt(format!("open: {e}")))
}

/// Generates a random 256-bit group key.
pub fn generate_group_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    fill_random(&mut key);
    key
}

/// Legacy (protocol ≤ 2) wrap: static-static ECDH between two identity keys.
/// Only used by tests and to read wraps created before the upgrade.
#[cfg(test)]
pub fn encrypt_group_key(
    group_key: &[u8],
    private_key: &SecretKey,
    peer_public_key: &PublicKey,
) -> Result<Vec<u8>, CryptoError> {
    let shared_key = derive_shared_key(private_key, peer_public_key, b"group-key-wrap")?;
    encrypt(&shared_key, group_key)
}

/// Opens a legacy static-static wrap with this device's identity key.
pub fn decrypt_group_key(
    encrypted_group_key: &[u8],
    private_key: &SecretKey,
    peer_public_key: &PublicKey,
) -> Result<Vec<u8>, CryptoError> {
    let shared_key = derive_shared_key(private_key, peer_public_key, b"group-key-wrap")?;
    decrypt(&shared_key, encrypted_group_key)
}

/// Key for a v3 wrap: ECDH between an ephemeral key and the recipient's static
/// encryption key, with both public keys bound into the HKDF salt. `private` and
/// `dh_peer` are (ephemeral, recipient) when wrapping and (recipient, ephemeral)
/// when unwrapping; the salt is the same on both sides.
fn derive_wrap_key_v3(
    private: &SecretKey,
    dh_peer: &PublicKey,
    ephemeral_public: &PublicKey,
    recipient_encryption_key: &PublicKey,
) -> Result<[u8; 32], CryptoError> {
    use sha2::Digest;
    let shared = diffie_hellman(private.to_nonzero_scalar(), dh_peer.as_affine());
    let mut salt = Sha256::new();
    salt.update(b"cpmesh-wrap-v3");
    salt.update(super::keys::public_key_to_bytes(ephemeral_public));
    salt.update(super::keys::public_key_to_bytes(recipient_encryption_key));
    derive_key(
        shared.raw_secret_bytes(),
        &salt.finalize(),
        b"cpmesh-group-key-wrap-v3",
    )
}

/// Wraps a group key for one recipient with a fresh ephemeral key, so a later
/// compromise of the sender's long-term keys does not open past wraps.
/// Layout: ephemeral public key(65) || nonce(12) || ciphertext(32) || tag(16).
pub fn wrap_group_key_v3(
    group_key: &[u8],
    recipient_encryption_key: &PublicKey,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; 12];
    fill_random(&mut nonce);
    wrap_group_key_v3_deterministic(
        group_key,
        &SecretKey::generate(),
        &nonce,
        recipient_encryption_key,
        aad,
    )
}

/// [`wrap_group_key_v3`] with caller-supplied ephemeral key and nonce (vectors).
pub fn wrap_group_key_v3_deterministic(
    group_key: &[u8],
    ephemeral_private: &SecretKey,
    nonce: &[u8; 12],
    recipient_encryption_key: &PublicKey,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral_public = ephemeral_private.public_key();
    let key = derive_wrap_key_v3(
        ephemeral_private,
        recipient_encryption_key,
        &ephemeral_public,
        recipient_encryption_key,
    )?;
    let sealed = encrypt_with_nonce(&key, nonce, group_key, aad)?;
    let mut blob = super::keys::public_key_to_bytes(&ephemeral_public);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Opens a v3 wrap with this device's static encryption key.
pub fn unwrap_group_key_v3(
    blob: &[u8],
    encryption_private: &SecretKey,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if blob.len() != cpmesh_proto::models::WRAP_V3_LEN {
        return Err(CryptoError::Decrypt(format!(
            "unexpected wrap length {}",
            blob.len()
        )));
    }
    let ephemeral_public = super::keys::KeyPair::parse_public_key(&blob[..65])
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    let key = derive_wrap_key_v3(
        encryption_private,
        &ephemeral_public,
        &ephemeral_public,
        &encryption_private.public_key(),
    )?;
    decrypt_with_aad(&key, &blob[65..], aad)
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

    #[test]
    fn aad_binds_ciphertext_to_its_context() {
        let key = [7u8; 32];
        let sealed = encrypt_with_aad(&key, b"secret", b"context-a").unwrap();
        assert_eq!(
            decrypt_with_aad(&key, &sealed, b"context-a").unwrap(),
            b"secret"
        );
        assert!(decrypt_with_aad(&key, &sealed, b"context-b").is_err());
        assert!(decrypt_with_aad(&key, &sealed, b"").is_err());
        // Plain encrypt() is encrypt_with_aad() with empty AAD.
        let plain = encrypt(&key, b"secret").unwrap();
        assert_eq!(decrypt_with_aad(&key, &plain, b"").unwrap(), b"secret");
    }

    #[test]
    fn v3_wrap_is_ephemeral_and_bound_to_recipient_and_aad() {
        let recipient = crate::crypto::keys::KeyPair::generate();
        let group_key = generate_group_key();
        let aad = b"cpmesh-wrap-v3\n1\nsender\nrecipient\n";
        let blob_1 = wrap_group_key_v3(&group_key, &recipient.public, aad).unwrap();
        let blob_2 = wrap_group_key_v3(&group_key, &recipient.public, aad).unwrap();
        assert_eq!(blob_1.len(), cpmesh_proto::models::WRAP_V3_LEN);
        // A fresh ephemeral key every time: no two wraps share a prefix.
        assert_ne!(blob_1[..65], blob_2[..65]);
        assert_eq!(
            unwrap_group_key_v3(&blob_1, &recipient.private, aad).unwrap(),
            group_key
        );
        assert_eq!(
            unwrap_group_key_v3(&blob_2, &recipient.private, aad).unwrap(),
            group_key
        );
        // Wrong recipient key, wrong AAD, tampered blob and bad lengths all fail.
        let other = crate::crypto::keys::KeyPair::generate();
        assert!(unwrap_group_key_v3(&blob_1, &other.private, aad).is_err());
        assert!(unwrap_group_key_v3(&blob_1, &recipient.private, b"other").is_err());
        let mut tampered = blob_1.clone();
        tampered[100] ^= 1;
        assert!(unwrap_group_key_v3(&tampered, &recipient.private, aad).is_err());
        assert!(unwrap_group_key_v3(&blob_1[1..], &recipient.private, aad).is_err());
        let mut bad_point = blob_1.clone();
        bad_point[1] ^= 0xFF;
        assert!(unwrap_group_key_v3(&bad_point, &recipient.private, aad).is_err());
    }

    #[test]
    fn v3_wrap_is_deterministic_given_ephemeral_key_and_nonce() {
        let recipient = crate::crypto::keys::KeyPair::generate();
        let ephemeral = SecretKey::generate();
        let nonce = [9u8; 12];
        let group_key = generate_group_key();
        let a = wrap_group_key_v3_deterministic(
            &group_key,
            &ephemeral,
            &nonce,
            &recipient.public,
            b"x",
        )
        .unwrap();
        let b = wrap_group_key_v3_deterministic(
            &group_key,
            &ephemeral,
            &nonce,
            &recipient.public,
            b"x",
        )
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(
            a[..65],
            crate::crypto::keys::public_key_to_bytes(&ephemeral.public_key())[..]
        );
    }
}
