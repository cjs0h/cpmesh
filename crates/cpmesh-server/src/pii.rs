use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type GcmNonce = Nonce<Aes256Gcm>;

/// Decodes a base64 key that must be exactly 32 bytes.
fn decode_key(value_b64: &str, name: &str) -> Result<[u8; 32], String> {
    let bytes = STANDARD
        .decode(value_b64)
        .map_err(|e| format!("decode {name}: {e}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be exactly 32 bytes (got {len})"))
}

pub struct PiiService {
    encryption_key: [u8; 32],
    hmac_key: [u8; 32],
}

impl PiiService {
    pub fn new(encryption_key_b64: &str, hmac_key_b64: &str) -> Result<Self, String> {
        Ok(PiiService {
            encryption_key: decode_key(encryption_key_b64, "PII_MASTER_KEY")?,
            hmac_key: decode_key(hmac_key_b64, "PII_HMAC_KEY")?,
        })
    }

    /// Encrypts plaintext using AES-256-GCM.
    /// Returns base64-encoded: [12-byte nonce] + [ciphertext+tag]
    pub fn encrypt(&self, plaintext: &str) -> Result<String, String> {
        if plaintext.is_empty() {
            return Ok(String::new());
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| format!("create cipher: {e}"))?;

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = GcmNonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| format!("encrypt: {e}"))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(STANDARD.encode(&result))
    }

    /// Decrypts base64-encoded ciphertext produced by encrypt().
    pub fn decrypt(&self, encoded: &str) -> Result<String, String> {
        if encoded.is_empty() {
            return Ok(String::new());
        }

        let data = STANDARD
            .decode(encoded)
            .map_err(|e| format!("base64 decode: {e}"))?;

        if data.len() < 12 {
            return Err("ciphertext too short".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| format!("create cipher: {e}"))?;

        let nonce_bytes: [u8; 12] = data[..12]
            .try_into()
            .map_err(|_| "invalid nonce length".to_string())?;
        let nonce = GcmNonce::from(nonce_bytes);
        let ciphertext = &data[12..];

        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| format!("decrypt: {e}"))?;

        String::from_utf8(plaintext).map_err(|e| format!("utf8: {e}"))
    }

    /// Computes a deterministic HMAC-SHA256 blind index for DB lookups on encrypted fields.
    pub fn blind_index(&self, value: &str) -> String {
        if value.is_empty() {
            return String::new();
        }
        let normalized = value.trim().to_lowercase();
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("Failed to create HMAC key");
        mac.update(normalized.as_bytes());
        let result = mac.finalize();
        result
            .into_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let pii = PiiService::new(
            "q88dhm/y/vHc80+0LxAr8OFZwMfkPChvdR9UTMztn5I=",
            "/aowWex7ni3uUnazmQk+rn6GPvb9lQFaSNIPlpiRAM0=",
        )
        .unwrap();

        let plaintext = "test@example.com";
        let encrypted = pii.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        let decrypted = pii.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_string() {
        let pii = PiiService::new(
            "q88dhm/y/vHc80+0LxAr8OFZwMfkPChvdR9UTMztn5I=",
            "/aowWex7ni3uUnazmQk+rn6GPvb9lQFaSNIPlpiRAM0=",
        )
        .unwrap();
        assert_eq!(pii.encrypt("").unwrap(), "");
        assert_eq!(pii.decrypt("").unwrap(), "");
    }

    #[test]
    fn test_blind_index_deterministic() {
        let pii = PiiService::new(
            "q88dhm/y/vHc80+0LxAr8OFZwMfkPChvdR9UTMztn5I=",
            "/aowWex7ni3uUnazmQk+rn6GPvb9lQFaSNIPlpiRAM0=",
        )
        .unwrap();
        let idx1 = pii.blind_index("Test@Example.COM");
        let idx2 = pii.blind_index("test@example.com");
        assert_eq!(idx1, idx2);
        assert_eq!(idx1.len(), 64); // hex-encoded SHA-256
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    use crate::test_support::{TEST_PII_HMAC_KEY, TEST_PII_MASTER_KEY};

    fn err_of(r: Result<PiiService, String>) -> String {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        }
    }

    fn pii() -> PiiService {
        PiiService::new(TEST_PII_MASTER_KEY, TEST_PII_HMAC_KEY).unwrap()
    }

    #[test]
    fn new_rejects_invalid_base64() {
        let err = err_of(PiiService::new("not base64!", TEST_PII_HMAC_KEY));
        assert!(err.contains("decode PII_MASTER_KEY"), "{err}");
        let err = err_of(PiiService::new(TEST_PII_MASTER_KEY, "***"));
        assert!(err.contains("decode PII_HMAC_KEY"), "{err}");
    }

    #[test]
    fn new_rejects_wrong_key_lengths() {
        let short = STANDARD.encode([0u8; 16]);
        let err = err_of(PiiService::new(&short, TEST_PII_HMAC_KEY));
        assert!(
            err.contains("PII_MASTER_KEY must be exactly 32 bytes (got 16)"),
            "{err}"
        );
        let long = STANDARD.encode([0u8; 64]);
        let err = err_of(PiiService::new(TEST_PII_MASTER_KEY, &long));
        assert!(
            err.contains("PII_HMAC_KEY must be exactly 32 bytes (got 64)"),
            "{err}"
        );
    }

    #[test]
    fn ciphertext_is_randomized_and_base64() {
        let p = pii();
        let a = p.encrypt("same plaintext").unwrap();
        let b = p.encrypt("same plaintext").unwrap();
        assert_ne!(a, b, "a fresh nonce is used for every encryption");
        let raw = STANDARD.decode(&a).unwrap();
        // 12-byte nonce + plaintext + 16-byte GCM tag
        assert_eq!(raw.len(), 12 + "same plaintext".len() + 16);
        assert_eq!(p.decrypt(&a).unwrap(), "same plaintext");
        assert_eq!(p.decrypt(&b).unwrap(), "same plaintext");
    }

    #[test]
    fn decrypt_with_other_key_fails() {
        let encrypted = pii().encrypt("secret@example.com").unwrap();
        let other_master = STANDARD.encode([7u8; 32]);
        let other = PiiService::new(&other_master, TEST_PII_HMAC_KEY).unwrap();
        let err = other.decrypt(&encrypted).unwrap_err();
        assert!(err.starts_with("decrypt:"), "{err}");
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let p = pii();
        let encrypted = p.encrypt("secret@example.com").unwrap();
        let mut raw = STANDARD.decode(&encrypted).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        assert!(p.decrypt(&STANDARD.encode(&raw)).is_err());
    }

    #[test]
    fn decrypt_rejects_garbage_inputs() {
        let p = pii();
        assert!(
            p.decrypt("not base64!")
                .unwrap_err()
                .contains("base64 decode")
        );
        let short = STANDARD.encode([0u8; 5]);
        assert_eq!(p.decrypt(&short).unwrap_err(), "ciphertext too short");
    }

    #[test]
    fn handles_unicode_plaintext() {
        let p = pii();
        let text = "Ünïcødé 名前 😀";
        assert_eq!(p.decrypt(&p.encrypt(text).unwrap()).unwrap(), text);
    }

    #[test]
    fn blind_index_normalizes_and_discriminates() {
        let p = pii();
        assert_eq!(p.blind_index(""), "");
        assert_eq!(p.blind_index("  A@B.com "), p.blind_index("a@b.com"));
        assert_ne!(p.blind_index("a@b.com"), p.blind_index("b@b.com"));
        assert!(
            p.blind_index("x")
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        // Different HMAC key, different index
        let other_hmac = STANDARD.encode([9u8; 32]);
        let other = PiiService::new(TEST_PII_MASTER_KEY, &other_hmac).unwrap();
        assert_ne!(p.blind_index("a@b.com"), other.blind_index("a@b.com"));
    }
}
