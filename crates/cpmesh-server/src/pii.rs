use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct PiiService {
    encryption_key: [u8; 32],
    hmac_key: [u8; 32],
}

impl PiiService {
    pub fn new(encryption_key_b64: &str, hmac_key_b64: &str) -> Result<Self, String> {
        let enc_key = STANDARD.decode(encryption_key_b64)
            .map_err(|e| format!("decode PII_MASTER_KEY: {e}"))?;
        if enc_key.len() != 32 {
            return Err(format!("PII_MASTER_KEY must be exactly 32 bytes (got {})", enc_key.len()));
        }

        let hmac_key = STANDARD.decode(hmac_key_b64)
            .map_err(|e| format!("decode PII_HMAC_KEY: {e}"))?;
        if hmac_key.len() != 32 {
            return Err(format!("PII_HMAC_KEY must be exactly 32 bytes (got {})", hmac_key.len()));
        }

        let mut ek = [0u8; 32];
        ek.copy_from_slice(&enc_key);
        let mut hk = [0u8; 32];
        hk.copy_from_slice(&hmac_key);

        Ok(PiiService {
            encryption_key: ek,
            hmac_key: hk,
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
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())
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

        let data = STANDARD.decode(encoded)
            .map_err(|e| format!("base64 decode: {e}"))?;

        if data.len() < 12 {
            return Err("ciphertext too short".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| format!("create cipher: {e}"))?;

        let nonce_bytes: [u8; 12] = data[..12].try_into()
            .map_err(|_| "invalid nonce length".to_string())?;
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = &data[12..];

        let plaintext = cipher.decrypt(&nonce, ciphertext)
            .map_err(|e| format!("decrypt: {e}"))?;

        String::from_utf8(plaintext).map_err(|e| format!("utf8: {e}"))
    }

    /// Computes a deterministic HMAC-SHA256 blind index for DB lookups on encrypted fields.
    pub fn blind_index(&self, value: &str) -> String {
        if value.is_empty() {
            return String::new();
        }
        let normalized = value.trim().to_lowercase();
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(&self.hmac_key).expect("Failed to create HMAC key");
        mac.update(normalized.as_bytes());
        let result = mac.finalize();
        result.into_bytes().iter().map(|b| format!("{:02x}", b)).collect()
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
        ).unwrap();

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
        ).unwrap();
        assert_eq!(pii.encrypt("").unwrap(), "");
        assert_eq!(pii.decrypt("").unwrap(), "");
    }

    #[test]
    fn test_blind_index_deterministic() {
        let pii = PiiService::new(
            "q88dhm/y/vHc80+0LxAr8OFZwMfkPChvdR9UTMztn5I=",
            "/aowWex7ni3uUnazmQk+rn6GPvb9lQFaSNIPlpiRAM0=",
        ).unwrap();
        let idx1 = pii.blind_index("Test@Example.COM");
        let idx2 = pii.blind_index("test@example.com");
        assert_eq!(idx1, idx2);
        assert_eq!(idx1.len(), 64); // hex-encoded SHA-256
    }
}
