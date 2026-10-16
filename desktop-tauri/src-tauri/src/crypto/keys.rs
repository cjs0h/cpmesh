use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PEM decode error: {0}")]
    PemDecode(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

/// Holds a P-256 key pair. Used as the device identity key (ECDSA only in
/// protocol v3) and, as a second independent instance, as the static ECDH
/// encryption key.
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub private: SecretKey,
    pub public: PublicKey,
}

/// The two long-term keys of a device: the identity key signs, the encryption
/// key receives ECDH wraps. Keeping them separate means no key is ever used by
/// two algorithms.
#[derive(Clone, Debug)]
pub struct DeviceKeys {
    pub identity: KeyPair,
    pub encryption: KeyPair,
}

impl DeviceKeys {
    #[cfg(test)]
    pub fn generate() -> Self {
        DeviceKeys {
            identity: KeyPair::generate(),
            encryption: KeyPair::generate(),
        }
    }

    /// Certifies the encryption key with the identity key so peers can verify it
    /// against the fingerprint they pinned, rather than trusting the relay.
    pub fn certify_encryption_key(&self) -> Vec<u8> {
        self.identity
            .sign_message(&cpmesh_proto::models::encryption_key_transcript(
                &self.identity.public_key_bytes(),
                &self.encryption.public_key_bytes(),
            ))
    }
}

/// Verifies that `encryption_key` was certified by the holder of `identity`.
pub fn verify_encryption_key(
    identity: &PublicKey,
    encryption_key: &[u8],
    signature: &[u8],
) -> Result<PublicKey, KeyError> {
    let key = KeyPair::parse_public_key(encryption_key)?;
    KeyPair::verify_message(
        identity,
        &cpmesh_proto::models::encryption_key_transcript(
            &public_key_to_bytes(identity),
            encryption_key,
        ),
        signature,
    )
    .map_err(|_| KeyError::InvalidKey("encryption key certification is invalid".into()))?;
    Ok(key)
}

impl KeyPair {
    /// Creates a new random ECDH P-256 key pair using the operating system's CSPRNG.
    pub fn generate() -> Self {
        let private = SecretKey::generate();
        let public = private.public_key();
        KeyPair { private, public }
    }

    /// Rebuilds a key pair from its 32-byte private scalar.
    pub fn from_scalar_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 32 {
            return Err(KeyError::InvalidKey(format!(
                "private scalar must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let private = SecretKey::from_slice(bytes)
            .map_err(|e| KeyError::InvalidKey(format!("invalid private key: {e}")))?;
        let public = private.public_key();
        Ok(KeyPair { private, public })
    }

    /// The 32-byte private scalar, for storage in the OS credential store.
    pub fn scalar_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.private.to_bytes().into())
    }

    /// Returns the public key as uncompressed SEC1 bytes for transmission.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        public_key_to_bytes(&self.public)
    }

    /// Parses raw SEC1 bytes into a public key.
    pub fn parse_public_key(data: &[u8]) -> Result<PublicKey, KeyError> {
        PublicKey::from_sec1_bytes(data)
            .map_err(|e| KeyError::InvalidKey(format!("invalid public key point: {e}")))
    }

    /// Saves the private key to a legacy PEM file (tests only; production keys
    /// live in the OS credential store, see `device_keys`).
    #[cfg(test)]
    pub fn save_private_key(&self, path: &Path) -> Result<(), KeyError> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let key_bytes = self.private.to_bytes();
        let pem_data = pem::Pem::new("ECDH PRIVATE KEY", &*key_bytes);
        let pem_str = pem::encode(&pem_data);
        write_private_file(path, pem_str.as_bytes())?;
        Ok(())
    }

    /// Loads a private key from a legacy PEM file (imported once into the store).
    pub fn load_private_key(path: &Path) -> Result<SecretKey, KeyError> {
        let data = fs::read_to_string(path)?;
        let pem_data =
            pem::parse(&data).map_err(|e| KeyError::PemDecode(format!("PEM parse: {e}")))?;
        if pem_data.tag() != "ECDH PRIVATE KEY" {
            return Err(KeyError::PemDecode(format!(
                "invalid PEM block type: {}",
                pem_data.tag()
            )));
        }
        SecretKey::from_slice(pem_data.contents())
            .map_err(|e| KeyError::InvalidKey(format!("invalid private key: {e}")))
    }

    /// Loads an existing key pair or generates a new one (legacy PEM, tests only).
    #[cfg(test)]
    pub fn load_or_generate(key_path: &Path) -> Result<Self, KeyError> {
        if key_path.exists() {
            let private = Self::load_private_key(key_path)?;
            let public = private.public_key();
            Ok(KeyPair { private, public })
        } else {
            let kp = Self::generate();
            kp.save_private_key(key_path)?;
            Ok(kp)
        }
    }

    /// Returns a human-readable SHA-256 fingerprint of the public key.
    /// Format: "AB:CD:EF:12:34:..." (32 hex pairs)
    pub fn fingerprint(public_key: &PublicKey) -> String {
        let hash = Sha256::digest(public_key_to_bytes(public_key));
        let mut fp = String::with_capacity(32 * 3 - 1);
        for (i, b) in hash.iter().enumerate() {
            if i > 0 {
                fp.push(':');
            }
            write!(fp, "{:02X}", b).expect("write to String cannot fail");
        }
        fp
    }

    /// Returns the first 8 bytes of the fingerprint for compact display.
    #[cfg(test)]
    pub fn short_fingerprint(public_key: &PublicKey) -> String {
        let fp = Self::fingerprint(public_key);
        let parts: Vec<&str> = fp.splitn(9, ':').collect();
        if parts.len() > 8 {
            parts[..8].join(":")
        } else {
            fp
        }
    }

    /// Signs this device's public key bytes using ECDSA-P256-SHA256.
    /// Proves the key was produced by the holder of the private key.
    pub fn sign_public_key(&self) -> Vec<u8> {
        let signing_key = SigningKey::from(&self.private);
        let hash = Sha256::digest(self.public_key_bytes());
        let signature: Signature = signing_key.sign(&hash);
        signature.to_der().as_bytes().to_vec()
    }

    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = SigningKey::from(&self.private).sign(message);
        signature.to_der().as_bytes().to_vec()
    }

    pub fn verify_message(
        public_key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), KeyError> {
        let signature =
            Signature::from_der(signature).map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        VerifyingKey::from(public_key)
            .verify(message, &signature)
            .map_err(|_| KeyError::InvalidKey("message signature is invalid".into()))
    }

    /// Verifies that a public key was self-signed by its owner.
    #[cfg(test)]
    pub fn verify_public_key_signature(
        public_key: &PublicKey,
        signature: &[u8],
    ) -> Result<(), KeyError> {
        let verifying_key = VerifyingKey::from(public_key);
        let sig = Signature::from_der(signature)
            .map_err(|e| KeyError::InvalidKey(format!("invalid signature format: {e}")))?;
        let hash = Sha256::digest(public_key_to_bytes(public_key));
        verifying_key.verify(&hash, &sig).map_err(|_| {
            KeyError::InvalidKey(
                "invalid public key signature: key may have been tampered with".into(),
            )
        })
    }
}

/// Encodes a public key as uncompressed SEC1 bytes (0x04 || X || Y, 65 bytes).
pub fn public_key_to_bytes(public_key: &PublicKey) -> Vec<u8> {
    public_key.to_sec1_point(false).as_bytes().to_vec()
}

/// Full 256-bit pairing code over both identity keys, compared through an
/// independent trusted channel on BOTH devices. It is a plain hash: in protocol
/// v3 the identity key never performs ECDH. Never shorten this without the
/// committed short-authentication-string protocol (`cpmesh_proto::models::sas_code`).
pub fn derive_approval_code(our_public: &PublicKey, peer_public: &PublicKey) -> String {
    cpmesh_proto::models::pairing_fingerprint(
        &public_key_to_bytes(our_public),
        &public_key_to_bytes(peer_public),
    )
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_key_pair() {
        let kp = KeyPair::generate();
        let bytes = kp.public_key_bytes();
        assert!(!bytes.is_empty());
        // Uncompressed P-256 public key is 65 bytes (0x04 + 32 + 32)
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
    }

    #[test]
    fn test_generated_key_pairs_are_unique() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
        assert_ne!(a.private.to_bytes(), b.private.to_bytes());
    }

    #[test]
    fn test_parse_public_key_roundtrip() {
        let kp = KeyPair::generate();
        let bytes = kp.public_key_bytes();
        let parsed = KeyPair::parse_public_key(&bytes).unwrap();
        assert_eq!(
            public_key_to_bytes(&kp.public),
            public_key_to_bytes(&parsed)
        );
    }

    #[test]
    fn test_parse_public_key_rejects_garbage() {
        assert!(KeyPair::parse_public_key(&[]).is_err());
        assert!(KeyPair::parse_public_key(&[0x04; 10]).is_err());
        // Right length, but not a point on the curve
        let mut bogus = vec![0x04u8];
        bogus.extend_from_slice(&[0xAB; 64]);
        assert!(KeyPair::parse_public_key(&bogus).is_err());
    }

    #[test]
    fn test_save_load_private_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.key");
        let kp = KeyPair::generate();
        kp.save_private_key(&path).unwrap();

        let loaded = KeyPair::load_private_key(&path).unwrap();
        assert_eq!(kp.private.to_bytes(), loaded.to_bytes());
    }

    #[test]
    fn test_save_private_key_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("deeper").join("device.key");
        KeyPair::generate().save_private_key(&path).unwrap();
        assert!(path.is_file());
    }

    #[test]
    fn test_load_private_key_rejects_wrong_pem_tag() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wrong.key");
        let pem_data = pem::Pem::new("RSA PRIVATE KEY", vec![1u8; 32]);
        fs::write(&path, pem::encode(&pem_data)).unwrap();
        let err = KeyPair::load_private_key(&path).unwrap_err();
        assert!(matches!(err, KeyError::PemDecode(_)), "{err}");
    }

    #[test]
    fn test_load_private_key_rejects_invalid_pem() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("garbage.key");
        fs::write(&path, "not a pem file").unwrap();
        assert!(matches!(
            KeyPair::load_private_key(&path),
            Err(KeyError::PemDecode(_))
        ));
    }

    #[test]
    fn test_load_private_key_rejects_invalid_scalar() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("zero.key");
        // An all-zero scalar is not a valid P-256 secret key.
        let pem_data = pem::Pem::new("ECDH PRIVATE KEY", vec![0u8; 32]);
        fs::write(&path, pem::encode(&pem_data)).unwrap();
        assert!(matches!(
            KeyPair::load_private_key(&path),
            Err(KeyError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_load_private_key_missing_file_is_io_error() {
        let dir = TempDir::new().unwrap();
        let err = KeyPair::load_private_key(&dir.path().join("missing.key")).unwrap_err();
        assert!(matches!(err, KeyError::Io(_)));
    }

    #[test]
    fn test_load_or_generate() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("device.key");

        // First call generates
        let kp1 = KeyPair::load_or_generate(&path).unwrap();
        // Second call loads
        let kp2 = KeyPair::load_or_generate(&path).unwrap();
        assert_eq!(kp1.private.to_bytes(), kp2.private.to_bytes());
    }

    #[test]
    fn test_fingerprint_format() {
        let kp = KeyPair::generate();
        let fp = KeyPair::fingerprint(&kp.public);
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 32);
        assert!(
            parts
                .iter()
                .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
        );
        assert_eq!(fp, fp.to_uppercase());
        // Deterministic for the same key
        assert_eq!(fp, KeyPair::fingerprint(&kp.public));
    }

    #[test]
    fn test_short_fingerprint_is_prefix() {
        let kp = KeyPair::generate();
        let fp = KeyPair::fingerprint(&kp.public);
        let short = KeyPair::short_fingerprint(&kp.public);
        assert_eq!(short.split(':').count(), 8);
        assert!(fp.starts_with(&short));
    }

    #[test]
    fn test_sign_and_verify_public_key() {
        let kp = KeyPair::generate();
        let sig = kp.sign_public_key();
        assert!(!sig.is_empty());
        KeyPair::verify_public_key_signature(&kp.public, &sig).unwrap();
    }

    #[test]
    fn test_verify_rejects_signature_from_other_key() {
        let kp = KeyPair::generate();
        let other = KeyPair::generate();
        let sig = other.sign_public_key();
        assert!(KeyPair::verify_public_key_signature(&kp.public, &sig).is_err());
    }

    #[test]
    fn test_verify_rejects_malformed_signature() {
        let kp = KeyPair::generate();
        assert!(KeyPair::verify_public_key_signature(&kp.public, b"nope").is_err());
    }

    #[test]
    fn pairing_fingerprint_is_symmetric_and_full_256_bits() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let code_a = derive_approval_code(&a.public, &b.public);
        let code_b = derive_approval_code(&b.public, &a.public);
        assert_eq!(code_a, code_b);
        assert_eq!(code_a.len(), 64);
        assert!(code_a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_approval_code_differs_for_different_peer() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let c = KeyPair::generate();
        let code_ab = derive_approval_code(&a.public, &b.public);
        let code_ac = derive_approval_code(&a.public, &c.public);
        assert_ne!(code_ab, code_ac);
    }

    #[test]
    fn scalar_roundtrip_preserves_the_key() {
        let kp = KeyPair::generate();
        let restored = KeyPair::from_scalar_bytes(kp.scalar_bytes().as_ref()).unwrap();
        assert_eq!(kp.public_key_bytes(), restored.public_key_bytes());
        assert!(KeyPair::from_scalar_bytes(&[0u8; 32]).is_err());
        assert!(KeyPair::from_scalar_bytes(&[1u8; 31]).is_err());
    }

    #[test]
    fn encryption_key_certification_binds_identity_and_key() {
        let keys = DeviceKeys::generate();
        let sig = keys.certify_encryption_key();
        let verified = verify_encryption_key(
            &keys.identity.public,
            &keys.encryption.public_key_bytes(),
            &sig,
        )
        .unwrap();
        assert_eq!(
            public_key_to_bytes(&verified),
            keys.encryption.public_key_bytes()
        );
        // Identity and encryption keys are distinct.
        assert_ne!(
            keys.identity.public_key_bytes(),
            keys.encryption.public_key_bytes()
        );
        // A relay cannot swap in its own encryption key…
        let mallory = KeyPair::generate();
        assert!(
            verify_encryption_key(&keys.identity.public, &mallory.public_key_bytes(), &sig)
                .is_err()
        );
        // …nor present a key certified by a different identity.
        assert!(
            verify_encryption_key(&mallory.public, &keys.encryption.public_key_bytes(), &sig)
                .is_err()
        );
        assert!(verify_encryption_key(&keys.identity.public, &[4u8; 65], &sig).is_err());
    }
}
