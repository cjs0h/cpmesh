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

/// Holds an ECDH P-256 key pair for E2E encryption.
pub struct KeyPair {
    pub private: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    /// Creates a new random ECDH P-256 key pair using the operating system's CSPRNG.
    pub fn generate() -> Self {
        let private = SecretKey::generate();
        let public = private.public_key();
        KeyPair { private, public }
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

    /// Saves the private key to a PEM file.
    pub fn save_private_key(&self, path: &Path) -> Result<(), KeyError> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let key_bytes = self.private.to_bytes();
        let pem_data = pem::Pem::new("ECDH PRIVATE KEY", &*key_bytes);
        let pem_str = pem::encode(&pem_data);
        fs::write(path, pem_str)?;
        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Loads a private key from a PEM file.
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

    /// Loads an existing key pair or generates a new one.
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

    /// Verifies that a public key was self-signed by its owner.
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

/// Derives an 8-digit approval code from an ECDH shared secret.
///
/// Both the approver and the pending device call this with their respective keys.
/// The code is derived entirely from the two public keys (via ECDH), so the server
/// cannot influence the result even if compromised.
///
/// Derivation: HKDF(ECDH(our_private, peer_public), salt=SHA256(sorted_pubkeys), info="cpnet-approval-v1")
pub fn derive_approval_code(
    our_private: &SecretKey,
    peer_public: &PublicKey,
    our_public: &PublicKey,
) -> Result<String, super::encrypt::CryptoError> {
    use hkdf::Hkdf;
    use p256::ecdh::diffie_hellman;

    // ECDH shared secret
    let shared_secret = diffie_hellman(our_private.to_nonzero_scalar(), peer_public.as_affine());
    let secret_bytes = shared_secret.raw_secret_bytes();

    // Salt = SHA256(sorted concatenation of both public keys)
    // Sort to ensure both sides produce the same salt regardless of who is approver/pending
    let our_bytes = public_key_to_bytes(our_public);
    let peer_bytes = public_key_to_bytes(peer_public);

    let combined = if our_bytes <= peer_bytes {
        [our_bytes.as_slice(), peer_bytes.as_slice()].concat()
    } else {
        [peer_bytes.as_slice(), our_bytes.as_slice()].concat()
    };

    let salt = Sha256::digest(&combined);

    // HKDF derivation
    let hk = Hkdf::<Sha256>::new(Some(&salt), secret_bytes);
    let mut derived = [0u8; 4];
    hk.expand(b"cpnet-approval-v1", &mut derived)
        .map_err(|_| super::encrypt::CryptoError::Hkdf)?;

    // Truncate to 8 decimal digits
    let code = u32::from_be_bytes(derived) % 100_000_000;
    Ok(format!("{:08}", code))
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
    fn test_approval_code_symmetric_and_8_digits() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let code_a = derive_approval_code(&a.private, &b.public, &a.public).unwrap();
        let code_b = derive_approval_code(&b.private, &a.public, &b.public).unwrap();
        assert_eq!(code_a, code_b);
        assert_eq!(code_a.len(), 8);
        assert!(code_a.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_approval_code_differs_for_different_peer() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let c = KeyPair::generate();
        let code_ab = derive_approval_code(&a.private, &b.public, &a.public).unwrap();
        let code_ac = derive_approval_code(&a.private, &c.public, &a.public).unwrap();
        assert_ne!(code_ab, code_ac);
    }
}
