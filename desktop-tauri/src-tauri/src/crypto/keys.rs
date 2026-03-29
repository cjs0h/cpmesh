use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier};
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand::rngs::OsRng;
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
    /// Creates a new random ECDH P-256 key pair.
    pub fn generate() -> Self {
        let private = SecretKey::random(&mut OsRng);
        let public = private.public_key();
        KeyPair { private, public }
    }

    /// Returns the public key as uncompressed SEC1 bytes for transmission.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Parses raw SEC1 bytes into a public key.
    pub fn parse_public_key(data: &[u8]) -> Result<PublicKey, KeyError> {
        let point = EncodedPoint::from_bytes(data)
            .map_err(|e| KeyError::InvalidKey(format!("invalid encoded point: {e}")))?;
        Option::from(PublicKey::from_encoded_point(&point))
            .ok_or_else(|| KeyError::InvalidKey("invalid public key point".into()))
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
        let bytes = public_key.to_encoded_point(false);
        let hash = Sha256::digest(bytes.as_bytes());
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
        let pub_bytes = self.public_key_bytes();
        let hash = Sha256::digest(&pub_bytes);
        let signature: Signature = signing_key.sign(&hash);
        signature.to_der().as_bytes().to_vec()
    }

    /// Verifies that a public key was self-signed by its owner.
    pub fn verify_public_key_signature(public_key: &PublicKey, signature: &[u8]) -> Result<(), KeyError> {
        let verifying_key = VerifyingKey::from(public_key);
        let sig = Signature::from_der(signature)
            .map_err(|e| KeyError::InvalidKey(format!("invalid signature format: {e}")))?;
        let pub_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
        let hash = Sha256::digest(&pub_bytes);
        verifying_key.verify(&hash, &sig)
            .map_err(|_| KeyError::InvalidKey("invalid public key signature: key may have been tampered with".into()))
    }
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
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // ECDH shared secret
    let shared_secret = diffie_hellman(
        our_private.to_nonzero_scalar(),
        peer_public.as_affine(),
    );
    let secret_bytes = shared_secret.raw_secret_bytes();

    // Salt = SHA256(sorted concatenation of both public keys)
    // Sort to ensure both sides produce the same salt regardless of who is approver/pending
    let our_bytes = our_public.to_encoded_point(false).as_bytes().to_vec();
    let peer_bytes = peer_public.to_encoded_point(false).as_bytes().to_vec();

    let combined = if our_bytes <= peer_bytes {
        [our_bytes.as_slice(), peer_bytes.as_slice()].concat()
    } else {
        [peer_bytes.as_slice(), our_bytes.as_slice()].concat()
    };

    let salt = Sha256::digest(&combined);

    // HKDF derivation
    let hk = Hkdf::<Sha256>::new(Some(&salt), &secret_bytes);
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
    use std::path::PathBuf;
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
    fn test_parse_public_key_roundtrip() {
        let kp = KeyPair::generate();
        let bytes = kp.public_key_bytes();
        let parsed = KeyPair::parse_public_key(&bytes).unwrap();
        assert_eq!(
            kp.public.to_encoded_point(false),
            parsed.to_encoded_point(false)
        );
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
    fn test_load_or_generate() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("device.key");

        // First call generates
        let kp1 = KeyPair::load_or_generate(&path).unwrap();
        // Second call loads
        let kp2 = KeyPair::load_or_generate(&path).unwrap();
        assert_eq!(kp1.private.to_bytes(), kp2.private.to_bytes());
    }
}
