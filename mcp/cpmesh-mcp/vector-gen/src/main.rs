//! Golden-vector generator for the cpmesh-mcp TypeScript package.
//!
//! Includes the desktop client's crypto modules byte-for-byte via #[path] and
//! emits deterministic test vectors as JSON on stdout. Randomized parameters
//! (nonces, salts) are pinned to fixed values; where the real high-level API
//! draws randomness internally, the equivalent fixed-input construction is
//! used so the TS side can reproduce every byte.
//!
//! Regenerate after changing the desktop crypto:
//!   cargo run --release > ../test/vectors.json

// The desktop client's crypto modules, compiled verbatim. They refer to each
// other through `super::`, so they sit side by side at the crate root, where
// #[path] resolves from src/. (An inline module would resolve from the
// non-existent src/<module>/, which Linux refuses to traverse.)
#[path = "../../../../desktop-tauri/src-tauri/src/crypto/encrypt.rs"]
mod encrypt;
#[path = "../../../../desktop-tauri/src-tauri/src/crypto/exchange.rs"]
mod exchange;
#[path = "../../../../desktop-tauri/src-tauri/src/crypto/keys.rs"]
mod keys;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce};
use base64::Engine;
use p256::SecretKey;
use p256::ecdh::diffie_hellman;
use serde_json::json;

use encrypt::{derive_key_from_group_key, derive_key_from_secret, derive_shared_key};
use keys::{KeyPair, derive_approval_code, public_key_to_bytes};

type GcmNonce = Nonce<Aes256Gcm>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    // Fixed, valid P-256 scalars.
    let priv_a_bytes: [u8; 32] =
        hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .try_into()
            .unwrap();
    let priv_b_bytes: [u8; 32] =
        hex_bytes("deadbeef00000000cafebabe00000000deadbeef00000000cafebabe0000000f")
            .try_into()
            .unwrap();

    let priv_a = SecretKey::from_slice(&priv_a_bytes).unwrap();
    let priv_b = SecretKey::from_slice(&priv_b_bytes).unwrap();
    let pub_a = priv_a.public_key();
    let pub_b = priv_b.public_key();

    let kp_a = KeyPair {
        private: priv_a.clone(),
        public: pub_a,
    };

    let pub_a_bytes = public_key_to_bytes(&pub_a);
    let pub_b_bytes = public_key_to_bytes(&pub_b);

    // Raw ECDH shared secret (x-coordinate).
    let ecdh_x = diffie_hellman(priv_a.to_nonzero_scalar(), pub_b.as_affine())
        .raw_secret_bytes()
        .to_vec();

    // ECDH-derived wrap key (salt "group-key-wrap", info "cpmesh-clipboard-v1").
    let shared_wrap_ab = derive_shared_key(&priv_a, &pub_b, b"group-key-wrap").unwrap();

    // Group key material.
    let group_key: [u8; 32] = {
        use sha2::Digest;
        let h: [u8; 32] = sha2::Sha256::digest(b"cpmesh-mcp golden group key").into();
        h
    };
    let group_key_2: [u8; 32] = {
        use sha2::Digest;
        let h: [u8; 32] = sha2::Sha256::digest(b"cpmesh-mcp golden group key v2").into();
        h
    };

    // Payload derivation (info "cpmesh-group-v1").
    let payload_salt: [u8; 16] = hex_bytes("10111213141516171819202122232425")
        .try_into()
        .unwrap();
    let payload_key = derive_key_from_group_key(&group_key, &payload_salt).unwrap();

    // AES-256-GCM with a fixed nonce.
    let nonce12: [u8; 12] = hex_bytes("303132333435363738393a3b").try_into().unwrap();
    let plaintext = b"Hello from cpmesh MCP golden vectors".to_vec();
    let cipher = Aes256Gcm::new_from_slice(&payload_key).unwrap();
    let ct_tag = cipher
        .encrypt(&GcmNonce::from(nonce12), plaintext.as_ref())
        .unwrap();

    // Full clipboard payload layout: salt(16) || nonce(12) || ct || tag.
    let mut payload_full = Vec::with_capacity(16 + 12 + ct_tag.len());
    payload_full.extend_from_slice(&payload_salt);
    payload_full.extend_from_slice(&nonce12);
    payload_full.extend_from_slice(&ct_tag);

    // Full group-key wrap layout with fixed nonce: nonce(12) || ct || tag
    // (identical to what encrypt_group_key produces, with randomness pinned).
    let wrap_cipher = Aes256Gcm::new_from_slice(&shared_wrap_ab).unwrap();
    let ct_tag_wrap = wrap_cipher
        .encrypt(&GcmNonce::from(nonce12), group_key.as_ref())
        .unwrap();
    let mut gk_wrapped = Vec::with_capacity(12 + ct_tag_wrap.len());
    gk_wrapped.extend_from_slice(&nonce12);
    gk_wrapped.extend_from_slice(&ct_tag_wrap);

    // Approval code (fully deterministic).
    let approval_code_ab = derive_approval_code(&priv_a, &pub_b, &pub_a).unwrap();

    // Public-key self-signature (ECDSA P-256, RFC 6979 → deterministic).
    let sig_a = kp_a.sign_public_key();
    let sender_id = "00000000-0000-4000-8000-000000000001";
    let recipient_id = "00000000-0000-4000-8000-000000000002";
    let members = vec![
        cpmesh_proto::models::DeviceIdentity {
            id: sender_id.into(),
            public_key: pub_a_bytes.clone(),
        },
        cpmesh_proto::models::DeviceIdentity {
            id: recipient_id.into(),
            public_key: pub_b_bytes.clone(),
        },
    ];
    let self_wrap_key = derive_shared_key(&priv_a, &pub_a, b"group-key-wrap").unwrap();
    let mut self_wrap = nonce12.to_vec();
    self_wrap.extend_from_slice(
        &Aes256Gcm::new_from_slice(&self_wrap_key)
            .unwrap()
            .encrypt(&GcmNonce::from(nonce12), group_key.as_ref())
            .unwrap(),
    );
    let hashes = std::collections::BTreeMap::from([
        (
            sender_id.to_string(),
            cpmesh_proto::models::wrapped_key_hash(&self_wrap),
        ),
        (
            recipient_id.to_string(),
            cpmesh_proto::models::wrapped_key_hash(&gk_wrapped),
        ),
    ]);
    let transcript =
        cpmesh_proto::models::membership_transcript(1, sender_id, &members, &hashes).unwrap();
    let membership_sig = kp_a.sign_message(&transcript);
    let group_keys = cpmesh_proto::models::GroupKeysResponse {
        current_version: 1,
        rotation_required: false,
        rotation_due_at: None,
        keys: vec![cpmesh_proto::models::VersionedGroupKey {
            version: 1,
            encrypted_key: gk_wrapped.clone(),
            from_device_id: sender_id.into(),
            from_public_key: pub_a_bytes.clone(),
            from_public_key_sig: Some(sig_a.clone()),
            membership: Some(cpmesh_proto::models::KeyMembership {
                members,
                wrapped_key_hashes: hashes,
                signature: membership_sig.clone(),
            }),
        }],
    };
    let ack = cpmesh_proto::models::ClipboardAck::Accepted {
        request_id: sender_id.into(),
        entry_id: recipient_id.into(),
        created_at: "2026-01-01T00:00:00Z".parse().unwrap(),
    };

    // Keyring file: salt(16) || nonce(12) || ct || tag over the keyring JSON,
    // KEK = HKDF(device private key, salt, "cpnet-keyring-v1").
    let keyring_salt: [u8; 16] = hex_bytes("404142434445464748494a4b4c4d4e4f")
        .try_into()
        .unwrap();
    let keyring_json = json!({
        "current_version": 2,
        "keys": {
            "1": base64::engine::general_purpose::STANDARD.encode(group_key),
            "2": base64::engine::general_purpose::STANDARD.encode(group_key_2),
        }
    });
    let keyring_bytes = serde_json::to_vec(&keyring_json).unwrap();
    let kek = derive_key_from_secret(&priv_a_bytes, &keyring_salt, b"cpnet-keyring-v1").unwrap();
    let kek_cipher = Aes256Gcm::new_from_slice(&kek).unwrap();
    let keyring_ct = kek_cipher
        .encrypt(&GcmNonce::from(nonce12), keyring_bytes.as_slice())
        .unwrap();
    let mut keyring_file = Vec::with_capacity(16 + 12 + keyring_ct.len());
    keyring_file.extend_from_slice(&keyring_salt);
    keyring_file.extend_from_slice(&nonce12);
    keyring_file.extend_from_slice(&keyring_ct);

    let out = json!({
        "priv_a": hex(&priv_a_bytes),
        "priv_b": hex(&priv_b_bytes),
        "pub_a": hex(&pub_a_bytes),
        "pub_b": hex(&pub_b_bytes),
        "ecdh_x_ab": hex(&ecdh_x),
        "shared_key_wrap_ab": hex(&shared_wrap_ab),
        "group_key": hex(&group_key),
        "group_key_2": hex(&group_key_2),
        "payload_salt": hex(&payload_salt),
        "payload_key": hex(&payload_key),
        "nonce12": hex(&nonce12),
        "plaintext": hex(&plaintext),
        "aes_ct_tag": hex(&ct_tag),
        "payload_full": hex(&payload_full),
        "gk_wrapped_fixed_nonce": hex(&gk_wrapped),
        "approval_code_ab": approval_code_ab,
        "sig_a_der": hex(&sig_a),
        "membership_transcript": hex(&transcript),
        "membership_signature": hex(&membership_sig),
        "group_keys_json": serde_json::to_string(&group_keys).unwrap(),
        "clipboard_ack_json": serde_json::to_string(&ack).unwrap(),
        "keyring_salt": hex(&keyring_salt),
        "keyring_file": hex(&keyring_file),
        "fingerprint_a": KeyPair::fingerprint(&pub_a),
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
