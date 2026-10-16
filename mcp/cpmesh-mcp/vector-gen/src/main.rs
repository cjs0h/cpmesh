#![allow(dead_code)]
#![recursion_limit = "512"]
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
#[path = "../../../../desktop-tauri/src-tauri/src/crypto/entry.rs"]
mod entry;
#[path = "../../../../desktop-tauri/src-tauri/src/crypto/exchange.rs"]
mod exchange;
#[path = "../../../../desktop-tauri/src-tauri/src/crypto/keys.rs"]
mod keys;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce};
use base64::Engine;
use cpmesh_proto::models as proto;
use p256::SecretKey;
use p256::ecdh::diffie_hellman;
use serde_json::json;

use encrypt::{derive_key_from_group_key, derive_key_from_secret, derive_shared_key};
use keys::{DeviceKeys, KeyPair, derive_approval_code, public_key_to_bytes};

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

    // Full pairing code (v3: a plain hash over both identity keys, no ECDH).
    let pairing_fingerprint_ab = derive_approval_code(&pub_a, &pub_b);

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
                members: members.clone(),
                wrapped_key_hashes: hashes,
                signature: membership_sig.clone(),
            }),
        }],
    };

    // === Protocol v3 ===

    // B's static encryption key, certified by B's identity key.
    let enc_priv_b_bytes: [u8; 32] =
        hex_bytes("0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221101")
            .try_into()
            .unwrap();
    let enc_priv_b = SecretKey::from_slice(&enc_priv_b_bytes).unwrap();
    let enc_pub_b = enc_priv_b.public_key();
    let enc_pub_b_bytes = public_key_to_bytes(&enc_pub_b);
    let keys_b = DeviceKeys {
        identity: KeyPair {
            private: priv_b.clone(),
            public: pub_b,
        },
        encryption: KeyPair {
            private: enc_priv_b.clone(),
            public: enc_pub_b,
        },
    };
    let encryption_key_transcript_b = proto::encryption_key_transcript(&pub_b_bytes, &enc_pub_b_bytes);
    let encryption_key_sig_b = keys_b.certify_encryption_key();
    keys::verify_encryption_key(&pub_b, &enc_pub_b_bytes, &encryption_key_sig_b).unwrap();

    // A's encryption key (needed for A's self-wrap in the v3 response).
    let enc_priv_a_bytes: [u8; 32] =
        hex_bytes("1111111111111111222222222222222233333333333333334444444444444444")
            .try_into()
            .unwrap();
    let enc_priv_a = SecretKey::from_slice(&enc_priv_a_bytes).unwrap();
    let enc_pub_a_bytes = public_key_to_bytes(&enc_priv_a.public_key());
    let keys_a = DeviceKeys {
        identity: kp_a.clone(),
        encryption: KeyPair {
            private: enc_priv_a.clone(),
            public: enc_priv_a.public_key(),
        },
    };
    let encryption_key_sig_a = keys_a.certify_encryption_key();

    // v3 wrap of the group key from A to B: fixed ephemeral key and nonce.
    let eph_priv_bytes: [u8; 32] =
        hex_bytes("5555555555555555666666666666666677777777777777778888888888888888")
            .try_into()
            .unwrap();
    let eph_priv = SecretKey::from_slice(&eph_priv_bytes).unwrap();
    let wrap_v3_aad = proto::wrap_aad(1, sender_id, recipient_id);
    let wrap_v3_blob = encrypt::wrap_group_key_v3_deterministic(
        &group_key,
        &eph_priv,
        &nonce12,
        &enc_pub_b,
        &wrap_v3_aad,
    )
    .unwrap();
    assert_eq!(
        encrypt::unwrap_group_key_v3(&wrap_v3_blob, &enc_priv_b, &wrap_v3_aad).unwrap(),
        group_key
    );
    // A's self-wrap (also deterministic) so the v3 membership transcript is complete.
    let self_wrap_v3 = encrypt::wrap_group_key_v3_deterministic(
        &group_key,
        &eph_priv,
        &nonce12,
        &enc_priv_a.public_key(),
        &proto::wrap_aad(1, sender_id, sender_id),
    )
    .unwrap();
    let hashes_v3 = std::collections::BTreeMap::from([
        (sender_id.to_string(), proto::wrapped_key_hash(&self_wrap_v3)),
        (recipient_id.to_string(), proto::wrapped_key_hash(&wrap_v3_blob)),
    ]);
    let transcript_v3 = proto::membership_transcript(1, sender_id, &members, &hashes_v3).unwrap();
    let membership_sig_v3 = kp_a.sign_message(&transcript_v3);
    let group_keys_v3 = proto::GroupKeysResponse {
        current_version: 1,
        rotation_required: false,
        rotation_due_at: None,
        keys: vec![proto::VersionedGroupKey {
            version: 1,
            encrypted_key: wrap_v3_blob.clone(),
            from_device_id: sender_id.into(),
            from_public_key: pub_a_bytes.clone(),
            from_public_key_sig: Some(sig_a.clone()),
            membership: Some(proto::KeyMembership {
                members: members.clone(),
                wrapped_key_hashes: hashes_v3,
                signature: membership_sig_v3.clone(),
            }),
        }],
    };

    // v3 clipboard entry from A: AAD-bound data + metadata, signed context.
    let request_id = "00000000-0000-4000-8000-000000000009";
    let sent_at: i64 = 1_700_000_000_123;
    let content_type = proto::ContentType::Text;
    let data_aad = proto::clipboard_data_aad(1, &content_type, sender_id, request_id, sent_at);
    let metadata_aad =
        proto::clipboard_metadata_aad(1, &content_type, sender_id, request_id, sent_at);
    let payload_v3_ct = encrypt::encrypt_with_nonce(&payload_key, &nonce12, &plaintext, &data_aad).unwrap();
    let mut payload_v3_full = payload_salt.to_vec();
    payload_v3_full.extend_from_slice(&payload_v3_ct);
    let metadata_json = br#"{"mime_type":"text/plain","size":36}"#.to_vec();
    let metadata_salt: [u8; 16] = hex_bytes("60616263646566676869707172737475")
        .try_into()
        .unwrap();
    let metadata_nonce: [u8; 12] = hex_bytes("a0a1a2a3a4a5a6a7a8a9aaab").try_into().unwrap();
    let metadata_key = derive_key_from_group_key(&group_key, &metadata_salt).unwrap();
    let metadata_v3_ct =
        encrypt::encrypt_with_nonce(&metadata_key, &metadata_nonce, &metadata_json, &metadata_aad)
            .unwrap();
    let mut metadata_v3_full = metadata_salt.to_vec();
    metadata_v3_full.extend_from_slice(&metadata_v3_ct);
    let signature_transcript = proto::clipboard_signature_transcript(
        1,
        &content_type,
        sender_id,
        request_id,
        sent_at,
        &payload_v3_full,
        &metadata_v3_full,
    );
    let sender_signature = kp_a.sign_message(&signature_transcript);
    {
        // Cross-check with the high-level API used by the desktop client.
        let mut ring = exchange::KeyExchange::new(keys_b.clone());
        ring.add_key_version(1, group_key.to_vec()).unwrap();
        let context = entry::EntryContext {
            key_version: 1,
            content_type: &content_type,
            sender_id,
            request_id,
            sent_at,
        };
        entry::verify_entry_signature(&pub_a, &context, &payload_v3_full, &metadata_v3_full, &sender_signature)
            .unwrap();
        let (data, meta) = entry::open_entry(&ring, &context, &payload_v3_full, &metadata_v3_full).unwrap();
        assert_eq!(data, plaintext);
        assert_eq!(meta, metadata_json);
    }

    // Committed short authentication string.
    let nonce_approver = [0xA5u8; 32];
    let nonce_pending = [0x5Au8; 32];
    let sas_commit = proto::sas_commitment(&nonce_approver);
    let sas_code = proto::sas_code(&nonce_approver, &nonce_pending, &pub_a_bytes, &pub_b_bytes);
    assert_eq!(
        sas_code,
        proto::sas_code(&nonce_approver, &nonce_pending, &pub_b_bytes, &pub_a_bytes)
    );

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
        "pairing_fingerprint_ab": pairing_fingerprint_ab,
        "sig_a_der": hex(&sig_a),
        "membership_transcript": hex(&transcript),
        "membership_signature": hex(&membership_sig),
        "group_keys_json": serde_json::to_string(&group_keys).unwrap(),
        "clipboard_ack_json": serde_json::to_string(&ack).unwrap(),
        "keyring_salt": hex(&keyring_salt),
        "keyring_file": hex(&keyring_file),
        "fingerprint_a": KeyPair::fingerprint(&pub_a),
        // --- protocol v3 ---
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "enc_priv_a": hex(&enc_priv_a_bytes),
        "enc_pub_a": hex(&enc_pub_a_bytes),
        "encryption_key_sig_a": hex(&encryption_key_sig_a),
        "enc_priv_b": hex(&enc_priv_b_bytes),
        "enc_pub_b": hex(&enc_pub_b_bytes),
        "encryption_key_transcript_b": hex(&encryption_key_transcript_b),
        "encryption_key_sig_b": hex(&encryption_key_sig_b),
        "wrap_v3_eph_priv": hex(&eph_priv_bytes),
        "wrap_v3_aad": hex(&wrap_v3_aad),
        "wrap_v3_blob": hex(&wrap_v3_blob),
        "self_wrap_v3_blob": hex(&self_wrap_v3),
        "membership_transcript_v3": hex(&transcript_v3),
        "membership_signature_v3": hex(&membership_sig_v3),
        "group_keys_v3_json": serde_json::to_string(&group_keys_v3).unwrap(),
        "request_id": request_id,
        "sent_at": sent_at,
        "data_aad": hex(&data_aad),
        "metadata_aad": hex(&metadata_aad),
        "payload_v3_full": hex(&payload_v3_full),
        "metadata_json": hex(&metadata_json),
        "metadata_salt": hex(&metadata_salt),
        "metadata_nonce": hex(&metadata_nonce),
        "metadata_v3_full": hex(&metadata_v3_full),
        "signature_transcript": hex(&signature_transcript),
        "sender_signature": hex(&sender_signature),
        "sas_nonce_approver": hex(&nonce_approver),
        "sas_nonce_pending": hex(&nonce_pending),
        "sas_commit": hex(&sas_commit),
        "sas_code": sas_code,
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
