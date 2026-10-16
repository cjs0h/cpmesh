//! Sealing and opening clipboard entries (protocol v3).
//!
//! Every entry is bound to its context (key version, content type, sender,
//! request ID, sender clock) through AES-GCM associated data, and the sender
//! signs that context plus both ciphertexts with its identity key. A relay can
//! therefore neither relabel, splice, re-attribute nor replay an entry.

use cpmesh_proto::models::{
    ContentType, clipboard_data_aad, clipboard_metadata_aad, clipboard_signature_transcript,
};
use p256::PublicKey;

use super::encrypt::CryptoError;
use super::exchange::KeyExchange;
use super::keys::{KeyError, KeyPair};

/// Identifies the entry every ciphertext and signature is bound to.
#[derive(Clone, Debug)]
pub struct EntryContext<'a> {
    pub key_version: i32,
    pub content_type: &'a ContentType,
    pub sender_id: &'a str,
    pub request_id: &'a str,
    pub sent_at: i64,
}

pub struct SealedEntry {
    pub encrypted_data: Vec<u8>,
    pub metadata: Vec<u8>,
    pub key_version: i32,
    pub signature: Vec<u8>,
}

/// Encrypts data and metadata under the current group key, bound to the
/// context, and signs the result. `context.key_version` is ignored: the current
/// version is used and returned.
pub fn seal_entry(
    exchange: &KeyExchange,
    identity: &KeyPair,
    context: &EntryContext<'_>,
    data: &[u8],
    metadata_json: &[u8],
) -> Result<SealedEntry, CryptoError> {
    let key_version = exchange.current_version;
    let context = EntryContext {
        key_version,
        ..context.clone()
    };
    let (encrypted_data, version) = exchange.encrypt_payload(data, &data_aad(&context))?;
    debug_assert_eq!(version, key_version);
    let (metadata, _) = exchange.encrypt_payload(metadata_json, &metadata_aad(&context))?;
    let signature = identity.sign_message(&transcript(&context, &encrypted_data, &metadata));
    Ok(SealedEntry {
        encrypted_data,
        metadata,
        key_version,
        signature,
    })
}

/// Checks the sender's signature over the context and both ciphertexts.
pub fn verify_entry_signature(
    sender_identity: &PublicKey,
    context: &EntryContext<'_>,
    encrypted_data: &[u8],
    metadata: &[u8],
    signature: &[u8],
) -> Result<(), KeyError> {
    KeyPair::verify_message(
        sender_identity,
        &transcript(context, encrypted_data, metadata),
        signature,
    )
}

/// Decrypts a verified entry. Returns the plaintext data and the metadata JSON
/// (empty when the entry carried none).
pub fn open_entry(
    exchange: &KeyExchange,
    context: &EntryContext<'_>,
    encrypted_data: &[u8],
    metadata: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let data = exchange.decrypt_payload(encrypted_data, context.key_version, &data_aad(context))?;
    let metadata_json = if metadata.is_empty() {
        Vec::new()
    } else {
        exchange.decrypt_payload(metadata, context.key_version, &metadata_aad(context))?
    };
    Ok((data, metadata_json))
}

fn data_aad(context: &EntryContext<'_>) -> Vec<u8> {
    clipboard_data_aad(
        context.key_version,
        context.content_type,
        context.sender_id,
        context.request_id,
        context.sent_at,
    )
}

fn metadata_aad(context: &EntryContext<'_>) -> Vec<u8> {
    clipboard_metadata_aad(
        context.key_version,
        context.content_type,
        context.sender_id,
        context.request_id,
        context.sent_at,
    )
}

fn transcript(context: &EntryContext<'_>, encrypted_data: &[u8], metadata: &[u8]) -> Vec<u8> {
    clipboard_signature_transcript(
        context.key_version,
        context.content_type,
        context.sender_id,
        context.request_id,
        context.sent_at,
        encrypted_data,
        metadata,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::DeviceKeys;

    const SENDER: &str = "00000000-0000-4000-8000-00000000000a";
    const REQUEST: &str = "00000000-0000-4000-8000-000000000001";

    fn mesh() -> (KeyExchange, KeyExchange) {
        let a = DeviceKeys::generate();
        let b = DeviceKeys::generate();
        let mut exch_a = KeyExchange::new(a);
        let mut exch_b = KeyExchange::new(b);
        exch_a.init_group_key();
        exch_b
            .add_key_version(1, exch_a.keys_by_version[&1].clone())
            .unwrap();
        (exch_a, exch_b)
    }

    #[test]
    fn sealed_entries_open_only_in_their_own_context() {
        let (sender, receiver) = mesh();
        let context = EntryContext {
            key_version: 0,
            content_type: &ContentType::Text,
            sender_id: SENDER,
            request_id: REQUEST,
            sent_at: 1_700_000_000_000,
        };
        let sealed = seal_entry(
            &sender,
            sender.key_pair(),
            &context,
            b"hello",
            br#"{"size":5}"#,
        )
        .unwrap();
        assert_eq!(sealed.key_version, 1);
        let context = EntryContext {
            key_version: 1,
            ..context
        };
        verify_entry_signature(
            &sender.key_pair().public,
            &context,
            &sealed.encrypted_data,
            &sealed.metadata,
            &sealed.signature,
        )
        .unwrap();
        let (data, meta) = open_entry(
            &receiver,
            &context,
            &sealed.encrypted_data,
            &sealed.metadata,
        )
        .unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(meta, br#"{"size":5}"#);

        // Relabelled content type: signature and AAD both fail.
        let relabelled = EntryContext {
            content_type: &ContentType::File,
            ..context.clone()
        };
        assert!(
            verify_entry_signature(
                &sender.key_pair().public,
                &relabelled,
                &sealed.encrypted_data,
                &sealed.metadata,
                &sealed.signature,
            )
            .is_err()
        );
        assert!(
            open_entry(
                &receiver,
                &relabelled,
                &sealed.encrypted_data,
                &sealed.metadata
            )
            .is_err()
        );
        // Re-attributed sender, different request ID or clock: AAD fails.
        for changed in [
            EntryContext {
                sender_id: "00000000-0000-4000-8000-00000000000b",
                ..context.clone()
            },
            EntryContext {
                request_id: "00000000-0000-4000-8000-000000000002",
                ..context.clone()
            },
            EntryContext {
                sent_at: 1_700_000_000_001,
                ..context.clone()
            },
        ] {
            assert!(
                open_entry(
                    &receiver,
                    &changed,
                    &sealed.encrypted_data,
                    &sealed.metadata
                )
                .is_err()
            );
        }
        // Metadata from another entry cannot be spliced onto this data.
        let other = seal_entry(
            &sender,
            sender.key_pair(),
            &EntryContext {
                request_id: "00000000-0000-4000-8000-000000000002",
                ..context.clone()
            },
            b"other",
            br#"{"size":5}"#,
        )
        .unwrap();
        assert!(open_entry(&receiver, &context, &sealed.encrypted_data, &other.metadata).is_err());
        // Data and metadata ciphertexts cannot be swapped either.
        assert!(
            open_entry(
                &receiver,
                &context,
                &sealed.metadata,
                &sealed.encrypted_data
            )
            .is_err()
        );
    }

    #[test]
    fn signatures_come_from_the_claimed_sender() {
        let (sender, _) = mesh();
        let context = EntryContext {
            key_version: 1,
            content_type: &ContentType::Image,
            sender_id: SENDER,
            request_id: REQUEST,
            sent_at: 42,
        };
        let sealed = seal_entry(&sender, sender.key_pair(), &context, b"png", b"").unwrap();
        let mallory = KeyPair::generate();
        assert!(
            verify_entry_signature(
                &mallory.public,
                &context,
                &sealed.encrypted_data,
                &sealed.metadata,
                &sealed.signature
            )
            .is_err()
        );
        let mut tampered = sealed.encrypted_data.clone();
        tampered[20] ^= 1;
        assert!(
            verify_entry_signature(
                &sender.key_pair().public,
                &context,
                &tampered,
                &sealed.metadata,
                &sealed.signature
            )
            .is_err()
        );
        assert!(
            verify_entry_signature(
                &sender.key_pair().public,
                &context,
                &sealed.encrypted_data,
                b"",
                &sealed.signature
            )
            .is_err()
        );
    }

    #[test]
    fn entries_without_metadata_open_with_empty_metadata() {
        let (sender, receiver) = mesh();
        let context = EntryContext {
            key_version: 1,
            content_type: &ContentType::Text,
            sender_id: SENDER,
            request_id: REQUEST,
            sent_at: 1,
        };
        let sealed = seal_entry(&sender, sender.key_pair(), &context, b"x", b"").unwrap();
        // The sender always encrypts some metadata blob; an absent one is tolerated.
        let (data, meta) = open_entry(&receiver, &context, &sealed.encrypted_data, &[]).unwrap();
        assert_eq!(data, b"x");
        assert!(meta.is_empty());
    }
}
