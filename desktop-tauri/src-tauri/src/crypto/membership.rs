use cpmesh_proto::models::{
    DeviceIdentity, KeyMembership, StoreGroupKeyEntry, VersionedGroupKey, membership_transcript,
    wrap_aad, wrapped_key_hash,
};
use p256::PublicKey;
use zeroize::Zeroizing;

use super::{encrypt, exchange::KeyExchange, keys::KeyPair, verify::KeyVerifier};

/// A mesh member together with the encryption key its identity key certified.
/// Only targets built through [`certified_target`] receive wraps.
#[derive(Clone)]
pub struct WrapTarget {
    pub identity: DeviceIdentity,
    pub encryption_key: PublicKey,
}

/// Checks a member's published encryption key against its (already pinned)
/// identity key. A missing or forged certification means the device has not
/// been updated to protocol v3, or the relay is lying; neither gets a wrap.
pub fn certified_target(
    identity: DeviceIdentity,
    encryption_key: Option<&[u8]>,
    encryption_key_sig: Option<&[u8]>,
) -> Result<WrapTarget, String> {
    let identity_key =
        KeyPair::parse_public_key(&identity.public_key).map_err(|e| e.to_string())?;
    let (Some(encryption_key), Some(signature)) = (encryption_key, encryption_key_sig) else {
        return Err(format!(
            "device {} has not published a certified encryption key; update it to protocol 3 or remove it",
            identity.id
        ));
    };
    let encryption_key =
        super::keys::verify_encryption_key(&identity_key, encryption_key, signature)
            .map_err(|e| format!("device {}: {e}", identity.id))?;
    Ok(WrapTarget {
        identity,
        encryption_key,
    })
}

fn identities(targets: &[WrapTarget]) -> Vec<DeviceIdentity> {
    targets.iter().map(|t| t.identity.clone()).collect()
}

/// Candidate wraps are staged without changing the active or persisted keyring.
pub fn stage_rotation(
    exchange: &KeyExchange,
    sender: &str,
    targets: &[WrapTarget],
) -> Result<(i32, Vec<StoreGroupKeyEntry>), String> {
    let version = exchange
        .current_version
        .checked_add(1)
        .ok_or("key version exhausted")?;
    let key = Zeroizing::new(encrypt::generate_group_key());
    Ok((
        version,
        signed_wraps(exchange.key_pair(), sender, version, key.as_ref(), targets)?,
    ))
}

/// Wraps `key` for every target with a fresh ephemeral key and signs the
/// membership transcript with the identity key.
pub fn signed_wraps(
    pair: &KeyPair,
    sender: &str,
    version: i32,
    key: &[u8],
    targets: &[WrapTarget],
) -> Result<Vec<StoreGroupKeyEntry>, String> {
    let members = identities(targets);
    validate_members(&members, sender, &pair.public_key_bytes())?;
    let mut wraps: Vec<StoreGroupKeyEntry> = targets
        .iter()
        .map(|target| {
            let encrypted_key = encrypt::wrap_group_key_v3(
                key,
                &target.encryption_key,
                &wrap_aad(version, sender, &target.identity.id),
            )
            .map_err(|e| e.to_string())?;
            Ok(StoreGroupKeyEntry {
                device_id: target.identity.id.clone(),
                encrypted_key,
                membership: None,
            })
        })
        .collect::<Result<_, String>>()?;
    let hashes = wraps
        .iter()
        .map(|wrap| {
            (
                wrap.device_id.clone(),
                wrapped_key_hash(&wrap.encrypted_key),
            )
        })
        .collect();
    let transcript = membership_transcript(version, sender, &members, &hashes)?;
    wraps[0].membership = Some(KeyMembership {
        members,
        wrapped_key_hashes: hashes,
        signature: pair.sign_message(&transcript),
    });
    Ok(wraps)
}

/// Imports only from an independently pinned sender. A self-signature supplied
/// by the relay is not evidence of mesh membership.
pub fn import_key(
    exchange: &mut KeyExchange,
    verifier: &mut KeyVerifier,
    recipient: &str,
    key: &VersionedGroupKey,
) -> Result<(), String> {
    let sender = KeyPair::parse_public_key(&key.from_public_key).map_err(|e| e.to_string())?;
    verifier    .verify_sender_at(&key.from_device_id, &sender, key.version)
        .map_err(|e| format!("Verify device {} through an independent full-fingerprint comparison before importing keys: {e}", key.from_device_id))?;
    if key.membership.is_none()
        && verifier.membership_version() > 0
        && key.version >= verifier.membership_version()
    {
        return Err(
            "New keys require authenticated membership; refusing a legacy downgrade".into(),
        );
    }
    if let Some(membership) = &key.membership {
        validate_members(
            &membership.members,
            recipient,
            &exchange.key_pair().public_key_bytes(),
        )?;
        validate_members(
            &membership.members,
            &key.from_device_id,
            &key.from_public_key,
        )?;
        if membership.wrapped_key_hashes.get(recipient)
            != Some(&wrapped_key_hash(&key.encrypted_key))
        {
            return Err("Wrapped key does not match the authenticated recipient commitment".into());
        }
        KeyPair::verify_message(
            &sender,
            &membership_transcript(
                key.version,
                &key.from_device_id,
                &membership.members,
                &membership.wrapped_key_hashes,
            )?,
            &membership.signature,
        )
        .map_err(|e| e.to_string())?;
    }
    let mut candidate = exchange.clone();
    candidate
        .import_wrapped(
            &key.encrypted_key,
            &sender,
            &key.from_device_id,
            recipient,
            key.version,
        )
        .map_err(|e| e.to_string())?;
    if let Some(membership) = &key.membership {
        verifier
            .accept_membership(key.version, &membership.members)
            .map_err(|e| e.to_string())?;
    }
    *exchange = candidate;
    Ok(())
}

fn validate_members(
    members: &[DeviceIdentity],
    own_id: &str,
    own_key: &[u8],
) -> Result<(), String> {
    let mut ids = std::collections::HashSet::new();
    if members.is_empty() {
        return Err("invalid membership size".into());
    }
    for member in members {
        // UUID syntax also rules out separators in the canonical signed transcript.
        if !cpmesh_proto::models::canonical_device_id(&member.id) || !ids.insert(&member.id) {
            return Err("invalid or duplicate member ID".into());
        }
        KeyPair::parse_public_key(&member.public_key).map_err(|e| e.to_string())?;
    }
    if !members
        .iter()
        .any(|m| m.id == own_id && m.public_key == own_key)
    {
        return Err("authenticated membership does not include the expected device key".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{DeviceKeys, public_key_to_bytes};

    fn target(id: &str, keys: &DeviceKeys) -> WrapTarget {
        certified_target(
            DeviceIdentity {
                id: id.into(),
                public_key: keys.identity.public_key_bytes(),
            },
            Some(&keys.encryption.public_key_bytes()),
            Some(&keys.certify_encryption_key()),
        )
        .unwrap()
    }

    #[test]
    fn unknown_sender_cannot_self_authorize_and_wraps_bind_the_transcript() {
        let a = DeviceKeys::generate();
        let b = DeviceKeys::generate();
        let aid = uuid::Uuid::new_v4().to_string();
        let bid = uuid::Uuid::new_v4().to_string();
        let targets = vec![target(&aid, &a), target(&bid, &b)];
        let mut recipient = KeyExchange::new(b);
        let sender = KeyExchange::new(a);
        let dir = tempfile::tempdir().unwrap();
        let mut verifier = KeyVerifier::new(dir.path()).unwrap();
        let (version, wraps) = stage_rotation(&sender, &aid, &targets).unwrap();
        assert_eq!(sender.current_version, 0);
        assert!(!sender.has_group_key());
        assert!(
            wraps
                .iter()
                .all(|w| w.encrypted_key.len() == cpmesh_proto::models::WRAP_V3_LEN)
        );
        let manifest = wraps[0].membership.clone();
        let wrap = wraps.into_iter().find(|w| w.device_id == bid).unwrap();
        let mut key = VersionedGroupKey {
            version,
            encrypted_key: wrap.encrypted_key,
            from_device_id: aid.clone(),
            from_public_key: public_key_to_bytes(&sender.key_pair().public),
            from_public_key_sig: Some(sender.key_pair().sign_public_key()),
            membership: manifest,
        };
        assert!(import_key(&mut recipient, &mut verifier, &bid, &key).is_err());
        assert!(!recipient.has_group_key());
        verifier
            .pin_after_approval(&aid, &sender.key_pair().public)
            .unwrap();
        key.version += 1;
        assert!(import_key(&mut recipient, &mut verifier, &bid, &key).is_err());
        key.version -= 1;
        import_key(&mut recipient, &mut verifier, &bid, &key).unwrap();
        assert_eq!(recipient.current_version, 1);
        assert!(verifier.is_pinned(&bid));
        assert!(verifier.public_key_of(&bid).is_some());
    }

    #[test]
    fn wraps_only_target_certified_encryption_keys() {
        let a = DeviceKeys::generate();
        let identity = DeviceIdentity {
            id: uuid::Uuid::new_v4().to_string(),
            public_key: a.identity.public_key_bytes(),
        };
        // Not yet upgraded: no encryption key.
        assert!(certified_target(identity.clone(), None, None).is_err());
        // The relay substitutes its own encryption key.
        let mallory = DeviceKeys::generate();
        assert!(
            certified_target(
                identity.clone(),
                Some(&mallory.encryption.public_key_bytes()),
                Some(&a.certify_encryption_key()),
            )
            .is_err()
        );
        assert!(
            certified_target(
                identity.clone(),
                Some(&mallory.encryption.public_key_bytes()),
                Some(&mallory.certify_encryption_key()),
            )
            .is_err()
        );
        assert!(
            certified_target(
                identity,
                Some(&a.encryption.public_key_bytes()),
                Some(&a.certify_encryption_key()),
            )
            .is_ok()
        );
    }
}
