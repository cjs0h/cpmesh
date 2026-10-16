use cpmesh_proto::models::{
    DeviceIdentity, KeyMembership, StoreGroupKeyEntry, VersionedGroupKey, membership_transcript,
    wrapped_key_hash,
};
use zeroize::Zeroizing;

use super::{encrypt, exchange::KeyExchange, keys::KeyPair, verify::KeyVerifier};

/// Candidate wraps are staged without changing the active or persisted keyring.
pub fn stage_rotation(
    exchange: &KeyExchange,
    sender: &str,
    members: &[DeviceIdentity],
) -> Result<(i32, Vec<StoreGroupKeyEntry>), String> {
    let version = exchange
        .current_version
        .checked_add(1)
        .ok_or("key version exhausted")?;
    let key = Zeroizing::new(encrypt::generate_group_key());
    Ok((
        version,
        signed_wraps(exchange.key_pair(), sender, version, key.as_ref(), members)?,
    ))
}

pub fn signed_wraps(
    pair: &KeyPair,
    sender: &str,
    version: i32,
    key: &[u8],
    members: &[DeviceIdentity],
) -> Result<Vec<StoreGroupKeyEntry>, String> {
    validate_members(members, sender, &pair.public_key_bytes())?;
    let mut wraps: Vec<StoreGroupKeyEntry> = members
        .iter()
        .map(|member| {
            let peer = KeyPair::parse_public_key(&member.public_key).map_err(|e| e.to_string())?;
            let encrypted_key =
                encrypt::encrypt_group_key(key, &pair.private, &peer).map_err(|e| e.to_string())?;
            Ok(StoreGroupKeyEntry {
                device_id: member.id.clone(),
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
    let transcript = membership_transcript(version, sender, members, &hashes)?;
    wraps[0].membership = Some(KeyMembership {
        members: members.to_vec(),
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
        .decrypt_from_device(&key.encrypted_key, &sender, key.version)
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
    use crate::crypto::keys::public_key_to_bytes;

    #[test]
    fn unknown_sender_cannot_self_authorize_and_wraps_bind_the_transcript() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let aid = uuid::Uuid::new_v4().to_string();
        let bid = uuid::Uuid::new_v4().to_string();
        let members = vec![
            DeviceIdentity {
                id: aid.clone(),
                public_key: a.public_key_bytes(),
            },
            DeviceIdentity {
                id: bid.clone(),
                public_key: b.public_key_bytes(),
            },
        ];
        let mut recipient = KeyExchange::new(b);
        let sender = KeyExchange::new(a);
        let dir = tempfile::tempdir().unwrap();
        let mut verifier = KeyVerifier::new(dir.path()).unwrap();
        let (version, wraps) = stage_rotation(&sender, &aid, &members).unwrap();
        assert_eq!(sender.current_version, 0);
        assert!(!sender.has_group_key());
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
    }
}
