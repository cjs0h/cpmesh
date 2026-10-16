//! Key lifecycle shared by sign-in, startup, reconnect and rotation notifications.
use std::path::Path;

use crate::api::client::{ApiClient, ApiError};
use crate::config::AppConfig;
use crate::crypto::{exchange::KeyExchange, keys::KeyPair, membership, verify::KeyVerifier};
use crate::proto::models::*;

pub fn bind_account(
    directory: &Path,
    server: &str,
    user: &str,
    previous: &AppConfig,
) -> Result<(), String> {
    let owner_path = directory.join("keyring_owner.json");
    let expected = serde_json::json!({"server": server.trim_end_matches('/'), "user": user});
    if owner_path.exists() {
        let owner: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&owner_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        if owner != expected {
            return Err("This keyring belongs to another account. Use a separate profile; do not overwrite its keys.".into());
        }
    } else {
        if AppConfig::keyring_path(directory).exists()
            && (previous.user_id != user
                || previous.server_url.trim_end_matches('/') != server.trim_end_matches('/'))
        {
            return Err("Cannot identify this legacy keyring's account. Restore its original configuration before signing in.".into());
        }
        super::crypto::keys::write_private_file(
            &owner_path,
            &serde_json::to_vec(&expected).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn restore(pair: KeyPair, directory: &Path) -> Result<KeyExchange, String> {
    let mut exchange = KeyExchange::new(pair);
    let path = AppConfig::keyring_path(directory);
    if path.exists() {
        exchange
            .load_keyring(&path)
            .map_err(|e| format!("Cannot restore saved keyring: {e}"))?;
    }
    Ok(exchange)
}

pub async fn trusted_members(
    exchange: &KeyExchange,
    api: &ApiClient,
    own_id: &str,
    directory: &Path,
) -> Result<Vec<DeviceIdentity>, String> {
    let mut verifier = KeyVerifier::new(directory).map_err(|e| e.to_string())?;
    verifier
        .pin_after_approval(own_id, &exchange.key_pair().public)
        .map_err(|e| e.to_string())?;
    let devices = api.get_device_keys().await.map_err(|e| e.to_string())?;
    devices
        .devices
        .into_iter()
        .filter(|d| d.status == DeviceStatus::Approved)
        .map(|d| {
            let public_key = d.public_key.ok_or("device public key missing")?;
            let key = KeyPair::parse_public_key(&public_key).map_err(|e| e.to_string())?;
            verifier.verify_pinned(&d.id, &key).map_err(|e| {
                format!(
                    "Verify device {} on the Devices page before distributing keys: {e}",
                    d.name
                )
            })?;
            Ok(DeviceIdentity {
                id: d.id,
                public_key,
            })
        })
        .collect()
}

/// Returns whether rotation is due. Missing wraps never imply a new mesh.
pub async fn synchronize(
    exchange: &mut KeyExchange,
    api: &ApiClient,
    own_id: &str,
    directory: &Path,
) -> Result<bool, String> {
    let mut candidate = exchange.clone();
    let mut verifier = KeyVerifier::new(directory).map_err(|e| e.to_string())?;
    verifier
        .pin_after_approval(own_id, &candidate.key_pair().public)
        .map_err(|e| e.to_string())?;
    let mut response = match api
        .get_current_group_keys(Some(candidate.current_version))
        .await
    {
        Ok(response) => response,
        Err(ApiError::Server { status: 404, .. }) => {
            let members = trusted_members(&candidate, api, own_id, directory).await?;
            if members.len() != 1 || members[0].id != own_id || candidate.current_version > 1 {
                return Err("Mesh key state is missing; restore your keyring or verify an existing device. Refusing to create replacement keys.".into());
            }
            let (version, wrapped_keys) = if let Some(key) = candidate.keys_by_version.get(&1) {
                (
                    1,
                    membership::signed_wraps(candidate.key_pair(), own_id, 1, key, &members)?,
                )
            } else {
                membership::stage_rotation(&candidate, own_id, &members)?
            };
            let result = api
                .rotate_group_key(&RotateGroupKeyRequest {
                    expected_current_version: 0,
                    new_version: version,
                    wrapped_keys,
                })
                .await;
            // A response can be lost after commit. Recover our authenticated self-wrap.
            match api.get_current_group_keys(Some(0)).await {
                Ok(response) => response,
                Err(e) => return Err(result.err().unwrap_or(e).to_string()),
            }
        }
        Err(e) => return Err(e.to_string()),
    };
    loop {
        if response.current_version < candidate.current_version
            || response.current_version < verifier.membership_version()
        {
            return Err(
                "Server key version rolled back; refusing to replace the saved keyring".into(),
            );
        }
        let before = candidate.current_version;
        for key in &response.keys {
            membership::import_key(&mut candidate, &mut verifier, own_id, key)?;
        }
        if candidate
            .keys_by_version
            .contains_key(&response.current_version)
        {
            break;
        }
        if candidate.current_version <= before {
            return Err("Current group key is missing for this device; restore or verify a peer, never reset the key".into());
        }
        response = api
            .get_current_group_keys(Some(candidate.current_version))
            .await
            .map_err(|e| e.to_string())?;
    }
    candidate
        .save_keyring(&AppConfig::keyring_path(directory))
        .map_err(|e| e.to_string())?;
    *exchange = candidate;
    Ok(verifier.rotation_required()
        || verifier.membership_version() < response.current_version
        || response.rotation_required
        || response
            .rotation_due_at
            .is_some_and(|due| due <= chrono::Utc::now()))
}

pub async fn rotate(
    exchange: &mut KeyExchange,
    api: &ApiClient,
    own_id: &str,
    directory: &Path,
) -> Result<(), String> {
    synchronize(exchange, api, own_id, directory).await?;
    let members = trusted_members(exchange, api, own_id, directory).await?;
    let (new_version, wrapped_keys) = membership::stage_rotation(exchange, own_id, &members)?;
    let result = api
        .rotate_group_key(&RotateGroupKeyRequest {
            expected_current_version: exchange.current_version,
            new_version,
            wrapped_keys,
        })
        .await;
    let required = synchronize(exchange, api, own_id, directory).await?;
    if !required && exchange.current_version >= new_version {
        return Ok(());
    }

    match result {
        Err(e) => Err(e.to_string()),
        Ok(_) => Err("Rotation was not confirmed; candidate key was not activated".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_and_relogin_restore_all_saved_versions_without_regenerating_version_one() {
        let dir = tempfile::tempdir().unwrap();
        let pair = KeyPair::generate();
        let mut original = KeyExchange::new(pair.clone());
        original.add_key_version(1, vec![11; 32]).unwrap();
        let (old_clip, _) = original.encrypt_payload(b"old clipboard").unwrap();
        original.add_key_version(2, vec![22; 32]).unwrap();
        original
            .save_keyring(&AppConfig::keyring_path(dir.path()))
            .unwrap();
        for _ in 0..2 {
            let restored = restore(pair.clone(), dir.path()).unwrap();
            assert_eq!(restored.current_version, 2);
            assert_eq!(
                restored.decrypt_payload(&old_clip, 1).unwrap(),
                b"old clipboard"
            );
        }
        std::fs::write(AppConfig::keyring_path(dir.path()), "invalid keyring").unwrap();
        assert!(
            restore(pair, dir.path()).is_err(),
            "corruption must not create replacement key material"
        );
    }

    #[test]
    fn account_binding_prevents_loading_another_accounts_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let previous = AppConfig::default();
        bind_account(dir.path(), "https://one.example", "alice", &previous).unwrap();
        bind_account(dir.path(), "https://one.example/", "alice", &previous).unwrap();
        assert!(bind_account(dir.path(), "https://one.example", "bob", &previous).is_err());
        assert!(bind_account(dir.path(), "https://other.example", "alice", &previous).is_err());
    }
}
