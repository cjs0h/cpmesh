//! Key lifecycle shared by sign-in, startup, reconnect and rotation notifications.
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::api::client::{ApiClient, ApiError};
use crate::config::AppConfig;
use crate::crypto::{
    exchange::KeyExchange,
    keys::{DeviceKeys, KeyPair},
    membership::{self, WrapTarget},
    verify::KeyVerifier,
};
use crate::proto::models::*;

/// Records which account the keys saved in an app data folder belong to.
pub const OWNER_FILE: &str = "keyring_owner.json";

/// The account keys belong to: a server and a user ID on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    pub server: String,
    pub user: String,
}

impl Owner {
    pub fn new(server: &str, user: &str) -> Self {
        Owner {
            server: server.trim_end_matches('/').to_string(),
            user: user.to_string(),
        }
    }
}

/// Whose keys are saved in an app data folder, compared with the account signing in.
#[derive(Debug, PartialEq)]
pub enum AccountKeys {
    /// They are this account's, or nothing is saved yet.
    Ready,
    /// Saved by a version from before owner records, and the configuration that would
    /// say whose they are was cleared (a sign-out on those versions did that).
    Unknown,
    /// Recorded as another account's.
    Other(Owner),
}

pub fn read_owner(directory: &Path) -> Result<Option<Owner>, String> {
    let path = directory.join(OWNER_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let owner: Owner = serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(Some(Owner::new(&owner.server, &owner.user)))
}

pub fn account_keys(
    directory: &Path,
    server: &str,
    user: &str,
    previous: &AppConfig,
) -> Result<AccountKeys, String> {
    let expected = Owner::new(server, user);
    Ok(match read_owner(directory)? {
        Some(owner) if owner == expected => AccountKeys::Ready,
        Some(owner) => AccountKeys::Other(owner),
        None if AppConfig::keyring_path(directory).exists()
            && Owner::new(&previous.server_url, &previous.user_id) != expected =>
        {
            AccountKeys::Unknown
        }
        None => AccountKeys::Ready,
    })
}

/// Records the keys saved here as `user`'s on `server`. Only after the user's own
/// choice when anything else says otherwise (see [`account_keys`]).
pub fn record_owner(directory: &Path, server: &str, user: &str) -> Result<(), String> {
    super::crypto::keys::write_private_file(
        &directory.join(OWNER_FILE),
        &serde_json::to_vec(&Owner::new(server, user)).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

pub fn bind_account(
    directory: &Path,
    server: &str,
    user: &str,
    previous: &AppConfig,
) -> Result<(), String> {
    match account_keys(directory, server, user, previous)? {
        AccountKeys::Ready if read_owner(directory)?.is_some() => Ok(()),
        AccountKeys::Ready => record_owner(directory, server, user),
        AccountKeys::Unknown => Err(
            "cpmesh can't tell which account the keys saved here belong to. Sign out, then sign in again to choose what happens to them."
                .into(),
        ),
        AccountKeys::Other(_) => Err(
            "The keys saved here belong to another account. Sign out, then sign in again: cpmesh keeps them archived for that account."
                .into(),
        ),
    }
}

pub fn restore(keys: DeviceKeys, directory: &Path) -> Result<KeyExchange, String> {
    let mut exchange = KeyExchange::new(keys);
    let path = AppConfig::keyring_path(directory);
    if path.exists() {
        exchange
            .load_keyring(&path)
            .map_err(|e| format!("Cannot restore saved keyring: {e}"))?;
    }
    Ok(exchange)
}

/// Makes sure the relay publishes this device's current certified encryption key,
/// so peers can wrap new group keys to it. Idempotent.
pub async fn publish_encryption_key(
    exchange: &KeyExchange,
    api: &ApiClient,
    own_id: &str,
) -> Result<(), String> {
    let devices = api.get_device_keys().await.map_err(|e| e.to_string())?;
    let published = devices
        .devices
        .iter()
        .find(|d| d.id == own_id)
        .and_then(|d| d.encryption_key.as_deref());
    if published == Some(exchange.keys().encryption.public_key_bytes().as_slice()) {
        return Ok(());
    }
    api.publish_encryption_key(exchange.keys())
        .await
        .map_err(|e| format!("Could not publish the device encryption key: {e}"))
}

/// Approved members whose identity key is pinned locally and whose encryption key
/// that identity certified. Only these receive wraps; the relay's listing alone
/// authorizes nothing.
pub async fn trusted_members(
    exchange: &KeyExchange,
    api: &ApiClient,
    own_id: &str,
    directory: &Path,
) -> Result<Vec<WrapTarget>, String> {
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
            let identity = DeviceIdentity {
                id: d.id,
                public_key,
            };
            if identity.id == own_id {
                // Our own encryption key comes from local storage, never from the relay.
                return Ok(WrapTarget {
                    identity,
                    encryption_key: exchange.keys().encryption.public,
                });
            }
            membership::certified_target(
                identity,
                d.encryption_key.as_deref(),
                d.encryption_key_sig.as_deref(),
            )
        })
        .collect()
}

/// Another approved device, and whether a new group key can be wrapped for it here.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Member {
    pub id: String,
    pub name: String,
    /// Pinned on this device, by a full-fingerprint comparison or a signed membership.
    pub verified: bool,
    /// It published an encryption key its identity certified (protocol 3).
    pub can_receive_keys: bool,
}

/// The approved devices other than this one, and what each needs before a new key can
/// reach it: a rotation wraps for every approved device, and only to verified ones.
pub async fn other_members(
    api: &ApiClient,
    own_id: &str,
    directory: &Path,
) -> Result<Vec<Member>, String> {
    let verifier = KeyVerifier::new(directory).map_err(|e| e.to_string())?;
    let devices = api.get_device_keys().await.map_err(|e| e.to_string())?;
    Ok(devices
        .devices
        .into_iter()
        .filter(|device| device.status == DeviceStatus::Approved && device.id != own_id)
        .map(|device| {
            let identity = device
                .public_key
                .as_deref()
                .and_then(|key| KeyPair::parse_public_key(key).ok());
            let verified = identity
                .as_ref()
                .is_some_and(|key| verifier.verify_pinned(&device.id, key).is_ok());
            let can_receive_keys = device.public_key.as_ref().is_some_and(|public_key| {
                membership::certified_target(
                    DeviceIdentity {
                        id: device.id.clone(),
                        public_key: public_key.clone(),
                    },
                    device.encryption_key.as_deref(),
                    device.encryption_key_sig.as_deref(),
                )
                .is_ok()
            });
            Member {
                id: device.id,
                name: device.name,
                verified,
                can_receive_keys,
            }
        })
        .collect())
}

/// Why keys could not be brought up to date.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The account has a current group key, but no device gave this one a copy, and
    /// it has none saved. Never a reason to create a new key by itself.
    #[error(
        "This device doesn't have your account's current encryption key, so it can't sync. Verify this device on another device that has the key, or restore it from a backup (Settings → Encryption keys)."
    )]
    MissingCurrentKey {
        /// The account's current key version.
        server_version: i32,
    },
    #[error("{0}")]
    Other(String),
}

impl From<String> for SyncError {
    fn from(error: String) -> Self {
        SyncError::Other(error)
    }
}

impl From<&str> for SyncError {
    fn from(error: &str) -> Self {
        SyncError::Other(error.to_string())
    }
}

impl From<SyncError> for String {
    fn from(error: SyncError) -> Self {
        error.to_string()
    }
}

/// Returns whether rotation is due. Missing wraps never imply a new mesh.
pub async fn synchronize(
    exchange: &mut KeyExchange,
    api: &ApiClient,
    own_id: &str,
    directory: &Path,
) -> Result<bool, SyncError> {
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
            if members.len() != 1
                || members[0].identity.id != own_id
                || candidate.current_version > 1
            {
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
                Err(e) => return Err(result.err().unwrap_or(e).to_string().into()),
            }
        }
        Err(e) => return Err(e.to_string().into()),
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
            return Err(SyncError::MissingCurrentKey {
                server_version: response.current_version,
            });
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

/// The last resort the user confirmed: when neither a device nor a backup holds the
/// account's current group key, starts a new one, wrapped for every approved member.
/// Clips encrypted with a key no device has stay unreadable; keys this device has are
/// kept. Only for the state the user reviewed: `expected_version` must still be the
/// account's current version, and this device must still lack it.
pub async fn reset_group_key(
    exchange: &mut KeyExchange,
    api: &ApiClient,
    own_id: &str,
    directory: &Path,
    expected_version: i32,
) -> Result<i32, String> {
    let current = match synchronize(exchange, api, own_id, directory).await {
        Ok(_) => {
            return Err(
                "This device has your current encryption key now, so nothing was reset.".into(),
            );
        }
        Err(SyncError::MissingCurrentKey { server_version }) => server_version,
        Err(e) => return Err(e.into()),
    };
    if current != expected_version {
        return Err(
            "Your account's encryption keys changed since you looked. Review them again.".into(),
        );
    }
    let members = trusted_members(exchange, api, own_id, directory).await?;
    let new_version = current.checked_add(1).ok_or("key version exhausted")?;
    let key = zeroize::Zeroizing::new(crate::crypto::encrypt::generate_group_key());
    let wrapped_keys = membership::signed_wraps(
        exchange.key_pair(),
        own_id,
        new_version,
        key.as_ref(),
        &members,
    )?;
    let result = api
        .rotate_group_key(&RotateGroupKeyRequest {
            expected_current_version: current,
            new_version,
            wrapped_keys,
        })
        .await;
    // Activated only through the relay's copy, like any rotation
    match synchronize(exchange, api, own_id, directory).await {
        Ok(_) if exchange.current_version >= new_version => {
            log::warn!(
                "Started encryption key version {new_version} after the user confirmed a reset"
            );
            Ok(new_version)
        }
        Ok(_) | Err(SyncError::MissingCurrentKey { .. }) => Err(match result {
            Err(e) => format!("Encryption was not reset: {e}"),
            Ok(_) => "The reset was not confirmed, so no new key was activated.".into(),
        }),
        Err(e) => Err(e.into()),
    }
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
        let keys = DeviceKeys::generate();
        let mut original = KeyExchange::new(keys.clone());
        original.add_key_version(1, vec![11; 32]).unwrap();
        let (old_clip, _) = original.encrypt_payload(b"old clipboard", b"").unwrap();
        original.add_key_version(2, vec![22; 32]).unwrap();
        original
            .save_keyring(&AppConfig::keyring_path(dir.path()))
            .unwrap();
        for _ in 0..2 {
            let restored = restore(keys.clone(), dir.path()).unwrap();
            assert_eq!(restored.current_version, 2);
            assert_eq!(
                restored.decrypt_payload(&old_clip, 1, b"").unwrap(),
                b"old clipboard"
            );
        }
        std::fs::write(AppConfig::keyring_path(dir.path()), "invalid keyring").unwrap();
        assert!(
            restore(keys, dir.path()).is_err(),
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

    #[test]
    fn says_whose_saved_keys_these_are() {
        let dir = tempfile::tempdir().unwrap();
        let blank = AppConfig::default();
        // Nothing saved: free to use for anyone
        assert_eq!(
            account_keys(dir.path(), "https://one.example", "alice", &blank).unwrap(),
            AccountKeys::Ready
        );

        // A keyring from before owner records, after a sign-out cleared the config
        std::fs::write(AppConfig::keyring_path(dir.path()), b"keyring").unwrap();
        assert_eq!(
            account_keys(dir.path(), "https://one.example", "alice", &blank).unwrap(),
            AccountKeys::Unknown
        );
        assert!(bind_account(dir.path(), "https://one.example", "alice", &blank).is_err());
        // …unless the config still names the account
        let configured = AppConfig {
            server_url: "https://one.example/".into(),
            user_id: "alice".into(),
            ..AppConfig::default()
        };
        assert_eq!(
            account_keys(dir.path(), "https://one.example", "alice", &configured).unwrap(),
            AccountKeys::Ready
        );

        // The user's choice is recorded, and then holds for that account only
        record_owner(dir.path(), "https://one.example/", "alice").unwrap();
        assert_eq!(
            read_owner(dir.path()).unwrap(),
            Some(Owner::new("https://one.example", "alice"))
        );
        assert_eq!(
            account_keys(dir.path(), "https://one.example", "alice", &blank).unwrap(),
            AccountKeys::Ready
        );
        assert_eq!(
            account_keys(dir.path(), "https://one.example", "bob", &blank).unwrap(),
            AccountKeys::Other(Owner::new("https://one.example", "alice"))
        );
    }

    #[test]
    fn owner_records_from_earlier_versions_still_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(OWNER_FILE),
            serde_json::json!({"server": "https://one.example", "user": "alice"}).to_string(),
        )
        .unwrap();
        assert_eq!(
            account_keys(
                dir.path(),
                "https://one.example/",
                "alice",
                &AppConfig::default()
            )
            .unwrap(),
            AccountKeys::Ready
        );
    }

    #[test]
    fn a_missing_current_key_is_reported_as_such() {
        let error = SyncError::MissingCurrentKey { server_version: 7 };
        assert!(matches!(
            error,
            SyncError::MissingCurrentKey { server_version: 7 }
        ));
        let message: String = error.into();
        assert!(message.contains("Settings → Encryption keys"), "{message}");
    }

    // ---- against a relay that keeps group keys like the real one ----------------

    use crate::api::client::tests::serve_with;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct Relay {
        current: i32,
        /// (recipient, version, wrap)
        wraps: Vec<(String, i32, serde_json::Value)>,
        devices: Vec<DeviceInfo>,
    }

    async fn fake_relay(relay: Arc<Mutex<Relay>>, own: DeviceIdentity) -> ApiClient {
        let base_url = serve_with(move |request| {
            let mut relay = relay.lock().unwrap();
            let (route, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
            match (request.method.as_str(), route) {
                ("GET", "/api/group-keys/current") if relay.current == 0 => {
                    (404, json!({"error": "no group key version exists"}).to_string())
                }
                ("GET", "/api/group-keys/current") => {
                    let since = query
                        .strip_prefix("since_version=")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(relay.current - 1);
                    let keys: Vec<_> = relay
                        .wraps
                        .iter()
                        .filter(|(to, version, _)| *to == own.id && *version > since)
                        .map(|(_, _, key)| key.clone())
                        .collect();
                    (
                        200,
                        json!({"current_version": relay.current, "keys": keys, "rotation_required": false})
                            .to_string(),
                    )
                }
                ("GET", "/api/devices/keys") => (
                    200,
                    serde_json::to_string(&DeviceKeysResponse {
                        devices: relay.devices.clone(),
                    })
                    .unwrap(),
                ),
                ("POST", "/api/group-keys/rotate") => {
                    let rotation: RotateGroupKeyRequest =
                        serde_json::from_str(&request.body).unwrap();
                    if rotation.expected_current_version != relay.current
                        || rotation.new_version != relay.current + 1
                        || rotation.wrapped_keys.len() != relay.devices.len()
                    {
                        return (409, json!({"error": "version conflict"}).to_string());
                    }
                    let membership = rotation
                        .wrapped_keys
                        .iter()
                        .find_map(|key| key.membership.clone());
                    for wrap in rotation.wrapped_keys {
                        let key = VersionedGroupKey {
                            version: rotation.new_version,
                            encrypted_key: wrap.encrypted_key,
                            from_device_id: own.id.clone(),
                            from_public_key: own.public_key.clone(),
                            from_public_key_sig: None,
                            membership: membership.clone(),
                        };
                        relay.wraps.push((
                            wrap.device_id,
                            rotation.new_version,
                            serde_json::to_value(key).unwrap(),
                        ));
                    }
                    relay.current = rotation.new_version;
                    (200, json!({"message": "key rotated"}).to_string())
                }
                _ => (404, json!({"error": "not found"}).to_string()),
            }
        })
        .await;
        let mut api = ApiClient::new(&base_url);
        api.set_tokens("access".into(), "refresh".into());
        api
    }

    /// The account is at key `current`, but the devices that held it were removed, so
    /// nobody gave this (only) device a copy.
    async fn account_without_key_holders(
        current: i32,
    ) -> (DeviceKeys, DeviceIdentity, Arc<Mutex<Relay>>, ApiClient) {
        let keys = DeviceKeys::generate();
        let own = DeviceIdentity {
            id: uuid::Uuid::new_v4().to_string(),
            public_key: keys.identity.public_key_bytes(),
        };
        let relay = Arc::new(Mutex::new(Relay {
            current,
            wraps: Vec::new(),
            devices: vec![DeviceInfo {
                id: own.id.clone(),
                name: "Linux - box".into(),
                public_key: Some(own.public_key.clone()),
                public_key_sig: None,
                encryption_key: None,
                encryption_key_sig: None,
                last_seen: None,
                online: false,
                status: DeviceStatus::Approved,
            }],
        }));
        let api = fake_relay(relay.clone(), own.clone()).await;
        (keys, own, relay, api)
    }

    #[tokio::test]
    async fn a_reset_starts_a_new_key_only_while_the_current_one_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (keys, own, relay, api) = account_without_key_holders(3).await;
        let mut exchange = KeyExchange::new(keys.clone());
        // An older key, e.g. restored from a backup
        exchange.add_key_version(1, vec![1; 32]).unwrap();

        match synchronize(&mut exchange, &api, &own.id, dir.path()).await {
            Err(SyncError::MissingCurrentKey { server_version }) => assert_eq!(server_version, 3),
            other => panic!("unexpected: {other:?}"),
        }
        // Nothing creates a key by itself
        assert_eq!(relay.lock().unwrap().current, 3);

        // Only for the state the user reviewed
        assert!(
            reset_group_key(&mut exchange, &api, &own.id, dir.path(), 2)
                .await
                .is_err()
        );
        assert_eq!(relay.lock().unwrap().current, 3);

        let version = reset_group_key(&mut exchange, &api, &own.id, dir.path(), 3)
            .await
            .unwrap();
        assert_eq!(version, 4);
        assert_eq!(relay.lock().unwrap().current, 4);
        assert_eq!(exchange.current_version, 4);
        assert_eq!(exchange.keys_by_version[&1], vec![1; 32], "older keys stay");
        // Saved for the next start, and syncing works again
        assert_eq!(restore(keys, dir.path()).unwrap().current_version, 4);
        assert!(
            synchronize(&mut exchange, &api, &own.id, dir.path())
                .await
                .is_ok()
        );

        // Nothing is missing now, so there is nothing to reset
        assert!(
            reset_group_key(&mut exchange, &api, &own.id, dir.path(), 4)
                .await
                .is_err()
        );
        assert_eq!(relay.lock().unwrap().current, 4);
    }

    #[tokio::test]
    async fn a_reset_reaches_every_approved_device_once_each_is_verified_here() {
        let dir = tempfile::tempdir().unwrap();
        let (keys, own, relay, api) = account_without_key_holders(3).await;
        // Another approved device that has no copy of the key either
        let peer_keys = DeviceKeys::generate();
        let peer = DeviceInfo {
            id: uuid::Uuid::new_v4().to_string(),
            name: "macOS - MacBook".into(),
            public_key: Some(peer_keys.identity.public_key_bytes()),
            public_key_sig: None,
            encryption_key: Some(peer_keys.encryption.public_key_bytes()),
            encryption_key_sig: Some(peer_keys.certify_encryption_key()),
            last_seen: None,
            online: false,
            status: DeviceStatus::Approved,
        };
        relay.lock().unwrap().devices.push(peer.clone());
        let mut exchange = KeyExchange::new(keys);

        assert_eq!(
            other_members(&api, &own.id, dir.path()).await.unwrap(),
            [Member {
                id: peer.id.clone(),
                name: peer.name.clone(),
                verified: false,
                can_receive_keys: true,
            }]
        );
        // Never wrapped to a device this one hasn't verified
        let error = reset_group_key(&mut exchange, &api, &own.id, dir.path(), 3)
            .await
            .unwrap_err();
        assert!(error.contains("Verify device macOS - MacBook"), "{error}");
        assert_eq!(relay.lock().unwrap().current, 3);

        // After comparing its full fingerprint (Verify a device)
        KeyVerifier::new(dir.path())
            .unwrap()
            .pin_after_approval(&peer.id, &peer_keys.identity.public)
            .unwrap();
        assert!(other_members(&api, &own.id, dir.path()).await.unwrap()[0].verified);
        assert_eq!(
            reset_group_key(&mut exchange, &api, &own.id, dir.path(), 3)
                .await
                .unwrap(),
            4
        );
        let relay = relay.lock().unwrap();
        let mut recipients: Vec<&str> = relay
            .wraps
            .iter()
            .filter(|(_, version, _)| *version == 4)
            .map(|(to, _, _)| to.as_str())
            .collect();
        recipients.sort();
        let mut expected = [own.id.as_str(), peer.id.as_str()];
        expected.sort();
        assert_eq!(
            recipients, expected,
            "every approved device gets the new key"
        );
    }

    #[tokio::test]
    async fn devices_that_cannot_receive_keys_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (_, own, relay, api) = account_without_key_holders(3).await;
        // Never updated to protocol 3: no certified encryption key
        let outdated = DeviceInfo {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Windows - Old".into(),
            public_key: Some(KeyPair::generate().public_key_bytes()),
            public_key_sig: None,
            encryption_key: None,
            encryption_key_sig: None,
            last_seen: None,
            online: false,
            status: DeviceStatus::Approved,
        };
        relay.lock().unwrap().devices.push(outdated);
        let members = other_members(&api, &own.id, dir.path()).await.unwrap();
        assert!(!members[0].can_receive_keys && !members[0].verified);
    }

    #[tokio::test]
    async fn restoring_the_current_key_from_a_backup_is_enough_to_sync() {
        let dir = tempfile::tempdir().unwrap();
        let (keys, own, relay, api) = account_without_key_holders(3).await;
        let mut exchange = KeyExchange::new(keys);
        exchange.add_key_version(3, vec![3; 32]).unwrap();
        assert!(
            synchronize(&mut exchange, &api, &own.id, dir.path())
                .await
                .is_ok()
        );
        assert_eq!(relay.lock().unwrap().current, 3, "no new key was needed");
    }
}
