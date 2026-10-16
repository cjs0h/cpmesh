//! Key lifecycle shared by sign-in, startup, reconnect and rotation notifications.
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::api::client::{ApiClient, ApiError};
use crate::config::AppConfig;
use crate::crypto::{
    exchange::KeyExchange,
    keys::{DeviceKeys, KeyPair},
    membership::{self, WrapTarget},
    verify::{KeyVerifier, VerifyError},
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
    match api.get_device_keys().await {
        Ok(devices) => {
            let published = devices
                .devices
                .iter()
                .find(|d| d.id == own_id)
                .and_then(|d| d.encryption_key.as_deref());
            if published == Some(exchange.keys().encryption.public_key_bytes().as_slice()) {
                return Ok(());
            }
        }
        // The listing is for approved devices only. A pending device still has to
        // publish: its approver wraps the group key to this key.
        Err(ApiError::Server { status: 403, .. }) => {}
        Err(e) => return Err(e.to_string()),
    }
    api.publish_encryption_key(exchange.keys())
        .await
        .map_err(|e| format!("Could not publish the device encryption key: {e}"))
}

/// Starts the error naming the devices that keep a new key from every member.
pub const KEY_SHARING_BLOCKED: &str =
    "New keys must reach every device, so first verify or remove on the Devices page:";

/// Approved members whose identity key is pinned locally and whose encryption key
/// that identity certified. Only these receive wraps; the relay's listing alone
/// authorizes nothing. A new key must reach every approved device, so any other
/// approved device is an error that names each one in the way.
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
    let mut targets = Vec::new();
    let mut blocked = Vec::new();
    for device in devices
        .devices
        .into_iter()
        .filter(|d| d.status == DeviceStatus::Approved)
    {
        if device.id == own_id {
            let own_key = exchange.keys().identity.public_key_bytes();
            if device.public_key.as_deref() != Some(own_key.as_slice()) {
                return Err(format!(
                    "The server lists another identity for this device (“{}”); refusing to share keys",
                    device.name
                ));
            }
            // Our own encryption key comes from local storage, never from the relay.
            targets.push(WrapTarget {
                identity: DeviceIdentity {
                    id: device.id,
                    public_key: own_key,
                },
                encryption_key: exchange.keys().encryption.public,
            });
            continue;
        }
        match assess(&verifier, device) {
            (_, Some(target)) => targets.push(target),
            (member, None) => blocked.push(member.blocker()),
        }
    }
    if !blocked.is_empty() {
        return Err(format!("{KEY_SHARING_BLOCKED} {}", blocked.join("; ")));
    }
    Ok(targets)
}

/// How far this device trusts an approved member's identity key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Pinned here: by a full-fingerprint or pairing-code comparison, or through a
    /// membership signed by a device pinned that way.
    Verified,
    /// Never verified on this device.
    Unverified,
    /// The relay lists another identity key than the one verified here.
    KeyChanged,
    /// Removed from the mesh on this device earlier.
    Revoked,
}

/// Another approved device, and whether a new group key can be wrapped for it here.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Member {
    pub id: String,
    pub name: String,
    /// Pinned on this device, by a full-fingerprint comparison or a signed membership.
    pub verified: bool,
    /// Why it isn't, when it isn't.
    pub trust: Trust,
    /// It published an encryption key its identity certified (protocol 3).
    pub can_receive_keys: bool,
    /// The relay's word on whether it holds the current key. It only decides whether
    /// to offer sharing the key; wraps still go only to verified members.
    pub has_current_key: Option<bool>,
}

impl Member {
    /// "Name (why a new key can't reach it)".
    fn blocker(&self) -> String {
        let reason = match self.trust {
            Trust::Unverified => "not verified on this device",
            Trust::KeyChanged => "its identity changed; remove it",
            Trust::Revoked => "removed earlier; remove it again",
            Trust::Verified => "needs an update to receive keys",
        };
        format!("{} ({reason})", self.name)
    }
}

/// An approved device as this device sees it, and the target to wrap new keys for
/// when it is verified here and published a certified encryption key.
fn assess(verifier: &KeyVerifier, device: DeviceInfo) -> (Member, Option<WrapTarget>) {
    let identity = device
        .public_key
        .as_deref()
        .and_then(|key| KeyPair::parse_public_key(key).ok());
    let trust = match identity.map(|key| verifier.verify_pinned(&device.id, &key)) {
        Some(Ok(())) => Trust::Verified,
        Some(Err(VerifyError::NotPinned)) => Trust::Unverified,
        Some(Err(VerifyError::Revoked)) => Trust::Revoked,
        // Including an identity key the relay didn't list, or listed unreadable
        _ => Trust::KeyChanged,
    };
    let target = device.public_key.clone().and_then(|public_key| {
        membership::certified_target(
            DeviceIdentity {
                id: device.id.clone(),
                public_key,
            },
            device.encryption_key.as_deref(),
            device.encryption_key_sig.as_deref(),
        )
        .ok()
    });
    let member = Member {
        id: device.id,
        name: device.name,
        verified: trust == Trust::Verified,
        trust,
        can_receive_keys: target.is_some(),
        has_current_key: device.has_current_key,
    };
    (member, target.filter(|_| trust == Trust::Verified))
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
        .map(|device| assess(&verifier, device).0)
        .collect())
}

/// Why keys could not be brought up to date.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The account has a current group key, but no device gave this one a copy it can
    /// accept, and it has none saved. Never a reason to create a new key by itself.
    #[error("{}", missing_key_message(.shared_by))]
    MissingCurrentKey {
        /// The account's current key version.
        server_version: i32,
        /// A device that sent this one the key but isn't verified here: its keys are
        /// accepted once it is.
        shared_by: Option<String>,
    },
    #[error("{0}")]
    Other(String),
}

fn missing_key_message(shared_by: &Option<String>) -> &'static str {
    if shared_by.is_some() {
        "Another device shared your encryption key with this one, but it isn't verified here yet, so this device can't accept it. Verify that device (Settings → Encryption keys)."
    } else {
        "This device doesn't have your account's current encryption key, so it can't sync. Verify this device on another device that has the key, or restore it from a backup (Settings → Encryption keys)."
    }
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

/// Whether `key` comes from a device this one never verified. Keys from devices it
/// verified, or removed, are for `import_key` to judge.
fn from_unverified_sender(verifier: &KeyVerifier, key: &VersionedGroupKey) -> bool {
    KeyPair::parse_public_key(&key.from_public_key).is_ok_and(|sender| {
        matches!(
            verifier.verify_sender_at(&key.from_device_id, &sender, key.version),
            Err(VerifyError::NotPinned)
        )
    })
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
        // Keys from a device never verified here wait until it is: the relay alone can't
        // make this device trust a sender. A membership imported meanwhile may vouch for
        // it, so those keys get a second look.
        let mut waiting = Vec::new();
        for key in &response.keys {
            if from_unverified_sender(&verifier, key) {
                waiting.push(key);
            } else {
                membership::import_key(&mut candidate, &mut verifier, own_id, key)?;
            }
        }
        let mut shared_by = None;
        for key in waiting {
            if from_unverified_sender(&verifier, key) {
                shared_by.get_or_insert_with(|| key.from_device_id.clone());
            } else {
                membership::import_key(&mut candidate, &mut verifier, own_id, key)?;
            }
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
                shared_by,
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
        Err(SyncError::MissingCurrentKey { server_version, .. }) => server_version,
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
pub(crate) mod tests {
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
        let error = SyncError::MissingCurrentKey {
            server_version: 7,
            shared_by: None,
        };
        assert!(matches!(
            error,
            SyncError::MissingCurrentKey {
                server_version: 7,
                ..
            }
        ));
        let message: String = error.into();
        assert!(message.contains("Settings → Encryption keys"), "{message}");
        // Sent by a device not verified here yet: verifying that one is the way
        let message: String = SyncError::MissingCurrentKey {
            server_version: 7,
            shared_by: Some("d".into()),
        }
        .into();
        assert!(message.contains("isn't verified here yet"), "{message}");
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
                has_current_key: None,
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
            Err(SyncError::MissingCurrentKey {
                server_version,
                shared_by: None,
            }) => assert_eq!(server_version, 3),
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
            has_current_key: None,
        };
        relay.lock().unwrap().devices.push(peer.clone());
        let mut exchange = KeyExchange::new(keys);

        assert_eq!(
            other_members(&api, &own.id, dir.path()).await.unwrap(),
            [Member {
                id: peer.id.clone(),
                name: peer.name.clone(),
                verified: false,
                trust: Trust::Unverified,
                can_receive_keys: true,
                has_current_key: None,
            }]
        );
        // Never wrapped to a device this one hasn't verified
        let error = reset_group_key(&mut exchange, &api, &own.id, dir.path(), 3)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            format!("{KEY_SHARING_BLOCKED} macOS - MacBook (not verified on this device)")
        );
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
            has_current_key: None,
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

    // ---- encryption-key publication against a scripted relay ------------------

    use crate::api::client::tests::serve;

    pub(crate) const NOT_APPROVED: &str = r#"{"error":"device is not approved (status: pending). Approval from another device is required."}"#;

    pub(crate) fn signed_in(base_url: &str) -> ApiClient {
        let mut api = ApiClient::new(base_url);
        api.set_tokens("access".into(), "refresh".into());
        api
    }

    /// A scripted response body; the scripted relay serves `'static` strings.
    pub(crate) fn body(value: impl serde::Serialize) -> &'static str {
        Box::leak(serde_json::to_string(&value).unwrap().into_boxed_str())
    }

    /// The relay's listing with this device publishing `encryption_key`.
    fn listing(own_id: &str, encryption_key: Option<Vec<u8>>) -> &'static str {
        body(DeviceKeysResponse {
            devices: vec![DeviceInfo {
                id: own_id.into(),
                name: "Mac".into(),
                public_key: None,
                public_key_sig: None,
                encryption_key,
                encryption_key_sig: None,
                last_seen: None,
                online: false,
                status: DeviceStatus::Approved,
                has_current_key: None,
            }],
        })
    }

    /// "METHOD /path" of every request the scripted relay received, in order.
    pub(crate) fn requests(
        log: &std::sync::Mutex<Vec<crate::api::client::tests::Recorded>>,
    ) -> Vec<String> {
        log.lock()
            .unwrap()
            .iter()
            .map(|r| format!("{} {}", r.method, r.path))
            .collect()
    }

    #[tokio::test]
    async fn pending_device_publishes_its_key_although_the_listing_is_closed_to_it() {
        let (base_url, log) = serve(vec![(403, NOT_APPROVED), (204, "")]).await;
        let exchange = KeyExchange::new(DeviceKeys::generate());

        publish_encryption_key(&exchange, &signed_in(&base_url), "own")
            .await
            .unwrap();

        assert_eq!(
            requests(&log),
            [
                "GET /api/devices/keys",
                "PUT /api/devices/me/encryption-key"
            ]
        );
        let sent: PublishEncryptionKeyRequest =
            serde_json::from_str(&log.lock().unwrap()[1].body).unwrap();
        assert_eq!(
            sent.encryption_key,
            exchange.keys().encryption.public_key_bytes()
        );
        // Certified by the identity the approver compares, so it can be wrapped to.
        crate::crypto::keys::verify_encryption_key(
            &exchange.key_pair().public,
            &sent.encryption_key,
            &sent.encryption_key_sig,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn approved_device_publishes_only_when_the_relay_lists_another_key() {
        let exchange = KeyExchange::new(DeviceKeys::generate());
        let own_key = exchange.keys().encryption.public_key_bytes();

        let (base_url, log) = serve(vec![(200, listing("own", Some(own_key)))]).await;
        publish_encryption_key(&exchange, &signed_in(&base_url), "own")
            .await
            .unwrap();
        assert_eq!(requests(&log), ["GET /api/devices/keys"]);

        let stale = DeviceKeys::generate().encryption.public_key_bytes();
        for listed in [None, Some(stale)] {
            let (base_url, log) = serve(vec![(200, listing("own", listed)), (204, "")]).await;
            publish_encryption_key(&exchange, &signed_in(&base_url), "own")
                .await
                .unwrap();
            assert_eq!(
                requests(&log),
                [
                    "GET /api/devices/keys",
                    "PUT /api/devices/me/encryption-key"
                ]
            );
        }
    }

    #[tokio::test]
    async fn other_listing_failures_are_reported_without_publishing() {
        let (base_url, log) = serve(vec![(500, r#"{"error":"database unavailable"}"#)]).await;
        let exchange = KeyExchange::new(DeviceKeys::generate());

        let error = publish_encryption_key(&exchange, &signed_in(&base_url), "own")
            .await
            .unwrap_err();
        assert!(error.contains("database unavailable"), "{error}");
        assert_eq!(requests(&log), ["GET /api/devices/keys"]);

        // A rejected publication is reported as such.
        let (base_url, _log) = serve(vec![
            (403, NOT_APPROVED),
            (
                400,
                r#"{"error":"encryption_key_sig is not a valid certification by public_key"}"#,
            ),
        ])
        .await;
        let error = publish_encryption_key(&exchange, &signed_in(&base_url), "own")
            .await
            .unwrap_err();
        assert!(
            error.starts_with("Could not publish the device encryption key"),
            "{error}"
        );
    }

    // ---- sharing the key with an approved device that lacks it -----------------

    use crate::api::client::tests::Recorded;
    use std::collections::HashSet;

    /// How the relay lists an approved device that published `keys`.
    pub(crate) fn listed(id: &str, name: &str, keys: &DeviceKeys) -> DeviceInfo {
        DeviceInfo {
            id: id.into(),
            name: name.into(),
            public_key: Some(keys.identity.public_key_bytes()),
            public_key_sig: None,
            encryption_key: Some(keys.encryption.public_key_bytes()),
            encryption_key_sig: Some(keys.certify_encryption_key()),
            last_seen: None,
            online: false,
            status: DeviceStatus::Approved,
            has_current_key: None,
        }
    }

    /// A session of `device` on the relay; the relay tells callers apart by token.
    pub(crate) fn device_client(base_url: &str, device: &str) -> ApiClient {
        let mut api = ApiClient::new(base_url);
        api.set_tokens(device.into(), "refresh".into());
        api
    }

    struct Wrap {
        recipient: String,
        version: i32,
        encrypted_key: Vec<u8>,
        from_device_id: String,
        from_public_key: Vec<u8>,
        membership: Option<KeyMembership>,
    }

    /// Keeps devices, wraps and the current version the way the server does, for
    /// the routes key sharing uses, for several devices (callers are told apart by token).
    pub(crate) struct Mesh {
        pub(crate) devices: Vec<DeviceInfo>,
        current: i32,
        wraps: Vec<Wrap>,
    }

    impl Mesh {
        pub(crate) async fn start(
            devices: Vec<DeviceInfo>,
            current: i32,
        ) -> (String, Arc<Mutex<Mesh>>) {
            let relay = Arc::new(Mutex::new(Mesh {
                devices,
                current,
                wraps: Vec::new(),
            }));
            let state = relay.clone();
            let base_url = serve_with(move |request| state.lock().unwrap().handle(request)).await;
            (base_url, relay)
        }

        pub(crate) fn holds_current_key(&self, device: &str) -> bool {
            self.wraps
                .iter()
                .any(|w| w.recipient == device && w.version == self.current)
        }

        /// Records that `device` received the current key (its contents don't matter).
        pub(crate) fn give_current_key(&mut self, device: &str) {
            self.wraps.push(Wrap {
                recipient: device.into(),
                version: self.current,
                encrypted_key: Vec::new(),
                from_device_id: device.into(),
                from_public_key: Vec::new(),
                membership: None,
            });
        }

        fn handle(&mut self, request: &Recorded) -> (u16, String) {
            let caller = request
                .authorization
                .as_deref()
                .and_then(|value| value.strip_prefix("Bearer "))
                .unwrap_or_default()
                .to_string();
            let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
            match (request.method.as_str(), path) {
                ("GET", "/api/devices/keys") => {
                    let devices = self
                        .devices
                        .iter()
                        .cloned()
                        .map(|mut d| {
                            if self.current > 0 && d.status == DeviceStatus::Approved {
                                d.has_current_key = Some(self.holds_current_key(&d.id));
                            }
                            d
                        })
                        .collect();
                    (
                        200,
                        serde_json::to_string(&DeviceKeysResponse { devices }).unwrap(),
                    )
                }
                ("GET", "/api/group-keys/current") if self.current == 0 => {
                    (404, r#"{"error":"no group key version exists"}"#.into())
                }
                ("GET", "/api/group-keys/current") => {
                    let since = query
                        .strip_prefix("since_version=")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(self.current - 1);
                    let keys = self
                        .wraps
                        .iter()
                        .filter(|w| w.recipient == caller && w.version > since)
                        .map(|w| VersionedGroupKey {
                            version: w.version,
                            encrypted_key: w.encrypted_key.clone(),
                            from_device_id: w.from_device_id.clone(),
                            from_public_key: w.from_public_key.clone(),
                            from_public_key_sig: None,
                            membership: w.membership.clone(),
                        })
                        .collect();
                    let response = GroupKeysResponse {
                        current_version: self.current,
                        keys,
                        rotation_required: false,
                        rotation_due_at: None,
                    };
                    (200, serde_json::to_string(&response).unwrap())
                }
                ("POST", "/api/group-keys/rotate") => {
                    let rotation: RotateGroupKeyRequest =
                        serde_json::from_str(&request.body).unwrap();
                    // Like the server: compare-and-swap, one wrap per approved device.
                    let approved: HashSet<&str> = self
                        .devices
                        .iter()
                        .filter(|d| d.status == DeviceStatus::Approved)
                        .map(|d| d.id.as_str())
                        .collect();
                    let recipients: HashSet<&str> = rotation
                        .wrapped_keys
                        .iter()
                        .map(|k| k.device_id.as_str())
                        .collect();
                    if rotation.expected_current_version != self.current
                        || rotation.new_version != self.current + 1
                        || recipients != approved
                    {
                        return (409, r#"{"error":"version conflict"}"#.into());
                    }
                    let sender = self
                        .devices
                        .iter()
                        .find(|d| d.id == caller)
                        .and_then(|d| d.public_key.clone())
                        .unwrap();
                    let membership = rotation
                        .wrapped_keys
                        .iter()
                        .find_map(|k| k.membership.clone());
                    for key in rotation.wrapped_keys {
                        self.wraps.push(Wrap {
                            recipient: key.device_id,
                            version: rotation.new_version,
                            encrypted_key: key.encrypted_key,
                            from_device_id: caller.clone(),
                            from_public_key: sender.clone(),
                            membership: membership.clone(),
                        });
                    }
                    self.current = rotation.new_version;
                    (200, r#"{"message":"key rotated"}"#.into())
                }
                ("DELETE", path) if path.starts_with("/api/devices/") => {
                    let id = &path["/api/devices/".len()..];
                    self.devices.retain(|d| d.id != id);
                    (204, String::new())
                }
                _ => (404, r#"{"error":"not found"}"#.into()),
            }
        }
    }

    #[tokio::test]
    async fn every_device_in_the_way_of_new_keys_is_named() {
        let own = DeviceKeys::generate();
        let ids: Vec<String> = (0..6).map(|_| uuid::Uuid::new_v4().to_string()).collect();
        let peers: Vec<DeviceKeys> = (0..5).map(|_| DeviceKeys::generate()).collect();
        let mut devices = vec![listed(&ids[0], "Studio", &own)];
        for (i, name) in ["Laptop", "Phone", "Tablet", "Old Mac", "Watch"]
            .into_iter()
            .enumerate()
        {
            devices.push(listed(&ids[i + 1], name, &peers[i]));
        }
        devices[5].encryption_key_sig = None; // Not updated to protocol 3
        let mut pending = listed(&uuid::Uuid::new_v4().to_string(), "New", &own);
        pending.status = DeviceStatus::Pending;
        devices.push(pending);
        let dir = tempfile::tempdir().unwrap();
        let mut verifier = KeyVerifier::new(dir.path()).unwrap();
        verifier
            .pin_after_approval(&ids[1], &peers[0].identity.public)
            .unwrap();
        // Tablet was verified with another identity than the relay lists now.
        verifier
            .pin_after_approval(&ids[3], &DeviceKeys::generate().identity.public)
            .unwrap();
        verifier
            .pin_after_approval(&ids[4], &peers[3].identity.public)
            .unwrap();
        verifier.remove_pin(&ids[4]).unwrap();
        verifier
            .pin_after_approval(&ids[5], &peers[4].identity.public)
            .unwrap();
        let (base_url, _relay) = Mesh::start(devices, 0).await;
        let api = device_client(&base_url, &ids[0]);

        let members = other_members(&api, &ids[0], dir.path()).await.unwrap();
        let summary: Vec<_> = members
            .iter()
            .map(|m| (m.name.as_str(), m.trust, m.can_receive_keys))
            .collect();
        assert_eq!(
            summary,
            [
                ("Laptop", Trust::Verified, true),
                ("Phone", Trust::Unverified, true),
                ("Tablet", Trust::KeyChanged, true),
                ("Old Mac", Trust::Revoked, true),
                ("Watch", Trust::Verified, false),
            ],
            "neither this device nor pending ones"
        );
        assert!(members.iter().all(|m| m.has_current_key.is_none()));

        let exchange = KeyExchange::new(own);
        let error = trusted_members(&exchange, &api, &ids[0], dir.path())
            .await
            .err()
            .unwrap();
        assert_eq!(
            error,
            format!(
                "{KEY_SHARING_BLOCKED} Phone (not verified on this device); Tablet (its identity changed; remove it); Old Mac (removed earlier; remove it again); Watch (needs an update to receive keys)"
            )
        );
    }

    #[tokio::test]
    async fn a_verified_member_shares_the_current_key_with_an_approved_device_that_lacks_it() {
        let (studio, mac) = (
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        );
        let (studio_keys, mac_keys) = (DeviceKeys::generate(), DeviceKeys::generate());
        let (studio_dir, mac_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        // The studio holds version 1; the Mac was approved without a wrap of it.
        let mut studio_exchange = KeyExchange::new(studio_keys.clone());
        studio_exchange.add_key_version(1, vec![1; 32]).unwrap();
        let (base_url, relay) = Mesh::start(
            vec![
                listed(&studio, "Studio", &studio_keys),
                listed(&mac, "Mac", &mac_keys),
            ],
            1,
        )
        .await;
        let (studio_api, mac_api) = (
            device_client(&base_url, &studio),
            device_client(&base_url, &mac),
        );

        // Instead of a dead end, the Mac is told how to get the key.
        let mut mac_exchange = KeyExchange::new(mac_keys.clone());
        assert!(matches!(
            synchronize(&mut mac_exchange, &mac_api, &mac, mac_dir.path()).await,
            Err(SyncError::MissingCurrentKey {
                server_version: 1,
                shared_by: None
            })
        ));

        // The studio sees that the Mac lacks the key, and shares nothing before
        // verifying it.
        let members = other_members(&studio_api, &studio, studio_dir.path())
            .await
            .unwrap();
        let listed_mac = members.iter().find(|m| m.id == mac).unwrap();
        assert_eq!(
            (listed_mac.trust, listed_mac.has_current_key),
            (Trust::Unverified, Some(false))
        );
        let error = rotate(
            &mut studio_exchange,
            &studio_api,
            &studio,
            studio_dir.path(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            format!("{KEY_SHARING_BLOCKED} Mac (not verified on this device)")
        );
        assert!(!relay.lock().unwrap().holds_current_key(&mac));

        // Once the studio verified the Mac (pairing code or fingerprint), it shares.
        KeyVerifier::new(studio_dir.path())
            .unwrap()
            .pin_after_approval(&mac, &mac_keys.identity.public)
            .unwrap();
        rotate(
            &mut studio_exchange,
            &studio_api,
            &studio,
            studio_dir.path(),
        )
        .await
        .unwrap();
        assert_eq!(studio_exchange.current_version, 2);
        assert!(relay.lock().unwrap().holds_current_key(&mac));

        // The Mac refuses the key until it verified the studio itself, and says who sent it.
        match synchronize(&mut mac_exchange, &mac_api, &mac, mac_dir.path()).await {
            Err(SyncError::MissingCurrentKey {
                server_version: 2,
                shared_by,
            }) => assert_eq!(shared_by.as_deref(), Some(studio.as_str())),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(!mac_exchange.has_group_key());
        KeyVerifier::new(mac_dir.path())
            .unwrap()
            .pin_after_approval(&studio, &studio_keys.identity.public)
            .unwrap();
        synchronize(&mut mac_exchange, &mac_api, &mac, mac_dir.path())
            .await
            .unwrap();
        assert_eq!(mac_exchange.current_version, 2);
        let (sealed, version) = studio_exchange
            .encrypt_payload(b"from the studio", b"")
            .unwrap();
        assert_eq!(
            mac_exchange.decrypt_payload(&sealed, version, b"").unwrap(),
            b"from the studio"
        );
    }
}
