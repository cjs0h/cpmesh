//! Moving keys out of the way, and bringing keys back from a backup.
//!
//! Key material is never deleted. Setting keys aside moves the files that belong to
//! the account they were used with into a new folder under `backups/` in the app data
//! folder, with a `backup.json` saying when and why. The device identity stays, so
//! this device can still open them later. Restoring opens a backup's keyring with the
//! identity key that saved it (one kept in the backup, like a pre-protocol-3
//! `device.key`, or this device's own) and adds its group keys to this device's
//! keyring, which is saved again under the current identity.

use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::crypto::exchange::{KeyExchange, SavedKeys, read_keyring};
use crate::crypto::keys::{KeyPair, write_private_file};
use crate::key_sync::{OWNER_FILE, Owner};

pub const BACKUPS_DIR: &str = "backups";
/// Accounts' files kept while another account uses this computer.
pub const ARCHIVE_DIR: &str = "archive";
const MANIFEST: &str = "backup.json";
const KEYRING: &str = "keyring.enc";
/// Larger files are not keys cpmesh wrote.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// Everything that belongs to the account the keys were used with: its group keys,
/// the record of whose they are, the devices pinned for it, their message clocks and
/// the local (decrypted) clipboard history.
pub const ACCOUNT_FILES: &[&str] = &[
    KEYRING,
    OWNER_FILE,
    "verified_keys.json",
    "sender_clocks.json",
    "pinned_keys.json",
    "history.db",
    "history.db-wal",
    "history.db-shm",
    "history.db-journal",
];

/// Just the group keys: for when this device's identity changed but its account didn't.
pub const KEYRING_FILES: &[&str] = &[KEYRING];

#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    #[serde(default)]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    reason: Option<String>,
    /// Public identity key (base64) of the device that set the keys aside.
    #[serde(default)]
    identity_public_key: Option<String>,
    #[serde(default)]
    owner: Option<Owner>,
    #[serde(default)]
    app_version: Option<String>,
}

/// A backup as the app shows it before restoring.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BackupInfo {
    /// The folder to restore from.
    pub path: String,
    pub name: String,
    /// When cpmesh set these keys aside (RFC 3339); unknown for other backups.
    pub created_at: Option<String>,
    /// Why cpmesh set them aside.
    pub reason: Option<String>,
    /// The server of the account they belonged to, when recorded.
    pub owner_server: Option<String>,
    /// Whether they are recorded as this account's; `None` when nothing says whose.
    pub same_account: Option<bool>,
    /// The group key versions inside, when the keyring could be opened.
    pub versions: Vec<i32>,
    /// Why it can't be restored, when it can't.
    pub problem: Option<String>,
}

/// Moves those of `files` that exist in `dir` into a new backup folder, and returns
/// the folder, or `None` when there was nothing to move.
pub fn set_aside(
    dir: &Path,
    files: &[&str],
    reason: &str,
    identity: Option<&KeyPair>,
    owner: Option<Owner>,
) -> Result<Option<PathBuf>, String> {
    move_files(
        dir,
        &dir.join(BACKUPS_DIR),
        "keys-",
        files,
        reason,
        identity,
        owner,
    )
}

/// Puts `owner`'s files away while another account uses this computer, in
/// `archive/<server>_<user>_<time>/`. They come back when `owner` signs in here again
/// ([`archived_for`], [`bring_back`]).
pub fn archive(
    dir: &Path,
    owner: &Owner,
    identity: Option<&KeyPair>,
) -> Result<Option<PathBuf>, String> {
    let host = owner
        .server
        .split("://")
        .last()
        .unwrap_or_default()
        .trim_end_matches('/');
    let user: String = owner.user.chars().take(8).collect();
    let prefix = format!("{}_{}_", file_name_part(host), file_name_part(&user));
    move_files(
        dir,
        &dir.join(ARCHIVE_DIR),
        &prefix,
        ACCOUNT_FILES,
        "archived while another account used this computer",
        identity,
        Some(owner.clone()),
    )
}

/// `text` with anything a file name shouldn't hold replaced.
fn file_name_part(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn move_files(
    dir: &Path,
    root: &Path,
    prefix: &str,
    files: &[&str],
    reason: &str,
    identity: Option<&KeyPair>,
    owner: Option<Owner>,
) -> Result<Option<PathBuf>, String> {
    let present: Vec<&str> = files
        .iter()
        .copied()
        .filter(|name| dir.join(name).exists())
        .collect();
    if present.is_empty() {
        return Ok(None);
    }
    let folder = create_folder(root, prefix)
        .map_err(|e| format!("Could not create a backup folder: {e}"))?;
    let manifest = Manifest {
        created_at: Some(chrono::Utc::now()),
        reason: Some(reason.to_string()),
        identity_public_key: identity.map(|key| STANDARD.encode(key.public_key_bytes())),
        owner,
        app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    // Written first, so even a backup interrupted halfway says what it is
    write_private_file(
        &folder.join(MANIFEST),
        &serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Could not write the backup: {e}"))?;
    for name in present {
        std::fs::rename(dir.join(name), folder.join(name))
            .map_err(|e| format!("Could not move {name} into {}: {e}", folder.display()))?;
    }
    log::info!("Moved keys into {}", folder.display());
    Ok(Some(folder))
}

/// A new folder only this user can open, named after `prefix` and the local time.
fn create_folder(root: &Path, prefix: &str) -> std::io::Result<PathBuf> {
    private_dir_builder().recursive(true).create(root)?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let mut n = 1;
    loop {
        let name = match n {
            1 => format!("{prefix}{stamp}"),
            _ => format!("{prefix}{stamp}-{n}"),
        };
        match private_dir_builder().create(root.join(&name)) {
            Ok(()) => return Ok(root.join(name)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1,
            Err(e) => return Err(e),
        }
    }
}

fn private_dir_builder() -> std::fs::DirBuilder {
    #[allow(unused_mut)]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
}

/// Backup folders in the app data folder `dir`, newest first: the ones cpmesh made
/// under `backups/` and `archive/`, and folders next to its files that hold a keyring
/// (backups made by hand, the way keys were recovered before cpmesh could do it).
pub fn list(dir: &Path) -> Vec<PathBuf> {
    newest_first(
        subfolders(&dir.join(BACKUPS_DIR))
            .into_iter()
            .chain(subfolders(&dir.join(ARCHIVE_DIR)))
            .chain(
                subfolders(dir)
                    .into_iter()
                    .filter(|folder| folder.join(KEYRING).is_file()),
            ),
    )
}

fn newest_first(folders: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut folders: Vec<(std::time::SystemTime, PathBuf)> = folders
        .into_iter()
        .map(|folder| {
            let modified = std::fs::metadata(&folder)
                .and_then(|meta| meta.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            (modified, folder)
        })
        .collect();
    folders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    folders.into_iter().map(|(_, folder)| folder).collect()
}

/// Archived files recorded as `owner`'s, newest first.
pub fn archived_for(dir: &Path, owner: &Owner) -> Vec<PathBuf> {
    newest_first(
        subfolders(&dir.join(ARCHIVE_DIR))
            .into_iter()
            .filter(|folder| recorded_owner(folder).as_ref() == Some(owner)),
    )
}

/// Whether `dir` holds none of an account's files, as after archiving them.
pub fn holds_no_account_files(dir: &Path) -> bool {
    ACCOUNT_FILES.iter().all(|name| !dir.join(name).exists())
}

/// Moves an archive's files back into `dir`, never over a file already there, and
/// removes the archive folder once nothing of the account is left in it.
pub fn bring_back(dir: &Path, folder: &Path) -> Result<(), String> {
    for name in ACCOUNT_FILES {
        let archived = folder.join(name);
        if archived.exists() && !dir.join(name).exists() {
            std::fs::rename(&archived, dir.join(name))
                .map_err(|e| format!("Could not bring back {name}: {e}"))?;
        }
    }
    if ACCOUNT_FILES.iter().all(|name| !folder.join(name).exists()) {
        let _ = std::fs::remove_file(folder.join(MANIFEST));
        let _ = std::fs::remove_dir(folder);
    }
    log::info!("Brought back the keys archived in {}", folder.display());
    Ok(())
}

fn subfolders(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect()
        })
        .unwrap_or_default()
}

/// The folder and keyring file for a folder or keyring path the user chose.
fn locate(path: &Path) -> Result<(PathBuf, PathBuf), String> {
    if path.is_dir() {
        let keyring = path.join(KEYRING);
        if !keyring.is_file() {
            return Err(format!(
                "There is no {KEYRING} in {}. Choose the folder that has it.",
                path.display()
            ));
        }
        Ok((path.to_path_buf(), keyring))
    } else if path.is_file() {
        let folder = path
            .parent()
            .ok_or("Choose the folder that has the keyring")?;
        Ok((folder.to_path_buf(), path.to_path_buf()))
    } else {
        Err(format!("{} doesn't exist.", path.display()))
    }
}

fn read_small(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

fn manifest(folder: &Path) -> Manifest {
    read_small(&folder.join(MANIFEST))
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or_default()
}

/// Whose keys these are, as recorded by cpmesh when it set them aside or used them.
fn recorded_owner(folder: &Path) -> Option<Owner> {
    manifest(folder)
        .owner
        .or_else(|| {
            read_small(&folder.join(OWNER_FILE))
                .and_then(|data| serde_json::from_slice::<Owner>(&data).ok())
        })
        .map(|owner| Owner::new(&owner.server, &owner.user))
}

/// Identity keys kept in a backup: a pre-protocol-3 `device.key`, or the credential
/// store's file fallback (a copy of an app data folder).
fn backup_identities(folder: &Path) -> Vec<KeyPair> {
    let mut found = Vec::new();
    let pem = folder.join("device.key");
    if read_small(&pem).is_some()
        && let Ok(private) = KeyPair::load_private_key(&pem)
    {
        found.push(KeyPair {
            public: private.public_key(),
            private,
        });
    }
    if let Some(encoded) =
        read_small(&folder.join(".secret_device_identity_key")).map(zeroize::Zeroizing::new)
        && let Ok(scalar) = STANDARD.decode(String::from_utf8_lossy(&encoded).trim())
        && let Ok(key) = KeyPair::from_scalar_bytes(&zeroize::Zeroizing::new(scalar))
    {
        found.push(key);
    }
    found
}

/// Public identity keys a backup is known to belong to, for recognizing the backup of
/// a device registration.
pub fn identity_public_keys(folder: &Path) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = backup_identities(folder)
        .iter()
        .map(KeyPair::public_key_bytes)
        .collect();
    if let Some(recorded) = manifest(folder)
        .identity_public_key
        .and_then(|key| STANDARD.decode(key).ok())
    {
        keys.push(recorded);
    }
    keys
}

/// Opens the keyring with whichever identity key saved it.
fn open(folder: &Path, keyring: &Path, current: Option<&KeyPair>) -> Result<SavedKeys, String> {
    if read_small(keyring).is_none() {
        return Err(format!("{} is not a cpmesh keyring.", keyring.display()));
    }
    let mut identities = backup_identities(folder);
    identities.extend(current.cloned());
    identities
        .iter()
        .find_map(|identity| read_keyring(keyring, identity).ok())
        .ok_or_else(|| {
            "Neither this device's key nor a device key in the backup opens it. Add the device.key \
             that was next to it to the folder and try again."
                .to_string()
        })
}

/// Describes the backup at `path` for the restore screen: `current` is this device's
/// identity and `account` the account it is signed in to.
pub fn inspect(path: &Path, current: Option<&KeyPair>, account: Option<&Owner>) -> BackupInfo {
    let mut info = BackupInfo {
        path: path.display().to_string(),
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        created_at: None,
        reason: None,
        owner_server: None,
        same_account: None,
        versions: Vec::new(),
        problem: None,
    };
    let (folder, keyring) = match locate(path) {
        Ok(found) => found,
        Err(problem) => {
            info.problem = Some(problem);
            return info;
        }
    };
    let manifest = manifest(&folder);
    info.created_at = manifest.created_at.map(|at| at.to_rfc3339());
    info.reason = manifest.reason;
    let owner = recorded_owner(&folder);
    info.owner_server = owner.as_ref().map(|owner| owner.server.clone());
    info.same_account = owner
        .as_ref()
        .zip(account)
        .map(|(owner, account)| owner == account);
    match open(&folder, &keyring, current) {
        Ok(saved) => info.versions = saved.keys.keys().copied().collect(),
        Err(problem) => info.problem = Some(problem),
    }
    if info.same_account == Some(false) {
        info.problem = Some(ANOTHER_ACCOUNT.into());
    }
    info
}

const ANOTHER_ACCOUNT: &str =
    "These keys belong to another account. cpmesh never uses one account's keys for another.";

/// Adds the group keys of the backup at `path` to `exchange`, keeping every key it
/// already has, and returns the versions it added. The caller saves the keyring.
pub fn restore_into(
    exchange: &mut KeyExchange,
    path: &Path,
    account: &Owner,
) -> Result<Vec<i32>, String> {
    let (folder, keyring) = locate(path)?;
    if recorded_owner(&folder).is_some_and(|owner| owner != *account) {
        return Err(ANOTHER_ACCOUNT.into());
    }
    let saved = open(&folder, &keyring, Some(exchange.key_pair()))?;
    let mut candidate = exchange.clone();
    let mut added = Vec::new();
    for (version, key) in &saved.keys {
        match candidate.keys_by_version.get(version) {
            Some(existing) if existing.as_slice() == key.as_slice() => {}
            Some(_) => {
                return Err(format!(
                    "This backup's key {version} differs from the one this device has, so it \
                     is from another account. Nothing was restored."
                ));
            }
            None => {
                candidate
                    .add_key_version(*version, key.to_vec())
                    .map_err(|e| e.to_string())?;
                added.push(*version);
            }
        }
    }
    *exchange = candidate;
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::DeviceKeys;

    fn owner(user: &str) -> Owner {
        Owner::new("https://cpmesh.example", user)
    }

    fn keyring_with(keys: &DeviceKeys, versions: &[(i32, u8)], dir: &Path) -> KeyExchange {
        let mut exchange = KeyExchange::new(keys.clone());
        for (version, byte) in versions {
            exchange.add_key_version(*version, vec![*byte; 32]).unwrap();
        }
        exchange.save_keyring(&dir.join(KEYRING)).unwrap();
        exchange
    }

    #[test]
    fn setting_aside_moves_files_into_a_private_folder_and_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let keys = DeviceKeys::generate();
        keyring_with(&keys, &[(1, 1)], dir.path());
        std::fs::write(dir.path().join("history.db"), b"history").unwrap();
        std::fs::write(dir.path().join("config.json"), b"{}").unwrap();

        let folder = set_aside(
            dir.path(),
            ACCOUNT_FILES,
            "unknown owner",
            Some(&keys.identity),
            None,
        )
        .unwrap()
        .unwrap();
        assert!(folder.starts_with(dir.path().join(BACKUPS_DIR)));
        assert!(!dir.path().join(KEYRING).exists());
        assert!(!dir.path().join("history.db").exists());
        assert!(folder.join(KEYRING).is_file());
        assert_eq!(
            std::fs::read(folder.join("history.db")).unwrap(),
            b"history"
        );
        // Files that are not the account's stay
        assert!(dir.path().join("config.json").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&folder).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }

        // A second backup in the same second gets its own folder
        keyring_with(&keys, &[(1, 1)], dir.path());
        let second = set_aside(dir.path(), KEYRING_FILES, "again", None, None)
            .unwrap()
            .unwrap();
        assert_ne!(second, folder);
        assert_eq!(list(dir.path()).len(), 2);
        // Nothing left to move
        assert_eq!(
            set_aside(dir.path(), KEYRING_FILES, "empty", None, None).unwrap(),
            None
        );
    }

    #[test]
    fn restores_keys_set_aside_under_the_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let keys = DeviceKeys::generate();
        keyring_with(&keys, &[(1, 1), (2, 2)], dir.path());
        let folder = set_aside(
            dir.path(),
            ACCOUNT_FILES,
            "test",
            Some(&keys.identity),
            None,
        )
        .unwrap()
        .unwrap();

        let info = inspect(&folder, Some(&keys.identity), Some(&owner("alice")));
        assert_eq!(info.versions, [1, 2]);
        assert_eq!(info.problem, None);
        assert!(info.created_at.is_some());
        assert_eq!(
            info.same_account, None,
            "legacy keys have no recorded owner"
        );

        let mut exchange = KeyExchange::new(keys.clone());
        exchange.add_key_version(3, vec![3; 32]).unwrap();
        let added = restore_into(&mut exchange, &folder, &owner("alice")).unwrap();
        assert_eq!(added, [1, 2]);
        assert_eq!(exchange.current_version, 3);
        assert_eq!(exchange.keys_by_version[&1], vec![1; 32]);
        // The backup itself stays
        assert!(folder.join(KEYRING).is_file());
    }

    #[test]
    fn re_encrypts_a_keyring_saved_under_an_earlier_identity() {
        let backup = tempfile::tempdir().unwrap();
        let old = DeviceKeys::generate();
        keyring_with(&old, &[(4, 4)], backup.path());
        // The identity key kept next to it, as pre-protocol-3 versions did
        old.identity
            .save_private_key(&backup.path().join("device.key"))
            .unwrap();

        let new = DeviceKeys::generate();
        let info = inspect(backup.path(), Some(&new.identity), None);
        assert_eq!(info.versions, [4]);
        let mut exchange = KeyExchange::new(new.clone());
        assert_eq!(
            restore_into(&mut exchange, backup.path(), &owner("alice")).unwrap(),
            [4]
        );
        assert_eq!(
            identity_public_keys(backup.path()),
            [old.identity.public_key_bytes()]
        );

        // Saved again, it opens with the new identity only
        let dir = tempfile::tempdir().unwrap();
        exchange.save_keyring(&dir.path().join(KEYRING)).unwrap();
        assert!(read_keyring(&dir.path().join(KEYRING), &new.identity).is_ok());
        assert!(read_keyring(&dir.path().join(KEYRING), &old.identity).is_err());

        // Without the old identity key there is nothing to open it with
        std::fs::remove_file(backup.path().join("device.key")).unwrap();
        let info = inspect(backup.path(), Some(&new.identity), None);
        assert!(info.versions.is_empty());
        assert!(info.problem.unwrap().contains("device.key"));
    }

    #[test]
    fn opens_with_the_credential_store_file_fallback() {
        let backup = tempfile::tempdir().unwrap();
        let old = DeviceKeys::generate();
        keyring_with(&old, &[(1, 9)], backup.path());
        std::fs::write(
            backup.path().join(".secret_device_identity_key"),
            STANDARD.encode(old.identity.scalar_bytes().as_ref()),
        )
        .unwrap();
        let mut exchange = KeyExchange::new(DeviceKeys::generate());
        restore_into(&mut exchange, backup.path(), &owner("alice")).unwrap();
        assert_eq!(exchange.keys_by_version[&1], vec![9; 32]);
    }

    #[test]
    fn never_restores_another_accounts_keys_or_replaces_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let keys = DeviceKeys::generate();
        keyring_with(&keys, &[(1, 1)], dir.path());
        let folder = set_aside(
            dir.path(),
            ACCOUNT_FILES,
            "another account",
            Some(&keys.identity),
            Some(owner("bob")),
        )
        .unwrap()
        .unwrap();
        let info = inspect(&folder, Some(&keys.identity), Some(&owner("alice")));
        assert_eq!(info.same_account, Some(false));
        assert!(info.problem.is_some());
        let mut exchange = KeyExchange::new(keys.clone());
        assert!(restore_into(&mut exchange, &folder, &owner("alice")).is_err());
        assert!(exchange.keys_by_version.is_empty());
        // Bob gets them back
        assert_eq!(
            restore_into(&mut exchange, &folder, &owner("bob")).unwrap(),
            [1]
        );

        // A different key for a version this device has is another mesh's
        let other = tempfile::tempdir().unwrap();
        keyring_with(&keys, &[(1, 7), (2, 2)], other.path());
        let mut exchange = KeyExchange::new(keys.clone());
        exchange.add_key_version(1, vec![1; 32]).unwrap();
        assert!(restore_into(&mut exchange, other.path(), &owner("alice")).is_err());
        assert!(
            !exchange.keys_by_version.contains_key(&2),
            "nothing is restored when one key conflicts"
        );
    }

    #[test]
    fn finds_backups_made_by_hand_next_to_the_app_files() {
        let dir = tempfile::tempdir().unwrap();
        let old = DeviceKeys::generate();
        // How keys were recovered by hand before: keyring and device key in a folder
        let manual = dir.path().join("legacy-v0.2.1-keys-backup-20261016-143359");
        std::fs::create_dir(&manual).unwrap();
        keyring_with(&old, &[(2, 2)], &manual);
        old.identity
            .save_private_key(&manual.join("device.key"))
            .unwrap();
        // Folders without a keyring are not backups
        std::fs::create_dir(dir.path().join("WebKitCache")).unwrap();

        let found = list(dir.path());
        assert_eq!(found, std::slice::from_ref(&manual));
        let info = inspect(&found[0], Some(&DeviceKeys::generate().identity), None);
        assert_eq!(info.versions, [2]);
        assert_eq!(info.problem, None);
    }

    #[test]
    fn an_accounts_archive_comes_back_only_for_that_account() {
        let dir = tempfile::tempdir().unwrap();
        let keys = DeviceKeys::generate();
        let alice = Owner::new(
            "https://relay.example.org/",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
        );
        keyring_with(&keys, &[(1, 1)], dir.path());
        crate::key_sync::record_owner(dir.path(), &alice.server, &alice.user).unwrap();
        std::fs::write(dir.path().join("history.db"), b"alice's clips").unwrap();

        let folder = archive(dir.path(), &alice, Some(&keys.identity))
            .unwrap()
            .unwrap();
        assert!(folder.starts_with(dir.path().join(ARCHIVE_DIR)));
        let name = folder.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("relay.example.org_0f1e2d3c_"), "{name}");
        assert!(holds_no_account_files(dir.path()));
        // Listed for restoring, too, recorded as Alice's
        assert_eq!(list(dir.path()), std::slice::from_ref(&folder));
        let bob = Owner::new("https://other.example", "bob");
        assert_eq!(
            inspect(&folder, Some(&keys.identity), Some(&bob)).same_account,
            Some(false)
        );

        assert!(archived_for(dir.path(), &bob).is_empty());
        assert_eq!(
            archived_for(dir.path(), &alice),
            std::slice::from_ref(&folder)
        );
        bring_back(dir.path(), &folder).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("history.db")).unwrap(),
            b"alice's clips"
        );
        assert_eq!(
            crate::key_sync::read_owner(dir.path()).unwrap(),
            Some(alice.clone())
        );
        assert!(read_keyring(&dir.path().join(KEYRING), &keys.identity).is_ok());
        // Nothing of Alice's is left behind, so the archive is gone
        assert!(!folder.exists());
        assert!(archived_for(dir.path(), &alice).is_empty());
    }

    #[test]
    fn recognizes_an_account_archived_by_hand() {
        // How an account was set aside by hand before: its files moved into archive/,
        // with the owner record 0.4.0 wrote and no manifest
        let dir = tempfile::tempdir().unwrap();
        let keys = DeviceKeys::generate();
        let folder = dir
            .path()
            .join(ARCHIVE_DIR)
            .join("relay.example.org_0f1e2d3c_by-hand");
        std::fs::create_dir_all(&folder).unwrap();
        keyring_with(&keys, &[(3, 3)], &folder);
        std::fs::write(
            folder.join(OWNER_FILE),
            br#"{"server":"https://relay.example.org","user":"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"}"#,
        )
        .unwrap();
        std::fs::write(folder.join("history.db"), b"clips").unwrap();
        let alice = Owner::new(
            "https://relay.example.org/",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
        );

        assert_eq!(list(dir.path()), std::slice::from_ref(&folder));
        let someone_else = Owner::new("https://relay.example.org", "c0ffee00");
        assert!(archived_for(dir.path(), &someone_else).is_empty());
        assert_eq!(
            archived_for(dir.path(), &alice),
            std::slice::from_ref(&folder)
        );
        let info = inspect(&folder, Some(&keys.identity), Some(&alice));
        assert_eq!(info.same_account, Some(true));
        assert_eq!(info.versions, [3]);

        bring_back(dir.path(), &folder).unwrap();
        assert_eq!(
            crate::key_sync::read_owner(dir.path()).unwrap(),
            Some(alice)
        );
        assert!(read_keyring(&dir.path().join(KEYRING), &keys.identity).is_ok());
        assert!(!folder.exists());
    }

    #[test]
    fn bringing_back_never_overwrites_files_in_use() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Owner::new("https://one.example", "alice");
        std::fs::write(dir.path().join("history.db"), b"archived").unwrap();
        let folder = archive(dir.path(), &alice, None).unwrap().unwrap();
        std::fs::write(dir.path().join("history.db"), b"in use").unwrap();
        bring_back(dir.path(), &folder).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("history.db")).unwrap(),
            b"in use"
        );
        // What could not come back stays archived
        assert_eq!(
            std::fs::read(folder.join("history.db")).unwrap(),
            b"archived"
        );
    }

    #[test]
    fn explains_folders_without_a_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let info = inspect(dir.path(), None, None);
        assert!(info.problem.unwrap().contains("no keyring.enc"));
        let info = inspect(&dir.path().join("missing"), None, None);
        assert!(info.problem.unwrap().contains("doesn't exist"));
        let mut exchange = KeyExchange::new(DeviceKeys::generate());
        assert!(restore_into(&mut exchange, dir.path(), &owner("alice")).is_err());
    }
}
