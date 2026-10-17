//! Verification of downloaded app updates.
//!
//! Release installers are signed with the project's update key (`tauri signer sign
//! --app-version <version>`, see `scripts/release/sign-installers.sh`), and the public
//! half is compiled into the app from `updater-key.pub`. An installer is only installed
//! when its signature verifies against that key, the version it was signed for is newer
//! than the running app, and it was built for this platform. A compromised server can
//! therefore neither push its own binary nor roll users back to an older release.

use std::collections::HashMap;

use base64::Engine;
use minisign_verify::{PublicKey, Signature};
use thiserror::Error;

/// The update public key in `tauri signer` format; empty when the build has none.
const UPDATE_PUBLIC_KEY: &str = include_str!("../updater-key.pub");

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UpdateError {
    #[error("this build cannot verify updates; download the new version from the website instead")]
    NoPublicKey,
    #[error("the update key built into this app is invalid")]
    BadPublicKey,
    #[error("the update signature is malformed")]
    BadSignature,
    #[error("the update signature is not valid, so it was not published by cpmesh")]
    InvalidSignature,
    #[error("the update signature does not say which version it is for")]
    UnsignedVersion,
    #[error("the update is version {0}, which is not newer than this version ({1})")]
    NotNewer(String, String),
    #[error("the update ({0}) is not built for this platform")]
    WrongPlatform(String),
}

/// An installer whose signature checked out.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedUpdate {
    /// The installer's file name as signed; safe to save it under.
    pub file_name: String,
    pub version: String,
}

/// The platform name used in installer file names (`cpmesh-<version>-<platform>-...`).
pub fn installer_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// Checks a downloaded installer against its `.sig` file before it may be launched.
pub fn verify_update(
    installer: &[u8],
    signature: &str,
    current_version: &str,
    platform: &str,
) -> Result<VerifiedUpdate, UpdateError> {
    verify_with_key(
        UPDATE_PUBLIC_KEY,
        installer,
        signature,
        current_version,
        platform,
    )
}

fn verify_with_key(
    public_key: &str,
    installer: &[u8],
    signature: &str,
    current_version: &str,
    platform: &str,
) -> Result<VerifiedUpdate, UpdateError> {
    let public_key = public_key.trim();
    if public_key.is_empty() {
        return Err(UpdateError::NoPublicKey);
    }
    let public_key = decode_base64_text(public_key)
        .and_then(|text| PublicKey::decode(&text).ok())
        .ok_or(UpdateError::BadPublicKey)?;
    let signature = decode_base64_text(signature.trim())
        .and_then(|text| Signature::decode(&text).ok())
        .ok_or(UpdateError::BadSignature)?;

    // Prehashed signatures only; `tauri signer` has always produced them
    public_key
        .verify(installer, &signature, false)
        .map_err(|_| UpdateError::InvalidSignature)?;

    // The trusted comment is covered by the signature:
    // "timestamp:<unix time>\tfile:<installer name>\tversion:<app version>"
    let fields: HashMap<&str, &str> = signature
        .trusted_comment()
        .split('\t')
        .filter_map(|field| field.split_once(':'))
        .collect();
    let version = *fields.get("version").ok_or(UpdateError::UnsignedVersion)?;
    let file_name = *fields.get("file").ok_or(UpdateError::UnsignedVersion)?;

    match (parse_version(version), parse_version(current_version)) {
        (Some(update), Some(current)) if update > current => {}
        _ => {
            return Err(UpdateError::NotNewer(
                version.to_string(),
                current_version.to_string(),
            ));
        }
    }

    let is_plain_name = !file_name.contains(['/', '\\']) && !file_name.contains("..");
    if !is_plain_name || !file_name.starts_with(&format!("cpmesh-{version}-{platform}-")) {
        return Err(UpdateError::WrongPlatform(file_name.to_string()));
    }

    Ok(VerifiedUpdate {
        file_name: file_name.to_string(),
        version: version.to_string(),
    })
}

/// `tauri signer` writes keys and signatures as base64 of the minisign text format.
fn decode_base64_text(encoded: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn parse_version(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.').map(|p| p.parse::<u64>().ok());
    let parsed = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures made with `tauri signer generate` and `tauri signer sign`. Test keys only.
    const PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDE4OUE3NzlDRDkzQzdCN0YKUldSL2V6elpuSGVhR09QU0JUQ1NPb2ViQjczQ28xRFNMcU5yaG9BdVQyT3oya1JPOW8vYkZxR3IK";
    const OTHER_PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDE5OEYzNkUzNDBEREI5ODcKUldTSHVkMUE0emFQR2VnWWpJWkl4TTFEUmpJanBtODF4Q0tRNVZEVUV6ZXdURjNvbTlWVVdMNGsK";
    const INSTALLER: &[u8] = b"cpmesh test installer\n";
    /// Signs `INSTALLER` as cpmesh-9.9.9-windows-amd64-setup.exe, version 9.9.9.
    const SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSL2V6elpuSGVhR09sYXRLUFAvajZnNGpYYzA1elVrdnkydENvelVzTjZHb092aW50bGVrUk1LL0NibXJMYU9xbkRmWjNNLzRYNEV2L2VnNjRESlJFV2tNaUNvN243bEE0PQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkyMDQzMjYxCWZpbGU6Y3BtZXNoLTkuOS45LXdpbmRvd3MtYW1kNjQtc2V0dXAuZXhlCXZlcnNpb246OS45LjkKK2hYYUcySkV4aTNkRU53dVZoMndxZFRoNThLME9uMFZHYnNrU0IrQnBoRll0T0JhTVozb0M4clNJTi90K1daSzhrWUdHM25WR01XSDhZTVJ5eHVUQ3c9PQo=";
    /// Signs `INSTALLER` without a version (no `--app-version`).
    const UNVERSIONED_SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSL2V6elpuSGVhR00wTGk4NXNpWTcrSTc5eXc5eGFDaFBmMVhZbnNVa0JLV3N0c0hpT1V2MVRSeHJ1TjN0dmhZZGxLbW45eVQzL1l5bEljTzN4dEloVnM0bEwyOGZ3dUFvPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkyMDQzMzUyCWZpbGU6dW52ZXJzaW9uZWQtY3BtZXNoLTkuOS45LXdpbmRvd3MtYW1kNjQtc2V0dXAuZXhlCmhWQ2o1ZkR1NzVwdXIwNmt3QkJyL1JJOTlCNUlNZ3M0N0xUOTBFL0RkVDFZanJkbjhsYTBNcU4wcXIwZHY0MkdhRlE3SDl4OHRtNVlaaE1zVUFwRkFRPT0K";

    fn verify(
        public_key: &str,
        installer: &[u8],
        signature: &str,
        current: &str,
        platform: &str,
    ) -> Result<VerifiedUpdate, UpdateError> {
        verify_with_key(public_key, installer, signature, current, platform)
    }

    #[test]
    fn accepts_a_newer_signed_installer_for_this_platform() {
        let update = verify(PUBLIC_KEY, INSTALLER, SIGNATURE, "0.1.0", "windows").unwrap();
        assert_eq!(
            update,
            VerifiedUpdate {
                file_name: "cpmesh-9.9.9-windows-amd64-setup.exe".into(),
                version: "9.9.9".into(),
            }
        );
        // A trailing newline from a .sig file download is fine
        let signature = format!("{SIGNATURE}\n");
        assert!(verify(PUBLIC_KEY, INSTALLER, &signature, "9.9.8", "windows").is_ok());
    }

    #[test]
    fn rejects_a_modified_installer() {
        assert_eq!(
            verify(
                PUBLIC_KEY,
                b"cpmesh test installer!\n",
                SIGNATURE,
                "0.1.0",
                "windows"
            ),
            Err(UpdateError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_a_signature_from_another_key() {
        assert_eq!(
            verify(OTHER_PUBLIC_KEY, INSTALLER, SIGNATURE, "0.1.0", "windows"),
            Err(UpdateError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_an_altered_trusted_comment() {
        // Claim a different version without re-signing
        let text = decode_base64_text(SIGNATURE)
            .unwrap()
            .replace("version:9.9.9", "version:9.9.10");
        let forged = base64::engine::general_purpose::STANDARD.encode(text);
        assert_eq!(
            verify(PUBLIC_KEY, INSTALLER, &forged, "0.1.0", "windows"),
            Err(UpdateError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_installers_that_are_not_newer() {
        for current in ["9.9.9", "9.10.0", "10.0.0"] {
            assert_eq!(
                verify(PUBLIC_KEY, INSTALLER, SIGNATURE, current, "windows"),
                Err(UpdateError::NotNewer("9.9.9".into(), current.into())),
                "{current}"
            );
        }
        // Unparseable versions fail closed
        assert!(matches!(
            verify(PUBLIC_KEY, INSTALLER, SIGNATURE, "dev", "windows"),
            Err(UpdateError::NotNewer(..))
        ));
    }

    #[test]
    fn rejects_installers_for_another_platform() {
        for platform in ["linux", "macos"] {
            assert_eq!(
                verify(PUBLIC_KEY, INSTALLER, SIGNATURE, "0.1.0", platform),
                Err(UpdateError::WrongPlatform(
                    "cpmesh-9.9.9-windows-amd64-setup.exe".into()
                ))
            );
        }
    }

    #[test]
    fn requires_the_signature_to_name_its_version() {
        assert_eq!(
            verify(
                PUBLIC_KEY,
                INSTALLER,
                UNVERSIONED_SIGNATURE,
                "0.1.0",
                "windows"
            ),
            Err(UpdateError::UnsignedVersion)
        );
    }

    #[test]
    fn fails_closed_without_a_usable_key_or_signature() {
        assert_eq!(
            verify("", INSTALLER, SIGNATURE, "0.1.0", "windows"),
            Err(UpdateError::NoPublicKey)
        );
        assert_eq!(
            verify("  \n", INSTALLER, SIGNATURE, "0.1.0", "windows"),
            Err(UpdateError::NoPublicKey)
        );
        assert_eq!(
            verify("not base64!", INSTALLER, SIGNATURE, "0.1.0", "windows"),
            Err(UpdateError::BadPublicKey)
        );
        for signature in ["", "garbage", "Z2FyYmFnZQ=="] {
            assert_eq!(
                verify(PUBLIC_KEY, INSTALLER, signature, "0.1.0", "windows"),
                Err(UpdateError::BadSignature),
                "{signature}"
            );
        }
    }

    #[test]
    fn built_in_key_is_empty_or_valid() {
        // An empty key only turns off automatic updates; a malformed one is a mistake
        let key = UPDATE_PUBLIC_KEY.trim();
        if !key.is_empty() {
            assert!(
                decode_base64_text(key)
                    .and_then(|text| PublicKey::decode(&text).ok())
                    .is_some(),
                "updater-key.pub is not a public key written by `tauri signer generate`"
            );
        }
    }

    #[test]
    fn parses_release_versions_only() {
        assert_eq!(parse_version("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_version("10.20.30"), Some((10, 20, 30)));
        for bad in ["", "1", "1.2", "1.2.3.4", "1.2.x", "v1.2.3", "1.2.3-beta"] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
    }
}
