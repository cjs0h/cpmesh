use sha2::{Digest, Sha256};

const FINGERPRINT_SALT: &str = "cpnet-device-fp-v1";

/// Generate a stable device fingerprint by hashing a platform-specific hardware ID
/// with the user's ID. The same physical device always produces the same fingerprint
/// for a given user, even across reinstalls.
pub fn generate_device_fingerprint(user_id: &str) -> Result<String, String> {
    let raw_id = get_platform_id()?;
    Ok(fingerprint_from_platform_id(&raw_id, user_id))
}

/// Deterministically derives the fingerprint: `hex(SHA-256("{raw_id}:{user_id}:{salt}"))`.
fn fingerprint_from_platform_id(raw_id: &str, user_id: &str) -> String {
    let input = format!("{}:{}:{}", raw_id, user_id, FINGERPRINT_SALT);
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// Auto-generate a human-readable device name from platform + hostname.
pub fn auto_device_name() -> String {
    let platform = platform_name();

    let hostname = gethostname::gethostname().to_string_lossy().to_string();

    // On mobile, hostname is often generic; just use platform name
    if cfg!(any(target_os = "android", target_os = "ios")) || hostname.is_empty() {
        platform.to_string()
    } else {
        format!("{} - {}", platform, hostname)
    }
}

/// Human-readable name of the current platform.
fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "android") {
        "Android"
    } else if cfg!(target_os = "ios") {
        "iOS"
    } else {
        "Unknown"
    }
}

// --- Platform-specific hardware ID retrieval ---

#[cfg(target_os = "windows")]
fn get_platform_id() -> Result<String, String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
        .map_err(|e| format!("Failed to open registry key: {e}"))?;
    let guid: String = key
        .get_value("MachineGuid")
        .map_err(|e| format!("Failed to read MachineGuid: {e}"))?;
    Ok(guid)
}

#[cfg(target_os = "macos")]
fn get_platform_id() -> Result<String, String> {
    let output = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map_err(|e| format!("Failed to run ioreg: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("IOPlatformUUID") {
            // Line format: "IOPlatformUUID" = "XXXXXXXX-XXXX-..."
            if let Some(uuid) = line.split('"').nth(3) {
                return Ok(uuid.to_string());
            }
        }
    }
    Err("IOPlatformUUID not found in ioreg output".into())
}

#[cfg(target_os = "linux")]
fn get_platform_id() -> Result<String, String> {
    std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("Failed to read /etc/machine-id: {e}"))
}

#[cfg(target_os = "android")]
fn get_platform_id() -> Result<String, String> {
    // On Android, read the unique device ID from the system property.
    // This is populated by the Kotlin plugin bridge (see android/DeviceFingerprintPlugin.kt).
    // Falls back to a build fingerprint if the plugin hasn't set the value.
    let output = std::process::Command::new("getprop")
        .arg("ro.serialno")
        .output()
        .map_err(|e| format!("Failed to get Android serial: {e}"))?;
    let serial = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if serial.is_empty() {
        // Fallback: use Build.FINGERPRINT which is stable per device/ROM
        let output = std::process::Command::new("getprop")
            .arg("ro.build.fingerprint")
            .output()
            .map_err(|e| format!("Failed to get build fingerprint: {e}"))?;
        let fp = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if fp.is_empty() {
            return Err("Could not determine Android device ID".into());
        }
        Ok(fp)
    } else {
        Ok(serial)
    }
}

#[cfg(target_os = "ios")]
fn get_platform_id() -> Result<String, String> {
    // On iOS, identifierForVendor is accessed via the Swift/ObjC bridge.
    // The Tauri iOS plugin populates this value at startup.
    // As a compile-time fallback, return an error prompting plugin setup.
    Err("iOS fingerprint requires the native plugin bridge — ensure DeviceFingerprintPlugin is loaded".into())
}

#[cfg(not(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    target_os = "ios"
)))]
fn get_platform_id() -> Result<String, String> {
    Err("Unsupported platform for device fingerprinting".into())
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_sha256_hex_of_salted_input() {
        let fp = fingerprint_from_platform_id("machine-guid", "user-1");
        assert_eq!(fp.len(), 64);
        assert!(
            fp.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        let expected = hex::encode(Sha256::digest(b"machine-guid:user-1:cpnet-device-fp-v1"));
        assert_eq!(fp, expected);
    }

    #[test]
    fn fingerprint_is_deterministic_and_user_scoped() {
        let a1 = fingerprint_from_platform_id("machine-guid", "user-1");
        let a2 = fingerprint_from_platform_id("machine-guid", "user-1");
        let b = fingerprint_from_platform_id("machine-guid", "user-2");
        let c = fingerprint_from_platform_id("other-machine", "user-1");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert_ne!(a1, c);
    }

    #[test]
    fn device_fingerprint_uses_platform_id_when_available() {
        // The platform ID comes from the OS (registry / machine-id / ioreg); CI
        // containers do not always expose one, so only assert when it does.
        match generate_device_fingerprint("user-1") {
            Ok(fp) => {
                assert_eq!(fp.len(), 64);
                assert_eq!(fp, generate_device_fingerprint("user-1").unwrap());
                assert_ne!(fp, generate_device_fingerprint("user-2").unwrap());
            }
            Err(e) => eprintln!("platform ID unavailable on this host, skipping: {e}"),
        }
    }

    #[test]
    fn auto_device_name_starts_with_platform() {
        let name = auto_device_name();
        assert!(!name.is_empty());
        assert!(name.starts_with(platform_name()), "{name}");
        if cfg!(any(target_os = "android", target_os = "ios")) {
            assert_eq!(name, platform_name());
        }
    }
}
