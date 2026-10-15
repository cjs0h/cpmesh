//! Recovery codes and emailed one-time codes.

use rand::Rng;
use sha2::{Digest, Sha256};

pub const RECOVERY_CODE_COUNT: usize = 10;
/// Characters per recovery code: 16 base32 characters carry 80 bits, so stored SHA-256
/// hashes cannot be reversed by brute force.
const RECOVERY_CODE_CHARS: usize = 16;
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Fresh recovery codes, formatted `xxxx-xxxx-xxxx-xxxx` for display.
pub fn generate_recovery_codes() -> Vec<String> {
    let mut rng = rand::rng();
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut bytes = [0u8; RECOVERY_CODE_CHARS];
            rng.fill_bytes(&mut bytes);
            // 256 is a multiple of 32, so masking keeps the characters uniform
            let chars: Vec<char> = bytes
                .iter()
                .map(|b| ALPHABET[(b & 0x1f) as usize] as char)
                .collect();
            chars
                .chunks(4)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("-")
        })
        .collect()
}

/// Canonical form of a typed recovery code (case, spaces and dashes ignored).
pub fn normalize_recovery_code(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (code.len() == RECOVERY_CODE_CHARS && code.bytes().all(|b| ALPHABET.contains(&b)))
        .then_some(code)
}

/// Hash stored for a recovery code (input must already be normalized).
pub fn hash_recovery_code(normalized: &str) -> String {
    hex(&Sha256::digest(normalized.as_bytes()))
}

/// A uniformly random six-digit code, for emails.
pub fn generate_numeric_code() -> String {
    use rand::RngExt;
    format!("{:06}", rand::rng().random_range(0..1_000_000u32))
}

/// Hash stored for an emailed code. Salted with the user ID so equal codes for
/// different users do not share a hash.
pub fn hash_email_code(user_id: uuid::Uuid, code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(code.trim().as_bytes());
    hex(&hasher.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `alice@example.com` → `a***@example.com`, for telling users where a code went.
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) if !local.is_empty() => {
            let first = local.chars().next().unwrap_or('*');
            format!("{first}***@{domain}")
        }
        _ => "***".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn recovery_codes_are_unique_formatted_and_normalizable() {
        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(codes.iter().collect::<HashSet<_>>().len(), codes.len());
        for code in &codes {
            assert_eq!(code.len(), 19, "{code}");
            assert_eq!(code.matches('-').count(), 3, "{code}");
            let normalized = normalize_recovery_code(code).unwrap();
            assert_eq!(normalized.len(), 16);
            // Typed in upper case with spaces still matches
            let typed = code.to_uppercase().replace('-', " ");
            assert_eq!(normalize_recovery_code(&typed).unwrap(), normalized);
        }
    }

    #[test]
    fn malformed_recovery_codes_are_rejected() {
        for bad in [
            "",
            "abcd",
            "abcd-efgh-ijkl-mno",
            "abcd-efgh-ijkl-mnop-q",
            "0bcd-efgh-ijkl-mnop",
            "abcd-efgh-ijkl-mn1p",
        ] {
            assert_eq!(normalize_recovery_code(bad), None, "{bad}");
        }
    }

    #[test]
    fn recovery_code_hash_is_sha256_hex() {
        assert_eq!(
            hash_recovery_code("abcdefghijklmnop"),
            hex(&Sha256::digest(b"abcdefghijklmnop"))
        );
        assert_eq!(hash_recovery_code("abcdefghijklmnop").len(), 64);
    }

    #[test]
    fn numeric_codes_have_six_digits() {
        for _ in 0..200 {
            let code = generate_numeric_code();
            assert_eq!(code.len(), 6, "{code}");
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn email_code_hashes_are_salted_per_user() {
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        assert_eq!(hash_email_code(a, "123456"), hash_email_code(a, " 123456 "));
        assert_ne!(hash_email_code(a, "123456"), hash_email_code(b, "123456"));
        assert_ne!(hash_email_code(a, "123456"), hash_email_code(a, "123457"));
    }

    #[test]
    fn emails_are_masked() {
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
        assert_eq!(mask_email("@example.com"), "***");
        assert_eq!(mask_email("nobody"), "***");
    }
}
