//! Authorization codes, device codes and user codes. Codes are stored only as SHA-256
//! hashes; user codes are short enough to type, so the endpoints that take them are
//! rate limited.

use sha2::{Digest, Sha256};

use crate::mfa::codes::hex;
use crate::mfa::webauthn::b64url;

/// Letters of user codes: consonants only, so codes spell no words and have no
/// look-alike characters (RFC 8628 section 6.1).
pub const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
/// Letters in a user code (about 34.5 bits), shown as `XXXX-XXXX`.
pub const USER_CODE_LEN: usize = 8;

/// A new authorization code or device code: 32 random bytes, base64url (43 characters).
pub fn random_secret() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    b64url(&bytes)
}

/// How a code is stored: SHA-256, hex.
pub fn hash(code: &str) -> String {
    hex(&Sha256::digest(code.as_bytes()))
}

/// A new user code, normalized (eight letters, no dash).
pub fn random_user_code() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..USER_CODE_LEN)
        .map(|_| char::from(USER_CODE_ALPHABET[rng.random_range(0..USER_CODE_ALPHABET.len())]))
        .collect()
}

/// A user code as typed: case, dashes and spaces do not matter. `None` unless eight
/// letters of the alphabet remain.
pub fn normalize_user_code(input: &str) -> Option<String> {
    if input.len() > 64 {
        return None;
    }
    let code: String = input
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (code.len() == USER_CODE_LEN && code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)))
        .then_some(code)
}

/// A normalized user code as shown to people: `XXXX-XXXX`.
pub fn display_user_code(code: &str) -> String {
    let (first, second) = code.split_at(code.len() / 2);
    format!("{first}-{second}")
}

/// A PKCE S256 challenge: base64url of a SHA-256 digest (43 characters), with some slack.
pub fn is_valid_code_challenge(challenge: &str) -> bool {
    (43..=128).contains(&challenge.len())
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A PKCE code verifier: 43 to 128 unreserved characters (RFC 7636 section 4.1).
pub fn is_valid_code_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// Whether `verifier` is the one `challenge` was made from (S256).
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    b64url(&Sha256::digest(verifier.as_bytes())) == challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_long_random_and_stored_hashed() {
        let (a, b) = (random_secret(), random_secret());
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_eq!(hash(&a).len(), 64);
        assert_eq!(hash(&a), hash(&a));
        assert_ne!(hash(&a), hash(&b));
        assert_eq!(
            hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn user_codes_use_the_alphabet_and_survive_normalization() {
        for _ in 0..200 {
            let code = random_user_code();
            assert_eq!(code.len(), USER_CODE_LEN);
            assert!(
                code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)),
                "{code}"
            );
            assert_eq!(normalize_user_code(&code).as_deref(), Some(code.as_str()));
            let shown = display_user_code(&code);
            assert_eq!(shown.len(), 9);
            assert_eq!(&shown[4..5], "-");
            assert_eq!(normalize_user_code(&shown), Some(code));
        }
    }

    #[test]
    fn typed_user_codes_ignore_case_dashes_and_spaces() {
        for typed in [
            "BCDF-GHJK",
            "bcdf-ghjk",
            "bcdfghjk",
            " BcDf GhJk ",
            "B-C-D-F-G-H-J-K",
            "bcdf\tghjk",
        ] {
            assert_eq!(
                normalize_user_code(typed).as_deref(),
                Some("BCDFGHJK"),
                "{typed:?}"
            );
        }
        for wrong in [
            "",
            "BCDF-GHJ",
            "BCDF-GHJKL",
            "ABCD-EFGH",
            "BCDF-GHJ1",
            "BCDF_GHJK",
            "BCDF–GHJK",
            "ß",
            &"B".repeat(100),
        ] {
            assert_eq!(normalize_user_code(wrong), None, "{wrong:?}");
        }
        assert_eq!(display_user_code("BCDFGHJK"), "BCDF-GHJK");
    }

    #[test]
    fn pkce_s256_matches_only_its_verifier() {
        // RFC 7636 appendix B
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(is_valid_code_verifier(verifier));
        assert!(is_valid_code_challenge(challenge));
        assert!(pkce_matches(verifier, challenge));
        assert!(!pkce_matches(&format!("{verifier}x"), challenge));
        assert!(!pkce_matches(challenge, challenge));

        assert!(is_valid_code_verifier(&"a.b_c~d-".repeat(16)));
        for verifier in [
            "short",
            &"a".repeat(42),
            &"a".repeat(129),
            &format!("{}+", "a".repeat(43)),
        ] {
            assert!(!is_valid_code_verifier(verifier), "{verifier}");
        }
        for challenge in ["short", &"a".repeat(129), &format!("{}=", "a".repeat(43))] {
            assert!(!is_valid_code_challenge(challenge), "{challenge}");
        }
    }
}
