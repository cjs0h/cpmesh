//! Time-based one-time passwords (RFC 6238) for authenticator apps.

use aws_lc_rs::{constant_time, hmac};
use rand::Rng;

/// Secret length in bytes (160 bits, as RFC 4226 recommends for HMAC-SHA1).
pub const SECRET_LEN: usize = 20;
pub const STEP_SECS: u64 = 30;
pub const DIGITS: usize = 6;

pub fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; SECRET_LEN];
    rand::rng().fill_bytes(&mut secret);
    secret
}

/// HOTP value (RFC 4226) of `secret` at `counter`, truncated to `digits` digits.
fn hotp(secret: &[u8], counter: u64, digits: usize) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mac = hmac::sign(&key, &counter.to_be_bytes());
    let hash = mac.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(hash[offset]) & 0x7f) << 24
        | u32::from(hash[offset + 1]) << 16
        | u32::from(hash[offset + 2]) << 8
        | u32::from(hash[offset + 3]);
    let modulus = 10u32.pow(digits as u32);
    format!("{:0width$}", binary % modulus, width = digits)
}

/// The code an authenticator shows during time step `step`.
pub fn code_at(secret: &[u8], step: u64) -> String {
    hotp(secret, step, DIGITS)
}

pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// Accepts "123456", "123 456" or "123-456".
fn normalize(code: &str) -> Option<String> {
    let digits: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    (digits.len() == DIGITS && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// Checks `code` against the steps around `unix_secs` (one step of clock drift either
/// way). Returns the matching step, which must be newer than `last_used_step` so a
/// code cannot be used twice.
pub fn verify(secret: &[u8], code: &str, unix_secs: u64, last_used_step: u64) -> Option<u64> {
    let code = normalize(code)?;
    let current = step_at(unix_secs);
    let mut matched = None;
    // Check every candidate so timing does not reveal which step matched
    for step in [current.saturating_sub(1), current, current + 1] {
        let candidate = code_at(secret, step);
        if constant_time::verify_slices_are_equal(candidate.as_bytes(), code.as_bytes()).is_ok()
            && step > last_used_step
            && matched.is_none()
        {
            matched = Some(step);
        }
    }
    matched
}

/// RFC 4648 base32 without padding, as authenticator apps expect secrets.
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// The `otpauth://` URI authenticator apps import (usually from a QR code).
pub fn otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    let issuer_enc = urlencoding::encode(issuer);
    format!(
        "otpauth://totp/{issuer_enc}:{account}?secret={secret}&issuer={issuer_enc}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        account = urlencoding::encode(account),
        secret = base32_encode(secret),
    )
}

/// An SVG QR code of `data`, for showing an `otpauth://` URI.
pub fn qr_svg(data: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M).ok()?;
    Some(
        code.render::<svg::Color<'_>>()
            .min_dimensions(200, 200)
            .dark_color(svg::Color("#0a0a0a"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_test_vectors() {
        // RFC 6238 Appendix B lists 8-digit values; authenticators show the last 6.
        for (time, expected) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(hotp(RFC_SECRET, step_at(time), 8), expected, "t={time}");
            assert_eq!(
                code_at(RFC_SECRET, step_at(time)),
                expected[2..],
                "t={time}"
            );
        }
    }

    #[test]
    fn rfc4226_hotp_test_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(code_at(RFC_SECRET, counter as u64), *code);
        }
    }

    #[test]
    fn verify_accepts_one_step_of_drift_and_returns_the_step() {
        let now = 1_700_000_000;
        let step = step_at(now);
        let secret = generate_secret();
        assert_eq!(verify(&secret, &code_at(&secret, step), now, 0), Some(step));
        assert_eq!(
            verify(&secret, &code_at(&secret, step - 1), now, 0),
            Some(step - 1)
        );
        assert_eq!(
            verify(&secret, &code_at(&secret, step + 1), now, 0),
            Some(step + 1)
        );
        assert_eq!(verify(&secret, &code_at(&secret, step - 2), now, 0), None);
        assert_eq!(verify(&secret, &code_at(&secret, step + 2), now, 0), None);
    }

    #[test]
    fn verify_refuses_replays_and_malformed_codes() {
        let now = 1_700_000_000;
        let step = step_at(now);
        let secret = generate_secret();
        let code = code_at(&secret, step);
        // Already used (or an older step was used after it)
        assert_eq!(verify(&secret, &code, now, step), None);
        assert_eq!(verify(&secret, &code, now, step + 1), None);
        assert_eq!(verify(&secret, &code, now, step - 1), Some(step));

        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert_eq!(verify(&secret, &spaced, now, 0), Some(step));
        for bad in ["", "12345", "1234567", "abcdef", "12 34 5"] {
            assert_eq!(verify(&secret, bad, now, 0), None, "{bad}");
        }
        // Another secret's code does not verify
        assert_eq!(verify(&generate_secret(), &code, now, 0), None);
    }

    #[test]
    fn generated_secrets_are_random_and_full_length() {
        let a = generate_secret();
        let b = generate_secret();
        assert_eq!(a.len(), SECRET_LEN);
        assert_ne!(a, b);
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(input.as_bytes()), expected, "{input}");
        }
        assert_eq!(
            base32_encode(RFC_SECRET),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    #[test]
    fn otpauth_uri_encodes_issuer_and_account() {
        let uri = otpauth_uri(RFC_SECRET, "cpmesh", "ada lovelace@example.com");
        assert_eq!(
            uri,
            "otpauth://totp/cpmesh:ada%20lovelace%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=cpmesh&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn qr_svg_renders_an_svg_document() {
        let svg = qr_svg("otpauth://totp/cpmesh:a?secret=ABC").unwrap();
        assert!(svg.contains("<svg"), "{svg}");
        assert!(svg.contains("#0a0a0a"));
    }
}
