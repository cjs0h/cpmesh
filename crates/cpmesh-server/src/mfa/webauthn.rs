//! A minimal WebAuthn relying party for passkeys used as a second factor.
//!
//! Implements the registration and authentication checks of the WebAuthn Level 2
//! specification (§7.1 and §7.2) for what browsers produce with `attestation: "none"`:
//! credential keys in ES256 (P-256), EdDSA (Ed25519) or RS256. Attestation statements are
//! not evaluated, as the "none" conveyance preference implies; any authenticator model
//! is accepted. Signatures are checked with aws-lc-rs.

use std::fmt;

use aws_lc_rs::signature::{self, UnparsedPublicKey};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

pub const ALG_ES256: i64 = -7;
pub const ALG_EDDSA: i64 = -8;
pub const ALG_RS256: i64 = -257;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// Longest credential ID the specification allows.
const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// Ceremony timeout offered to the browser.
pub const TIMEOUT_MS: u64 = 300_000;

/// The relying party ceremonies are checked against.
pub struct RelyingParty<'a> {
    /// RP ID: the domain passkeys are scoped to.
    pub id: &'a str,
    /// Exact origins the browser may report.
    pub origins: &'a [String],
}

#[derive(Debug, PartialEq, Eq)]
pub enum WebauthnError {
    Malformed(&'static str),
    WrongType,
    ChallengeMismatch,
    OriginMismatch,
    RpIdMismatch,
    UserNotPresent,
    CredentialMismatch,
    UnsupportedKey,
    BadSignature,
    CounterRegression,
    UserHandleMismatch,
}

impl fmt::Display for WebauthnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            WebauthnError::Malformed(what) => {
                return write!(f, "malformed passkey response: {what}");
            }
            WebauthnError::WrongType => "unexpected passkey ceremony type",
            WebauthnError::ChallengeMismatch => "passkey challenge does not match",
            WebauthnError::OriginMismatch => "passkey response came from an unexpected origin",
            WebauthnError::RpIdMismatch => "passkey is for a different site",
            WebauthnError::UserNotPresent => "the authenticator did not confirm user presence",
            WebauthnError::CredentialMismatch => "unknown passkey",
            WebauthnError::UnsupportedKey => "this passkey uses an unsupported key type",
            WebauthnError::BadSignature => "passkey signature is invalid",
            WebauthnError::CounterRegression => {
                "passkey signature counter went backwards; the authenticator may be cloned"
            }
            WebauthnError::UserHandleMismatch => "passkey belongs to another account",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for WebauthnError {}

/// `PublicKeyCredential` from `navigator.credentials.create()`, binary fields base64url.
#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub response: AttestationResponse,
}

#[derive(Debug, Deserialize)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(default)]
    pub transports: Vec<String>,
}

/// `PublicKeyCredential` from `navigator.credentials.get()`, binary fields base64url.
#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub response: AssertionResponse,
}

#[derive(Debug, Deserialize)]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle", default)]
    pub user_handle: Option<String>,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

/// A credential that passed registration, ready to store.
#[derive(Debug)]
pub struct NewCredential {
    pub credential_id: Vec<u8>,
    /// The credential public key as a COSE_Key (CBOR), parsed again for each assertion.
    pub public_key: Vec<u8>,
    pub algorithm: i64,
    pub sign_count: u32,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub user_verified: bool,
}

/// A registered credential, as loaded for an assertion.
pub struct StoredCredential<'a> {
    pub credential_id: &'a [u8],
    pub public_key: &'a [u8],
    pub sign_count: u32,
}

/// The outcome of a successful assertion.
#[derive(Debug, PartialEq, Eq)]
pub struct Assertion {
    pub sign_count: u32,
    pub user_verified: bool,
    pub backed_up: bool,
}

/// Decodes base64url, tolerating padding and the standard alphabet.
pub fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    let normalized: String = value
        .trim()
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    URL_SAFE_NO_PAD.decode(normalized).ok()
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `PublicKeyCredentialCreationOptions` for registering a passkey.
pub struct CreationParams<'a> {
    pub rp_name: &'a str,
    pub challenge: &'a [u8],
    pub user_handle: &'a [u8],
    pub user_name: &'a str,
    pub user_display_name: &'a str,
    /// Credentials the user already has (ID and transports), so they are not registered twice.
    pub exclude: &'a [(Vec<u8>, Vec<String>)],
}

pub fn creation_options(rp: &RelyingParty<'_>, p: &CreationParams<'_>) -> serde_json::Value {
    json!({
        "challenge": b64url(p.challenge),
        "rp": { "id": rp.id, "name": p.rp_name },
        "user": {
            "id": b64url(p.user_handle),
            "name": p.user_name,
            "displayName": p.user_display_name,
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": ALG_ES256 },
            { "type": "public-key", "alg": ALG_EDDSA },
            { "type": "public-key", "alg": ALG_RS256 },
        ],
        "timeout": TIMEOUT_MS,
        "attestation": "none",
        "excludeCredentials": descriptors(p.exclude),
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "preferred",
        },
    })
}

/// `PublicKeyCredentialRequestOptions` for asserting one of `allow`.
pub fn request_options(
    rp: &RelyingParty<'_>,
    challenge: &[u8],
    allow: &[(Vec<u8>, Vec<String>)],
) -> serde_json::Value {
    json!({
        "challenge": b64url(challenge),
        "rpId": rp.id,
        "allowCredentials": descriptors(allow),
        "userVerification": "preferred",
        "timeout": TIMEOUT_MS,
    })
}

fn descriptors(credentials: &[(Vec<u8>, Vec<String>)]) -> serde_json::Value {
    credentials
        .iter()
        .map(|(id, transports)| {
            let mut d = json!({ "type": "public-key", "id": b64url(id) });
            if !transports.is_empty() {
                d["transports"] = json!(transports);
            }
            d
        })
        .collect()
}

/// Verifies a registration ceremony (WebAuthn §7.1).
pub fn verify_registration(
    rp: &RelyingParty<'_>,
    expected_challenge: &[u8],
    credential: &RegistrationResponse,
) -> Result<NewCredential, WebauthnError> {
    if credential.kind != "public-key" {
        return Err(WebauthnError::Malformed("credential type"));
    }
    let client_data_json = b64url_decode(&credential.response.client_data_json)
        .ok_or(WebauthnError::Malformed("clientDataJSON encoding"))?;
    check_client_data(rp, &client_data_json, "webauthn.create", expected_challenge)?;

    let attestation = b64url_decode(&credential.response.attestation_object)
        .ok_or(WebauthnError::Malformed("attestationObject encoding"))?;
    let attestation: Value = ciborium::from_reader(attestation.as_slice())
        .map_err(|_| WebauthnError::Malformed("attestationObject CBOR"))?;
    let auth_data = map_get_text(&attestation, "authData")
        .and_then(Value::as_bytes)
        .ok_or(WebauthnError::Malformed("authData"))?;

    let parsed = parse_authenticator_data(auth_data)?;
    check_rp_and_presence(rp, &parsed)?;
    let attested = parsed
        .attested
        .ok_or(WebauthnError::Malformed("attested credential data"))?;

    let raw_id = b64url_decode(&credential.raw_id).ok_or(WebauthnError::Malformed("rawId"))?;
    if raw_id != attested.credential_id {
        return Err(WebauthnError::CredentialMismatch);
    }
    let key = CoseKey::parse(&attested.public_key)?;

    let mut transports: Vec<String> = credential
        .response
        .transports
        .iter()
        .filter(|t| t.len() <= 32 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .take(8)
        .cloned()
        .collect();
    transports.dedup();

    Ok(NewCredential {
        credential_id: attested.credential_id,
        public_key: attested.public_key,
        algorithm: key.algorithm(),
        sign_count: parsed.sign_count,
        transports,
        backup_eligible: parsed.flags & FLAG_BE != 0,
        user_verified: parsed.flags & FLAG_UV != 0,
    })
}

/// Verifies an authentication ceremony (WebAuthn §7.2) against a stored credential.
pub fn verify_authentication(
    rp: &RelyingParty<'_>,
    expected_challenge: &[u8],
    stored: &StoredCredential<'_>,
    expected_user_handle: &[u8],
    credential: &AuthenticationResponse,
) -> Result<Assertion, WebauthnError> {
    if credential.kind != "public-key" {
        return Err(WebauthnError::Malformed("credential type"));
    }
    let raw_id = b64url_decode(&credential.raw_id).ok_or(WebauthnError::Malformed("rawId"))?;
    if raw_id != stored.credential_id {
        return Err(WebauthnError::CredentialMismatch);
    }
    if let Some(handle) = credential
        .response
        .user_handle
        .as_deref()
        .filter(|h| !h.is_empty())
    {
        let handle = b64url_decode(handle).ok_or(WebauthnError::Malformed("userHandle"))?;
        if handle != expected_user_handle {
            return Err(WebauthnError::UserHandleMismatch);
        }
    }

    let client_data_json = b64url_decode(&credential.response.client_data_json)
        .ok_or(WebauthnError::Malformed("clientDataJSON encoding"))?;
    check_client_data(rp, &client_data_json, "webauthn.get", expected_challenge)?;

    let auth_data = b64url_decode(&credential.response.authenticator_data)
        .ok_or(WebauthnError::Malformed("authenticatorData encoding"))?;
    let parsed = parse_authenticator_data(&auth_data)?;
    check_rp_and_presence(rp, &parsed)?;

    let sig = b64url_decode(&credential.response.signature)
        .ok_or(WebauthnError::Malformed("signature encoding"))?;
    let mut message = auth_data.clone();
    message.extend_from_slice(&Sha256::digest(&client_data_json));
    CoseKey::parse(stored.public_key)?.verify(&message, &sig)?;

    // Authenticators without a counter always report zero; otherwise it must grow
    if (parsed.sign_count != 0 || stored.sign_count != 0) && parsed.sign_count <= stored.sign_count
    {
        return Err(WebauthnError::CounterRegression);
    }

    Ok(Assertion {
        sign_count: parsed.sign_count,
        user_verified: parsed.flags & FLAG_UV != 0,
        backed_up: parsed.flags & FLAG_BS != 0,
    })
}

fn check_client_data(
    rp: &RelyingParty<'_>,
    client_data_json: &[u8],
    expected_type: &str,
    expected_challenge: &[u8],
) -> Result<(), WebauthnError> {
    let client_data: ClientData = serde_json::from_slice(client_data_json)
        .map_err(|_| WebauthnError::Malformed("clientDataJSON"))?;
    if client_data.kind != expected_type {
        return Err(WebauthnError::WrongType);
    }
    let challenge =
        b64url_decode(&client_data.challenge).ok_or(WebauthnError::ChallengeMismatch)?;
    if challenge.is_empty() || challenge != expected_challenge {
        return Err(WebauthnError::ChallengeMismatch);
    }
    if !rp.origins.contains(&client_data.origin) {
        return Err(WebauthnError::OriginMismatch);
    }
    // A ceremony run inside a cross-origin iframe was not run by this site
    if client_data.cross_origin == Some(true) {
        return Err(WebauthnError::OriginMismatch);
    }
    Ok(())
}

fn check_rp_and_presence(
    rp: &RelyingParty<'_>,
    data: &AuthenticatorData,
) -> Result<(), WebauthnError> {
    if data.rp_id_hash != Sha256::digest(rp.id.as_bytes()).as_slice() {
        return Err(WebauthnError::RpIdMismatch);
    }
    if data.flags & FLAG_UP == 0 {
        return Err(WebauthnError::UserNotPresent);
    }
    Ok(())
}

struct AttestedCredential {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
}

struct AuthenticatorData {
    rp_id_hash: Vec<u8>,
    flags: u8,
    sign_count: u32,
    attested: Option<AttestedCredential>,
}

fn parse_authenticator_data(data: &[u8]) -> Result<AuthenticatorData, WebauthnError> {
    const HEADER: usize = 37;
    if data.len() < HEADER {
        return Err(WebauthnError::Malformed("authenticatorData too short"));
    }
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    let mut rest = &data[HEADER..];

    let attested = if flags & FLAG_AT != 0 {
        // aaguid (16) + credential ID length (2)
        if rest.len() < 18 {
            return Err(WebauthnError::Malformed("attested credential data"));
        }
        let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        if id_len == 0 || id_len > MAX_CREDENTIAL_ID_LEN || rest.len() < 18 + id_len {
            return Err(WebauthnError::Malformed("credential ID"));
        }
        let credential_id = rest[18..18 + id_len].to_vec();
        rest = &rest[18 + id_len..];
        let key_len = cbor_item_len(rest)?;
        let public_key = rest[..key_len].to_vec();
        rest = &rest[key_len..];
        Some(AttestedCredential {
            credential_id,
            public_key,
        })
    } else {
        None
    };

    if flags & FLAG_ED != 0 {
        let ext_len = cbor_item_len(rest)?;
        rest = &rest[ext_len..];
    }
    if !rest.is_empty() {
        return Err(WebauthnError::Malformed("trailing authenticatorData bytes"));
    }

    Ok(AuthenticatorData {
        rp_id_hash: data[..32].to_vec(),
        flags,
        sign_count,
        attested,
    })
}

/// Length in bytes of the CBOR item at the start of `data`.
fn cbor_item_len(data: &[u8]) -> Result<usize, WebauthnError> {
    let mut cursor = std::io::Cursor::new(data);
    let _: Value =
        ciborium::from_reader(&mut cursor).map_err(|_| WebauthnError::Malformed("CBOR item"))?;
    usize::try_from(cursor.position()).map_err(|_| WebauthnError::Malformed("CBOR item"))
}

fn map_get_text<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn map_get_int(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(key))
        .map(|(_, v)| v)
}

fn int_of(value: Option<&Value>) -> Option<i128> {
    value?.as_integer().map(i128::from)
}

fn bytes_of(value: Option<&Value>) -> Option<&Vec<u8>> {
    value?.as_bytes()
}

/// A credential public key (RFC 9052 COSE_Key).
enum CoseKey {
    /// Uncompressed SEC1 point.
    Es256(Vec<u8>),
    Ed25519(Vec<u8>),
    Rs256 {
        n: Vec<u8>,
        e: Vec<u8>,
    },
}

impl CoseKey {
    fn parse(cose: &[u8]) -> Result<CoseKey, WebauthnError> {
        let value: Value = ciborium::from_reader(cose)
            .map_err(|_| WebauthnError::Malformed("credential public key"))?;
        let map = value
            .as_map()
            .ok_or(WebauthnError::Malformed("credential public key"))?;
        let kty = int_of(map_get_int(map, 1));
        let alg = int_of(map_get_int(map, 3));
        match (kty, alg) {
            // EC2 / ES256 on P-256
            (Some(2), Some(a)) if a == i128::from(ALG_ES256) => {
                let (x, y) = (
                    bytes_of(map_get_int(map, -2)),
                    bytes_of(map_get_int(map, -3)),
                );
                match (int_of(map_get_int(map, -1)), x, y) {
                    (Some(1), Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => {
                        let mut point = Vec::with_capacity(65);
                        point.push(0x04);
                        point.extend_from_slice(x);
                        point.extend_from_slice(y);
                        Ok(CoseKey::Es256(point))
                    }
                    _ => Err(WebauthnError::UnsupportedKey),
                }
            }
            // OKP / EdDSA on Ed25519
            (Some(1), Some(a)) if a == i128::from(ALG_EDDSA) => {
                match (int_of(map_get_int(map, -1)), bytes_of(map_get_int(map, -2))) {
                    (Some(6), Some(x)) if x.len() == 32 => Ok(CoseKey::Ed25519(x.clone())),
                    _ => Err(WebauthnError::UnsupportedKey),
                }
            }
            // RSA / RS256
            (Some(3), Some(a)) if a == i128::from(ALG_RS256) => {
                match (
                    bytes_of(map_get_int(map, -1)),
                    bytes_of(map_get_int(map, -2)),
                ) {
                    (Some(n), Some(e)) if n.len() >= 256 && !e.is_empty() => Ok(CoseKey::Rs256 {
                        n: n.clone(),
                        e: e.clone(),
                    }),
                    _ => Err(WebauthnError::UnsupportedKey),
                }
            }
            _ => Err(WebauthnError::UnsupportedKey),
        }
    }

    fn algorithm(&self) -> i64 {
        match self {
            CoseKey::Es256(_) => ALG_ES256,
            CoseKey::Ed25519(_) => ALG_EDDSA,
            CoseKey::Rs256 { .. } => ALG_RS256,
        }
    }

    fn verify(&self, message: &[u8], sig: &[u8]) -> Result<(), WebauthnError> {
        let result = match self {
            CoseKey::Es256(point) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
                    .verify(message, sig)
            }
            CoseKey::Ed25519(key) => {
                UnparsedPublicKey::new(&signature::ED25519, key).verify(message, sig)
            }
            CoseKey::Rs256 { n, e } => signature::RsaPublicKeyComponents {
                n: n.as_slice(),
                e: e.as_slice(),
            }
            .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, sig),
        };
        result.map_err(|_| WebauthnError::BadSignature)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    pub const RP_ID: &str = "cpmesh.test";
    pub const ORIGIN: &str = "https://cpmesh.test";

    pub fn origins() -> Vec<String> {
        vec![ORIGIN.to_string()]
    }

    fn cbor(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(value, &mut out).unwrap();
        out
    }

    fn int(v: i64) -> Value {
        Value::Integer(v.into())
    }

    /// A software authenticator for tests: holds one key and builds browser-shaped responses.
    pub struct TestAuthenticator {
        key: TestKey,
        pub credential_id: Vec<u8>,
        pub counter: u32,
        pub flags: u8,
        pub rp_id: String,
        pub origin: String,
    }

    enum TestKey {
        Es256(EcdsaKeyPair),
        Ed25519(Ed25519KeyPair),
        Rs256(aws_lc_rs::rsa::KeyPair),
    }

    impl TestAuthenticator {
        pub fn es256() -> Self {
            let key = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
            Self::with_key(TestKey::Es256(key))
        }

        pub fn ed25519() -> Self {
            Self::with_key(TestKey::Ed25519(Ed25519KeyPair::generate().unwrap()))
        }

        pub fn rs256() -> Self {
            let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
            Self::with_key(TestKey::Rs256(key))
        }

        fn with_key(key: TestKey) -> Self {
            let mut credential_id = vec![0u8; 32];
            aws_lc_rs::rand::fill(&mut credential_id).unwrap();
            TestAuthenticator {
                key,
                credential_id,
                counter: 0,
                flags: FLAG_UP | FLAG_UV,
                rp_id: RP_ID.to_string(),
                origin: ORIGIN.to_string(),
            }
        }

        fn cose_key(&self) -> Vec<u8> {
            let map = match &self.key {
                TestKey::Es256(k) => {
                    let point = k.public_key().as_ref();
                    vec![
                        (int(1), int(2)),
                        (int(3), int(ALG_ES256)),
                        (int(-1), int(1)),
                        (int(-2), Value::Bytes(point[1..33].to_vec())),
                        (int(-3), Value::Bytes(point[33..65].to_vec())),
                    ]
                }
                TestKey::Ed25519(k) => vec![
                    (int(1), int(1)),
                    (int(3), int(ALG_EDDSA)),
                    (int(-1), int(6)),
                    (int(-2), Value::Bytes(k.public_key().as_ref().to_vec())),
                ],
                TestKey::Rs256(k) => {
                    let parts = signature::RsaPublicKeyComponents::<Vec<u8>>::from(k.public_key());
                    vec![
                        (int(1), int(3)),
                        (int(3), int(ALG_RS256)),
                        (int(-1), Value::Bytes(parts.n)),
                        (int(-2), Value::Bytes(parts.e)),
                    ]
                }
            };
            cbor(&Value::Map(map))
        }

        fn auth_data(&self, attested: bool) -> Vec<u8> {
            let mut data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
            let flags = if attested {
                self.flags | FLAG_AT
            } else {
                self.flags
            };
            data.push(flags);
            data.extend_from_slice(&self.counter.to_be_bytes());
            if attested {
                data.extend_from_slice(&[0u8; 16]);
                data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.credential_id);
                data.extend_from_slice(&self.cose_key());
            }
            data
        }

        pub fn client_data(&self, kind: &str, challenge: &[u8]) -> Vec<u8> {
            json!({
                "type": kind,
                "challenge": b64url(challenge),
                "origin": self.origin,
                "crossOrigin": false,
            })
            .to_string()
            .into_bytes()
        }

        /// JSON as the browser serializes `navigator.credentials.create()`.
        pub fn register(&self, challenge: &[u8]) -> serde_json::Value {
            let attestation = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(vec![])),
                (
                    Value::Text("authData".into()),
                    Value::Bytes(self.auth_data(true)),
                ),
            ]);
            json!({
                "id": b64url(&self.credential_id),
                "rawId": b64url(&self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64url(&self.client_data("webauthn.create", challenge)),
                    "attestationObject": b64url(&cbor(&attestation)),
                    "transports": ["internal", "hybrid"],
                },
            })
        }

        /// JSON as the browser serializes `navigator.credentials.get()`.
        pub fn assert(&mut self, challenge: &[u8], user_handle: &[u8]) -> serde_json::Value {
            if self.counter > 0 {
                self.counter += 1;
            }
            let auth_data = self.auth_data(false);
            let client_data = self.client_data("webauthn.get", challenge);
            let mut message = auth_data.clone();
            message.extend_from_slice(&Sha256::digest(&client_data));
            let sig = self.sign(&message);
            json!({
                "id": b64url(&self.credential_id),
                "rawId": b64url(&self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64url(&client_data),
                    "authenticatorData": b64url(&auth_data),
                    "signature": b64url(&sig),
                    "userHandle": b64url(user_handle),
                },
            })
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            match &self.key {
                TestKey::Es256(k) => k
                    .sign(&SystemRandom::new(), message)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                TestKey::Ed25519(k) => k.sign(message).as_ref().to_vec(),
                TestKey::Rs256(k) => {
                    let mut sig = vec![0u8; k.public_modulus_len()];
                    k.sign(
                        &signature::RSA_PKCS1_SHA256,
                        &SystemRandom::new(),
                        message,
                        &mut sig,
                    )
                    .unwrap();
                    sig
                }
            }
        }
    }

    fn register_with(
        auth: &TestAuthenticator,
        challenge: &[u8],
    ) -> Result<NewCredential, WebauthnError> {
        let origins = origins();
        let rp = RelyingParty {
            id: RP_ID,
            origins: &origins,
        };
        let response: RegistrationResponse =
            serde_json::from_value(auth.register(challenge)).unwrap();
        verify_registration(&rp, challenge, &response)
    }

    fn assert_with(
        cred: &NewCredential,
        stored_count: u32,
        expected_challenge: &[u8],
        response: serde_json::Value,
    ) -> Result<Assertion, WebauthnError> {
        let origins = origins();
        let rp = RelyingParty {
            id: RP_ID,
            origins: &origins,
        };
        let response: AuthenticationResponse = serde_json::from_value(response).unwrap();
        verify_authentication(
            &rp,
            expected_challenge,
            &StoredCredential {
                credential_id: &cred.credential_id,
                public_key: &cred.public_key,
                sign_count: stored_count,
            },
            b"user-handle",
            &response,
        )
    }

    #[test]
    fn registers_and_asserts_with_each_supported_algorithm() {
        for (mut auth, alg) in [
            (TestAuthenticator::es256(), ALG_ES256),
            (TestAuthenticator::ed25519(), ALG_EDDSA),
            (TestAuthenticator::rs256(), ALG_RS256),
        ] {
            let cred = register_with(&auth, b"registration-challenge").unwrap();
            assert_eq!(cred.algorithm, alg);
            assert_eq!(cred.credential_id, auth.credential_id);
            assert_eq!(cred.transports, vec!["internal", "hybrid"]);
            assert!(cred.user_verified);
            assert!(!cred.backup_eligible);

            let response = auth.assert(b"login-challenge", b"user-handle");
            let assertion = assert_with(&cred, 0, b"login-challenge", response).unwrap();
            assert_eq!(assertion.sign_count, 0);
            assert!(assertion.user_verified);
        }
    }

    #[test]
    fn registration_rejects_wrong_challenge_origin_type_and_rp() {
        let auth = TestAuthenticator::es256();
        let origins = origins();
        let rp = RelyingParty {
            id: RP_ID,
            origins: &origins,
        };
        let response: RegistrationResponse =
            serde_json::from_value(auth.register(b"challenge")).unwrap();
        assert_eq!(
            verify_registration(&rp, b"other", &response).unwrap_err(),
            WebauthnError::ChallengeMismatch
        );

        let mut evil = TestAuthenticator::es256();
        evil.origin = "https://evil.example".into();
        let response: RegistrationResponse =
            serde_json::from_value(evil.register(b"challenge")).unwrap();
        assert_eq!(
            verify_registration(&rp, b"challenge", &response).unwrap_err(),
            WebauthnError::OriginMismatch
        );

        let mut other_rp = TestAuthenticator::es256();
        other_rp.rp_id = "evil.example".into();
        let response: RegistrationResponse =
            serde_json::from_value(other_rp.register(b"challenge")).unwrap();
        assert_eq!(
            verify_registration(&rp, b"challenge", &response).unwrap_err(),
            WebauthnError::RpIdMismatch
        );

        let mut absent = TestAuthenticator::es256();
        absent.flags = 0;
        let response: RegistrationResponse =
            serde_json::from_value(absent.register(b"challenge")).unwrap();
        assert_eq!(
            verify_registration(&rp, b"challenge", &response).unwrap_err(),
            WebauthnError::UserNotPresent
        );

        // An assertion's client data cannot stand in for a registration
        let mut json = auth.register(b"challenge");
        json["response"]["clientDataJSON"] =
            json!(b64url(&auth.client_data("webauthn.get", b"challenge")));
        let response: RegistrationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            verify_registration(&rp, b"challenge", &response).unwrap_err(),
            WebauthnError::WrongType
        );

        // rawId must name the credential in the authenticator data
        let mut json = auth.register(b"challenge");
        json["rawId"] = json!(b64url(b"another-id"));
        let response: RegistrationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            verify_registration(&rp, b"challenge", &response).unwrap_err(),
            WebauthnError::CredentialMismatch
        );
    }

    #[test]
    fn assertion_rejects_tampering() {
        let mut auth = TestAuthenticator::es256();
        let cred = register_with(&auth, b"c").unwrap();

        // Wrong challenge
        let response = auth.assert(b"login", b"user-handle");
        assert_eq!(
            assert_with(&cred, 0, b"other", response).unwrap_err(),
            WebauthnError::ChallengeMismatch
        );

        // Signature over different data
        let mut response = auth.assert(b"login", b"user-handle");
        let mut sig = b64url_decode(response["response"]["signature"].as_str().unwrap()).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 1;
        response["response"]["signature"] = json!(b64url(&sig));
        assert_eq!(
            assert_with(&cred, 0, b"login", response).unwrap_err(),
            WebauthnError::BadSignature
        );

        // Authenticator data altered after signing (user verification flag flipped)
        let mut response = auth.assert(b"login", b"user-handle");
        let mut data =
            b64url_decode(response["response"]["authenticatorData"].as_str().unwrap()).unwrap();
        data[32] ^= FLAG_UV;
        response["response"]["authenticatorData"] = json!(b64url(&data));
        assert_eq!(
            assert_with(&cred, 0, b"login", response).unwrap_err(),
            WebauthnError::BadSignature
        );

        // Somebody else's account
        let response = auth.assert(b"login", b"other-user");
        assert_eq!(
            assert_with(&cred, 0, b"login", response).unwrap_err(),
            WebauthnError::UserHandleMismatch
        );

        // Another credential's key
        let other = TestAuthenticator::es256();
        let other_cred = register_with(&other, b"c").unwrap();
        let response = auth.assert(b"login", b"user-handle");
        assert_eq!(
            assert_with(&other_cred, 0, b"login", response).unwrap_err(),
            WebauthnError::CredentialMismatch
        );
    }

    #[test]
    fn signature_counter_must_increase_once_used() {
        let mut auth = TestAuthenticator::ed25519();
        auth.counter = 5;
        let cred = register_with(&auth, b"c").unwrap();
        assert_eq!(cred.sign_count, 5);

        let response = auth.assert(b"login", b"user-handle"); // counter 6
        assert_eq!(
            assert_with(&cred, 5, b"login", response)
                .unwrap()
                .sign_count,
            6
        );
        // A clone replaying an older counter value is refused
        let response = auth.assert(b"login", b"user-handle"); // counter 7
        assert_eq!(
            assert_with(&cred, 9, b"login", response).unwrap_err(),
            WebauthnError::CounterRegression
        );
    }

    #[test]
    fn options_carry_challenge_rp_and_credentials() {
        let origins = origins();
        let rp = RelyingParty {
            id: RP_ID,
            origins: &origins,
        };
        let exclude = vec![(b"cred-1".to_vec(), vec!["usb".to_string()])];
        let create = creation_options(
            &rp,
            &CreationParams {
                rp_name: "cpmesh",
                challenge: b"challenge",
                user_handle: b"user-handle",
                user_name: "alice",
                user_display_name: "Alice",
                exclude: &exclude,
            },
        );
        assert_eq!(create["challenge"], b64url(b"challenge"));
        assert_eq!(create["rp"]["id"], RP_ID);
        assert_eq!(create["user"]["id"], b64url(b"user-handle"));
        assert_eq!(create["attestation"], "none");
        assert_eq!(create["excludeCredentials"][0]["id"], b64url(b"cred-1"));
        assert_eq!(create["excludeCredentials"][0]["transports"][0], "usb");
        assert_eq!(create["pubKeyCredParams"].as_array().unwrap().len(), 3);

        let request = request_options(&rp, b"login", &[(b"cred-2".to_vec(), vec![])]);
        assert_eq!(request["rpId"], RP_ID);
        assert_eq!(request["allowCredentials"][0]["id"], b64url(b"cred-2"));
        assert!(request["allowCredentials"][0].get("transports").is_none());
    }

    #[test]
    fn base64url_decoding_is_lenient_about_padding_and_alphabet() {
        assert_eq!(b64url_decode("_-8").unwrap(), vec![0xff, 0xef]);
        assert_eq!(b64url_decode("/+8=").unwrap(), vec![0xff, 0xef]);
        assert_eq!(b64url_decode("not base64!"), None);
    }

    #[test]
    fn authenticator_data_parsing_handles_extensions_and_rejects_garbage() {
        let auth = TestAuthenticator::es256();
        let mut data = auth.auth_data(true);
        data[32] |= FLAG_ED;
        data.extend_from_slice(&cbor(&Value::Map(vec![(
            Value::Text("credProtect".into()),
            int(2),
        )])));
        let parsed = parse_authenticator_data(&data).unwrap();
        assert_eq!(parsed.attested.unwrap().credential_id, auth.credential_id);

        assert!(parse_authenticator_data(&data[..20]).is_err());
        let mut trailing = auth.auth_data(false);
        trailing.push(0);
        assert!(parse_authenticator_data(&trailing).is_err());
    }

    #[test]
    fn unsupported_keys_are_rejected() {
        // ES384 (alg -35) on P-384
        let key = cbor(&Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-35)),
            (int(-1), int(2)),
            (int(-2), Value::Bytes(vec![1; 48])),
            (int(-3), Value::Bytes(vec![1; 48])),
        ]));
        assert!(matches!(
            CoseKey::parse(&key),
            Err(WebauthnError::UnsupportedKey)
        ));
        // RSA key below 2048 bits
        let key = cbor(&Value::Map(vec![
            (int(1), int(3)),
            (int(3), int(ALG_RS256)),
            (int(-1), Value::Bytes(vec![0xff; 128])),
            (int(-2), Value::Bytes(vec![1, 0, 1])),
        ]));
        assert!(matches!(
            CoseKey::parse(&key),
            Err(WebauthnError::UnsupportedKey)
        ));
    }
}
