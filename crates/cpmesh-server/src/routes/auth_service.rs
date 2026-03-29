use jsonwebtoken::{decode, encode, Header, Validation, DecodingKey, EncodingKey, Algorithm};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::RwLock;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::rngs::OsRng;
use tracing::warn;

use crate::routes::middleware::AuthClaims;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    exp: u64,
    iat: u64,
    jti: String,
    #[serde(default = "default_token_type")]
    tt: String, // "access" or "refresh"
}

fn default_token_type() -> String {
    "access".to_string()
}

/// A parsed public key with its key ID.
struct PublicKeyEntry {
    kid: String,
    decoding_key: DecodingKey,
}

/// Result of validating a refresh token.
pub enum RefreshResult {
    /// Valid token: (claims, jti, exp)
    Ok(AuthClaims, String, u64),
    /// Token was already revoked — possible theft
    Reused(uuid::Uuid),
    /// Token is invalid (expired, bad signature, wrong type, etc.)
    Invalid(String),
}

pub struct AuthService {
    active_kid: String,
    encoding_key: EncodingKey,
    public_keys: Vec<PublicKeyEntry>,
    access_expiry: Duration,
    refresh_expiry: Duration,
    revoked: RwLock<HashMap<String, u64>>, // L1 cache: jti -> expires_at
    pool: Option<PgPool>,
}

impl AuthService {
    /// Create an AuthService with RS256 keys.
    /// - `active_kid`: key ID to embed in JWT headers
    /// - `private_key_pem`: RSA private key in PEM format for signing
    /// - `public_keys_json`: JSON array of `[{"kid":"...", "pem":"..."}]` for verification
    pub fn new(active_kid: &str, private_key_pem: &str, public_keys_json: &str, pool: Option<PgPool>) -> Result<Self, String> {
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| format!("invalid JWT private key PEM: {e}"))?;

        let public_keys = parse_public_keys(public_keys_json)?;
        if public_keys.is_empty() {
            return Err("no JWT public keys configured".to_string());
        }

        Ok(AuthService {
            active_kid: active_kid.to_string(),
            encoding_key,
            public_keys,
            access_expiry: Duration::from_secs(3600),           // 1 hour
            refresh_expiry: Duration::from_secs(7 * 24 * 3600), // 7 days
            revoked: RwLock::new(HashMap::new()),
            pool,
        })
    }

    pub fn hash_password(&self, password: &str) -> Result<String, String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("hash password: {e}"))?;
        Ok(hash.to_string())
    }

    pub fn check_password(&self, hash: &str, password: &str) -> bool {
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    pub fn generate_access_token(&self, user_id: uuid::Uuid, device_id: Option<uuid::Uuid>) -> Result<String, String> {
        let now = now_secs();
        let claims = Claims {
            user_id: user_id.to_string(),
            device_id: device_id.map(|d| d.to_string()),
            exp: now + self.access_expiry.as_secs(),
            iat: now,
            jti: generate_jti(),
            tt: "access".to_string(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| format!("encode token: {e}"))
    }

    pub fn generate_refresh_token(&self, user_id: uuid::Uuid) -> Result<String, String> {
        let now = now_secs();
        let claims = Claims {
            user_id: user_id.to_string(),
            device_id: None,
            exp: now + self.refresh_expiry.as_secs(),
            iat: now,
            jti: generate_jti(),
            tt: "refresh".to_string(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| format!("encode token: {e}"))
    }

    /// Select the decoding key matching the token's `kid` header claim.
    fn decoding_key_for_token(&self, token: &str) -> Result<&DecodingKey, String> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| format!("invalid token header: {e}"))?;

        // Reject non-RS256 tokens
        if header.alg != Algorithm::RS256 {
            return Err(format!("unsupported token algorithm: {:?}, only RS256 is accepted", header.alg));
        }

        let kid = header.kid.unwrap_or_default();
        self.public_keys
            .iter()
            .find(|k| k.kid == kid)
            .map(|k| &k.decoding_key)
            .ok_or_else(|| format!("unknown key ID: {kid}"))
    }

    /// Validate an access token (rejects refresh tokens).
    pub fn validate_access_token(&self, token: &str) -> Result<AuthClaims, String> {
        let decoding_key = self.decoding_key_for_token(token)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        let data = decode::<Claims>(token, decoding_key, &validation)
            .map_err(|e| format!("validate token: {e}"))?;

        // Reject refresh tokens used as access tokens
        if data.claims.tt == "refresh" {
            return Err("refresh token cannot be used as access token".to_string());
        }

        // Check in-memory revocation
        if !data.claims.jti.is_empty() {
            let revoked = self.revoked.read().expect("revoked RwLock poisoned");
            if revoked.contains_key(&data.claims.jti) {
                return Err("token has been revoked".to_string());
            }
        }

        // DB check is done in middleware via check_revoked_db_async
        if !data.claims.jti.is_empty() {
            if let Some(ref pool) = self.pool {
                let _ = (data.claims.jti.clone(), pool.clone());
            }
        }

        let user_id = uuid::Uuid::parse_str(&data.claims.user_id)
            .map_err(|e| format!("invalid user_id in token: {e}"))?;
        let device_id = data.claims.device_id
            .and_then(|d| uuid::Uuid::parse_str(&d).ok());

        Ok(AuthClaims { user_id, device_id, iat: data.claims.iat })
    }

    /// Validate a refresh token. Returns the claims, JTI, and expiry on success.
    /// Returns `RefreshResult::Reused` if the token was already revoked (theft detection).
    pub fn validate_refresh_token(&self, token: &str) -> RefreshResult {
        let decoding_key = match self.decoding_key_for_token(token) {
            Ok(k) => k,
            Err(e) => return RefreshResult::Invalid(e),
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        let data = match decode::<Claims>(token, decoding_key, &validation) {
            Ok(d) => d,
            Err(e) => return RefreshResult::Invalid(format!("validate token: {e}")),
        };

        // Must be a refresh token (legacy tokens without tt field default to "access")
        if data.claims.tt != "refresh" {
            return RefreshResult::Invalid("not a refresh token".to_string());
        }

        // Check revocation — if revoked, this is a reuse (theft detection)
        if !data.claims.jti.is_empty() {
            let revoked = self.revoked.read().expect("revoked RwLock poisoned");
            if revoked.contains_key(&data.claims.jti) {
                if let Ok(uid) = uuid::Uuid::parse_str(&data.claims.user_id) {
                    return RefreshResult::Reused(uid);
                }
                return RefreshResult::Invalid("token has been revoked".to_string());
            }
        }

        let user_id = match uuid::Uuid::parse_str(&data.claims.user_id) {
            Ok(uid) => uid,
            Err(e) => return RefreshResult::Invalid(format!("invalid user_id: {e}")),
        };
        let device_id = data.claims.device_id
            .and_then(|d| uuid::Uuid::parse_str(&d).ok());

        RefreshResult::Ok(
            AuthClaims { user_id, device_id, iat: data.claims.iat },
            data.claims.jti,
            data.claims.exp,
        )
    }

    /// Backward-compatible validate_token (used during transition, accepts both types).
    pub fn validate_token(&self, token: &str) -> Result<AuthClaims, String> {
        self.validate_access_token(token)
    }

    /// Revoke a token by JTI. Persists to DB if pool is available.
    pub fn revoke_token(&self, jti: &str, user_id: uuid::Uuid, expires_at: u64) {
        // L1: in-memory
        {
            let mut revoked = self.revoked.write().expect("revoked RwLock poisoned");
            revoked.insert(jti.to_string(), expires_at);
        }

        // L2: persist to DB (fire-and-forget)
        if let Some(ref pool) = self.pool {
            let pool = pool.clone();
            let jti = jti.to_string();
            tokio::spawn(async move {
                if let Err(e) = sqlx::query(
                    "INSERT INTO revoked_tokens (jti, user_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (jti) DO NOTHING"
                )
                .bind(&jti)
                .bind(user_id)
                .bind(expires_at as i64)
                .execute(&pool)
                .await {
                    warn!("Failed to persist revoked token: {e}");
                }
            });
        }
    }

    /// Check if a JTI is revoked in the database and promote to in-memory cache.
    pub async fn check_revoked_db_async(&self, jti: &str) -> bool {
        if let Some(ref pool) = self.pool {
            let row: Option<(i64,)> = sqlx::query_as(
                "SELECT expires_at FROM revoked_tokens WHERE jti = $1"
            )
            .bind(jti)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

            if let Some((expires_at,)) = row {
                // Promote to L1 cache
                let mut revoked = self.revoked.write().expect("revoked RwLock poisoned");
                revoked.insert(jti.to_string(), expires_at as u64);
                return true;
            }
        }
        false
    }

    /// Spawn a background task that cleans up expired revoked tokens.
    pub fn start_cleanup(&self) {
        if let Some(ref pool) = self.pool {
            let pool = pool.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let now = now_secs() as i64;
                    let _ = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < $1")
                        .bind(now)
                        .execute(&pool)
                        .await;
                }
            });
        }
    }
}

/// Parse a JSON array of `[{"kid":"...", "pem":"..."}]` into public key entries.
fn parse_public_keys(json_str: &str) -> Result<Vec<PublicKeyEntry>, String> {
    if json_str.is_empty() {
        return Ok(vec![]);
    }

    #[derive(Deserialize)]
    struct KeyEntry {
        kid: String,
        pem: String,
    }

    let entries: Vec<KeyEntry> = serde_json::from_str(json_str)
        .map_err(|e| format!("invalid JWT_PUBLIC_KEYS_JSON: {e}"))?;

    entries.into_iter().map(|entry| {
        let decoding_key = DecodingKey::from_rsa_pem(entry.pem.as_bytes())
            .map_err(|e| format!("invalid public key PEM for kid '{}': {e}", entry.kid))?;
        Ok(PublicKeyEntry { kid: entry.kid, decoding_key })
    }).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

pub fn now_epoch() -> u64 {
    now_secs()
}

fn generate_jti() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
