use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::oauth::{AGENT_REFRESH_TTL, AgentClaims, Scopes};
use crate::routes::middleware::AuthClaims;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Claims {
    user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    exp: u64,
    iat: u64,
    /// Original session issuance, preserved by refresh and step-up. Unlike `iat`,
    /// it cannot move past a password-change revocation while refresh is in flight.
    #[serde(default, skip_serializing_if = "is_zero")]
    session_start: u64,
    jti: String,
    /// Token type: "access", "refresh", "mfa" (sign-in ticket) or "passkey" (ceremony).
    #[serde(default = "default_token_type")]
    tt: String,
    /// The session was established with a second factor.
    #[serde(default, skip_serializing_if = "is_false")]
    mfa: bool,
    /// When the user last signed in or confirmed a second factor, for actions that
    /// need a recent sign-in. Zero on tokens issued before this claim existed.
    #[serde(default, skip_serializing_if = "is_zero")]
    auth_time: u64,
    /// Sign-in ticket: "verify" or "enroll".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stage: Option<String>,
    /// Sign-in ticket: "pwd" or "sso".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    amr: Option<String>,
    /// Sign-in ticket: the emailed code was confirmed.
    #[serde(default, skip_serializing_if = "is_false")]
    email_ok: bool,
    /// Passkey ceremony: base64url challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chal: Option<String>,
    /// Passkey ceremony: "register" or "authenticate".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    /// Agent session: the OAuth client ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cid: Option<String>,
    /// Agent session: the grant's scopes, separated by spaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scp: Option<String>,
    /// Agent session: the grant ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gid: Option<String>,
}

fn default_token_type() -> String {
    "access".to_string()
}

fn is_false(v: &bool) -> bool {
    !*v
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// What a session (access and refresh token pair) grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionGrant {
    pub user_id: uuid::Uuid,
    pub device_id: Option<uuid::Uuid>,
    pub mfa: bool,
    pub auth_time: u64,
    pub session_start: u64,
    /// The agent the session belongs to; `None` for first-party apps.
    pub agent: Option<AgentClaims>,
}

impl SessionGrant {
    /// A session for a sign-in completed now.
    pub fn signed_in(user_id: uuid::Uuid, mfa: bool) -> Self {
        let now = now_secs();
        SessionGrant {
            user_id,
            device_id: None,
            mfa,
            auth_time: now,
            session_start: now,
            agent: None,
        }
    }

    /// The same session, as described by its claims.
    pub fn from_claims(claims: &AuthClaims) -> Self {
        SessionGrant {
            user_id: claims.user_id,
            device_id: claims.device_id,
            mfa: claims.mfa,
            auth_time: claims.auth_time,
            session_start: claims.session_started_at(),
            agent: claims.agent,
        }
    }

    pub fn with_device(mut self, device_id: Option<uuid::Uuid>) -> Self {
        self.device_id = device_id;
        self
    }

    /// Makes this the session of an agent, under the grant `agent` names.
    pub fn with_agent(mut self, agent: AgentClaims) -> Self {
        self.agent = Some(agent);
        self
    }
}

/// Which step a sign-in ticket allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MfaStage {
    /// The account has a second factor: confirm it.
    Verify,
    /// The account must set up a second factor before signing in.
    Enroll,
}

/// How the first factor was satisfied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstFactor {
    Password,
    Sso,
}

/// A short-lived, single-use ticket proving the first factor of a sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MfaTicket {
    pub user_id: uuid::Uuid,
    pub stage: MfaStage,
    pub first_factor: FirstFactor,
    pub email_ok: bool,
    pub jti: String,
    pub exp: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyPurpose {
    Register,
    Authenticate,
}

impl PasskeyPurpose {
    fn as_str(self) -> &'static str {
        match self {
            PasskeyPurpose::Register => "register",
            PasskeyPurpose::Authenticate => "authenticate",
        }
    }
}

/// A verified passkey challenge token.
#[derive(Debug)]
pub struct PasskeyChallenge {
    pub challenge: Vec<u8>,
    pub jti: String,
    pub exp: u64,
}

/// How long a sign-in ticket can be used to finish signing in.
pub const MFA_TICKET_TTL: Duration = Duration::from_secs(600);
/// How long a passkey ceremony may take.
pub const PASSKEY_CHALLENGE_TTL: Duration = Duration::from_secs(300);

/// A parsed public key with its key ID.
struct PublicKeyEntry {
    kid: String,
    decoding_key: DecodingKey,
}

/// Result of validating a refresh token. Single use is enforced separately by
/// [`AuthService::consume_refresh_token`].
pub enum RefreshResult {
    /// Valid token: (claims, jti, exp)
    Ok(AuthClaims, String, u64),
    /// Token is invalid (expired, bad signature, wrong type, etc.)
    Invalid(String),
}

/// Outcome of recording a refresh token use.
#[derive(Debug, PartialEq, Eq)]
pub enum RefreshTokenUse {
    /// First use: the caller may issue a new token pair.
    First,
    /// Already used moments ago, typically by a concurrent request from the same
    /// client (e.g. two processes sharing a session). Not treated as theft.
    Concurrent,
    /// Used or revoked earlier: treat as token theft.
    Reused,
}

/// How long a second use of a refresh token counts as a benign race rather than theft.
const REFRESH_REUSE_GRACE: Duration = Duration::from_secs(10);

/// How long revocations are kept after the token expires. Must exceed the leeway
/// token validation allows on `exp` (60 seconds by default).
const REVOCATION_RETENTION_MARGIN: Duration = Duration::from_secs(300);

/// A revoked or consumed token in the in-memory cache.
#[derive(Clone, Copy)]
struct Revocation {
    expires_at: u64,
    revoked_at: u64,
}

pub struct AuthService {
    active_kid: String,
    encoding_key: EncodingKey,
    public_keys: Vec<PublicKeyEntry>,
    access_expiry: Duration,
    refresh_expiry: Duration,
    agent_refresh_expiry: Duration,
    refresh_reuse_grace: Duration,
    revoked: Arc<RwLock<HashMap<String, Revocation>>>, // L1 cache keyed by jti
    pool: Option<PgPool>,
}

impl AuthService {
    /// Create an AuthService with RS256 keys.
    /// - `active_kid`: key ID to embed in JWT headers
    /// - `private_key_pem`: RSA private key in PEM format for signing
    /// - `public_keys_json`: JSON array of `[{"kid":"...", "pem":"..."}]` for verification
    pub fn new(
        active_kid: &str,
        private_key_pem: &str,
        public_keys_json: &str,
        pool: Option<PgPool>,
    ) -> Result<Self, String> {
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
            access_expiry: Duration::from_secs(3600), // 1 hour
            refresh_expiry: Duration::from_secs(7 * 24 * 3600), // 7 days
            agent_refresh_expiry: AGENT_REFRESH_TTL,
            refresh_reuse_grace: REFRESH_REUSE_GRACE,
            revoked: Arc::new(RwLock::new(HashMap::new())),
            pool,
        })
    }

    /// How long an access token lasts (the OAuth token endpoint's `expires_in`).
    pub fn access_token_ttl(&self) -> Duration {
        self.access_expiry
    }

    /// Overrides the window in which a repeated refresh token use counts as a benign race.
    pub fn with_refresh_reuse_grace(mut self, grace: Duration) -> Self {
        self.refresh_reuse_grace = grace;
        self
    }

    pub fn hash_password(&self, password: &str) -> Result<String, String> {
        // A random 16-byte salt is generated by the password-hash crate.
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|hash| hash.to_string())
            .map_err(|e| format!("hash password: {e}"))
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

    pub async fn hash_password_async(&self, password: &str) -> Result<String, String> {
        let password = password.to_owned();
        crate::blocking::run(crate::blocking::Work::Password, move || {
            Argon2::default()
                .hash_password(password.as_bytes())
                .map(|hash| hash.to_string())
                .map_err(|e| format!("hash password: {e}"))
        })
        .await
    }

    pub async fn check_password_async(&self, hash: &str, password: &str) -> Result<bool, String> {
        let (hash, password) = (hash.to_owned(), password.to_owned());
        crate::blocking::run(crate::blocking::Work::Password, move || {
            let parsed = PasswordHash::new(&hash)
                .map_err(|e| format!("invalid stored password hash: {e}"))?;
            Ok(Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok())
        })
        .await
    }

    /// Issues an access token for a session that did not use a second factor.
    pub fn generate_access_token(
        &self,
        user_id: uuid::Uuid,
        device_id: Option<uuid::Uuid>,
    ) -> Result<String, String> {
        self.issue_access(&SessionGrant::signed_in(user_id, false).with_device(device_id))
    }

    /// Issues a refresh token for a session that did not use a second factor. A
    /// device-bound token keeps every token refreshed from it bound to the same device.
    pub fn generate_refresh_token(
        &self,
        user_id: uuid::Uuid,
        device_id: Option<uuid::Uuid>,
    ) -> Result<String, String> {
        self.issue_refresh(&SessionGrant::signed_in(user_id, false).with_device(device_id))
    }

    pub fn issue_access(&self, grant: &SessionGrant) -> Result<String, String> {
        self.sign(&self.session_claims(grant, "access", self.access_expiry))
    }

    /// Issues a refresh token: 7 days for first-party sessions, 30 for agents. Each
    /// refresh issues a new one, so both lifetimes slide.
    pub fn issue_refresh(&self, grant: &SessionGrant) -> Result<String, String> {
        let ttl = if grant.agent.is_some() {
            self.agent_refresh_expiry
        } else {
            self.refresh_expiry
        };
        self.sign(&self.session_claims(grant, "refresh", ttl))
    }

    /// Issues an access and refresh token pair.
    pub fn issue_session(&self, grant: &SessionGrant) -> Result<(String, String), String> {
        Ok((self.issue_access(grant)?, self.issue_refresh(grant)?))
    }

    pub fn issue_device_challenge(
        &self,
        user_id: uuid::Uuid,
        access_token: &str,
    ) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        self.sign(&Claims {
            chal: Some(crate::mfa::webauthn::b64url(&Sha256::digest(
                access_token.as_bytes(),
            ))),
            ..base_claims(user_id, "device-proof", Duration::from_secs(120))
        })
    }

    pub fn validate_device_challenge(
        &self,
        challenge: &str,
        user_id: uuid::Uuid,
        access_token: &str,
    ) -> Result<(String, u64), String> {
        use sha2::{Digest, Sha256};
        let claims = self.decode_typed(challenge, "device-proof")?;
        let session_hash = crate::mfa::webauthn::b64url(&Sha256::digest(access_token.as_bytes()));
        if claims.user_id != user_id.to_string()
            || claims.chal.as_deref() != Some(session_hash.as_str())
        {
            return Err("device challenge belongs to another session".into());
        }
        Ok((claims.jti, claims.exp))
    }

    fn session_claims(&self, grant: &SessionGrant, tt: &str, ttl: Duration) -> Claims {
        Claims {
            device_id: grant.device_id.map(|d| d.to_string()),
            mfa: grant.mfa,
            auth_time: grant.auth_time,
            session_start: grant.session_start,
            cid: grant.agent.map(|agent| agent.client_id.to_string()),
            scp: grant.agent.map(|agent| agent.scopes.to_string()),
            gid: grant.agent.map(|agent| agent.grant_id.to_string()),
            ..base_claims(grant.user_id, tt, ttl)
        }
    }

    /// Issues a sign-in ticket for the second step of signing in.
    pub fn issue_mfa_ticket(
        &self,
        user_id: uuid::Uuid,
        stage: MfaStage,
        first_factor: FirstFactor,
        email_ok: bool,
    ) -> Result<String, String> {
        self.sign(&Claims {
            stage: Some(
                match stage {
                    MfaStage::Verify => "verify",
                    MfaStage::Enroll => "enroll",
                }
                .to_string(),
            ),
            amr: Some(
                match first_factor {
                    FirstFactor::Password => "pwd",
                    FirstFactor::Sso => "sso",
                }
                .to_string(),
            ),
            email_ok,
            ..base_claims(user_id, "mfa", MFA_TICKET_TTL)
        })
    }

    /// Validates a sign-in ticket's signature, type and expiry. Single use is enforced
    /// with [`Self::consume_once`] when the sign-in completes.
    pub fn validate_mfa_ticket(&self, token: &str) -> Result<MfaTicket, String> {
        let claims = self.decode_typed(token, "mfa")?;
        let stage = match claims.stage.as_deref() {
            Some("verify") => MfaStage::Verify,
            Some("enroll") => MfaStage::Enroll,
            _ => return Err("sign-in ticket has no stage".to_string()),
        };
        let first_factor = match claims.amr.as_deref() {
            Some("pwd") => FirstFactor::Password,
            Some("sso") => FirstFactor::Sso,
            _ => return Err("sign-in ticket has no first factor".to_string()),
        };
        if self.is_cached_as_used(&claims.jti) {
            return Err("sign-in ticket has already been used".to_string());
        }
        Ok(MfaTicket {
            user_id: parse_user_id(&claims.user_id)?,
            stage,
            first_factor,
            email_ok: claims.email_ok,
            jti: claims.jti,
            exp: claims.exp,
        })
    }

    /// Issues a token carrying a passkey ceremony's challenge, so the server keeps no
    /// ceremony state. The token is single use (see [`Self::consume_once`]).
    pub fn issue_passkey_challenge(
        &self,
        user_id: uuid::Uuid,
        purpose: PasskeyPurpose,
        challenge: &[u8],
    ) -> Result<String, String> {
        self.sign(&Claims {
            chal: Some(crate::mfa::webauthn::b64url(challenge)),
            purpose: Some(purpose.as_str().to_string()),
            ..base_claims(user_id, "passkey", PASSKEY_CHALLENGE_TTL)
        })
    }

    pub fn validate_passkey_challenge(
        &self,
        token: &str,
        user_id: uuid::Uuid,
        purpose: PasskeyPurpose,
    ) -> Result<PasskeyChallenge, String> {
        let claims = self.decode_typed(token, "passkey")?;
        if parse_user_id(&claims.user_id)? != user_id {
            return Err("passkey challenge belongs to another account".to_string());
        }
        if claims.purpose.as_deref() != Some(purpose.as_str()) {
            return Err("passkey challenge is for another ceremony".to_string());
        }
        let challenge = claims
            .chal
            .as_deref()
            .and_then(crate::mfa::webauthn::b64url_decode)
            .filter(|c| !c.is_empty())
            .ok_or("passkey challenge is missing")?;
        Ok(PasskeyChallenge {
            challenge,
            jti: claims.jti,
            exp: claims.exp,
        })
    }

    /// Marks a single-use token as used. Returns `false` when it was used before.
    pub async fn consume_once(
        &self,
        jti: &str,
        user_id: uuid::Uuid,
        expires_at: u64,
    ) -> Result<bool, String> {
        Ok(self.consume_refresh_token(jti, user_id, expires_at).await? == RefreshTokenUse::First)
    }

    fn is_cached_as_used(&self, jti: &str) -> bool {
        self.revoked
            .read()
            .expect("revoked RwLock poisoned")
            .contains_key(jti)
    }

    fn sign(&self, claims: &Claims) -> Result<String, String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        encode(&header, claims, &self.encoding_key).map_err(|e| format!("encode token: {e}"))
    }

    /// Verifies a token's signature and expiry and requires the token type `tt`.
    fn decode_typed(&self, token: &str, tt: &str) -> Result<Claims, String> {
        let decoding_key = self.decoding_key_for_token(token)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        let data = decode::<Claims>(token, decoding_key, &validation)
            .map_err(|e| format!("validate token: {e}"))?;
        if data.claims.tt != tt {
            return Err(format!(
                "expected a token of type {tt}, got {}",
                data.claims.tt
            ));
        }
        Ok(data.claims)
    }

    /// Select the decoding key matching the token's `kid` header claim.
    fn decoding_key_for_token(&self, token: &str) -> Result<&DecodingKey, String> {
        let header =
            jsonwebtoken::decode_header(token).map_err(|e| format!("invalid token header: {e}"))?;

        // Reject non-RS256 tokens
        if header.alg != Algorithm::RS256 {
            return Err(format!(
                "unsupported token algorithm: {:?}, only RS256 is accepted",
                header.alg
            ));
        }

        let kid = header.kid.unwrap_or_default();
        self.public_keys
            .iter()
            .find(|k| k.kid == kid)
            .map(|k| &k.decoding_key)
            .ok_or_else(|| format!("unknown key ID: {kid}"))
    }

    /// Validate an access token (rejects every other token type).
    pub fn validate_access_token(&self, token: &str) -> Result<AuthClaims, String> {
        let claims = self.decode_typed(token, "access")?;

        // Check in-memory revocation (the database is consulted by the middleware)
        if !claims.jti.is_empty() && self.is_cached_as_used(&claims.jti) {
            return Err("token has been revoked".to_string());
        }

        Ok(AuthClaims {
            user_id: parse_user_id(&claims.user_id)?,
            device_id: claims
                .device_id
                .as_deref()
                .and_then(|d| uuid::Uuid::parse_str(d).ok()),
            iat: claims.iat,
            session_start: claims.session_start,
            mfa: claims.mfa,
            auth_time: claims.auth_time,
            agent: agent_claims(&claims)?,
        })
    }

    /// Validate a refresh token's signature, expiry and type. Returns the claims, JTI,
    /// and expiry on success. Reuse is detected by [`Self::consume_refresh_token`].
    pub fn validate_refresh_token(&self, token: &str) -> RefreshResult {
        // Legacy tokens without a tt field default to "access" and are refused here
        let claims = match self.decode_typed(token, "refresh") {
            Ok(c) => c,
            Err(e) => return RefreshResult::Invalid(e),
        };

        // Single use is tracked by JTI, so a refresh token without one cannot be accepted
        if claims.jti.is_empty() {
            return RefreshResult::Invalid("refresh token has no jti".to_string());
        }

        let user_id = match parse_user_id(&claims.user_id) {
            Ok(uid) => uid,
            Err(e) => return RefreshResult::Invalid(e),
        };
        let agent = match agent_claims(&claims) {
            Ok(agent) => agent,
            Err(e) => return RefreshResult::Invalid(e),
        };
        let device_id = claims
            .device_id
            .and_then(|d| uuid::Uuid::parse_str(&d).ok());

        RefreshResult::Ok(
            AuthClaims {
                user_id,
                device_id,
                iat: claims.iat,
                session_start: claims.session_start,
                mfa: claims.mfa,
                auth_time: claims.auth_time,
                agent,
            },
            claims.jti,
            claims.exp,
        )
    }

    /// Backward-compatible validate_token (used during transition, accepts both types).
    pub fn validate_token(&self, token: &str) -> Result<AuthClaims, String> {
        self.validate_access_token(token)
    }

    /// Records that a refresh token has been used, atomically, before new tokens are
    /// issued for it. With a database the `revoked_tokens` primary key decides, so
    /// concurrent requests and other server instances cannot both succeed.
    pub async fn consume_refresh_token(
        &self,
        jti: &str,
        user_id: uuid::Uuid,
        expires_at: u64,
    ) -> Result<RefreshTokenUse, String> {
        let now = now_secs();
        let cached = self
            .revoked
            .read()
            .expect("revoked RwLock poisoned")
            .get(jti)
            .copied();
        if let Some(r) = cached {
            return Ok(self.classify_reuse(now, r.revoked_at));
        }

        let Some(ref pool) = self.pool else {
            // No database (tests): the cache decides, under its write lock.
            let mut revoked = self.revoked.write().expect("revoked RwLock poisoned");
            if let Some(r) = revoked.get(jti) {
                return Ok(self.classify_reuse(now, r.revoked_at));
            }
            revoked.insert(
                jti.to_string(),
                Revocation {
                    expires_at,
                    revoked_at: now,
                },
            );
            return Ok(RefreshTokenUse::First);
        };

        let inserted = sqlx::query(
            "INSERT INTO revoked_tokens (jti, user_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(user_id)
        .bind(expires_at as i64)
        .execute(pool)
        .await
        .map_err(|e| format!("record refresh token use: {e}"))?
        .rows_affected()
            == 1;
        if inserted {
            let mut revoked = self.revoked.write().expect("revoked RwLock poisoned");
            revoked.insert(
                jti.to_string(),
                Revocation {
                    expires_at,
                    revoked_at: now,
                },
            );
            return Ok(RefreshTokenUse::First);
        }

        let recent: Option<(bool,)> = sqlx::query_as(
            "SELECT COALESCE(revoked_at > NOW() - make_interval(secs => $2), FALSE) FROM revoked_tokens WHERE jti = $1",
        )
        .bind(jti)
        .bind(self.refresh_reuse_grace.as_secs_f64())
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("look up refresh token use: {e}"))?;
        Ok(match recent {
            Some((true,)) => RefreshTokenUse::Concurrent,
            _ => RefreshTokenUse::Reused,
        })
    }

    fn classify_reuse(&self, now: u64, revoked_at: u64) -> RefreshTokenUse {
        if now.saturating_sub(revoked_at) < self.refresh_reuse_grace.as_secs() {
            RefreshTokenUse::Concurrent
        } else {
            RefreshTokenUse::Reused
        }
    }

    /// Revoke a token by JTI. Persists to DB if pool is available.
    pub fn revoke_token(&self, jti: &str, user_id: uuid::Uuid, expires_at: u64) {
        // L1: in-memory
        {
            let mut revoked = self.revoked.write().expect("revoked RwLock poisoned");
            revoked.insert(
                jti.to_string(),
                Revocation {
                    expires_at,
                    revoked_at: now_secs(),
                },
            );
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
            let row: Option<(i64,)> =
                sqlx::query_as("SELECT expires_at FROM revoked_tokens WHERE jti = $1")
                    .bind(jti)
                    .fetch_optional(pool)
                    .await
                    .unwrap_or(None);

            if let Some((expires_at,)) = row {
                // Promote to L1 cache
                let mut revoked = self.revoked.write().expect("revoked RwLock poisoned");
                revoked.insert(
                    jti.to_string(),
                    Revocation {
                        expires_at: expires_at as u64,
                        revoked_at: now_secs(),
                    },
                );
                return true;
            }
        }
        false
    }

    /// Spawn a background task that drops expired entries from the revocation table
    /// and from this instance's cache.
    pub fn start_cleanup(&self) {
        if let Some(ref pool) = self.pool {
            let pool = pool.clone();
            let revoked = self.revoked.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    // Keep entries a while past expiry: token validation allows clock leeway
                    let cutoff = now_secs().saturating_sub(REVOCATION_RETENTION_MARGIN.as_secs());
                    revoked
                        .write()
                        .expect("revoked RwLock poisoned")
                        .retain(|_, r| r.expires_at >= cutoff);
                    let _ = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < $1")
                        .bind(cutoff as i64)
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

    let entries: Vec<KeyEntry> =
        serde_json::from_str(json_str).map_err(|e| format!("invalid JWT_PUBLIC_KEYS_JSON: {e}"))?;

    entries
        .into_iter()
        .map(|entry| {
            let decoding_key = DecodingKey::from_rsa_pem(entry.pem.as_bytes())
                .map_err(|e| format!("invalid public key PEM for kid '{}': {e}", entry.kid))?;
            Ok(PublicKeyEntry {
                kid: entry.kid,
                decoding_key,
            })
        })
        .collect()
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
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn base_claims(user_id: uuid::Uuid, tt: &str, ttl: Duration) -> Claims {
    let now = now_secs();
    Claims {
        user_id: user_id.to_string(),
        exp: now + ttl.as_secs(),
        iat: now,
        jti: generate_jti(),
        tt: tt.to_string(),
        ..Claims::default()
    }
}

fn parse_user_id(value: &str) -> Result<uuid::Uuid, String> {
    uuid::Uuid::parse_str(value).map_err(|e| format!("invalid user_id in token: {e}"))
}

/// The agent behind a session token: all of `cid`, `scp` and `gid`, or none of them.
fn agent_claims(claims: &Claims) -> Result<Option<AgentClaims>, String> {
    match (&claims.cid, &claims.scp, &claims.gid) {
        (None, None, None) => Ok(None),
        (Some(cid), Some(scp), Some(gid)) => Ok(Some(AgentClaims {
            client_id: crate::oauth::registered_client(cid)
                .ok_or_else(|| format!("token names an unknown client: {cid}"))?,
            scopes: Scopes::from_recorded(scp.split_ascii_whitespace()),
            grant_id: uuid::Uuid::parse_str(gid)
                .map_err(|e| format!("invalid grant id in token: {e}"))?,
        })),
        _ => Err("token has incomplete agent claims".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::Scope;
    use crate::test_support::{TEST_KID, generate_rsa_keys, test_auth_service, test_keys};

    fn uid() -> uuid::Uuid {
        uuid::Uuid::new_v4()
    }

    fn err_of(r: Result<AuthService, String>) -> String {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn password_hash_roundtrip() {
        let svc = test_auth_service();
        let hash = svc.hash_password("Correct-Horse-9!").unwrap();
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        assert!(svc.check_password(&hash, "Correct-Horse-9!"));
        assert!(!svc.check_password(&hash, "correct-horse-9!"));
        assert!(!svc.check_password(&hash, ""));
    }

    #[test]
    fn password_hashes_are_salted() {
        let svc = test_auth_service();
        let a = svc.hash_password("same").unwrap();
        let b = svc.hash_password("same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_hash_never_verifies() {
        let svc = test_auth_service();
        assert!(!svc.check_password("", "pw"));
        assert!(!svc.check_password("not-a-phc-string", "pw"));
        assert!(!svc.check_password("$argon2id$v=19$m=1,t=1,p=1$garbage", "pw"));
    }

    #[test]
    fn access_token_roundtrip_with_device() {
        let svc = test_auth_service();
        let user = uid();
        let device = uid();
        let before = now_secs();
        let token = svc.generate_access_token(user, Some(device)).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some(TEST_KID));

        let claims = svc.validate_access_token(&token).unwrap();
        assert_eq!(claims.user_id, user);
        assert_eq!(claims.device_id, Some(device));
        assert!(claims.iat >= before && claims.iat <= now_secs());

        // validate_token is a backward-compatible alias
        assert_eq!(svc.validate_token(&token).unwrap().user_id, user);
    }

    #[test]
    fn access_token_without_device_has_no_device_claim() {
        let svc = test_auth_service();
        let token = svc.generate_access_token(uid(), None).unwrap();
        let claims = svc.validate_access_token(&token).unwrap();
        assert!(claims.device_id.is_none());

        // The device_id field is omitted from the payload entirely
        let payload = token.split('.').nth(1).unwrap();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("device_id").is_none());
        assert_eq!(json["tt"], "access");
        assert_eq!(json["jti"].as_str().unwrap().len(), 32);
    }

    #[test]
    fn refresh_token_cannot_be_used_as_access_token_and_vice_versa() {
        let svc = test_auth_service();
        let user = uid();
        let refresh = svc.generate_refresh_token(user, None).unwrap();
        let access = svc.generate_access_token(user, None).unwrap();

        let err = svc.validate_access_token(&refresh).unwrap_err();
        assert!(
            err.contains("expected a token of type access, got refresh"),
            "{err}"
        );

        match svc.validate_refresh_token(&access) {
            RefreshResult::Invalid(e) => assert!(
                e.contains("expected a token of type refresh, got access"),
                "{e}"
            ),
            _ => panic!("access token accepted as refresh token"),
        }
    }

    #[test]
    fn session_grants_carry_mfa_and_auth_time_through_refresh() {
        let svc = test_auth_service();
        let grant = SessionGrant {
            user_id: uid(),
            device_id: Some(uid()),
            mfa: true,
            auth_time: 1_700_000_000,
            session_start: 1_700_000_000,
            agent: None,
        };
        let (access, refresh) = svc.issue_session(&grant).unwrap();
        let claims = svc.validate_access_token(&access).unwrap();
        assert!(claims.mfa);
        assert_eq!(claims.auth_time, 1_700_000_000);
        assert_eq!(SessionGrant::from_claims(&claims), grant);

        let RefreshResult::Ok(refreshed, _, _) = svc.validate_refresh_token(&refresh) else {
            panic!("refresh token rejected");
        };
        assert_eq!(SessionGrant::from_claims(&refreshed), grant);

        // Plain sessions have neither
        let claims = svc
            .validate_access_token(&svc.generate_access_token(uid(), None).unwrap())
            .unwrap();
        assert!(!claims.mfa);
        assert!(claims.auth_time > 0);
    }

    #[test]
    fn mfa_tickets_round_trip_and_are_not_access_tokens() {
        let svc = test_auth_service();
        let user = uid();
        let token = svc
            .issue_mfa_ticket(user, MfaStage::Enroll, FirstFactor::Password, true)
            .unwrap();
        let ticket = svc.validate_mfa_ticket(&token).unwrap();
        assert_eq!(ticket.user_id, user);
        assert_eq!(ticket.stage, MfaStage::Enroll);
        assert_eq!(ticket.first_factor, FirstFactor::Password);
        assert!(ticket.email_ok);
        assert!(ticket.exp > now_secs() + MFA_TICKET_TTL.as_secs() - 5);

        let token = svc
            .issue_mfa_ticket(user, MfaStage::Verify, FirstFactor::Sso, false)
            .unwrap();
        let ticket = svc.validate_mfa_ticket(&token).unwrap();
        assert_eq!(ticket.stage, MfaStage::Verify);
        assert_eq!(ticket.first_factor, FirstFactor::Sso);
        assert!(!ticket.email_ok);

        // A ticket proves only the first factor: it is not a session
        assert!(svc.validate_access_token(&token).is_err());
        assert!(matches!(
            svc.validate_refresh_token(&token),
            RefreshResult::Invalid(_)
        ));
        // ...and a session token is not a ticket
        let access = svc.generate_access_token(user, None).unwrap();
        assert!(svc.validate_mfa_ticket(&access).is_err());
    }

    #[tokio::test]
    async fn mfa_tickets_are_single_use() {
        let svc = test_auth_service();
        let user = uid();
        let token = svc
            .issue_mfa_ticket(user, MfaStage::Verify, FirstFactor::Password, false)
            .unwrap();
        let ticket = svc.validate_mfa_ticket(&token).unwrap();
        assert!(
            svc.consume_once(&ticket.jti, user, ticket.exp)
                .await
                .unwrap()
        );
        assert!(
            !svc.consume_once(&ticket.jti, user, ticket.exp)
                .await
                .unwrap()
        );
        assert!(
            svc.validate_mfa_ticket(&token)
                .unwrap_err()
                .contains("already been used")
        );
    }

    #[test]
    fn passkey_challenges_are_bound_to_user_and_purpose() {
        let svc = test_auth_service();
        let user = uid();
        let token = svc
            .issue_passkey_challenge(user, PasskeyPurpose::Register, b"random-challenge")
            .unwrap();
        let challenge = svc
            .validate_passkey_challenge(&token, user, PasskeyPurpose::Register)
            .unwrap();
        assert_eq!(challenge.challenge, b"random-challenge");

        assert!(
            svc.validate_passkey_challenge(&token, uid(), PasskeyPurpose::Register)
                .unwrap_err()
                .contains("another account")
        );
        assert!(
            svc.validate_passkey_challenge(&token, user, PasskeyPurpose::Authenticate)
                .unwrap_err()
                .contains("another ceremony")
        );
        assert!(svc.validate_access_token(&token).is_err());
        assert!(svc.validate_mfa_ticket(&token).is_err());
    }

    #[test]
    fn refresh_token_validates() {
        let svc = test_auth_service();
        let user = uid();
        let token = svc.generate_refresh_token(user, None).unwrap();

        let (claims, jti, exp) = match svc.validate_refresh_token(&token) {
            RefreshResult::Ok(c, jti, exp) => (c, jti, exp),
            _ => panic!("fresh refresh token rejected"),
        };
        assert_eq!(claims.user_id, user);
        assert!(claims.device_id.is_none());
        assert_eq!(jti.len(), 32);
        assert!(exp > now_secs() + 6 * 24 * 3600, "7 day expiry");
    }

    #[test]
    fn device_bound_refresh_token_carries_the_device() {
        let svc = test_auth_service();
        let (user, device) = (uid(), uid());
        let token = svc.generate_refresh_token(user, Some(device)).unwrap();
        match svc.validate_refresh_token(&token) {
            RefreshResult::Ok(c, _, _) => {
                assert_eq!(c.user_id, user);
                assert_eq!(c.device_id, Some(device));
            }
            _ => panic!("device-bound refresh token rejected"),
        }
    }

    #[tokio::test]
    async fn refresh_token_is_single_use() {
        let svc = test_auth_service();
        let user = uid();
        let token = svc.generate_refresh_token(user, None).unwrap();
        let RefreshResult::Ok(_, jti, exp) = svc.validate_refresh_token(&token) else {
            panic!("fresh refresh token rejected");
        };

        assert_eq!(
            svc.consume_refresh_token(&jti, user, exp).await.unwrap(),
            RefreshTokenUse::First
        );
        // A second use within the grace window is a race between the client's own requests
        assert_eq!(
            svc.consume_refresh_token(&jti, user, exp).await.unwrap(),
            RefreshTokenUse::Concurrent
        );
    }

    #[tokio::test]
    async fn refresh_token_reuse_after_grace_is_theft() {
        let svc = test_auth_service().with_refresh_reuse_grace(Duration::ZERO);
        let user = uid();
        let token = svc.generate_refresh_token(user, None).unwrap();
        let RefreshResult::Ok(_, jti, exp) = svc.validate_refresh_token(&token) else {
            panic!("fresh refresh token rejected");
        };

        assert_eq!(
            svc.consume_refresh_token(&jti, user, exp).await.unwrap(),
            RefreshTokenUse::First
        );
        assert_eq!(
            svc.consume_refresh_token(&jti, user, exp).await.unwrap(),
            RefreshTokenUse::Reused
        );
    }

    #[tokio::test]
    async fn revoked_refresh_token_counts_as_reused() {
        let svc = test_auth_service().with_refresh_reuse_grace(Duration::ZERO);
        let user = uid();
        svc.revoke_token("revoked-jti", user, now_secs() + 60);
        assert_eq!(
            svc.consume_refresh_token("revoked-jti", user, now_secs() + 60)
                .await
                .unwrap(),
            RefreshTokenUse::Reused
        );
    }

    #[test]
    fn revoked_access_token_is_rejected() {
        let svc = test_auth_service();
        let user = uid();
        let token = svc.generate_access_token(user, None).unwrap();
        let payload = token.split('.').nth(1).unwrap();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let jti = json["jti"].as_str().unwrap();

        svc.validate_access_token(&token).unwrap();
        svc.revoke_token(jti, user, now_secs() + 60);
        let err = svc.validate_access_token(&token).unwrap_err();
        assert!(err.contains("revoked"), "{err}");
    }

    #[test]
    fn tampered_token_is_rejected() {
        let svc = test_auth_service();
        let token = svc.generate_access_token(uid(), None).unwrap();
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        // Flip a character in the signature
        let sig = parts[2].clone();
        let flipped = if sig.ends_with('A') { "B" } else { "A" };
        parts[2] = format!("{}{}", &sig[..sig.len() - 1], flipped);
        let tampered = parts.join(".");
        assert!(svc.validate_access_token(&tampered).is_err());
        assert!(matches!(
            svc.validate_refresh_token(&tampered),
            RefreshResult::Invalid(_)
        ));
    }

    #[test]
    fn garbage_tokens_are_rejected() {
        let svc = test_auth_service();
        for t in ["", "abc", "a.b.c", "Bearer x"] {
            assert!(svc.validate_access_token(t).is_err(), "{t:?}");
            assert!(
                matches!(svc.validate_refresh_token(t), RefreshResult::Invalid(_)),
                "{t:?}"
            );
        }
    }

    #[test]
    fn token_from_unknown_kid_is_rejected() {
        let svc = test_auth_service();
        let foreign = generate_rsa_keys("other-kid");
        let foreign_svc = AuthService::new(
            "other-kid",
            &foreign.private_pem,
            &foreign.public_keys_json,
            None,
        )
        .unwrap();
        let token = foreign_svc.generate_access_token(uid(), None).unwrap();
        let err = svc.validate_access_token(&token).unwrap_err();
        assert!(err.contains("unknown key ID: other-kid"), "{err}");
    }

    #[test]
    fn token_signed_by_wrong_key_with_known_kid_is_rejected() {
        let svc = test_auth_service();
        // Same kid, different private key: signature must not verify
        let foreign = generate_rsa_keys(TEST_KID);
        let foreign_svc = AuthService::new(
            TEST_KID,
            &foreign.private_pem,
            &foreign.public_keys_json,
            None,
        )
        .unwrap();
        let token = foreign_svc.generate_access_token(uid(), None).unwrap();
        let err = svc.validate_access_token(&token).unwrap_err();
        assert!(err.contains("validate token"), "{err}");
    }

    #[test]
    fn algorithm_confusion_attack_is_rejected() {
        // An attacker signs an HS256 token using the server's *public* key as the HMAC secret.
        let svc = test_auth_service();
        let keys = test_keys();
        let claims = Claims {
            user_id: uid().to_string(),
            exp: now_secs() + 3600,
            iat: now_secs(),
            jti: generate_jti(),
            tt: "access".to_string(),
            ..Claims::default()
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(TEST_KID.to_string());
        let forged = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(keys.public_pem.as_bytes()),
        )
        .unwrap();

        let err = svc.validate_access_token(&forged).unwrap_err();
        assert!(err.contains("unsupported token algorithm"), "{err}");
        assert!(matches!(
            svc.validate_refresh_token(&forged),
            RefreshResult::Invalid(_)
        ));
    }

    #[test]
    fn expired_token_is_rejected() {
        let keys = test_keys();
        let claims = Claims {
            user_id: uid().to_string(),
            exp: now_secs() - 120,
            iat: now_secs() - 3720,
            jti: generate_jti(),
            tt: "access".to_string(),
            ..Claims::default()
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(keys.private_pem.as_bytes()).unwrap(),
        )
        .unwrap();
        let err = test_auth_service()
            .validate_access_token(&token)
            .unwrap_err();
        assert!(err.contains("ExpiredSignature"), "{err}");
    }

    #[test]
    fn legacy_token_without_type_defaults_to_access() {
        let keys = test_keys();
        #[derive(Serialize)]
        struct LegacyClaims {
            user_id: String,
            exp: u64,
            iat: u64,
            jti: String,
        }
        let user = uid();
        let legacy = LegacyClaims {
            user_id: user.to_string(),
            exp: now_secs() + 60,
            iat: now_secs(),
            jti: generate_jti(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let token = encode(
            &header,
            &legacy,
            &EncodingKey::from_rsa_pem(keys.private_pem.as_bytes()).unwrap(),
        )
        .unwrap();

        let svc = test_auth_service();
        assert_eq!(svc.validate_access_token(&token).unwrap().user_id, user);
        assert!(matches!(
            svc.validate_refresh_token(&token),
            RefreshResult::Invalid(_)
        ));
    }

    #[test]
    fn invalid_user_id_claim_is_rejected() {
        let keys = test_keys();
        let claims = Claims {
            user_id: "not-a-uuid".to_string(),
            exp: now_secs() + 60,
            iat: now_secs(),
            jti: generate_jti(),
            tt: "refresh".to_string(),
            ..Claims::default()
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(keys.private_pem.as_bytes()).unwrap(),
        )
        .unwrap();
        let svc = test_auth_service();
        match svc.validate_refresh_token(&token) {
            RefreshResult::Invalid(e) => assert!(e.contains("invalid user_id"), "{e}"),
            _ => panic!("accepted token with invalid user id"),
        }
    }

    #[test]
    fn multiple_public_keys_allow_rotation() {
        let old = generate_rsa_keys("old");
        let new = test_keys();
        let combined = serde_json::json!([
            { "kid": "old", "pem": old.public_pem },
            { "kid": TEST_KID, "pem": new.public_pem },
        ])
        .to_string();
        // Signs with the new key, but still verifies tokens from the old one
        let svc = AuthService::new(TEST_KID, &new.private_pem, &combined, None).unwrap();
        let old_svc =
            AuthService::new("old", &old.private_pem, &old.public_keys_json, None).unwrap();

        let user = uid();
        let old_token = old_svc.generate_access_token(user, None).unwrap();
        let new_token = svc.generate_access_token(user, None).unwrap();
        assert_eq!(svc.validate_access_token(&old_token).unwrap().user_id, user);
        assert_eq!(svc.validate_access_token(&new_token).unwrap().user_id, user);
        assert_eq!(
            jsonwebtoken::decode_header(&new_token)
                .unwrap()
                .kid
                .as_deref(),
            Some(TEST_KID)
        );
    }

    #[test]
    fn new_rejects_bad_key_material() {
        let keys = test_keys();
        let err = err_of(AuthService::new(
            TEST_KID,
            "not a pem",
            &keys.public_keys_json,
            None,
        ));
        assert!(err.contains("invalid JWT private key PEM"), "{err}");

        let err = err_of(AuthService::new(TEST_KID, &keys.private_pem, "", None));
        assert!(err.contains("no JWT public keys configured"), "{err}");

        let err = err_of(AuthService::new(TEST_KID, &keys.private_pem, "[]", None));
        assert!(err.contains("no JWT public keys configured"), "{err}");

        let err = err_of(AuthService::new(
            TEST_KID,
            &keys.private_pem,
            "{not json",
            None,
        ));
        assert!(err.contains("invalid JWT_PUBLIC_KEYS_JSON"), "{err}");

        let bad_pem = serde_json::json!([{ "kid": "k", "pem": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----" }]).to_string();
        let err = err_of(AuthService::new(
            TEST_KID,
            &keys.private_pem,
            &bad_pem,
            None,
        ));
        assert!(err.contains("invalid public key PEM for kid 'k'"), "{err}");
    }

    #[test]
    fn jti_is_random_hex() {
        let a = generate_jti();
        let b = generate_jti();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn now_epoch_is_recent() {
        let now = now_epoch();
        assert!(now > 1_700_000_000);
        assert!(now <= now_secs());
    }

    #[tokio::test]
    async fn db_revocation_check_is_false_without_pool() {
        let svc = test_auth_service();
        assert!(!svc.check_revoked_db_async("anything").await);
        // Both are no-ops without a pool
        svc.start_cleanup();
    }

    fn agent() -> AgentClaims {
        AgentClaims {
            client_id: crate::oauth::MCP_CLIENT_ID,
            scopes: Scopes::of(&[Scope::ClipboardRead, Scope::ClipboardWrite]),
            grant_id: uid(),
        }
    }

    fn payload(token: &str) -> serde_json::Value {
        let payload = token.split('.').nth(1).unwrap();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
                .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn sign(claims: &Claims) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let key = EncodingKey::from_rsa_pem(test_keys().private_pem.as_bytes()).unwrap();
        encode(&header, claims, &key).unwrap()
    }

    #[test]
    fn agent_sessions_carry_client_scopes_and_grant_through_refresh() {
        let svc = test_auth_service();
        let agent = agent();
        let grant = SessionGrant::signed_in(uid(), true)
            .with_device(Some(uid()))
            .with_agent(agent);
        let (access, refresh) = svc.issue_session(&grant).unwrap();

        let claims = svc.validate_access_token(&access).unwrap();
        assert_eq!(claims.agent, Some(agent));
        assert_eq!(SessionGrant::from_claims(&claims), grant);
        let json = payload(&access);
        assert_eq!(json["cid"], "cpmesh-mcp");
        assert_eq!(json["scp"], "clipboard:read clipboard:write");
        assert_eq!(json["gid"], agent.grant_id.to_string());
        // Access tokens last an hour, for agents too
        assert_eq!(svc.access_token_ttl(), Duration::from_secs(3600));
        assert!(json["exp"].as_u64().unwrap() <= now_secs() + 3600);

        let RefreshResult::Ok(refreshed, _, exp) = svc.validate_refresh_token(&refresh) else {
            panic!("agent refresh token rejected");
        };
        assert_eq!(SessionGrant::from_claims(&refreshed), grant);
        // Agent refresh tokens last 30 days; first-party ones keep their 7
        assert!(exp > now_secs() + 29 * 24 * 3600, "{exp}");
        assert!(exp <= now_secs() + 30 * 24 * 3600, "{exp}");
        let first_party = svc
            .issue_refresh(&SessionGrant {
                agent: None,
                ..grant
            })
            .unwrap();
        let RefreshResult::Ok(_, _, exp) = svc.validate_refresh_token(&first_party) else {
            panic!("refresh token rejected");
        };
        assert!(exp <= now_secs() + 7 * 24 * 3600, "{exp}");
    }

    #[test]
    fn first_party_tokens_carry_no_agent_claims() {
        let svc = test_auth_service();
        let grant = SessionGrant::signed_in(uid(), true).with_device(Some(uid()));
        let (access, refresh) = svc.issue_session(&grant).unwrap();
        for token in [&access, &refresh] {
            let mut keys: Vec<String> = payload(token)
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            keys.sort();
            // The same claims as before agents existed
            assert_eq!(
                keys,
                [
                    "auth_time",
                    "device_id",
                    "exp",
                    "iat",
                    "jti",
                    "mfa",
                    "session_start",
                    "tt",
                    "user_id"
                ]
            );
        }
        assert_eq!(svc.validate_access_token(&access).unwrap().agent, None);
    }

    #[test]
    fn incomplete_or_unknown_agent_claims_invalidate_the_token() {
        let svc = test_auth_service();
        let gid = uid().to_string();
        let claims = |tt: &str, cid: Option<&str>, scp: Option<&str>, gid: Option<&str>| Claims {
            user_id: uid().to_string(),
            exp: now_secs() + 60,
            iat: now_secs(),
            jti: generate_jti(),
            tt: tt.to_string(),
            cid: cid.map(String::from),
            scp: scp.map(String::from),
            gid: gid.map(String::from),
            ..Claims::default()
        };
        for (cid, scp, gid) in [
            (Some("cpmesh-mcp"), None, Some(gid.as_str())),
            (Some("cpmesh-mcp"), Some("clipboard:read"), None),
            (None, Some("clipboard:read"), Some(gid.as_str())),
            (
                Some("another-client"),
                Some("clipboard:read"),
                Some(gid.as_str()),
            ),
            (
                Some("cpmesh-mcp"),
                Some("clipboard:read"),
                Some("not-a-uuid"),
            ),
        ] {
            let access = sign(&claims("access", cid, scp, gid));
            assert!(
                svc.validate_access_token(&access).is_err(),
                "{cid:?} {scp:?} {gid:?}"
            );
            let refresh = sign(&claims("refresh", cid, scp, gid));
            assert!(
                matches!(
                    svc.validate_refresh_token(&refresh),
                    RefreshResult::Invalid(_)
                ),
                "{cid:?} {scp:?} {gid:?}"
            );
        }

        // Scopes this server does not know are dropped, never granted
        let token = sign(&claims(
            "access",
            Some("cpmesh-mcp"),
            Some("clipboard:write admin:everything"),
            Some(&gid),
        ));
        let agent = svc.validate_access_token(&token).unwrap().agent.unwrap();
        assert_eq!(agent.scopes, Scopes::of(&[Scope::ClipboardWrite]));
        assert_eq!(agent.grant_id.to_string(), gid);
    }
}
