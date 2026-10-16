//! Two-factor authentication: what follows a successful first factor, and checking
//! each kind of second factor.
//!
//! Every sign-in that needs a second factor gets a short-lived, single-use ticket
//! instead of tokens. With the ticket the client either confirms an existing factor
//! (stage "verify") or sets one up (stage "enroll"). Setting one up after a password
//! sign-in first needs a code emailed to the account when email is configured, so a
//! leaked password alone cannot enroll an attacker's authenticator.

pub mod codes;
pub mod totp;
pub mod webauthn;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;

use crate::AppState;
use crate::config::{Config, MfaPolicy};
use crate::db::MfaSummary;
use crate::models::User;
use crate::routes::auth_service::{FirstFactor, MfaStage, PasskeyPurpose};

/// Consecutive failed second-factor attempts before the account's second factor locks.
pub const MAX_FAILURES: i32 = 10;
pub const LOCK_SECS: i64 = 15 * 60;
pub const EMAIL_CODE_TTL_SECS: i64 = 10 * 60;
pub const EMAIL_CODE_MAX_ATTEMPTS: i32 = 5;
/// Minimum time between two emailed codes for one account.
pub const EMAIL_CODE_RESEND_SECS: i64 = 30;
/// Sensitive actions need a sign-in or second-factor confirmation this recent.
pub const RECENT_AUTH: Duration = Duration::from_secs(10 * 60);
pub const PASSKEY_NAME_MAX_LEN: usize = 60;
/// Issuer shown in authenticator apps.
pub const TOTP_ISSUER: &str = "cpmesh";

/// Whether `user` must have a second factor.
pub fn required_for(config: &Config, user: &User) -> bool {
    match config.mfa_policy {
        MfaPolicy::All => true,
        MfaPolicy::Staff => user.role().is_staff(),
    }
}

/// What follows a successful first factor.
pub enum SignInStep {
    /// No second factor is involved: issue a session.
    Complete,
    /// Ask for (or set up) a second factor: the response body to send.
    SecondFactor(serde_json::Value),
}

/// Decides how a sign-in continues once the password (or SSO) checked out.
pub async fn after_first_factor(
    state: &AppState,
    user: &User,
    first_factor: FirstFactor,
) -> Result<SignInStep, String> {
    let summary = state
        .db
        .mfa_summary(user.id)
        .await
        .map_err(|e| format!("load two-factor state: {e}"))?;

    if summary.enabled() {
        let ticket = state
            .auth
            .issue_mfa_ticket(user.id, MfaStage::Verify, first_factor, false)?;
        return Ok(SignInStep::SecondFactor(challenge_body(
            state,
            &ticket,
            MfaStage::Verify,
            &summary,
            None,
        )));
    }
    if !required_for(&state.config, user) {
        return Ok(SignInStep::Complete);
    }

    let email = user_email(state, user);
    let needs_email_code =
        first_factor == FirstFactor::Password && state.email.is_configured() && !email.is_empty();
    let ticket =
        state
            .auth
            .issue_mfa_ticket(user.id, MfaStage::Enroll, first_factor, !needs_email_code)?;
    let hint = needs_email_code.then(|| codes::mask_email(&email));
    Ok(SignInStep::SecondFactor(challenge_body(
        state,
        &ticket,
        MfaStage::Enroll,
        &summary,
        hint,
    )))
}

/// The body sent instead of tokens when a second factor is needed. `error` stays human
/// readable for clients that predate two-factor authentication; `code` is for new ones.
pub fn challenge_body(
    state: &AppState,
    ticket: &str,
    stage: MfaStage,
    summary: &MfaSummary,
    email_hint: Option<String>,
) -> serde_json::Value {
    let passkeys = state.config.passkeys_enabled();
    let (stage_name, message, methods) = match stage {
        MfaStage::Verify => {
            let mut methods = Vec::new();
            if summary.totp {
                methods.push("totp");
            }
            if summary.passkeys > 0 && passkeys {
                methods.push("webauthn");
            }
            if summary.recovery_codes > 0 {
                methods.push("recovery");
            }
            (
                "verify",
                "Two-factor authentication is required: enter the code from your authenticator app or use a passkey.",
                methods,
            )
        }
        MfaStage::Enroll => {
            let mut methods = vec!["totp"];
            if passkeys {
                methods.push("webauthn");
            }
            (
                "enroll",
                "Two-factor authentication is required for this account. Set it up on the web dashboard to finish signing in.",
                methods,
            )
        }
    };
    json!({
        "error": message,
        "code": "mfa_required",
        "mfa_token": ticket,
        "stage": stage_name,
        "methods": methods,
        "email_code_required": email_hint.is_some(),
        "email_hint": email_hint,
        "passkeys_available": passkeys,
    })
}

/// The account's email address in plain text (empty when it has none).
pub fn user_email(state: &AppState, user: &User) -> String {
    let stored = user.email.as_deref().unwrap_or_default();
    match &state.pii {
        Some(pii) if !stored.is_empty() => pii.decrypt(stored).unwrap_or_default(),
        _ => stored.to_string(),
    }
}

/// The name to greet the user with in emails.
pub fn user_display_name(state: &AppState, user: &User) -> String {
    let name = match &state.pii {
        Some(pii) => pii.decrypt(&user.full_name).unwrap_or_default(),
        None => user.full_name.clone(),
    };
    if name.trim().is_empty() {
        user.username.clone()
    } else {
        name
    }
}

/// Encrypts an authenticator secret for storage (PII key when configured).
pub fn seal_secret(state: &AppState, secret: &[u8]) -> Result<String, String> {
    let encoded = STANDARD.encode(secret);
    match &state.pii {
        Some(pii) => pii.encrypt(&encoded),
        None => Ok(encoded),
    }
}

pub fn open_secret(state: &AppState, sealed: &str) -> Option<Vec<u8>> {
    let encoded = match &state.pii {
        Some(pii) => pii.decrypt(sealed).ok()?,
        None => sealed.to_string(),
    };
    STANDARD.decode(encoded).ok()
}

/// The WebAuthn relying party, when passkeys are configured.
pub fn relying_party(config: &Config) -> Option<webauthn::RelyingParty<'_>> {
    config.passkeys_enabled().then(|| webauthn::RelyingParty {
        id: &config.webauthn_rp_id,
        origins: &config.webauthn_origins,
    })
}

/// WebAuthn user handle: the account ID's bytes.
pub fn user_handle(user_id: uuid::Uuid) -> Vec<u8> {
    user_id.as_bytes().to_vec()
}

/// Why a second factor was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Wrong code or signature; counts toward the lockout.
    Invalid(String),
    /// Too many failures recently.
    Locked,
    Internal(String),
}

/// A second factor presented by the client.
pub enum Factor<'a> {
    Totp(&'a str),
    Recovery(&'a str),
    Passkey {
        challenge_token: &'a str,
        credential: &'a webauthn::AuthenticationResponse,
    },
}

impl Factor<'_> {
    pub fn method(&self) -> &'static str {
        match self {
            Factor::Totp(_) => "totp",
            Factor::Recovery(_) => "recovery",
            Factor::Passkey { .. } => "webauthn",
        }
    }
}

/// Checks a second factor of `user_id`, counting failures toward the lockout.
pub async fn verify_factor(
    state: &AppState,
    user_id: uuid::Uuid,
    factor: &Factor<'_>,
) -> Result<(), VerifyError> {
    match state.db.mfa_locked_until(user_id).await {
        Ok(Some(_)) => return Err(VerifyError::Locked),
        Ok(None) => {}
        Err(e) => return Err(VerifyError::Internal(e.to_string())),
    }

    let outcome = match factor {
        Factor::Totp(code) => check_totp(state, user_id, code).await,
        Factor::Recovery(code) => check_recovery_code(state, user_id, code).await,
        Factor::Passkey {
            challenge_token,
            credential,
        } => check_passkey(state, user_id, challenge_token, credential).await,
    };

    match outcome {
        Ok(()) => {
            let _ = state.db.clear_mfa_failures(user_id).await;
            Ok(())
        }
        Err(VerifyError::Invalid(reason)) => {
            match state
                .db
                .record_mfa_failure(user_id, MAX_FAILURES, LOCK_SECS)
                .await
            {
                Ok(true) => Err(VerifyError::Locked),
                Ok(false) => Err(VerifyError::Invalid(reason)),
                Err(e) => Err(VerifyError::Internal(e.to_string())),
            }
        }
        Err(other) => Err(other),
    }
}

async fn check_totp(state: &AppState, user_id: uuid::Uuid, code: &str) -> Result<(), VerifyError> {
    let invalid = || VerifyError::Invalid("invalid authentication code".to_string());
    let mfa = state
        .db
        .get_user_mfa(user_id)
        .await
        .map_err(|e| VerifyError::Internal(e.to_string()))?
        .ok_or_else(invalid)?;
    let secret = mfa
        .totp_secret
        .as_deref()
        .and_then(|sealed| open_secret(state, sealed))
        .ok_or_else(invalid)?;
    let last_step = u64::try_from(mfa.totp_last_step).unwrap_or(0);
    let Some(step) = totp::verify(&secret, code, now_secs(), last_step) else {
        // Signing in again right after using a code shows the same code: say so
        return Err(match totp::verify(&secret, code, now_secs(), 0) {
            Some(_) => VerifyError::Invalid(
                "this code was already used; wait for the next code in your authenticator app"
                    .to_string(),
            ),
            None => invalid(),
        });
    };
    // Record the step atomically: a code can be used once, even by concurrent requests
    match state.db.record_totp_step(user_id, step as i64).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(invalid()),
        Err(e) => Err(VerifyError::Internal(e.to_string())),
    }
}

async fn check_recovery_code(
    state: &AppState,
    user_id: uuid::Uuid,
    code: &str,
) -> Result<(), VerifyError> {
    let invalid = || VerifyError::Invalid("invalid recovery code".to_string());
    let normalized = codes::normalize_recovery_code(code).ok_or_else(invalid)?;
    match state
        .db
        .use_recovery_code(user_id, &codes::hash_recovery_code(&normalized))
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(invalid()),
        Err(e) => Err(VerifyError::Internal(e.to_string())),
    }
}

async fn check_passkey(
    state: &AppState,
    user_id: uuid::Uuid,
    challenge_token: &str,
    credential: &webauthn::AuthenticationResponse,
) -> Result<(), VerifyError> {
    let Some(rp) = relying_party(&state.config) else {
        return Err(VerifyError::Invalid(
            "passkeys are not configured on this server".to_string(),
        ));
    };
    let challenge = state
        .auth
        .validate_passkey_challenge(challenge_token, user_id, PasskeyPurpose::Authenticate)
        .map_err(VerifyError::Invalid)?;
    // A challenge answers one ceremony only
    match state
        .auth
        .consume_once(&challenge.jti, user_id, challenge.exp)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(VerifyError::Invalid(
                "this passkey challenge was already used".to_string(),
            ));
        }
        Err(e) => return Err(VerifyError::Internal(e)),
    }

    let raw_id = webauthn::b64url_decode(&credential.raw_id)
        .ok_or_else(|| VerifyError::Invalid("unknown passkey".to_string()))?;
    let stored = state
        .db
        .list_webauthn_credentials(user_id)
        .await
        .map_err(|e| VerifyError::Internal(e.to_string()))?
        .into_iter()
        .find(|c| c.credential_id == raw_id)
        .ok_or_else(|| VerifyError::Invalid("unknown passkey".to_string()))?;

    let previous = stored.sign_count;
    let assertion = webauthn::verify_authentication(
        &rp,
        &challenge.challenge,
        &webauthn::StoredCredential {
            credential_id: &stored.credential_id,
            public_key: &stored.public_key,
            sign_count: u32::try_from(previous).unwrap_or(u32::MAX),
        },
        &user_handle(user_id),
        credential,
    )
    .map_err(|e| VerifyError::Invalid(e.to_string()))?;

    match state
        .db
        .record_webauthn_use(stored.id, previous, i64::from(assertion.sign_count))
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(VerifyError::Invalid(
            "this passkey was used concurrently; try again".to_string(),
        )),
        Err(e) => Err(VerifyError::Internal(e.to_string())),
    }
}

/// Generates fresh recovery codes for the account, replacing any old ones.
pub async fn issue_recovery_codes(
    state: &AppState,
    user_id: uuid::Uuid,
) -> Result<Vec<String>, String> {
    let recovery = codes::generate_recovery_codes();
    let hashes: Vec<String> = recovery
        .iter()
        .filter_map(|c| codes::normalize_recovery_code(c))
        .map(|c| codes::hash_recovery_code(&c))
        .collect();
    state
        .db
        .replace_recovery_codes(user_id, &hashes)
        .await
        .map_err(|e| format!("store recovery codes: {e}"))?;
    Ok(recovery)
}

/// Awaits bounded delivery of a best-effort security notice.
pub async fn notify(state: &Arc<AppState>, user: &User, subject: &'static str, message: String) {
    if !state.email.is_configured() {
        return;
    }
    let email = user_email(state, user);
    if email.is_empty() {
        return;
    }
    let name = user_display_name(state, user);
    if let Err(e) = state
        .email
        .send_security_notice(&email, &name, subject, &message)
        .await
    {
        tracing::warn!("Failed to send security notice: {e}");
    }
}

fn now_secs() -> u64 {
    crate::routes::auth_service::now_epoch()
}
