//! Two-factor authentication endpoints (`/api/mfa/*`).
//!
//! They serve two kinds of callers (see [`MfaPrincipal`]):
//! - a sign-in waiting for its second factor, holding the ticket from the login
//!   response: it confirms a factor (`/verify`) or sets one up, and gets a session;
//! - a signed-in user managing their factors, or confirming one again ("step-up")
//!   before a sensitive action.

use std::sync::Arc;

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;

use super::auth_service::{MfaStage, PasskeyPurpose, SessionGrant};
use super::middleware::{ApiError, MfaPrincipal, json_error, json_error_code, json_response};
use crate::AppState;
use crate::audit::{self, RequestMeta};
use crate::mfa::{self, Factor, VerifyError, codes, totp, webauthn};
use crate::models::*;

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::warn!("two-factor endpoint failed: {e}");
    json_error("internal error", StatusCode::INTERNAL_SERVER_ERROR)
}

/// A wrong code is answered with 401 like an expired session; `code` tells them apart.
fn invalid_code(message: &str) -> Response {
    json_error_code("invalid_code", message, StatusCode::UNAUTHORIZED, json!({}))
}

fn reauth_required() -> ApiError {
    ApiError::coded(
        StatusCode::FORBIDDEN,
        "reauth_required",
        "Confirm it's you to continue.",
    )
}

async fn load_user(state: &AppState, user_id: uuid::Uuid) -> Result<User, ApiError> {
    state
        .db
        .get_user_by_id(user_id)
        .await
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "user not found"))
}

/// Setting up a factor needs: a signed-in session with a recent sign-in, or a sign-in
/// in the enroll stage that has confirmed its emailed code (when one is required).
async fn check_may_enroll(state: &AppState, principal: &MfaPrincipal) -> Result<(), ApiError> {
    match principal {
        MfaPrincipal::Session(claims) if claims.authenticated_within(mfa::RECENT_AUTH) => Ok(()),
        MfaPrincipal::Session(_) => Err(reauth_required()),
        MfaPrincipal::SignIn(t) if t.stage == MfaStage::Enroll && t.email_ok => {
            // The ticket was issued while the account had no second factor. If one was
            // set up since, only confirming it signs in.
            let summary = state
                .db
                .mfa_summary(t.user_id)
                .await
                .map_err(ApiError::internal)?;
            if summary.enabled() {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "this account has two-factor authentication now; sign in again",
                ));
            }
            Ok(())
        }
        MfaPrincipal::SignIn(t) if t.stage == MfaStage::Enroll => Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "email_code_required",
            "Enter the code we emailed you first.",
        )),
        MfaPrincipal::SignIn(_) => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "confirm your existing second factor to finish signing in",
        )),
    }
}

/// Removing factors needs a session confirmed with a second factor recently.
fn check_may_remove(principal: &MfaPrincipal) -> Result<(), ApiError> {
    match principal {
        MfaPrincipal::Session(claims)
            if claims.mfa && claims.authenticated_within(mfa::RECENT_AUTH) =>
        {
            Ok(())
        }
        MfaPrincipal::Session(_) => Err(reauth_required()),
        MfaPrincipal::SignIn(_) => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "finish signing in first",
        )),
    }
}

// === Status ===

pub async fn handle_status(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
) -> Response {
    let user = match load_user(&state, principal.user_id()).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };
    let summary = match state.db.mfa_summary(user.id).await {
        Ok(s) => s,
        Err(e) => return internal(e),
    };
    let passkeys = match state.db.list_webauthn_credentials(user.id).await {
        Ok(p) => p,
        Err(e) => return internal(e),
    };
    let email_hint = match &principal {
        MfaPrincipal::SignIn(t) if t.stage == MfaStage::Enroll && !t.email_ok => {
            Some(codes::mask_email(&mfa::user_email(&state, &user)))
        }
        _ => None,
    };
    let (session, stage, email_code_required) = match &principal {
        MfaPrincipal::Session(c) => (Some(c), None, false),
        MfaPrincipal::SignIn(t) => match t.stage {
            MfaStage::Verify => (None, Some("verify"), false),
            MfaStage::Enroll => (None, Some("enroll"), !t.email_ok),
        },
    };
    json_response(
        StatusCode::OK,
        json!({
            "required": mfa::required_for(&state.config, &user),
            "enabled": summary.enabled(),
            "totp": summary.totp,
            "passkeys": passkeys.iter().map(passkey_json).collect::<Vec<_>>(),
            "recovery_codes_remaining": summary.recovery_codes,
            "passkeys_available": state.config.passkeys_enabled(),
            "session_verified": session.map(|c| c.mfa),
            "recent_auth": session.map(|c| c.authenticated_within(mfa::RECENT_AUTH)),
            "has_password": !user.password.is_empty(),
            "stage": stage,
            "email_code_required": email_code_required,
            "email_hint": email_hint,
        }),
    )
}

fn passkey_json(p: &WebauthnCredential) -> serde_json::Value {
    json!({
        "id": p.id,
        "name": p.name,
        "created_at": p.created_at,
        "last_used_at": p.last_used_at,
        "backup_eligible": p.backup_eligible,
    })
}

// === Emailed confirmation code (before enrolling after a password sign-in) ===

pub async fn handle_send_email_code(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
    meta: RequestMeta,
) -> Response {
    let MfaPrincipal::SignIn(ticket) = &principal else {
        return json_error("you are already signed in", StatusCode::BAD_REQUEST);
    };
    if ticket.stage != MfaStage::Enroll || ticket.email_ok {
        return json_error("no emailed code is needed", StatusCode::BAD_REQUEST);
    }
    let user = match load_user(&state, ticket.user_id).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };
    let email = mfa::user_email(&state, &user);
    if email.is_empty() {
        return json_error("this account has no email address", StatusCode::BAD_REQUEST);
    }

    match state.db.email_code_sent_at(user.id).await {
        Ok(Some(sent))
            if (chrono::Utc::now() - sent).num_seconds() < mfa::EMAIL_CODE_RESEND_SECS =>
        {
            return json_error(
                "a code was sent moments ago; check your inbox",
                StatusCode::TOO_MANY_REQUESTS,
            );
        }
        Ok(_) => {}
        Err(e) => return internal(e),
    }

    let code = codes::generate_numeric_code();
    if let Err(e) = state
        .db
        .store_email_code(
            user.id,
            &codes::hash_email_code(user.id, &code),
            mfa::EMAIL_CODE_TTL_SECS,
        )
        .await
    {
        return internal(e);
    }
    let name = mfa::user_display_name(&state, &user);
    let sent = state.email.send_mfa_email_code(&email, &name, &code).await;
    match sent {
        Ok(()) => {}
        Err(e) => {
            tracing::warn!("Failed to email confirmation code: {e}");
            return json_error(
                "could not send the email; try again later",
                StatusCode::BAD_GATEWAY,
            );
        }
    }

    audit::record(
        &state,
        Some(user.id),
        None,
        AUDIT_MFA_EMAIL_CODE_SENT,
        &meta,
        json!({}),
    )
    .await;
    json_response(
        StatusCode::OK,
        json!({ "sent": true, "email_hint": codes::mask_email(&email) }),
    )
}

#[derive(Deserialize)]
pub struct CodeBody {
    pub code: String,
}

pub async fn handle_verify_email_code(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
    axum::Json(req): axum::Json<CodeBody>,
) -> Response {
    let MfaPrincipal::SignIn(ticket) = &principal else {
        return json_error("you are already signed in", StatusCode::BAD_REQUEST);
    };
    if ticket.stage != MfaStage::Enroll {
        return json_error("no emailed code is needed", StatusCode::BAD_REQUEST);
    }
    let code: String = req.code.chars().filter(|c| c.is_ascii_digit()).collect();
    let check = match state
        .db
        .check_email_code(
            ticket.user_id,
            &codes::hash_email_code(ticket.user_id, &code),
            mfa::EMAIL_CODE_MAX_ATTEMPTS,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => return internal(e),
    };
    match check {
        crate::db::EmailCodeCheck::Valid => {}
        crate::db::EmailCodeCheck::Invalid => {
            return invalid_code("that code is not right");
        }
        crate::db::EmailCodeCheck::Expired | crate::db::EmailCodeCheck::Missing => {
            return invalid_code("that code has expired; request a new one");
        }
        crate::db::EmailCodeCheck::TooManyAttempts => {
            return json_error(
                "too many wrong codes; request a new one",
                StatusCode::TOO_MANY_REQUESTS,
            );
        }
    }

    // The old ticket is superseded; issue one that allows setting up a factor
    match state
        .auth
        .issue_mfa_ticket(ticket.user_id, MfaStage::Enroll, ticket.first_factor, true)
    {
        Ok(token) => {
            let _ = state
                .auth
                .consume_once(&ticket.jti, ticket.user_id, ticket.exp)
                .await;
            json_response(StatusCode::OK, json!({ "mfa_token": token }))
        }
        Err(e) => internal(e),
    }
}

// === Authenticator app (TOTP) ===

pub async fn handle_totp_setup(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
) -> Response {
    if let Err(r) = check_may_enroll(&state, &principal).await {
        return r.into_response();
    }
    let user = match load_user(&state, principal.user_id()).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };
    match state.db.mfa_summary(user.id).await {
        Ok(s) if s.totp => {
            return json_error(
                "an authenticator app is already set up",
                StatusCode::CONFLICT,
            );
        }
        Ok(_) => {}
        Err(e) => return internal(e),
    }

    let secret = totp::generate_secret();
    let sealed = match mfa::seal_secret(&state, &secret) {
        Ok(s) => s,
        Err(e) => return internal(e),
    };
    if let Err(e) = state.db.set_pending_totp(user.id, &sealed).await {
        return internal(e);
    }
    let account = {
        let email = mfa::user_email(&state, &user);
        if email.is_empty() {
            user.username.clone()
        } else {
            email
        }
    };
    let uri = totp::otpauth_uri(&secret, mfa::TOTP_ISSUER, &account);
    json_response(
        StatusCode::OK,
        json!({
            "secret": totp::base32_encode(&secret),
            "otpauth_uri": uri,
            "qr_svg": totp::qr_svg(&uri),
        }),
    )
}

pub async fn handle_totp_enable(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
    meta: RequestMeta,
    axum::Json(req): axum::Json<CodeBody>,
) -> Response {
    if let Err(r) = check_may_enroll(&state, &principal).await {
        return r.into_response();
    }
    let user = match load_user(&state, principal.user_id()).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };
    let pending = match state.db.get_user_mfa(user.id).await {
        Ok(Some(m)) if m.totp_secret.is_some() => {
            return json_error(
                "an authenticator app is already set up",
                StatusCode::CONFLICT,
            );
        }
        Ok(Some(m)) => m.totp_pending_secret,
        Ok(None) => None,
        Err(e) => return internal(e),
    };
    let Some(sealed) = pending else {
        return json_error("start the setup first", StatusCode::BAD_REQUEST);
    };
    let Some(secret) = mfa::open_secret(&state, &sealed) else {
        return internal("pending secret cannot be decrypted");
    };
    let Some(step) = totp::verify(
        &secret,
        &req.code,
        crate::routes::auth_service::now_epoch(),
        0,
    ) else {
        return invalid_code("that code is not right; check your authenticator app's time");
    };
    if let Err(e) = state.db.enable_totp(user.id, &sealed, step as i64).await {
        return internal(e);
    }

    audit::record(
        &state,
        Some(user.id),
        None,
        AUDIT_MFA_TOTP_ENABLE,
        &meta,
        json!({}),
    )
    .await;
    mfa::notify(
        &state,
        &user,
        "Two-factor authentication changed",
        "An authenticator app was set up for two-factor authentication on your account.".into(),
    )
    .await;
    finish_enrollment(&state, &principal, &user, "totp", &meta, json!({})).await
}

// === Passkeys ===

pub async fn handle_passkey_options(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
) -> Response {
    if let Err(r) = check_may_enroll(&state, &principal).await {
        return r.into_response();
    }
    let Some(rp) = mfa::relying_party(&state.config) else {
        return json_error(
            "passkeys are not configured on this server",
            StatusCode::NOT_IMPLEMENTED,
        );
    };
    let user = match load_user(&state, principal.user_id()).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };
    let existing = match state.db.list_webauthn_credentials(user.id).await {
        Ok(p) => p,
        Err(e) => return internal(e),
    };
    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);
    let token =
        match state
            .auth
            .issue_passkey_challenge(user.id, PasskeyPurpose::Register, &challenge)
        {
            Ok(t) => t,
            Err(e) => return internal(e),
        };
    let exclude: Vec<(Vec<u8>, Vec<String>)> = existing
        .iter()
        .map(|c| (c.credential_id.clone(), c.transport_list()))
        .collect();
    let display = mfa::user_display_name(&state, &user);
    let options = webauthn::creation_options(
        &rp,
        &webauthn::CreationParams {
            rp_name: "cpmesh",
            challenge: &challenge,
            user_handle: &mfa::user_handle(user.id),
            user_name: &user.username,
            user_display_name: &display,
            exclude: &exclude,
        },
    );
    json_response(
        StatusCode::OK,
        json!({ "options": options, "challenge_token": token }),
    )
}

#[derive(Deserialize)]
pub struct RegisterPasskeyBody {
    pub challenge_token: String,
    #[serde(default)]
    pub name: String,
    pub credential: webauthn::RegistrationResponse,
}

fn clean_passkey_name(name: &str) -> Result<String, ApiError> {
    let name: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    let name = if name.is_empty() {
        "Passkey".to_string()
    } else {
        name
    };
    if name.chars().count() > mfa::PASSKEY_NAME_MAX_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "passkey names are 60 characters at most",
        ));
    }
    Ok(name)
}

pub async fn handle_passkey_register(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
    meta: RequestMeta,
    axum::Json(req): axum::Json<RegisterPasskeyBody>,
) -> Response {
    if let Err(r) = check_may_enroll(&state, &principal).await {
        return r.into_response();
    }
    let Some(rp) = mfa::relying_party(&state.config) else {
        return json_error(
            "passkeys are not configured on this server",
            StatusCode::NOT_IMPLEMENTED,
        );
    };
    let name = match clean_passkey_name(&req.name) {
        Ok(n) => n,
        Err(r) => return r.into_response(),
    };
    let user = match load_user(&state, principal.user_id()).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };
    let challenge = match state.auth.validate_passkey_challenge(
        &req.challenge_token,
        user.id,
        PasskeyPurpose::Register,
    ) {
        Ok(c) => c,
        Err(e) => return json_error(&e, StatusCode::BAD_REQUEST),
    };
    match state
        .auth
        .consume_once(&challenge.jti, user.id, challenge.exp)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return json_error(
                "this passkey challenge was already used",
                StatusCode::BAD_REQUEST,
            );
        }
        Err(e) => return internal(e),
    }
    let credential = match webauthn::verify_registration(&rp, &challenge.challenge, &req.credential)
    {
        Ok(c) => c,
        Err(e) => return json_error(&e.to_string(), StatusCode::BAD_REQUEST),
    };
    let stored = match state
        .db
        .add_webauthn_credential(user.id, &credential, &name)
        .await
    {
        Ok(s) => s,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return json_error("this passkey is already registered", StatusCode::CONFLICT);
        }
        Err(e) => return internal(e),
    };

    audit::record(
        &state,
        Some(user.id),
        None,
        AUDIT_MFA_PASSKEY_ADD,
        &meta,
        json!({ "passkey_id": stored.id, "name": stored.name }),
    )
    .await;
    mfa::notify(
        &state,
        &user,
        "Two-factor authentication changed",
        format!(
            "A passkey named \"{}\" was added to your account.",
            stored.name
        ),
    )
    .await;
    finish_enrollment(
        &state,
        &principal,
        &user,
        "webauthn",
        &meta,
        json!({ "passkey": passkey_json(&stored) }),
    )
    .await
}

#[derive(Deserialize)]
pub struct RenamePasskeyBody {
    pub name: String,
}

pub async fn handle_passkey_rename(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
    Path(id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<RenamePasskeyBody>,
) -> Response {
    let MfaPrincipal::Session(claims) = &principal else {
        return json_error("finish signing in first", StatusCode::FORBIDDEN);
    };
    let name = match clean_passkey_name(&req.name) {
        Ok(n) => n,
        Err(r) => return r.into_response(),
    };
    let result = state
        .db
        .rename_webauthn_credential(claims.user_id, id, &name)
        .await;
    match result {
        Ok(true) => json_response(StatusCode::OK, json!({ "id": id, "name": name })),
        Ok(false) => json_error("passkey not found", StatusCode::NOT_FOUND),
        Err(e) => internal(e),
    }
}

/// After a factor was added: recovery codes if it was the first, and a session.
async fn finish_enrollment(
    state: &Arc<AppState>,
    principal: &MfaPrincipal,
    user: &User,
    method: &'static str,
    meta: &RequestMeta,
    mut body: serde_json::Value,
) -> Response {
    let summary = match state.db.mfa_summary(user.id).await {
        Ok(s) => s,
        Err(e) => return internal(e),
    };
    if summary.methods() == 1 || summary.recovery_codes == 0 {
        match mfa::issue_recovery_codes(state, user.id).await {
            Ok(codes) => body["recovery_codes"] = json!(codes),
            Err(e) => return internal(e),
        }
    }

    let grant = match principal {
        MfaPrincipal::SignIn(ticket) => {
            match state
                .auth
                .consume_once(&ticket.jti, ticket.user_id, ticket.exp)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return json_error(
                        "this sign-in was already completed; sign in again",
                        StatusCode::UNAUTHORIZED,
                    );
                }
                Err(e) => return internal(e),
            }
            audit::record(
                state,
                Some(user.id),
                None,
                AUDIT_LOGIN_OK,
                meta,
                json!({ "mfa": method, "enrolled": true }),
            )
            .await;
            audit::record_activity(state, user.id).await;
            SessionGrant::signed_in(user.id, true)
        }
        MfaPrincipal::Session(claims) => SessionGrant {
            mfa: true,
            auth_time: crate::routes::auth_service::now_epoch(),
            ..SessionGrant::from_claims(claims)
        },
    };
    match state.auth.issue_session(&grant) {
        Ok((access, refresh)) => {
            body["access_token"] = json!(access);
            body["refresh_token"] = json!(refresh);
            json_response(StatusCode::OK, body)
        }
        Err(e) => internal(e),
    }
}

// === Confirming a factor: finishing a sign-in, or step-up ===

pub async fn handle_verify_options(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
) -> Response {
    if let MfaPrincipal::SignIn(t) = &principal
        && t.stage != MfaStage::Verify
    {
        return json_error(
            "set up a second factor to finish signing in",
            StatusCode::BAD_REQUEST,
        );
    }
    let Some(rp) = mfa::relying_party(&state.config) else {
        return json_error(
            "passkeys are not configured on this server",
            StatusCode::NOT_IMPLEMENTED,
        );
    };
    let user_id = principal.user_id();
    let passkeys = match state.db.list_webauthn_credentials(user_id).await {
        Ok(p) => p,
        Err(e) => return internal(e),
    };
    if passkeys.is_empty() {
        return json_error("this account has no passkeys", StatusCode::BAD_REQUEST);
    }
    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);
    let token =
        match state
            .auth
            .issue_passkey_challenge(user_id, PasskeyPurpose::Authenticate, &challenge)
        {
            Ok(t) => t,
            Err(e) => return internal(e),
        };
    let allow: Vec<(Vec<u8>, Vec<String>)> = passkeys
        .iter()
        .map(|c| (c.credential_id.clone(), c.transport_list()))
        .collect();
    json_response(
        StatusCode::OK,
        json!({
            "options": webauthn::request_options(&rp, &challenge, &allow),
            "challenge_token": token,
        }),
    )
}

#[derive(Deserialize)]
pub struct VerifyBody {
    /// "totp", "recovery", "webauthn", or (step-up without a second factor) "password".
    pub method: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub challenge_token: Option<String>,
    #[serde(default)]
    pub credential: Option<webauthn::AuthenticationResponse>,
}

pub async fn handle_verify(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
    meta: RequestMeta,
    axum::Json(req): axum::Json<VerifyBody>,
) -> Response {
    if let MfaPrincipal::SignIn(t) = &principal
        && t.stage != MfaStage::Verify
    {
        return json_error(
            "set up a second factor to finish signing in",
            StatusCode::BAD_REQUEST,
        );
    }
    let user = match load_user(&state, principal.user_id()).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };

    if req.method == "password" {
        return password_step_up(&state, &principal, &user, &meta, req.password.as_deref()).await;
    }

    let factor = match (
        req.method.as_str(),
        &req.code,
        &req.challenge_token,
        &req.credential,
    ) {
        ("totp", Some(code), _, _) => Factor::Totp(code),
        ("recovery", Some(code), _, _) => Factor::Recovery(code),
        ("webauthn", _, Some(challenge_token), Some(credential)) => Factor::Passkey {
            challenge_token,
            credential,
        },
        _ => {
            return json_error(
                "send a method with its code, or a passkey response",
                StatusCode::BAD_REQUEST,
            );
        }
    };

    match mfa::verify_factor(&state, user.id, &factor).await {
        Ok(()) => {}
        Err(VerifyError::Invalid(reason)) => {
            audit::record(
                &state,
                Some(user.id),
                None,
                AUDIT_MFA_FAIL,
                &meta,
                json!({ "method": factor.method() }),
            )
            .await;
            return invalid_code(&reason);
        }
        Err(VerifyError::Locked) => {
            audit::record(
                &state,
                Some(user.id),
                None,
                AUDIT_MFA_LOCKED,
                &meta,
                json!({ "method": factor.method() }),
            )
            .await;
            return json_error_code(
                "mfa_locked",
                "Too many failed attempts. Try again in 15 minutes.",
                StatusCode::TOO_MANY_REQUESTS,
                json!({}),
            );
        }
        Err(VerifyError::Internal(e)) => return internal(e),
    }

    let mut body = json!({});
    if matches!(factor, Factor::Recovery(_)) {
        let remaining = state
            .db
            .mfa_summary(user.id)
            .await
            .map(|s| s.recovery_codes)
            .unwrap_or(0);
        body["recovery_codes_remaining"] = json!(remaining);
        audit::record(
            &state,
            Some(user.id),
            None,
            AUDIT_MFA_RECOVERY_USED,
            &meta,
            json!({ "remaining": remaining }),
        )
        .await;
        mfa::notify(
            &state,
            &user,
            "Recovery code used",
            format!(
                "A recovery code was used to sign in to your account. {remaining} unused codes remain."
            ),
        ).await;
    }

    let grant = match &principal {
        MfaPrincipal::SignIn(ticket) => {
            match state
                .auth
                .consume_once(&ticket.jti, ticket.user_id, ticket.exp)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return json_error(
                        "this sign-in was already completed; sign in again",
                        StatusCode::UNAUTHORIZED,
                    );
                }
                Err(e) => return internal(e),
            }
            audit::record(
                &state,
                Some(user.id),
                None,
                AUDIT_LOGIN_OK,
                &meta,
                json!({ "mfa": factor.method() }),
            )
            .await;
            audit::record_activity(&state, user.id).await;
            SessionGrant::signed_in(user.id, true)
        }
        MfaPrincipal::Session(claims) => {
            audit::record(
                &state,
                Some(user.id),
                None,
                AUDIT_MFA_STEP_UP,
                &meta,
                json!({ "method": factor.method() }),
            )
            .await;
            SessionGrant {
                mfa: true,
                auth_time: crate::routes::auth_service::now_epoch(),
                ..SessionGrant::from_claims(claims)
            }
        }
    };
    match state.auth.issue_session(&grant) {
        Ok((access, refresh)) => {
            body["access_token"] = json!(access);
            body["refresh_token"] = json!(refresh);
            json_response(StatusCode::OK, body)
        }
        Err(e) => internal(e),
    }
}

/// Re-entering the password refreshes a session's sign-in time, for accounts that
/// have no second factor yet (so they can set one up).
async fn password_step_up(
    state: &Arc<AppState>,
    principal: &MfaPrincipal,
    user: &User,
    meta: &RequestMeta,
    password: Option<&str>,
) -> Response {
    let MfaPrincipal::Session(claims) = principal else {
        return json_error("use your second factor", StatusCode::BAD_REQUEST);
    };
    match state.db.mfa_summary(user.id).await {
        Ok(s) if s.enabled() => {
            return json_error(
                "confirm with your second factor instead",
                StatusCode::BAD_REQUEST,
            );
        }
        Ok(_) => {}
        Err(e) => return internal(e),
    }
    let password = password.unwrap_or_default();
    let password_ok = if user.password.is_empty() {
        false
    } else {
        match state
            .auth
            .check_password_async(&user.password, password)
            .await
        {
            Ok(ok) => ok,
            Err(e) => return internal(e),
        }
    };
    if !password_ok {
        audit::record(
            state,
            Some(user.id),
            None,
            AUDIT_LOGIN_FAIL,
            meta,
            json!({ "step_up": true }),
        )
        .await;
        return json_error_code(
            "invalid_password",
            "incorrect password",
            StatusCode::UNAUTHORIZED,
            json!({}),
        );
    }
    let grant = SessionGrant {
        auth_time: crate::routes::auth_service::now_epoch(),
        ..SessionGrant::from_claims(claims)
    };
    match state.auth.issue_session(&grant) {
        Ok((access, refresh)) => json_response(
            StatusCode::OK,
            json!({ "access_token": access, "refresh_token": refresh }),
        ),
        Err(e) => internal(e),
    }
}

// === Removing factors ===

/// Refuses to remove the account's last method when two-factor authentication is
/// required for it.
async fn check_not_last_method(
    state: &AppState,
    user: &User,
    removing: i64,
) -> Result<(), ApiError> {
    let summary = state
        .db
        .mfa_summary(user.id)
        .await
        .map_err(ApiError::internal)?;
    if mfa::required_for(&state.config, user) && summary.methods() - removing < 1 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "two-factor authentication is required for this account; add another method before removing this one",
        ));
    }
    Ok(())
}

/// Clears recovery codes once the account has no method left.
async fn cleanup_after_removal(state: &AppState, user_id: uuid::Uuid) {
    if let Ok(summary) = state.db.mfa_summary(user_id).await
        && !summary.enabled()
    {
        let _ = state.db.replace_recovery_codes(user_id, &[]).await;
    }
}

pub async fn handle_totp_disable(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
    meta: RequestMeta,
) -> Response {
    if let Err(r) = check_may_remove(&principal) {
        return r.into_response();
    }
    let user = match load_user(&state, principal.user_id()).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };
    match state.db.mfa_summary(user.id).await {
        Ok(s) if !s.totp => {
            return json_error("no authenticator app is set up", StatusCode::NOT_FOUND);
        }
        Ok(_) => {}
        Err(e) => return internal(e),
    }
    if let Err(r) = check_not_last_method(&state, &user, 1).await {
        return r.into_response();
    }
    if let Err(e) = state.db.disable_totp(user.id).await {
        return internal(e);
    }
    cleanup_after_removal(&state, user.id).await;
    audit::record(
        &state,
        Some(user.id),
        None,
        AUDIT_MFA_TOTP_DISABLE,
        &meta,
        json!({}),
    )
    .await;
    mfa::notify(
        &state,
        &user,
        "Two-factor authentication changed",
        "The authenticator app was removed from your account's two-factor authentication.".into(),
    )
    .await;
    json_response(
        StatusCode::OK,
        json!({ "message": "authenticator app removed" }),
    )
}

pub async fn handle_passkey_delete(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
    meta: RequestMeta,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if let Err(r) = check_may_remove(&principal) {
        return r.into_response();
    }
    let user = match load_user(&state, principal.user_id()).await {
        Ok(u) => u,
        Err(r) => return r.into_response(),
    };
    if let Err(r) = check_not_last_method(&state, &user, 1).await {
        return r.into_response();
    }
    match state.db.delete_webauthn_credential(user.id, id).await {
        Ok(true) => {}
        Ok(false) => return json_error("passkey not found", StatusCode::NOT_FOUND),
        Err(e) => return internal(e),
    }
    cleanup_after_removal(&state, user.id).await;
    audit::record(
        &state,
        Some(user.id),
        None,
        AUDIT_MFA_PASSKEY_REMOVE,
        &meta,
        json!({ "passkey_id": id }),
    )
    .await;
    mfa::notify(
        &state,
        &user,
        "Two-factor authentication changed",
        "A passkey was removed from your account.".into(),
    )
    .await;
    json_response(StatusCode::OK, json!({ "message": "passkey removed" }))
}

pub async fn handle_regenerate_recovery_codes(
    State(state): State<Arc<AppState>>,
    Extension(principal): Extension<MfaPrincipal>,
    meta: RequestMeta,
) -> Response {
    if let Err(r) = check_may_remove(&principal) {
        return r.into_response();
    }
    let user_id = principal.user_id();
    match state.db.mfa_summary(user_id).await {
        Ok(s) if !s.enabled() => {
            return json_error(
                "set up two-factor authentication first",
                StatusCode::BAD_REQUEST,
            );
        }
        Ok(_) => {}
        Err(e) => return internal(e),
    }
    match mfa::issue_recovery_codes(&state, user_id).await {
        Ok(codes) => {
            audit::record(
                &state,
                Some(user_id),
                None,
                AUDIT_MFA_RECOVERY_REGENERATE,
                &meta,
                json!({}),
            )
            .await;
            json_response(StatusCode::OK, json!({ "recovery_codes": codes }))
        }
        Err(e) => internal(e),
    }
}
