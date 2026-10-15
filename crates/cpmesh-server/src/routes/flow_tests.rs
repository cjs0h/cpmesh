//! End-to-end HTTP flows that need PostgreSQL: signing in with each kind of second
//! factor, the admin console's gates (2FA session, roles, recent sign-in), API tokens,
//! suspension, runtime settings, uploads and the desktop handoff.
//!
//! Like `tests/db.rs`, these run only when `TEST_DATABASE_URL` is set; each test
//! migrates a throwaway schema. They live in the crate to reuse the software passkey
//! authenticator and TOTP code generator of the unit tests.

use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{StatusCode, header};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};

use crate::config::Config;
use crate::db::Db;
use crate::email::EmailService;
use crate::mfa::totp;
use crate::mfa::webauthn::tests::TestAuthenticator;
use crate::mfa::webauthn::{b64url, b64url_decode};
use crate::models::User;
use crate::pii::PiiService;
use crate::rbac::Role;
use crate::routes::auth::PkceCodeStore;
use crate::routes::auth_service::{AuthService, SessionGrant, now_epoch};
use crate::routes::middleware::build_rate_limiter;
use crate::settings::SettingsCache;
use crate::test_support::*;
use crate::ws::Hub;
use crate::{AppState, RateLimiters};

const PASSWORD: &str = "Correct-Horse-9!";

struct TestApp {
    router: Router,
    state: Arc<AppState>,
}

#[derive(Default)]
struct Options {
    smtp: bool,
    download_url_prefixes: Vec<String>,
    downloads_dir: Option<String>,
    updater_public_key: Option<String>,
}

async fn with_app<F, Fut>(options: Options, body: F)
where
    F: FnOnce(TestApp) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping database flow test");
        return;
    };
    let schema = format!("f_{}", uuid::Uuid::new_v4().simple());
    let admin = PgPool::connect(&url).await.expect("connect");
    let _ = sqlx::query("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\" WITH SCHEMA public")
        .execute(&admin)
        .await;
    sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .expect("create schema");
    let connect = PgConnectOptions::from_str(&url)
        .expect("parse url")
        .options([("search_path", format!("{schema},public"))]);
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(connect)
        .await
        .expect("connect pool");
    let db = Db { pool: pool.clone() };
    db.migrate().await.expect("migrate");

    let mut config = Config::from_lookup(|key| match key {
        "BASE_URL" => Some("https://cpmesh.test".into()),
        "JWT_ACTIVE_KID" => Some(TEST_KID.into()),
        _ => None,
    });
    config.download_url_prefixes = options.download_url_prefixes;
    config.downloads_dir = options.downloads_dir.unwrap_or_default();
    config.updater_public_key = options.updater_public_key.unwrap_or_default();
    let email = if options.smtp {
        EmailService::from_lookup(|key| match key {
            "SMTP_HOST" => Some("smtp.invalid".into()),
            "SMTP_FROM" => Some("noreply@cpmesh.test".into()),
            _ => None,
        })
    } else {
        EmailService::disabled()
    };
    let keys = test_keys();
    let state = Arc::new(AppState {
        db,
        config,
        hub: Hub::new(),
        pii: Some(PiiService::new(TEST_PII_MASTER_KEY, TEST_PII_HMAC_KEY).unwrap()),
        auth: AuthService::new(
            TEST_KID,
            &keys.private_pem,
            &keys.public_keys_json,
            Some(pool.clone()),
        )
        .unwrap(),
        email,
        pkce_store: PkceCodeStore::new(),
        rate_limiters: RateLimiters {
            login: build_rate_limiter(1000),
            register: build_rate_limiter(1000),
            refresh: build_rate_limiter(1000),
            mfa: build_rate_limiter(1000),
        },
        settings: SettingsCache::new(),
    });
    let app = TestApp {
        router: crate::routes::build_router(state.clone()),
        state,
    };

    let result = tokio::spawn(body(app)).await;
    pool.close().await;
    let _ = sqlx::query(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .execute(&admin)
        .await;
    admin.close().await;
    if let Err(e) = result {
        if e.is_panic() {
            std::panic::resume_unwind(e.into_panic());
        }
        panic!("test body was cancelled: {e}");
    }
}

impl TestApp {
    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = request(method, uri);
        if let Some(token) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let req = match body {
            Some(body) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        let resp = send(&self.router, req).await;
        let status = resp.status();
        let bytes = body_bytes(resp).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// A verified member with the test password.
    async fn member(&self, username: &str) -> User {
        let db = &self.state.db;
        let user = db
            .create_user(crate::db::CreateUserParams {
                username,
                password_hash: &self.state.auth.hash_password(PASSWORD).unwrap(),
                email: &format!("{username}@example.com"),
                full_name: &format!("{username} Example"),
                country: None,
                mobile: None,
                pii: self.state.pii.as_ref(),
            })
            .await
            .unwrap();
        db.set_email_verified(user.id, true).await.unwrap();
        db.get_user_by_id(user.id).await.unwrap()
    }

    async fn staff(&self, username: &str, role: Role) -> User {
        let user = self.member(username).await;
        self.state.db.change_user_role(user.id, role).await.unwrap();
        self.state.db.get_user_by_id(user.id).await.unwrap()
    }

    /// Access token of a session confirmed with a second factor just now.
    fn mfa_session(&self, user: &User) -> String {
        self.state
            .auth
            .issue_access(&SessionGrant::signed_in(user.id, true))
            .unwrap()
    }

    /// A session confirmed with a second factor `age_secs` ago.
    fn old_mfa_session(&self, user: &User, age_secs: u64) -> String {
        self.state
            .auth
            .issue_access(&SessionGrant {
                auth_time: now_epoch() - age_secs,
                ..SessionGrant::signed_in(user.id, true)
            })
            .unwrap()
    }

    async fn login(&self, username: &str) -> (StatusCode, Value) {
        self.call(
            "POST",
            "/api/auth/login",
            None,
            Some(json!({"username": username, "password": PASSWORD})),
        )
        .await
    }

    /// Gives `user` an authenticator app directly, returning its secret.
    async fn enable_totp(&self, user: &User) -> Vec<u8> {
        let secret = totp::generate_secret();
        let sealed = crate::mfa::seal_secret(&self.state, &secret).unwrap();
        self.state
            .db
            .set_pending_totp(user.id, &sealed)
            .await
            .unwrap();
        self.state
            .db
            .enable_totp(user.id, &sealed, 0)
            .await
            .unwrap();
        secret
    }
}

fn code_now(secret: &[u8], offset: u64) -> String {
    totp::code_at(secret, totp::step_at(now_epoch()) + offset)
}

fn mfa_flag(app: &TestApp, access: &str) -> bool {
    app.state.auth.validate_access_token(access).unwrap().mfa
}

#[tokio::test]
async fn password_sign_in_sets_up_and_then_verifies_an_authenticator_app() {
    with_app(Options::default(), |app| async move {
        let alice = app.member("alice").await;

        // Every account needs a second factor; this one has none yet
        let (status, body) = app.login("alice").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["code"], "mfa_required");
        assert_eq!(body["stage"], "enroll");
        assert_eq!(body["email_code_required"], false);
        assert!(body["error"].as_str().unwrap().contains("Two-factor"));
        let ticket = body["mfa_token"].as_str().unwrap().to_string();

        // The ticket is not a session
        let (status, _) = app.call("GET", "/api/me", Some(&ticket), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, status_body) = app.call("GET", "/api/mfa", Some(&ticket), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(status_body["stage"], "enroll");
        assert_eq!(status_body["enabled"], false);

        let (status, setup) = app
            .call("POST", "/api/mfa/totp/setup", Some(&ticket), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{setup}");
        assert!(
            setup["otpauth_uri"]
                .as_str()
                .unwrap()
                .starts_with("otpauth://totp/cpmesh:")
        );
        assert!(setup["qr_svg"].as_str().unwrap().contains("<svg"));
        assert_eq!(setup["secret"].as_str().unwrap().len(), 32);
        let pending = app.state.db.get_user_mfa(alice.id).await.unwrap().unwrap();
        let secret =
            crate::mfa::open_secret(&app.state, &pending.totp_pending_secret.unwrap()).unwrap();
        assert_eq!(totp::base32_encode(&secret), setup["secret"]);

        let (status, _) = app
            .call(
                "POST",
                "/api/mfa/totp/enable",
                Some(&ticket),
                Some(json!({"code": "000000"})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, done) = app
            .call(
                "POST",
                "/api/mfa/totp/enable",
                Some(&ticket),
                Some(json!({"code": code_now(&secret, 0)})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{done}");
        let recovery: Vec<String> = serde_json::from_value(done["recovery_codes"].clone()).unwrap();
        assert_eq!(recovery.len(), 10);
        let access = done["access_token"].as_str().unwrap();
        assert!(mfa_flag(&app, access));

        // The sign-in ticket is used up
        let (status, _) = app.call("GET", "/api/mfa", Some(&ticket), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, me) = app.call("GET", "/api/me", Some(access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me["mfa"]["enabled"], true);
        assert_eq!(me["mfa"]["session_verified"], true);
        assert_eq!(me["role"], "user");

        // Next sign-in asks for the factor
        let (status, body) = app.login("alice").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["stage"], "verify");
        assert_eq!(body["methods"], json!(["totp", "recovery"]));
        let ticket = body["mfa_token"].as_str().unwrap().to_string();
        let (status, body) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&ticket),
                Some(json!({"method": "totp", "code": "123456"})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            body["code"], "invalid_code",
            "told apart from an expired session"
        );
        let (status, done) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&ticket),
                Some(json!({"method": "recovery", "code": recovery[0].to_uppercase()})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{done}");
        assert_eq!(done["recovery_codes_remaining"], 9);
        assert!(mfa_flag(&app, done["access_token"].as_str().unwrap()));

        // A recovery code works once
        let (_, body) = app.login("alice").await;
        let ticket = body["mfa_token"].as_str().unwrap().to_string();
        let (status, _) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&ticket),
                Some(json!({"method": "recovery", "code": recovery[0]})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // An authenticator code works once
        let next = code_now(&secret, 1);
        let (status, _) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&ticket),
                Some(json!({"method": "totp", "code": next})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = app.login("alice").await;
        let ticket = body["mfa_token"].as_str().unwrap().to_string();
        let (status, body) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&ticket),
                Some(json!({"method": "totp", "code": next})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "replayed code accepted");
        assert!(
            body["error"].as_str().unwrap().contains("already used"),
            "{body}"
        );
    })
    .await;
}

#[tokio::test]
async fn repeated_wrong_codes_lock_the_second_factor() {
    with_app(Options::default(), |app| async move {
        let bob = app.member("bob").await;
        let secret = app.enable_totp(&bob).await;
        let (_, body) = app.login("bob").await;
        let ticket = body["mfa_token"].as_str().unwrap().to_string();
        let wrong = json!({"method": "totp", "code": "000000"});
        for attempt in 1..crate::mfa::MAX_FAILURES {
            let (status, _) = app
                .call(
                    "POST",
                    "/api/mfa/verify",
                    Some(&ticket),
                    Some(wrong.clone()),
                )
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
        }
        let (status, body) = app
            .call("POST", "/api/mfa/verify", Some(&ticket), Some(wrong))
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["code"], "mfa_locked");
        // Even the right code waits out the lock
        let (status, _) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&ticket),
                Some(json!({"method": "totp", "code": code_now(&secret, 0)})),
            )
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    })
    .await;
}

#[tokio::test]
async fn passkeys_can_be_set_up_and_used_to_sign_in() {
    with_app(Options::default(), |app| async move {
        let carol = app.member("carol").await;
        let (_, body) = app.login("carol").await;
        assert_eq!(body["passkeys_available"], true);
        assert!(
            body["methods"]
                .as_array()
                .unwrap()
                .contains(&json!("webauthn"))
        );
        let ticket = body["mfa_token"].as_str().unwrap().to_string();

        let (status, options) = app
            .call("POST", "/api/mfa/passkeys/options", Some(&ticket), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        assert_eq!(options["options"]["rp"]["id"], "cpmesh.test");
        assert_eq!(
            options["options"]["user"]["id"],
            b64url(carol.id.as_bytes())
        );
        let challenge = b64url_decode(options["options"]["challenge"].as_str().unwrap()).unwrap();
        let mut authenticator = TestAuthenticator::es256();
        let (status, done) = app
            .call(
                "POST",
                "/api/mfa/passkeys",
                Some(&ticket),
                Some(json!({
                    "challenge_token": options["challenge_token"],
                    "name": "  Laptop  ",
                    "credential": authenticator.register(&challenge),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{done}");
        assert_eq!(done["passkey"]["name"], "Laptop");
        assert_eq!(done["recovery_codes"].as_array().unwrap().len(), 10);
        assert!(mfa_flag(&app, done["access_token"].as_str().unwrap()));

        // Sign in with the passkey
        let (_, body) = app.login("carol").await;
        assert_eq!(body["stage"], "verify");
        assert_eq!(body["methods"], json!(["webauthn", "recovery"]));
        let ticket = body["mfa_token"].as_str().unwrap().to_string();
        let (_, status_body) = app.call("GET", "/api/mfa", Some(&ticket), None).await;
        assert_eq!(status_body["stage"], "verify");
        assert_eq!(status_body["email_code_required"], false);
        assert_eq!(status_body["passkeys"][0]["name"], "Laptop");
        let (status, options) = app
            .call("POST", "/api/mfa/verify/options", Some(&ticket), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{options}");
        assert_eq!(
            options["options"]["allowCredentials"][0]["id"],
            b64url(&authenticator.credential_id)
        );
        let challenge = b64url_decode(options["options"]["challenge"].as_str().unwrap()).unwrap();
        let assertion = authenticator.assert(&challenge, carol.id.as_bytes());
        let verify = json!({
            "method": "webauthn",
            "challenge_token": options["challenge_token"],
            "credential": assertion,
        });
        let (status, done) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&ticket),
                Some(verify.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{done}");

        // The challenge answered one ceremony; replaying it fails
        let (_, body) = app.login("carol").await;
        let ticket = body["mfa_token"].as_str().unwrap().to_string();
        let (status, _) = app
            .call("POST", "/api/mfa/verify", Some(&ticket), Some(verify))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // A signed-in user manages their passkeys
        let session = app.mfa_session(&carol);
        let (_, status_body) = app.call("GET", "/api/mfa", Some(&session), None).await;
        let id = status_body["passkeys"][0]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let (status, _) = app
            .call(
                "PATCH",
                &format!("/api/mfa/passkeys/{id}"),
                Some(&session),
                Some(json!({"name": "Work laptop"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        // It is the only method and 2FA is required: it cannot be removed
        let (status, body) = app
            .call(
                "DELETE",
                &format!("/api/mfa/passkeys/{id}"),
                Some(&session),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    })
    .await;
}

#[tokio::test]
async fn emailed_code_must_confirm_the_account_before_setup() {
    with_app(
        Options {
            smtp: true,
            ..Options::default()
        },
        |app| async move {
            let dave = app.member("dave").await;
            let (_, body) = app.login("dave").await;
            assert_eq!(body["stage"], "enroll");
            assert_eq!(body["email_code_required"], true);
            assert_eq!(body["email_hint"], "d***@example.com");
            let ticket = body["mfa_token"].as_str().unwrap().to_string();
            let (_, status_body) = app.call("GET", "/api/mfa", Some(&ticket), None).await;
            assert_eq!(status_body["email_code_required"], true);
            assert_eq!(status_body["email_hint"], "d***@example.com");

            let (status, body) = app
                .call("POST", "/api/mfa/totp/setup", Some(&ticket), None)
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["code"], "email_code_required");

            // (Sending needs a real SMTP server; store a known code instead)
            app.state
                .db
                .store_email_code(
                    dave.id,
                    &crate::mfa::codes::hash_email_code(dave.id, "424242"),
                    600,
                )
                .await
                .unwrap();
            let (status, _) = app
                .call(
                    "POST",
                    "/api/mfa/email-code/verify",
                    Some(&ticket),
                    Some(json!({"code": "111111"})),
                )
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            let (status, body) = app
                .call(
                    "POST",
                    "/api/mfa/email-code/verify",
                    Some(&ticket),
                    Some(json!({"code": "424 242"})),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let confirmed = body["mfa_token"].as_str().unwrap().to_string();

            let (status, _) = app.call("GET", "/api/mfa", Some(&ticket), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "old ticket superseded");
            let (status, _) = app
                .call("POST", "/api/mfa/totp/setup", Some(&confirmed), None)
                .await;
            assert_eq!(status, StatusCode::OK);
        },
    )
    .await;
}

#[tokio::test]
async fn admin_console_needs_a_two_factor_session_and_the_right_role() {
    with_app(Options::default(), |app| async move {
        let owner = app.staff("olivia", Role::Owner).await;
        let viewer = app.staff("victor", Role::Viewer).await;
        let support = app.staff("sam", Role::Support).await;
        let member = app.member("mia").await;

        let plain = app
            .state
            .auth
            .generate_access_token(owner.id, None)
            .unwrap();
        let (status, body) = app
            .call("GET", "/api/admin/users", Some(&plain), None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "mfa_required");
        assert_eq!(body["enrolled"], false);

        let (status, body) = app
            .call(
                "GET",
                "/api/admin/users?per_page=2",
                Some(&app.mfa_session(&owner)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 4);
        assert_eq!(body["items"].as_array().unwrap().len(), 2);

        // Members never get in, 2FA or not
        let (status, _) = app
            .call(
                "GET",
                "/api/admin/stats",
                Some(&app.mfa_session(&member)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Viewers read but do not change
        let viewer_token = app.mfa_session(&viewer);
        let (status, _) = app
            .call("GET", "/api/admin/stats", Some(&viewer_token), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        let suspend = format!("/api/admin/users/{}/suspend", member.id);
        let (status, _) = app
            .call("POST", &suspend, Some(&viewer_token), Some(json!({})))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Support manages members, but not other staff
        let support_token = app.mfa_session(&support);
        let (status, body) = app
            .call(
                "POST",
                &suspend,
                Some(&support_token),
                Some(json!({"reason": "abuse"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, _) = app
            .call(
                "POST",
                &format!("/api/admin/users/{}/suspend", viewer.id),
                Some(&support_token),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = app
            .call(
                "PUT",
                &format!("/api/admin/users/{}/role", member.id),
                Some(&support_token),
                Some(json!({"role": "admin"})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // The suspension shows up in the user's audit trail, naming who did it
        let (status, detail) = app
            .call(
                "GET",
                &format!("/api/admin/users/{}", member.id),
                Some(&viewer_token),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert!(detail["user"]["suspended_at"].is_string());
        assert_eq!(detail["suspended_reason"], "abuse");
        let mut found = false;
        for _ in 0..50 {
            let (_, logs) = app
                .call(
                    "GET",
                    &format!("/api/admin/audit-logs?user_id={}", member.id),
                    Some(&viewer_token),
                    None,
                )
                .await;
            if logs["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "admin_suspend_user" && e["username"] == "sam")
            {
                found = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(found, "suspension was not audited");
    })
    .await;
}

#[tokio::test]
async fn sensitive_admin_actions_need_a_recent_sign_in() {
    with_app(Options::default(), |app| async move {
        let owner = app.staff("oscar", Role::Owner).await;
        let member = app.member("max").await;
        let path = format!("/api/admin/users/{}", member.id);

        let stale = app.old_mfa_session(&owner, 3600);
        let (status, body) = app.call("DELETE", &path, Some(&stale), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "reauth_required");

        let fresh = app.mfa_session(&owner);
        let (status, _) = app
            .call(
                "DELETE",
                &format!("/api/admin/users/{}", owner.id),
                Some(&fresh),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "cannot delete yourself");
        let (status, _) = app.call("DELETE", &path, Some(&fresh), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(app.state.db.get_user_by_id(member.id).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn owners_change_roles_and_one_owner_always_remains() {
    with_app(Options::default(), |app| async move {
        let owner = app.staff("orla", Role::Owner).await;
        let admin = app.staff("adam", Role::Admin).await;
        let member = app.member("mo").await;
        let role_path = format!("/api/admin/users/{}/role", member.id);

        let (status, _) = app
            .call(
                "PUT",
                &role_path,
                Some(&app.mfa_session(&admin)),
                Some(json!({"role": "support"})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "admins cannot change roles");

        let owner_token = app.mfa_session(&owner);
        let (status, _) = app
            .call(
                "PUT",
                &role_path,
                Some(&owner_token),
                Some(json!({"role": "wizard"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = app
            .call(
                "PUT",
                &role_path,
                Some(&owner_token),
                Some(json!({"role": "support"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let (_, me) = app
            .call("GET", "/api/me", Some(&app.mfa_session(&member)), None)
            .await;
        assert_eq!(me["role"], "support");
        assert_eq!(me["is_admin"], true);
        assert_eq!(me["permissions"], json!(["view", "manage_users"]));

        let (status, _) = app
            .call(
                "PUT",
                &format!("/api/admin/users/{}/role", owner.id),
                Some(&owner_token),
                Some(json!({"role": "admin"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "not your own role");
        assert_eq!(
            app.state
                .db
                .change_user_role(owner.id, Role::Admin)
                .await
                .unwrap(),
            crate::db::RoleChange::LastOwner
        );
    })
    .await;
}

#[tokio::test]
async fn suspension_ends_sessions_and_blocks_sign_in() {
    with_app(Options::default(), |app| async move {
        let owner = app.staff("ophelia", Role::Owner).await;
        let member = app.member("milo").await;
        let session = app.mfa_session(&member);
        let refresh = app
            .state
            .auth
            .issue_refresh(&SessionGrant::signed_in(member.id, true))
            .unwrap();

        let owner_token = app.mfa_session(&owner);
        let (status, _) = app
            .call(
                "POST",
                &format!("/api/admin/users/{}/suspend", member.id),
                Some(&owner_token),
                Some(json!({"reason": "chargeback"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = app.call("GET", "/api/me", Some(&session), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "account_suspended");
        let (status, body) = app
            .call(
                "POST",
                "/api/auth/refresh",
                None,
                Some(json!({"refresh_token": refresh})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "account_suspended");
        let (status, body) = app.login("milo").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "account_suspended");

        let (status, _) = app
            .call(
                "POST",
                &format!("/api/admin/users/{}/unsuspend", member.id),
                Some(&owner_token),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = app.login("milo").await;
        assert_eq!(body["code"], "mfa_required");
    })
    .await;
}

#[tokio::test]
async fn refresh_keeps_how_the_session_was_established() {
    with_app(Options::default(), |app| async move {
        let member = app.member("rita").await;
        let grant = SessionGrant {
            auth_time: now_epoch() - 120,
            ..SessionGrant::signed_in(member.id, true)
        };
        let refresh = app.state.auth.issue_refresh(&grant).unwrap();
        let (status, body) = app
            .call(
                "POST",
                "/api/auth/refresh",
                None,
                Some(json!({"refresh_token": refresh})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = app
            .state
            .auth
            .validate_access_token(body["access_token"].as_str().unwrap())
            .unwrap();
        assert!(claims.mfa);
        assert_eq!(claims.auth_time, grant.auth_time);
    })
    .await;
}

#[tokio::test]
async fn step_up_refreshes_the_sign_in_time() {
    with_app(Options::default(), |app| async move {
        // Without a second factor, the password confirms it's you
        let member = app.member("uma").await;
        let stale = app
            .state
            .auth
            .issue_access(&SessionGrant {
                auth_time: now_epoch() - 3600,
                ..SessionGrant::signed_in(member.id, false)
            })
            .unwrap();
        let (status, body) = app
            .call("POST", "/api/mfa/totp/setup", Some(&stale), None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "reauth_required");
        let (status, body) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&stale),
                Some(json!({"method": "password", "password": "wrong"})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "invalid_password");
        let (status, body) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&stale),
                Some(json!({"method": "password", "password": PASSWORD})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let fresh = body["access_token"].as_str().unwrap().to_string();
        let (status, _) = app
            .call("POST", "/api/mfa/totp/setup", Some(&fresh), None)
            .await;
        assert_eq!(status, StatusCode::OK);

        // With a second factor, the password is not enough
        let other = app.member("ursa").await;
        let secret = app.enable_totp(&other).await;
        let stale = app.old_mfa_session(&other, 3600);
        let (status, body) = app
            .call("DELETE", "/api/mfa/totp", Some(&stale), None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "reauth_required");
        let (status, _) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&stale),
                Some(json!({"method": "password", "password": PASSWORD})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = app
            .call(
                "POST",
                "/api/mfa/verify",
                Some(&stale),
                Some(json!({"method": "totp", "code": code_now(&secret, 0)})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let fresh = body["access_token"].as_str().unwrap().to_string();
        // Recent enough now, but it is the only method of a required 2FA
        let (status, _) = app
            .call("DELETE", "/api/mfa/totp", Some(&fresh), None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, body) = app
            .call("POST", "/api/mfa/recovery-codes", Some(&fresh), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["recovery_codes"].as_array().unwrap().len(), 10);
    })
    .await;
}

#[tokio::test]
async fn admins_reset_two_factor_and_the_user_sets_it_up_again() {
    with_app(Options::default(), |app| async move {
        let owner = app.staff("owen", Role::Owner).await;
        let member = app.member("mabel").await;
        app.enable_totp(&member).await;
        let session = app.mfa_session(&member);
        // Revocation has one-second resolution
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let (status, _) = app
            .call(
                "DELETE",
                &format!("/api/admin/users/{}/mfa", member.id),
                Some(&app.mfa_session(&owner)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!app.state.db.mfa_summary(member.id).await.unwrap().enabled());
        let (status, _) = app.call("GET", "/api/me", Some(&session), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "signed out everywhere");
        let (_, body) = app.login("mabel").await;
        assert_eq!(body["stage"], "enroll");
    })
    .await;
}

#[tokio::test]
async fn api_tokens_publish_releases_and_nothing_else() {
    with_app(Options::default(), |app| async move {
        let owner = app.staff("odin", Role::Owner).await;
        let session = app.mfa_session(&owner);
        let (status, _) = app
            .call(
                "POST",
                "/api/admin/api-tokens",
                Some(&session),
                Some(json!({"name": "CI", "scopes": ["everything"]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = app
            .call(
                "POST",
                "/api/admin/api-tokens",
                Some(&session),
                Some(json!({"name": "Release workflow", "scopes": ["releases:write"]})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let token = body["token"].as_str().unwrap().to_string();
        assert!(token.starts_with("cpm_"));
        assert!(body["api_token"]["expires_at"].is_string());
        let token_id = body["api_token"]["id"].as_str().unwrap().to_string();

        let release = json!({
            "version": "1.2.3",
            "platform": "windows",
            "arch": "amd64",
            "download_url": "https://github.com/cjs0h/cpmesh/releases/download/v1.2.3/a.exe",
            "is_current": true,
        });
        let (status, body) = app
            .call(
                "POST",
                "/api/admin/releases",
                Some(&token),
                Some(release.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, _) = app
            .call("GET", "/api/admin/downloads", Some(&token), None)
            .await;
        assert_eq!(status, StatusCode::OK);

        for path in ["/api/admin/users", "/api/me", "/api/admin/api-tokens"] {
            let (status, _) = app.call("GET", path, Some(&token), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        }

        // The token acts for its creator, who must still be allowed
        app.staff("odette", Role::Owner).await;
        assert_eq!(
            app.state
                .db
                .change_user_role(owner.id, Role::Support)
                .await
                .unwrap(),
            crate::db::RoleChange::Changed
        );
        let (status, _) = app
            .call(
                "POST",
                "/api/admin/releases",
                Some(&token),
                Some(release.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        app.state
            .db
            .change_user_role(owner.id, Role::Owner)
            .await
            .unwrap();

        let (status, _) = app
            .call(
                "DELETE",
                &format!("/api/admin/api-tokens/{token_id}"),
                Some(&session),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = app
            .call("POST", "/api/admin/releases", Some(&token), Some(release))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn download_links_must_point_at_allowed_hosts() {
    with_app(
        Options {
            download_url_prefixes: vec![
                "https://github.com/cjs0h/cpmesh/releases/download/".into(),
            ],
            ..Options::default()
        },
        |app| async move {
            let owner = app.staff("opal", Role::Owner).await;
            let token = app.mfa_session(&owner);
            let link = |url: &str| json!({"name": "Windows", "url": url, "platform": "windows"});
            let (status, body) = app
                .call(
                    "POST",
                    "/api/admin/downloads",
                    Some(&token),
                    Some(link("https://evil.example/cpmesh.exe")),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body["error"].as_str().unwrap().contains("not allowed"));
            let (status, _) = app
                .call(
                    "POST",
                    "/api/admin/downloads",
                    Some(&token),
                    Some(link(
                        "https://github.com/cjs0h/cpmesh/releases/download/v1/cpmesh.exe",
                    )),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED);
        },
    )
    .await;
}

#[tokio::test]
async fn runtime_settings_override_registration_and_show_a_banner() {
    with_app(Options::default(), |app| async move {
        let owner = app.staff("ola", Role::Owner).await;
        let viewer = app.staff("vera", Role::Viewer).await;
        let token = app.mfa_session(&owner);

        let (status, _) = app
            .call(
                "PUT",
                "/api/admin/settings",
                Some(&app.mfa_session(&viewer)),
                Some(json!({"registration_open": false})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = app
            .call(
                "PUT",
                "/api/admin/settings",
                Some(&token),
                Some(json!({"banner": {"message": "Hi", "tone": "neon"}})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, body) = app
            .call(
                "PUT",
                "/api/admin/settings",
                Some(&token),
                Some(json!({
                    "registration_open": false,
                    "banner": {"message": "Maintenance at 22:00 UTC", "tone": "warning"},
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["registration_open"]["value"], false);
        assert_eq!(body["registration_open"]["override"], false);
        assert_eq!(body["registration_open"]["default"], true);

        let (_, public) = app.call("GET", "/api/settings", None, None).await;
        assert_eq!(public["registration_open"], false);
        assert_eq!(public["banner"]["tone"], "warning");
        assert_eq!(public["passkeys_available"], true);
        let (status, body) = app
            .call(
                "POST",
                "/api/auth/register",
                None,
                Some(json!({
                    "username": "newbie", "password": PASSWORD, "password_confirm": PASSWORD,
                    "email": "newbie@example.com", "full_name": "New Bie",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (status, body) = app
            .call(
                "PUT",
                "/api/admin/settings",
                Some(&token),
                Some(json!({"registration_open": null, "banner": null})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["registration_open"]["value"], true);
        assert!(body["banner"].is_null());
    })
    .await;
}

#[tokio::test]
async fn stats_and_user_search() {
    with_app(Options::default(), |app| async move {
        let owner = app.staff("orson", Role::Owner).await;
        let alpha = app.member("alpha_one").await;
        app.member("beta_two").await;
        app.enable_totp(&alpha).await;
        app.state.db.record_activity(alpha.id).await.unwrap();
        app.state.db.record_activity(alpha.id).await.unwrap();
        let token = app.mfa_session(&owner);

        let (status, stats) = app
            .call("GET", "/api/admin/stats", Some(&token), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{stats}");
        assert_eq!(stats["total_users"], 3);
        assert_eq!(stats["staff_users"], 1);
        assert_eq!(stats["mfa_users"], 1);
        assert_eq!(stats["active_users_1d"], 1);
        assert_eq!(stats["signups"].as_array().unwrap().len(), 30);
        assert_eq!(stats["signups"][29]["count"], 3);
        assert_eq!(stats["active_users"][29]["count"], 1);
        assert_eq!(stats["plans"][0]["users"], 3);

        let list = |query: &str| format!("/api/admin/users?{query}");
        let (_, page) = app.call("GET", &list("q=TWO"), Some(&token), None).await;
        assert_eq!(page["total"], 1);
        assert_eq!(page["items"][0]["username"], "beta_two");
        // Emails are encrypted: they match exactly, through the blind index
        let (_, page) = app
            .call("GET", &list("q=alpha_one@example.com"), Some(&token), None)
            .await;
        assert_eq!(page["total"], 1);
        assert_eq!(page["items"][0]["email"], "alpha_one@example.com");
        let (_, page) = app
            .call("GET", &list("q=example.com"), Some(&token), None)
            .await;
        assert_eq!(page["total"], 0);
        let (_, page) = app
            .call("GET", &list(&format!("q={}", alpha.id)), Some(&token), None)
            .await;
        assert_eq!(page["total"], 1);
        let (_, page) = app
            .call("GET", &list("role=staff"), Some(&token), None)
            .await;
        assert_eq!(page["total"], 1);
        let (_, page) = app
            .call("GET", &list("status=no_mfa"), Some(&token), None)
            .await;
        assert_eq!(page["total"], 2);
        let (_, page) = app
            .call("GET", &list("per_page=1&page=3"), Some(&token), None)
            .await;
        assert_eq!(page["total"], 3);
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert_eq!(page["items"][0]["mfa_enabled"], false);
    })
    .await;
}

#[tokio::test]
async fn a_fresh_web_sign_in_can_be_handed_to_the_desktop_app() {
    with_app(Options::default(), |app| async move {
        use sha2::Digest;
        let member = app.member("nadia").await;
        let verifier = "a-long-random-code-verifier-for-the-pkce-exchange-123456";
        let challenge = b64url(&sha2::Sha256::digest(verifier.as_bytes()));

        let (status, _) = app
            .call(
                "POST",
                "/api/auth/native-code",
                Some(&app.mfa_session(&member)),
                Some(json!({"code_challenge": "short"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = app
            .call(
                "POST",
                "/api/auth/native-code",
                Some(&app.old_mfa_session(&member, 3600)),
                Some(json!({"code_challenge": challenge})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "reauth_required");
        let unverified = app
            .state
            .auth
            .generate_access_token(member.id, None)
            .unwrap();
        let (status, body) = app
            .call(
                "POST",
                "/api/auth/native-code",
                Some(&unverified),
                Some(json!({"code_challenge": challenge})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "mfa_required");

        let (status, body) = app
            .call(
                "POST",
                "/api/auth/native-code",
                Some(&app.mfa_session(&member)),
                Some(json!({"code_challenge": challenge})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let code = body["code"].as_str().unwrap();
        let (status, tokens) = app
            .call(
                "POST",
                "/api/auth/social/exchange",
                None,
                Some(json!({"code": code, "code_verifier": verifier})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{tokens}");
        assert!(mfa_flag(&app, tokens["access_token"].as_str().unwrap()));
    })
    .await;
}

/// A multipart/form-data body from (field, filename, content) parts.
fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> (String, Vec<u8>) {
    let boundary = "cpmesh-test-boundary";
    let mut body = Vec::new();
    for (field, file_name, content) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match file_name {
            Some(name) => body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{field}\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{field}\"\r\n\r\n").as_bytes(),
            ),
        }
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

#[tokio::test]
async fn installer_uploads_stream_to_disk_and_need_a_valid_signature() {
    // Fixtures from desktop-tauri/src-tauri/src/updater.rs (test keys only)
    const PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDE4OUE3NzlDRDkzQzdCN0YKUldSL2V6elpuSGVhR09QU0JUQ1NPb2ViQjczQ28xRFNMcU5yaG9BdVQyT3oya1JPOW8vYkZxR3IK";
    const INSTALLER: &[u8] = b"cpmesh test installer\n";
    const NAME: &str = "cpmesh-9.9.9-windows-amd64-setup.exe";
    const SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSL2V6elpuSGVhR09sYXRLUFAvajZnNGpYYzA1elVrdnkydENvelVzTjZHb092aW50bGVrUk1LL0NibXJMYU9xbkRmWjNNLzRYNEV2L2VnNjRESlJFV2tNaUNvN243bEE0PQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkyMDQzMjYxCWZpbGU6Y3BtZXNoLTkuOS45LXdpbmRvd3MtYW1kNjQtc2V0dXAuZXhlCXZlcnNpb246OS45LjkKK2hYYUcySkV4aTNkRU53dVZoMndxZFRoNThLME9uMFZHYnNrU0IrQnBoRll0T0JhTVozb0M4clNJTi90K1daSzhrWUdHM25WR01XSDhZTVJ5eHVUQ3c9PQo=";

    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_string_lossy().to_string();
    with_app(
        Options {
            downloads_dir: Some(dir_path.clone()),
            updater_public_key: Some(PUBLIC_KEY.into()),
            ..Options::default()
        },
        move |app| async move {
            let sig_name = format!("{NAME}.sig");
            let owner = app.staff("orrin", Role::Owner).await;
            let token = app.mfa_session(&owner);
            let upload = |parts: Vec<(&str, Option<&str>, &[u8])>| {
                let (content_type, body) = multipart(&parts);
                request("POST", "/api/admin/downloads/upload")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))
                    .unwrap()
            };

            // Unsigned (or wrongly signed) installers are refused and leave nothing behind
            let resp = send(&app.router, upload(vec![("file", Some(NAME), INSTALLER)])).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let resp = send(
                &app.router,
                upload(vec![
                    ("file", Some(NAME), &b"tampered\n"[..]),
                    ("signature", Some(sig_name.as_str()), SIGNATURE.as_bytes()),
                ]),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(std::fs::read_dir(&dir_path).unwrap().count(), 0);

            let signed = || {
                upload(vec![
                    ("file", Some(NAME), INSTALLER),
                    ("signature", Some(sig_name.as_str()), SIGNATURE.as_bytes()),
                ])
            };
            let resp = send(&app.router, signed()).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_json(resp).await;
            let uploaded = &body["uploaded"][0];
            assert_eq!(uploaded["signed"], true);
            assert_eq!(uploaded["size"], INSTALLER.len());
            assert_eq!(
                uploaded["sha256"],
                crate::mfa::codes::hex(&<sha2::Sha256 as sha2::Digest>::digest(INSTALLER))
            );

            // No silent overwrite
            let resp = send(&app.router, signed()).await;
            assert_eq!(resp.status(), StatusCode::CONFLICT);
            let resp = send(
                &app.router,
                upload(vec![
                    ("replace", None, &b"true"[..]),
                    ("file", Some(NAME), INSTALLER),
                    ("file", Some(sig_name.as_str()), SIGNATURE.as_bytes()),
                ]),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);

            // Served from disk with its signature, and listed once with the checksum
            let resp = send(
                &app.router,
                request("GET", &format!("/api/downloads/{NAME}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers()[header::CONTENT_LENGTH],
                INSTALLER.len().to_string()
            );
            assert_eq!(body_bytes(resp).await, INSTALLER);
            let resp = send(
                &app.router,
                request("GET", &format!("/api/downloads/{NAME}.sig"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let (_, links) = app
                .call("GET", "/api/admin/downloads", Some(&token), None)
                .await;
            assert_eq!(links.as_array().unwrap().len(), 1);
            assert_eq!(links[0]["sha256"], uploaded["sha256"]);

            // Uploading needs a recent sign-in
            let stale = app.old_mfa_session(&owner, 3600);
            let (content_type, body) = multipart(&[("file", Some("x.deb"), &b"x"[..])]);
            let resp = send(
                &app.router,
                request("POST", "/api/admin/downloads/upload")
                    .header(header::AUTHORIZATION, format!("Bearer {stale}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        },
    )
    .await;
    drop(dir);
}

#[tokio::test]
async fn an_enroll_ticket_cannot_add_a_factor_once_the_account_has_one() {
    with_app(Options::default(), |app| async move {
        let eve = app.member("eve").await;
        let (_, body) = app.login("eve").await;
        assert_eq!(body["stage"], "enroll");
        let ticket = body["mfa_token"].as_str().unwrap().to_string();

        // Meanwhile the owner sets up an authenticator elsewhere
        app.enable_totp(&eve).await;
        for path in ["/api/mfa/totp/setup", "/api/mfa/passkeys/options"] {
            let (status, body) = app.call("POST", path, Some(&ticket), None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        }
    })
    .await;
}
