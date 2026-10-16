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

fn device_key() -> aws_lc_rs::signature::EcdsaKeyPair {
    aws_lc_rs::signature::EcdsaKeyPair::generate(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
    )
    .unwrap()
}

fn device_registration(
    key: &aws_lc_rs::signature::EcdsaKeyPair,
    challenge: &str,
    fingerprint: &str,
) -> Value {
    use aws_lc_rs::signature::KeyPair;
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    json!({
        "name": "Proof device", "fingerprint": fingerprint,
        "public_key": b64.encode(key.public_key().as_ref()),
        "proof": {
            "challenge": challenge,
            "signature": b64.encode(key.sign(&aws_lc_rs::rand::SystemRandom::new(), &cpmesh_proto::models::device_proof_transcript(challenge)).unwrap().as_ref()),
        },
    })
}

#[tokio::test]
async fn device_registration_requires_fresh_session_bound_possession_and_issues_bound_refresh() {
    with_app(Options::default(), |app| async move {
        let user = app.member("proof").await;
        let token = app.mfa_session(&user);
        let other_session = app.mfa_session(&user);
        let key = device_key();
        let (_, challenge) = app
            .call("POST", "/api/devices/challenge", Some(&token), None)
            .await;
        let body = device_registration(&key, challenge["challenge"].as_str().unwrap(), "fp");
        let mut legacy = body.clone();
        legacy.as_object_mut().unwrap().remove("proof");
        assert_eq!(
            app.call("POST", "/api/devices", Some(&token), Some(legacy))
                .await
                .0,
            StatusCode::UPGRADE_REQUIRED
        );
        assert_eq!(
            app.call(
                "POST",
                "/api/devices",
                Some(&other_session),
                Some(body.clone())
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let (status, registration) = app
            .call("POST", "/api/devices", Some(&token), Some(body.clone()))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{registration}");
        let id = registration["device"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let access = app
            .state
            .auth
            .validate_access_token(registration["access_token"].as_str().unwrap())
            .unwrap();
        assert_eq!(access.device_id, Some(id));
        assert!(access.mfa);
        let crate::routes::auth_service::RefreshResult::Ok(refresh, _, _) = app
            .state
            .auth
            .validate_refresh_token(registration["refresh_token"].as_str().unwrap())
        else {
            panic!("invalid refresh");
        };
        assert_eq!(refresh.device_id, Some(id));
        assert_eq!(
            app.call("POST", "/api/devices", Some(&token), Some(body))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );

        // Knowing the fingerprint or a captured public-key signature never authorizes replacement.
        let (_, challenge) = app
            .call("POST", "/api/devices/challenge", Some(&other_session), None)
            .await;
        let replacement = device_registration(
            &device_key(),
            challenge["challenge"].as_str().unwrap(),
            "fp",
        );
        let (status, conflict) = app
            .call(
                "POST",
                "/api/devices",
                Some(&other_session),
                Some(replacement),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        // The app offers to replace exactly this registration
        assert_eq!(conflict["code"], "device_keys_changed", "{conflict}");
        assert_eq!(conflict["device_id"], id.to_string());
        assert_eq!(conflict["device_name"], "Proof device");
        let (_, challenge) = app
            .call("POST", "/api/devices/challenge", Some(&other_session), None)
            .await;
        let reconnect = device_registration(&key, challenge["challenge"].as_str().unwrap(), "fp");
        assert_eq!(
            app.call(
                "POST",
                "/api/devices",
                Some(&other_session),
                Some(reconnect)
            )
            .await
            .0,
            StatusCode::OK
        );
    })
    .await;
}

#[tokio::test]
async fn an_account_whose_only_key_holder_was_removed_can_start_new_keys() {
    use aws_lc_rs::signature::KeyPair as _;
    use base64::Engine;
    use cpmesh_proto::models as proto;
    let b64 = base64::engine::general_purpose::STANDARD;
    with_app(Options::default(), |app| async move {
        let user = app.member("lost-keys").await;
        let web = app.mfa_session(&user);
        let register = |key: aws_lc_rs::signature::EcdsaKeyPair, fingerprint: &'static str| {
            let app = &app;
            let web = web.clone();
            async move {
                let (_, challenge) = app
                    .call("POST", "/api/devices/challenge", Some(&web), None)
                    .await;
                let body = device_registration(
                    &key,
                    challenge["challenge"].as_str().unwrap(),
                    fingerprint,
                );
                let (status, registered) = app
                    .call("POST", "/api/devices", Some(&web), Some(body))
                    .await;
                assert_eq!(status, StatusCode::CREATED, "{registered}");
                (key, registered)
            }
        };

        // The only device that held the account's keys (versions 1 and 2) is removed
        let (_, old) = register(device_key(), "fp-old").await;
        let old_id: uuid::Uuid = old["device"]["id"].as_str().unwrap().parse().unwrap();
        let db = &app.state.db;
        db.rotate_group_key(user.id, old_id, 0, 1, &[(old_id, vec![1; 60])], 24)
            .await
            .unwrap();
        db.rotate_group_key(user.id, old_id, 1, 2, &[(old_id, vec![2; 60])], 24)
            .await
            .unwrap();
        let (status, _) = app
            .call(
                "DELETE",
                &format!("/api/devices/{old_id}"),
                Some(&web),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Registered again, this computer is the first device and approved, but no
        // device can give it key 2
        let (new_key, new) = register(device_key(), "fp-new").await;
        assert_eq!(new["device"]["status"], "approved");
        let new_id = new["device"]["id"].as_str().unwrap().to_string();
        let access = new["access_token"].as_str().unwrap().to_string();
        let current_uri = "/api/group-keys/current?since_version=0";
        let (status, current) = app.call("GET", current_uri, Some(&access), None).await;
        assert_eq!(status, StatusCode::OK, "{current}");
        assert_eq!(current["current_version"], 2);
        assert_eq!(current["keys"], json!([]));
        assert_eq!(current["rotation_required"], true);

        // The app's last resort: version 3 for every approved device, from a device that
        // never held version 2. No database reset needed.
        let members = vec![proto::DeviceIdentity {
            id: new_id.clone(),
            public_key: new_key.public_key().as_ref().to_vec(),
        }];
        let wrap = vec![7u8; proto::WRAP_V3_LEN];
        let hashes: std::collections::BTreeMap<String, String> =
            [(new_id.clone(), proto::wrapped_key_hash(&wrap))].into();
        let transcript = proto::membership_transcript(3, &new_id, &members, &hashes).unwrap();
        let reset = json!({
            "expected_current_version": 2,
            "new_version": 3,
            "wrapped_keys": [{
                "device_id": new_id,
                "encrypted_key": b64.encode(&wrap),
                "membership": {
                    "members": members,
                    "wrapped_key_hashes": hashes,
                    "signature": b64.encode(device_sign(&new_key, &transcript)),
                },
            }],
        });
        let (status, body) = app
            .call("POST", "/api/group-keys/rotate", Some(&access), Some(reset))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, current) = app.call("GET", current_uri, Some(&access), None).await;
        assert_eq!(current["current_version"], 3);
        assert_eq!(current["keys"].as_array().unwrap().len(), 1);
        assert_eq!(current["rotation_required"], false);
    })
    .await;
}

#[tokio::test]
async fn simultaneous_first_registrations_only_auto_approve_one_device() {
    with_app(Options::default(), |app| async move {
        let user = app.member("registration-race").await;
        let token = app.mfa_session(&user);
        let (_, a) = app
            .call("POST", "/api/devices/challenge", Some(&token), None)
            .await;
        let (_, b) = app
            .call("POST", "/api/devices/challenge", Some(&token), None)
            .await;
        let a = device_registration(&device_key(), a["challenge"].as_str().unwrap(), "a");
        let b = device_registration(&device_key(), b["challenge"].as_str().unwrap(), "b");
        let (a, b) = tokio::join!(
            app.call("POST", "/api/devices", Some(&token), Some(a)),
            app.call("POST", "/api/devices", Some(&token), Some(b)),
        );
        assert_eq!(a.0, StatusCode::CREATED, "{:?}", a.1);
        assert_eq!(b.0, StatusCode::CREATED, "{:?}", b.1);
        let devices = app.state.db.get_devices_by_user(user.id).await.unwrap();
        assert_eq!(devices.iter().filter(|d| d.status == "approved").count(), 1);
        assert_eq!(devices.iter().filter(|d| d.status == "pending").count(), 1);
    })
    .await;
}

type TestSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn open_socket(address: std::net::SocketAddr, token: &str) -> TestSocket {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://{address}/ws").into_client_request().unwrap();
    req.headers_mut().insert(
        "x-cpmesh-protocol",
        cpmesh_proto::models::PROTOCOL_VERSION.parse().unwrap(),
    );
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

async fn socket_message(socket: &mut TestSocket, kind: &str) -> Value {
    use futures_util::StreamExt;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let message = socket.next().await.expect("socket closed").unwrap();
            if let tokio_tungstenite::tungstenite::Message::Text(text) = message {
                let value: Value = serde_json::from_str(&text).unwrap();
                if value["type"] == kind {
                    return value["payload"].clone();
                }
            }
        }
    })
    .await
    .expect("message deadline")
}

async fn socket_closed(socket: &mut TestSocket) {
    use futures_util::StreamExt;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while let Some(message) = socket.next().await {
            if matches!(
                message,
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) | Err(_)
            ) {
                return;
            }
        }
    })
    .await
    .expect("revoked socket remained open");
}

/// A protocol-v3 push: the entry context and both ciphertexts are signed by the
/// sender's identity key.
fn signed_push(
    key: &aws_lc_rs::signature::EcdsaKeyPair,
    device_id: uuid::Uuid,
    request_id: &str,
    key_version: i32,
    encrypted_data: &[u8],
    sent_at: i64,
) -> Value {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let transcript = cpmesh_proto::models::clipboard_signature_transcript(
        key_version,
        &cpmesh_proto::models::ContentType::Text,
        &device_id.to_string(),
        request_id,
        sent_at,
        encrypted_data,
        b"",
    );
    let signature = key
        .sign(&aws_lc_rs::rand::SystemRandom::new(), &transcript)
        .unwrap();
    json!({"type": "clipboard_push", "payload": {
        "request_id": request_id, "content_type": "text",
        "encrypted_data": b64.encode(encrypted_data),
        "key_version": key_version, "sent_at": sent_at,
        "sender_signature": b64.encode(signature.as_ref()),
    }})
}

#[tokio::test]
async fn live_sockets_acknowledge_commit_reconcile_ids_and_stop_after_revocation() {
    use aws_lc_rs::signature::KeyPair as _;
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    with_app(Options::default(), |app| async move {
        let user = app.member("live-relay").await;
        let a_key = device_key();
        let a = app.state.db.create_device(user.id, "A", a_key.public_key().as_ref(), None, "approved", None).await.unwrap();
        let b = app.state.db.create_device(user.id, "B", &[4; 65], None, "approved", None).await.unwrap();
        app.state.db.rotate_group_key(user.id, a.id, 0, 1, &[(a.id, vec![1; 60]), (b.id, vec![2; 60])], 24).await.unwrap();
        let grant = SessionGrant::signed_in(user.id, true);
        let (a_access, stolen_refresh) = app.state.auth.issue_session(&grant.with_device(Some(a.id))).unwrap();
        let b_access = app.state.auth.issue_access(&grant.with_device(Some(b.id))).unwrap();
        let web_access = app.state.auth.issue_access(&grant).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = app.router.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
        });
        let mut a_socket = open_socket(address, &a_access).await;
        let mut b_socket = open_socket(address, &b_access).await;
        let mut browser = open_socket(address, &web_access).await;
        let request_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp_millis();
        let push = signed_push(&a_key, a.id, &request_id, 1, &[7; 48], now);

        // Unsigned, relabelled, mis-signed and stale-clock pushes are refused.
        let mut unsigned = push.clone();
        unsigned["payload"].as_object_mut().unwrap().remove("sender_signature");
        a_socket.send(Message::Text(unsigned.to_string().into())).await.unwrap();
        assert_eq!(socket_message(&mut a_socket, "clipboard_ack").await["code"], "signature_required");
        let mut relabelled = push.clone();
        relabelled["payload"]["content_type"] = json!("file");
        a_socket.send(Message::Text(relabelled.to_string().into())).await.unwrap();
        assert_eq!(socket_message(&mut a_socket, "clipboard_ack").await["code"], "invalid_signature");
        let forged = signed_push(&device_key(), a.id, &request_id, 1, &[7; 48], now);
        a_socket.send(Message::Text(forged.to_string().into())).await.unwrap();
        assert_eq!(socket_message(&mut a_socket, "clipboard_ack").await["code"], "invalid_signature");
        let stale_clock = signed_push(&a_key, a.id, &request_id, 1, &[7; 48], now - 2 * 24 * 60 * 60 * 1000);
        a_socket.send(Message::Text(stale_clock.to_string().into())).await.unwrap();
        assert_eq!(socket_message(&mut a_socket, "clipboard_ack").await["code"], "clock_skew");

        a_socket.send(Message::Text(push.to_string().into())).await.unwrap();
        let ack = socket_message(&mut a_socket, "clipboard_ack").await;
        assert_eq!(ack["status"], "accepted");
        assert_eq!(ack["request_id"], request_id);
        let received = socket_message(&mut b_socket, "clipboard_new").await;
        assert_eq!(received["entry"]["id"], ack["entry_id"]);
        // Receivers get everything they need to verify the sender themselves.
        assert_eq!(received["entry"]["request_id"], request_id);
        assert_eq!(received["entry"]["sent_at"], now);
        assert_eq!(received["entry"]["sender_signature"], push["payload"]["sender_signature"]);
        assert_eq!(received["entry"]["device_id"], a.id.to_string());
        let metadata = socket_message(&mut browser, "clipboard_new").await;
        assert_eq!(metadata["entry"]["encrypted_size"], 48);
        assert!(metadata["entry"].get("encrypted_data").is_none());
        a_socket.send(Message::Text(push.to_string().into())).await.unwrap();
        let retry = socket_message(&mut a_socket, "clipboard_ack").await;
        assert_eq!(retry["entry_id"], ack["entry_id"]);
        assert_eq!(app.state.db.count_user_clipboard_entries(user.id).await.unwrap(), 1);
        let (status, history) = app.call("GET", "/api/clipboard?metadata_only=true", Some(&web_access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(history["entries"][0].get("encrypted_data").is_none());
        let (status, history) = app.call("GET", "/api/clipboard", Some(&a_access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(history["entries"][0]["sender_signature"], push["payload"]["sender_signature"]);
        assert_eq!(history["entries"][0]["sent_at"], now);
        assert_eq!(history["entries"][0]["request_id"], request_id);
        let mut invalid = push.clone();
        let invalid_id = uuid::Uuid::new_v4().to_string();
        invalid["payload"]["request_id"] = json!(invalid_id);
        invalid["payload"]["encrypted_data"] = json!("not base64");
        a_socket.send(Message::Text(invalid.to_string().into())).await.unwrap();
        let rejection = socket_message(&mut a_socket, "clipboard_ack").await;
        assert_eq!(rejection["request_id"], invalid_id);
        assert_eq!(rejection["code"], "invalid_payload");
        sqlx::query("ALTER TABLE clipboard_entries ADD CONSTRAINT fail_clipboard_test CHECK (key_version <> 1) NOT VALID")
            .execute(&app.state.db.pool).await.unwrap();
        let failed = signed_push(&a_key, a.id, &uuid::Uuid::new_v4().to_string(), 1, &[7; 48], now);
        a_socket.send(Message::Text(failed.to_string().into())).await.unwrap();
        assert_eq!(socket_message(&mut a_socket, "clipboard_ack").await["code"], "temporarily_unavailable");
        sqlx::query("ALTER TABLE clipboard_entries DROP CONSTRAINT fail_clipboard_test")
            .execute(&app.state.db.pool).await.unwrap();
        app.state.db.clear_clipboard_history(user.id).await.unwrap();
        a_socket.send(Message::Text(push.to_string().into())).await.unwrap();
        assert_eq!(socket_message(&mut a_socket, "clipboard_ack").await["entry_id"], ack["entry_id"]);
        assert_eq!(app.state.db.count_user_clipboard_entries(user.id).await.unwrap(), 0, "retries must not resurrect deleted history");

        let (status, _) = app.call("DELETE", &format!("/api/devices/{}", b.id), Some(&web_access), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        socket_closed(&mut b_socket).await;
        assert!(!app.state.hub.is_device_online(&user.id.to_string(), &b.id.to_string()).await);
        let stale_id = uuid::Uuid::new_v4().to_string();
        let stale = signed_push(&a_key, a.id, &stale_id, 1, &[7; 48], now);
        a_socket.send(Message::Text(stale.to_string().into())).await.unwrap();
        assert_eq!(socket_message(&mut a_socket, "clipboard_ack").await["code"], "rotation_required");
        app.state.db.rotate_group_key(user.id, a.id, 1, 2, &[(a.id, vec![3; 60])], 24).await.unwrap();
        let rotated = signed_push(&a_key, a.id, &stale_id, 2, &[7; 48], now);
        a_socket.send(Message::Text(rotated.to_string().into())).await.unwrap();
        assert_eq!(socket_message(&mut a_socket, "clipboard_ack").await["status"], "accepted");

        let (status, changed) = app.call("PUT", "/api/me/password", Some(&web_access),
            Some(json!({"current_password": PASSWORD, "new_password": "Changed-Horse-7!"}))).await;
        assert_eq!(status, StatusCode::OK, "{changed}");
        assert_eq!(changed["reauth_required"], true);
        socket_closed(&mut a_socket).await;
        socket_closed(&mut browser).await;
        assert_eq!(app.call("POST", "/api/auth/refresh", None, Some(json!({"refresh_token": stolen_refresh}))).await.0, StatusCode::UNAUTHORIZED);
        // A refresh that was already in flight cannot mint its way past the cutoff.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let late_refresh = app.state.auth.issue_refresh(&grant).unwrap();
        assert_eq!(app.call("POST", "/api/auth/refresh", None, Some(json!({"refresh_token": late_refresh}))).await.0, StatusCode::UNAUTHORIZED);
        server.abort();
        let _ = server.await;
    }).await;
}

/// Signs `message` with a device identity key (DER ECDSA).
fn device_sign(key: &aws_lc_rs::signature::EcdsaKeyPair, message: &[u8]) -> Vec<u8> {
    key.sign(&aws_lc_rs::rand::SystemRandom::new(), message)
        .unwrap()
        .as_ref()
        .to_vec()
}

#[tokio::test]
async fn pairing_uses_committed_short_codes_and_certified_encryption_keys() {
    use aws_lc_rs::signature::KeyPair as _;
    use base64::Engine;
    use cpmesh_proto::models as proto;
    let b64 = base64::engine::general_purpose::STANDARD;
    with_app(Options::default(), |app| async move {
        let user = app.member("pairing-v3").await;
        let grant = SessionGrant::signed_in(user.id, true);

        // Approver A exists already; it publishes an identity-certified encryption key.
        let a_key = device_key();
        let a_enc = device_key();
        let a = app.state.db.create_device(user.id, "A", a_key.public_key().as_ref(), None, "approved", None).await.unwrap();
        let a_access = app.state.auth.issue_access(&grant.with_device(Some(a.id))).unwrap();
        let a_cert = device_sign(&a_key, &proto::encryption_key_transcript(a_key.public_key().as_ref(), a_enc.public_key().as_ref()));
        let publish = |key: &[u8], sig: &[u8]| json!({"encryption_key": b64.encode(key), "encryption_key_sig": b64.encode(sig)});
        // Wrong certification, an identity key reused as encryption key, then a valid one.
        let (status, _) = app.call("PUT", "/api/devices/me/encryption-key", Some(&a_access),
            Some(publish(a_enc.public_key().as_ref(), &device_sign(&device_key(), b"x")))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = app.call("PUT", "/api/devices/me/encryption-key", Some(&a_access),
            Some(publish(a_key.public_key().as_ref(), &a_cert))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = app.call("PUT", "/api/devices/me/encryption-key", Some(&a_access),
            Some(publish(a_enc.public_key().as_ref(), &a_cert))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Pending B registers with its encryption key in one step.
        let b_key = device_key();
        let b_enc = device_key();
        let web = app.state.auth.issue_access(&grant).unwrap();
        let (status, challenge) = app.call("POST", "/api/devices/challenge", Some(&web), None).await;
        assert_eq!(status, StatusCode::OK);
        let mut registration = device_registration(&b_key, challenge["challenge"].as_str().unwrap(), "fp-b");
        registration["encryption_key"] = json!(b64.encode(b_enc.public_key().as_ref()));
        registration["encryption_key_sig"] = json!(b64.encode(device_sign(&b_key, b"not the transcript")));
        let (status, _) = app.call("POST", "/api/devices", Some(&web), Some(registration.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a forged certification is refused before the proof is consumed");
        let (status, challenge) = app.call("POST", "/api/devices/challenge", Some(&web), None).await;
        assert_eq!(status, StatusCode::OK);
        let mut registration = device_registration(&b_key, challenge["challenge"].as_str().unwrap(), "fp-b");
        registration["encryption_key"] = json!(b64.encode(b_enc.public_key().as_ref()));
        registration["encryption_key_sig"] = json!(b64.encode(device_sign(&b_key,
            &proto::encryption_key_transcript(b_key.public_key().as_ref(), b_enc.public_key().as_ref()))));
        let (status, registered) = app.call("POST", "/api/devices", Some(&web), Some(registration)).await;
        assert_eq!(status, StatusCode::CREATED, "{registered}");
        assert_eq!(registered["device"]["status"], "pending");
        let b_id: uuid::Uuid = registered["device"]["id"].as_str().unwrap().parse().unwrap();
        let b_access = registered["access_token"].as_str().unwrap().to_string();

        let (status, keys) = app.call("GET", "/api/devices/keys", Some(&a_access), None).await;
        assert_eq!(status, StatusCode::OK);
        let listed_b = keys["devices"].as_array().unwrap().iter().find(|d| d["id"] == b_id.to_string()).unwrap();
        assert_eq!(listed_b["encryption_key"], b64.encode(b_enc.public_key().as_ref()));
        assert!(listed_b["encryption_key_sig"].is_string());

        // Pairing: the approver commits first.
        let begin_uri = format!("/api/device-approvals/{b_id}/begin");
        let nonce_a = [0xA5u8; 32];
        let commit = proto::sas_commitment(&nonce_a);
        let (status, _) = app.call("POST", &begin_uri, Some(&a_access), Some(json!({"commit": b64.encode(commit)}))).await;
        assert_eq!(status, StatusCode::UPGRADE_REQUIRED, "pairing version header is required");
        let (status, _) = app.call_with_headers("POST", &begin_uri, Some(&a_access), &[("x-cpmesh-pairing", "3")], None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a commitment is required");
        let (status, session) = app.call_with_headers("POST", &begin_uri, Some(&a_access), &[("x-cpmesh-pairing", "3")],
            Some(json!({"commit": b64.encode(commit)}))).await;
        assert_eq!(status, StatusCode::OK, "{session}");
        assert_eq!(session["pairing_version"], 3);
        assert_eq!(session["pending_encryption_key"], b64.encode(b_enc.public_key().as_ref()));
        let session_id = session["session_id"].as_str().unwrap().to_string();

        // The pending device sees the commitment but no nonce yet.
        let (status, me) = app.call("GET", "/api/device-approvals/me", Some(&b_access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me["approver_commit"], b64.encode(commit));
        assert!(me.get("approver_nonce").is_none());
        // The approver cannot open its commitment before the pending nonce exists.
        let reveal_uri = format!("/api/device-approvals/{b_id}/reveal");
        let (status, _) = app.call("POST", &reveal_uri, Some(&a_access),
            Some(json!({"session_id": session_id, "nonce": b64.encode(nonce_a)}))).await;
        assert_eq!(status, StatusCode::CONFLICT);

        let nonce_b = [0x5Au8; 32];
        let (status, _) = app.call("POST", "/api/device-approvals/me/nonce", Some(&b_access),
            Some(json!({"session_id": session_id, "nonce": b64.encode(nonce_b)}))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = app.call("POST", "/api/device-approvals/me/nonce", Some(&b_access),
            Some(json!({"session_id": session_id, "nonce": b64.encode([1u8; 32])}))).await;
        assert_eq!(status, StatusCode::CONFLICT, "the nonce cannot be changed afterwards");

        let (status, state) = app.call("GET", &format!("/api/device-approvals/{b_id}/session"), Some(&a_access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(state["pending_nonce"], b64.encode(nonce_b));
        let (status, _) = app.call("POST", &reveal_uri, Some(&a_access),
            Some(json!({"session_id": session_id, "nonce": b64.encode([9u8; 32])}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a nonce that does not open the commitment is refused");
        let (status, _) = app.call("POST", &reveal_uri, Some(&a_access),
            Some(json!({"session_id": session_id, "nonce": b64.encode(nonce_a)}))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, me) = app.call("GET", "/api/device-approvals/me", Some(&b_access), None).await;
        let revealed: [u8; 32] = b64.decode(me["approver_nonce"].as_str().unwrap()).unwrap().try_into().unwrap();
        assert_eq!(proto::sas_commitment(&revealed), commit);
        let sas_a = proto::sas_code(&nonce_a, &nonce_b, a_key.public_key().as_ref(), b_key.public_key().as_ref());
        let sas_b = proto::sas_code(&revealed, &nonce_b, b_key.public_key().as_ref(), a_key.public_key().as_ref());
        assert_eq!(sas_a, sas_b);
        assert_eq!(sas_a.len(), 9);

        // Approval: v3 wraps are 125 bytes and committed to by the signed transcript.
        let members = vec![
            proto::DeviceIdentity { id: a.id.to_string(), public_key: a_key.public_key().as_ref().to_vec() },
            proto::DeviceIdentity { id: b_id.to_string(), public_key: b_key.public_key().as_ref().to_vec() },
        ];
        let approve = |wrap_len: usize| {
            let wraps = [(a.id.to_string(), vec![1u8; wrap_len]), (b_id.to_string(), vec![2u8; wrap_len])];
            let hashes: std::collections::BTreeMap<String, String> = wraps.iter()
                .map(|(id, wrap)| (id.clone(), proto::wrapped_key_hash(wrap))).collect();
            let transcript = proto::membership_transcript(1, &a.id.to_string(), &members, &hashes).unwrap();
            let signature = device_sign(&a_key, &transcript);
            json!({
                "session_id": session_id, "expected_current_version": 0, "new_version": 1,
                "wrapped_keys": [
                    {"device_id": wraps[0].0, "encrypted_key": b64.encode(&wraps[0].1), "membership": {
                        "members": members, "wrapped_key_hashes": hashes, "signature": b64.encode(signature)}},
                    {"device_id": wraps[1].0, "encrypted_key": b64.encode(&wraps[1].1)},
                ],
            })
        };
        let approve_uri = format!("/api/device-approvals/{b_id}/approve");
        let (status, _) = app.call("POST", &approve_uri, Some(&a_access), Some(approve(60))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "legacy static-static wraps are no longer accepted");
        let (status, body) = app.call("POST", &approve_uri, Some(&a_access), Some(approve(proto::WRAP_V3_LEN))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, current) = app.call("GET", "/api/group-keys/current", Some(&b_access), None).await;
        assert_eq!(status, StatusCode::OK, "{current}");
        assert_eq!(current["current_version"], 1);
        assert_eq!(b64.decode(current["keys"][0]["encrypted_key"].as_str().unwrap()).unwrap().len(), proto::WRAP_V3_LEN);
        assert!(current["keys"][0]["membership"].is_object());
    }).await;
}

#[tokio::test]
async fn approved_devices_missing_the_current_key_are_flagged_and_can_pair_to_receive_it() {
    use aws_lc_rs::signature::KeyPair as _;
    use base64::Engine;
    use cpmesh_proto::models as proto;
    let b64 = base64::engine::general_purpose::STANDARD;
    with_app(Options::default(), |app| async move {
        let db = &app.state.db;
        let user = app.member("keyless").await;
        let grant = SessionGrant::signed_in(user.id, true);
        let a_key = device_key();
        let a = db.create_device(user.id, "A", a_key.public_key().as_ref(), None, "approved", None).await.unwrap();
        let a_access = app.state.auth.issue_access(&grant.with_device(Some(a.id))).unwrap();
        assert!(db.rotate_group_key(user.id, a.id, 0, 1, &[(a.id, vec![1; proto::WRAP_V3_LEN])], 24).await.unwrap());
        // D is approved but holds no wrap of the current key, as older servers could
        // leave a device after re-registering it.
        let d_key = device_key();
        let d = db.create_device(user.id, "D", d_key.public_key().as_ref(), None, "approved", Some("fp-d")).await.unwrap();
        let d_access = app.state.auth.issue_access(&grant.with_device(Some(d.id))).unwrap();

        let flag = |devices: &Value, id: uuid::Uuid| {
            devices.as_array().unwrap().iter().find(|x| x["id"] == id.to_string()).unwrap()["has_current_key"].clone()
        };
        let (status, keys) = app.call("GET", "/api/devices/keys", Some(&a_access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(flag(&keys["devices"], a.id), true);
        assert_eq!(flag(&keys["devices"], d.id), false);
        let (status, listed) = app.call("GET", "/api/devices", Some(&d_access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(flag(&listed, d.id), false, "D can see that it lacks the key");
        let (status, current) = app.call("GET", "/api/group-keys/current?since_version=0", Some(&d_access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(current["current_version"], 1);
        assert_eq!(current["keys"], json!([]));

        // A verifies D with the committed short code, as for a new device.
        let begin = async |target: uuid::Uuid| {
            app.call_with_headers("POST", &format!("/api/device-approvals/{target}/begin"), Some(&a_access),
                &[("x-cpmesh-pairing", "3")], Some(json!({"commit": b64.encode(proto::sas_commitment(&[7u8; 32]))}))).await
        };
        assert_eq!(begin(a.id).await.0, StatusCode::BAD_REQUEST, "a device cannot pair with itself");
        let (status, session) = begin(d.id).await;
        assert_eq!(status, StatusCode::OK, "{session}");
        assert_eq!(session["pending_public_key"], b64.encode(d_key.public_key().as_ref()));
        let session_id = session["session_id"].as_str().unwrap().to_string();
        let (status, me) = app.call("GET", "/api/device-approvals/me", Some(&d_access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me["status"], "approved");
        assert_eq!(me["session_id"], session_id);
        assert_eq!(me["approver_device_id"], a.id.to_string());
        assert_eq!(me["approver_public_key"], b64.encode(a_key.public_key().as_ref()));
        let (status, _) = app.call("POST", "/api/device-approvals/me/nonce", Some(&d_access),
            Some(json!({"session_id": session_id, "nonce": b64.encode([8u8; 32])}))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = app.call("POST", &format!("/api/device-approvals/{}/reveal", d.id), Some(&a_access),
            Some(json!({"session_id": session_id, "nonce": b64.encode([7u8; 32])}))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        // Pairing never changes an approved device's status.
        let (status, _) = app.call("POST", &format!("/api/device-approvals/{}/approve", d.id), Some(&a_access),
            Some(json!({"session_id": session_id, "expected_current_version": 1, "new_version": 2, "wrapped_keys": []}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // A shares the key by rotating to every approved member.
        let members = vec![
            proto::DeviceIdentity { id: a.id.to_string(), public_key: a_key.public_key().as_ref().to_vec() },
            proto::DeviceIdentity { id: d.id.to_string(), public_key: d_key.public_key().as_ref().to_vec() },
        ];
        let wraps = [(a.id.to_string(), vec![3u8; proto::WRAP_V3_LEN]), (d.id.to_string(), vec![4u8; proto::WRAP_V3_LEN])];
        let hashes: std::collections::BTreeMap<String, String> = wraps.iter()
            .map(|(id, wrap)| (id.clone(), proto::wrapped_key_hash(wrap))).collect();
        let transcript = proto::membership_transcript(2, &a.id.to_string(), &members, &hashes).unwrap();
        let rotation = json!({
            "expected_current_version": 1, "new_version": 2,
            "wrapped_keys": [
                {"device_id": wraps[0].0, "encrypted_key": b64.encode(&wraps[0].1), "membership": {
                    "members": members, "wrapped_key_hashes": hashes, "signature": b64.encode(device_sign(&a_key, &transcript))}},
                {"device_id": wraps[1].0, "encrypted_key": b64.encode(&wraps[1].1)},
            ],
        });
        let (status, body) = app.call("POST", "/api/group-keys/rotate", Some(&a_access), Some(rotation)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, keys) = app.call("GET", "/api/devices/keys", Some(&a_access), None).await;
        assert_eq!(flag(&keys["devices"], d.id), true);
        let (status, current) = app.call("GET", "/api/group-keys/current?since_version=0", Some(&d_access), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(current["current_version"], 2);
        assert_eq!(current["keys"][0]["from_device_id"], a.id.to_string());
        assert!(current["keys"][0]["membership"].is_object());

        // Signing in again with D's identity keeps its approval and its wrap; a new
        // identity behind D's fingerprint is refused instead of replacing D's keys.
        let web = app.state.auth.issue_access(&grant).unwrap();
        for (key, expected) in [(&d_key, StatusCode::OK), (&device_key(), StatusCode::CONFLICT)] {
            let (_, challenge) = app.call("POST", "/api/devices/challenge", Some(&web), None).await;
            let registration = device_registration(key, challenge["challenge"].as_str().unwrap(), "fp-d");
            let (status, registered) = app.call("POST", "/api/devices", Some(&web), Some(registration)).await;
            assert_eq!(status, expected, "{registered}");
            if expected == StatusCode::CONFLICT {
                assert_eq!(registered["code"], "device_keys_changed");
                assert_eq!(registered["device_id"], d.id.to_string());
            }
        }
        let (_, keys) = app.call("GET", "/api/devices/keys", Some(&a_access), None).await;
        let listed_d = keys["devices"].as_array().unwrap().iter().find(|x| x["id"] == d.id.to_string()).unwrap();
        assert_eq!(listed_d["status"], "approved");
        assert_eq!(listed_d["has_current_key"], true);
        assert_eq!(keys["devices"].as_array().unwrap().len(), 2);
    }).await;
}

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
        self.call_with_headers(method, uri, token, &[], body).await
    }

    async fn call_with_headers(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = request(method, uri);
        if let Some(token) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        for (name, value) in headers {
            req = req.header(*name, *value);
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
