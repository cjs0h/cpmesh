//! Router-level tests: routing, middleware ordering, static serving and CORS.
//!
//! The database pool is closed, so these cover everything that happens before
//! (or instead of) a database round-trip.

use axum::body::Body;
use axum::http::{Method, StatusCode, header};
use tempfile::TempDir;

use crate::test_support::*;

#[tokio::test]
async fn protected_routes_require_a_token() {
    let app = test_router(test_state(test_config()).await);
    for path in [
        "/api/me",
        "/api/devices",
        "/api/clipboard",
        "/api/device-approvals/me",
        "/api/admin/users",
        "/ws",
    ] {
        let resp = send(&app, request("GET", path).body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            body_json(resp).await["error"],
            "missing authorization token",
            "{path}"
        );
    }
}

#[tokio::test]
async fn protected_routes_reject_invalid_tokens() {
    let app = test_router(test_state(test_config()).await);
    let resp = send(
        &app,
        request("GET", "/api/me")
            .header(header::AUTHORIZATION, "Bearer not.a.jwt")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["error"], "invalid or expired token");

    // Refresh tokens are not accepted as access tokens by the middleware either
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let refresh = state
        .auth
        .generate_refresh_token(uuid::Uuid::new_v4(), None)
        .unwrap();
    let resp = send(
        &app,
        request("GET", "/api/me")
            .header(header::AUTHORIZATION, format!("Bearer {refresh}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["error"], "invalid or expired token");
}

#[tokio::test]
async fn valid_token_for_unknown_user_is_unauthorized() {
    // The token verifies, but the user lookup fails (no database): the middleware
    // must fail closed rather than let the request through.
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let token = state
        .auth
        .generate_access_token(uuid::Uuid::new_v4(), None)
        .unwrap();
    let resp = send(
        &app,
        request("GET", "/api/me")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        body_json(resp).await["error"]
            .as_str()
            .unwrap()
            .contains("user no longer exists")
    );
}

#[tokio::test]
async fn tokens_in_the_query_string_are_not_accepted() {
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let token = state
        .auth
        .generate_access_token(uuid::Uuid::new_v4(), None)
        .unwrap();
    for path in [
        format!("/ws?token={token}"),
        format!("/api/me?token={token}"),
    ] {
        let resp = send(&app, request("GET", &path).body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            body_json(resp).await["error"],
            "missing authorization token",
            "{path}"
        );
    }
}

/// A web dashboard session: signed in, but not bound to a device.
fn browser_session() -> crate::routes::middleware::AuthClaims {
    crate::routes::middleware::AuthClaims {
        user_id: uuid::Uuid::new_v4(),
        device_id: None,
        iat: 0,
        mfa: false,
        auth_time: 0,
    }
}

/// A WebSocket upgrade request (as a browser sends it) for `uri`.
fn ws_upgrade(uri: &str) -> axum::http::Request<Body> {
    request("GET", uri)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn websocket_ticket_replaces_the_bearer_token_and_is_single_use() {
    let app = test_router(test_state(test_config()).await);
    let ticket =
        crate::routes::websocket::issue_ticket(browser_session(), client_addr().ip()).await;

    // The ticket stands in for the bearer token: the request gets past ticket
    // validation to the session check, which fails here only because the test
    // state has no database.
    let resp = send(&app, ws_upgrade(&format!("/ws?ticket={ticket}"))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        body_json(resp).await["error"]
            .as_str()
            .unwrap()
            .contains("user no longer exists")
    );

    // Tickets are single-use
    let resp = send(&app, ws_upgrade(&format!("/ws?ticket={ticket}"))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["error"], "invalid or expired ticket");
}

#[tokio::test]
async fn websocket_ticket_is_bound_to_the_requesting_address() {
    let app = test_router(test_state(test_config()).await);
    let other_ip = "198.51.100.7".parse().unwrap();
    let ticket = crate::routes::websocket::issue_ticket(browser_session(), other_ip).await;

    let resp = send(&app, ws_upgrade(&format!("/ws?ticket={ticket}"))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["error"], "invalid or expired ticket");
}

#[tokio::test]
async fn websocket_rejects_unknown_tickets() {
    let app = test_router(test_state(test_config()).await);
    let resp = send(&app, ws_upgrade("/ws?ticket=deadbeef")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["error"], "invalid or expired ticket");
}

#[tokio::test]
async fn public_endpoints_do_not_require_auth() {
    let app = test_router(test_state(test_config()).await);
    for path in ["/api/downloads", "/api/downloads/current", "/api/plans"] {
        let resp = send(&app, request("GET", path).body(Body::empty()).unwrap()).await;
        // Database is unreachable: handlers degrade to an empty list
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        assert_eq!(body_json(resp).await, serde_json::json!([]), "{path}");
    }
}

#[tokio::test]
async fn update_check_requires_platform_and_degrades_without_db() {
    let app = test_router(test_state(test_config()).await);
    let resp = send(
        &app,
        request("GET", "/api/updates/check")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({"update_available": false})
    );

    let resp = send(
        &app,
        request(
            "GET",
            "/api/updates/check?platform=windows&arch=amd64&version=0.1.0",
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({"update_available": false})
    );
}

#[tokio::test]
async fn download_file_serves_from_downloads_dir_with_attachment_headers() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("cpmesh-setup.exe"), b"MZ-binary").unwrap();
    let mut cfg = test_config();
    cfg.downloads_dir = dir.path().to_string_lossy().to_string();
    let app = test_router(test_state(cfg).await);

    let resp = send(
        &app,
        request("GET", "/api/downloads/cpmesh-setup.exe")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()[header::CONTENT_TYPE],
        "application/vnd.microsoft.portable-executable"
    );
    assert_eq!(
        resp.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"cpmesh-setup.exe\""
    );
    assert_eq!(body_bytes(resp).await, b"MZ-binary");

    // Unknown file
    let resp = send(
        &app,
        request("GET", "/api/downloads/missing.dmg")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn download_file_blocks_path_traversal() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("secret.txt"), b"top secret").unwrap();
    let nested = dir.path().join("downloads");
    std::fs::create_dir(&nested).unwrap();
    let mut cfg = test_config();
    cfg.downloads_dir = nested.to_string_lossy().to_string();
    let app = test_router(test_state(cfg).await);

    for path in [
        "/api/downloads/..%2Fsecret.txt",
        "/api/downloads/..%5Csecret.txt",
        "/api/downloads/%2E%2E%2Fsecret.txt",
        "/api/downloads/..",
    ] {
        let resp = send(&app, request("GET", path).body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn download_file_is_disabled_when_no_downloads_dir() {
    let cfg = test_config(); // downloads_dir is empty
    let app = test_router(test_state(cfg).await);
    let resp = send(
        &app,
        request("GET", "/api/downloads/anything.exe")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn spa_fallback_serves_index_for_unknown_paths() {
    let app = test_router(test_state(test_config()).await);
    for path in ["/", "/login", "/devices/abc", "/not/an/api/route"] {
        let resp = send(&app, request("GET", path).body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let ct = resp.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.starts_with("text/html"), "{path}: {ct}");
        let body = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(body.contains("<html"), "{path}");
    }
}

#[tokio::test]
async fn unknown_api_method_is_405_not_spa() {
    let app = test_router(test_state(test_config()).await);
    let resp = send(
        &app,
        request("DELETE", "/api/auth/login")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn security_headers_are_applied_to_api_and_spa_responses() {
    let app = test_router(test_state(test_config()).await);
    for path in ["/", "/api/auth/social/status", "/api/me"] {
        let resp = send(&app, request("GET", path).body(Body::empty()).unwrap()).await;
        let h = resp.headers();
        assert_eq!(h["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(h["x-frame-options"], "DENY", "{path}");
        assert!(h.contains_key("content-security-policy"), "{path}");
        assert!(h.contains_key("strict-transport-security"), "{path}");
    }
}

#[tokio::test]
async fn cors_is_same_origin_only_by_default() {
    let app = test_router(test_state(test_config()).await);
    let resp = send(
        &app,
        request("OPTIONS", "/api/auth/login")
            .header(header::ORIGIN, "https://evil.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "no origin may be allowed when ALLOWED_ORIGINS is empty"
    );
}

#[tokio::test]
async fn cors_allows_only_configured_origins_with_credentials() {
    let mut cfg = test_config();
    cfg.allowed_origins = vec!["https://app.cpmesh.test".into()];
    let app = test_router(test_state(cfg).await);

    let preflight = |origin: &str| {
        request("OPTIONS", "/api/auth/login")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
            .body(Body::empty())
            .unwrap()
    };

    let resp = send(&app, preflight("https://app.cpmesh.test")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://app.cpmesh.test"
    );
    assert_eq!(
        resp.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
        "true"
    );
    // Requested headers are mirrored (a `*` wildcard is invalid with credentials)
    assert_eq!(
        resp.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "content-type"
    );
    let methods = resp.headers()[header::ACCESS_CONTROL_ALLOW_METHODS]
        .to_str()
        .unwrap()
        .to_string();
    for m in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
        assert!(methods.contains(m.as_str()), "{methods}");
    }

    let resp = send(&app, preflight("https://evil.example")).await;
    assert!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );

    // Actual (non-preflight) cross-origin requests also carry the headers
    let resp = send(
        &app,
        request("GET", "/api/auth/social/status")
            .header(header::ORIGIN, "https://app.cpmesh.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://app.cpmesh.test"
    );
}

#[tokio::test]
async fn admin_routes_fail_closed_when_user_cannot_be_loaded() {
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let token = state
        .auth
        .generate_access_token(uuid::Uuid::new_v4(), None)
        .unwrap();
    let resp = send(
        &app,
        request("GET", "/api/admin/stats")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    // auth_middleware runs first and cannot confirm the user exists
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
