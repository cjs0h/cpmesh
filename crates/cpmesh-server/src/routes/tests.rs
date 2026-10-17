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
        session_start: 0,
        mfa: false,
        auth_time: 0,
        agent: None,
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
async fn oidc_callback_requires_nonempty_matching_cookie_and_state() {
    let app = test_router(test_state(test_config()).await);
    for (uri, cookie) in [
        (
            "/api/auth/social/callback?code=x",
            Some("cpmesh_oidc_state=expected"),
        ),
        ("/api/auth/social/callback?code=x&state=expected", None),
        (
            "/api/auth/social/callback?code=x&state=",
            Some("cpmesh_oidc_state=expected"),
        ),
        (
            "/api/auth/social/callback?code=x&state=wrong",
            Some("cpmesh_oidc_state=expected"),
        ),
        (
            "/api/auth/social/callback?code=x&state=expected",
            Some("cpmesh_oidc_state="),
        ),
    ] {
        let mut req = request("GET", uri);
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        let response = send(&app, req.body(Body::empty()).unwrap()).await;
        assert!(response.status().is_redirection());
        assert!(
            response.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("invalid+state+parameter")
        );
    }
}

#[tokio::test]
async fn public_endpoints_do_not_require_auth() {
    let app = test_router(test_state(test_config()).await);
    for path in ["/api/downloads", "/api/downloads/current", "/api/plans"] {
        let resp = send(&app, request("GET", path).body(Body::empty()).unwrap()).await;
        // Public does not mean failures should look like an empty catalogue.
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR, "{path}");
        assert!(body_json(resp).await["error"].is_string());
    }
}

#[tokio::test]
async fn update_check_reports_database_failure_instead_of_no_update() {
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
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body_json(resp).await["error"].is_string());
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
    let etag = resp.headers()[header::ETAG].clone();
    assert_eq!(resp.headers()[header::ACCEPT_RANGES], "bytes");
    assert_eq!(body_bytes(resp).await, b"MZ-binary");

    for (range, expected) in [
        ("bytes=3-5", b"bin".as_slice()),
        ("bytes=-3", b"ary".as_slice()),
    ] {
        let response = send(
            &app,
            request("GET", "/api/downloads/cpmesh-setup.exe")
                .header(header::RANGE, range)
                .header(header::IF_RANGE, &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "3");
        assert_eq!(body_bytes(response).await, expected);
    }
    let response = send(
        &app,
        request("GET", "/api/downloads/cpmesh-setup.exe")
            .header(header::RANGE, "bytes=99-")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes */9");
    let response = send(
        &app,
        request("GET", "/api/downloads/cpmesh-setup.exe")
            .header(header::IF_NONE_MATCH, &etag)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert!(body_bytes(response).await.is_empty());

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

// ---- Agent tokens: default-deny scope policy ---------------------------------

use crate::oauth::policy::{AGENT_ROUTES, agent_access};
use crate::oauth::{AgentClaims, MCP_CLIENT_ID, Scope, Scopes};
use crate::routes::auth_service::{RefreshResult, RefreshTokenUse, SessionGrant};

/// Every (method, route template) the router registers. axum has no API to list
/// routes, so this reads them from the router's `Debug` output.
fn registered_routes(router: &axum::Router) -> Vec<(Method, String)> {
    let dump = format!("{router:?}");
    let start = dump
        .find("path_router")
        .expect("axum Router Debug format changed");
    let end = dump
        .find("fallback_router")
        .expect("axum Router Debug format changed");
    let dump = &dump[start..end];
    let paths: std::collections::HashMap<&str, &str> =
        regex::Regex::new(r#"RouteId\((\d+)\): "([^"]*)""#)
            .unwrap()
            .captures_iter(dump)
            .map(|c| (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str()))
            .collect();
    let methods = [
        Method::GET,
        Method::HEAD,
        Method::DELETE,
        Method::OPTIONS,
        Method::PATCH,
        Method::POST,
        Method::PUT,
        Method::TRACE,
        Method::CONNECT,
    ];
    let routers = regex::Regex::new(
        r"RouteId\((\d+)\): MethodRouter\(MethodRouter \{ get: (\w+), head: (\w+), delete: (\w+), options: (\w+), patch: (\w+), post: (\w+), put: (\w+), trace: (\w+), connect: (\w+),",
    )
    .unwrap();
    let mut routes = Vec::new();
    let mut seen = 0;
    for c in routers.captures_iter(dump) {
        seen += 1;
        let path = paths[c.get(1).unwrap().as_str()];
        for (i, method) in methods.iter().enumerate() {
            if &c[i + 2] != "None" {
                routes.push((method.clone(), path.to_string()));
            }
        }
    }
    assert_eq!(seen, paths.len(), "axum Router Debug format changed");
    routes
}

/// A request path for a route template, with every parameter filled in.
fn concrete(template: &str) -> String {
    regex::Regex::new(r"\{[^}]+\}")
        .unwrap()
        .replace_all(template, uuid::Uuid::new_v4().to_string())
        .into_owned()
}

fn agent_session(scopes: &[Scope], device: bool) -> SessionGrant {
    SessionGrant::signed_in(uuid::Uuid::new_v4(), true)
        .with_device(device.then(uuid::Uuid::new_v4))
        .with_agent(AgentClaims {
            client_id: MCP_CLIENT_ID,
            scopes: Scopes::of(scopes),
            grant_id: uuid::Uuid::new_v4(),
        })
}

async fn call_as(
    app: &axum::Router,
    method: &Method,
    path: &str,
    token: &str,
) -> axum::http::Response<Body> {
    send(
        app,
        request(method.as_str(), path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

fn insufficient_scope_challenge(resp: &axum::http::Response<Body>) -> Option<String> {
    let challenge = resp.headers().get(header::WWW_AUTHENTICATE)?;
    let challenge = challenge.to_str().unwrap().to_string();
    challenge
        .contains("error=\"insufficient_scope\"")
        .then_some(challenge)
}

#[tokio::test]
async fn agents_are_refused_on_every_route_the_policy_does_not_list() {
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let routes = registered_routes(&app);
    assert!(routes.len() > 75, "{routes:?}");
    for (method, route, _) in AGENT_ROUTES {
        assert!(
            routes.contains(&(method.clone(), route.to_string())),
            "{method} {route} is listed but not registered"
        );
    }

    // Even with every scope and a device, only the listed routes get past the policy
    // (to the session check, which fails here for want of a database).
    let agent = state
        .auth
        .issue_access(&agent_session(&Scope::ALL, true))
        .unwrap();
    let first_party = state
        .auth
        .generate_access_token(uuid::Uuid::new_v4(), Some(uuid::Uuid::new_v4()))
        .unwrap();
    for (method, route) in &routes {
        let path = concrete(route);
        let resp = call_as(&app, method, &path, &agent).await;
        let refused =
            resp.status() == StatusCode::FORBIDDEN && insufficient_scope_challenge(&resp).is_some();
        assert_eq!(
            refused,
            agent_access(method, route).is_none(),
            "agent token on {method} {route}: {}",
            resp.status()
        );

        let resp = call_as(&app, method, &path, &first_party).await;
        assert!(
            insufficient_scope_challenge(&resp).is_none(),
            "first-party token refused on {method} {route}"
        );
    }
}

#[tokio::test]
async fn agents_never_reach_account_admin_or_other_devices_routes() {
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let agent = state
        .auth
        .issue_access(&agent_session(&Scope::ALL, true))
        .unwrap();
    let id = uuid::Uuid::new_v4();
    for (method, path) in [
        (Method::POST, "/api/auth/native-code".to_string()),
        (Method::PUT, "/api/me/password".into()),
        (Method::GET, "/api/me/subscription".into()),
        (Method::GET, "/api/mfa".into()),
        (Method::POST, "/api/mfa/verify".into()),
        (Method::POST, "/api/mfa/totp/setup".into()),
        (Method::GET, "/api/admin/users".into()),
        (Method::GET, "/api/admin/releases".into()),
        (Method::POST, "/api/ws/ticket".into()),
        (Method::DELETE, "/api/clipboard".into()),
        (Method::GET, "/api/group-key".into()),
        (Method::POST, "/api/group-key".into()),
        (Method::GET, "/api/device-approvals/pending".into()),
        (Method::POST, format!("/api/device-approvals/{id}/begin")),
        (Method::GET, format!("/api/device-approvals/{id}/session")),
        (Method::POST, format!("/api/device-approvals/{id}/reveal")),
        (Method::POST, format!("/api/device-approvals/{id}/approve")),
        (Method::POST, format!("/api/device-approvals/{id}/reject")),
        (Method::POST, "/api/auth/refresh".into()),
        (Method::GET, "/api/plans".into()),
        (Method::GET, "/no/such/route".into()),
    ] {
        let resp = call_as(&app, &method, &path, &agent).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(
            insufficient_scope_challenge(&resp).as_deref(),
            Some("Bearer error=\"insufficient_scope\""),
            "{method} {path}"
        );
        let body = body_json(resp).await;
        assert_eq!(body["code"], "insufficient_scope", "{method} {path}");
    }
}

#[tokio::test]
async fn agents_need_a_route_scope_and_a_paired_device() {
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let token = |scopes: &[Scope], device: bool| {
        state
            .auth
            .issue_access(&agent_session(scopes, device))
            .unwrap()
    };
    let entry = format!("/api/clipboard/{}", uuid::Uuid::new_v4());

    let read_only = token(&[Scope::ClipboardRead], true);
    let resp = call_as(&app, &Method::DELETE, &entry, &read_only).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        insufficient_scope_challenge(&resp).as_deref(),
        Some("Bearer error=\"insufficient_scope\", scope=\"clipboard:delete\"")
    );
    assert_eq!(body_json(resp).await["scope"], "clipboard:delete");
    // A route its scope allows gets as far as the session check
    let resp = call_as(&app, &Method::GET, "/api/clipboard", &read_only).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The WebSocket opens with clipboard:read or clipboard:write
    let resp = call_as(
        &app,
        &Method::GET,
        "/ws",
        &token(&[Scope::DevicesManage], true),
    )
    .await;
    assert_eq!(
        insufficient_scope_challenge(&resp).as_deref(),
        Some("Bearer error=\"insufficient_scope\", scope=\"clipboard:read clipboard:write\"")
    );
    let resp = call_as(
        &app,
        &Method::GET,
        "/ws",
        &token(&[Scope::ClipboardWrite], true),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Before its device is registered, an agent can only enroll
    let unpaired = token(&Scope::ALL, false);
    for (method, path) in [
        (Method::GET, "/api/devices"),
        (Method::GET, "/api/group-keys/current"),
        (Method::GET, "/api/clipboard"),
        (Method::GET, "/ws"),
    ] {
        let resp = call_as(&app, &method, path, &unpaired).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method} {path}");
        assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_none());
        assert_eq!(body_json(resp).await["code"], "device_required");
    }
    for (method, path) in [
        (Method::GET, "/api/me"),
        (Method::POST, "/api/devices/challenge"),
        (Method::GET, "/api/device-approvals/me"),
    ] {
        let resp = call_as(&app, &method, path, &unpaired).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
    }
}

#[tokio::test]
async fn agent_refresh_tokens_are_refused_at_the_first_party_endpoint() {
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let session = agent_session(&[Scope::ClipboardRead], true);
    let refresh = state.auth.issue_refresh(&session).unwrap();

    let resp = send(
        &app,
        json_request(
            "POST",
            "/api/auth/refresh",
            serde_json::json!({"refresh_token": refresh}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["code"], "oauth_client");

    // Refused before it was used: it still works at the token endpoint
    let RefreshResult::Ok(_, jti, exp) = state.auth.validate_refresh_token(&refresh) else {
        panic!("agent refresh token rejected");
    };
    assert_eq!(
        state
            .auth
            .consume_refresh_token(&jti, session.user_id, exp)
            .await
            .unwrap(),
        RefreshTokenUse::First
    );
}

#[tokio::test]
async fn websocket_tickets_never_carry_agent_sessions() {
    let app = test_router(test_state(test_config()).await);
    let mut claims = browser_session();
    claims.agent = agent_session(&Scope::ALL, true).agent;
    let ticket = crate::routes::websocket::issue_ticket(claims, client_addr().ip()).await;
    let resp = send(&app, ws_upgrade(&format!("/ws?ticket={ticket}"))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["error"], "invalid or expired ticket");
}

// ---- OAuth authorization server ----------------------------------------------

const LOOPBACK: &str = "http://127.0.0.1:53682/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The parameters of a query string.
fn query_map(query: &str) -> std::collections::HashMap<String, String> {
    let uri: axum::http::Uri = format!("/?{query}").parse().unwrap();
    axum::extract::Query::try_from_uri(&uri).unwrap().0
}

fn location(resp: &axum::http::Response<Body>) -> String {
    resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string()
}

/// The query of a redirect to `LOOPBACK`.
fn loopback_query(resp: &axum::http::Response<Body>) -> std::collections::HashMap<String, String> {
    assert_eq!(resp.status(), StatusCode::FOUND);
    let target = location(resp);
    let query = target
        .strip_prefix(&format!("{LOOPBACK}?"))
        .unwrap_or_else(|| panic!("not a redirect to the client: {target}"));
    query_map(query)
}

fn authorize_uri(params: &[(&str, &str)]) -> String {
    format!(
        "/oauth/authorize?{}",
        crate::oauth::request::query_string(params)
    )
}

fn valid_authorize_params() -> Vec<(&'static str, &'static str)> {
    vec![
        ("response_type", "code"),
        ("client_id", MCP_CLIENT_ID),
        ("redirect_uri", LOOPBACK),
        ("state", "opaque-state_123"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("scope", "clipboard:write clipboard:read"),
        ("agent_name", "Claude Code via cpmesh-mcp on höst"),
    ]
}

fn with(
    params: &[(&'static str, &'static str)],
    name: &str,
    value: Option<&'static str>,
) -> Vec<(&'static str, &'static str)> {
    let mut params: Vec<_> = params.iter().copied().filter(|(n, _)| *n != name).collect();
    if let Some(value) = value {
        params.push((Box::leak(name.to_string().into_boxed_str()), value));
    }
    params
}

fn assert_unframable(resp: &axum::http::Response<Body>, what: &str) {
    let h = resp.headers();
    assert_eq!(h["x-frame-options"], "DENY", "{what}");
    let csp = h["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'"), "{what}: {csp}");
}

fn form_request(uri: &str, params: &[(&str, &str)]) -> axum::http::Request<Body> {
    request("POST", uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(crate::oauth::request::query_string(params)))
        .unwrap()
}

/// An OAuth error response: status, `error`, and the no-store headers checked.
async fn oauth_error(resp: axum::http::Response<Body>) -> (StatusCode, String) {
    let status = resp.status();
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(resp.headers()[header::PRAGMA], "no-cache");
    let body = body_json(resp).await;
    assert!(body["error_description"].is_string(), "{body}");
    (status, body["error"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn oauth_metadata_describes_the_authorization_server() {
    let mut config = test_config();
    config.base_url = "https://cpmesh.test/".into();
    let app = test_router(test_state(config).await);
    let resp = send(
        &app,
        request("GET", "/.well-known/oauth-authorization-server")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let metadata = body_json(resp).await;
    assert_eq!(
        metadata,
        serde_json::json!({
            "issuer": "https://cpmesh.test",
            "authorization_endpoint": "https://cpmesh.test/oauth/authorize",
            "token_endpoint": "https://cpmesh.test/oauth/token",
            "device_authorization_endpoint": "https://cpmesh.test/oauth/device_authorization",
            "revocation_endpoint": "https://cpmesh.test/oauth/revoke",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code"
            ],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [
                "clipboard:read",
                "clipboard:write",
                "clipboard:delete",
                "devices:manage"
            ],
            "authorization_response_iss_parameter_supported": true,
        })
    );

    // Without BASE_URL there is no issuer, so agents cannot sign in
    let mut config = test_config();
    config.base_url = String::new();
    let app = test_router(test_state(config).await);
    let resp = send(
        &app,
        request("GET", "/.well-known/oauth-authorization-server")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        oauth_error(resp).await,
        (StatusCode::INTERNAL_SERVER_ERROR, "server_error".into())
    );
    let resp = send(
        &app,
        request("GET", &authorize_uri(&valid_authorize_params()))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(resp.headers().get(header::LOCATION).is_none());
}

#[tokio::test]
async fn authorize_never_redirects_for_an_unregistered_client_or_redirect_uri() {
    let app = test_router(test_state(test_config()).await);
    let valid = valid_authorize_params();
    for params in [
        with(&valid, "client_id", None),
        with(&valid, "client_id", Some("someone-else")),
        with(&valid, "redirect_uri", None),
        with(
            &valid,
            "redirect_uri",
            Some("http://localhost:53682/callback"),
        ),
        with(
            &valid,
            "redirect_uri",
            Some("https://127.0.0.1:53682/callback"),
        ),
        with(
            &valid,
            "redirect_uri",
            Some("http://127.0.0.1:53682/elsewhere"),
        ),
        with(
            &valid,
            "redirect_uri",
            Some("http://evil@127.0.0.1:53682/callback"),
        ),
        with(
            &valid,
            "redirect_uri",
            Some("http://127.0.0.1:53682/callback#x"),
        ),
        with(
            &valid,
            "redirect_uri",
            Some("https://evil.example/callback"),
        ),
        // Repeated: neither value is trusted
        [
            valid.clone(),
            vec![("redirect_uri", "https://evil.example/callback")],
        ]
        .concat(),
        [valid.clone(), vec![("client_id", MCP_CLIENT_ID)]].concat(),
    ] {
        let resp = send(
            &app,
            request("GET", &authorize_uri(&params))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{params:?}");
        assert!(resp.headers().get(header::LOCATION).is_none(), "{params:?}");
        assert!(
            resp.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert_unframable(&resp, "error page");
        let page = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(page.contains("isn't valid"), "{page}");
        assert!(!page.contains("evil"), "the page reflects no input");
    }
}

#[tokio::test]
async fn authorize_errors_go_back_to_the_client_with_state_and_issuer() {
    let app = test_router(test_state(test_config()).await);
    let valid = valid_authorize_params();
    let long_name: &'static str = Box::leak("a".repeat(101).into_boxed_str());
    for (params, error, state_echoed) in [
        (with(&valid, "state", None), "invalid_request", false),
        (
            with(&valid, "state", Some("bad\tstate")),
            "invalid_request",
            false,
        ),
        (with(&valid, "response_type", None), "invalid_request", true),
        (
            with(&valid, "response_type", Some("token")),
            "unsupported_response_type",
            true,
        ),
        (
            with(&valid, "code_challenge_method", None),
            "invalid_request",
            true,
        ),
        (
            with(&valid, "code_challenge_method", Some("plain")),
            "invalid_request",
            true,
        ),
        (
            with(&valid, "code_challenge", None),
            "invalid_request",
            true,
        ),
        (
            with(&valid, "code_challenge", Some("short")),
            "invalid_request",
            true,
        ),
        (
            with(&valid, "scope", Some("clipboard:read admin")),
            "invalid_scope",
            true,
        ),
        (
            with(&valid, "agent_name", Some(long_name)),
            "invalid_request",
            true,
        ),
        (
            with(&valid, "agent_name", Some("rtl\u{202E}name")),
            "invalid_request",
            true,
        ),
        (
            [valid.clone(), vec![("scope", "clipboard:read")]].concat(),
            "invalid_request",
            true,
        ),
    ] {
        let resp = send(
            &app,
            request("GET", &authorize_uri(&params))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let query = loopback_query(&resp);
        assert_eq!(query["error"], error, "{params:?}");
        assert!(!query["error_description"].is_empty());
        assert_eq!(query["iss"], "https://cpmesh.test");
        assert_eq!(
            query.get("state").map(String::as_str),
            state_echoed.then_some("opaque-state_123"),
            "{params:?}"
        );
        assert!(!query.contains_key("code"));
    }
}

#[tokio::test]
async fn valid_authorization_requests_go_to_the_consent_page() {
    let app = test_router(test_state(test_config()).await);
    let resp = send(
        &app,
        request("GET", &authorize_uri(&valid_authorize_params()))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_unframable(&resp, "redirect");
    let target = location(&resp);
    let query = query_map(target.strip_prefix("/#/authorize?").unwrap());
    let expected: std::collections::HashMap<String, String> = [
        ("client_id", MCP_CLIENT_ID),
        ("redirect_uri", LOOPBACK),
        ("response_type", "code"),
        ("state", "opaque-state_123"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        // Canonical order
        ("scope", "clipboard:read clipboard:write"),
        ("agent_name", "Claude Code via cpmesh-mcp on höst"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert_eq!(query, expected);

    // Without a scope the agent asks for every scope; IPv6 loopback works too
    let params = with(
        &with(&valid_authorize_params(), "scope", None),
        "redirect_uri",
        Some("http://[::1]:1/callback"),
    );
    let resp = send(
        &app,
        request("GET", &authorize_uri(&with(&params, "agent_name", None)))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let target = location(&resp);
    let query = query_map(target.strip_prefix("/#/authorize?").unwrap());
    assert_eq!(
        query["scope"],
        "clipboard:read clipboard:write clipboard:delete devices:manage"
    );
    assert_eq!(query["redirect_uri"], "http://[::1]:1/callback");
    assert!(!query.contains_key("agent_name"));
}

#[tokio::test]
async fn consent_pages_cannot_be_framed() {
    let app = test_router(test_state(test_config()).await);
    for path in [
        "/",
        "/index.html",
        "/activate",
        "/activate?user_code=BCDF-GHJK",
    ] {
        let resp = send(&app, request("GET", path).body(Body::empty()).unwrap()).await;
        assert_unframable(&resp, path);
    }
}

#[tokio::test]
async fn activate_carries_only_well_formed_user_codes() {
    let app = test_router(test_state(test_config()).await);
    for (uri, target) in [
        ("/activate", "/#/activate"),
        (
            "/activate?user_code=BCDF-GHJK",
            "/#/activate?user_code=BCDF-GHJK",
        ),
        (
            "/activate?user_code=bcdf%20ghjk",
            "/#/activate?user_code=BCDF-GHJK",
        ),
        (
            "/activate?user_code=bcdfghjk&x=1",
            "/#/activate?user_code=BCDF-GHJK",
        ),
        ("/activate?user_code=ABCD-EFGH", "/#/activate"),
        ("/activate?user_code=%3Cscript%3E", "/#/activate"),
        ("/activate?user_code=", "/#/activate"),
    ] {
        let resp = send(&app, request("GET", uri).body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::FOUND, "{uri}");
        assert_eq!(location(&resp), target, "{uri}");
    }
}

#[tokio::test]
async fn device_authorization_is_rate_limited_per_address() {
    let state = test_state_with(
        test_config(),
        std::collections::HashMap::from([("oauth_device", 2)]),
    )
    .await;
    let app = test_router(state);
    let start = || {
        form_request(
            "/oauth/device_authorization",
            &[("client_id", MCP_CLIENT_ID)],
        )
    };
    for _ in 0..2 {
        // Gets as far as storing the code (no database here)
        let (status, error) = oauth_error(send(&app, start()).await).await;
        assert_eq!(
            (status, error.as_str()),
            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        );
    }
    let resp = send(&app, start()).await;
    assert!(resp.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(
        oauth_error(resp).await,
        (
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable".into()
        )
    );
}

#[tokio::test]
async fn device_authorization_checks_the_client_scope_and_agent_name() {
    let app = test_router(test_state(test_config()).await);
    for (params, error) in [
        (vec![], "invalid_request"),
        (vec![("client_id", "someone-else")], "invalid_client"),
        (
            vec![("client_id", MCP_CLIENT_ID), ("scope", "everything")],
            "invalid_scope",
        ),
        (
            vec![("client_id", MCP_CLIENT_ID), ("agent_name", "bell\u{7}")],
            "invalid_request",
        ),
    ] {
        let resp = send(&app, form_request("/oauth/device_authorization", &params)).await;
        assert_eq!(
            oauth_error(resp).await,
            (StatusCode::BAD_REQUEST, error.to_string()),
            "{params:?}"
        );
    }
}

#[tokio::test]
async fn the_token_endpoint_answers_with_rfc_6749_errors() {
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let first_party_refresh = state
        .auth
        .generate_refresh_token(uuid::Uuid::new_v4(), None)
        .unwrap();
    let mcp = ("client_id", MCP_CLIENT_ID);
    for (params, error) in [
        (vec![mcp], "invalid_request"),
        (
            vec![mcp, ("grant_type", "password")],
            "unsupported_grant_type",
        ),
        (
            vec![mcp, ("grant_type", "client_credentials")],
            "unsupported_grant_type",
        ),
        (vec![("grant_type", "refresh_token")], "invalid_request"),
        (
            vec![("client_id", "nobody"), ("grant_type", "refresh_token")],
            "invalid_client",
        ),
        (
            vec![mcp, ("grant_type", "refresh_token")],
            "invalid_request",
        ),
        (
            vec![
                mcp,
                ("grant_type", "refresh_token"),
                ("refresh_token", "garbage"),
            ],
            "invalid_grant",
        ),
        // A first-party session never refreshes here
        (
            vec![
                mcp,
                ("grant_type", "refresh_token"),
                ("refresh_token", first_party_refresh.as_str()),
            ],
            "invalid_grant",
        ),
        (
            vec![mcp, ("grant_type", "authorization_code"), ("code", "x")],
            "invalid_request",
        ),
        (
            vec![
                mcp,
                ("grant_type", "authorization_code"),
                ("code", "x"),
                ("redirect_uri", LOOPBACK),
                ("code_verifier", "too-short"),
            ],
            "invalid_request",
        ),
        (
            vec![
                mcp,
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ],
            "invalid_request",
        ),
        (
            vec![
                mcp,
                ("grant_type", "refresh_token"),
                ("grant_type", "refresh_token"),
            ],
            "invalid_request",
        ),
    ] {
        let resp = send(&app, form_request("/oauth/token", &params)).await;
        assert_eq!(
            oauth_error(resp).await,
            (StatusCode::BAD_REQUEST, error.to_string()),
            "{params:?}"
        );
    }

    // Only form bodies
    let resp = send(
        &app,
        json_request(
            "POST",
            "/oauth/token",
            serde_json::json!({"grant_type": "refresh_token", "client_id": MCP_CLIENT_ID}),
        ),
    )
    .await;
    assert_eq!(
        oauth_error(resp).await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
}

#[tokio::test]
async fn revocation_accepts_any_token_but_only_acts_on_the_clients_own() {
    let state = test_state(test_config()).await;
    let app = test_router(state.clone());
    let revoke = |params: Vec<(&str, &str)>| form_request("/oauth/revoke", &params);
    let first_party = state
        .auth
        .generate_access_token(uuid::Uuid::new_v4(), None)
        .unwrap();

    assert_eq!(
        oauth_error(send(&app, revoke(vec![("token", "x")])).await).await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
    assert_eq!(
        oauth_error(send(&app, revoke(vec![("client_id", "nobody"), ("token", "x")])).await).await,
        (StatusCode::BAD_REQUEST, "invalid_client".into())
    );
    assert_eq!(
        oauth_error(send(&app, revoke(vec![("client_id", MCP_CLIENT_ID)])).await).await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
    // Unknown, invalid and first-party tokens change nothing (no database here)
    for token in ["garbage", first_party.as_str()] {
        let resp = send(
            &app,
            revoke(vec![
                ("client_id", MCP_CLIENT_ID),
                ("token", token),
                ("token_type_hint", "refresh_token"),
            ]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        assert!(body_bytes(resp).await.is_empty());
    }
    // An agent's own token reaches its grant, which needs the database
    let agent = state
        .auth
        .issue_refresh(&agent_session(&[Scope::ClipboardRead], false))
        .unwrap();
    let resp = send(
        &app,
        revoke(vec![
            ("client_id", MCP_CLIENT_ID),
            ("token", agent.as_str()),
        ]),
    )
    .await;
    assert_eq!(
        oauth_error(resp).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable".into()
        )
    );
}
