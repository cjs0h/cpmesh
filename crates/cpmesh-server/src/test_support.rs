//! Shared helpers for in-crate unit and router tests.
//!
//! Everything here runs without a database: the pool is created lazily and never
//! connects, so handlers that touch the database observe an error path, while
//! validation, auth, rate limiting, static serving and middleware behave normally.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::config::Config;
use crate::db::Db;
use crate::email::EmailService;
use crate::pii::PiiService;
use crate::routes::auth::PkceCodeStore;
use crate::routes::auth_service::AuthService;
use crate::routes::middleware::build_rate_limiter;
use crate::ws::Hub;
use crate::{AppState, RateLimiters};

/// Key ID used for the generated test signing key.
pub const TEST_KID: &str = "test-key-1";

/// Base64 (32-byte) PII keys usable with [`PiiService::new`].
pub const TEST_PII_MASTER_KEY: &str = "q88dhm/y/vHc80+0LxAr8OFZwMfkPChvdR9UTMztn5I=";
pub const TEST_PII_HMAC_KEY: &str = "/aowWex7ni3uUnazmQk+rn6GPvb9lQFaSNIPlpiRAM0=";

/// A freshly generated RS256 key pair in PEM form.
pub struct TestKeys {
    pub private_pem: String,
    pub public_pem: String,
    /// JSON array in the `JWT_PUBLIC_KEYS_PATH` file format.
    pub public_keys_json: String,
}

/// Generates an RSA key pair (once per test binary; RSA keygen is slow).
pub fn test_keys() -> &'static TestKeys {
    static KEYS: LazyLock<TestKeys> = LazyLock::new(|| generate_rsa_keys(TEST_KID));
    &KEYS
}

/// Generates an independent RSA key pair, e.g. to simulate a foreign signer.
pub fn generate_rsa_keys(kid: &str) -> TestKeys {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::KeyPair as _;

    let key_pair = KeyPair::generate(KeySize::Rsa2048).expect("generate RSA key");
    let private_der = key_pair.as_der().expect("export PKCS#8");
    let public_der = key_pair.public_key().as_der().expect("export SPKI");

    let private_pem = to_pem("PRIVATE KEY", private_der.as_ref());
    let public_pem = to_pem("PUBLIC KEY", public_der.as_ref());
    let public_keys_json = serde_json::json!([{ "kid": kid, "pem": public_pem }]).to_string();

    TestKeys {
        private_pem,
        public_pem,
        public_keys_json,
    }
}

fn to_pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let body: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is ascii"))
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        body.join("\n")
    )
}

/// An [`AuthService`] backed by the shared test keys and no database.
pub fn test_auth_service() -> AuthService {
    let keys = test_keys();
    AuthService::new(TEST_KID, &keys.private_pem, &keys.public_keys_json, None)
        .expect("test auth service")
}

/// A configuration with the test keys referenced and sane defaults.
pub fn test_config() -> Config {
    let mut cfg = Config::from_lookup(|_| None);
    cfg.jwt_active_kid = TEST_KID.to_string();
    cfg.base_url = "https://cpmesh.test".to_string();
    cfg.downloads_dir = String::new();
    cfg
}

/// Builds an [`AppState`] whose database pool is closed, so every query fails
/// immediately with `PoolClosed` instead of attempting a connection.
pub async fn test_state(config: Config) -> Arc<AppState> {
    test_state_with(config, HashMap::new()).await
}

/// Like [`test_state`] but with custom per-route rate limits (requests per minute).
pub async fn test_state_with(config: Config, rate_limits: HashMap<&str, u32>) -> Arc<AppState> {
    let pool = sqlx::PgPool::connect_lazy("postgres://cpmesh:cpmesh@127.0.0.1:1/cpmesh_unused")
        .expect("lazy pool");
    // A closed pool rejects acquisition without connecting (and without sqlx's
    // connection-refused retry/backoff loop).
    pool.close().await;
    assert!(pool.is_closed());

    let pii = if config.pii_master_key.is_empty() {
        None
    } else {
        Some(PiiService::new(&config.pii_master_key, &config.pii_hmac_key).expect("pii"))
    };
    let limit = |name: &str| *rate_limits.get(name).unwrap_or(&1_000);

    Arc::new(AppState {
        db: Db { pool },
        config,
        hub: Hub::new(),
        pii,
        auth: test_auth_service(),
        email: EmailService::disabled(),
        pkce_store: PkceCodeStore::new(),
        rate_limiters: RateLimiters {
            login: build_rate_limiter(limit("login")),
            register: build_rate_limiter(limit("register")),
            refresh: build_rate_limiter(limit("refresh")),
        },
    })
}

/// The full application router over a test state.
pub fn test_router(state: Arc<AppState>) -> Router {
    crate::routes::build_router(state)
}

/// Client address attached to test requests (the server normally supplies it).
pub fn client_addr() -> SocketAddr {
    "203.0.113.10:4242".parse().unwrap()
}

/// Builds a request with the connect-info extension the middleware expects.
pub fn request(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(client_addr()))
}

/// Builds a JSON request body with the right content type.
pub fn json_request(method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
    request(method, uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Sends a request through the router and returns the response.
pub async fn send(router: &Router, req: Request<Body>) -> Response<Body> {
    router.clone().oneshot(req).await.expect("router response")
}

/// Reads the whole response body.
pub async fn body_bytes(resp: Response<Body>) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec()
}

/// Reads the response body as JSON.
pub async fn body_json(resp: Response<Body>) -> serde_json::Value {
    let bytes = body_bytes(resp).await;
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "response body is not JSON ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_valid_pem_and_json() {
        let keys = test_keys();
        assert!(
            keys.private_pem
                .starts_with("-----BEGIN PRIVATE KEY-----\n")
        );
        assert!(
            keys.private_pem
                .trim_end()
                .ends_with("-----END PRIVATE KEY-----")
        );
        assert!(keys.public_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        let parsed: serde_json::Value = serde_json::from_str(&keys.public_keys_json).unwrap();
        assert_eq!(parsed[0]["kid"], TEST_KID);
        assert_eq!(parsed[0]["pem"], keys.public_pem);
    }

    #[test]
    fn pem_lines_are_wrapped_at_64_columns() {
        let pem = to_pem("TEST", &[0u8; 100]);
        for line in pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(line.len() <= 64, "{line}");
        }
    }
}
