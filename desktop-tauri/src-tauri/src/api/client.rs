use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::proto::models::*;

/// Refresh the access token when it expires within this many seconds.
const REFRESH_MARGIN_SECS: u64 = 60;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Server error ({status}): {message}")]
    Server { status: u16, message: String },
}

/// Durable storage for the session's tokens, so rotated tokens survive restarts.
pub trait TokenPersistence: Send + Sync {
    fn save(&self, access: &str, refresh: &str);
    fn load(&self) -> Option<(String, String)>;
    fn clear(&self);
}

#[derive(Default)]
struct Session {
    access: Option<String>,
    refresh: Option<String>,
}

#[derive(serde::Serialize)]
struct RefreshRequest<'a> {
    refresh_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<&'a str>,
}

/// REST API client for the cpmesh server.
pub struct ApiClient {
    base_url: String,
    client: Client,
    session: Mutex<Session>,
    /// The device this session belongs to; refreshed tokens stay bound to it.
    device_id: Option<String>,
    persistence: Option<Arc<dyn TokenPersistence>>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        ApiClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
            session: Mutex::new(Session::default()),
            device_id: None,
            persistence: None,
        }
    }

    /// Saves tokens rotated by session refreshes to `persistence`.
    pub fn with_persistence(mut self, persistence: Arc<dyn TokenPersistence>) -> Self {
        self.persistence = Some(persistence);
        self
    }

    pub fn set_tokens(&mut self, access: String, refresh: String) {
        *self.session() = Session {
            access: non_empty(access),
            refresh: non_empty(refresh),
        };
    }

    /// Binds refreshed tokens to `device_id`.
    pub fn set_device_id(&mut self, device_id: Option<String>) {
        self.device_id = device_id.filter(|d| !d.is_empty());
    }

    pub fn access_token(&self) -> Option<String> {
        self.session().access.clone()
    }

    pub fn refresh_token(&self) -> Option<String> {
        self.session().refresh.clone()
    }

    /// Whether the client holds a session that can still be refreshed.
    pub fn has_session(&self) -> bool {
        self.session().refresh.is_some()
    }

    fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }

    // === Session ===

    /// Exchanges the refresh token for a new token pair. Returns `Ok(false)` when the
    /// session has ended (revoked, signed out everywhere, or the device was removed)
    /// and the user has to sign in again.
    pub async fn refresh_session(&self) -> Result<bool, ApiError> {
        let Some(refresh) = self.refresh_token() else {
            return Ok(false);
        };
        let resp = self
            .client
            .post(format!("{}/api/auth/refresh", self.base_url))
            .json(&RefreshRequest {
                refresh_token: &refresh,
                device_id: self.device_id.as_deref(),
            })
            .send()
            .await?;

        match resp.status() {
            StatusCode::OK => {
                let pair: AuthResponse = resp.json().await?;
                if let Some(persistence) = &self.persistence {
                    persistence.save(&pair.access_token, &pair.refresh_token);
                }
                *self.session() = Session {
                    access: non_empty(pair.access_token),
                    refresh: non_empty(pair.refresh_token),
                };
                Ok(true)
            }
            // The token was used moments ago, e.g. by a request whose response was lost
            StatusCode::CONFLICT => Ok(self.adopt_rotated_session(&refresh)),
            StatusCode::UNAUTHORIZED => {
                self.end_session();
                Ok(false)
            }
            _ => Err(read_error(resp).await),
        }
    }

    /// Takes over the pair `consumed` was rotated to if it was saved. Otherwise ends
    /// the session: presenting the consumed token again later would look like token
    /// theft to the server and sign the user out everywhere.
    fn adopt_rotated_session(&self, consumed: &str) -> bool {
        if let Some((access, refresh)) = self.persistence.as_ref().and_then(|p| p.load())
            && !refresh.is_empty()
            && refresh != consumed
        {
            *self.session() = Session {
                access: non_empty(access),
                refresh: Some(refresh),
            };
            return true;
        }
        self.end_session();
        false
    }

    /// Forgets the session, in memory and in storage.
    fn end_session(&self) {
        if let Some(persistence) = &self.persistence {
            persistence.clear();
        }
        *self.session() = Session::default();
    }

    /// Refreshes the session when the access token is missing or about to expire.
    async fn refresh_if_expiring(&self) {
        let expiring = self
            .access_token()
            .is_none_or(|token| expires_within(&token, REFRESH_MARGIN_SECS));
        if expiring && self.has_session() {
            // On failure the request goes out anyway, and a 401 triggers another attempt.
            let _ = self.refresh_session().await;
        }
    }

    /// The access token to open a connection with, refreshed first when it is about
    /// to expire or when `force_refresh` is set because the server rejected it.
    /// `None` once the session has ended.
    pub async fn connection_token(&self, force_refresh: bool) -> Option<String> {
        if force_refresh {
            let _ = self.refresh_session().await;
        } else {
            self.refresh_if_expiring().await;
        }
        if !self.has_session() {
            return None;
        }
        self.access_token()
    }

    // === Auth ===

    pub async fn register(&self, req: &RegisterRequest) -> Result<(), ApiError> {
        let resp = self
            .client
            .post(format!("{}/api/auth/register", self.base_url))
            .json(req)
            .send()
            .await?;

        if resp.status() == StatusCode::CREATED {
            Ok(())
        } else {
            Err(read_error(resp).await)
        }
    }

    pub async fn login(
        &mut self,
        username: &str,
        password: &str,
        device_name: &str,
    ) -> Result<AuthResponse, ApiError> {
        let resp = self
            .client
            .post(format!("{}/api/auth/login", self.base_url))
            .json(&LoginRequest {
                username: username.to_string(),
                password: password.to_string(),
                device_name: device_name.to_string(),
            })
            .send()
            .await?;

        if resp.status() == StatusCode::OK {
            let auth: AuthResponse = resp.json().await?;
            self.set_tokens(auth.access_token.clone(), auth.refresh_token.clone());
            Ok(auth)
        } else {
            Err(read_error(resp).await)
        }
    }

    // === Devices ===

    pub async fn register_device(
        &mut self,
        name: &str,
        public_key: Vec<u8>,
        public_key_sig: Option<Vec<u8>>,
        fingerprint: Option<String>,
    ) -> Result<RegisterDeviceResponse, ApiError> {
        let resp =
            self.send_authed(self.request(Method::POST, "/api/devices").json(
                &RegisterDeviceRequest {
                    name: name.to_string(),
                    public_key,
                    public_key_sig,
                    fingerprint,
                },
            ))
            .await?;

        let status = resp.status();
        if status == StatusCode::CREATED || status == StatusCode::OK {
            let result: RegisterDeviceResponse = resp.json().await?;
            self.session().access = non_empty(result.access_token.clone());
            self.set_device_id(Some(result.device.id.clone()));
            Ok(result)
        } else {
            Err(read_error(resp).await)
        }
    }

    pub async fn get_devices(&self) -> Result<Vec<DeviceInfo>, ApiError> {
        self.authed_get_json("/api/devices").await
    }

    pub async fn delete_device(&self, device_id: &str) -> Result<(), ApiError> {
        let resp = self
            .send_authed(self.request(Method::DELETE, &format!("/api/devices/{device_id}")))
            .await?;

        if resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            Err(read_error(resp).await)
        }
    }

    pub async fn get_device_keys(&self) -> Result<DeviceKeysResponse, ApiError> {
        self.authed_get_json("/api/devices/keys").await
    }

    // === Group Key ===

    pub async fn get_group_key(&self) -> Result<Option<GroupKeyResponse>, ApiError> {
        let resp = self
            .send_authed(self.request(Method::GET, "/api/group-key"))
            .await?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json().await?)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(read_error(resp).await),
        }
    }

    pub async fn store_group_keys(&self, keys: &[StoreGroupKeyEntry]) -> Result<(), ApiError> {
        let resp = self
            .send_authed(self.request(Method::POST, "/api/group-key").json(keys))
            .await?;

        if resp.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(read_error(resp).await)
        }
    }

    // === Device Approval ===

    pub async fn get_my_approval_status(&self) -> Result<ApprovalStatusResponse, ApiError> {
        self.authed_get_json("/api/device-approvals/me").await
    }

    pub async fn get_pending_devices(&self) -> Result<Vec<PendingDeviceInfo>, ApiError> {
        self.authed_get_json("/api/device-approvals/pending").await
    }

    pub async fn begin_approval(
        &self,
        pending_device_id: &str,
    ) -> Result<ApprovalSessionResponse, ApiError> {
        let resp = self
            .send_authed(self.request(
                Method::POST,
                &format!("/api/device-approvals/{pending_device_id}/begin"),
            ))
            .await?;
        if resp.status() == StatusCode::OK {
            Ok(resp.json().await?)
        } else {
            Err(read_error(resp).await)
        }
    }

    pub async fn approve_device(
        &self,
        pending_device_id: &str,
        req: &ApproveDeviceRequest,
    ) -> Result<serde_json::Value, ApiError> {
        let resp = self
            .send_authed(
                self.request(
                    Method::POST,
                    &format!("/api/device-approvals/{pending_device_id}/approve"),
                )
                .json(req),
            )
            .await?;
        match resp.status() {
            StatusCode::OK => Ok(resp.json().await?),
            StatusCode::CONFLICT => Err(ApiError::Server {
                status: 409,
                message: "version conflict — retry".to_string(),
            }),
            _ => Err(read_error(resp).await),
        }
    }

    pub async fn reject_device(&self, pending_device_id: &str) -> Result<(), ApiError> {
        let resp = self
            .send_authed(self.request(
                Method::POST,
                &format!("/api/device-approvals/{pending_device_id}/reject"),
            ))
            .await?;
        if resp.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(read_error(resp).await)
        }
    }

    // === Versioned Group Keys ===

    #[allow(dead_code)]
    pub async fn get_current_group_keys(
        &self,
        since_version: Option<i32>,
    ) -> Result<GroupKeysResponse, ApiError> {
        let path = match since_version {
            Some(v) => format!("/api/group-keys/current?since_version={v}"),
            None => "/api/group-keys/current".to_string(),
        };
        let resp = self.send_authed(self.request(Method::GET, &path)).await?;
        match resp.status() {
            StatusCode::OK => Ok(resp.json().await?),
            StatusCode::NOT_FOUND => Err(ApiError::Server {
                status: 404,
                message: "no group keys".to_string(),
            }),
            _ => Err(read_error(resp).await),
        }
    }

    #[allow(dead_code)]
    pub async fn rotate_group_key(
        &self,
        req: &RotateGroupKeyRequest,
    ) -> Result<serde_json::Value, ApiError> {
        let resp = self
            .send_authed(
                self.request(Method::POST, "/api/group-keys/rotate")
                    .json(req),
            )
            .await?;
        match resp.status() {
            StatusCode::OK => Ok(resp.json().await?),
            StatusCode::CONFLICT => Err(ApiError::Server {
                status: 409,
                message: "version conflict — retry".to_string(),
            }),
            _ => Err(read_error(resp).await),
        }
    }

    // === Clipboard ===

    pub async fn get_clipboard_history(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<ClipboardHistoryResponse, ApiError> {
        self.authed_get_json(&format!("/api/clipboard?limit={limit}&offset={offset}"))
            .await
    }

    // === Account ===

    pub async fn change_password(&self, current: &str, new_password: &str) -> Result<(), ApiError> {
        let resp = self
            .send_authed(self.request(Method::PUT, "/api/me/password").json(
                &ChangePasswordRequest {
                    current_password: current.to_string(),
                    new_password: new_password.to_string(),
                },
            ))
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(read_error(resp).await)
        }
    }

    pub async fn get_me(&self) -> Result<crate::commands::UserInfo, ApiError> {
        self.authed_get_json("/api/me").await
    }

    // === Updates ===

    pub async fn check_update(
        &self,
        platform: &str,
        arch: &str,
        current_version: &str,
    ) -> Result<UpdateCheckResponse, ApiError> {
        let resp = self
            .client
            .get(format!(
                "{}/api/updates/check?platform={}&arch={}&version={}",
                self.base_url,
                urlencoding::encode(platform),
                urlencoding::encode(arch),
                urlencoding::encode(current_version),
            ))
            .send()
            .await?;

        if resp.status() == StatusCode::OK {
            Ok(resp.json().await?)
        } else {
            Err(read_error(resp).await)
        }
    }

    // === Helpers ===

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.base_url))
    }

    /// Sends a request with the session's access token. Refreshes the session first
    /// when the token is about to expire, and once more if the server rejects it.
    async fn send_authed(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, ApiError> {
        self.refresh_if_expiring().await;

        let mut request = builder.build()?;
        self.authorize(&mut request);
        let retry = request.try_clone();
        let resp = self.client.execute(request).await?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        // Rejected before it was processed, so it is safe to send again
        let Some(mut retry) = retry else {
            return Ok(resp);
        };
        if !self.refresh_session().await? {
            return Ok(resp);
        }
        self.authorize(&mut retry);
        Ok(self.client.execute(retry).await?)
    }

    fn authorize(&self, request: &mut reqwest::Request) {
        let Some(token) = self.access_token() else {
            return;
        };
        if let Ok(mut value) = HeaderValue::from_str(&format!("Bearer {token}")) {
            value.set_sensitive(true);
            request.headers_mut().insert(AUTHORIZATION, value);
        }
    }

    async fn authed_get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let resp = self.send_authed(self.request(Method::GET, path)).await?;
        if resp.status() == StatusCode::OK {
            Ok(resp.json().await?)
        } else {
            Err(read_error(resp).await)
        }
    }
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

/// Whether a JWT expires within `margin_secs`. Tokens whose expiry cannot be read
/// count as valid; the server has the final say.
fn expires_within(token: &str, margin_secs: u64) -> bool {
    let Some(exp) = jwt_expiry(token) else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    exp <= now.saturating_add(margin_secs)
}

/// Reads a JWT's `exp` claim without verifying the token.
fn jwt_expiry(token: &str) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct Claims {
        exp: u64,
    }
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice::<Claims>(&bytes).ok().map(|c| c.exp)
}

async fn read_error(resp: reqwest::Response) -> ApiError {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    parse_error_body(status, &body)
}

/// Builds an [`ApiError::Server`] from a response body, preferring the server's
/// `{"error": "..."}` message and falling back to the raw body.
fn parse_error_body(status: u16, body: &str) -> ApiError {
    if let Ok(err_obj) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(msg) = err_obj.get("error").and_then(|v| v.as_str())
    {
        return ApiError::Server {
            status,
            message: msg.to_string(),
        };
    }

    ApiError::Server {
        status,
        message: body.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_strips_trailing_slashes_from_base_url() {
        assert_eq!(
            ApiClient::new("https://cpmesh.example/").base_url,
            "https://cpmesh.example"
        );
        assert_eq!(
            ApiClient::new("https://cpmesh.example///").base_url,
            "https://cpmesh.example"
        );
        assert_eq!(
            ApiClient::new("http://localhost:8080").base_url,
            "http://localhost:8080"
        );
    }

    #[test]
    fn tokens_start_empty_and_can_be_set() {
        let mut client = ApiClient::new("https://cpmesh.example");
        assert_eq!(client.access_token(), None);
        assert_eq!(client.refresh_token(), None);
        assert!(!client.has_session());
        client.set_tokens("acc".into(), "ref".into());
        assert_eq!(client.access_token().as_deref(), Some("acc"));
        assert_eq!(client.refresh_token().as_deref(), Some("ref"));
        assert!(client.has_session());

        // Empty strings (nothing stored) are no session at all
        client.set_tokens(String::new(), String::new());
        assert_eq!(client.access_token(), None);
        assert!(!client.has_session());
    }

    #[test]
    fn authorize_adds_bearer_header_only_when_token_present() {
        let mut client = ApiClient::new("https://cpmesh.example");
        let mut req = client.request(Method::GET, "/api/me").build().unwrap();
        client.authorize(&mut req);
        assert_eq!(req.url().as_str(), "https://cpmesh.example/api/me");
        assert!(req.headers().get("authorization").is_none());

        client.set_tokens("tok".into(), "ref".into());
        let mut req = client
            .request(Method::DELETE, "/api/devices/abc")
            .build()
            .unwrap();
        client.authorize(&mut req);
        assert_eq!(req.method(), Method::DELETE);
        assert_eq!(req.url().path(), "/api/devices/abc");
        let value = req.headers().get("authorization").unwrap();
        assert_eq!(value.to_str().unwrap(), "Bearer tok");
        assert!(value.is_sensitive());
    }

    /// A JWT-shaped token expiring at `exp`; only the payload matters to the client.
    fn token_expiring_at(exp: u64) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"user_id":"u","exp":{exp}}}"#));
        format!("eyJhbGciOiJSUzI1NiJ9.{payload}.c2ln")
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn reads_jwt_expiry_without_verifying() {
        assert_eq!(jwt_expiry(&token_expiring_at(1_234)), Some(1_234));
        for garbage in ["", "abc", "a.b.c", "a.!!!.c"] {
            assert_eq!(jwt_expiry(garbage), None, "{garbage}");
        }

        assert!(expires_within(&token_expiring_at(now() - 5), 60));
        assert!(expires_within(&token_expiring_at(now() + 30), 60));
        assert!(!expires_within(&token_expiring_at(now() + 3_600), 60));
        // Unreadable tokens are left to the server to judge
        assert!(!expires_within("opaque-token", 60));
    }

    // ---- session refresh against a scripted HTTP server -----------------------

    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[derive(Debug)]
    struct Recorded {
        method: String,
        path: String,
        authorization: Option<String>,
        body: String,
    }

    /// Serves `responses` in order, one per connection, recording each request.
    async fn serve(responses: Vec<(u16, &'static str)>) -> (String, Arc<Mutex<Vec<Recorded>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let recorded = log.clone();
        tokio::spawn(async move {
            for (status, body) in responses {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut request_line = String::new();
                reader.read_line(&mut request_line).await.unwrap();
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();

                let (mut authorization, mut length) = (None, 0);
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).await.unwrap();
                    let line = line.trim_end();
                    if line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        match name.to_ascii_lowercase().as_str() {
                            "authorization" => authorization = Some(value.trim().to_string()),
                            "content-length" => length = value.trim().parse().unwrap(),
                            _ => {}
                        }
                    }
                }
                let mut body_bytes = vec![0; length];
                reader.read_exact(&mut body_bytes).await.unwrap();
                recorded.lock().unwrap().push(Recorded {
                    method,
                    path,
                    authorization,
                    body: String::from_utf8(body_bytes).unwrap(),
                });

                let response = format!(
                    "HTTP/1.1 {status} Scripted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let mut stream = reader.into_inner();
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.ok();
            }
        });
        (base_url, log)
    }

    #[derive(Default)]
    struct MemoryStore {
        tokens: Mutex<Option<(String, String)>>,
        cleared: AtomicBool,
    }

    impl TokenPersistence for MemoryStore {
        fn save(&self, access: &str, refresh: &str) {
            *self.tokens.lock().unwrap() = Some((access.to_string(), refresh.to_string()));
        }
        fn load(&self) -> Option<(String, String)> {
            self.tokens.lock().unwrap().clone()
        }
        fn clear(&self) {
            *self.tokens.lock().unwrap() = None;
            self.cleared.store(true, Ordering::SeqCst);
        }
    }

    fn client_for(base_url: &str, store: &Arc<MemoryStore>) -> ApiClient {
        let mut client = ApiClient::new(base_url).with_persistence(store.clone());
        client.set_tokens(token_expiring_at(now() + 3_600), "refresh-1".into());
        client.set_device_id(Some("device-1".into()));
        client
    }

    #[tokio::test]
    async fn rejected_request_is_retried_once_with_refreshed_tokens() {
        let (base_url, log) = serve(vec![
            (401, r#"{"error":"invalid or expired token"}"#),
            (
                200,
                r#"{"access_token":"access-2","refresh_token":"refresh-2"}"#,
            ),
            (200, "[]"),
        ])
        .await;
        let store = Arc::new(MemoryStore::default());
        let client = client_for(&base_url, &store);
        let first_token = client.access_token().unwrap();

        assert!(client.get_devices().await.unwrap().is_empty());

        let log = log.lock().unwrap();
        assert_eq!(log.len(), 3, "{log:?}");
        assert_eq!(log[0].path, "/api/devices");
        assert_eq!(
            log[0].authorization.as_deref(),
            Some(format!("Bearer {first_token}").as_str())
        );
        assert_eq!(
            (log[1].method.as_str(), log[1].path.as_str()),
            ("POST", "/api/auth/refresh")
        );
        let refresh_body: serde_json::Value = serde_json::from_str(&log[1].body).unwrap();
        assert_eq!(refresh_body["refresh_token"], "refresh-1");
        assert_eq!(
            refresh_body["device_id"], "device-1",
            "refreshed tokens stay bound"
        );
        assert_eq!(log[2].authorization.as_deref(), Some("Bearer access-2"));

        assert_eq!(client.refresh_token().as_deref(), Some("refresh-2"));
        assert_eq!(
            store.load(),
            Some(("access-2".to_string(), "refresh-2".to_string())),
            "rotated tokens are persisted"
        );
    }

    #[tokio::test]
    async fn expiring_token_is_refreshed_before_connecting() {
        let (base_url, log) = serve(vec![(
            200,
            r#"{"access_token":"access-2","refresh_token":"refresh-2"}"#,
        )])
        .await;
        let store = Arc::new(MemoryStore::default());
        let mut client = client_for(&base_url, &store);
        client.set_tokens(token_expiring_at(now() + 10), "refresh-1".into());

        assert_eq!(
            client.connection_token(false).await.as_deref(),
            Some("access-2")
        );
        assert_eq!(log.lock().unwrap()[0].path, "/api/auth/refresh");
    }

    #[tokio::test]
    async fn revoked_session_ends_and_is_cleared_from_storage() {
        let (base_url, _log) = serve(vec![(
            401,
            r#"{"error":"session compromised, all sessions revoked — please log in again"}"#,
        )])
        .await;
        let store = Arc::new(MemoryStore::default());
        store.save("old-access", "refresh-1");
        let client = client_for(&base_url, &store);

        assert_eq!(client.connection_token(true).await, None);
        assert!(!client.has_session());
        assert!(store.cleared.load(Ordering::SeqCst));
        assert_eq!(store.load(), None);
        // Nothing left to present to the server
        assert!(!client.refresh_session().await.unwrap());
    }

    #[tokio::test]
    async fn concurrent_rotation_adopts_the_pair_another_client_saved() {
        let (base_url, _log) =
            serve(vec![(409, r#"{"error":"refresh token already used"}"#)]).await;
        let store = Arc::new(MemoryStore::default());
        let client = client_for(&base_url, &store);
        // Another app instance sharing the session rotated it first
        store.save("access-other", "refresh-other");

        assert!(client.refresh_session().await.unwrap());
        assert_eq!(client.access_token().as_deref(), Some("access-other"));
        assert_eq!(client.refresh_token().as_deref(), Some("refresh-other"));
    }

    #[tokio::test]
    async fn consumed_refresh_token_is_never_presented_again() {
        let (base_url, log) = serve(vec![(409, r#"{"error":"refresh token already used"}"#)]).await;
        let store = Arc::new(MemoryStore::default());
        let client = client_for(&base_url, &store);
        store.save("access-1", "refresh-1"); // nothing newer was saved

        assert!(!client.refresh_session().await.unwrap());
        assert!(!client.has_session());
        assert!(!client.refresh_session().await.unwrap());
        assert_eq!(log.lock().unwrap().len(), 1, "no second refresh attempt");
        // Not even after a restart
        assert_eq!(store.load(), None);
    }

    #[test]
    fn parse_error_body_prefers_json_error_field() {
        let err = parse_error_body(401, r#"{"error":"invalid credentials"}"#);
        match err {
            ApiError::Server { status, message } => {
                assert_eq!(status, 401);
                assert_eq!(message, "invalid credentials");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_error_body_falls_back_to_raw_body() {
        for body in [
            "plain text failure",
            r#"{"message":"no error key"}"#,
            "",
            "{",
        ] {
            match parse_error_body(500, body) {
                ApiError::Server { status, message } => {
                    assert_eq!(status, 500);
                    assert_eq!(message, body);
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn api_error_display_includes_status_and_message() {
        let err = ApiError::Server {
            status: 409,
            message: "version conflict".into(),
        };
        assert_eq!(err.to_string(), "Server error (409): version conflict");
    }
}
