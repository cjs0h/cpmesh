use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::proto::models::*;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Server error ({status}): {message}")]
    Server { status: u16, message: String },
}

/// REST API client for the cpmesh server.
pub struct ApiClient {
    base_url: String,
    client: Client,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        ApiClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
            access_token: None,
            refresh_token: None,
        }
    }

    pub fn set_tokens(&mut self, access: String, refresh: String) {
        self.access_token = Some(access);
        self.refresh_token = Some(refresh);
    }

    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    // === Auth ===

    pub async fn register(
        &self,
        username: &str,
        email: &str,
        full_name: &str,
        password: &str,
        password_confirm: &str,
        country: Option<&str>,
        mobile: Option<&str>,
    ) -> Result<(), ApiError> {
        let resp = self
            .client
            .post(format!("{}/api/auth/register", self.base_url))
            .json(&RegisterRequest {
                username: username.to_string(),
                password: password.to_string(),
                password_confirm: password_confirm.to_string(),
                email: email.to_string(),
                full_name: full_name.to_string(),
                country: country.map(|s| s.to_string()),
                mobile: mobile.map(|s| s.to_string()),
            })
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
            self.access_token = Some(auth.access_token.clone());
            self.refresh_token = Some(auth.refresh_token.clone());
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
        let resp = self
            .authed_post("/api/devices")
            .json(&RegisterDeviceRequest {
                name: name.to_string(),
                public_key,
                public_key_sig,
                fingerprint,
            })
            .send()
            .await?;

        let status = resp.status();
        if status == StatusCode::CREATED || status == StatusCode::OK {
            let result: RegisterDeviceResponse = resp.json().await?;
            self.access_token = Some(result.access_token.clone());
            Ok(result)
        } else {
            Err(read_error(resp).await)
        }
    }

    pub async fn get_devices(&self) -> Result<Vec<DeviceInfo>, ApiError> {
        let resp = self.authed_get("/api/devices").send().await?;
        if resp.status() == StatusCode::OK {
            let devices: Vec<DeviceInfo> = resp.json().await?;
            Ok(devices)
        } else {
            Err(read_error(resp).await)
        }
    }

    pub async fn delete_device(&self, device_id: &str) -> Result<(), ApiError> {
        let resp = self
            .authed_request(reqwest::Method::DELETE, &format!("/api/devices/{device_id}"))
            .send()
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
        let resp = self.authed_get("/api/group-key").send().await?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json().await?)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(read_error(resp).await),
        }
    }

    pub async fn store_group_keys(&self, keys: &[StoreGroupKeyEntry]) -> Result<(), ApiError> {
        let resp = self
            .authed_post("/api/group-key")
            .json(keys)
            .send()
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

    pub async fn begin_approval(&self, pending_device_id: &str) -> Result<ApprovalSessionResponse, ApiError> {
        let resp = self
            .authed_post(&format!("/api/device-approvals/{pending_device_id}/begin"))
            .send()
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
            .authed_post(&format!("/api/device-approvals/{pending_device_id}/approve"))
            .json(req)
            .send()
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
            .authed_post(&format!("/api/device-approvals/{pending_device_id}/reject"))
            .send()
            .await?;
        if resp.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(read_error(resp).await)
        }
    }

    // === Versioned Group Keys ===

    #[allow(dead_code)]
    pub async fn get_current_group_keys(&self, since_version: Option<i32>) -> Result<GroupKeysResponse, ApiError> {
        let path = match since_version {
            Some(v) => format!("/api/group-keys/current?since_version={v}"),
            None => "/api/group-keys/current".to_string(),
        };
        let resp = self.authed_get(&path).send().await?;
        match resp.status() {
            StatusCode::OK => Ok(resp.json().await?),
            StatusCode::NOT_FOUND => Err(ApiError::Server { status: 404, message: "no group keys".to_string() }),
            _ => Err(read_error(resp).await),
        }
    }

    #[allow(dead_code)]
    pub async fn rotate_group_key(&self, req: &RotateGroupKeyRequest) -> Result<serde_json::Value, ApiError> {
        let resp = self
            .authed_post("/api/group-keys/rotate")
            .json(req)
            .send()
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
        let resp = self
            .authed_get(&format!("/api/clipboard?limit={limit}&offset={offset}"))
            .send()
            .await?;

        if resp.status() == StatusCode::OK {
            Ok(resp.json().await?)
        } else {
            Err(read_error(resp).await)
        }
    }

    // === Account ===

    pub async fn change_password(
        &self,
        current: &str,
        new_password: &str,
    ) -> Result<(), ApiError> {
        let resp = self
            .authed_request(reqwest::Method::PUT, "/api/me/password")
            .json(&ChangePasswordRequest {
                current_password: current.to_string(),
                new_password: new_password.to_string(),
            })
            .send()
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

    pub async fn check_update(&self, platform: &str, arch: &str, current_version: &str) -> Result<UpdateCheckResponse, ApiError> {
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

    fn authed_get(&self, path: &str) -> reqwest::RequestBuilder {
        self.authed_request(reqwest::Method::GET, path)
    }

    fn authed_post(&self, path: &str) -> reqwest::RequestBuilder {
        self.authed_request(reqwest::Method::POST, path)
    }

    fn authed_request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .request(method, format!("{}{path}", self.base_url));
        if let Some(token) = &self.access_token {
            req = req.bearer_auth(token);
        }
        req
    }

    async fn authed_get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let resp = self.authed_get(path).send().await?;
        if resp.status() == StatusCode::OK {
            Ok(resp.json().await?)
        } else {
            Err(read_error(resp).await)
        }
    }
}

async fn read_error(resp: reqwest::Response) -> ApiError {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if let Ok(err_obj) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(msg) = err_obj.get("error").and_then(|v| v.as_str()) {
            return ApiError::Server {
                status,
                message: msg.to_string(),
            };
        }
    }

    ApiError::Server {
        status,
        message: body,
    }
}
