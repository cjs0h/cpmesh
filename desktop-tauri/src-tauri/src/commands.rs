use log::{debug, error, info};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager, State};
use tokio::sync::{Mutex, RwLock};

use crate::api::client::{
    ApiClient, ApiError, LoginOutcome, MfaChallenge, MfaMethod, MfaStage, MfaVerified,
};
use crate::config::{AppConfig, TokenStore};
use crate::crypto::entry::EntryContext;
use crate::crypto::exchange::KeyExchange;
use crate::crypto::keys::{KeyPair, derive_approval_code};
use crate::crypto::verify::{KeyVerifier, ReplayGuard};
use crate::device_keys::DeviceKeyStore;
use crate::history::History;
use crate::proto::models::*;
use crate::state::AppState;
use crate::ws::connection::{TokenProvider, WsConnection, WsEvent};
use base64::Engine as _;

/// An API client for `server_url` that keeps rotated tokens in secure storage.
pub(crate) fn api_client(server_url: &str, config_dir: &std::path::Path) -> ApiClient {
    ApiClient::new(server_url).with_persistence(Arc::new(TokenStore::new(config_dir)))
}

/// An API client resuming the session stored in secure storage for `device_id`.
pub(crate) fn restore_api_client(
    server_url: &str,
    config_dir: &std::path::Path,
    device_id: &str,
) -> ApiClient {
    let mut api = api_client(server_url, config_dir);
    let store = TokenStore::new(config_dir);
    api.set_tokens(
        store.load_access_token().ok().flatten().unwrap_or_default(),
        store
            .load_refresh_token()
            .ok()
            .flatten()
            .unwrap_or_default(),
    );
    api.set_device_id(Some(device_id.to_string()));
    api
}

/// Shown when the session can no longer be refreshed.
const SESSION_EXPIRED: &str =
    "Your session has expired. Sign out, then sign in again to resume syncing.";

/// How long the server accepts the ticket for a sign-in's second factor.
const MFA_TICKET_TTL: Duration = Duration::from_secs(10 * 60);

/// Shown when the second factor arrives after the sign-in ended.
const MFA_SIGN_IN_EXPIRED: &str = "Your sign-in expired. Sign in again.";

/// A password sign-in waiting for its second factor. The ticket is kept in memory
/// only: it is used once and expires after [`MFA_TICKET_TTL`].
struct PendingMfaLogin {
    server_url: String,
    device_name: String,
    mfa_token: String,
    /// Taken before the password was sent, so it never outlives the server's ticket.
    started: Instant,
}

impl PendingMfaLogin {
    fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) >= MFA_TICKET_TTL
    }
}

/// Shared application state managed by Tauri.
pub struct AppContext {
    pub config: RwLock<AppConfig>,
    pub api: Mutex<ApiClient>,
    pub exchange: Mutex<Option<KeyExchange>>,
    pub ws: Mutex<Option<Arc<WsConnection>>>,
    pub history: Mutex<Option<History>>,
    pub state: RwLock<AppState>,
    pub config_dir: PathBuf,
    pub devices: RwLock<Vec<DeviceInfo>>,
    /// Flag to skip clipboard poll after we write an incoming entry.
    pub skip_clipboard: Arc<AtomicBool>,
    /// Hash of the last content written to clipboard (prevents echo duplicates).
    pub last_clipboard_hash: Arc<tokio::sync::Mutex<[u8; 32]>>,
    /// The sign-in `complete_mfa_login` finishes. Lock after `api` when holding both.
    pending_mfa: Mutex<Option<PendingMfaLogin>>,
    pairing: Mutex<std::collections::HashMap<String, PairingCandidate>>,
    lifecycle: Mutex<()>,
    connect_cancel: Mutex<tokio_util::sync::CancellationToken>,
    generation: AtomicU64,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    history_sync: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pending_push: Mutex<Option<PendingPush>>,
    key_operations: Mutex<()>,
    rotation_pending: AtomicBool,
}

#[derive(Clone)]
struct PairingCandidate {
    peer: DeviceIdentity,
    /// The pending device's certified encryption key, as shown by the relay when
    /// the session began; verified against the pinned identity before wrapping.
    peer_encryption: Option<(Vec<u8>, Vec<u8>)>,
    /// Full 256-bit pairing code over both identity keys.
    fingerprint: String,
    /// Our SAS nonce (approver: committed; pending: submitted after the commitment).
    nonce: Option<[u8; 32]>,
    /// The approver's commitment as first seen by the pending device.
    commit: Option<[u8; 32]>,
    /// Short authentication string, available once both nonces are known.
    sas: Option<String>,
    started: Instant,
    incoming: bool,
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    crate::crypto::encrypt::fill_random(&mut nonce);
    nonce
}

fn nonce32(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "Pairing nonce has the wrong length".to_string())
}

/// Loads this device's long-term keys from the credential store.
fn device_keys(ctx: &AppContext) -> Result<crate::crypto::keys::DeviceKeys, String> {
    DeviceKeyStore::new(&ctx.config_dir).load_or_generate()
}

impl AppContext {
    pub fn new(cfg_dir: PathBuf) -> Self {
        let config = AppConfig::load(&cfg_dir).unwrap_or_default();
        let (api, state) = if config.is_configured() {
            (
                restore_api_client(&config.server_url, &cfg_dir, &config.device_id),
                AppState::Disconnected,
            )
        } else {
            (ApiClient::new(&config.server_url), AppState::NotConfigured)
        };

        AppContext {
            config: RwLock::new(config),
            api: Mutex::new(api),
            exchange: Mutex::new(None),
            ws: Mutex::new(None),
            history: Mutex::new(None),
            state: RwLock::new(state),
            config_dir: cfg_dir,
            devices: RwLock::new(vec![]),
            skip_clipboard: Arc::new(AtomicBool::new(false)),
            last_clipboard_hash: Arc::new(tokio::sync::Mutex::new([0u8; 32])),
            pending_mfa: Mutex::new(None),
            pairing: Mutex::new(std::collections::HashMap::new()),
            lifecycle: Mutex::new(()),
            connect_cancel: Mutex::new(tokio_util::sync::CancellationToken::new()),
            generation: AtomicU64::new(0),
            tasks: Mutex::new(Vec::new()),
            history_sync: Mutex::new(None),
            pending_push: Mutex::new(None),
            key_operations: Mutex::new(()),
            rotation_pending: AtomicBool::new(false),
        }
    }

    /// Takes the sign-in waiting for its second factor, unless it has expired.
    async fn take_pending_mfa(&self, now: Instant) -> Option<PendingMfaLogin> {
        self.pending_mfa
            .lock()
            .await
            .take()
            .filter(|pending| !pending.is_expired(now))
    }
}

// === Serializable types for frontend ===

/// What `setup_and_login` led to.
#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginStep {
    /// Signed in, and this device is set up.
    SignedIn,
    VerificationSent,
    /// The password was right; a second factor comes next.
    MfaRequired(MfaPrompt),
}

/// What the sign-in screen asks for next. The ticket itself stays in the backend.
#[derive(Debug, PartialEq, Serialize)]
pub struct MfaPrompt {
    pub stage: MfaStage,
    /// Verify: the methods the account has. Enroll: the methods it can set up.
    pub methods: Vec<String>,
    pub email_code_required: bool,
    pub email_hint: Option<String>,
    pub passkeys_available: bool,
    /// The server's explanation.
    pub message: String,
}

impl From<&MfaChallenge> for MfaPrompt {
    fn from(challenge: &MfaChallenge) -> Self {
        MfaPrompt {
            stage: challenge.stage,
            methods: challenge.methods.clone(),
            email_code_required: challenge.email_code_required,
            email_hint: challenge.email_hint.clone(),
            passkeys_available: challenge.passkeys_available,
            message: challenge.message.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MfaLoginDone {
    /// Set when a recovery code was used: how many unused ones are left.
    pub recovery_codes_remaining: Option<u32>,
}

/// Why the second factor did not finish the sign-in.
#[derive(Debug, PartialEq, Serialize)]
pub struct MfaLoginError {
    pub message: String,
    /// The sign-in cannot continue (expired, locked, suspended, or the device setup
    /// after the code failed): start again with the password.
    pub restart: bool,
}

impl MfaLoginError {
    fn restart(message: impl Into<String>) -> Self {
        MfaLoginError {
            message: message.into(),
            restart: true,
        }
    }

    /// Explains a rejected second factor. A locked (for longer than the ticket lives) or
    /// suspended account ends the sign-in; anything else, usually a mistyped code, can
    /// be retried with the same ticket.
    fn from_api(e: &ApiError) -> Self {
        let (message, restart) = match e {
            ApiError::Server {
                code: Some(code),
                message,
                ..
            } => (
                sentence_case(message),
                matches!(code.as_str(), "mfa_locked" | "account_suspended"),
            ),
            ApiError::Server { status, .. } if *status >= 500 => (
                format!("The server could not check the code (HTTP {status}). Try again."),
                false,
            ),
            ApiError::Server { message, .. } => (sentence_case(message), false),
            ApiError::Http(e) => (format!("Could not reach the server: {e}"), false),
        };
        MfaLoginError { message, restart }
    }
}

/// `message` with its first letter capitalized, to show a server error on its own.
fn sentence_case(message: &str) -> String {
    let mut chars = message.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Structured server errors carry a message written for people; other errors keep
/// their status for troubleshooting.
fn describe_api_error(e: &ApiError) -> String {
    match e {
        ApiError::Server {
            code: Some(_),
            message,
            ..
        } => message.clone(),
        other => other.to_string(),
    }
}

#[derive(Serialize)]
pub struct StatusInfo {
    pub state: AppState,
    pub server_url: String,
    pub device_name: String,
    pub device_count: usize,
    pub online_count: usize,
}

#[derive(Serialize)]
pub struct HistoryEntry {
    pub id: String,
    pub device_name: String,
    pub content_type: String,
    pub preview: String,
    pub size: i64,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct HistoryPage {
    pub entries: Vec<HistoryEntry>,
    pub has_more: bool,
}

fn plain_to_history_entry(e: &PlainEntry) -> HistoryEntry {
    let preview = match &e.content_type {
        ContentType::Text => truncate_preview(&String::from_utf8_lossy(&e.data), 200),
        ContentType::Image => {
            let w = e.metadata.width.unwrap_or(0);
            let h = e.metadata.height.unwrap_or(0);
            format!("Image {}x{}", w, h)
        }
        ContentType::File => e
            .metadata
            .filename
            .clone()
            .unwrap_or_else(|| "Unknown file".into()),
    };

    HistoryEntry {
        id: e.id.clone(),
        device_name: e.device_name.clone(),
        content_type: e.content_type.to_string(),
        preview,
        size: e.metadata.size,
        created_at: e.created_at.to_rfc3339(),
    }
}

/// Truncates `text` to at most `max_chars` characters (never splitting a UTF-8
/// character) and appends an ellipsis when something was cut off.
fn truncate_preview(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        Some((cut, _)) => format!("{}...", &text[..cut]),
        None => text.to_string(),
    }
}

fn notification_body(entry: &PlainEntry) -> String {
    match entry.content_type {
        ContentType::Text => truncate_preview(&String::from_utf8_lossy(&entry.data), 80),
        ContentType::Image => "Image copied".into(),
        ContentType::File => entry
            .metadata
            .filename
            .clone()
            .unwrap_or_else(|| "File received".into()),
    }
}

// === Tauri Commands ===

#[tauri::command]
pub async fn get_status(ctx: State<'_, AppContext>) -> Result<StatusInfo, String> {
    let state = ctx.state.read().await.clone();
    let config = ctx.config.read().await;
    let devices = ctx.devices.read().await;

    Ok(StatusInfo {
        state,
        server_url: config.server_url.clone(),
        device_name: config.device_name.clone(),
        device_count: devices.len(),
        online_count: devices.iter().filter(|d| d.online).count(),
    })
}

#[tauri::command]
pub async fn get_app_state(ctx: State<'_, AppContext>) -> Result<AppState, String> {
    Ok(ctx.state.read().await.clone())
}

// Tauri IPC commands receive each frontend argument as a separate parameter.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn setup_and_login(
    ctx: State<'_, AppContext>,
    server_url: String,
    username: String,
    password: String,
    is_register: bool,
    email: Option<String>,
    full_name: Option<String>,
    password_confirm: Option<String>,
    country: Option<String>,
    mobile: Option<String>,
) -> Result<LoginStep, String> {
    // Validate server URL scheme
    if !server_url.starts_with("https://") && !server_url.starts_with("http://") {
        return Err("Server URL must start with https:// or http://".into());
    }

    let mut api = ctx.api.lock().await;
    *api = api_client(&server_url, &ctx.config_dir);
    // A new sign-in replaces one that was waiting for its second factor
    ctx.pending_mfa.lock().await.take();

    // Register or login
    if is_register {
        let email = email.ok_or("Email is required for registration")?;
        let full_name = full_name.ok_or("Full name is required for registration")?;
        let password_confirm = password_confirm.ok_or("Password confirmation is required")?;
        api.register(&RegisterRequest {
            username: username.clone(),
            password: password.clone(),
            password_confirm,
            email,
            full_name,
            country,
            mobile,
        })
        .await
        .map_err(|e| format!("Registration failed: {e}"))?;
        return Ok(LoginStep::VerificationSent);
    }

    let device_name = crate::fingerprint::auto_device_name();

    let started = Instant::now();
    let outcome = api
        .login(&username, &password, &device_name)
        .await
        .map_err(|e| format!("Login failed: {}", describe_api_error(&e)))?;
    let auth_resp = match outcome {
        LoginOutcome::SignedIn(auth) => auth,
        LoginOutcome::SecondFactor(challenge) => {
            let prompt = MfaPrompt::from(&challenge);
            // Only codes can be confirmed in the app; setting up a second factor needs
            // the web dashboard
            if challenge.stage == MfaStage::Verify {
                *ctx.pending_mfa.lock().await = Some(PendingMfaLogin {
                    server_url,
                    device_name,
                    mfa_token: challenge.mfa_token,
                    started,
                });
            }
            return Ok(LoginStep::MfaRequired(prompt));
        }
    };

    let user_id = auth_resp.user_id.unwrap_or_default();
    finish_sign_in(&ctx, &mut api, server_url, user_id, device_name).await?;
    Ok(LoginStep::SignedIn)
}

/// Finishes the sign-in `setup_and_login` paused for a second factor, then sets up
/// this device like a sign-in without one.
#[tauri::command]
pub async fn complete_mfa_login(
    ctx: State<'_, AppContext>,
    method: MfaMethod,
    code: String,
) -> Result<MfaLoginDone, MfaLoginError> {
    let mut api = ctx.api.lock().await;
    let (pending, verified) = verify_pending_mfa(&ctx, &mut api, method, code.trim()).await?;

    // The ticket is used up, so a failure from here on needs a new sign-in
    let user = api
        .get_me()
        .await
        .map_err(|e| MfaLoginError::restart(format!("Failed to get user info: {e}")))?;
    finish_sign_in(
        &ctx,
        &mut api,
        pending.server_url,
        user.id,
        pending.device_name,
    )
    .await
    .map_err(MfaLoginError::restart)?;

    Ok(MfaLoginDone {
        recovery_codes_remaining: verified.recovery_codes_remaining,
    })
}

/// Forgets a sign-in waiting for its second factor.
#[tauri::command]
pub async fn cancel_mfa_login(ctx: State<'_, AppContext>) -> Result<(), String> {
    ctx.pending_mfa.lock().await.take();
    Ok(())
}

/// Sends the second factor of the paused sign-in. A ticket rejected because of a
/// mistyped code stays pending for another try; otherwise it is used up.
async fn verify_pending_mfa(
    ctx: &AppContext,
    api: &mut ApiClient,
    method: MfaMethod,
    code: &str,
) -> Result<(PendingMfaLogin, MfaVerified), MfaLoginError> {
    let pending = ctx
        .take_pending_mfa(Instant::now())
        .await
        .ok_or_else(|| MfaLoginError::restart(MFA_SIGN_IN_EXPIRED))?;

    *api = api_client(&pending.server_url, &ctx.config_dir);
    match api.verify_mfa(&pending.mfa_token, method, code).await {
        Ok(verified) => Ok((pending, verified)),
        Err(e) => {
            let error = MfaLoginError::from_api(&e);
            if !error.restart {
                *ctx.pending_mfa.lock().await = Some(pending);
            }
            Err(error)
        }
    }
}

/// Registers this device for a freshly signed-in session and saves the account: the
/// device key pair, the group key (once the device is approved), the tokens in secure
/// storage and the config.
async fn finish_sign_in(
    ctx: &AppContext,
    api: &mut ApiClient,
    server_url: String,
    user_id: String,
    device_name: String,
) -> Result<(), String> {
    crate::key_sync::bind_account(
        &ctx.config_dir,
        &server_url,
        &user_id,
        &*ctx.config.read().await,
    )?;
    // Generate stable device fingerprint using the account's user_id
    let fingerprint = crate::fingerprint::generate_device_fingerprint(&user_id).ok();

    // Load or generate the device keys (identity + encryption) from the credential store
    let keys = device_keys(ctx).map_err(|e| format!("Key generation failed: {e}"))?;
    // Register device with fingerprint and the certified encryption key
    let reg_resp = api
        .register_device(&device_name, &keys, fingerprint)
        .await
        .map_err(|e| format!("Device registration failed: {e}"))?;

    let device_id = reg_resp.device.id.clone();
    let device_status = reg_resp.device.status.to_string();

    // Restore first; connect() is the sole network key-initialization path.
    let exchange = crate::key_sync::restore(keys, &ctx.config_dir)?;

    // Save tokens to secure storage
    let token_store = TokenStore::new(&ctx.config_dir);
    token_store
        .save_tokens(
            &api.access_token().unwrap_or_default(),
            &api.refresh_token().unwrap_or_default(),
        )
        .map_err(|e| format!("Token save failed: {e}"))?;

    // Save config (no tokens in plaintext)
    let mut config = ctx.config.write().await;
    config.server_url = server_url;
    config.user_id = user_id;
    config.device_id = device_id;
    config.device_name = device_name;
    config.device_status = device_status;
    config
        .save(&ctx.config_dir)
        .map_err(|e| format!("Config save failed: {e}"))?;
    drop(config);

    // Update state
    *ctx.state.write().await = AppState::Disconnected;
    *ctx.exchange.lock().await = Some(exchange);

    // Initialize history
    let db_path = ctx.config_dir.join("history.db");
    *ctx.history.lock().await = Some(History::open(&db_path, 1000).map_err(|e| e.to_string())?);

    Ok(())
}

#[tauri::command]
pub async fn connect(
    app_handle: tauri::AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<(), String> {
    let _lifecycle = ctx.lifecycle.lock().await;
    if ctx
        .ws
        .lock()
        .await
        .as_ref()
        .is_some_and(|ws| !ws.is_closed())
    {
        return Ok(());
    }
    stop_connection_tasks(&ctx).await;
    let generation = ctx.generation.fetch_add(1, Ordering::SeqCst) + 1;
    let cancel = tokio_util::sync::CancellationToken::new();
    *ctx.connect_cancel.lock().await = cancel.clone();
    let config = ctx.config.read().await.clone();
    if !config.is_configured() {
        return Err("App not configured".into());
    }
    if !ctx.api.lock().await.has_session() {
        return Err(SESSION_EXPIRED.into());
    }

    tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err("Connection cancelled".into()),
        result = prepare_connection(&ctx, &config) => result?,
    }

    // Ensure history is ready
    if ctx.history.lock().await.is_none() {
        let db_path = ctx.config_dir.join("history.db");
        *ctx.history.lock().await = Some(History::open(&db_path, 1000).map_err(|e| e.to_string())?);
    }

    *ctx.state.write().await = AppState::Connecting;
    let _ = app_handle.emit("connection-state-changed", AppState::Connecting);

    // Create the WebSocket connection; each attempt gets a current token from the API client
    let token_handle = app_handle.clone();
    let token_provider: TokenProvider = Arc::new(move |force_refresh| {
        let handle = token_handle.clone();
        Box::pin(async move {
            let ctx = handle.state::<AppContext>();
            let api = ctx.api.lock().await;
            api.connection_token(force_refresh).await
        })
    });
    let fingerprint = crate::fingerprint::generate_device_fingerprint(&config.user_id).ok();
    let (ws_conn, mut event_rx) =
        WsConnection::new(&config.server_url, token_provider, fingerprint);
    let ws_conn = Arc::new(ws_conn);

    // Store connection
    *ctx.ws.lock().await = Some(ws_conn.clone());

    // Start connection in background
    let ws_clone = ws_conn.clone();
    let connection_task = tokio::spawn(async move {
        ws_clone.connect_with_reconnect().await;
    });

    // Event handler task
    let handle = app_handle.clone();
    let event_task = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let ctx = handle.state::<AppContext>();
            if ctx.generation.load(Ordering::SeqCst) != generation {
                break;
            }
            if ctx
                .ws
                .lock()
                .await
                .as_ref()
                .is_some_and(|ws| ws.is_closed())
            {
                *ctx.state.write().await = AppState::Disconnected;
                let _ = handle.emit("connection-state-changed", AppState::Disconnected);
                let _ = handle.emit(
                    "sync-error",
                    "Connection stopped; reconnect to resume from history",
                );
                break;
            }
            match event {
                WsEvent::Connected => {
                    let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                    if let Err(error) = refresh_keys(&ctx).await {
                        if let Some(ws) = ctx.ws.lock().await.as_ref() {
                            ws.close();
                        }
                        let _ = handle.emit("sync-error", error);
                        continue;
                    }
                    if ctx.generation.load(Ordering::SeqCst) != generation {
                        break;
                    }
                    *ctx.state.write().await = AppState::Connected;
                    let _ = handle.emit("connection-state-changed", AppState::Connected);

                    // Refresh device list
                    {
                        let api = ctx.api.lock().await;
                        if let Ok(devices) = api.get_devices().await {
                            *ctx.devices.write().await = devices;
                        }
                    };
                    let mut previous = ctx.history_sync.lock().await;
                    if let Some(task) = previous.take() {
                        task.abort();
                        let _ = task.await;
                    }
                    if ctx.generation.load(Ordering::SeqCst) == generation {
                        let history_handle = handle.clone();
                        *previous = Some(tokio::spawn(async move {
                            if let Err(error) = sync_history(history_handle.state()).await {
                                error!("History catch-up failed: {error}");
                                let _ = history_handle.emit("sync-error", error);
                            } else {
                                let _ = history_handle.emit("history-synced", ());
                            }
                        }));
                    }
                }
                WsEvent::Disconnected => {
                    let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                    let current = ctx.state.read().await.clone();
                    let closed = ctx.ws.lock().await.as_ref().is_none_or(|ws| ws.is_closed());
                    if closed {
                        *ctx.state.write().await = AppState::Disconnected;
                        let _ = handle.emit("connection-state-changed", AppState::Disconnected);
                    } else if current != AppState::Disconnected {
                        *ctx.state.write().await = AppState::Connecting;
                        let _ = handle.emit("connection-state-changed", AppState::Connecting);
                    }
                }
                WsEvent::ClipboardNew(payload) => {
                    let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                    // Authenticate, replay-check and decrypt the entry
                    match authenticate_entry(&ctx, &payload.entry, true).await {
                        Err(reason) => {
                            log::warn!(
                                "Rejected clipboard entry {} from {}: {reason}",
                                payload.entry.id,
                                payload.entry.device_id
                            );
                            let _ = handle.emit(
                                "sync-error",
                                format!("Rejected an unauthenticated clipboard entry: {reason}"),
                            );
                        }
                        Ok(plain) => {
                            // Store in local history
                            if let Some(history) = ctx.history.lock().await.as_ref() {
                                let _ = history.add(&plain);
                            }

                            // Update hash so clipboard monitor won't echo this back
                            {
                                let hash: [u8; 32] = Sha256::digest(&plain.data).into();
                                *ctx.last_clipboard_hash.lock().await = hash;
                            }

                            // Write to local clipboard
                            #[cfg(desktop)]
                            match plain.content_type {
                                ContentType::Text => {
                                    if let Ok(text) = String::from_utf8(plain.data.clone()) {
                                        ctx.skip_clipboard.store(true, Ordering::SeqCst);
                                        let mut clip = arboard::Clipboard::new().ok();
                                        if let Some(ref mut c) = clip {
                                            let _ = c.set_text(&text);
                                        }
                                        let flag = ctx.skip_clipboard.clone();
                                        tokio::spawn(async move {
                                            tokio::time::sleep(std::time::Duration::from_millis(
                                                500,
                                            ))
                                            .await;
                                            flag.store(false, Ordering::SeqCst);
                                        });
                                    }
                                }
                                ContentType::Image => {
                                    let img_data = plain.data.clone();
                                    ctx.skip_clipboard.store(true, Ordering::SeqCst);
                                    let write_ok = tokio::task::spawn_blocking(move || {
                                        set_clipboard_image(&img_data)
                                    })
                                    .await
                                    .unwrap_or(false);

                                    if !write_ok {
                                        error!("Failed to write image to clipboard");
                                    }
                                    let flag = ctx.skip_clipboard.clone();
                                    tokio::spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_millis(500))
                                            .await;
                                        flag.store(false, Ordering::SeqCst);
                                    });
                                }
                                _ => {}
                            }

                            // Write to local clipboard (mobile)
                            #[cfg(not(desktop))]
                            match plain.content_type {
                                ContentType::Text => {
                                    if let Ok(text) = String::from_utf8(plain.data.clone()) {
                                        ctx.skip_clipboard.store(true, Ordering::SeqCst);
                                        use tauri_plugin_clipboard_manager::ClipboardExt;
                                        if let Err(e) = handle.clipboard().write_text(&text) {
                                            error!("Failed to write text to mobile clipboard: {e}");
                                        }
                                        let flag = ctx.skip_clipboard.clone();
                                        tokio::spawn(async move {
                                            tokio::time::sleep(std::time::Duration::from_millis(
                                                500,
                                            ))
                                            .await;
                                            flag.store(false, Ordering::SeqCst);
                                        });
                                    }
                                }
                                _ => {
                                    // Image/file clipboard not supported on mobile yet
                                }
                            }

                            // Send system notification if enabled
                            {
                                let config = ctx.config.read().await;
                                if config.notifications_enabled {
                                    let title = format!("Clipboard from {}", plain.device_name);
                                    let body = notification_body(&plain);
                                    use tauri_plugin_notification::NotificationExt;
                                    let _ = handle
                                        .notification()
                                        .builder()
                                        .title(title)
                                        .body(body)
                                        .show();
                                }
                            }

                            // Emit to frontend
                            let entry = plain_to_history_entry(&plain);
                            let _ = handle.emit("clipboard-new", &entry);
                        }
                    }
                }
                WsEvent::DeviceStatus(payload) => {
                    let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                    let mut devices = ctx.devices.write().await;
                    if let Some(dev) = devices.iter_mut().find(|d| d.id == payload.device_id) {
                        dev.online = payload.online;
                    }
                    let _ = handle.emit("device-status-changed", &payload);
                }
                WsEvent::GroupKeyUpdated | WsEvent::RotationNeeded => {
                    if let Err(error) = refresh_keys(&ctx).await {
                        if let Some(ws) = ctx.ws.lock().await.as_ref() {
                            ws.close();
                        }
                        error!("Key synchronization failed: {error}");
                        let _ = handle.emit("sync-error", error);
                    }
                }
                WsEvent::SessionExpired => {
                    let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                    ctx.ws.lock().await.take();
                    *ctx.state.write().await = AppState::Disconnected;
                    let _ = handle.emit("connection-state-changed", AppState::Disconnected);
                    if ctx.config.read().await.notifications_enabled {
                        use tauri_plugin_notification::NotificationExt;
                        let _ = handle
                            .notification()
                            .builder()
                            .title("cpmesh")
                            .body(SESSION_EXPIRED)
                            .show();
                    }
                }
                WsEvent::Error(msg) => {
                    error!("WS error: {msg}");
                    let _ = handle.emit("sync-error", msg);
                }
            }
        }
    });

    // Clipboard monitor — polls local clipboard and sends changes to server
    let monitor_task = {
        let monitor_handle = app_handle.clone();
        let monitor_ws = ws_conn.clone();
        tokio::spawn(async move {
            #[cfg(desktop)]
            clipboard_monitor(monitor_handle, monitor_ws).await;
            #[cfg(not(desktop))]
            mobile_clipboard_monitor(monitor_handle, monitor_ws).await;
        })
    };
    *ctx.tasks.lock().await = vec![connection_task, event_task, monitor_task];

    Ok(())
}

// === Image clipboard helpers (desktop only) ===

async fn prepare_connection(ctx: &AppContext, config: &AppConfig) -> Result<(), String> {
    crate::key_sync::bind_account(&ctx.config_dir, &config.server_url, &config.user_id, config)?;
    let store = DeviceKeyStore::new(&ctx.config_dir);
    if !store.has_identity() {
        return Err("Device key is missing; restore it or pair a replacement device".into());
    }
    let keys = store.load_or_generate()?;
    {
        let mut api = ctx.api.lock().await;
        api.connection_token(false).await.ok_or(SESSION_EXPIRED)?;
        if !api.is_device_bound(&config.device_id) {
            let registration = api
                .register_device(
                    &config.device_name,
                    &keys,
                    crate::fingerprint::generate_device_fingerprint(&config.user_id).ok(),
                )
                .await
                .map_err(|e| e.to_string())?;
            if registration.device.id != config.device_id {
                return Err(
                    "Device registration changed; sign out and pair this device again".into(),
                );
            }
        }
    }
    if ctx.exchange.lock().await.is_none() {
        *ctx.exchange.lock().await = Some(crate::key_sync::restore(keys, &ctx.config_dir)?);
    }
    {
        // Peers wrap new group keys to the encryption key the relay lists for us.
        let api = ctx.api.lock().await;
        let exchange = ctx.exchange.lock().await;
        crate::key_sync::publish_encryption_key(
            exchange.as_ref().expect("keyring restored"),
            &api,
            &config.device_id,
        )
        .await?;
    }
    refresh_keys(ctx).await?;
    let mut config = ctx.config.write().await;
    config.device_status = "approved".into();
    config.save(&ctx.config_dir).map_err(|e| e.to_string())
}

async fn refresh_keys(ctx: &AppContext) -> Result<(), String> {
    let _operation = ctx.key_operations.lock().await;
    let own_id = ctx.config.read().await.device_id.clone();
    let api = ctx.api.lock().await;
    let mut exchange = ctx.exchange.lock().await;
    if exchange.is_none() {
        let store = DeviceKeyStore::new(&ctx.config_dir);
        if !store.has_identity() {
            return Err("Device key is missing".into());
        }
        let keys = store.load_or_generate()?;
        *exchange = Some(crate::key_sync::restore(keys, &ctx.config_dir)?);
    }
    let exchange = exchange.as_mut().expect("keyring restored");
    let due = crate::key_sync::synchronize(exchange, &api, &own_id, &ctx.config_dir).await?;
    if due {
        crate::key_sync::rotate(exchange, &api, &own_id, &ctx.config_dir).await?;
    }
    ctx.rotation_pending.store(false, Ordering::SeqCst);
    Ok(())
}

async fn stop_connection_tasks(ctx: &AppContext) {
    if let Some(ws) = ctx.ws.lock().await.take() {
        ws.close();
    }
    if let Some(task) = ctx.history_sync.lock().await.take() {
        task.abort();
        let _ = task.await;
    }
    let tasks = std::mem::take(&mut *ctx.tasks.lock().await);
    for mut task in tasks {
        if tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

#[cfg(desktop)]
enum ClipboardContent {
    Text(String),
    Image {
        rgba: Vec<u8>,
        width: usize,
        height: usize,
        fingerprint: [u8; 32],
    },
    UnchangedImage,
    Empty,
}

#[cfg(desktop)]
static CLIPBOARD_WORKER: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));

#[cfg(desktop)]
struct EncodedImage {
    fingerprint: [u8; 32],
    data: Vec<u8>,
    metadata: Metadata,
    hash: [u8; 32],
}

#[cfg(desktop)]
fn image_fingerprint(rgba: &[u8], width: usize, height: usize) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((width as u64).to_be_bytes());
    hash.update((height as u64).to_be_bytes());
    hash.update(rgba);
    hash.finalize().into()
}

struct PendingPush {
    hash: [u8; 32],
    payload: ClipboardPushPayload,
}

async fn send_local_clipboard(
    ctx: &AppContext,
    ws: &WsConnection,
    content_type: &ContentType,
    data: &[u8],
    metadata: &Metadata,
) -> Result<crate::ws::connection::ClipboardReceipt, String> {
    if ctx.rotation_pending.load(Ordering::SeqCst) {
        return Err("Revocation is pending; clipboard encryption is paused".into());
    }
    if data.len() > content_size_limit(content_type) {
        return Err("Clipboard exceeds the content size limit".into());
    }
    let hash = Sha256::digest(data).into();
    let mut pending = ctx.pending_push.lock().await;
    if pending.as_ref().is_none_or(|p| p.hash != hash) {
        let guard = ctx.exchange.lock().await;
        let exchange = guard.as_ref().ok_or("Encryption not initialized")?;
        let sender_id = ctx.config.read().await.device_id.clone();
        let request_id = uuid::Uuid::new_v4().to_string();
        let sent_at = chrono::Utc::now().timestamp_millis();
        let metadata = serde_json::to_vec(metadata).map_err(|e| e.to_string())?;
        let sealed = crate::crypto::entry::seal_entry(
            exchange,
            exchange.key_pair(),
            &EntryContext {
                key_version: exchange.current_version,
                content_type,
                sender_id: &sender_id,
                request_id: &request_id,
                sent_at,
            },
            data,
            &metadata,
        )
        .map_err(|e| e.to_string())?;
        *pending = Some(PendingPush {
            hash,
            payload: ClipboardPushPayload {
                request_id: Some(request_id),
                content_type: content_type.clone(),
                encrypted_data: sealed.encrypted_data,
                metadata: Some(base64::engine::general_purpose::STANDARD.encode(sealed.metadata)),
                key_version: sealed.key_version,
                sent_at: Some(sent_at),
                sender_signature: Some(sealed.signature),
            },
        });
    }
    let result = ws
        .send_clipboard(
            pending
                .as_ref()
                .expect("pending clipboard prepared")
                .payload
                .clone(),
        )
        .await;
    if result.is_ok() {
        *pending = None;
    } else if result
        .as_ref()
        .err()
        .is_some_and(|e| e.starts_with("rotation_required:"))
    {
        // A correlated rejection is definitive. Unknown outcomes retain the exact
        // ciphertext and request ID so retries cannot duplicate a committed entry.
        *pending = None;
        refresh_keys(ctx).await?;
    }
    result
}

/// Encode raw RGBA bytes to PNG.
#[cfg(desktop)]
fn encode_rgba_to_png(rgba: &[u8], width: u32, height: u32) -> Option<Vec<u8>> {
    use image::{ImageBuffer, RgbaImage};
    use std::io::Cursor;

    let img: RgbaImage = ImageBuffer::from_raw(width, height, rgba.to_vec())?;
    let mut buf = Cursor::new(Vec::new());
    img.write_to(&mut buf, image::ImageFormat::Png).ok()?;
    Some(buf.into_inner())
}

/// Decode PNG bytes and write to the system clipboard as an image.
#[cfg(desktop)]
fn set_clipboard_image(png_bytes: &[u8]) -> bool {
    use image::GenericImageView;
    use std::borrow::Cow;

    let img = match image::load_from_memory(png_bytes) {
        Ok(i) => i,
        Err(_) => return false,
    };
    let rgba = img.to_rgba8();
    let (w, h) = img.dimensions();
    let img_data = arboard::ImageData {
        width: w as usize,
        height: h as usize,
        bytes: Cow::Borrowed(rgba.as_raw()),
    };
    let mut clip = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(_) => return false,
    };
    clip.set_image(img_data).is_ok()
}

/// Polls the local clipboard every 250ms and sends changes to the server.
#[cfg(desktop)]
async fn clipboard_monitor(handle: tauri::AppHandle, ws: Arc<WsConnection>) {
    use std::time::Duration;

    let mut last_hash: [u8; 32] = [0u8; 32];
    let mut encoded_image: Option<EncodedImage> = None;
    let mut interval = tokio::time::interval(Duration::from_millis(250));

    loop {
        interval.tick().await;
        if ws.is_closed() {
            break;
        }

        let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();

        // Stop if disconnected or ws replaced
        let state = ctx.state.read().await.clone();
        if state != AppState::Connected {
            if state == AppState::Disconnected || state == AppState::NotConfigured {
                debug!("Clipboard monitor stopping: state={:?}", state);
                break;
            }
            // Connecting state — keep waiting
            continue;
        }

        // Skip if we just wrote an incoming entry to clipboard
        if ctx.skip_clipboard.load(Ordering::SeqCst) || ctx.rotation_pending.load(Ordering::SeqCst)
        {
            continue;
        }

        // Read current clipboard content (blocking — run in spawn_blocking)
        let previous_image = encoded_image.as_ref().map(|image| image.fingerprint);
        let permit = CLIPBOARD_WORKER
            .clone()
            .acquire_owned()
            .await
            .expect("clipboard worker stays open");
        let read = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut c = match arboard::Clipboard::new() {
                Ok(c) => c,
                Err(_) => return ClipboardContent::Empty,
            };
            // Try text first
            if let Ok(text) = c.get_text()
                && !text.is_empty()
            {
                return ClipboardContent::Text(text);
            }
            // Try image
            if let Ok(img) = c.get_image() {
                let fingerprint = image_fingerprint(&img.bytes, img.width, img.height);
                if previous_image == Some(fingerprint) {
                    return ClipboardContent::UnchangedImage;
                }
                return ClipboardContent::Image {
                    rgba: img.bytes.into_owned(),
                    width: img.width,
                    height: img.height,
                    fingerprint,
                };
            }
            ClipboardContent::Empty
        })
        .await;
        let clip_content = match read {
            Ok(content) => content,
            Err(error) => {
                error!("Clipboard worker failed: {error}");
                continue;
            }
        };
        if ws.is_closed() {
            break;
        }

        let (content_type, data, meta, hash) = match clip_content {
            ClipboardContent::Text(text) => {
                let bytes = text.as_bytes().to_vec();
                let meta = Metadata {
                    size: bytes.len() as i64,
                    mime_type: Some("text/plain".into()),
                    ..Default::default()
                };
                let hash = Sha256::digest(&bytes).into();
                (ContentType::Text, bytes, meta, hash)
            }
            ClipboardContent::Image {
                rgba,
                width,
                height,
                fingerprint,
            } => {
                let permit = CLIPBOARD_WORKER
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("clipboard worker stays open");
                let encoded = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let bytes = encode_rgba_to_png(&rgba, width as u32, height as u32)?;
                    let hash: [u8; 32] = Sha256::digest(&bytes).into();
                    Some((bytes, hash))
                })
                .await;
                let (png_bytes, hash) = match encoded {
                    Ok(Some(result)) => result,
                    other => {
                        error!("Clipboard image encoding failed: {:?}", other.err());
                        continue;
                    }
                };
                let meta = Metadata {
                    size: png_bytes.len() as i64,
                    mime_type: Some("image/png".into()),
                    width: Some(width as i32),
                    height: Some(height as i32),
                    ..Default::default()
                };
                encoded_image = Some(EncodedImage {
                    fingerprint,
                    data: png_bytes.clone(),
                    metadata: meta.clone(),
                    hash,
                });
                (ContentType::Image, png_bytes, meta, hash)
            }
            ClipboardContent::UnchangedImage => {
                let image = encoded_image
                    .as_ref()
                    .expect("unchanged image has cached encoding");
                if image.hash == last_hash {
                    continue;
                }
                (
                    ContentType::Image,
                    image.data.clone(),
                    image.metadata.clone(),
                    image.hash,
                )
            }
            ClipboardContent::Empty => continue,
        };

        if hash == last_hash {
            continue;
        }
        // Also skip if this matches content we just received from another device
        if hash == *ctx.last_clipboard_hash.lock().await {
            last_hash = hash;
            continue;
        }
        let receipt = match send_local_clipboard(&ctx, &ws, &content_type, &data, &meta).await {
            Ok(receipt) => receipt,
            Err(e) => {
                error!("Clipboard persistence failed: {e}");
                let _ = handle.emit("sync-error", e);
                continue;
            }
        };
        last_hash = hash;

        debug!("Sent clipboard {:?} ({} bytes)", content_type, data.len());

        // Also store in local history
        let config = ctx.config.read().await;
        let plain = PlainEntry {
            id: receipt.id,
            device_id: config.device_id.clone(),
            device_name: config.device_name.clone(),
            content_type,
            data,
            metadata: meta,
            created_at: receipt.created_at,
            authenticated: true,
        };
        drop(config);

        if let Some(history) = ctx.history.lock().await.as_ref() {
            let _ = history.add(&plain);
        }

        let entry = plain_to_history_entry(&plain);
        let _ = handle.emit("clipboard-new", &entry);
    }
}

/// Polls the local clipboard on mobile and sends changes to the server.
/// On Android 10+, clipboard can only be read when the app is in the foreground,
/// so this monitor gracefully handles read failures when backgrounded.
#[cfg(not(desktop))]
async fn mobile_clipboard_monitor(handle: tauri::AppHandle, ws: Arc<WsConnection>) {
    use std::time::Duration;
    use tauri_plugin_clipboard_manager::ClipboardExt;

    let mut last_hash: [u8; 32] = [0u8; 32];
    let mut interval = tokio::time::interval(Duration::from_millis(500));

    loop {
        interval.tick().await;
        if ws.is_closed() {
            break;
        }

        let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();

        let state = ctx.state.read().await.clone();
        if state != AppState::Connected {
            if state == AppState::Disconnected || state == AppState::NotConfigured {
                debug!("Mobile clipboard monitor stopping: state={:?}", state);
                break;
            }
            continue;
        }

        if ctx.skip_clipboard.load(Ordering::SeqCst) || ctx.rotation_pending.load(Ordering::SeqCst)
        {
            continue;
        }

        // Read clipboard text — will fail silently when backgrounded on Android 10+
        let text = match handle.clipboard().read_text() {
            Ok(t) => t,
            Err(_) => continue, // expected when app is not in foreground
        };

        if text.is_empty() {
            continue;
        }

        let data = text.as_bytes().to_vec();
        let hash: [u8; 32] = Sha256::digest(&data).into();
        if hash == last_hash {
            continue;
        }
        if hash == *ctx.last_clipboard_hash.lock().await {
            last_hash = hash;
            continue;
        }
        let meta = Metadata {
            size: data.len() as i64,
            mime_type: Some("text/plain".into()),
            ..Default::default()
        };
        let receipt = match send_local_clipboard(&ctx, &ws, &ContentType::Text, &data, &meta).await
        {
            Ok(receipt) => receipt,
            Err(e) => {
                error!("Clipboard persistence failed: {e}");
                let _ = handle.emit("sync-error", e);
                continue;
            }
        };
        last_hash = hash;

        debug!("Sent mobile clipboard text ({} bytes)", data.len());

        // Store in local history
        let config = ctx.config.read().await;
        let plain = PlainEntry {
            id: receipt.id,
            device_id: config.device_id.clone(),
            device_name: config.device_name.clone(),
            content_type: ContentType::Text,
            data,
            metadata: meta,
            created_at: receipt.created_at,
        };
        drop(config);

        if let Some(history) = ctx.history.lock().await.as_ref() {
            let _ = history.add(&plain);
        }

        let entry = plain_to_history_entry(&plain);
        let _ = handle.emit("clipboard-new", &entry);
    }
}

#[tauri::command]
pub async fn disconnect(
    app_handle: tauri::AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<(), String> {
    ctx.connect_cancel.lock().await.cancel();
    ctx.generation.fetch_add(1, Ordering::SeqCst);
    let _lifecycle = ctx.lifecycle.lock().await;
    stop_connection_tasks(&ctx).await;
    *ctx.state.write().await = AppState::Disconnected;
    let _ = app_handle.emit("connection-state-changed", AppState::Disconnected);
    Ok(())
}

#[tauri::command]
pub async fn get_devices(ctx: State<'_, AppContext>) -> Result<Vec<DeviceInfo>, String> {
    let api = ctx.api.lock().await;
    let devices = api.get_devices().await.map_err(|e| e.to_string())?;
    *ctx.devices.write().await = devices.clone();
    Ok(devices)
}

#[tauri::command]
pub async fn remove_device(ctx: State<'_, AppContext>, device_id: String) -> Result<(), String> {
    uuid::Uuid::parse_str(&device_id).map_err(|_| "Invalid device ID")?;
    let deleted = {
        let _operation = ctx.key_operations.lock().await;
        ctx.rotation_pending.store(true, Ordering::SeqCst);
        let mut verifier =
            crate::crypto::verify::KeyVerifier::new(&ctx.config_dir).map_err(|e| e.to_string())?;
        verifier.remove_pin(&device_id).map_err(|e| e.to_string())?;
        ctx.api.lock().await.delete_device(&device_id).await
    };
    if let Err(error) = deleted {
        if let Some(ws) = ctx.ws.lock().await.as_ref() {
            ws.close();
        }
        return Err(format!("Removal not confirmed; syncing is paused: {error}"));
    }
    ctx.devices.write().await.retain(|d| d.id != device_id);
    if device_id != ctx.config.read().await.device_id {
        refresh_keys(&ctx).await?;
    }
    Ok(())
}

// === Device Approval Commands ===

#[derive(Serialize)]
pub struct PendingDeviceEntry {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ApprovalSessionInfo {
    pub session_id: String,
    /// Full 64-character pairing code over both identity keys.
    pub approval_code: String,
    /// Eight-digit short authentication string once both nonces are exchanged.
    pub sas: Option<String>,
    pub expires_at: String,
}

#[derive(Serialize)]
pub struct MyApprovalStatusInfo {
    pub status: String,
    pub approval_code: Option<String>,
    pub sas: Option<String>,
    pub session_id: Option<String>,
    pub locally_verified: bool,
}

#[tauri::command]
pub async fn get_pending_devices(
    ctx: State<'_, AppContext>,
) -> Result<Vec<PendingDeviceEntry>, String> {
    let pending = {
        let api = ctx.api.lock().await;
        api.get_pending_devices().await.map_err(|e| e.to_string())?
    };
    Ok(pending
        .iter()
        .map(|d| PendingDeviceEntry {
            id: d.id.clone(),
            name: d.name.clone(),
            created_at: d.created_at.to_rfc3339(),
        })
        .collect())
}

#[tauri::command]
pub async fn begin_device_approval(
    ctx: State<'_, AppContext>,
    pending_device_id: String,
) -> Result<ApprovalSessionInfo, String> {
    // Commit to our SAS nonce before the pending device contributes its own.
    let nonce = random_nonce();
    let commit = sas_commitment(&nonce);
    // Lock API briefly to call begin_approval, then release
    let session = {
        let api = ctx.api.lock().await;
        api.begin_approval(&pending_device_id, &commit)
            .await
            .map_err(|e| e.to_string())?
    };
    if session.pairing_version != PAIRING_VERSION || session.pending_device_id != pending_device_id
    {
        return Err("Update both clients and the server before pairing".into());
    }

    // Cache exactly the identity displayed to the user, not a later relay lookup.
    let kp = device_keys(&ctx)?.identity;
    let pending_pub = KeyPair::parse_public_key(&session.pending_public_key)
        .map_err(|e| format!("Invalid pending device public key: {e}"))?;

    let code = derive_approval_code(&kp.public, &pending_pub);
    ctx.pairing.lock().await.insert(
        session.session_id.clone(),
        PairingCandidate {
            peer: DeviceIdentity {
                id: pending_device_id,
                public_key: session.pending_public_key,
            },
            peer_encryption: session
                .pending_encryption_key
                .zip(session.pending_encryption_key_sig),
            fingerprint: code.clone(),
            nonce: Some(nonce),
            commit: Some(commit),
            sas: None,
            started: Instant::now(),
            incoming: false,
        },
    );

    Ok(ApprovalSessionInfo {
        session_id: session.session_id,
        approval_code: code,
        sas: None,
        expires_at: session.expires_at.to_rfc3339(),
    })
}

/// Approver: once the pending device has contributed its nonce, reveal ours and
/// compute the short authentication string shown on both screens.
#[tauri::command]
pub async fn poll_device_approval(
    ctx: State<'_, AppContext>,
    pending_device_id: String,
    session_id: String,
) -> Result<ApprovalSessionInfo, String> {
    let candidate = ctx
        .pairing
        .lock()
        .await
        .get(&session_id)
        .cloned()
        .ok_or("Pairing session is missing; start again")?;
    if candidate.incoming || candidate.peer.id != pending_device_id {
        return Err("Pairing session changed; start again".into());
    }
    let state = {
        let api = ctx.api.lock().await;
        api.approval_session(&pending_device_id)
            .await
            .map_err(|e| e.to_string())?
    };
    if state.session_id != session_id {
        return Err("Pairing session changed; start again".into());
    }
    let mut sas = candidate.sas.clone();
    if sas.is_none()
        && let (Some(pending_nonce), Some(nonce)) = (&state.pending_nonce, candidate.nonce)
    {
        let pending_nonce = nonce32(pending_nonce)?;
        // Our nonce was committed first; it is only opened after theirs arrived.
        if state.approver_nonce.is_none() {
            let api = ctx.api.lock().await;
            api.reveal_approval_nonce(&pending_device_id, &session_id, &nonce)
                .await
                .map_err(|e| e.to_string())?;
        }
        let own = device_keys(&ctx)?.identity.public_key_bytes();
        let code = sas_code(&nonce, &pending_nonce, &own, &candidate.peer.public_key);
        if let Some(entry) = ctx.pairing.lock().await.get_mut(&session_id) {
            entry.sas = Some(code.clone());
        }
        sas = Some(code);
    }
    Ok(ApprovalSessionInfo {
        session_id,
        approval_code: candidate.fingerprint,
        sas,
        expires_at: state.expires_at.to_rfc3339(),
    })
}

#[tauri::command]
pub async fn confirm_device_approval(
    ctx: State<'_, AppContext>,
    pending_device_id: String,
    session_id: String,
    fingerprint: String,
) -> Result<(), String> {
    let candidate = ctx
        .pairing
        .lock()
        .await
        .get(&session_id)
        .cloned()
        .ok_or("Start pairing again")?;
    if candidate.incoming
        || candidate.peer.id != pending_device_id
        || !code_matches(&candidate, &fingerprint)
        || candidate.started.elapsed() > MFA_TICKET_TTL
    {
        return Err("Pairing code or session changed; start again".into());
    }
    if candidate.sas.is_none() {
        return Err("Wait until both devices show the same 8-digit code".into());
    }
    let _operation = ctx.key_operations.lock().await;
    let own_id = ctx.config.read().await.device_id.clone();
    let api = ctx.api.lock().await;
    let mut guard = ctx.exchange.lock().await;
    let exchange = guard.as_mut().ok_or("Encryption not initialized")?;
    crate::key_sync::synchronize(exchange, &api, &own_id, &ctx.config_dir).await?;
    let mut members =
        crate::key_sync::trusted_members(exchange, &api, &own_id, &ctx.config_dir).await?;
    // The new member's encryption key must be certified by the identity we just
    // compared; fall back to the relay listing only to find that certification.
    let peer_encryption = match candidate.peer_encryption {
        Some(pair) => Some(pair),
        None => api
            .get_device_keys()
            .await
            .map_err(|e| e.to_string())?
            .devices
            .into_iter()
            .find(|d| d.id == pending_device_id)
            .and_then(|d| d.encryption_key.zip(d.encryption_key_sig)),
    };
    members.push(crate::crypto::membership::certified_target(
        candidate.peer,
        peer_encryption.as_ref().map(|(key, _)| key.as_slice()),
        peer_encryption.as_ref().map(|(_, sig)| sig.as_slice()),
    )?);
    let (new_version, wrapped_keys) =
        crate::crypto::membership::stage_rotation(exchange, &own_id, &members)?;
    let result = api
        .approve_device(
            &pending_device_id,
            &ApproveDeviceRequest {
                session_id: session_id.clone(),
                expected_current_version: exchange.current_version,
                new_version,
                wrapped_keys,
            },
        )
        .await;
    // Recover the accepted self-wrap even when the approval response was lost.
    crate::key_sync::synchronize(exchange, &api, &own_id, &ctx.config_dir).await?;
    let verifier =
        crate::crypto::verify::KeyVerifier::new(&ctx.config_dir).map_err(|e| e.to_string())?;
    if exchange.current_version < new_version || !verifier.is_pinned(&pending_device_id) {
        result.map_err(|e| e.to_string())?;
        return Err("Approval was not confirmed; keys were not activated".into());
    }
    drop(guard);
    drop(api);
    ctx.pairing.lock().await.remove(&session_id);
    Ok(())
}

#[tauri::command]
pub async fn reject_pending_device(
    ctx: State<'_, AppContext>,
    pending_device_id: String,
) -> Result<(), String> {
    {
        let api = ctx.api.lock().await;
        api.reject_device(&pending_device_id)
            .await
            .map_err(|e| e.to_string())?;
    }
    info!("Device {} rejected", pending_device_id);
    Ok(())
}

#[tauri::command]
pub async fn get_my_approval_status(
    ctx: State<'_, AppContext>,
) -> Result<MyApprovalStatusInfo, String> {
    let resp = {
        let api = ctx.api.lock().await;
        api.get_my_approval_status()
            .await
            .map_err(|e| e.to_string())?
    };

    if let (Some(session_id), Some(approver_pub_bytes), Some(approver_id)) = (
        &resp.session_id,
        &resp.approver_public_key,
        &resp.approver_device_id,
    ) {
        if resp.pairing_version != PAIRING_VERSION {
            return Err("Update the approving client and server".into());
        }
        let kp = device_keys(&ctx)?.identity;
        let peer = KeyPair::parse_public_key(approver_pub_bytes).map_err(|e| e.to_string())?;
        let fingerprint = derive_approval_code(&kp.public, &peer);
        // Phase 1 (pairing lock only): record the session and the commitment as
        // first seen; the relay cannot swap either later.
        let needs_nonce = {
            let mut candidates = ctx.pairing.lock().await;
            if candidates.get(session_id).is_some_and(|old| {
                old.peer.public_key != *approver_pub_bytes || old.peer.id != *approver_id
            }) {
                return Err("Pairing identity changed; do not approve this session".into());
            }
            let candidate = candidates
                .entry(session_id.clone())
                .or_insert(PairingCandidate {
                    peer: DeviceIdentity {
                        id: approver_id.clone(),
                        public_key: approver_pub_bytes.clone(),
                    },
                    peer_encryption: None,
                    fingerprint,
                    nonce: None,
                    commit: None,
                    sas: None,
                    started: Instant::now(),
                    incoming: true,
                });
            match (&resp.approver_commit, candidate.commit) {
                (Some(commit), None) => candidate.commit = Some(nonce32(commit)?),
                (Some(commit), Some(seen)) if seen != nonce32(commit)? => {
                    return Err("Pairing commitment changed; do not approve this session".into());
                }
                _ => {}
            }
            candidate.commit.is_some() && candidate.nonce.is_none()
        };
        // Phase 2 (API lock only): contribute our nonce, but only after the
        // approver committed to theirs.
        let submitted = if needs_nonce {
            let nonce = random_nonce();
            let api = ctx.api.lock().await;
            api.submit_pending_nonce(session_id, &nonce)
                .await
                .map_err(|e| e.to_string())?;
            Some(nonce)
        } else {
            None
        };
        // Phase 3 (pairing lock only): store the nonce and derive the code once the
        // approver has opened its commitment.
        let mut candidates = ctx.pairing.lock().await;
        if let Some(candidate) = candidates.get_mut(session_id) {
            if let Some(nonce) = submitted
                && candidate.nonce.is_none()
            {
                candidate.nonce = Some(nonce);
            }
            if candidate.sas.is_none()
                && let (Some(approver_nonce), Some(commit), Some(nonce)) =
                    (&resp.approver_nonce, candidate.commit, candidate.nonce)
            {
                let approver_nonce = nonce32(approver_nonce)?;
                if sas_commitment(&approver_nonce) != commit {
                    return Err(
                        "Pairing commitment does not match the revealed nonce; do not approve this session"
                            .into(),
                    );
                }
                candidate.sas = Some(sas_code(
                    &approver_nonce,
                    &nonce,
                    &kp.public_key_bytes(),
                    approver_pub_bytes,
                ));
            }
        }
    }
    let candidates = ctx.pairing.lock().await;
    let candidate = resp
        .session_id
        .as_ref()
        .and_then(|id| candidates.get_key_value(id))
        .or_else(|| {
            candidates
                .iter()
                .filter(|(_, c)| c.incoming)
                .max_by_key(|(_, c)| c.started)
        });
    let own_id = ctx.config.read().await.device_id.clone();
    let verifier =
        crate::crypto::verify::KeyVerifier::new(&ctx.config_dir).map_err(|e| e.to_string())?;
    let locally_verified = if let Some((_, candidate)) = candidate {
        let key =
            KeyPair::parse_public_key(&candidate.peer.public_key).map_err(|e| e.to_string())?;
        verifier.verify_pinned(&candidate.peer.id, &key).is_ok()
    } else {
        verifier.has_peer(&own_id)
    };
    let approval_code = candidate.map(|(_, c)| c.fingerprint.clone());
    let sas = candidate.and_then(|(_, c)| c.sas.clone());
    let session_id = candidate.map(|(id, _)| id.clone());
    Ok(MyApprovalStatusInfo {
        status: resp.status.to_string(),
        approval_code,
        sas,
        session_id,
        locally_verified,
    })
}

/// Accepts either the 8-digit short code or the full 64-character pairing code.
fn code_matches(candidate: &PairingCandidate, entered: &str) -> bool {
    let normalized = normalize_fingerprint(entered);
    if normalized.len() == 8 && normalized.chars().all(|c| c.is_ascii_digit()) {
        return candidate
            .sas
            .as_ref()
            .is_some_and(|sas| normalize_fingerprint(sas) == normalized);
    }
    normalized == candidate.fingerprint
}

fn normalize_fingerprint(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

#[tauri::command]
pub async fn confirm_pairing(
    ctx: State<'_, AppContext>,
    session_id: String,
    fingerprint: String,
) -> Result<(), String> {
    let _operation = ctx.key_operations.lock().await;
    let candidates = ctx.pairing.lock().await;
    let candidate = candidates
        .get(&session_id)
        .ok_or("Pairing session is missing; start again")?;
    if !candidate.incoming
        || !code_matches(candidate, &fingerprint)
        || candidate.started.elapsed() > MFA_TICKET_TTL
    {
        return Err("Pairing code or session expired; start again".into());
    }
    if candidate.sas.is_none() {
        return Err("Wait until both devices show the same 8-digit code".into());
    }
    let key = KeyPair::parse_public_key(&candidate.peer.public_key).map_err(|e| e.to_string())?;
    let mut verifier =
        crate::crypto::verify::KeyVerifier::new(&ctx.config_dir).map_err(|e| e.to_string())?;
    verifier
        .pin_after_approval(&candidate.peer.id, &key)
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct OwnIdentity {
    device_id: String,
    fingerprint: String,
}

#[tauri::command]
pub async fn get_own_identity(ctx: State<'_, AppContext>) -> Result<OwnIdentity, String> {
    let pair = device_keys(&ctx)?.identity;
    Ok(OwnIdentity {
        device_id: ctx.config.read().await.device_id.clone(),
        fingerprint: KeyPair::fingerprint(&pair.public),
    })
}

/// Explicit recovery/migration only: the expected FULL fingerprint must come from
/// the other device itself, not a value copied from the relay's device listing.
#[tauri::command]
pub async fn verify_device_identity(
    ctx: State<'_, AppContext>,
    device_id: String,
    fingerprint: String,
) -> Result<(), String> {
    let generation = ctx.generation.load(Ordering::SeqCst);
    let devices = ctx
        .api
        .lock()
        .await
        .get_device_keys()
        .await
        .map_err(|e| e.to_string())?;
    let peer = devices
        .devices
        .iter()
        .find(|d| d.id == device_id && d.status == DeviceStatus::Approved)
        .ok_or("Approved device not found")?;
    let key = KeyPair::parse_public_key(peer.public_key.as_deref().ok_or("Device key missing")?)
        .map_err(|e| e.to_string())?;
    let expected = normalize_fingerprint(&fingerprint);
    if expected.len() != 64 || expected != normalize_fingerprint(&KeyPair::fingerprint(&key)) {
        return Err("Full fingerprint does not match. Do not trust this device.".into());
    }
    let _operation = ctx.key_operations.lock().await;
    if generation != ctx.generation.load(Ordering::SeqCst) {
        return Err("Session changed; verify again".into());
    }
    let mut verifier =
        crate::crypto::verify::KeyVerifier::new(&ctx.config_dir).map_err(|e| e.to_string())?;
    verifier
        .pin_after_approval(&device_id, &key)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_history(
    ctx: State<'_, AppContext>,
    page: usize,
    page_size: usize,
) -> Result<HistoryPage, String> {
    let history = ctx.history.lock().await;
    let history = history.as_ref().ok_or("History not initialized")?;

    let size = if page_size == 0 { 20 } else { page_size };
    let offset = page * size;
    let entries = history.list(size + 1, offset).map_err(|e| e.to_string())?;
    let has_more = entries.len() > size;
    let entries: Vec<HistoryEntry> = entries
        .iter()
        .take(size)
        .map(plain_to_history_entry)
        .collect();

    Ok(HistoryPage { entries, has_more })
}

#[tauri::command]
pub async fn search_history(
    ctx: State<'_, AppContext>,
    query: String,
) -> Result<Vec<HistoryEntry>, String> {
    let history = ctx.history.lock().await;
    let history = history.as_ref().ok_or("History not initialized")?;

    let entries = history.search(&query, 50).map_err(|e| e.to_string())?;
    Ok(entries.iter().map(plain_to_history_entry).collect())
}

#[tauri::command]
pub async fn copy_entry(
    #[allow(unused)] app_handle: tauri::AppHandle,
    ctx: State<'_, AppContext>,
    entry_id: String,
) -> Result<(), String> {
    let history = ctx.history.lock().await;
    let history = history.as_ref().ok_or("History not initialized")?;

    let entry = history
        .get(&entry_id)
        .map_err(|e| e.to_string())?
        .ok_or("Entry not found")?;

    match entry.content_type {
        ContentType::Text => {
            let text = String::from_utf8(entry.data).map_err(|e| e.to_string())?;
            #[cfg(desktop)]
            {
                let mut clip = arboard::Clipboard::new().map_err(|e| e.to_string())?;
                clip.set_text(&text).map_err(|e| e.to_string())?;
            }
            #[cfg(not(desktop))]
            {
                // On mobile, use tauri clipboard plugin
                use tauri_plugin_clipboard_manager::ClipboardExt;
                app_handle
                    .clipboard()
                    .write_text(&text)
                    .map_err(|e| e.to_string())?;
            }
        }
        ContentType::Image => {
            #[cfg(desktop)]
            {
                let data = entry.data;
                let ok = tokio::task::spawn_blocking(move || set_clipboard_image(&data))
                    .await
                    .map_err(|e| e.to_string())?;
                if !ok {
                    return Err("Failed to write image to clipboard".into());
                }
            }
            #[cfg(not(desktop))]
            {
                return Err("Image clipboard copy is not supported on mobile yet".into());
            }
        }
        _ => {
            return Err("This content type cannot be copied yet".into());
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn delete_entry(ctx: State<'_, AppContext>, entry_id: String) -> Result<(), String> {
    let history = ctx.history.lock().await;
    if let Some(h) = history.as_ref() {
        h.delete(&entry_id).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn clear_history(ctx: State<'_, AppContext>) -> Result<(), String> {
    let history = ctx.history.lock().await;
    if let Some(h) = history.as_ref() {
        h.clear().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Verifies a relay-delivered entry before it is trusted: the sender must be a
/// pinned member whose signature covers the entry's context and both ciphertexts,
/// and live entries must carry a strictly increasing sender clock. Legacy
/// (pre-v3, unsigned) entries are readable for history only, never auto-pasted.
async fn authenticate_entry(
    ctx: &AppContext,
    entry: &ClipboardEntry,
    live: bool,
) -> Result<PlainEntry, String> {
    let metadata_bytes = if entry.metadata.is_empty() {
        Vec::new()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(&entry.metadata)
            .map_err(|e| format!("invalid metadata encoding: {e}"))?
    };
    let plain = |data: Vec<u8>, metadata: Metadata, authenticated: bool| PlainEntry {
        id: entry.id.clone(),
        device_id: entry.device_id.clone(),
        device_name: entry.device_name.clone(),
        content_type: entry.content_type.clone(),
        data,
        metadata,
        created_at: entry.created_at,
        authenticated,
    };

    let (Some(request_id), Some(sent_at), Some(signature)) =
        (&entry.request_id, entry.sent_at, &entry.sender_signature)
    else {
        if live {
            return Err("entry is not signed; update the sending device".into());
        }
        let exchange_guard = ctx.exchange.lock().await;
        let exchange = exchange_guard
            .as_ref()
            .ok_or("Encryption not initialized")?;
        let data = exchange
            .decrypt_payload_legacy(&entry.encrypted_data, entry.key_version)
            .map_err(|e| format!("decrypt failed: {e}"))?;
        let mut metadata = Metadata::default();
        if !metadata_bytes.is_empty()
            && let Ok(bytes) = exchange.decrypt_payload_legacy(&metadata_bytes, entry.key_version)
            && let Ok(m) = serde_json::from_slice(&bytes)
        {
            metadata = m;
        }
        return Ok(plain(data, metadata, false));
    };

    // The sender must be a member we pinned ourselves, not merely one the relay lists.
    let mut verifier = KeyVerifier::new(&ctx.config_dir).map_err(|e| e.to_string())?;
    let sender_key = match verifier.public_key_of(&entry.device_id) {
        Some(key) => key,
        None => {
            // A hash-only pin from before v3: the relay's listing is accepted only
            // when it matches that pin.
            let devices = {
                let api = ctx.api.lock().await;
                api.get_device_keys().await.map_err(|e| e.to_string())?
            };
            let listed = devices
                .devices
                .iter()
                .find(|d| d.id == entry.device_id)
                .and_then(|d| d.public_key.as_deref())
                .ok_or("sender is not a known device")?;
            let key = KeyPair::parse_public_key(listed).map_err(|e| e.to_string())?;
            verifier
                .record_public_key(&entry.device_id, &key)
                .map_err(|e| format!("sender is not a verified member: {e}"))?;
            key
        }
    };
    verifier
        .verify_sender_at(&entry.device_id, &sender_key, entry.key_version)
        .map_err(|e| format!("sender is not a verified member: {e}"))?;

    let context = EntryContext {
        key_version: entry.key_version,
        content_type: &entry.content_type,
        sender_id: &entry.device_id,
        request_id,
        sent_at,
    };
    crate::crypto::entry::verify_entry_signature(
        &sender_key,
        &context,
        &entry.encrypted_data,
        &metadata_bytes,
        signature,
    )
    .map_err(|_| "sender signature is invalid")?;

    if live {
        ReplayGuard::new(&ctx.config_dir)
            .map_err(|e| e.to_string())?
            .accept(&entry.device_id, sent_at)
            .map_err(|e| e.to_string())?;
    }

    let exchange_guard = ctx.exchange.lock().await;
    let exchange = exchange_guard
        .as_ref()
        .ok_or("Encryption not initialized")?;
    let (data, metadata_json) = crate::crypto::entry::open_entry(
        exchange,
        &context,
        &entry.encrypted_data,
        &metadata_bytes,
    )
    .map_err(|e| format!("decrypt failed: {e}"))?;
    let metadata = if metadata_json.is_empty() {
        Metadata::default()
    } else {
        serde_json::from_slice(&metadata_json).unwrap_or_default()
    };
    Ok(plain(data, metadata, true))
}

/// Fetches clipboard history from the server, decrypts, and stores locally.
#[tauri::command]
pub async fn sync_history(ctx: State<'_, AppContext>) -> Result<usize, String> {
    let state = ctx.state.read().await.clone();
    if state != AppState::Connected {
        return Err("Not connected to server".into());
    }

    let mut total_synced: usize = 0;
    let mut offset: u32 = 0;
    const PAGE_SIZE: u32 = 50;
    const MAX_ENTRIES: u32 = 500;

    loop {
        if offset >= MAX_ENTRIES {
            break;
        }

        // Fetch one page — hold api lock only for the request
        let resp = {
            let api = ctx.api.lock().await;
            api.get_clipboard_history(PAGE_SIZE, offset)
                .await
                .map_err(|e| format!("Failed to fetch history: {e}"))?
        };

        // Authenticate and decrypt entries; unverifiable ones are skipped
        let mut plain_entries = Vec::new();
        for entry in &resp.entries {
            match authenticate_entry(&ctx, entry, false).await {
                Ok(plain) => plain_entries.push(plain),
                Err(e) => debug!("Skipping entry {} ({e})", entry.id),
            }
        }

        // Store entries — hold history lock only for insertion
        {
            let history = ctx.history.lock().await;
            let history = history.as_ref().ok_or("History not initialized")?;
            for plain in &plain_entries {
                history
                    .add(plain)
                    .map_err(|e| format!("Failed to store synchronized history: {e}"))?;
                total_synced += 1;
            }
        }

        if !resp.has_more || resp.entries.is_empty() {
            break;
        }
        offset += resp.entries.len() as u32;
    }

    info!("Synced {total_synced} entries from server");
    Ok(total_synced)
}

#[tauri::command]
pub async fn get_config(ctx: State<'_, AppContext>) -> Result<AppConfig, String> {
    Ok(ctx.config.read().await.clone())
}

#[tauri::command]
pub async fn update_config(
    app_handle: tauri::AppHandle,
    ctx: State<'_, AppContext>,
    server_url: Option<String>,
    auto_connect: Option<bool>,
    autostart: Option<bool>,
    notifications_enabled: Option<bool>,
    global_hotkey: Option<String>,
) -> Result<(), String> {
    let mut config = ctx.config.write().await;
    if let Some(v) = server_url {
        if !v.starts_with("https://") && !v.starts_with("http://") {
            return Err("Server URL must start with https:// or http://".into());
        }
        config.server_url = v.clone();
        // Point the API client at the new URL, keeping the stored session
        *ctx.api.lock().await = restore_api_client(&v, &ctx.config_dir, &config.device_id);
    }
    if let Some(v) = auto_connect {
        config.auto_connect = v;
    }
    if let Some(v) = autostart {
        config.autostart = v;
        // Wire to Tauri autostart plugin (desktop only)
        #[cfg(desktop)]
        {
            use tauri_plugin_autostart::ManagerExt;
            let autostart_mgr = app_handle.autolaunch();
            if v {
                let _ = autostart_mgr.enable();
            } else {
                let _ = autostart_mgr.disable();
            }
        }
    }
    if let Some(v) = notifications_enabled {
        config.notifications_enabled = v;
    }
    if let Some(v) = global_hotkey {
        config.global_hotkey = v;
    }
    config.save(&ctx.config_dir).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn change_password(
    app_handle: tauri::AppHandle,
    ctx: State<'_, AppContext>,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    {
        let api = ctx.api.lock().await;
        api.change_password(&current_password, &new_password)
            .await
            .map_err(|e| e.to_string())?;
    }
    logout(app_handle, ctx).await
}

#[tauri::command]
pub async fn logout(
    app_handle: tauri::AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<(), String> {
    ctx.connect_cancel.lock().await.cancel();
    ctx.generation.fetch_add(1, Ordering::SeqCst);
    let _lifecycle = ctx.lifecycle.lock().await;
    stop_connection_tasks(&ctx).await;
    {
        let config = ctx.config.read().await;
        if !config.user_id.is_empty() {
            crate::key_sync::bind_account(
                &ctx.config_dir,
                &config.server_url,
                &config.user_id,
                &config,
            )?;
        }
    }

    // Forget the session in memory first, so no refresh can write it back to storage
    *ctx.api.lock().await = ApiClient::new(&AppConfig::default().server_url);
    ctx.pending_mfa.lock().await.take();
    ctx.pairing.lock().await.clear();
    ctx.pending_push.lock().await.take();

    // Clear tokens from secure storage
    let token_store = TokenStore::new(&ctx.config_dir);
    token_store.clear().map_err(|e| e.to_string())?;

    // Reset config to defaults
    let mut config = ctx.config.write().await;
    *config = AppConfig::default();
    config.save(&ctx.config_dir).map_err(|e| e.to_string())?;

    // Clear state
    *ctx.state.write().await = AppState::NotConfigured;
    *ctx.exchange.lock().await = None;
    *ctx.history.lock().await = None;
    ctx.devices.write().await.clear();

    let _ = app_handle.emit("connection-state-changed", "not_configured");
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateInfo {
    pub update_available: bool,
    pub version: String,
    pub download_url: String,
    pub release_notes: String,
}

#[tauri::command]
pub async fn check_update(ctx: State<'_, AppContext>) -> Result<Option<UpdateInfo>, String> {
    let api = ctx.api.lock().await;
    if api.access_token().is_none() {
        return Ok(None);
    }

    let current_version = env!("CARGO_PKG_VERSION");
    let platform = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else {
        "unknown"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "amd64"
    } else {
        ""
    };

    match api.check_update(platform, arch, current_version).await {
        Ok(resp) => {
            if resp.update_available {
                Ok(Some(UpdateInfo {
                    update_available: true,
                    version: resp.version.unwrap_or_default(),
                    download_url: resp.download_url.unwrap_or_default(),
                    release_notes: resp.release_notes.unwrap_or_default(),
                }))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            info!("Update check failed: {e}");
            Ok(None)
        }
    }
}

/// Largest installer the updater downloads.
const MAX_INSTALLER_BYTES: usize = 512 * 1024 * 1024;
/// Largest signature file the updater downloads.
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

#[tauri::command]
pub async fn download_and_install_update(
    ctx: State<'_, AppContext>,
    download_url: String,
) -> Result<(), String> {
    let server_url = ctx.config.read().await.server_url.clone();
    let installer_url = resolve_download_url(&server_url, &download_url)?;
    let client = reqwest::Client::new();

    info!("Downloading update from: {installer_url}");
    let installer = download(&client, installer_url.clone(), MAX_INSTALLER_BYTES).await?;
    let signature = download(&client, signature_url(&installer_url), MAX_SIGNATURE_BYTES)
        .await
        .map_err(|e| format!("The update's signature could not be downloaded: {e}"))?;

    // Never launch an installer that does not verify against the key built into the app
    let update = crate::updater::verify_update(
        &installer,
        &String::from_utf8_lossy(&signature),
        env!("CARGO_PKG_VERSION"),
        crate::updater::installer_platform(),
    )
    .map_err(|e| format!("The update was not installed: {e}"))?;

    let dir = private_temp_dir().map_err(|e| format!("Failed to save the update: {e}"))?;
    let file_path = dir.join(&update.file_name);
    std::fs::write(&file_path, &installer)
        .map_err(|e| format!("Failed to save the update: {e}"))?;
    info!(
        "Verified update v{} saved to: {}",
        update.version,
        file_path.display()
    );

    // Launch the installer
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        open::that(&file_path).map_err(|e| format!("Failed to open installer: {e}"))?;
    }

    Ok(())
}

/// Resolves an update download URL, which may be relative to the server, to http(s).
fn resolve_download_url(server_url: &str, download_url: &str) -> Result<url::Url, String> {
    let base = url::Url::parse(server_url).map_err(|e| format!("Invalid server URL: {e}"))?;
    let resolved = base
        .join(download_url)
        .map_err(|e| format!("Invalid download URL: {e}"))?;
    match resolved.scheme() {
        "https" | "http" => Ok(resolved),
        other => Err(format!("Unsupported download URL scheme: {other}")),
    }
}

/// Each release installer has its signature next to it, at `<installer URL>.sig`.
fn signature_url(installer_url: &url::Url) -> url::Url {
    let mut url = installer_url.clone();
    url.set_path(&format!("{}.sig", installer_url.path()));
    url
}

/// Downloads `url` into memory, refusing bodies larger than `limit` bytes.
async fn download(
    client: &reqwest::Client,
    url: url::Url,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Download failed with status: {}", resp.status()));
    }
    if resp.content_length().is_some_and(|len| len > limit as u64) {
        return Err("Download is larger than expected".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("Failed to read download: {e}"))?
    {
        if body.len() + chunk.len() > limit {
            return Err("Download is larger than expected".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// A new directory only this user can access, so the verified installer cannot be
/// swapped before it is launched.
fn private_temp_dir() -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("cpmesh-update-{}", uuid::Uuid::new_v4()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir)?;
    Ok(dir)
}

// =============================================================================
// OAuth / Social Login Commands
// =============================================================================

#[derive(Serialize)]
pub struct SocialStatus {
    pub enabled: bool,
    pub provider: String,
}

/// Check if the server supports social/OIDC login.
#[tauri::command]
pub async fn check_social_status(server_url: String) -> Result<SocialStatus, String> {
    let url = format!(
        "{}/api/auth/social/status",
        server_url.trim_end_matches('/')
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Failed to reach server: {e}"))?;

    if !resp.status().is_success() {
        return Ok(SocialStatus {
            enabled: false,
            provider: String::new(),
        });
    }

    #[derive(serde::Deserialize)]
    struct StatusResp {
        enabled: bool,
        provider: String,
    }

    let data: StatusResp = resp
        .json()
        .await
        .map_err(|e| format!("Invalid response: {e}"))?;
    Ok(SocialStatus {
        enabled: data.enabled,
        provider: data.provider,
    })
}

/// Whether the server's web dashboard can hand a sign-in to the app ("Sign in with
/// browser"). Servers with two-factor authentication publish public settings; older
/// ones answer `/api/settings` with the dashboard's page.
#[tauri::command]
pub async fn check_browser_sign_in(server_url: String) -> Result<bool, String> {
    let url = format!("{}/api/settings", server_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Failed to reach server: {e}"))?;
    if !resp.status().is_success() {
        return Ok(false);
    }
    let body = resp.text().await.unwrap_or_default();
    Ok(supports_browser_sign_in(&body))
}

/// Recognizes the public settings of a server with two-factor authentication.
fn supports_browser_sign_in(settings: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(settings)
        .is_ok_and(|v| v.get("mfa_required").is_some_and(|r| r.is_boolean()))
}

/// Complete device setup using tokens obtained from OAuth (via PKCE exchange), or from
/// a sign-in on the web dashboard ("Sign in with browser").
/// Reuses the device registration + group key flow from setup_and_login.
#[tauri::command]
pub async fn setup_with_oauth_tokens(
    ctx: State<'_, AppContext>,
    server_url: String,
    access_token: String,
    refresh_token: String,
) -> Result<(), String> {
    // Validate server URL scheme
    if !server_url.starts_with("https://") && !server_url.starts_with("http://") {
        return Err("Server URL must start with https:// or http://".into());
    }

    let mut api = ctx.api.lock().await;
    *api = api_client(&server_url, &ctx.config_dir);
    api.set_tokens(access_token, refresh_token);
    // The browser finished the sign-in instead of the second-factor prompt
    ctx.pending_mfa.lock().await.take();

    // Get user info to obtain user_id for fingerprinting
    let user_info = api
        .get_me()
        .await
        .map_err(|e| format!("Failed to get user info: {e}"))?;

    let device_name = crate::fingerprint::auto_device_name();
    finish_sign_in(&ctx, &mut api, server_url, user_info.id, device_name).await
}

#[derive(Serialize, serde::Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: String,
    pub email_verified: bool,
    pub auth_provider: String,
    pub is_admin: bool,
    pub avatar_url: Option<String>,
}

/// Fetch the current user's profile from the server.
#[tauri::command]
pub async fn get_user_info(ctx: State<'_, AppContext>) -> Result<UserInfo, String> {
    let api = ctx.api.lock().await;
    api.get_me().await.map_err(|e| e.to_string())
}

#[derive(Serialize, serde::Deserialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: String,
}

/// Exchange a PKCE one-time code for OAuth tokens via the server.
/// This goes through reqwest (Rust HTTP client) to avoid CORS issues
/// that would occur with a direct fetch from the webview.
#[tauri::command]
pub async fn exchange_oauth_code(
    server_url: String,
    code: String,
    code_verifier: String,
) -> Result<OAuthTokens, String> {
    let url = format!(
        "{}/api/auth/social/exchange",
        server_url.trim_end_matches('/')
    );
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .timeout(std::time::Duration::from_secs(15))
        .json(&serde_json::json!({
            "code": code,
            "code_verifier": code_verifier,
        }))
        .send()
        .await
        .map_err(|e| format!("Exchange request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        // Try to extract error message from JSON body
        let msg = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| format!("Exchange failed (HTTP {status})"));
        return Err(msg);
    }

    resp.json::<OAuthTokens>()
        .await
        .map_err(|e| format!("Invalid exchange response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_notifications_do_not_interrupt_later_entries() {
        let mut entry = PlainEntry {
            id: "notification".into(),
            device_id: "device".into(),
            device_name: "Sender".into(),
            content_type: ContentType::Text,
            data: "€".repeat(27).into_bytes(),
            metadata: Metadata::default(),
            created_at: chrono::Utc::now(),
            authenticated: true,
        };
        assert_eq!(notification_body(&entry), "€".repeat(27));
        entry.data = "€".repeat(81).into_bytes();
        assert_eq!(notification_body(&entry), format!("{}...", "€".repeat(80)));
        entry.data = b"the next event still works".to_vec();
        assert_eq!(notification_body(&entry), "the next event still works");
    }

    #[test]
    fn update_urls_resolve_against_the_server_and_must_be_http() {
        let url = resolve_download_url(
            "https://cpmesh.example",
            "https://github.com/cjs0h/cpmesh/releases/download/v1.2.3/cpmesh-1.2.3-macos-universal.dmg",
        )
        .unwrap();
        assert_eq!(url.host_str(), Some("github.com"));

        let url = resolve_download_url(
            "https://cpmesh.example/",
            "/api/downloads/cpmesh-1.2.3-linux-amd64.deb",
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://cpmesh.example/api/downloads/cpmesh-1.2.3-linux-amd64.deb"
        );

        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ftp://host/file",
        ] {
            assert!(
                resolve_download_url("https://cpmesh.example", bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn signature_sits_next_to_the_installer() {
        let installer = url::Url::parse(
            "https://github.com/o/r/releases/download/v1.2.3/cpmesh-1.2.3-windows-amd64-setup.exe",
        )
        .unwrap();
        assert_eq!(
            signature_url(&installer).as_str(),
            "https://github.com/o/r/releases/download/v1.2.3/cpmesh-1.2.3-windows-amd64-setup.exe.sig"
        );
    }

    #[test]
    fn update_directory_is_new_and_private() {
        let a = private_temp_dir().unwrap();
        let b = private_temp_dir().unwrap();
        assert_ne!(a, b);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&a).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        std::fs::remove_dir(a).unwrap();
        std::fs::remove_dir(b).unwrap();
    }
    use chrono::TimeZone;

    fn plain(content_type: ContentType, data: &[u8], metadata: Metadata) -> PlainEntry {
        PlainEntry {
            id: "e1".into(),
            device_id: "d1".into(),
            device_name: "Laptop".into(),
            content_type,
            data: data.to_vec(),
            metadata,
            created_at: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            authenticated: true,
        }
    }

    #[test]
    fn truncate_preview_keeps_short_text_intact() {
        assert_eq!(truncate_preview("hello", 200), "hello");
        assert_eq!(truncate_preview("", 200), "");
        let exactly = "x".repeat(200);
        assert_eq!(truncate_preview(&exactly, 200), exactly);
    }

    #[test]
    fn truncate_preview_adds_ellipsis_and_respects_char_boundaries() {
        let long = "a".repeat(250);
        let out = truncate_preview(&long, 200);
        assert_eq!(out.len(), 203);
        assert!(out.ends_with("..."));

        // Multi-byte characters must not be split (this used to panic on byte slicing)
        let emoji = "😀".repeat(150);
        let out = truncate_preview(&emoji, 200);
        assert_eq!(out, emoji, "150 chars is under the limit");
        let emoji = "😀".repeat(300);
        let out = truncate_preview(&emoji, 200);
        assert_eq!(out.chars().count(), 203);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn history_entry_text_preview_and_fields() {
        let e = plain(
            ContentType::Text,
            b"copied text",
            Metadata {
                size: 11,
                ..Metadata::default()
            },
        );
        let h = plain_to_history_entry(&e);
        assert_eq!(h.id, "e1");
        assert_eq!(h.device_name, "Laptop");
        assert_eq!(h.content_type, "text");
        assert_eq!(h.preview, "copied text");
        assert_eq!(h.size, 11);
        assert_eq!(h.created_at, "2023-11-14T22:13:20+00:00");
    }

    #[test]
    fn history_entry_text_preview_truncates_long_text() {
        let text = "é".repeat(500); // 2 bytes per char; byte slicing at 200 would panic
        let e = plain(ContentType::Text, text.as_bytes(), Metadata::default());
        let h = plain_to_history_entry(&e);
        assert_eq!(h.preview.chars().count(), 203);
        assert!(h.preview.ends_with("..."));
    }

    #[test]
    fn history_entry_image_preview_uses_dimensions() {
        let e = plain(
            ContentType::Image,
            &[0, 1, 2],
            Metadata {
                width: Some(1920),
                height: Some(1080),
                ..Metadata::default()
            },
        );
        assert_eq!(plain_to_history_entry(&e).preview, "Image 1920x1080");
        assert_eq!(plain_to_history_entry(&e).content_type, "image");

        let e = plain(ContentType::Image, &[0], Metadata::default());
        assert_eq!(plain_to_history_entry(&e).preview, "Image 0x0");
    }

    #[test]
    fn history_entry_file_preview_uses_filename() {
        let e = plain(
            ContentType::File,
            &[0],
            Metadata {
                filename: Some("report.pdf".into()),
                ..Metadata::default()
            },
        );
        assert_eq!(plain_to_history_entry(&e).preview, "report.pdf");
        assert_eq!(plain_to_history_entry(&e).content_type, "file");

        let e = plain(ContentType::File, &[0], Metadata::default());
        assert_eq!(plain_to_history_entry(&e).preview, "Unknown file");
    }

    #[cfg(desktop)]
    #[test]
    fn encode_rgba_to_png_roundtrips_pixels() {
        // 2x2 image: red, green / blue, transparent
        let rgba: Vec<u8> = vec![
            255, 0, 0, 255, 0, 255, 0, 255, //
            0, 0, 255, 255, 0, 0, 0, 0,
        ];
        let png = encode_rgba_to_png(&rgba, 2, 2).expect("valid dimensions encode");
        assert!(png.starts_with(&[0x89, b'P', b'N', b'G']));

        let decoded = image::load_from_memory(&png).unwrap().to_rgba8();
        assert_eq!(decoded.dimensions(), (2, 2));
        assert_eq!(decoded.as_raw(), &rgba);
    }

    #[cfg(desktop)]
    #[test]
    fn encode_rgba_to_png_rejects_mismatched_buffer() {
        assert!(encode_rgba_to_png(&[0u8; 3], 2, 2).is_none());
    }

    // ---- two-factor sign-in ----------------------------------------------------

    use crate::api::client::tests::serve;

    fn context() -> (tempfile::TempDir, AppContext) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = AppContext::new(dir.path().to_path_buf());
        (dir, ctx)
    }

    fn pending_login(server_url: &str, started: Instant) -> PendingMfaLogin {
        PendingMfaLogin {
            server_url: server_url.to_string(),
            device_name: "Laptop".into(),
            mfa_token: "ticket-1".into(),
            started,
        }
    }

    fn server_error(status: u16, code: Option<&str>, message: &str) -> ApiError {
        ApiError::Server {
            status,
            code: code.map(str::to_string),
            message: message.into(),
        }
    }

    /// Why `verify_pending_mfa` turned down `code`.
    async fn rejected(ctx: &AppContext, api: &mut ApiClient, code: &str) -> MfaLoginError {
        match verify_pending_mfa(ctx, api, MfaMethod::Totp, code).await {
            Ok(_) => panic!("{code} was accepted"),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn a_paused_sign_in_is_used_once_and_expires_after_ten_minutes() {
        let (_dir, ctx) = context();
        let started = Instant::now();
        let almost_expired = started + MFA_TICKET_TTL - Duration::from_secs(1);

        *ctx.pending_mfa.lock().await = Some(pending_login("https://s", started));
        assert!(ctx.take_pending_mfa(almost_expired).await.is_some());
        assert!(
            ctx.take_pending_mfa(almost_expired).await.is_none(),
            "used once"
        );

        *ctx.pending_mfa.lock().await = Some(pending_login("https://s", started));
        assert!(
            ctx.take_pending_mfa(started + MFA_TICKET_TTL)
                .await
                .is_none()
        );
        assert!(
            ctx.pending_mfa.lock().await.is_none(),
            "an expired ticket is dropped"
        );
    }

    #[tokio::test]
    async fn a_mistyped_code_can_be_retried_but_a_lockout_ends_the_sign_in() {
        let (base_url, log) = serve(vec![
            (401, r#"{"error":"invalid authentication code"}"#),
            (
                429,
                r#"{"error":"Too many failed attempts. Try again in 15 minutes.","code":"mfa_locked"}"#,
            ),
        ])
        .await;
        let (_dir, ctx) = context();
        *ctx.pending_mfa.lock().await = Some(pending_login(&base_url, Instant::now()));
        let mut api = ApiClient::new(&base_url);

        let err = rejected(&ctx, &mut api, "000000").await;
        assert_eq!(
            err,
            MfaLoginError {
                message: "Invalid authentication code".into(),
                restart: false,
            }
        );
        assert!(
            ctx.pending_mfa.lock().await.is_some(),
            "kept for another try"
        );

        let err = rejected(&ctx, &mut api, "111111").await;
        assert_eq!(
            err,
            MfaLoginError {
                message: "Too many failed attempts. Try again in 15 minutes.".into(),
                restart: true,
            }
        );
        assert!(ctx.pending_mfa.lock().await.is_none());

        // Nothing is left to send
        let err = rejected(&ctx, &mut api, "222222").await;
        assert_eq!(err, MfaLoginError::restart(MFA_SIGN_IN_EXPIRED));
        assert_eq!(log.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_accepted_code_uses_up_the_ticket() {
        let (base_url, log) = serve(vec![(
            200,
            r#"{"access_token":"access-1","refresh_token":"refresh-1","recovery_codes_remaining":9}"#,
        )])
        .await;
        let (_dir, ctx) = context();
        *ctx.pending_mfa.lock().await = Some(pending_login(&base_url, Instant::now()));
        let mut api = ApiClient::new("https://elsewhere.example");

        let (pending, verified) =
            verify_pending_mfa(&ctx, &mut api, MfaMethod::Recovery, "abcd-efgh-ijkl-mnop")
                .await
                .unwrap();
        assert_eq!(pending.server_url, base_url);
        assert_eq!(pending.device_name, "Laptop");
        assert_eq!(verified.recovery_codes_remaining, Some(9));
        // The client now talks to the sign-in's server, with the new session
        assert_eq!(api.access_token().as_deref(), Some("access-1"));
        assert!(ctx.pending_mfa.lock().await.is_none());
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_mfa_prompt_leaves_the_ticket_in_the_backend() {
        let challenge = MfaChallenge {
            message: "Two-factor authentication is required.".into(),
            mfa_token: "ticket-1".into(),
            stage: MfaStage::Verify,
            methods: vec!["totp".into(), "recovery".into()],
            email_code_required: false,
            email_hint: None,
            passkeys_available: true,
        };
        assert_eq!(
            serde_json::to_value(LoginStep::MfaRequired(MfaPrompt::from(&challenge))).unwrap(),
            serde_json::json!({
                "status": "mfa_required",
                "stage": "verify",
                "methods": ["totp", "recovery"],
                "email_code_required": false,
                "email_hint": null,
                "passkeys_available": true,
                "message": "Two-factor authentication is required.",
            })
        );
        assert_eq!(
            serde_json::to_value(LoginStep::SignedIn).unwrap(),
            serde_json::json!({ "status": "signed_in" })
        );

        let enroll = MfaChallenge {
            stage: MfaStage::Enroll,
            email_code_required: true,
            email_hint: Some("a***@example.com".into()),
            ..challenge
        };
        let prompt = serde_json::to_value(MfaPrompt::from(&enroll)).unwrap();
        assert_eq!(prompt["stage"], "enroll");
        assert_eq!(prompt["email_code_required"], true);
        assert_eq!(prompt["email_hint"], "a***@example.com");
    }

    #[test]
    fn the_app_sends_codes_but_not_passkeys() {
        assert_eq!(
            serde_json::from_str::<MfaMethod>(r#""totp""#).unwrap(),
            MfaMethod::Totp
        );
        assert_eq!(
            serde_json::from_str::<MfaMethod>(r#""recovery""#).unwrap(),
            MfaMethod::Recovery
        );
        assert!(serde_json::from_str::<MfaMethod>(r#""webauthn""#).is_err());
    }

    #[test]
    fn mfa_errors_say_whether_the_sign_in_can_continue() {
        for (error, message, restart) in [
            (
                server_error(401, None, "invalid authentication code"),
                "Invalid authentication code",
                false,
            ),
            (
                server_error(401, None, "invalid recovery code"),
                "Invalid recovery code",
                false,
            ),
            (
                server_error(429, None, "too many requests, please try again later"),
                "Too many requests, please try again later",
                false,
            ),
            (
                server_error(
                    429,
                    Some("mfa_locked"),
                    "Too many failed attempts. Try again in 15 minutes.",
                ),
                "Too many failed attempts. Try again in 15 minutes.",
                true,
            ),
            (
                server_error(403, Some("account_suspended"), "this account is suspended"),
                "This account is suspended",
                true,
            ),
            (
                server_error(502, None, "<html>Bad Gateway</html>"),
                "The server could not check the code (HTTP 502). Try again.",
                false,
            ),
        ] {
            assert_eq!(
                MfaLoginError::from_api(&error),
                MfaLoginError {
                    message: message.into(),
                    restart,
                },
                "{error}"
            );
        }
    }

    #[test]
    fn login_errors_show_structured_messages_alone() {
        assert_eq!(
            describe_api_error(&server_error(
                403,
                Some("account_suspended"),
                "This account is suspended. Contact your administrator."
            )),
            "This account is suspended. Contact your administrator."
        );
        assert_eq!(
            describe_api_error(&server_error(401, None, "invalid credentials")),
            "Server error (401): invalid credentials"
        );
    }

    #[test]
    fn sentence_case_capitalizes_the_first_letter_only() {
        assert_eq!(sentence_case("invalid code"), "Invalid code");
        assert_eq!(sentence_case("Already. fine"), "Already. fine");
        assert_eq!(sentence_case("élan"), "Élan");
        assert_eq!(sentence_case(""), "");
    }

    #[test]
    fn recognizes_servers_whose_dashboard_hands_sign_ins_to_the_app() {
        assert!(supports_browser_sign_in(
            r#"{"registration_open":true,"banner":null,"passkeys_available":true,"mfa_required":true}"#
        ));
        assert!(supports_browser_sign_in(r#"{"mfa_required":false}"#));
        // Older servers answer with the dashboard's page
        for older in [
            "<!doctype html><html></html>",
            "",
            "{}",
            "[]",
            r#"{"mfa_required":"yes"}"#,
        ] {
            assert!(!supports_browser_sign_in(older), "{older}");
        }
    }
}
