use log::{debug, error, info};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{Emitter, Manager, State};
use tokio::sync::{Mutex, RwLock};

use crate::api::client::ApiClient;
use crate::config::{AppConfig, TokenStore};
use crate::crypto::exchange::KeyExchange;
use crate::crypto::keys::{KeyPair, derive_approval_code};
use crate::history::History;
use crate::proto::models::*;
use crate::state::AppState;
use crate::ws::connection::{WsConnection, WsEvent};
use base64::Engine as _;

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
}

impl AppContext {
    pub fn new(cfg_dir: PathBuf) -> Self {
        let config = AppConfig::load(&cfg_dir).unwrap_or_default();
        let mut api = ApiClient::new(&config.server_url);
        let state = if config.is_configured() {
            // Load tokens from secure storage
            let token_store = TokenStore::new(&cfg_dir);
            let access = token_store
                .load_access_token()
                .ok()
                .flatten()
                .unwrap_or_default();
            let refresh = token_store
                .load_refresh_token()
                .ok()
                .flatten()
                .unwrap_or_default();
            if !access.is_empty() && !refresh.is_empty() {
                api.set_tokens(access, refresh);
            }
            AppState::Disconnected
        } else {
            AppState::NotConfigured
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
        }
    }
}

// === Serializable types for frontend ===

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
) -> Result<(), String> {
    // Validate server URL scheme
    if !server_url.starts_with("https://") && !server_url.starts_with("http://") {
        return Err("Server URL must start with https:// or http://".into());
    }

    let mut api = ctx.api.lock().await;
    *api = ApiClient::new(&server_url);

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
    }

    let device_name = crate::fingerprint::auto_device_name();

    let auth_resp = api
        .login(&username, &password, &device_name)
        .await
        .map_err(|e| format!("Login failed: {e}"))?;

    // Generate stable device fingerprint using user_id from auth response
    let user_id = auth_resp.user_id.clone().unwrap_or_default();
    let fingerprint = crate::fingerprint::generate_device_fingerprint(&user_id).ok();

    // Generate device key pair
    let key_path = AppConfig::key_path(&ctx.config_dir);
    let kp =
        KeyPair::load_or_generate(&key_path).map_err(|e| format!("Key generation failed: {e}"))?;
    let pub_bytes = kp.public_key_bytes();
    let sig = kp.sign_public_key();

    // Register device with fingerprint
    let reg_resp = api
        .register_device(&device_name, pub_bytes, Some(sig), fingerprint)
        .await
        .map_err(|e| format!("Device registration failed: {e}"))?;

    let device_id = reg_resp.device.id.clone();
    let device_status = reg_resp.device.status.to_string();

    // Setup group key (only if device is approved — first device auto-approves)
    let mut exchange = KeyExchange::new(kp);
    if device_status == "approved" {
        setup_group_key(&mut exchange, &api, &device_id, &ctx.config_dir)
            .await
            .map_err(|e| format!("Key exchange failed: {e}"))?;
    }

    // Save tokens to secure storage
    let token_store = TokenStore::new(&ctx.config_dir);
    token_store
        .save_tokens(
            api.access_token().unwrap_or_default(),
            api.refresh_token().unwrap_or_default(),
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

    // Update state
    *ctx.state.write().await = AppState::Disconnected;
    *ctx.exchange.lock().await = Some(exchange);

    // Initialize history
    let db_path = ctx.config_dir.join("history.db");
    if let Ok(h) = History::open(&db_path, 1000) {
        *ctx.history.lock().await = Some(h);
    }

    Ok(())
}

async fn setup_group_key(
    exchange: &mut KeyExchange,
    api: &ApiClient,
    device_id: &str,
    config_dir: &std::path::Path,
) -> Result<(), String> {
    let mut verifier = crate::crypto::verify::KeyVerifier::new(config_dir)
        .map_err(|e| format!("Key verifier init failed: {e}"))?;

    // Try to get existing group key
    match api.get_group_key().await.map_err(|e| e.to_string())? {
        Some(gk_resp) => {
            let peer_pub =
                KeyPair::parse_public_key(&gk_resp.from_public_key).map_err(|e| e.to_string())?;

            // Verify ECDSA signature on sender's public key
            if let Some(sig) = &gk_resp.from_public_key_sig {
                KeyPair::verify_public_key_signature(&peer_pub, sig).map_err(|e| {
                    format!("SECURITY: Sender key signature invalid (possible MITM): {e}")
                })?;
                info!(
                    "Verified sender key signature (device {})",
                    gk_resp.from_device_id
                );
            } else {
                info!("WARNING: Sender device has no key signature (legacy device)");
            }

            // Migrate legacy TOFU pin or verify existing pin
            verifier.migrate_legacy(&gk_resp.from_device_id, &peer_pub)
                .map_err(|e| match e {
                    crate::crypto::verify::VerifyError::KeyChanged =>
                        format!("SECURITY: Sender device {} public key has CHANGED. \
                            This could indicate a man-in-the-middle attack. \
                            If the device was legitimately re-created, delete pinned_keys.json and retry.",
                            gk_resp.from_device_id),
                    other => format!("Key verification failed: {other}"),
                })?;

            let version = gk_resp.version;
            exchange
                .decrypt_from_device(&gk_resp.encrypted_key, &peer_pub, version)
                .map_err(|e| e.to_string())?;
            info!(
                "Received group key v{} from device {} (fingerprint: {})",
                version,
                gk_resp.from_device_id,
                KeyPair::short_fingerprint(&peer_pub)
            );

            // Save keyring
            let keyring_path = AppConfig::keyring_path(config_dir);
            let _ = exchange.save_keyring(&keyring_path);
        }
        None => {
            // First device — generate group key and distribute
            exchange.init_group_key();
            info!("Generated new group key (first device)");

            let keys_resp = api.get_device_keys().await.map_err(|e| e.to_string())?;
            let mut store_keys = vec![];
            for dev in &keys_resp.devices {
                if dev.id == device_id {
                    continue;
                }
                if dev.status != DeviceStatus::Approved {
                    continue;
                }
                if let Some(pk_bytes) = &dev.public_key
                    && let Ok(peer_pub) = KeyPair::parse_public_key(pk_bytes)
                {
                    if let Some(sig) = &dev.public_key_sig
                        && let Err(e) = KeyPair::verify_public_key_signature(&peer_pub, sig)
                    {
                        info!(
                            "SECURITY: Device {} ({}) has invalid key signature, skipping: {e}",
                            dev.name, dev.id
                        );
                        continue;
                    }

                    // Pin approved peer's key
                    let _ = verifier.migrate_legacy(&dev.id, &peer_pub);

                    if let Ok(encrypted) = exchange.encrypt_for_device(&peer_pub) {
                        store_keys.push(StoreGroupKeyEntry {
                            device_id: dev.id.clone(),
                            encrypted_key: encrypted,
                        });
                        info!(
                            "Encrypted group key for device {} (fingerprint: {})",
                            dev.name,
                            KeyPair::short_fingerprint(&peer_pub)
                        );
                    }
                }
            }
            // Always hit the endpoint to record version 1 in the DB, even if store_keys is empty
            api.store_group_keys(&store_keys)
                .await
                .map_err(|e| e.to_string())?;

            // Save keyring
            let keyring_path = AppConfig::keyring_path(config_dir);
            let _ = exchange.save_keyring(&keyring_path);
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn connect(
    app_handle: tauri::AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<(), String> {
    let config = ctx.config.read().await.clone();
    if !config.is_configured() {
        return Err("App not configured".into());
    }

    // Ensure exchange is ready and has group keys.
    // For newly approved devices, the exchange exists but has no keys
    // (it was created empty during setup_and_login while device was pending).
    {
        let needs_setup = {
            let guard = ctx.exchange.lock().await;
            match guard.as_ref() {
                None => true,
                Some(ex) => !ex.has_group_key(),
            }
        };

        if needs_setup {
            let key_path = AppConfig::key_path(&ctx.config_dir);
            let kp = KeyPair::load_or_generate(&key_path).map_err(|e| e.to_string())?;
            let mut exchange = KeyExchange::new(kp);

            // Try loading cached keyring from disk first
            let keyring_path = AppConfig::keyring_path(&ctx.config_dir);
            if keyring_path.exists()
                && let Err(e) = exchange.load_keyring(&keyring_path)
            {
                info!("Could not load cached keyring, will fetch from server: {e}");
            }

            // If keyring didn't have keys, fetch from server
            if !exchange.has_group_key() {
                let api = ctx.api.lock().await;
                setup_group_key(&mut exchange, &api, &config.device_id, &ctx.config_dir)
                    .await
                    .map_err(|e| e.to_string())?;
            }

            *ctx.exchange.lock().await = Some(exchange);

            // Update device_status to approved now that we have keys
            // (handles pending→approved transition)
            let mut cfg = ctx.config.write().await;
            if cfg.device_status != "approved" {
                cfg.device_status = "approved".to_string();
                let _ = cfg.save(&ctx.config_dir);
            }
        }
    }

    // Ensure history is ready
    if ctx.history.lock().await.is_none() {
        let db_path = ctx.config_dir.join("history.db");
        if let Ok(h) = History::open(&db_path, 1000) {
            *ctx.history.lock().await = Some(h);
        }
    }

    *ctx.state.write().await = AppState::Connecting;
    let _ = app_handle.emit("connection-state-changed", AppState::Connecting);

    // Create WebSocket connection (load token from secure storage)
    let token_store = TokenStore::new(&ctx.config_dir);
    let ws_token = token_store
        .load_access_token()
        .ok()
        .flatten()
        .unwrap_or_default();
    let fingerprint = crate::fingerprint::generate_device_fingerprint(&config.user_id).ok();
    let (ws_conn, mut event_rx) = WsConnection::new(&config.server_url, &ws_token, fingerprint);
    let ws_conn = Arc::new(ws_conn);

    // Store connection
    *ctx.ws.lock().await = Some(ws_conn.clone());

    // Start connection in background
    let ws_clone = ws_conn.clone();
    tokio::spawn(async move {
        ws_clone.connect_with_reconnect().await;
    });

    // Event handler task
    let handle = app_handle.clone();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                WsEvent::Connected => {
                    let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                    *ctx.state.write().await = AppState::Connected;
                    let _ = handle.emit("connection-state-changed", AppState::Connected);

                    // Refresh device list
                    {
                        let api = ctx.api.lock().await;
                        if let Ok(devices) = api.get_devices().await {
                            *ctx.devices.write().await = devices;
                        }
                    };
                }
                WsEvent::Disconnected => {
                    let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                    let current = ctx.state.read().await.clone();
                    if current != AppState::Disconnected {
                        *ctx.state.write().await = AppState::Connecting;
                        let _ = handle.emit("connection-state-changed", AppState::Connecting);
                    }
                }
                WsEvent::ClipboardNew(payload) => {
                    let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                    // Decrypt the entry
                    let exchange_guard = ctx.exchange.lock().await;
                    if let Some(exchange) = exchange_guard.as_ref() {
                        let kv = payload.entry.key_version;
                        if let Ok(data) =
                            exchange.decrypt_payload(&payload.entry.encrypted_data, kv)
                        {
                            let mut meta = Metadata::default();
                            if !payload.entry.metadata.is_empty()
                                && let Ok(meta_encrypted) =
                                    base64::engine::general_purpose::STANDARD
                                        .decode(&payload.entry.metadata)
                                && let Ok(meta_bytes) =
                                    exchange.decrypt_payload(&meta_encrypted, kv)
                                && let Ok(m) = serde_json::from_slice(&meta_bytes)
                            {
                                meta = m;
                            }

                            let plain = PlainEntry {
                                id: payload.entry.id,
                                device_id: payload.entry.device_id,
                                device_name: payload.entry.device_name,
                                content_type: payload.entry.content_type,
                                data,
                                metadata: meta,
                                created_at: payload.entry.created_at,
                            };

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
                                    let body = match plain.content_type {
                                        ContentType::Text => {
                                            let text = String::from_utf8_lossy(&plain.data);
                                            if text.len() > 80 {
                                                format!("{}...", &text[..80])
                                            } else {
                                                text.to_string()
                                            }
                                        }
                                        ContentType::Image => "Image copied".into(),
                                        ContentType::File => plain
                                            .metadata
                                            .filename
                                            .clone()
                                            .unwrap_or_else(|| "File received".into()),
                                    };
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
                WsEvent::GroupKeyUpdated => {
                    info!("Group key updated, re-fetching...");
                    let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                    let api = ctx.api.lock().await;
                    match api.get_group_key().await {
                        Ok(Some(gk_resp)) => {
                            let key_path = AppConfig::key_path(&ctx.config_dir);
                            if let Ok(kp) = KeyPair::load_or_generate(&key_path) {
                                let peer_pub = KeyPair::parse_public_key(&gk_resp.from_public_key);
                                if let Ok(peer_pub) = peer_pub {
                                    // Verify signature
                                    if let Some(sig) = &gk_resp.from_public_key_sig
                                        && let Err(e) =
                                            KeyPair::verify_public_key_signature(&peer_pub, sig)
                                    {
                                        error!("SECURITY: Group key sender signature invalid: {e}");
                                        continue;
                                    }
                                    // TOFU check
                                    if let Ok(mut verifier) =
                                        crate::crypto::verify::KeyVerifier::new(&ctx.config_dir)
                                        && let Err(e) = verifier
                                            .migrate_legacy(&gk_resp.from_device_id, &peer_pub)
                                    {
                                        error!(
                                            "SECURITY: Group key sender key verification failed: {e}"
                                        );
                                        continue;
                                    }

                                    let mut new_exchange = KeyExchange::new(kp);
                                    let version = gk_resp.version;
                                    if new_exchange
                                        .decrypt_from_device(
                                            &gk_resp.encrypted_key,
                                            &peer_pub,
                                            version,
                                        )
                                        .is_ok()
                                    {
                                        // Preserve old key versions from existing exchange
                                        if let Some(old_exch) = ctx.exchange.lock().await.as_ref() {
                                            for (&v, k) in &old_exch.keys_by_version {
                                                if v != version {
                                                    new_exchange.add_key_version(v, k.clone());
                                                }
                                            }
                                        }
                                        *ctx.exchange.lock().await = Some(new_exchange);
                                        info!(
                                            "Group key refreshed successfully from device {} (v{})",
                                            gk_resp.from_device_id, version
                                        );
                                    } else {
                                        error!("Failed to decrypt new group key");
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            info!("No group key available after update notification");
                        }
                        Err(e) => {
                            error!("Failed to re-fetch group key: {e}");
                        }
                    }
                }
                WsEvent::Error(msg) => {
                    error!("WS error: {msg}");
                }
            }
        }
    });

    // Clipboard monitor — polls local clipboard and sends changes to server
    #[cfg(desktop)]
    {
        let monitor_handle = app_handle.clone();
        let monitor_ws = ws_conn.clone();
        tokio::spawn(async move {
            clipboard_monitor(monitor_handle, monitor_ws).await;
        });
    }

    #[cfg(not(desktop))]
    {
        let monitor_handle = app_handle.clone();
        let monitor_ws = ws_conn.clone();
        tokio::spawn(async move {
            mobile_clipboard_monitor(monitor_handle, monitor_ws).await;
        });
    }

    Ok(())
}

// === Image clipboard helpers (desktop only) ===

#[cfg(desktop)]
enum ClipboardContent {
    Text(String),
    Image {
        rgba: Vec<u8>,
        width: usize,
        height: usize,
    },
    Empty,
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
    let mut interval = tokio::time::interval(Duration::from_millis(250));

    loop {
        interval.tick().await;

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
        if ctx.skip_clipboard.load(Ordering::SeqCst) {
            continue;
        }

        // Read current clipboard content (blocking — run in spawn_blocking)
        let clip_content = tokio::task::spawn_blocking(|| {
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
                return ClipboardContent::Image {
                    rgba: img.bytes.into_owned(),
                    width: img.width,
                    height: img.height,
                };
            }
            ClipboardContent::Empty
        })
        .await
        .unwrap_or(ClipboardContent::Empty);

        let (content_type, data, meta) = match clip_content {
            ClipboardContent::Text(text) => {
                let bytes = text.as_bytes().to_vec();
                let meta = Metadata {
                    size: bytes.len() as i64,
                    mime_type: Some("text/plain".into()),
                    ..Default::default()
                };
                (ContentType::Text, bytes, meta)
            }
            ClipboardContent::Image {
                rgba,
                width,
                height,
            } => {
                // Encode RGBA to PNG
                let png_bytes = match encode_rgba_to_png(&rgba, width as u32, height as u32) {
                    Some(b) => b,
                    None => continue,
                };
                let meta = Metadata {
                    size: png_bytes.len() as i64,
                    mime_type: Some("image/png".into()),
                    width: Some(width as i32),
                    height: Some(height as i32),
                    ..Default::default()
                };
                (ContentType::Image, png_bytes, meta)
            }
            ClipboardContent::Empty => continue,
        };

        // Hash to detect changes
        let hash: [u8; 32] = Sha256::digest(&data).into();
        if hash == last_hash {
            continue;
        }
        // Also skip if this matches content we just received from another device
        if hash == *ctx.last_clipboard_hash.lock().await {
            last_hash = hash;
            continue;
        }
        last_hash = hash;

        // Encrypt and send
        let exchange_guard = ctx.exchange.lock().await;
        let exchange = match exchange_guard.as_ref() {
            Some(e) => e,
            None => continue,
        };

        let (encrypted, key_version) = match exchange.encrypt_payload(&data) {
            Ok(result) => result,
            Err(e) => {
                error!("Clipboard encrypt failed: {e}");
                continue;
            }
        };

        let meta_json = serde_json::to_vec(&meta).unwrap_or_default();
        let enc_meta_bytes = exchange
            .encrypt_payload(&meta_json)
            .map(|(d, _)| d)
            .unwrap_or_default();

        // Must drop exchange lock before other operations
        drop(exchange_guard);

        // Metadata is sent as base64 since the field is a String
        let enc_meta_b64 = base64::engine::general_purpose::STANDARD.encode(&enc_meta_bytes);

        let payload = ClipboardPushPayload {
            content_type: content_type.clone(),
            encrypted_data: encrypted,
            metadata: Some(enc_meta_b64),
            key_version,
        };

        if let Err(e) = ws.send_clipboard(payload) {
            error!("Failed to send clipboard: {e}");
            continue;
        }

        debug!("Sent clipboard {:?} ({} bytes)", content_type, data.len());

        // Also store in local history
        let config = ctx.config.read().await;
        let plain = PlainEntry {
            id: uuid::Uuid::new_v4().to_string(),
            device_id: config.device_id.clone(),
            device_name: config.device_name.clone(),
            content_type,
            data,
            metadata: meta,
            created_at: chrono::Utc::now(),
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

        let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();

        let state = ctx.state.read().await.clone();
        if state != AppState::Connected {
            if state == AppState::Disconnected || state == AppState::NotConfigured {
                debug!("Mobile clipboard monitor stopping: state={:?}", state);
                break;
            }
            continue;
        }

        if ctx.skip_clipboard.load(Ordering::SeqCst) {
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
        last_hash = hash;

        // Encrypt and send
        let exchange_guard = ctx.exchange.lock().await;
        let exchange = match exchange_guard.as_ref() {
            Some(e) => e,
            None => continue,
        };

        let (encrypted, key_version) = match exchange.encrypt_payload(&data) {
            Ok(result) => result,
            Err(e) => {
                error!("Mobile clipboard encrypt failed: {e}");
                continue;
            }
        };

        let meta = Metadata {
            size: data.len() as i64,
            mime_type: Some("text/plain".into()),
            ..Default::default()
        };
        let meta_json = serde_json::to_vec(&meta).unwrap_or_default();
        let enc_meta_bytes = exchange
            .encrypt_payload(&meta_json)
            .map(|(d, _)| d)
            .unwrap_or_default();
        drop(exchange_guard);

        let enc_meta_b64 = base64::engine::general_purpose::STANDARD.encode(&enc_meta_bytes);

        let payload = ClipboardPushPayload {
            content_type: ContentType::Text,
            encrypted_data: encrypted,
            metadata: Some(enc_meta_b64),
            key_version,
        };

        if let Err(e) = ws.send_clipboard(payload) {
            error!("Failed to send mobile clipboard: {e}");
            continue;
        }

        debug!("Sent mobile clipboard text ({} bytes)", data.len());

        // Store in local history
        let config = ctx.config.read().await;
        let plain = PlainEntry {
            id: uuid::Uuid::new_v4().to_string(),
            device_id: config.device_id.clone(),
            device_name: config.device_name.clone(),
            content_type: ContentType::Text,
            data,
            metadata: meta,
            created_at: chrono::Utc::now(),
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
    if let Some(ws) = ctx.ws.lock().await.take() {
        ws.close();
    }
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
    let api = ctx.api.lock().await;
    api.delete_device(&device_id)
        .await
        .map_err(|e| e.to_string())?;
    ctx.devices.write().await.retain(|d| d.id != device_id);
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
    pub approval_code: String,
    pub expires_at: String,
}

#[derive(Serialize)]
pub struct MyApprovalStatusInfo {
    pub status: String,
    pub approval_code: Option<String>,
    pub session_id: Option<String>,
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
    // Lock API briefly to call begin_approval, then release
    let session = {
        let api = ctx.api.lock().await;
        api.begin_approval(&pending_device_id)
            .await
            .map_err(|e| e.to_string())?
    };

    // Derive 8-digit verification code from ECDH between our key and the pending device's key
    let key_path = AppConfig::key_path(&ctx.config_dir);
    let kp =
        KeyPair::load_or_generate(&key_path).map_err(|e| format!("Failed to load key: {e}"))?;

    let pending_pub = KeyPair::parse_public_key(&session.pending_public_key)
        .map_err(|e| format!("Invalid pending device public key: {e}"))?;

    let code = derive_approval_code(&kp.private, &pending_pub, &kp.public)
        .map_err(|e| format!("Failed to derive approval code: {e}"))?;

    Ok(ApprovalSessionInfo {
        session_id: session.session_id,
        approval_code: code,
        expires_at: session.expires_at.to_rfc3339(),
    })
}

#[tauri::command]
pub async fn confirm_device_approval(
    ctx: State<'_, AppContext>,
    pending_device_id: String,
    session_id: String,
) -> Result<(), String> {
    // Fetch device info with API lock, then release it
    let (all_devices, pending_devices) = {
        let api = ctx.api.lock().await;
        let all = api.get_device_keys().await.map_err(|e| e.to_string())?;
        let pending = api.get_pending_devices().await.map_err(|e| e.to_string())?;
        (all, pending)
    };

    let pending_dev = pending_devices
        .iter()
        .find(|d| d.id == pending_device_id)
        .ok_or("Pending device not found")?;

    // Build list of all device public keys: approved devices + the pending device
    let mut peer_devices: Vec<(String, p256::PublicKey)> = Vec::new();

    for dev in &all_devices.devices {
        if dev.status != DeviceStatus::Approved {
            continue;
        }
        if let Some(pk_bytes) = &dev.public_key
            && let Ok(pub_key) = KeyPair::parse_public_key(pk_bytes)
        {
            peer_devices.push((dev.id.clone(), pub_key));
        }
    }

    // Add the pending device
    let pending_pub = KeyPair::parse_public_key(&pending_dev.public_key)
        .map_err(|e| format!("Invalid pending device key: {e}"))?;
    peer_devices.push((pending_device_id.clone(), pending_pub));

    // Generate next group key version (exchange lock only)
    let req = {
        let mut exchange_guard = ctx.exchange.lock().await;
        let exchange = exchange_guard
            .as_mut()
            .ok_or("Encryption not initialized")?;

        let (new_version, wrapped) = exchange
            .generate_next_version(&peer_devices)
            .map_err(|e| format!("Key rotation failed: {e}"))?;

        let wrapped_keys: Vec<StoreGroupKeyEntry> = wrapped
            .into_iter()
            .map(|(device_id, encrypted_key)| StoreGroupKeyEntry {
                device_id,
                encrypted_key,
            })
            .collect();

        // Save keyring while we have the lock
        let keyring_path = AppConfig::keyring_path(&ctx.config_dir);
        let _ = exchange.save_keyring(&keyring_path);

        ApproveDeviceRequest {
            session_id,
            expected_current_version: new_version - 1,
            new_version,
            wrapped_keys,
        }
    };

    // Send approval with API lock (exchange is released)
    {
        let api = ctx.api.lock().await;
        api.approve_device(&pending_device_id, &req)
            .await
            .map_err(|e| e.to_string())?;
    }

    info!(
        "Device {} approved, group key rotated to v{}",
        pending_device_id, req.new_version
    );
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

    // If there's an active approval session, derive the verification code
    let approval_code = if let (Some(_session_id), Some(approver_pub_bytes)) =
        (&resp.session_id, &resp.approver_public_key)
    {
        let key_path = AppConfig::key_path(&ctx.config_dir);
        let kp =
            KeyPair::load_or_generate(&key_path).map_err(|e| format!("Failed to load key: {e}"))?;
        let approver_pub = KeyPair::parse_public_key(approver_pub_bytes)
            .map_err(|e| format!("Invalid approver public key: {e}"))?;
        derive_approval_code(&kp.private, &approver_pub, &kp.public).ok()
    } else {
        None
    };

    Ok(MyApprovalStatusInfo {
        status: resp.status.to_string(),
        approval_code,
        session_id: resp.session_id,
    })
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

        // Decrypt entries — hold exchange lock only for decryption
        let plain_entries = {
            let exchange_guard = ctx.exchange.lock().await;
            let exchange = exchange_guard
                .as_ref()
                .ok_or("Encryption not initialized")?;

            let mut entries = Vec::new();
            for entry in &resp.entries {
                let kv = entry.key_version;
                let data = match exchange.decrypt_payload(&entry.encrypted_data, kv) {
                    Ok(d) => d,
                    Err(_) => match exchange.decrypt_payload_legacy(&entry.encrypted_data) {
                        Ok(d) => d,
                        Err(e) => {
                            debug!("Skipping entry {} (decrypt failed: {e})", entry.id);
                            continue;
                        }
                    },
                };

                let mut meta = Metadata::default();
                if !entry.metadata.is_empty()
                    && let Ok(meta_encrypted) =
                        base64::engine::general_purpose::STANDARD.decode(&entry.metadata)
                    && let Ok(meta_bytes) = exchange.decrypt_payload(&meta_encrypted, kv)
                    && let Ok(m) = serde_json::from_slice(&meta_bytes)
                {
                    meta = m;
                }

                entries.push(PlainEntry {
                    id: entry.id.clone(),
                    device_id: entry.device_id.clone(),
                    device_name: entry.device_name.clone(),
                    content_type: entry.content_type.clone(),
                    data,
                    metadata: meta,
                    created_at: entry.created_at,
                });
            }
            entries
        };

        // Store entries — hold history lock only for insertion
        {
            let history = ctx.history.lock().await;
            if let Some(h) = history.as_ref() {
                for plain in &plain_entries {
                    if h.add(plain).is_ok() {
                        total_synced += 1;
                    }
                }
            }
        }

        if !resp.has_more || resp.entries.is_empty() {
            break;
        }
        offset += PAGE_SIZE;
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
        // Update the API client base URL
        let mut api = ctx.api.lock().await;
        *api = ApiClient::new(&v);
        // Reload tokens from secure storage
        let ts = TokenStore::new(&ctx.config_dir);
        let access = ts.load_access_token().ok().flatten().unwrap_or_default();
        let refresh = ts.load_refresh_token().ok().flatten().unwrap_or_default();
        api.set_tokens(access, refresh);
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
    ctx: State<'_, AppContext>,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    let api = ctx.api.lock().await;
    api.change_password(&current_password, &new_password)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn logout(
    app_handle: tauri::AppHandle,
    ctx: State<'_, AppContext>,
) -> Result<(), String> {
    // Disconnect WebSocket if connected
    if let Some(ws) = ctx.ws.lock().await.take() {
        ws.close();
    }

    // Clear tokens from secure storage
    let token_store = TokenStore::new(&ctx.config_dir);
    let _ = token_store.clear();

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

#[tauri::command]
pub async fn download_and_install_update(
    ctx: State<'_, AppContext>,
    download_url: String,
) -> Result<(), String> {
    // Resolve relative URLs against the configured server URL
    let full_url = if download_url.starts_with("http://") || download_url.starts_with("https://") {
        download_url.clone()
    } else {
        let config = ctx.config.read().await;
        let base = config.server_url.trim_end_matches('/');
        format!("{}{}", base, download_url)
    };

    info!("Downloading update from: {full_url}");

    // Download the file
    let client = reqwest::Client::new();
    let resp = client
        .get(&full_url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("Download failed with status: {}", resp.status()));
    }

    // Extract filename from URL path
    let filename = full_url
        .split('/')
        .next_back()
        .unwrap_or("cpmesh-update")
        .to_string();

    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join(&filename);

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read download: {e}"))?;

    std::fs::write(&file_path, &bytes).map_err(|e| format!("Failed to save file: {e}"))?;

    info!("Update downloaded to: {}", file_path.display());

    // Launch the installer
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        open::that(&file_path).map_err(|e| format!("Failed to open installer: {e}"))?;
    }

    Ok(())
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

/// Complete device setup using tokens obtained from OAuth (via PKCE exchange).
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
    *api = ApiClient::new(&server_url);
    api.set_tokens(access_token, refresh_token);

    // Get user info to obtain user_id for fingerprinting
    let user_info = api
        .get_me()
        .await
        .map_err(|e| format!("Failed to get user info: {e}"))?;
    let user_id = user_info.id.clone();

    let device_name = crate::fingerprint::auto_device_name();
    let fingerprint = crate::fingerprint::generate_device_fingerprint(&user_id).ok();

    // Generate device key pair
    let key_path = AppConfig::key_path(&ctx.config_dir);
    let kp =
        KeyPair::load_or_generate(&key_path).map_err(|e| format!("Key generation failed: {e}"))?;
    let pub_bytes = kp.public_key_bytes();
    let sig = kp.sign_public_key();

    // Register device with fingerprint
    let reg_resp = api
        .register_device(&device_name, pub_bytes, Some(sig), fingerprint)
        .await
        .map_err(|e| format!("Device registration failed: {e}"))?;

    let device_id = reg_resp.device.id.clone();
    let device_status = reg_resp.device.status.to_string();

    // Setup group key (only if approved)
    let mut exchange = KeyExchange::new(kp);
    if device_status == "approved" {
        setup_group_key(&mut exchange, &api, &device_id, &ctx.config_dir)
            .await
            .map_err(|e| format!("Key exchange failed: {e}"))?;
    }

    // Save tokens to secure storage
    let token_store = TokenStore::new(&ctx.config_dir);
    token_store
        .save_tokens(
            api.access_token().unwrap_or_default(),
            api.refresh_token().unwrap_or_default(),
        )
        .map_err(|e| format!("Token save failed: {e}"))?;

    // Save config
    let mut config = ctx.config.write().await;
    config.server_url = server_url;
    config.user_id = user_id;
    config.device_id = device_id;
    config.device_name = device_name;
    config.device_status = device_status;
    config
        .save(&ctx.config_dir)
        .map_err(|e| format!("Config save failed: {e}"))?;

    // Update state
    *ctx.state.write().await = AppState::Disconnected;
    *ctx.exchange.lock().await = Some(exchange);

    // Initialize history
    let db_path = ctx.config_dir.join("history.db");
    if let Ok(h) = History::open(&db_path, 1000) {
        *ctx.history.lock().await = Some(h);
    }

    Ok(())
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
}
