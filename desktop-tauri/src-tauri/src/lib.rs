mod api;
mod commands;
mod config;
mod crypto;
mod fingerprint;
mod history;
mod proto;
mod secure_storage;
mod state;
mod updater;
mod ws;

use commands::AppContext;
use tauri::{Emitter, Listener, Manager};

#[cfg(desktop)]
use tauri::menu::{AboutMetadataBuilder, MenuBuilder, MenuItemBuilder, SubmenuBuilder};
#[cfg(desktop)]
use tauri::tray::TrayIconEvent;

#[cfg(desktop)]
fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let show = MenuItemBuilder::with_id("show", "Show cpmesh").build(app)?;
    let connect = MenuItemBuilder::with_id("connect", "Connect").build(app)?;
    let disconnect = MenuItemBuilder::with_id("disconnect", "Disconnect").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&show)
        .separator()
        .item(&connect)
        .item(&disconnect)
        .separator()
        .item(&quit)
        .build()?;

    if let Some(tray) = app.tray_by_id("main") {
        tray.set_menu(Some(menu))?;
        tray.set_show_menu_on_left_click(false)?;

        let handle = app.handle().clone();
        tray.on_menu_event(move |app_handle, event| match event.id().as_ref() {
            "show" => {
                if let Some(w) = app_handle.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "connect" => {
                let h = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let ctx: tauri::State<'_, AppContext> = h.state::<AppContext>();
                    let _ = commands::connect(h.clone(), ctx).await;
                });
            }
            "disconnect" => {
                let h = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let ctx: tauri::State<'_, AppContext> = h.state::<AppContext>();
                    let _ = commands::disconnect(h.clone(), ctx).await;
                });
            }
            "quit" => {
                app_handle.exit(0);
            }
            _ => {}
        });

        let handle2 = app.handle().clone();
        tray.on_tray_icon_event(move |_tray, event| {
            if let TrayIconEvent::DoubleClick { .. } = event
                && let Some(w) = handle2.get_webview_window("main")
            {
                let _ = w.show();
                let _ = w.set_focus();
            }
        });
    }

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::init();

    let builder = tauri::Builder::default();

    #[cfg(desktop)]
    let builder = builder.menu(|handle| {
        let about = AboutMetadataBuilder::new()
            .name(Some("cpmesh"))
            .version(Some(env!("CARGO_PKG_VERSION")))
            .build();
        let app_menu = SubmenuBuilder::new(handle, "cpmesh")
            .about(Some(about))
            .separator()
            .hide()
            .hide_others()
            .show_all()
            .separator()
            .quit()
            .build()?;
        let edit_menu = SubmenuBuilder::new(handle, "Edit")
            .undo()
            .redo()
            .separator()
            .cut()
            .copy()
            .paste()
            .select_all()
            .build()?;
        let window_menu = SubmenuBuilder::new(handle, "Window")
            .minimize()
            .close_window()
            .build()?;
        MenuBuilder::new(handle)
            .item(&app_menu)
            .item(&edit_menu)
            .item(&window_menu)
            .build()
    });

    let builder = builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_deep_link::init());

    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            // When a second instance is launched (e.g. via deep link), this callback fires
            // in the ORIGINAL instance. The new instance exits immediately.

            // Show and focus the main window
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }

            // Check argv for a deep-link URL (e.g. cpmesh://auth/callback?code=...)
            for arg in &argv {
                if arg.starts_with("cpmesh://auth/callback")
                    && let Some(query_str) = arg.split('?').nth(1)
                {
                    let params: std::collections::HashMap<String, String> = query_str
                        .split('&')
                        .filter_map(|pair| {
                            let mut parts = pair.splitn(2, '=');
                            Some((
                                parts.next()?.to_string(),
                                urlencoding::decode(parts.next().unwrap_or(""))
                                    .unwrap_or_default()
                                    .to_string(),
                            ))
                        })
                        .collect();

                    if let Some(code) = params.get("code") {
                        let _ = app.emit(
                            "oauth-callback",
                            serde_json::json!({
                                "code": code,
                            }),
                        );
                    }
                }
            }
        }));

    builder
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_app_state,
            commands::setup_and_login,
            commands::setup_with_oauth_tokens,
            commands::check_social_status,
            commands::get_user_info,
            commands::exchange_oauth_code,
            commands::connect,
            commands::disconnect,
            commands::get_devices,
            commands::remove_device,
            commands::get_pending_devices,
            commands::begin_device_approval,
            commands::confirm_device_approval,
            commands::reject_pending_device,
            commands::get_my_approval_status,
            commands::get_history,
            commands::search_history,
            commands::copy_entry,
            commands::delete_entry,
            commands::clear_history,
            commands::sync_history,
            commands::get_config,
            commands::update_config,
            commands::change_password,
            commands::logout,
            commands::check_update,
            commands::download_and_install_update,
        ])
        .setup(|app| {
            // Resolve config directory: use Tauri's app data dir (works on all platforms including Android/iOS)
            let cfg_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| config::config_dir());
            std::fs::create_dir_all(&cfg_dir).ok();
            log::info!("Config directory: {}", cfg_dir.display());

            let ctx = AppContext::new(cfg_dir);
            app.manage(ctx);

            // Handle deep-link URLs (OAuth callback from browser)
            let handle_for_deep_link = app.handle().clone();
            app.listen("deep-link://new-url", move |event: tauri::Event| {
                if let Ok(urls) = serde_json::from_str::<Vec<String>>(event.payload()) {
                    for url in urls {
                        if url.starts_with("cpmesh://auth/callback") {
                            // Parse query parameters from the URL
                            if let Some(query_str) = url.split('?').nth(1) {
                                let params: std::collections::HashMap<String, String> = query_str
                                    .split('&')
                                    .filter_map(|pair| {
                                        let mut parts = pair.splitn(2, '=');
                                        Some((
                                            parts.next()?.to_string(),
                                            urlencoding::decode(parts.next().unwrap_or(""))
                                                .unwrap_or_default()
                                                .to_string(),
                                        ))
                                    })
                                    .collect();

                                if let Some(code) = params.get("code") {
                                    let _ = handle_for_deep_link.emit(
                                        "oauth-callback",
                                        serde_json::json!({
                                            "code": code,
                                        }),
                                    );
                                }
                            }
                        }
                    }
                }
            });

            // Packages register the cpmesh:// handler (used by browser sign-in) through their
            // .desktop file, but an AppImage is never installed, so it registers itself on
            // every start, which also keeps the handler pointing at it after it's moved
            #[cfg(target_os = "linux")]
            {
                if app.env().appimage.is_some() {
                    let handle = app.handle().clone();
                    tauri::async_runtime::spawn_blocking(move || {
                        use tauri_plugin_deep_link::DeepLinkExt;
                        if let Err(e) = handle.deep_link().register_all() {
                            log::error!("Failed to register the cpmesh:// URL scheme: {e}");
                        }
                    });
                }
            }

            #[cfg(desktop)]
            {
                // Setup system tray (non-fatal if it fails)
                if let Err(e) = setup_tray(app) {
                    log::error!("Failed to setup tray: {e}");
                }

                // Hide to tray on window close (instead of quitting)
                if let Some(window) = app.get_webview_window("main") {
                    let w = window.clone();
                    window.on_window_event(move |event| {
                        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                            api.prevent_close();
                            let _ = w.hide();
                        }
                    });
                }

                // Register global hotkey (non-fatal if it fails — e.g. shortcut already taken)
                {
                    use tauri_plugin_global_shortcut::GlobalShortcutExt;
                    let handle_for_hotkey = app.handle().clone();
                    if let Err(e) = app.global_shortcut().on_shortcut(
                        "CmdOrCtrl+Shift+Space",
                        move |_app, _shortcut, event| {
                            if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed
                                && let Some(w) = handle_for_hotkey.get_webview_window("main")
                            {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        },
                    ) {
                        log::error!("Failed to register global shortcut: {e}");
                    }
                }
            }

            // Background update checker (desktop only)
            #[cfg(desktop)]
            {
                let update_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    // Wait 30 seconds before the first check
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                    loop {
                        let ctx: tauri::State<'_, AppContext> = update_handle.state::<AppContext>();
                        let server_url = {
                            let config = ctx.config.read().await;
                            if config.is_configured() {
                                Some(config.server_url.clone())
                            } else {
                                None
                            }
                        };

                        if let Some(server_url) = server_url {
                            let current_version = env!("CARGO_PKG_VERSION");
                            let platform = if cfg!(target_os = "macos") {
                                "darwin"
                            } else if cfg!(target_os = "windows") {
                                "windows"
                            } else {
                                "linux"
                            };
                            let arch = if cfg!(target_arch = "aarch64") {
                                "arm64"
                            } else {
                                "amd64"
                            };

                            let client = api::client::ApiClient::new(&server_url);
                            match client.check_update(platform, arch, current_version).await {
                                Ok(resp) if resp.update_available => {
                                    let info = commands::UpdateInfo {
                                        update_available: true,
                                        version: resp.version.unwrap_or_default(),
                                        download_url: resp.download_url.unwrap_or_default(),
                                        release_notes: resp.release_notes.unwrap_or_default(),
                                    };
                                    let _ = update_handle.emit("update-available", &info);
                                    log::info!("Update available: v{}", info.version);
                                }
                                Ok(_) => {
                                    log::debug!("No update available");
                                }
                                Err(e) => {
                                    log::debug!("Background update check failed: {e}");
                                }
                            }
                        }

                        // Sleep 60 minutes before next check
                        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    }
                });
            }

            // Auto-connect on startup if configured
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                let should_connect = {
                    let config = ctx.config.read().await;
                    config.is_configured() && config.auto_connect
                };
                if should_connect {
                    let cfg: config::AppConfig = ctx.config.read().await.clone();
                    let key_path = config::AppConfig::key_path(&ctx.config_dir);
                    if let Ok(kp) = crypto::keys::KeyPair::load_or_generate(&key_path) {
                        let mut exchange = crypto::exchange::KeyExchange::new(kp);

                        // Restore the stored session
                        *ctx.api.lock().await = commands::restore_api_client(
                            &cfg.server_url,
                            &ctx.config_dir,
                            &cfg.device_id,
                        );

                        // Try to setup group key
                        {
                            let api: tokio::sync::MutexGuard<'_, api::client::ApiClient> =
                                ctx.api.lock().await;
                            if let Ok(gk) = api.get_group_key().await {
                                if let Some(gk_resp) = gk {
                                    if let Ok(peer_pub) = crypto::keys::KeyPair::parse_public_key(
                                        &gk_resp.from_public_key,
                                    ) {
                                        let version = gk_resp.version;
                                        let _ = exchange.decrypt_from_device(
                                            &gk_resp.encrypted_key,
                                            &peer_pub,
                                            version,
                                        );
                                    }
                                } else {
                                    exchange.init_group_key();
                                }
                            }
                        }
                        *ctx.exchange.lock().await = Some(exchange);

                        // Initialize history
                        let db_path = ctx.config_dir.join("history.db");
                        if let Ok(h) = history::History::open(&db_path, 1000) {
                            *ctx.history.lock().await = Some(h);
                        }

                        // Connect
                        let _ = commands::connect(handle.clone(), handle.state()).await;
                    }
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
