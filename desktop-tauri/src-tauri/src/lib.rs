mod api;
mod commands;
mod config;
mod crypto;
mod device_keys;
mod fingerprint;
mod history;
mod key_backup;
mod key_sync;
mod proto;
#[cfg(desktop)]
mod relaunch;
mod secure_storage;
#[cfg(desktop)]
mod shortcut;
mod state;
#[cfg(desktop)]
mod tray;
mod updater;
mod ws;

use commands::AppContext;
use tauri::{Emitter, Listener, Manager};

#[cfg(desktop)]
use tauri::menu::{AboutMetadataBuilder, MenuBuilder, MenuItemBuilder, SubmenuBuilder};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::init();

    #[cfg(desktop)]
    {
        let env = tauri::Env::default();
        relaunch::record_start(&env);
        // A package upgrade may have left the previous version running in the tray
        #[cfg(target_os = "linux")]
        relaunch::end_outdated_instances(&env);
    }

    let builder = tauri::Builder::default();

    #[cfg(desktop)]
    let builder = builder.menu(|handle| {
        let about = AboutMetadataBuilder::new()
            .name(Some("cpmesh"))
            .version(Some(env!("CARGO_PKG_VERSION")))
            .build();
        let settings = MenuItemBuilder::with_id("app:settings", "Settings…")
            .accelerator("CmdOrCtrl+,")
            .build(handle)?;
        let app_menu = SubmenuBuilder::new(handle, "cpmesh")
            .about(Some(about))
            .separator()
            .item(&settings)
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

    // One handler for every menu, the tray's included (tray menu handlers receive them all)
    #[cfg(desktop)]
    let builder = builder.on_menu_event(tray::handle_menu_event);

    let builder = builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_deep_link::init());

    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            // Opened at login, cpmesh starts in the background
            Some(vec![tray::BACKGROUND_ARG]),
        ))
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            // When a second instance is launched (e.g. via deep link), this callback fires
            // in the ORIGINAL instance. The new instance exits immediately.

            // Opened again after an update was installed: the new version takes over
            if relaunch::relaunch_if_updated(app, &argv) {
                return;
            }

            // Show and focus the main window
            tray::show_main_window(app);

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
            commands::complete_mfa_login,
            commands::cancel_mfa_login,
            commands::setup_with_oauth_tokens,
            commands::resolve_sign_in,
            commands::cancel_sign_in,
            commands::check_social_status,
            commands::check_browser_sign_in,
            commands::get_user_info,
            commands::exchange_oauth_code,
            commands::connect,
            commands::disconnect,
            commands::get_devices,
            commands::remove_device,
            commands::get_pending_devices,
            commands::begin_device_approval,
            commands::poll_device_approval,
            commands::confirm_device_approval,
            commands::reject_pending_device,
            commands::get_my_approval_status,
            commands::confirm_pairing,
            commands::get_own_identity,
            commands::verify_device_identity,
            commands::get_history,
            commands::search_history,
            commands::copy_entry,
            commands::delete_entry,
            commands::clear_history,
            commands::sync_history,
            commands::get_config,
            commands::update_config,
            commands::get_data_dir,
            #[cfg(desktop)]
            shortcut::get_global_shortcut,
            #[cfg(desktop)]
            shortcut::set_global_shortcut,
            commands::change_password,
            commands::logout,
            commands::check_update,
            commands::download_and_install_update,
            commands::update_installed,
            commands::restart_app,
            commands::get_key_problem,
            commands::get_key_recovery_status,
            commands::inspect_key_backup,
            commands::restore_key_backup,
            commands::reset_encryption,
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
            ctx.attach(app.handle().clone());
            #[cfg(desktop)]
            let (configured, autostart) = ctx
                .config
                .try_read()
                .map(|c| (c.is_configured(), c.autostart))
                .unwrap_or((false, false));
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
                // Menu bar / system tray (non-fatal if it fails)
                let tray_ready = match tray::setup(app) {
                    Ok(()) => true,
                    Err(e) => {
                        log::error!("Failed to setup tray: {e}");
                        false
                    }
                };

                // Closing the window leaves cpmesh syncing from the tray; without a tray
                // there would be no way back, so the window closes normally
                if let Some(window) = app.get_webview_window("main") {
                    let handle = app.handle().clone();
                    window.on_window_event(move |event| {
                        if let tauri::WindowEvent::CloseRequested { api, .. } = event
                            && tray::is_ready()
                        {
                            api.prevent_close();
                            tray::hide_main_window(&handle);
                            tray::announce_background(&handle);
                        }
                    });
                }

                // The window starts hidden; it stays that way only when opened at login
                let background = std::env::args().any(|arg| arg == tray::BACKGROUND_ARG);
                if tray_ready && configured && background {
                    tray::hide_main_window(app.handle());
                } else {
                    tray::show_main_window(app.handle());
                }

                // Re-register Open at Login so its launch arguments match this version
                if autostart {
                    use tauri_plugin_autostart::ManagerExt;
                    if let Err(e) = app.autolaunch().enable() {
                        log::warn!("Failed to refresh Open at Login: {e}");
                    }
                }

                // The shortcut that shows cpmesh from anywhere (one another app holds is
                // reported in Settings rather than failing startup)
                shortcut::init(app.handle());
            }

            // Background update checker (desktop only)
            #[cfg(desktop)]
            {
                // A newer version installed over this one is offered as a restart
                relaunch::watch_for_update(app.handle().clone());

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

            // Startup uses the same restoration, authorization and persistence path as reconnect.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let ctx: tauri::State<'_, AppContext> = handle.state::<AppContext>();
                let should_connect = {
                    let config = ctx.config.read().await;
                    config.is_configured() && config.auto_connect
                };
                if should_connect
                    && let Err(error) = commands::connect(handle.clone(), handle.state()).await
                {
                    log::error!("Auto-connect failed: {error}");
                    let _ = handle.emit("sync-error", error);
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // Starts the new version when this one quit for it (see `relaunch`)
            #[cfg(desktop)]
            if let tauri::RunEvent::Exit = event {
                relaunch::on_exit(app);
            }
            // Opening cpmesh again (Finder, Spotlight, the Dock) while it runs in the
            // background shows the window, or starts the version installed over it
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen {
                has_visible_windows,
                ..
            } = event
            {
                if relaunch::binary_replaced() {
                    relaunch::relaunch(app, relaunch::foreground_args());
                } else if !has_visible_windows {
                    tray::show_main_window(app);
                }
            }
            #[cfg(not(desktop))]
            let _ = (app, event);
        });
}
