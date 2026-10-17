//! Menu bar (macOS) and system tray (Windows, Linux) presence: a live status line,
//! recent clips to copy back, quick actions, and the window lifecycle that keeps
//! cpmesh syncing in the background after its window is closed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use tauri::image::Image;
use tauri::menu::{
    CheckMenuItemBuilder, Menu, MenuBuilder, MenuEvent, MenuItemBuilder, SubmenuBuilder,
};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Listener, Manager, Wry};

use crate::commands::{self, AppContext};
use crate::state::AppState;

const TRAY_ID: &str = "main";
/// Launch argument "Open at Login" passes: start in the background, without a window.
pub const BACKGROUND_ARG: &str = "--background";
/// Marks that the "still running" notice was shown, so it appears only once.
const BACKGROUND_NOTICE_MARKER: &str = "background-notice-shown";
const RECENT_CLIPS: usize = 6;
const CLIP_LABEL_CHARS: usize = 44;
/// Routes the menus may open in the window.
const ROUTES: [&str; 4] = ["/", "/history", "/devices", "/settings"];

// macOS tints template images for light and dark menu bars; elsewhere the tray shows
// the colour tile.
#[cfg(target_os = "macos")]
const LIVE_ICON: &[u8] = include_bytes!("../icons/tray/tray-template.png");
#[cfg(target_os = "macos")]
const IDLE_ICON: &[u8] = include_bytes!("../icons/tray/tray-template-offline.png");
#[cfg(not(target_os = "macos"))]
const LIVE_ICON: &[u8] = include_bytes!("../icons/tray/tray.png");
#[cfg(not(target_os = "macos"))]
const IDLE_ICON: &[u8] = include_bytes!("../icons/tray/tray-offline.png");

static TRAY_READY: AtomicBool = AtomicBool::new(false);
/// What the tray currently shows, so refreshes that would change nothing are skipped.
static RENDERED: Mutex<Option<Snapshot>> = Mutex::new(None);
static REFRESH: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    SignedOut,
    Pending,
    Offline,
    Connecting,
    Live,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    status: Status,
    devices: usize,
    online: usize,
    autostart: bool,
    /// The global shortcut that shows cpmesh, while it is registered
    shortcut: Option<String>,
    /// (history entry id, menu label), newest first
    clips: Vec<(String, String)>,
}

fn status_of(state: &AppState, configured: bool, pending: bool) -> Status {
    if !configured || *state == AppState::NotConfigured {
        Status::SignedOut
    } else if pending {
        Status::Pending
    } else {
        match state {
            AppState::Connected => Status::Live,
            AppState::Connecting => Status::Connecting,
            _ => Status::Offline,
        }
    }
}

fn status_text(snapshot: &Snapshot) -> String {
    match snapshot.status {
        Status::SignedOut => "Not signed in".into(),
        Status::Pending => "Waiting for approval".into(),
        Status::Offline => "Offline — sync paused".into(),
        Status::Connecting => "Connecting…".into(),
        Status::Live if snapshot.devices > 1 => format!(
            "Syncing — {} of {} devices online",
            snapshot.online.min(snapshot.devices),
            snapshot.devices
        ),
        Status::Live => "Syncing".into(),
    }
}

/// One line of a clip's preview, shortened for a menu.
fn clip_label(preview: &str) -> String {
    let mut lines = preview.lines().map(str::trim).filter(|l| !l.is_empty());
    let Some(first) = lines.next() else {
        return "Empty clip".into();
    };
    let mut label: String = first.chars().take(CLIP_LABEL_CHARS).collect();
    if first.chars().count() > CLIP_LABEL_CHARS || lines.next().is_some() {
        label = label.trim_end().to_string();
        label.push('…');
    }
    // `&` marks a keyboard mnemonic in menu labels; `&&` is a literal ampersand
    label.replace('&', "&&")
}

/// The state without waiting on locks: for building the first menu during setup.
fn snapshot_now(ctx: &AppContext) -> Snapshot {
    let state = ctx
        .state
        .try_read()
        .map(|s| s.clone())
        .unwrap_or(AppState::Disconnected);
    let (configured, pending, autostart) = ctx
        .config
        .try_read()
        .map(|c| (c.is_configured(), c.device_status == "pending", c.autostart))
        .unwrap_or((false, false, false));
    Snapshot {
        status: status_of(&state, configured, pending),
        devices: 0,
        online: 0,
        autostart,
        // Registered after the tray, which then refreshes
        shortcut: None,
        clips: Vec::new(),
    }
}

async fn snapshot(app: &AppHandle) -> Snapshot {
    let ctx = app.state::<AppContext>();
    let state = ctx.state.read().await.clone();
    let (configured, pending, autostart) = {
        let config = ctx.config.read().await;
        (
            config.is_configured(),
            config.device_status == "pending",
            config.autostart,
        )
    };
    let (devices, online) = {
        let devices = ctx.devices.read().await;
        (devices.len(), devices.iter().filter(|d| d.online).count())
    };
    let status = status_of(&state, configured, pending);
    let clips = if matches!(status, Status::SignedOut | Status::Pending) {
        Vec::new()
    } else {
        commands::get_history(app.state(), 0, RECENT_CLIPS)
            .await
            .map(|page| {
                page.entries
                    .into_iter()
                    .map(|e| (e.id, clip_label(&e.preview)))
                    .collect()
            })
            .unwrap_or_default()
    };
    Snapshot {
        status,
        devices,
        online,
        autostart,
        shortcut: crate::shortcut::active(app),
        clips,
    }
}

fn icon(live: bool) -> Image<'static> {
    static LIVE: OnceLock<Image<'static>> = OnceLock::new();
    static IDLE: OnceLock<Image<'static>> = OnceLock::new();
    let (cell, bytes) = if live {
        (&LIVE, LIVE_ICON)
    } else {
        (&IDLE, IDLE_ICON)
    };
    cell.get_or_init(|| decode_icon(bytes)).clone()
}

fn decode_icon(bytes: &[u8]) -> Image<'static> {
    let rgba = image::load_from_memory(bytes)
        .expect("bundled tray icon is a valid PNG")
        .into_rgba8();
    let (width, height) = rgba.dimensions();
    Image::new(rgba.as_raw(), width, height).to_owned()
}

fn build_menu(app: &AppHandle, snapshot: &Snapshot) -> tauri::Result<Menu<Wry>> {
    let status = MenuItemBuilder::with_id("tray:status", status_text(snapshot))
        .enabled(false)
        .build(app)?;
    let signed_in = !matches!(snapshot.status, Status::SignedOut);
    let open_label = if signed_in {
        "Open cpmesh"
    } else {
        "Sign In…"
    };
    let open_item = |accelerator: Option<&str>| {
        let mut item = MenuItemBuilder::with_id("tray:open", open_label);
        if let Some(accelerator) = accelerator {
            item = item.accelerator(accelerator);
        }
        item.build(app)
    };
    // A shortcut the menu can't spell is left out rather than losing the menu
    let open = open_item(snapshot.shortcut.as_deref()).or_else(|e| {
        log::warn!("The tray menu can't show the shortcut: {e}");
        open_item(None)
    })?;
    let autostart = CheckMenuItemBuilder::with_id("tray:autostart", "Open at Login")
        .checked(snapshot.autostart)
        .build(app)?;
    let quit = MenuItemBuilder::with_id("tray:quit", "Quit cpmesh")
        .accelerator("CmdOrCtrl+Q")
        .build(app)?;

    let mut menu = MenuBuilder::new(app).item(&status).separator().item(&open);

    if matches!(
        snapshot.status,
        Status::Live | Status::Offline | Status::Connecting
    ) {
        let mut clips = SubmenuBuilder::new(app, "Recent Clips");
        if snapshot.clips.is_empty() {
            clips = clips.item(
                &MenuItemBuilder::with_id("tray:no-clips", "Nothing copied yet")
                    .enabled(false)
                    .build(app)?,
            );
        }
        for (id, label) in &snapshot.clips {
            clips =
                clips.item(&MenuItemBuilder::with_id(format!("tray:clip:{id}"), label).build(app)?);
        }
        let clips = clips
            .separator()
            .item(&MenuItemBuilder::with_id("tray:nav:/history", "Show All History…").build(app)?)
            .build()?;

        let (toggle_id, toggle_label) = match snapshot.status {
            Status::Live => ("tray:disconnect", "Disconnect"),
            Status::Connecting => ("tray:disconnect", "Stop Connecting"),
            _ => ("tray:connect", "Connect"),
        };
        let toggle = MenuItemBuilder::with_id(toggle_id, toggle_label).build(app)?;
        let devices = MenuItemBuilder::with_id("tray:nav:/devices", "Devices…").build(app)?;
        let settings = MenuItemBuilder::with_id("tray:nav:/settings", "Settings…")
            .accelerator("CmdOrCtrl+,")
            .build(app)?;

        menu = menu
            .item(&clips)
            .separator()
            .item(&toggle)
            .separator()
            .item(&devices)
            .item(&settings);
    }

    menu.separator()
        .item(&autostart)
        .separator()
        .item(&quit)
        .build()
}

fn render(app: &AppHandle, snapshot: Snapshot) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    match build_menu(app, &snapshot) {
        Ok(menu) => {
            if let Err(e) = tray.set_menu(Some(menu)) {
                log::error!("Failed to update the tray menu: {e}");
            }
        }
        Err(e) => {
            log::error!("Failed to build the tray menu: {e}");
            return;
        }
    }
    let _ = tray.set_icon(Some(icon(snapshot.status == Status::Live)));
    #[cfg(target_os = "macos")]
    let _ = tray.set_icon_as_template(true);
    let _ = tray.set_tooltip(Some(format!("cpmesh — {}", status_text(&snapshot))));
    if let Ok(mut rendered) = RENDERED.lock() {
        *rendered = Some(snapshot);
    }
}

async fn refresh(app: &AppHandle) {
    let _serialized = REFRESH
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let snapshot = snapshot(app).await;
    let unchanged = RENDERED
        .lock()
        .map(|rendered| rendered.as_ref() == Some(&snapshot))
        .unwrap_or(false);
    if !unchanged {
        render(app, snapshot);
    }
}

/// Brings the tray up to date with the app; cheap when nothing changed.
pub fn schedule_refresh(app: &AppHandle) {
    if !TRAY_READY.load(Ordering::Acquire) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move { refresh(&app).await });
}

/// Whether the tray is up, so closing the window can leave cpmesh running.
pub fn is_ready() -> bool {
    TRAY_READY.load(Ordering::Acquire)
}

pub fn setup(app: &tauri::App) -> tauri::Result<()> {
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon(false))
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip("cpmesh")
        // Menu bar items open their menu on click; Windows trays open the app instead
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
                && !cfg!(target_os = "macos")
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    // Linux trays only appear once they have a menu, so the first one is built now
    render(app.handle(), snapshot_now(&app.state::<AppContext>()));
    TRAY_READY.store(true, Ordering::Release);

    for event in [
        "connection-state-changed",
        "device-status-changed",
        "clipboard-new",
        "history-synced",
        "config-changed",
    ] {
        let handle = app.handle().clone();
        app.listen(event, move |_| schedule_refresh(&handle));
    }
    schedule_refresh(app.handle());
    Ok(())
}

pub fn show_main_window(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_dock_visibility(true);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Hides the window; on macOS cpmesh also leaves the Dock and lives in the menu bar.
pub fn hide_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = app.set_dock_visibility(false);
        // macOS ignores hiding the Dock icon within a second of showing it, so try
        // again once that has passed if the window is still hidden
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            let hidden = app
                .get_webview_window("main")
                .is_none_or(|w| !w.is_visible().unwrap_or(true));
            if hidden {
                let _ = app.set_dock_visibility(false);
            }
        });
    }
}

/// Tells the user, once, that closing the window left cpmesh running.
pub fn announce_background(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let ctx = app.state::<AppContext>();
        if !ctx.config.read().await.notifications_enabled {
            return;
        }
        let marker = ctx.config_dir.join(BACKGROUND_NOTICE_MARKER);
        if marker.exists() || std::fs::write(&marker, b"").is_err() {
            return;
        }
        let place = if cfg!(target_os = "macos") {
            "menu bar"
        } else {
            "system tray"
        };
        use tauri_plugin_notification::NotificationExt;
        let _ = app
            .notification()
            .builder()
            .title("cpmesh is still running")
            .body(format!(
                "It keeps syncing in the background. Open it again from the cpmesh icon in the {place}."
            ))
            .show();
    });
}

fn navigate(app: &AppHandle, path: &str) {
    if !ROUTES.contains(&path) {
        return;
    }
    show_main_window(app);
    let _ = app.emit("navigate", path);
}

/// Handles the tray menu and the app menu's own items (ids `tray:*` and `app:*`).
pub fn handle_menu_event(app: &AppHandle, event: MenuEvent) {
    let id = event.id().as_ref();
    let Some(action) = id.strip_prefix("tray:").or_else(|| id.strip_prefix("app:")) else {
        return;
    };
    match action {
        "open" => show_main_window(app),
        "settings" => navigate(app, "/settings"),
        "quit" => app.exit(0),
        "connect" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = commands::connect(app.clone(), app.state()).await {
                    log::error!("Connect from the tray failed: {error}");
                    let _ = app.emit("sync-error", error);
                }
            });
        }
        "disconnect" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = commands::disconnect(app.clone(), app.state()).await {
                    log::error!("Disconnect from the tray failed: {error}");
                }
            });
        }
        "autostart" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let enable = !app.state::<AppContext>().config.read().await.autostart;
                if let Err(error) = commands::update_config(
                    app.clone(),
                    app.state(),
                    None,
                    None,
                    Some(enable),
                    None,
                )
                .await
                {
                    log::error!("Changing Open at Login failed: {error}");
                }
                // The check mark toggled itself; put it back in step with the config
                if let Ok(mut rendered) = RENDERED.lock() {
                    *rendered = None;
                }
                schedule_refresh(&app);
            });
        }
        other => {
            if let Some(path) = other.strip_prefix("nav:") {
                navigate(app, path);
            } else if let Some(entry_id) = other.strip_prefix("clip:") {
                let app = app.clone();
                let entry_id = entry_id.to_string();
                tauri::async_runtime::spawn(async move {
                    if let Err(error) =
                        commands::copy_entry(app.clone(), app.state(), entry_id).await
                    {
                        log::error!("Copying a recent clip failed: {error}");
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(status: Status, devices: usize, online: usize) -> Snapshot {
        Snapshot {
            status,
            devices,
            online,
            autostart: false,
            shortcut: None,
            clips: Vec::new(),
        }
    }

    #[test]
    fn status_follows_account_approval_and_connection() {
        assert_eq!(
            status_of(&AppState::Connected, false, false),
            Status::SignedOut
        );
        assert_eq!(
            status_of(&AppState::NotConfigured, true, false),
            Status::SignedOut
        );
        assert_eq!(status_of(&AppState::Connected, true, true), Status::Pending);
        assert_eq!(status_of(&AppState::Connected, true, false), Status::Live);
        assert_eq!(
            status_of(&AppState::Connecting, true, false),
            Status::Connecting
        );
        assert_eq!(
            status_of(&AppState::Disconnected, true, false),
            Status::Offline
        );
    }

    #[test]
    fn status_text_counts_devices_only_when_there_are_others() {
        assert_eq!(status_text(&snapshot(Status::Live, 1, 1)), "Syncing");
        assert_eq!(
            status_text(&snapshot(Status::Live, 3, 2)),
            "Syncing — 2 of 3 devices online"
        );
        assert_eq!(
            status_text(&snapshot(Status::Live, 2, 5)),
            "Syncing — 2 of 2 devices online"
        );
        assert_eq!(
            status_text(&snapshot(Status::Offline, 3, 0)),
            "Offline — sync paused"
        );
    }

    #[test]
    fn clip_labels_fit_a_menu() {
        assert_eq!(clip_label("hello"), "hello");
        assert_eq!(clip_label("  \n  first line\nsecond"), "first line…");
        assert_eq!(clip_label(""), "Empty clip");
        assert_eq!(clip_label("Tom & Jerry"), "Tom && Jerry");
        let long = "x".repeat(80);
        let label = clip_label(&long);
        assert_eq!(label.chars().count(), CLIP_LABEL_CHARS + 1);
        assert!(label.ends_with('…'));
    }

    #[test]
    fn bundled_icons_decode() {
        for bytes in [LIVE_ICON, IDLE_ICON] {
            let image = decode_icon(bytes);
            assert!(image.width() > 0 && image.width() == image.height());
        }
    }
}
