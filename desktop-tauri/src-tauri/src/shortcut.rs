//! The global shortcut that brings cpmesh forward from any app. It is saved in the
//! config as an accelerator ("CmdOrCtrl+Shift+Space"), registered with the system while
//! cpmesh runs, shown next to "Open cpmesh" in the tray menu and changed from Settings.

use std::sync::{Mutex, PoisonError};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::commands::AppContext;
use crate::config::DEFAULT_GLOBAL_HOTKEY;

/// Whether ⌘ (rather than Ctrl) is the primary modifier.
const MAC: bool = cfg!(target_os = "macos");

/// ⌘ on macOS, Ctrl elsewhere.
const PRIMARY: u8 = 1;
/// ⌃ on macOS; elsewhere Ctrl is [`PRIMARY`].
const CONTROL: u8 = 1 << 1;
const ALT: u8 = 1 << 2;
const SHIFT: u8 = 1 << 3;
/// The Windows or Super key; on macOS ⌘ is [`PRIMARY`].
const SUPER: u8 = 1 << 4;

/// Modifiers in the order a saved shortcut lists them.
const MODIFIERS: [(u8, &str); 5] = [
    (PRIMARY, "CmdOrCtrl"),
    (CONTROL, "Control"),
    (ALT, "Alt"),
    (SHIFT, "Shift"),
    (SUPER, "Super"),
];

/// Keys a shortcut can end with besides letters, digits, F1–F24 and the numpad digits,
/// spelled like `KeyboardEvent.code`, with the other spellings accepted for them.
const NAMED_KEYS: &[(&str, &[&str])] = &[
    ("Space", &[]),
    ("Enter", &["return"]),
    ("Tab", &[]),
    ("Backspace", &[]),
    ("Delete", &[]),
    ("Insert", &[]),
    ("Home", &[]),
    ("End", &[]),
    ("PageUp", &[]),
    ("PageDown", &[]),
    ("ArrowUp", &["up"]),
    ("ArrowDown", &["down"]),
    ("ArrowLeft", &["left"]),
    ("ArrowRight", &["right"]),
    ("Escape", &["esc"]),
    ("Backquote", &["`"]),
    ("Minus", &["-"]),
    ("Equal", &["="]),
    ("BracketLeft", &["["]),
    ("BracketRight", &["]"]),
    ("Backslash", &["\\"]),
    ("Semicolon", &[";"]),
    ("Quote", &["'"]),
    ("Comma", &[","]),
    ("Period", &["."]),
    ("Slash", &["/"]),
    ("NumpadAdd", &[]),
    ("NumpadSubtract", &[]),
    ("NumpadMultiply", &[]),
    ("NumpadDivide", &[]),
    ("NumpadDecimal", &[]),
    ("NumpadEnter", &[]),
    ("PrintScreen", &[]),
    ("ScrollLock", &[]),
    ("Pause", &[]),
];

const FORMAT_ERROR: &str =
    "A shortcut is one or more modifier keys and then one other key, like Ctrl+Shift+Space.";
const KEY_ERROR: &str = "That key can’t be part of a shortcut.";

fn needs_modifier(mac: bool) -> String {
    let keys = if mac {
        "⌘, ⌥ or ⌃"
    } else {
        "Ctrl or Alt"
    };
    format!("Include {keys} so the shortcut doesn’t get in the way of typing.")
}

/// Checks a shortcut and spells it the way cpmesh saves it: modifiers in a fixed order,
/// then one key. "ctrl+shift+keyv" becomes "CmdOrCtrl+Shift+V" outside macOS, where
/// Ctrl is the primary modifier; on macOS (`mac`) Ctrl is "Control" and Cmd "CmdOrCtrl".
/// Only F1–F24 work without ⌘/Ctrl, ⌥/Alt, ⌃ or Super, so typing is never captured.
pub fn normalize(shortcut: &str, mac: bool) -> Result<String, String> {
    let tokens: Vec<&str> = shortcut.split('+').map(str::trim).collect();
    let Some((&key, modifiers)) = tokens.split_last() else {
        return Err(FORMAT_ERROR.into());
    };
    if tokens.iter().any(|token| token.is_empty()) {
        return Err(FORMAT_ERROR.into());
    }
    let mut held = 0;
    for token in modifiers {
        held |= modifier(token, mac).ok_or(FORMAT_ERROR)?;
    }
    if modifier(key, mac).is_some() {
        return Err(FORMAT_ERROR.into());
    }
    let key = key_name(key).ok_or(KEY_ERROR)?;
    if held & !SHIFT == 0 && !is_function_key(&key) {
        return Err(needs_modifier(mac));
    }
    let mut parts: Vec<&str> = MODIFIERS
        .iter()
        .filter(|(bit, _)| held & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    parts.push(&key);
    Ok(parts.join("+"))
}

fn modifier(token: &str, mac: bool) -> Option<u8> {
    Some(match token.to_ascii_lowercase().as_str() {
        "cmdorctrl" | "cmdorcontrol" | "commandorctrl" | "commandorcontrol" => PRIMARY,
        "ctrl" | "control" if mac => CONTROL,
        "ctrl" | "control" => PRIMARY,
        "cmd" | "command" | "super" | "meta" if mac => PRIMARY,
        "cmd" | "command" | "super" | "meta" => SUPER,
        "alt" | "option" => ALT,
        "shift" => SHIFT,
        _ => return None,
    })
}

/// The saved name of a key, or None when it can't end a shortcut.
fn key_name(token: &str) -> Option<String> {
    let lower = token.to_ascii_lowercase();
    // Letters and digits, alone or spelled like `KeyboardEvent.code` ("KeyV", "Digit1")
    let bare = lower
        .strip_prefix("key")
        .filter(|rest| single(rest, |c| c.is_ascii_lowercase()))
        .or_else(|| {
            lower
                .strip_prefix("digit")
                .filter(|rest| single(rest, |c| c.is_ascii_digit()))
        })
        .unwrap_or(&lower);
    if single(bare, |c| c.is_ascii_alphanumeric()) {
        return Some(bare.to_ascii_uppercase());
    }
    if let Some(number) = lower
        .strip_prefix('f')
        .and_then(|number| number.parse::<u8>().ok())
        .filter(|number| (1..=24).contains(number))
    {
        return Some(format!("F{number}"));
    }
    if let Some(digit) = lower
        .strip_prefix("numpad")
        .filter(|rest| single(rest, |c| c.is_ascii_digit()))
    {
        return Some(format!("Numpad{digit}"));
    }
    NAMED_KEYS
        .iter()
        .find(|(name, aliases)| name.eq_ignore_ascii_case(&lower) || aliases.contains(&&*lower))
        .map(|(name, _)| name.to_string())
}

/// Whether `text` is one character that `accept` allows.
fn single(text: &str, accept: impl Fn(char) -> bool) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(accept) && chars.next().is_none()
}

fn is_function_key(key: &str) -> bool {
    key.strip_prefix('F')
        .is_some_and(|number| number.parse::<u8>().is_ok())
}

/// What Settings shows about the shortcut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShortcutStatus {
    /// The saved shortcut as [`normalize`] spells it; empty when it is turned off.
    pub shortcut: String,
    /// What "Reset" goes back to.
    pub default_shortcut: String,
    /// Whether pressing the shortcut reaches cpmesh right now.
    pub registered: bool,
    /// Why the saved shortcut isn't registered.
    pub error: Option<String>,
    /// Set on Linux Wayland sessions, which may not pass shortcuts on to apps: the command
    /// that shows cpmesh, for a shortcut set up in the desktop's keyboard settings.
    pub launch_command: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Registration {
    shortcut: String,
    registered: bool,
    error: Option<String>,
}

/// The shortcut cpmesh registered, or tried to; managed as app state.
#[derive(Default)]
pub struct GlobalShortcut {
    current: Mutex<Registration>,
    /// One change at a time, so none can leave an extra shortcut registered.
    changing: tokio::sync::Mutex<()>,
}

impl GlobalShortcut {
    fn current(&self) -> Registration {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn replace(&self, registration: Registration) {
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = registration;
    }
}

/// Registers the saved shortcut at startup. One that another app holds doesn't stop
/// cpmesh from starting; Settings explains it instead.
pub fn init(app: &AppHandle) {
    let saved = app
        .state::<AppContext>()
        .config
        .try_read()
        .map(|config| config.global_hotkey.clone())
        .unwrap_or_else(|_| DEFAULT_GLOBAL_HOTKEY.to_string());
    let shortcut = match saved.trim() {
        "" => String::new(),
        saved => normalize(saved, MAC).unwrap_or_else(|e| {
            log::warn!("Using the default shortcut instead of {saved:?}: {e}");
            DEFAULT_GLOBAL_HOTKEY.to_string()
        }),
    };
    let registration =
        switch(app, &Registration::default(), &shortcut).unwrap_or_else(|error| Registration {
            shortcut,
            registered: false,
            error: Some(error),
        });
    app.manage(GlobalShortcut {
        current: Mutex::new(registration),
        ..Default::default()
    });
    crate::tray::schedule_refresh(app);
}

/// The shortcut that shows cpmesh right now, for the tray menu.
pub fn active(app: &AppHandle) -> Option<String> {
    let current = app.try_state::<GlobalShortcut>()?.current();
    current.registered.then_some(current.shortcut)
}

/// Moves the registration from `from` to `to` (empty for none). `to` is registered
/// before `from` is let go, so when the system refuses `to`, `from` keeps working.
fn switch(app: &AppHandle, from: &Registration, to: &str) -> Result<Registration, String> {
    if from.registered && from.shortcut == to {
        return Ok(from.clone());
    }
    if !to.is_empty() {
        register(app, to)?;
    }
    if from.registered {
        unregister(app, &from.shortcut);
    }
    Ok(Registration {
        shortcut: to.to_string(),
        registered: !to.is_empty(),
        error: None,
    })
}

fn register(app: &AppHandle, shortcut: &str) -> Result<(), String> {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
    app.global_shortcut()
        .on_shortcut(shortcut, |app, _shortcut, event| {
            if event.state == ShortcutState::Pressed {
                crate::tray::show_main_window(app);
            }
        })
        .map_err(|e| {
            log::warn!("Failed to register the global shortcut {shortcut}: {e}");
            failure_reason(&e.to_string())
        })
}

fn unregister(app: &AppHandle, shortcut: &str) {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;
    if let Err(e) = app.global_shortcut().unregister(shortcut) {
        log::warn!("Failed to unregister the global shortcut {shortcut}: {e}");
    }
    // global-hotkey's X11 backend queues the ungrab without sending it, which would keep
    // the keys from other apps; the key lookup in a second call is a round trip that sends it
    #[cfg(target_os = "linux")]
    let _ = app.global_shortcut().unregister(shortcut);
}

/// What a refused registration means for the user.
fn failure_reason(error: &str) -> String {
    if error.to_ascii_lowercase().contains("already registered") {
        "Another app is already using it.".into()
    } else {
        "Your system didn’t accept it.".into()
    }
}

fn status(app: &AppHandle) -> ShortcutStatus {
    let current = app
        .try_state::<GlobalShortcut>()
        .map(|shortcut| shortcut.current())
        .unwrap_or_default();
    ShortcutStatus {
        shortcut: current.shortcut,
        default_shortcut: DEFAULT_GLOBAL_HOTKEY.to_string(),
        registered: current.registered,
        error: current.error,
        launch_command: launch_command(app),
    }
}

/// On Linux Wayland sessions, the command that starts cpmesh, or shows it while it
/// runs (a second launch hands over to the running app).
fn launch_command(app: &AppHandle) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let wayland = std::env::var("XDG_SESSION_TYPE")
            .is_ok_and(|session| session.eq_ignore_ascii_case("wayland"))
            || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|display| !display.is_empty());
        if !wayland {
            return None;
        }
        // An AppImage runs from a mount that changes every launch; the file itself stays
        let program = app
            .env()
            .appimage
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::current_exe().ok())?;
        Some(shell_quote(&program.to_string_lossy()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        None
    }
}

/// `text` as a single word for a POSIX shell.
#[cfg(any(target_os = "linux", test))]
fn shell_quote(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+=:@%,".contains(c));
    if plain {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

async fn save(ctx: &AppContext, shortcut: &str) -> Result<(), String> {
    let mut config = ctx.config.write().await;
    if config.global_hotkey == shortcut {
        return Ok(());
    }
    let previous = std::mem::replace(&mut config.global_hotkey, shortcut.to_string());
    config.save(&ctx.config_dir).map_err(|e| {
        config.global_hotkey = previous;
        format!("The settings file couldn’t be saved: {e}")
    })
}

#[tauri::command]
pub async fn get_global_shortcut(app: AppHandle) -> ShortcutStatus {
    status(&app)
}

/// Changes the shortcut to `shortcut`, an accelerator like "CmdOrCtrl+Shift+V", or turns
/// it off when empty. Setting the saved shortcut again retries one that failed.
#[tauri::command]
pub async fn set_global_shortcut(
    app: AppHandle,
    ctx: State<'_, AppContext>,
    shortcut: String,
) -> Result<ShortcutStatus, String> {
    let wanted = match shortcut.trim() {
        "" => String::new(),
        shortcut => normalize(shortcut, MAC)?,
    };
    let manager = app
        .try_state::<GlobalShortcut>()
        .ok_or("Shortcuts aren’t ready yet. Try again in a moment.")?;
    let _changing = manager.changing.lock().await;
    let current = manager.current();
    let next = switch(&app, &current, &wanted)?;
    if let Err(error) = save(&ctx, &wanted).await {
        // Back to the shortcut the config still has
        let restored =
            switch(&app, &next, &current.shortcut).unwrap_or_else(|reason| Registration {
                shortcut: current.shortcut.clone(),
                registered: false,
                error: Some(reason),
            });
        manager.replace(restored);
        return Err(error);
    }
    manager.replace(next);
    let _ = app.emit("config-changed", ());
    Ok(status(&app))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn shortcuts_are_saved_one_way() {
        for mac in [false, true] {
            assert_eq!(
                normalize(DEFAULT_GLOBAL_HOTKEY, mac).unwrap(),
                DEFAULT_GLOBAL_HOTKEY
            );
            assert_eq!(
                normalize(" shift + cmdorctrl + keyv ", mac).unwrap(),
                "CmdOrCtrl+Shift+V"
            );
            assert_eq!(
                normalize("CommandOrControl+Alt+digit1", mac).unwrap(),
                "CmdOrCtrl+Alt+1"
            );
            assert_eq!(normalize("Alt+`", mac).unwrap(), "Alt+Backquote");
            assert_eq!(normalize("option+up", mac).unwrap(), "Alt+ArrowUp");
            assert_eq!(
                normalize("alt+shift+numpad5", mac).unwrap(),
                "Alt+Shift+Numpad5"
            );
            assert_eq!(normalize("Alt+Return", mac).unwrap(), "Alt+Enter");
        }
    }

    #[test]
    fn ctrl_and_super_depend_on_the_platform() {
        assert_eq!(
            normalize("Ctrl+Shift+Space", false).unwrap(),
            "CmdOrCtrl+Shift+Space"
        );
        assert_eq!(
            normalize("Ctrl+Shift+Space", true).unwrap(),
            "Control+Shift+Space"
        );
        assert_eq!(normalize("Super+V", false).unwrap(), "Super+V");
        assert_eq!(normalize("Cmd+V", true).unwrap(), "CmdOrCtrl+V");
        assert_eq!(
            normalize("Control+Command+K", true).unwrap(),
            "CmdOrCtrl+Control+K"
        );
    }

    #[test]
    fn only_function_keys_work_without_a_modifier() {
        assert_eq!(normalize("F9", false).unwrap(), "F9");
        assert_eq!(normalize("shift+f24", true).unwrap(), "Shift+F24");
        for typing in ["V", "Shift+V", "Space", "Shift+Enter", "5"] {
            let error = normalize(typing, false).unwrap_err();
            assert!(error.contains("Ctrl or Alt"), "{typing}: {error}");
        }
        assert!(normalize("Shift+V", true).unwrap_err().contains('⌘'));
    }

    #[test]
    fn malformed_shortcuts_are_refused() {
        for bad in [
            "",
            "+",
            "Ctrl+",
            "Ctrl++V",
            "Ctrl+Shift",
            "Ctrl+V+B",
            "Hyper+V",
            "Ctrl+CapsLock",
            "Ctrl+F0",
            "Ctrl+F25",
            "Ctrl+Key",
            "Ctrl+DigitA",
            "Ctrl+é",
            "Ctrl+Plus",
        ] {
            assert!(normalize(bad, false).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn every_key_registers_as_spelled() {
        let mut keys: Vec<String> = ('A'..='Z').chain('0'..='9').map(String::from).collect();
        keys.extend((1..=24).map(|n| format!("F{n}")));
        keys.extend((0..=9).map(|n| format!("Numpad{n}")));
        keys.extend(NAMED_KEYS.iter().map(|(name, _)| name.to_string()));
        for key in keys {
            assert_eq!(
                normalize(&format!("Alt+{key}"), false).unwrap(),
                format!("Alt+{key}")
            );
            for mac in [false, true] {
                let shortcut = normalize(&format!("CmdOrCtrl+Alt+Shift+{key}"), mac).unwrap();
                tauri_plugin_global_shortcut::Shortcut::from_str(&shortcut)
                    .unwrap_or_else(|e| panic!("{shortcut}: {e}"));
            }
        }
    }

    #[test]
    fn refused_registrations_are_explained() {
        assert_eq!(
            failure_reason("HotKey already registered: HotKey { mods: SHIFT, key: Space }"),
            "Another app is already using it."
        );
        assert_eq!(
            failure_reason("Unable to register hotkey: RegisterEventHotKey failed for Space"),
            "Your system didn’t accept it."
        );
    }

    #[test]
    fn launch_commands_are_one_shell_word() {
        assert_eq!(shell_quote("/usr/bin/cpmesh"), "/usr/bin/cpmesh");
        assert_eq!(
            shell_quote("/home/me/Apps/cpmesh 0.4.AppImage"),
            "'/home/me/Apps/cpmesh 0.4.AppImage'"
        );
        assert_eq!(shell_quote("/tmp/it's"), r"'/tmp/it'\''s'");
    }
}
