//! Hands over to a newer cpmesh installed over the running one.
//!
//! Closing the window leaves cpmesh running in the tray, so an update (a package
//! upgrade, the in-app updater's installer, a replaced AppImage) leaves the previous
//! version running from an executable that has since been replaced. Opening cpmesh
//! again would only bring that version back: the single-instance plugin hands every
//! launch to the running process. So the running process remembers the executable it
//! started from, and when a launch arrives after that file changed, it exits and
//! starts the new version with the launch's arguments instead.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use tauri::{AppHandle, Emitter, Manager};

/// How often a running cpmesh looks for a newer version installed over it.
const UPDATE_POLL: Duration = Duration::from_secs(30);

/// The executable this process started from, as it was then.
static STARTED: OnceLock<Option<(PathBuf, Stamp)>> = OnceLock::new();
/// The arguments to start the new version with, once this process has exited.
static RELAUNCH_ARGS: Mutex<Option<Vec<OsString>>> = Mutex::new(None);
static UPDATE_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Tells one build of the executable on disk from another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    /// Device and inode: package managers install a new file instead of rewriting the old one
    #[cfg(unix)]
    file: (u64, u64),
}

impl Stamp {
    fn of(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        Ok(Stamp {
            len: meta.len(),
            modified: meta.modified().ok(),
            #[cfg(unix)]
            file: {
                use std::os::unix::fs::MetadataExt;
                (meta.dev(), meta.ino())
            },
        })
    }
}

/// Remembers the executable this process runs from (the AppImage, for an AppImage).
/// Called first thing, before the file could change.
pub fn record_start(env: &tauri::Env) {
    STARTED.get_or_init(|| {
        let path = tauri::process::current_binary(env).ok()?;
        let stamp = Stamp::of(&path).ok()?;
        Some((path, stamp))
    });
}

/// The executable now at `path`, if it is not the one that was there at `started`. A
/// missing file was uninstalled rather than updated: there is nothing to start.
fn replacement(path: &Path, started: &Stamp) -> Option<Stamp> {
    Stamp::of(path).ok().filter(|now| now != started)
}

/// Whether a different build was installed where this process started from.
pub fn binary_replaced() -> bool {
    matches!(STARTED.get(), Some(Some((path, started))) if replacement(path, started).is_some())
}

fn is_link(arg: &OsStr) -> bool {
    arg.to_string_lossy().starts_with("cpmesh://")
}

/// Launches that carry a cpmesh:// link (a browser handing back a sign-in) belong to
/// the running instance, which started that sign-in.
pub fn is_link_launch<S: AsRef<OsStr>>(args: &[S]) -> bool {
    args.iter().any(|arg| is_link(arg.as_ref()))
}

/// Exits so that the version on disk starts with `args` (program name first).
pub fn relaunch(app: &AppHandle, args: Vec<OsString>) {
    log::info!("Restarting into the cpmesh installed on disk");
    *RELAUNCH_ARGS.lock().unwrap_or_else(|e| e.into_inner()) = Some(args);
    app.exit(0);
}

/// For a launch the single-instance plugin handed to this process: if a newer version
/// was installed since this one started, exits so that it starts instead, with the
/// launch's arguments. Returns whether it did.
pub fn relaunch_if_updated(app: &AppHandle, argv: &[String]) -> bool {
    if is_link_launch(argv) || !binary_replaced() {
        return false;
    }
    relaunch(app, argv.iter().map(OsString::from).collect());
    true
}

/// This process's arguments for a restart the user asked for: without
/// `--background`, so the window opens, and without a sign-in link already handled.
pub fn foreground_args() -> Vec<OsString> {
    without_background(std::env::args_os())
}

fn without_background(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    args.into_iter()
        .enumerate()
        .filter(|(i, arg)| *i == 0 || (arg != crate::tray::BACKGROUND_ARG && !is_link(arg)))
        .map(|(_, arg)| arg)
        .collect()
}

/// For `RunEvent::Exit`: starts the new version if [`relaunch`] asked for it. Plugins
/// handle Exit before the app's callback, so the single-instance plugin has released
/// its lock (D-Bus name, socket or mutex) by now, and the new process doesn't hand its
/// launch back to this one.
pub fn on_exit(app: &AppHandle) {
    let Some(args) = RELAUNCH_ARGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    else {
        return;
    };
    let mut env = app.env();
    env.args_os = args;
    app.cleanup_before_exit();
    tauri::process::restart(&env);
}

/// Watches for a newer version installed over this one, so the window can offer a
/// restart. A changed file counts once it stayed the same for a whole interval, so
/// one still being copied is not mistaken for an update.
pub fn watch_for_update(app: AppHandle) {
    let Some(Some((path, started))) = STARTED.get() else {
        return;
    };
    tauri::async_runtime::spawn(async move {
        let mut candidate = None;
        loop {
            tokio::time::sleep(UPDATE_POLL).await;
            let now = replacement(path, started);
            if now.is_some() && now == candidate {
                UPDATE_INSTALLED.store(true, Ordering::Release);
                log::info!("A newer cpmesh was installed; it starts after a restart");
                let _ = app.emit("update-installed", ());
                return;
            }
            candidate = now;
        }
    });
}

/// Whether [`watch_for_update`] found a newer version installed over this one.
pub fn update_installed() -> bool {
    UPDATE_INSTALLED.load(Ordering::Acquire)
}

/// Ends cpmesh processes that still run an executable this one was installed over, so
/// that this launch starts instead of being handed to them. A package upgrade puts a
/// new file in place of the old one, which the kernel then reports as deleted for the
/// processes still running it. Versions from before [`relaunch_if_updated`] never
/// restart by themselves, so without this an update would only take effect once they
/// quit. Only the launching user's own processes are ended, even when cpmesh runs as
/// root. An AppImage is a separate file, and links belong to the running instance
/// (see [`is_link_launch`]), so both are left alone.
#[cfg(target_os = "linux")]
pub fn end_outdated_instances(env: &tauri::Env) {
    if env.appimage.is_some() || is_link_launch(&env.args_os) {
        return;
    }
    let Ok(exe) = tauri::process::current_binary(env) else {
        return;
    };
    let outdated = outdated_processes(
        Path::new("/proc"),
        &exe,
        std::process::id(),
        rustix::process::geteuid().as_raw(),
    );
    if outdated.is_empty() {
        return;
    }
    for pid in &outdated {
        log::info!("Ending cpmesh process {pid}: it still runs the version this one replaced");
        terminate(*pid);
    }
    // Its single-instance D-Bus name is released when the process is gone
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while outdated.iter().any(|pid| is_running(*pid)) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(200));
}

/// Processes other than `own` that run as user `uid` and whose executable is `exe` as it
/// was before being replaced. The kernel gives a process's `/proc/<pid>` folder to its
/// effective user, so that is whose processes they are; anyone else's are never
/// returned, whatever they run.
#[cfg(target_os = "linux")]
fn outdated_processes(proc: &Path, exe: &Path, own: u32, uid: u32) -> Vec<u32> {
    use std::os::unix::fs::MetadataExt;

    let mut replaced = exe.as_os_str().to_os_string();
    replaced.push(" (deleted)");
    let Ok(entries) = std::fs::read_dir(proc) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            if pid == own || entry.metadata().ok()?.uid() != uid {
                return None;
            }
            let running = std::fs::read_link(entry.path().join("exe")).ok()?;
            (running.as_os_str() == replaced).then_some(pid)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn terminate(pid: u32) {
    let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return;
    };
    if let Err(e) = rustix::process::kill_process(pid, rustix::process::Signal::TERM) {
        log::warn!("Could not end the outdated cpmesh process: {e}");
    }
}

/// Exited processes, zombies included, no longer have an executable.
#[cfg(target_os = "linux")]
fn is_running(pid: u32) -> bool {
    std::fs::read_link(format!("/proc/{pid}/exe")).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_file_in_place_of_the_executable_is_a_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("cpmesh-desktop");
        std::fs::write(&exe, b"version 1").unwrap();
        let started = Stamp::of(&exe).unwrap();
        assert_eq!(replacement(&exe, &started), None);

        // How package managers install: a new file renamed over the old one
        let staged = dir.path().join("cpmesh-desktop.dpkg-new");
        std::fs::write(&staged, b"version 2, a little larger").unwrap();
        std::fs::rename(&staged, &exe).unwrap();
        assert!(replacement(&exe, &started).is_some());

        // Uninstalled: nothing to start
        std::fs::remove_file(&exe).unwrap();
        assert_eq!(replacement(&exe, &started), None);
    }

    #[test]
    fn only_plain_launches_restart_into_the_new_version() {
        assert!(is_link_launch(&[
            "/usr/bin/cpmesh-desktop",
            "cpmesh://auth/callback?code=abc"
        ]));
        assert!(!is_link_launch(&["/usr/bin/cpmesh-desktop"]));
        assert!(!is_link_launch(&[
            "/usr/bin/cpmesh-desktop",
            "--background"
        ]));
    }

    #[test]
    fn a_restart_the_user_asked_for_opens_the_window() {
        let args = without_background(
            [
                "/usr/bin/cpmesh-desktop",
                "--background",
                "cpmesh://auth/callback?code=used",
                "--other",
            ]
            .map(OsString::from),
        );
        assert_eq!(
            args,
            ["/usr/bin/cpmesh-desktop", "--other"].map(OsString::from)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_processes_still_running_a_replaced_executable() {
        use std::os::unix::fs::MetadataExt;

        let proc = tempfile::tempdir().unwrap();
        let link = |pid: &str, target: &str| {
            std::fs::create_dir(proc.path().join(pid)).unwrap();
            std::os::unix::fs::symlink(target, proc.path().join(pid).join("exe")).unwrap();
        };
        link("100", "/usr/bin/cpmesh-desktop (deleted)");
        link("200", "/usr/bin/cpmesh-desktop");
        link("300", "/opt/other/cpmesh-desktop (deleted)");
        link("400", "/usr/bin/cpmesh-desktop (deleted)");
        std::fs::create_dir(proc.path().join("self")).unwrap();
        let user = std::fs::metadata(proc.path().join("100")).unwrap().uid();
        let mut found =
            outdated_processes(proc.path(), Path::new("/usr/bin/cpmesh-desktop"), 400, user);
        found.sort();
        assert_eq!(
            found,
            [100],
            "only other processes running the replaced file"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn leaves_other_users_processes_alone() {
        use std::os::unix::fs::MetadataExt;

        let proc = tempfile::tempdir().unwrap();
        let process = proc.path().join("100");
        std::fs::create_dir(&process).unwrap();
        std::os::unix::fs::symlink("/usr/bin/cpmesh-desktop (deleted)", process.join("exe"))
            .unwrap();
        // Like /proc/<pid>, the folder belongs to the user the process runs as
        let user = std::fs::metadata(&process).unwrap().uid();
        let exe = Path::new("/usr/bin/cpmesh-desktop");

        assert_eq!(outdated_processes(proc.path(), exe, 1, user), [100]);
        // Not even a cpmesh running as root ends another user's process
        for other in [0, user.wrapping_add(1)] {
            if other != user {
                assert!(
                    outdated_processes(proc.path(), exe, 1, other).is_empty(),
                    "found by uid {other}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ends_a_process_running_a_replaced_executable() {
        // A child running a copy of the shell, waiting for input, whose executable is
        // then replaced the way a package upgrade does it
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("sh");
        std::fs::copy("/bin/sh", &exe).unwrap();
        let mut child = std::process::Command::new(&exe)
            .args(["-c", "read line"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !std::fs::read_link(format!("/proc/{}/exe", child.id()))
            .is_ok_and(|running| running == exe)
        {
            assert!(std::time::Instant::now() < deadline, "child did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        let staged = dir.path().join("sh.new");
        std::fs::copy("/bin/sh", &staged).unwrap();
        std::fs::rename(&staged, &exe).unwrap();

        let own = std::process::id();
        let user = rustix::process::geteuid().as_raw();
        let found = outdated_processes(Path::new("/proc"), &exe, own, user);
        assert_eq!(found, [child.id()]);
        // The real /proc gives it to this test's user, so for anyone else it isn't there
        assert!(outdated_processes(Path::new("/proc"), &exe, own, user.wrapping_add(1)).is_empty());
        terminate(child.id());
        let status = child.wait().unwrap();
        assert!(!status.success(), "ended by the signal");
        assert!(outdated_processes(Path::new("/proc"), &exe, own, user).is_empty());
    }
}
