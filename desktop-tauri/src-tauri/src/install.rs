//! Installs a verified update over the running cpmesh, which then starts the new version.
//!
//! How depends on how this copy was installed:
//! - Linux .deb package: the package manager upgrades it as root once the user
//!   authenticates in the desktop's password dialog (polkit). Opening the package instead
//!   hands it to an app store, and Ubuntu's App Center only reports an older version of an
//!   installed package as installed.
//! - AppImage: the new AppImage takes the place of this one's file.
//! - macOS: the app on the update's disk image takes the place of this app bundle. An
//!   administrator's password is asked for only when the user can't change its folder.
//! - Windows: the installer updates the installation without asking anything, closes
//!   cpmesh if it still runs and starts the new version.
//!
//! The installer is verified before ([`crate::updater::verify_update`]); this only installs it.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use tauri::AppHandle;

/// How this copy of cpmesh was installed, which decides the installer an update takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Installation {
    /// Linux: the .deb package
    #[cfg(target_os = "linux")]
    Deb,
    /// Linux: the AppImage at this path
    #[cfg(target_os = "linux")]
    AppImage(PathBuf),
    /// macOS: the app bundle at this path
    #[cfg(target_os = "macos")]
    App(PathBuf),
    /// Windows: the installation the NSIS installer made
    #[cfg(windows)]
    Nsis,
}

impl Installation {
    /// This copy of cpmesh, or why it can't install updates itself.
    pub fn detect(env: &tauri::Env) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            use tauri::utils::{config::BundleType, platform::bundle_type};
            // The bundler marks the binary it packages with the package's format
            match (bundle_type(), &env.appimage) {
                (Some(BundleType::Deb), _) => Ok(Installation::Deb),
                (Some(BundleType::AppImage), Some(appimage)) => {
                    Ok(Installation::AppImage(PathBuf::from(appimage)))
                }
                _ => Err(
                    "This copy of cpmesh wasn't installed from its .deb package or \
                     AppImage, so it can't update itself. Update it the way you installed it."
                        .into(),
                ),
            }
        }
        #[cfg(target_os = "macos")]
        {
            let exe = tauri::process::current_binary(env)
                .map_err(|e| format!("Couldn't find the running app: {e}"))?;
            macos::app_bundle(&exe).map(Installation::App)
        }
        #[cfg(windows)]
        {
            let _ = env;
            Ok(Installation::Nsis)
        }
    }

    /// The installer to download, given the one the update check offers. It offers one per
    /// platform, the .deb on Linux, and a release has the AppImage next to it under the
    /// same name.
    pub fn installer_url(&self, offered: &url::Url) -> Result<url::Url, String> {
        #[cfg(target_os = "linux")]
        {
            let extension = match self {
                Installation::Deb => "deb",
                Installation::AppImage(_) => "AppImage",
            };
            linux::package_url(offered, extension)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(offered.clone())
        }
    }

    /// Refuses a verified installer of another kind than this installation takes.
    pub fn check_installer(&self, file_name: &str) -> Result<(), String> {
        let suffix = match self {
            #[cfg(target_os = "linux")]
            Installation::Deb => ".deb",
            #[cfg(target_os = "linux")]
            Installation::AppImage(_) => ".AppImage",
            #[cfg(target_os = "macos")]
            Installation::App(_) => ".dmg",
            #[cfg(windows)]
            Installation::Nsis => "-setup.exe",
        };
        if has_suffix(file_name, suffix) {
            Ok(())
        } else {
            Err(format!(
                "The update ({file_name}) can't be installed here: this copy of cpmesh \
                 updates from its {suffix} installer"
            ))
        }
    }

    /// Installs the verified `installer`. Blocks until it's done, which includes the time
    /// the user takes to authenticate.
    pub fn install(&self, installer: &Path) -> Result<(), String> {
        match self {
            #[cfg(target_os = "linux")]
            Installation::Deb => linux::install_deb(installer),
            #[cfg(target_os = "linux")]
            Installation::AppImage(appimage) => linux::replace_appimage(installer, appimage),
            #[cfg(target_os = "macos")]
            Installation::App(bundle) => macos::install_disk_image(installer, bundle),
            #[cfg(windows)]
            Installation::Nsis => windows::start_installer(installer),
        }
    }
}

/// Whether this is the binary in cpmesh's AppImage. `APPIMAGE` alone doesn't tell: a
/// program started from another AppImage (from its terminal, say) inherits it.
#[cfg(target_os = "linux")]
pub fn is_appimage() -> bool {
    matches!(
        tauri::utils::platform::bundle_type(),
        Some(tauri::utils::config::BundleType::AppImage)
    )
}

/// Hands over to the installed update. On Windows cpmesh exits, and the installer it
/// started replaces it and starts the new version; elsewhere the new version is in place
/// already, and cpmesh restarts into it with its window open.
pub fn hand_over(app: &AppHandle) {
    #[cfg(windows)]
    app.exit(0);
    #[cfg(not(windows))]
    crate::relaunch::relaunch(app, crate::relaunch::foreground_args());
}

static INSTALLING: AtomicBool = AtomicBool::new(false);

/// Held while an update is downloaded and installed, so that one is at a time.
pub struct Installing(());

impl Installing {
    pub fn start() -> Result<Self, String> {
        if INSTALLING.swap(true, Ordering::AcqRel) {
            return Err("The update is being installed already".into());
        }
        Ok(Installing(()))
    }

    /// The update is installed and cpmesh hands over to it: no other starts meanwhile.
    pub fn finish(self) {
        std::mem::forget(self);
    }
}

impl Drop for Installing {
    fn drop(&mut self) {
        INSTALLING.store(false, Ordering::Release);
    }
}

fn has_suffix(name: &str, suffix: &str) -> bool {
    name.to_ascii_lowercase()
        .ends_with(&suffix.to_ascii_lowercase())
}

/// A new hidden path next to `path`, to put its replacement together in: moving that over
/// `path` stays within one folder, so it happens in one step.
#[cfg(unix)]
fn sibling(path: &Path, purpose: &str) -> std::io::Result<PathBuf> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not in a folder", path.display()),
        ));
    };
    let name = name.to_string_lossy();
    Ok(dir.join(format!(".{name}.{purpose}-{}", uuid::Uuid::new_v4())))
}

/// What a failed command's error output says went wrong, short enough to show: its error
/// lines (apt's "E:", dpkg's and pkexec's errors) if it marks any, else its last line.
#[cfg(unix)]
fn failure_detail(output: &str) -> String {
    const LIMIT: usize = 400;
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let errors: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("E:") || line.to_ascii_lowercase().contains("error"))
        .collect();
    let detail = match (errors.is_empty(), lines.last()) {
        (false, _) => errors.join(" "),
        (true, Some(last)) => last.to_string(),
        (true, None) => "no details".to_string(),
    };
    if detail.chars().count() > LIMIT {
        format!("{}…", detail.chars().take(LIMIT).collect::<String>())
    } else {
        detail
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::io::ErrorKind;
    use std::path::Path;
    use std::process::{Command, Stdio};

    use super::failure_detail;

    const APT_GET: &str = "/usr/bin/apt-get";
    const DPKG: &str = "/usr/bin/dpkg";
    const PKEXEC: &str = "/usr/bin/pkexec";

    /// `offered`, a release's Linux package, with `extension` instead of its own.
    pub fn package_url(offered: &url::Url, extension: &str) -> Result<url::Url, String> {
        let path = offered.path();
        let lower = path.to_ascii_lowercase();
        let stem = [".deb", ".appimage", ".rpm"]
            .into_iter()
            .find_map(|own| lower.strip_suffix(own))
            .map(|stem| &path[..stem.len()])
            .ok_or_else(|| format!("The update ({offered}) is not a Linux package"))?;
        let mut url = offered.clone();
        url.set_path(&format!("{stem}.{extension}"));
        Ok(url)
    }

    /// Upgrades cpmesh to `package` with the system's package manager, run as root through
    /// polkit, which asks for the user's password in the desktop's own dialog.
    pub fn install_deb(package: &Path) -> Result<(), String> {
        let command = deb_install_command(package, Path::new(APT_GET).exists());
        log::info!("Installing the update: {PKEXEC} {command:?}");
        let output = Command::new(PKEXEC)
            .args(&command)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| match e.kind() {
                ErrorKind::NotFound => format!(
                    "Installing the update needs pkexec (polkit), which isn't installed. \
                     Install it from a terminal instead: sudo apt install {}",
                    package.display()
                ),
                _ => format!("Couldn't start installing the update: {e}"),
            })?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::info!(
            "pkexec exited with {}\n{}{stderr}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        );
        match output.status.code() {
            Some(0) => Ok(()),
            // pkexec: the user dismissed the password dialog
            Some(126) => Err("The update was not installed: authentication was cancelled".into()),
            // pkexec: not authorized, or no polkit agent to ask the user
            Some(127) => Err(format!(
                "cpmesh wasn't allowed to install the update ({}). \
                 Install it from a terminal instead: sudo apt install {}",
                failure_detail(&stderr),
                package.display()
            )),
            _ => Err(format!(
                "The package manager couldn't install the update: {}",
                failure_detail(&stderr)
            )),
        }
    }

    /// What pkexec runs to install `package` over the installed version. apt also installs
    /// dependencies a new version adds; it removes no package for it, and waits a while for
    /// a busy package manager (unattended upgrades) instead of failing.
    pub fn deb_install_command(package: &Path, apt: bool) -> Vec<OsString> {
        let program: &[&str] = if apt {
            &[
                APT_GET,
                "install",
                "--yes",
                "--no-remove",
                "-o",
                "DPkg::Lock::Timeout=120",
            ]
        } else {
            &[DPKG, "--install"]
        };
        program
            .iter()
            .map(OsString::from)
            .chain([package.as_os_str().to_owned()])
            .collect()
    }

    /// Puts the new AppImage in place of `appimage`. The running AppImage keeps its file
    /// open, so it runs on until cpmesh restarts.
    pub fn replace_appimage(new: &Path, appimage: &Path) -> Result<(), String> {
        replace_file(new, appimage).map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem => format!(
                "cpmesh can't replace {} ({e}). Download the new AppImage from the website \
                 instead.",
                appimage.display()
            ),
            _ => format!("Failed to install the update: {e}"),
        })
    }

    /// Replaces the file at `target` with a copy of `new` in one step, keeping its
    /// permissions.
    pub fn replace_file(new: &Path, target: &Path) -> std::io::Result<()> {
        let permissions = std::fs::metadata(target)?.permissions();
        let staged = super::sibling(target, "update")?;
        let result = std::fs::copy(new, &staged)
            .and_then(|_| std::fs::set_permissions(&staged, permissions))
            .and_then(|()| std::fs::File::open(&staged)?.sync_all())
            .and_then(|()| std::fs::rename(&staged, target));
        if result.is_err() {
            let _ = std::fs::remove_file(&staged);
        }
        result
    }
}

/// Replaces the macOS app bundle. Also compiled into the tests on Linux, which run its file
/// operations.
#[cfg(any(target_os = "macos", all(unix, test)))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod macos {
    use std::io::ErrorKind;
    use std::path::{Component, Path, PathBuf};
    use std::process::{Command, Stdio};

    use super::failure_detail;

    pub const MOVE_TO_APPLICATIONS: &str = "Move cpmesh to your Applications folder and open \
        it from there, then install the update again.";

    /// The app bundle `exe` belongs to (`<bundle>.app/Contents/MacOS/<exe>`).
    pub fn app_bundle(exe: &Path) -> Result<PathBuf, String> {
        let named = |dir: &Path, name: &str| dir.file_name().is_some_and(|n| n == name);
        let bundle = exe
            .parent()
            .filter(|dir| named(dir, "MacOS"))
            .and_then(Path::parent)
            .filter(|dir| named(dir, "Contents"))
            .and_then(Path::parent)
            .filter(|dir| dir.extension().is_some_and(|ext| ext == "app"))
            .ok_or_else(|| format!("cpmesh isn't running from an app ({})", exe.display()))?;
        // An app opened where it was downloaded runs from a read-only copy (App Translocation)
        if bundle
            .components()
            .any(|part| part == Component::Normal("AppTranslocation".as_ref()))
        {
            return Err(MOVE_TO_APPLICATIONS.into());
        }
        Ok(bundle.to_path_buf())
    }

    /// The app on the update's disk image, mounted at `volume`.
    pub fn find_app(volume: &Path) -> Result<PathBuf, String> {
        let entries = std::fs::read_dir(volume)
            .map_err(|e| format!("Failed to read the update's disk image: {e}"))?;
        let apps: Vec<PathBuf> = entries
            .flatten()
            // Not the link to /Applications that the app is dragged onto
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "app"))
            .collect();
        match <[PathBuf; 1]>::try_from(apps) {
            Ok([app]) => Ok(app),
            Err(apps) => Err(format!(
                "The update's disk image holds {} apps instead of one",
                apps.len()
            )),
        }
    }

    /// Replaces `bundle` with the app on the disk image `dmg`.
    pub fn install_disk_image(dmg: &Path, bundle: &Path) -> Result<(), String> {
        let volume = dmg.with_file_name("volume");
        std::fs::create_dir(&volume).map_err(|e| format!("Failed to open the update: {e}"))?;
        // The disk image's signature was checked, so hdiutil needn't verify its checksums
        run(Command::new("/usr/bin/hdiutil")
            .args([
                "attach",
                "-nobrowse",
                "-noautoopen",
                "-noverify",
                "-readonly",
            ])
            .args(["-quiet", "-mountpoint"])
            .arg(&volume)
            .arg(dmg))
        .map_err(|e| format!("Failed to open the update's disk image: {e}"))?;
        let result = find_app(&volume).and_then(|app| replace_bundle(&app, bundle));
        detach(&volume);
        result
    }

    fn detach(volume: &Path) {
        for force in [false, true] {
            let mut command = Command::new("/usr/bin/hdiutil");
            command.args(["detach", "-quiet"]).arg(volume);
            if force {
                command.arg("-force");
            }
            match run(&mut command) {
                Ok(()) => return,
                Err(e) => log::warn!("Couldn't eject the update's disk image: {e}"),
            }
        }
    }

    fn run(command: &mut Command) -> Result<(), String> {
        let output = command
            .stdin(Stdio::null())
            .output()
            .map_err(|e| e.to_string())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(failure_detail(&String::from_utf8_lossy(&output.stderr)))
        }
    }

    /// Puts a copy of `new` in place of `bundle`.
    fn replace_bundle(new: &Path, bundle: &Path) -> Result<(), String> {
        let replacement = Replacement::next_to(bundle)
            .map_err(|e| format!("Failed to install the update: {e}"))?;
        // Creating the copy's folder tells whether the user may change the bundle's folder
        match std::fs::create_dir(&replacement.staged) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return replace_as_admin(&replacement, new, bundle);
            }
            Err(e) if e.kind() == ErrorKind::ReadOnlyFilesystem => {
                return Err(MOVE_TO_APPLICATIONS.into());
            }
            Err(e) => return Err(format!("Failed to install the update: {e}")),
        }
        // ditto copies the app with its links, extended attributes and code signature
        let installed = run(Command::new("/usr/bin/ditto")
            .arg(new)
            .arg(&replacement.staged))
        .and_then(|()| replacement.swap(bundle).map_err(|e| e.to_string()));
        if let Err(e) = installed {
            let _ = std::fs::remove_dir_all(&replacement.staged);
            return Err(format!("Failed to install the update: {e}"));
        }
        touch(bundle);
        if let Err(e) = std::fs::remove_dir_all(&replacement.previous) {
            log::warn!(
                "Couldn't remove the previous version at {}: {e}",
                replacement.previous.display()
            );
        }
        Ok(())
    }

    /// Marks the replaced `bundle` as changed, so that Launch Services reads the new app's
    /// details instead of those it keeps for the previous one.
    pub fn touch(bundle: &Path) {
        let now = std::time::SystemTime::now();
        if let Err(e) = std::fs::File::open(bundle).and_then(|dir| dir.set_modified(now)) {
            log::warn!(
                "Couldn't update the modification time of {}: {e}",
                bundle.display()
            );
        }
    }

    /// Does what [`replace_bundle`] does as root, once the user authenticates as an
    /// administrator.
    fn replace_as_admin(
        replacement: &Replacement,
        new: &Path,
        bundle: &Path,
    ) -> Result<(), String> {
        let script = replacement.script("/usr/bin/ditto", new, bundle);
        let output = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(as_administrator(&script))
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("Couldn't ask for permission to install the update: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        let error = String::from_utf8_lossy(&output.stderr);
        // AppleScript's "User canceled" error
        if error.contains("(-128)") {
            return Err("The update was not installed: authentication was cancelled".into());
        }
        Err(format!(
            "The update was not installed: {}",
            failure_detail(&error)
        ))
    }

    /// AppleScript that runs the shell `script` as root, asking for an administrator's
    /// password first.
    pub fn as_administrator(script: &str) -> String {
        format!(
            "do shell script {} with prompt {} with administrator privileges",
            applescript_string(script),
            applescript_string("cpmesh needs an administrator's permission to install its update."),
        )
    }

    fn applescript_string(text: &str) -> String {
        format!("\"{}\"", text.replace('\\', r"\\").replace('"', "\\\""))
    }

    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
    }

    /// Where the new bundle is put together, and where the old one goes when the new one
    /// takes its place: next to the bundle, so moving them takes one step each and needs no
    /// more permission than creating the new one did.
    pub struct Replacement {
        staged: PathBuf,
        previous: PathBuf,
    }

    impl Replacement {
        pub fn next_to(bundle: &Path) -> std::io::Result<Self> {
            Ok(Replacement {
                staged: super::sibling(bundle, "update")?,
                previous: super::sibling(bundle, "previous")?,
            })
        }

        /// Moves the new bundle in place of `bundle`, keeping the old one if that fails.
        pub fn swap(&self, bundle: &Path) -> std::io::Result<()> {
            std::fs::rename(bundle, &self.previous)?;
            if let Err(e) = std::fs::rename(&self.staged, bundle) {
                if let Err(undo) = std::fs::rename(&self.previous, bundle) {
                    log::error!(
                        "Couldn't put cpmesh back at {}, it's at {}: {undo}",
                        bundle.display(),
                        self.previous.display()
                    );
                }
                return Err(e);
            }
            Ok(())
        }

        /// A shell script that copies `new` with `copy` and swaps it in like
        /// [`Replacement::swap`], then removes the old bundle and touches the new one like
        /// [`touch`]. Only copying and swapping decide whether it succeeds.
        pub fn script(&self, copy: &str, new: &Path, bundle: &Path) -> String {
            let [new, staged, bundle, previous] =
                [new, &self.staged, bundle, &self.previous].map(shell_quote);
            format!(
                "{copy} {new} {staged} || {{ /bin/rm -rf {staged}; exit 1; }}; \
                 /bin/mv {bundle} {previous} || {{ /bin/rm -rf {staged}; exit 1; }}; \
                 /bin/mv {staged} {bundle} || \
                 {{ /bin/mv {previous} {bundle}; /bin/rm -rf {staged}; exit 1; }}; \
                 /bin/rm -rf {previous}; /usr/bin/touch {bundle}; exit 0"
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn write_bundle(bundle: &Path, version: &str) {
            std::fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
            std::fs::write(bundle.join("Contents/MacOS/cpmesh-desktop"), version).unwrap();
        }

        fn bundle_version(bundle: &Path) -> String {
            std::fs::read_to_string(bundle.join("Contents/MacOS/cpmesh-desktop")).unwrap()
        }

        const LONG_AGO: std::time::Duration = std::time::Duration::from_secs(1_000_000);

        fn set_modified(path: &Path, since_epoch: std::time::Duration) {
            std::fs::File::open(path)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + since_epoch)
                .unwrap();
        }

        /// Modified this century, unlike what [`set_modified`] set it to
        fn was_touched(path: &Path) -> bool {
            let modified = std::fs::metadata(path).unwrap().modified().unwrap();
            modified > std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000)
        }

        fn names(dir: &Path) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }

        #[test]
        fn finds_the_bundle_the_app_runs_from() {
            assert_eq!(
                app_bundle(Path::new(
                    "/Applications/cpmesh.app/Contents/MacOS/cpmesh-desktop"
                )),
                Ok(PathBuf::from("/Applications/cpmesh.app"))
            );
            for exe in [
                "/usr/local/bin/cpmesh-desktop",
                "/Applications/cpmesh.app/Contents/cpmesh-desktop",
                "/Applications/cpmesh/Contents/MacOS/cpmesh-desktop",
                "cpmesh-desktop",
            ] {
                assert!(app_bundle(Path::new(exe)).is_err(), "{exe}");
            }
            // A translocated app can't be replaced where it runs
            assert_eq!(
                app_bundle(Path::new(
                    "/private/var/folders/x/T/AppTranslocation/0E1F/d/cpmesh.app/Contents/MacOS/cpmesh-desktop"
                )),
                Err(MOVE_TO_APPLICATIONS.to_string())
            );
        }

        #[test]
        fn finds_the_one_app_on_the_disk_image() {
            let volume = tempfile::tempdir().unwrap();
            write_bundle(&volume.path().join("cpmesh.app"), "2");
            std::os::unix::fs::symlink("/Applications", volume.path().join("Applications"))
                .unwrap();
            std::os::unix::fs::symlink(
                volume.path().join("cpmesh.app"),
                volume.path().join("link.app"),
            )
            .unwrap();
            std::fs::write(volume.path().join(".DS_Store"), "").unwrap();
            assert_eq!(
                find_app(volume.path()),
                Ok(volume.path().join("cpmesh.app"))
            );

            write_bundle(&volume.path().join("other.app"), "2");
            assert!(find_app(volume.path()).is_err());
            assert!(find_app(&volume.path().join("missing")).is_err());
        }

        #[test]
        fn swaps_the_new_bundle_in() {
            let dir = tempfile::tempdir().unwrap();
            let bundle = dir.path().join("cpmesh.app");
            write_bundle(&bundle, "1");
            let replacement = Replacement::next_to(&bundle).unwrap();
            assert_eq!(replacement.staged.parent(), Some(dir.path()));
            assert_eq!(replacement.previous.parent(), Some(dir.path()));
            write_bundle(&replacement.staged, "2");

            replacement.swap(&bundle).unwrap();
            assert_eq!(bundle_version(&bundle), "2");
            assert_eq!(bundle_version(&replacement.previous), "1");
            assert!(!replacement.staged.exists());
        }

        #[test]
        fn a_failed_swap_keeps_the_old_bundle() {
            let dir = tempfile::tempdir().unwrap();
            let bundle = dir.path().join("cpmesh.app");
            write_bundle(&bundle, "1");
            // Nothing was staged
            let replacement = Replacement::next_to(&bundle).unwrap();
            assert!(replacement.swap(&bundle).is_err());
            assert_eq!(bundle_version(&bundle), "1");
            assert_eq!(names(dir.path()), ["cpmesh.app"]);
        }

        #[test]
        fn the_script_replaces_the_bundle() {
            let dir = tempfile::tempdir().unwrap();
            // Quotes, spaces and shell characters in the folder's name stay literal
            let apps = dir.path().join(r#"it's "my" $HOME \ apps"#);
            let bundle = apps.join("cpmesh.app");
            write_bundle(&bundle, "1");
            let new = dir.path().join("volume/cpmesh.app");
            write_bundle(&new, "2");
            set_modified(&new, LONG_AGO);
            let replacement = Replacement::next_to(&bundle).unwrap();

            // Copies keep their modification time, like ditto
            let script = replacement.script("/bin/cp -Rp", &new, &bundle);
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .status()
                .unwrap();
            assert!(status.success(), "{script}");
            assert_eq!(bundle_version(&bundle), "2");
            assert_eq!(bundle_version(&new), "2");
            assert_eq!(names(&apps), ["cpmesh.app"]);
            assert!(was_touched(&bundle));
        }

        #[test]
        fn touching_the_bundle_marks_it_changed() {
            let dir = tempfile::tempdir().unwrap();
            let bundle = dir.path().join("cpmesh.app");
            write_bundle(&bundle, "2");
            set_modified(&bundle, LONG_AGO);
            touch(&bundle);
            assert!(was_touched(&bundle));
            // A missing bundle is only logged
            touch(&dir.path().join("missing.app"));
        }

        #[test]
        fn the_script_keeps_the_old_bundle_when_copying_fails() {
            let dir = tempfile::tempdir().unwrap();
            let bundle = dir.path().join("cpmesh.app");
            write_bundle(&bundle, "1");
            let replacement = Replacement::next_to(&bundle).unwrap();

            let script = replacement.script("/bin/cp -R", &dir.path().join("missing"), &bundle);
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .status()
                .unwrap();
            assert!(!status.success());
            assert_eq!(bundle_version(&bundle), "1");
            assert_eq!(names(dir.path()), ["cpmesh.app"]);
        }

        #[test]
        fn runs_the_script_as_administrator() {
            assert_eq!(
                as_administrator(r#"/bin/mv 'a "b" \ c' 'd'"#),
                r#"do shell script "/bin/mv 'a \"b\" \\ c' 'd'" with prompt "cpmesh needs an administrator's permission to install its update." with administrator privileges"#
            );
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::path::Path;

    /// The NSIS installer's options for an update: passive (a progress bar and no
    /// questions; it closes cpmesh if it still runs), over the existing installation
    /// (/UPDATE), and starting cpmesh once it's done (/R)
    const UPDATE_OPTIONS: [&str; 3] = ["/P", "/UPDATE", "/R"];

    pub fn start_installer(installer: &Path) -> Result<(), String> {
        std::process::Command::new(installer)
            .args(UPDATE_OPTIONS)
            .spawn()
            .map(drop)
            .map_err(|e| format!("Couldn't start the installer: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_one_update_at_a_time() {
        let first = Installing::start().unwrap();
        assert!(Installing::start().is_err());
        drop(first);
        drop(Installing::start().unwrap());
    }

    #[test]
    fn installer_suffixes_match_in_any_case() {
        assert!(has_suffix("cpmesh-0.5.0-linux-amd64.AppImage", ".appimage"));
        assert!(has_suffix("cpmesh-0.5.0-linux-amd64.DEB", ".deb"));
        assert!(has_suffix(
            "cpmesh-0.5.0-windows-amd64-setup.exe",
            "-setup.exe"
        ));
        assert!(!has_suffix("cpmesh-0.5.0-linux-amd64.deb", ".AppImage"));
        assert!(!has_suffix("cpmesh-0.5.0-windows-amd64.msi", "-setup.exe"));
        assert!(!has_suffix("deb", ".deb"));
    }

    #[cfg(unix)]
    #[test]
    fn replacements_are_hidden_next_to_what_they_replace() {
        let path = Path::new("/Applications/cpmesh.app");
        let staged = sibling(path, "update").unwrap();
        assert_eq!(staged.parent(), path.parent());
        let name = staged.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(".cpmesh.app.update-"), "{name}");
        assert_ne!(staged, sibling(path, "update").unwrap());
        assert!(sibling(Path::new("/"), "update").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn reports_what_went_wrong() {
        let apt = "Reading package lists...\n\
            N: Download is performed unsandboxed as root as file '/tmp/x.deb' couldn't be accessed by user '_apt'.\n\
            E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 (unattended-upgr)\n\
            E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?\n";
        assert_eq!(
            failure_detail(apt),
            "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 \
             (unattended-upgr) E: Unable to acquire the dpkg frontend lock \
             (/var/lib/dpkg/lock-frontend), is another process using it?"
        );
        assert_eq!(
            failure_detail(
                "Error executing command as another user: No authentication agent found.\n"
            ),
            "Error executing command as another user: No authentication agent found."
        );
        assert_eq!(failure_detail("first\n  last line \n\n"), "last line");
        assert_eq!(failure_detail(""), "no details");
        let long = failure_detail(&format!("E: {}", "x".repeat(1000)));
        assert_eq!(long.chars().count(), 401);
        assert!(long.ends_with('…'));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use std::ffi::OsString;
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;

        use super::super::linux::*;
        use super::super::*;

        #[test]
        fn each_installation_downloads_its_own_package() {
            let deb = url::Url::parse(
                "https://github.com/cjs0h/cpmesh/releases/download/v0.5.0/cpmesh-0.5.0-linux-amd64.deb",
            )
            .unwrap();
            let appimage = url::Url::parse(
                "https://github.com/cjs0h/cpmesh/releases/download/v0.5.0/cpmesh-0.5.0-linux-amd64.AppImage",
            )
            .unwrap();
            let running = Installation::AppImage("/home/me/Apps/cpmesh.AppImage".into());
            assert_eq!(Installation::Deb.installer_url(&deb), Ok(deb.clone()));
            assert_eq!(running.installer_url(&deb), Ok(appimage.clone()));
            // Whichever package the server offers
            assert_eq!(Installation::Deb.installer_url(&appimage), Ok(deb));
            assert_eq!(running.installer_url(&appimage), Ok(appimage));

            let other_server =
                url::Url::parse("https://dl.example.com/files/cpmesh-0.5.0-linux-amd64.DEB?t=1")
                    .unwrap();
            assert_eq!(
                running.installer_url(&other_server).unwrap().as_str(),
                "https://dl.example.com/files/cpmesh-0.5.0-linux-amd64.AppImage?t=1"
            );
            let windows =
                url::Url::parse("https://example.com/cpmesh-0.5.0-windows-amd64-setup.exe")
                    .unwrap();
            assert!(Installation::Deb.installer_url(&windows).is_err());
            assert!(package_url(&windows, "AppImage").is_err());
        }

        #[test]
        fn each_installation_takes_its_own_installer() {
            let appimage = Installation::AppImage("/home/me/cpmesh.AppImage".into());
            assert!(
                Installation::Deb
                    .check_installer("cpmesh-0.5.0-linux-amd64.deb")
                    .is_ok()
            );
            assert!(
                Installation::Deb
                    .check_installer("cpmesh-0.5.0-linux-amd64.AppImage")
                    .is_err()
            );
            assert!(
                appimage
                    .check_installer("cpmesh-0.5.0-linux-amd64.AppImage")
                    .is_ok()
            );
            assert!(
                appimage
                    .check_installer("cpmesh-0.5.0-linux-amd64.deb")
                    .is_err()
            );
        }

        #[test]
        fn installs_packages_with_apt_or_dpkg() {
            let package = std::path::Path::new("/tmp/cpmesh-update-1/cpmesh-0.5.0-linux-amd64.deb");
            assert_eq!(
                deb_install_command(package, true),
                [
                    "/usr/bin/apt-get",
                    "install",
                    "--yes",
                    "--no-remove",
                    "-o",
                    "DPkg::Lock::Timeout=120",
                    "/tmp/cpmesh-update-1/cpmesh-0.5.0-linux-amd64.deb",
                ]
                .map(OsString::from)
            );
            assert_eq!(
                deb_install_command(package, false),
                [
                    "/usr/bin/dpkg",
                    "--install",
                    "/tmp/cpmesh-update-1/cpmesh-0.5.0-linux-amd64.deb",
                ]
                .map(OsString::from)
            );
        }

        #[test]
        fn replaces_the_appimage_keeping_its_permissions() {
            let dir = tempfile::tempdir().unwrap();
            let appimage = dir.path().join("cpmesh.AppImage");
            std::fs::write(&appimage, "version 1").unwrap();
            std::fs::set_permissions(&appimage, std::fs::Permissions::from_mode(0o750)).unwrap();
            let download = dir.path().join("download");
            std::fs::write(&download, "version 2, a little larger").unwrap();
            // Like the running AppImage, which keeps the file open
            let mut running = std::fs::File::open(&appimage).unwrap();

            replace_appimage(&download, &appimage).unwrap();
            assert_eq!(
                std::fs::read_to_string(&appimage).unwrap(),
                "version 2, a little larger"
            );
            let mode = std::fs::metadata(&appimage).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, 0o750);
            let mut old = String::new();
            running.read_to_string(&mut old).unwrap();
            assert_eq!(old, "version 1");

            let mut names: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            assert_eq!(names, ["cpmesh.AppImage", "download"]);
        }

        #[test]
        fn a_failed_replacement_leaves_the_appimage_alone() {
            let dir = tempfile::tempdir().unwrap();
            let appimage = dir.path().join("cpmesh.AppImage");
            std::fs::write(&appimage, "version 1").unwrap();

            assert!(replace_appimage(&dir.path().join("missing"), &appimage).is_err());
            assert_eq!(std::fs::read_to_string(&appimage).unwrap(), "version 1");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}
