fn main() {
    let mut attributes = tauri_build::Attributes::new();
    if target_is_windows_msvc() {
        // Tauri embeds its app manifest, which loads Common Controls v6, only into the app
        // binary. Test executables that link the Tauri runtime (tests build an AppContext,
        // which holds an AppHandle) then import v6-only functions such as
        // TaskDialogIndirect and can't start: STATUS_ENTRYPOINT_NOT_FOUND. Embed the same
        // manifest with the linker into every executable instead, as Tauri does for its own
        // tests (tauri-apps/tauri#4383).
        attributes = attributes
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
        embed_windows_manifest();
    }
    if let Err(error) = tauri_build::try_build(attributes) {
        println!("{error:#}");
        std::process::exit(1);
    }
}

fn target_is_windows_msvc() -> bool {
    std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "msvc")
}

fn embed_windows_manifest() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let manifest = std::path::Path::new(&dir).join("windows-app-manifest.xml");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    // Just this manifest, like the one Tauri embeds: no linker-generated UAC section
    println!("cargo:rustc-link-arg=/MANIFESTUAC:NO");
}
