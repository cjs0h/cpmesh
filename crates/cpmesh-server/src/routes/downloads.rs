use std::sync::Arc;
use axum::{extract::{Path, State}, http::StatusCode, response::{IntoResponse, Response}};

use crate::AppState;
use super::middleware::{json_response};

pub async fn handle_list_downloads(
    State(state): State<Arc<AppState>>,
) -> Response {
    let links = state.db.list_active_download_links().await.unwrap_or_default();
    json_response(StatusCode::OK, links)
}

pub async fn handle_list_current_release_downloads(
    State(state): State<Arc<AppState>>,
) -> Response {
    let links = state.db.list_downloads_for_current_releases().await.unwrap_or_default();
    json_response(StatusCode::OK, links)
}

pub async fn handle_download_file(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Response {
    if state.config.downloads_dir.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Sanitize: no path traversal
    if filename.is_empty() || filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let path = std::path::Path::new(&state.config.downloads_dir).join(&filename);
    if !path.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mime = mime_for_download(&filename);
    let disposition = format!("attachment; filename=\"{}\"", filename);

    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, mime),
            (axum::http::header::CONTENT_DISPOSITION, &disposition),
        ],
        bytes,
    ).into_response()
}

/// Public endpoint: GET /api/updates/check?platform=darwin&arch=arm64&version=0.1.0
/// Returns the latest release for the given platform/arch if newer than the provided version.
pub async fn handle_check_update(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<UpdateCheckQuery>,
) -> Response {
    let platform = params.platform.unwrap_or_default();
    let arch = params.arch.unwrap_or_default();
    let current_version = params.version.unwrap_or_default();

    if platform.is_empty() {
        return json_response(StatusCode::OK, serde_json::json!({"update_available": false}));
    }

    match state.db.get_current_release(&platform, &arch).await {
        Ok(Some(release)) => {
            let has_update = !current_version.is_empty() && release.version != current_version && is_newer_version(&release.version, &current_version);
            json_response(StatusCode::OK, serde_json::json!({
                "update_available": has_update,
                "version": release.version,
                "download_url": release.download_url,
                "release_notes": release.release_notes,
            }))
        }
        _ => json_response(StatusCode::OK, serde_json::json!({"update_available": false})),
    }
}

#[derive(serde::Deserialize)]
pub struct UpdateCheckQuery {
    pub platform: Option<String>,
    pub arch: Option<String>,
    pub version: Option<String>,
}

/// Simple semver comparison: returns true if `new_ver` > `current_ver`.
fn is_newer_version(new_ver: &str, current_ver: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect()
    };
    let new_parts = parse(new_ver);
    let cur_parts = parse(current_ver);
    for i in 0..new_parts.len().max(cur_parts.len()) {
        let n = new_parts.get(i).copied().unwrap_or(0);
        let c = cur_parts.get(i).copied().unwrap_or(0);
        if n > c { return true; }
        if n < c { return false; }
    }
    false
}

fn mime_for_download(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    if lower.ends_with(".exe") { "application/vnd.microsoft.portable-executable" }
    else if lower.ends_with(".msi") { "application/x-msi" }
    else if lower.ends_with(".dmg") { "application/x-apple-diskimage" }
    else if lower.ends_with(".pkg") { "application/vnd.apple.installer+xml" }
    else if lower.ends_with(".deb") { "application/vnd.debian.binary-package" }
    else if lower.ends_with(".rpm") { "application/x-rpm" }
    else if lower.ends_with(".appimage") { "application/x-executable" }
    else if lower.ends_with(".apk") { "application/vnd.android.package-archive" }
    else if lower.ends_with(".tar.gz") { "application/gzip" }
    else if lower.ends_with(".zip") { "application/zip" }
    else { "application/octet-stream" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_version() {
        // Newer versions
        assert!(is_newer_version("0.2.0", "0.1.0"));
        assert!(is_newer_version("1.0.0", "0.9.9"));
        assert!(is_newer_version("0.1.1", "0.1.0"));
        assert!(is_newer_version("0.10.0", "0.9.0"));
        assert!(is_newer_version("v0.2.0", "0.1.0"));

        // Not newer (same or older)
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.2.0"));
        assert!(!is_newer_version("0.0.9", "0.1.0"));
        assert!(!is_newer_version("1.0.0", "1.0.0"));
    }

    #[test]
    fn test_mime_for_download() {
        assert_eq!(mime_for_download("app.dmg"), "application/x-apple-diskimage");
        assert_eq!(mime_for_download("setup.exe"), "application/vnd.microsoft.portable-executable");
        assert_eq!(mime_for_download("app.apk"), "application/vnd.android.package-archive");
        assert_eq!(mime_for_download("app.deb"), "application/vnd.debian.binary-package");
        assert_eq!(mime_for_download("random.bin"), "application/octet-stream");
    }
}
