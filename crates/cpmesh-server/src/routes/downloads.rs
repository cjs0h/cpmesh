use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use std::sync::{Arc, LazyLock};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::Semaphore;

use super::middleware::{ApiError, json_response};
use crate::AppState;

pub async fn handle_list_downloads(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_active_download_links().await {
        Ok(links) => json_response(StatusCode::OK, links),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

pub async fn handle_list_current_release_downloads(State(state): State<Arc<AppState>>) -> Response {
    match state.db.list_downloads_for_current_releases().await {
        Ok(links) => json_response(StatusCode::OK, links),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

pub async fn handle_download_file(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
    headers: HeaderMap,
) -> Response {
    if state.config.downloads_dir.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Sanitize: no path traversal, and no hidden files (uploads in progress)
    if filename.is_empty()
        || filename.starts_with('.')
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains("..")
        || filename.contains('"')
        || filename.chars().any(char::is_control)
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    static DOWNLOADS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(64)));
    let permit = match DOWNLOADS.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let path = std::path::Path::new(&state.config.downloads_dir).join(&filename);
    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(e) => return ApiError::internal(e).into_response(),
    };
    let metadata = match file.metadata().await {
        Ok(m) if m.is_file() => m,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    };

    let modified = match metadata.modified() {
        Ok(modified) => chrono::DateTime::<chrono::Utc>::from(modified),
        Err(e) => return ApiError::internal(e).into_response(),
    };
    let etag = format!(
        "\"{}-{}-{}\"",
        metadata.len(),
        modified.timestamp(),
        modified.timestamp_subsec_nanos()
    );
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    response_headers.insert(header::ETAG, etag.parse().unwrap());
    response_headers.insert(
        header::LAST_MODIFIED,
        modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        "public, max-age=0, must-revalidate".parse().unwrap(),
    );
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(etag.as_str())
    {
        return (StatusCode::NOT_MODIFIED, response_headers).into_response();
    }
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .filter(|_| {
            headers
                .get(header::IF_RANGE)
                .is_none_or(|v| v == etag.as_str())
        });
    let (start, length, status) = match range {
        Some(range) => match byte_range(range, metadata.len()) {
            Some((start, end)) => {
                response_headers.insert(
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{}", metadata.len())
                        .parse()
                        .unwrap(),
                );
                (start, end - start + 1, StatusCode::PARTIAL_CONTENT)
            }
            None => {
                response_headers.insert(
                    header::CONTENT_RANGE,
                    format!("bytes */{}", metadata.len()).parse().unwrap(),
                );
                return (StatusCode::RANGE_NOT_SATISFIABLE, response_headers).into_response();
            }
        },
        None => (0, metadata.len(), StatusCode::OK),
    };
    if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
        return ApiError::internal(e).into_response();
    }
    let reader = tokio_util::io::ReaderStream::new(file.take(length));
    let stream =
        futures_util::stream::unfold((reader, permit), |(mut reader, permit)| async move {
            reader.next().await.map(|chunk| (chunk, (reader, permit)))
        });
    let body = axum::body::Body::from_stream(stream);
    let mime = mime_for_download(&filename);
    let disposition = format!("attachment; filename=\"{}\"", filename);

    (
        status,
        response_headers,
        [
            (axum::http::header::CONTENT_TYPE, mime.to_string()),
            (axum::http::header::CONTENT_DISPOSITION, disposition),
            (axum::http::header::CONTENT_LENGTH, length.to_string()),
        ],
        body,
    )
        .into_response()
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
        return json_response(
            StatusCode::OK,
            serde_json::json!({"update_available": false}),
        );
    }

    match state.db.get_current_release(&platform, &arch).await {
        Ok(Some(release)) => {
            let has_update = !current_version.is_empty()
                && release.version != current_version
                && is_newer_version(&release.version, &current_version);
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "update_available": has_update,
                    "version": release.version,
                    "download_url": release.download_url,
                    "release_notes": release.release_notes,
                }),
            )
        }
        Ok(None) => json_response(
            StatusCode::OK,
            serde_json::json!({"update_available": false}),
        ),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

fn byte_range(value: &str, length: u64) -> Option<(u64, u64)> {
    if length == 0 {
        return None;
    }
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
    if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        return (suffix > 0).then_some((length.saturating_sub(suffix), length - 1));
    }
    let start: u64 = start.parse().ok()?;
    let end = if end.is_empty() {
        length - 1
    } else {
        end.parse::<u64>().ok()?.min(length - 1)
    };
    (start < length && start <= end).then_some((start, end))
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
        if n > c {
            return true;
        }
        if n < c {
            return false;
        }
    }
    false
}

fn mime_for_download(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    if lower.ends_with(".exe") {
        "application/vnd.microsoft.portable-executable"
    } else if lower.ends_with(".msi") {
        "application/x-msi"
    } else if lower.ends_with(".dmg") {
        "application/x-apple-diskimage"
    } else if lower.ends_with(".pkg") {
        "application/vnd.apple.installer+xml"
    } else if lower.ends_with(".deb") {
        "application/vnd.debian.binary-package"
    } else if lower.ends_with(".rpm") {
        "application/x-rpm"
    } else if lower.ends_with(".appimage") {
        "application/x-executable"
    } else if lower.ends_with(".apk") {
        "application/vnd.android.package-archive"
    } else if lower.ends_with(".tar.gz") {
        "application/gzip"
    } else if lower.ends_with(".zip") {
        "application/zip"
    } else {
        "application/octet-stream"
    }
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
    fn version_comparison_handles_uneven_lengths_and_prefixes() {
        assert!(is_newer_version("1.0.0.1", "1.0.0"));
        assert!(!is_newer_version("1.0.0", "1.0.0.0"));
        assert!(is_newer_version("1.1", "1.0.5"));
        assert!(!is_newer_version("v1.0", "v1.0.0"));
        assert!(is_newer_version("2", "1.9.9"));
        // Non-numeric segments are ignored rather than crashing
        assert!(is_newer_version("1.2.0-beta", "1.1.0"));
        assert!(!is_newer_version("", "0.0.1"));
        assert!(!is_newer_version("", ""));
    }

    #[test]
    fn test_mime_for_download() {
        assert_eq!(
            mime_for_download("app.dmg"),
            "application/x-apple-diskimage"
        );
        assert_eq!(
            mime_for_download("setup.exe"),
            "application/vnd.microsoft.portable-executable"
        );
        assert_eq!(
            mime_for_download("app.apk"),
            "application/vnd.android.package-archive"
        );
        assert_eq!(
            mime_for_download("app.deb"),
            "application/vnd.debian.binary-package"
        );
        assert_eq!(mime_for_download("random.bin"), "application/octet-stream");
    }

    #[test]
    fn mime_for_download_covers_all_formats_case_insensitively() {
        assert_eq!(mime_for_download("Setup.MSI"), "application/x-msi");
        assert_eq!(
            mime_for_download("app.PKG"),
            "application/vnd.apple.installer+xml"
        );
        assert_eq!(mime_for_download("app.rpm"), "application/x-rpm");
        assert_eq!(
            mime_for_download("app.AppImage"),
            "application/x-executable"
        );
        assert_eq!(mime_for_download("app.tar.gz"), "application/gzip");
        assert_eq!(mime_for_download("app.zip"), "application/zip");
        assert_eq!(mime_for_download("noextension"), "application/octet-stream");
    }
}
