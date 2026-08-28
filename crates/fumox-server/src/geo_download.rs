//! Startup download of the GeoLite2 databases.
//!
//! Fumox never ships the `.mmdb` files (they are gitignored, §12). Until
//! now the operator had to fetch them by hand; this module closes that gap:
//! before the listeners bind, each GeoLite2 database in `[geo].db_dir` is
//! checked and — when missing, implausible (a truncated or broken download
//! from an earlier attempt) or older than [`MAX_AGE`] — re-downloaded from
//! the fixed public mirrors into a temporary file that is atomically
//! renamed into place. The resolver therefore always finds either a
//! complete file or nothing, never a half-written one, and a failed
//! download simply retries on the next start.
//!
//! Everything here is best-effort: a failure (unwritable directory, no
//! network, mirror down) is logged and skipped — geo enrichment is an
//! optional enhancement (SPEC §6), never a startup requirement.

use fumox_core::config::{AppConfig, GeoDbKind};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Databases older than this are refreshed at the next start.
const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
/// Connect timeout for one download.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Overall budget for one download — the City database is ~70 MB.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Redirect hops allowed between the shortlink and the release asset.
const MAX_REDIRECTS: usize = 5;
/// The MaxMind metadata marker; a real `.mmdb` ends with its metadata block.
const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
/// Tail window scanned for the metadata marker.
const MARKER_WINDOW: u64 = 128 * 1024;

/// One downloadable GeoLite2 database: its canonical file name comes from
/// the [`GeoDbKind`], the URL is the public release mirror.
struct GeoFile {
    kind: GeoDbKind,
    url: &'static str,
}

fn all_files() -> [GeoFile; 3] {
    [
        GeoFile {
            kind: GeoDbKind::Country,
            url: "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb",
        },
        GeoFile {
            kind: GeoDbKind::City,
            url: "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb",
        },
        GeoFile {
            kind: GeoDbKind::Asn,
            url: "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb",
        },
    ]
}

/// Ensure every GeoLite2 database is present and reasonably fresh in
/// `[geo].db_dir`. Called once from `main` before the geo resolver is built.
pub async fn ensure_geo_databases(config: &AppConfig) {
    let geo = &config.geo;
    if !geo.enabled {
        tracing::debug!("geo enrichment disabled — skipping GeoLite2 database download");
        return;
    }
    if geo.db_dir.as_os_str().is_empty() {
        tracing::debug!("[geo].db_dir is empty — skipping GeoLite2 database download");
        return;
    }
    if !ensure_writable_dir(&geo.db_dir) {
        tracing::warn!(
            dir = %geo.db_dir.display(),
            "directory is not writable — skipping GeoLite2 database download; \
             provide the .mmdb files manually"
        );
        return;
    }

    for file in all_files() {
        let name = file.kind.file_name();
        match ensure_one(&geo.db_dir, &file, &config.fetch.user_agent).await {
            Outcome::Fresh => tracing::debug!(file = name, "GeoLite2 database is up to date"),
            Outcome::Downloaded { bytes } => {
                tracing::info!(file = name, bytes, "GeoLite2 database downloaded");
            }
            Outcome::Failed { reason } => {
                tracing::warn!(
                    file = name,
                    reason,
                    "GeoLite2 database download failed; will retry on next start"
                );
            }
        }
    }
}

enum Outcome {
    /// Plausible file, younger than [`MAX_AGE`].
    Fresh,
    /// A fresh copy was installed (missing, implausible or stale before).
    Downloaded { bytes: u64 },
    /// Download or validation failed; the previous file (if any) is intact.
    Failed { reason: String },
}

async fn ensure_one(dir: &Path, file: &GeoFile, user_agent: &str) -> Outcome {
    let path = dir.join(file.kind.file_name());
    if !needs_download(&path) {
        return Outcome::Fresh;
    }
    match download_and_install(&path, file.url, user_agent).await {
        Ok(bytes) => Outcome::Downloaded { bytes },
        Err(reason) => Outcome::Failed { reason },
    }
}

/// Whether the file must be (re-)downloaded: absent, implausible (empty or
/// without the MaxMind metadata marker — e.g. a broken earlier download) or
/// older than [`MAX_AGE`].
fn needs_download(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return true; // absent
    };
    if !meta.is_file() || !plausible_mmdb(path) {
        return true; // broken content — refresh regardless of age
    }
    // A future mtime (clock skew) counts as fresh: it cannot be a month old.
    match SystemTime::now().duration_since(meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)) {
        Ok(age) => age > MAX_AGE,
        Err(_) => false,
    }
}

/// Light format check: non-empty and the MaxMind metadata marker appears in
/// the file tail. Catches HTML error pages, empty and truncated files.
fn plausible_mmdb(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let len = match file.metadata().map(|m| m.len()) {
        Ok(len) if len > 0 => len,
        _ => return false,
    };
    use std::io::{Read, Seek, SeekFrom};
    let start = len.saturating_sub(MARKER_WINDOW);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return false;
    }
    let mut tail = Vec::new();
    match file.read_to_end(&mut tail) {
        Ok(_) => twoway_find(&tail).is_some(),
        Err(_) => false,
    }
}

/// Find [`METADATA_MARKER`] in a buffer (naive scan; the window is small).
fn twoway_find(haystack: &[u8]) -> Option<usize> {
    haystack
        .windows(METADATA_MARKER.len())
        .position(|window| window == METADATA_MARKER)
}

/// Create `dir` when missing and probe that we can actually write to it
/// (mode bits alone do not decide — ACLs, read-only mounts and root do).
fn ensure_writable_dir(dir: &Path) -> bool {
    if let Err(err) = std::fs::create_dir_all(dir) {
        tracing::warn!(dir = %dir.display(), error = %err, "cannot create db_dir");
        return false;
    }
    let probe = dir.join(format!(".fumox-write-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            drop(std::fs::remove_file(&probe));
            true
        }
        Err(err) => {
            tracing::warn!(dir = %dir.display(), error = %err, "db_dir is not writable");
            false
        }
    }
}

/// Download `url` into a sibling temporary file and atomically rename it
/// onto `dest` after validation. On any failure the temporary file is
/// removed and `dest` (if it exists) is left untouched, so the next start
/// retries with a clean slate.
async fn download_and_install(dest: &Path, url: &str, user_agent: &str) -> Result<u64, String> {
    let tmp = tmp_path(dest);
    let result = download_body(url, &tmp, user_agent).await;
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(reason) => {
            drop(std::fs::remove_file(&tmp));
            return Err(reason);
        }
    };
    if !plausible_mmdb(&tmp) {
        drop(std::fs::remove_file(&tmp));
        return Err("downloaded file is not a valid MaxMind database".to_string());
    }
    // Same-directory rename: atomic on POSIX and Windows.
    std::fs::rename(&tmp, dest).map_err(|err| {
        drop(std::fs::remove_file(&tmp));
        format!("cannot move the file into place: {err}")
    })?;
    Ok(bytes)
}

/// Sibling temporary path, unique per process so overlapping starts never
/// clobber each other. Finalization is `rename`, which requires the same
/// filesystem.
fn tmp_path(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "GeoLite2.mmdb".to_string());
    dest.with_file_name(format!("{name}.{}.tmp", std::process::id()))
}

async fn download_body(url: &str, tmp: &Path, user_agent: &str) -> Result<u64, String> {
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(user_agent.to_string())
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        .build()
        .map_err(|err| err.to_string())?;

    tokio::time::timeout(DOWNLOAD_TIMEOUT, async {
        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(|err| format!("request failed: {err}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        let mut file = tokio::fs::File::create(tmp)
            .await
            .map_err(|err| format!("cannot create the temporary file: {err}"))?;
        use tokio::io::AsyncWriteExt;
        let mut total = 0u64;
        // `chunk()` streams the body without pulling in a Stream extension.
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| format!("download interrupted: {err}"))?
        {
            file.write_all(&chunk)
                .await
                .map_err(|err| format!("cannot write the temporary file: {err}"))?;
            total += chunk.len() as u64;
        }
        file.flush()
            .await
            .map_err(|err| format!("cannot flush the temporary file: {err}"))?;
        file.sync_all()
            .await
            .map_err(|err| format!("cannot sync the temporary file: {err}"))?;
        Ok(total)
    })
    .await
    .map_err(|_| format!("download timed out after {}s", DOWNLOAD_TIMEOUT.as_secs()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fumox-geo-dl-test-{}",
            fumox_core::models::new_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake_mmdb(body: &[u8]) -> Vec<u8> {
        let mut bytes = body.to_vec();
        bytes.extend_from_slice(METADATA_MARKER);
        bytes
    }

    #[test]
    fn marker_scan_finds_the_metadata_tail() {
        assert!(twoway_find(&fake_mmdb(b"proxies")).is_some());
        assert!(twoway_find(b"no marker here").is_none());
        assert!(twoway_find(b"").is_none());
    }

    #[test]
    fn plausibility_rejects_empty_and_markerless_files() {
        let dir = scratch_dir();
        let path = dir.join("x.mmdb");

        // Absent file.
        assert!(needs_download(&path));

        // Empty file (a broken download).
        std::fs::write(&path, b"").unwrap();
        assert!(needs_download(&path));

        // Markerless content (an HTML error page served with HTTP 200).
        std::fs::write(&path, b"<html>not a database</html>").unwrap();
        assert!(needs_download(&path));

        // A plausible, fresh file stays.
        std::fs::write(&path, fake_mmdb(b"db-body")).unwrap();
        assert!(!needs_download(&path));

        // Older than a month — refresh.
        let month_ago = SystemTime::now() - Duration::from_secs(31 * 24 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(month_ago)
            .unwrap();
        assert!(needs_download(&path));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn writable_dir_requires_a_real_writable_directory() {
        let dir = scratch_dir();
        assert!(ensure_writable_dir(&dir));

        // Missing directories are created (the default db_dir is relative).
        let nested = dir.join("a/b");
        assert!(ensure_writable_dir(&nested));
        assert!(nested.is_dir());

        // A regular file in the place of the directory is not writable.
        let as_file = dir.join("occupied");
        std::fs::write(&as_file, b"x").unwrap();
        assert!(!ensure_writable_dir(&as_file));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tmp_path_is_a_sibling_with_a_process_suffix() {
        let dest = Path::new("/tmp/geo/GeoLite2-City.mmdb");
        let tmp = tmp_path(dest);
        assert_eq!(tmp.parent(), dest.parent());
        let name = tmp.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("GeoLite2-City.mmdb."), "name was: {name}");
        assert!(name.ends_with(".tmp"));
    }
}
