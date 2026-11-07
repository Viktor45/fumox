//! Startup download of the GeoLite2 databases.
//!
//! Fumox never ships the `.mmdb` files (they are gitignored). Until
//! now the operator had to fetch them by hand; this module closes that gap:
//! before the listeners bind, each GeoLite2 database in `[geo].db_dir` is
//! checked and, when missing or implausible (a truncated, broken or
//! wrongly typed download from an earlier attempt) or older than
//! [`MAX_AGE`], re-downloaded from the configured mirror into a temporary
//! file that is atomically renamed into place. The resolver therefore
//! always finds either a complete file or nothing, never a half-written
//! one, and a failed download simply retries on the next start.
//!
//! The wait is bounded by the caller (`[geo].startup_download_budget_secs`,
//! read in `main`): past that budget startup continues and the download
//! finishes in the background, so the resolver this run opens without a
//! database and the next start picks it up. The atomic rename is what makes
//! that safe.
//!
//! Everything here is best-effort: a failure (unwritable directory, no
//! network, mirror down) is logged and skipped, geo enrichment is an
//! optional enhancement, never a startup requirement. The download is
//! unattended, so it neither follows a redirect off https nor to a host
//! outside [`REDIRECT_HOSTS`] (plus the mirror the operator configured),
//! and accepts a file only when its own metadata block declares the
//! `database_type` this slot expects.
//!
//! Three knobs make the channel the operator's own: `[geo].auto_download`
//! off keeps the "files by hand only" model, `[geo].download_urls` names
//! the mirrors, and `[geo].sha256` pins the checksum of a file whose
//! download must match it (a mismatch leaves the previous database in
//! place).

use fumox_core::config::{AppConfig, GeoDbKind};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Databases older than this are refreshed at the next start.
const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
/// Connect timeout for one download.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Overall budget for one download. The City database is ~70 MB and the
/// mirrors throttle, so the ceiling has to cover a slow link: a download
/// that runs past it simply retries on the next start (the partial
/// temporary file is removed, nothing partial is ever installed).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// Redirect hops allowed between the shortlink and the release asset.
const MAX_REDIRECTS: usize = 5;
/// Upper bound on one database download: the City database is ~70 MB, so
/// anything larger is a broken or hostile mirror, not a database. The
/// stream is cut as soon as the running total passes the cap, so a rogue
/// endpoint cannot fill the disk (the response is streamed to a temp file
/// and would otherwise be bounded only by the download budget).
const MAX_MMDB_BYTES: u64 = 512 * 1024 * 1024;
/// The MaxMind metadata marker; a real `.mmdb` ends with its metadata block.
const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
/// Tail window scanned for the metadata marker.
const MARKER_WINDOW: u64 = 128 * 1024;
/// Hosts a redirect may lead to, besides `*.githubusercontent.com` (the
/// release-asset CDN, whose exact subdomain varies). The default mirror
/// URLs are hardcoded public GitHub release links, which answer with a
/// redirect to one of these; nothing else may follow. A redirect to any
/// other host (or off https) is refused rather than fetched, so a hijacked
/// release or a mis-typed URL cannot deliver a foreign file: the content
/// check is a format check, not provenance. The host of the mirror the
/// operator configured is allowed as well: that URL is the operator's own
/// choice, and a mirror that redirects to its own CDN would otherwise be
/// unusable.
const REDIRECT_HOSTS: &[&str] = &["github.com"];

/// CDN suffix the release-asset redirect is allowed to land on.
const REDIRECT_HOST_SUFFIX: &str = ".githubusercontent.com";

/// Age past which an orphaned temporary file is removed: a download that
/// died mid-write leaves its `.tmp` behind, and nothing else ever cleans
/// it up. A live download writes for at most [`DOWNLOAD_TIMEOUT`], so a
/// day-old temporary file belongs to a process that is long gone.
const ORPHAN_TMP_AGE: Duration = Duration::from_secs(24 * 3600);

/// One downloadable GeoLite2 database: its canonical file name comes from
/// the [`GeoDbKind`], the URL comes from `[geo].download_urls`.
struct GeoFile {
    kind: GeoDbKind,
    /// `database_type` the file's own metadata block must declare. The
    /// marker alone accepts any MaxMind build, so without this a mirror
    /// that serves the ASN file under the City name installs silently and
    /// every proxy gets wrong country/AS facts. The string is MaxMind's
    /// own, fixed per product, and is rewritten into the metadata block
    /// exactly like the other database fields.
    db_type: &'static str,
}

fn all_files() -> [GeoFile; 2] {
    [
        GeoFile {
            kind: GeoDbKind::City,
            db_type: "GeoLite2-City",
        },
        GeoFile {
            kind: GeoDbKind::Asn,
            db_type: "GeoLite2-ASN",
        },
    ]
}

/// Ensure every GeoLite2 database is present and reasonably fresh in
/// `[geo].db_dir`. Called once from `main` before the geo resolver is built.
pub async fn ensure_geo_databases(config: &AppConfig) {
    let geo = &config.geo;
    if !geo.enabled {
        tracing::debug!("geo enrichment disabled, skipping GeoLite2 database download");
        return;
    }
    if !geo.auto_download {
        tracing::info!("[geo].auto_download is off; the .mmdb files are provided by hand");
        return;
    }
    if geo.db_dir.as_os_str().is_empty() {
        tracing::debug!("[geo].db_dir is empty, skipping GeoLite2 database download");
        return;
    }
    if let Err(reason) = ensure_writable_dir(&geo.db_dir) {
        tracing::warn!(
            dir = %geo.db_dir.display(),
            reason,
            "db_dir is not writable, skipping GeoLite2 database download; \
             provide the .mmdb files manually"
        );
        return;
    }
    cleanup_orphan_tmp_files(&geo.db_dir);

    for file in all_files() {
        let name = file.kind.file_name();
        let Some(url) = geo.download_urls.get(name) else {
            tracing::warn!(
                file = name,
                "no download URL configured for this database; provide the file by hand"
            );
            continue;
        };
        let checksum = geo.sha256.get(name).map(String::as_str);
        match ensure_one(&geo.db_dir, &file, url, checksum, &config.fetch.user_agent).await {
            Outcome::Fresh => tracing::debug!(file = name, "GeoLite2 database is up to date"),
            Outcome::Downloaded { bytes } => {
                tracing::info!(file = name, bytes, "GeoLite2 database downloaded");
            }
            Outcome::Failed { reason } => {
                tracing::warn!(
                    file = name,
                    reason,
                    "GeoLite2 database download failed; will retry on next start; \
                     provide the .mmdb file in [geo].db_dir manually or change [geo].download_urls"
                );
            }
        }
    }
}

/// Remove the temporary files of downloads that died mid-write. The name
/// of a temporary file carries a random suffix, so the age is what tells
/// a leftover apart from a live download.
fn cleanup_orphan_tmp_files(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".tmp") || !name.contains(".mmdb.") {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let age = meta
            .modified()
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .unwrap_or(Duration::ZERO);
        if age > ORPHAN_TMP_AGE {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {
                    tracing::debug!(file = %entry.path().display(), "removed an orphaned download")
                }
                Err(err) => tracing::warn!(
                    file = %entry.path().display(),
                    error = %err,
                    "cannot remove an orphaned download"
                ),
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

async fn ensure_one(
    dir: &Path,
    file: &GeoFile,
    url: &str,
    checksum: Option<&str>,
    user_agent: &str,
) -> Outcome {
    let path = dir.join(file.kind.file_name());
    let freshness = freshness(&path, file.db_type);
    if freshness == Freshness::Fresh {
        return Outcome::Fresh;
    }
    // The reason travels with the start of the download, so the log tells a
    // first install (file is absent) from a routine refresh (stale) and
    // from a repair (failed the content check).
    tracing::info!(
        file = file.kind.file_name(),
        reason = freshness.label(),
        "the installed file is {}; re-downloading",
        freshness.label()
    );
    match download_and_install(&path, url, file.db_type, checksum, user_agent).await {
        Ok(bytes) => Outcome::Downloaded { bytes },
        Err(reason) => Outcome::Failed { reason },
    }
}

/// Why the file in a slot must be (re-)downloaded, or `Fresh` when it must
/// not. The reason is what the pre-download log line names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freshness {
    /// A plausible file, younger than [`MAX_AGE`].
    Fresh,
    /// Nothing (or something that is not a regular file) in the slot.
    Absent,
    /// The file carries no MaxMind metadata block: empty, unreadable, an
    /// HTML error page served with HTTP 200, a truncated download.
    NotADatabase,
    /// A database older than [`MAX_AGE`].
    Stale,
}

impl Freshness {
    /// The phrase the pre-download log line uses.
    fn label(self) -> &'static str {
        match self {
            Freshness::Fresh => "fresh",
            Freshness::Absent => "absent",
            Freshness::NotADatabase => "failed the content check",
            Freshness::Stale => "stale",
        }
    }
}

/// Whether the file in a slot must be (re-)downloaded, and why.
///
/// A missing, empty or markerless file (an HTML error page served with
/// HTTP 200, a truncated download) is replaced whatever its age. A file
/// that carries the MaxMind metadata block is kept even when it declares
/// another `database_type`: that is a database from another provider or
/// another product, and replacing it with the built-in mirror's file
/// would silently drop the operator's choice. Age is only consulted for a
/// file that passes the content check, so a stale database is refreshed
/// instead of being kept for another month.
fn freshness(path: &Path, db_type: &str) -> Freshness {
    let Ok(meta) = std::fs::metadata(path) else {
        return Freshness::Absent;
    };
    if !meta.is_file() {
        return Freshness::Absent;
    }
    let Some(tail) = read_tail(path) else {
        return Freshness::NotADatabase; // empty or unreadable
    };
    let Some(marker) = naive_find(&tail, METADATA_MARKER) else {
        return Freshness::NotADatabase; // no metadata block: not a database
    };
    if naive_find(&tail[marker..], db_type.as_bytes()).is_none() {
        tracing::info!(
            path = %path.display(),
            expected = db_type,
            "the installed database declares another type; keeping it"
        );
        return Freshness::Fresh;
    }
    // A future mtime (clock skew) counts as fresh: it cannot be a month old.
    match SystemTime::now().duration_since(meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)) {
        Ok(age) if age > MAX_AGE => Freshness::Stale,
        _ => Freshness::Fresh,
    }
}

/// Content check for one slot: non-empty, the MaxMind metadata marker in
/// the file tail, and the metadata block declaring `db_type`. Catches HTML
/// error pages, empty and truncated files, and a database installed under
/// the wrong name (which would tag every proxy with the wrong facts).
/// It is deliberately a *format and identity* check, not a trust
/// guarantee: the mirrors publish no checksum to pin here, so what this
/// buys is "never silently install the wrong database", not provenance.
/// An operator who pins a checksum (`[geo].sha256`) gets provenance too.
fn verified_mmdb(path: &Path, db_type: &str) -> bool {
    let Some(tail) = read_tail(path) else {
        return false;
    };
    match naive_find(&tail, METADATA_MARKER) {
        // The type only counts when it sits in the metadata block, i.e.
        // after the marker: a city name appearing in the data section is
        // not a declaration of what the file is.
        Some(marker) => naive_find(&tail[marker..], db_type.as_bytes()).is_some(),
        None => false,
    }
}

/// The last [`MARKER_WINDOW`] bytes of the file, or `None` when the file is
/// missing, empty or unreadable.
fn read_tail(path: &Path) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = match file.metadata().map(|m| m.len()) {
        Ok(len) if len > 0 => len,
        _ => return None,
    };
    use std::io::{Read, Seek, SeekFrom};
    if file
        .seek(SeekFrom::Start(len.saturating_sub(MARKER_WINDOW)))
        .is_err()
    {
        return None;
    }
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).ok()?;
    Some(tail)
}

/// Find `needle` in a buffer with a naive sliding-window scan: no Two-Way
/// or other linear-time algorithm behind the name, the worst case is
/// O(n·m), which is safe only because the haystack is the last
/// [`MARKER_WINDOW`] (128 KiB) bytes of a file and the needle is a fixed
/// 15-byte marker.
fn naive_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Redirect policy for the unattended download: at most [`MAX_REDIRECTS`]
/// hops, https only, and only to the hosts the release links are expected
/// to answer from (see [`REDIRECT_HOSTS`]) plus the mirror the operator
/// configured. The download runs without an operator watching, so an
/// unexpected target is refused outright instead of being fetched and
/// content-checked.
fn redirect_policy(mirror_host: Option<&str>) -> reqwest::redirect::Policy {
    let mirror_host = mirror_host.map(str::to_ascii_lowercase);
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        if !redirect_target_ok(attempt.url(), mirror_host.as_deref()) {
            return attempt.error("refusing a redirect off https or to an unexpected host");
        }
        attempt.follow()
    })
}

/// Whether a redirect may follow to `url`: https only, and only to a host
/// the download already trusts (the release mirrors, their CDN, or the
/// mirror the operator configured).
fn redirect_target_ok(url: &reqwest::Url, mirror_host: Option<&str>) -> bool {
    url.scheme() == "https"
        && url
            .host_str()
            .is_some_and(|host| host_allowed_for_redirect(host, mirror_host))
}

/// Whether a redirect may follow to `host`: one of the exact mirror hosts,
/// the release-asset CDN suffix, or the mirror the operator configured.
fn host_allowed_for_redirect(host: &str, mirror_host: Option<&str>) -> bool {
    let host = host.to_ascii_lowercase();
    REDIRECT_HOSTS.contains(&host.as_str())
        || host.ends_with(REDIRECT_HOST_SUFFIX)
        || mirror_host == Some(host.as_str())
}

/// Create `dir` when missing and probe that we can actually write to it
/// (mode bits alone do not decide, ACLs, read-only mounts and root do).
/// The error text comes back with `Err`; the caller owns the single log
/// line, so the reason and the action are reported in one place.
fn ensure_writable_dir(dir: &Path) -> Result<(), String> {
    if let Err(err) = std::fs::create_dir_all(dir) {
        return Err(format!("cannot create the directory: {err}"));
    }
    let probe = dir.join(format!(".fumox-write-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            drop(std::fs::remove_file(&probe));
            Ok(())
        }
        Err(err) => Err(format!("cannot write to the directory: {err}")),
    }
}

/// Download `url` into a sibling temporary file and atomically rename it
/// onto `dest` after validation. On any failure the temporary file is
/// removed and `dest` (if it exists) is left untouched, so the next start
/// retries with a clean slate.
///
/// `checksum` is the expected SHA-256 of the file, when the operator
/// pinned one (`[geo].sha256`): a mismatch refuses the install, and the
/// previous database stays where it is.
async fn download_and_install(
    dest: &Path,
    url: &str,
    db_type: &str,
    checksum: Option<&str>,
    user_agent: &str,
) -> Result<u64, String> {
    let tmp = tmp_path(dest);
    // The download runs unattended for minutes, so the start is an info
    // event, not silence until the outcome: `bytes_hint` is the ceiling
    // the stream is cut at ([`MAX_MMDB_BYTES`]), the size the operator
    // should expect to move, not the exact file size.
    tracing::info!(
        file = %dest.display(),
        url,
        bytes_hint = MAX_MMDB_BYTES,
        "downloading GeoLite2 database, this may take a few minutes"
    );
    let bytes = match download_body(url, &tmp, user_agent).await {
        Ok(bytes) => bytes,
        Err(reason) => {
            drop(std::fs::remove_file(&tmp));
            return Err(reason);
        }
    };
    if !verified_mmdb(&tmp, db_type) {
        drop(std::fs::remove_file(&tmp));
        return Err(format!(
            "downloaded file does not declare database_type {db_type}"
        ));
    }
    if let Some(expected) = checksum {
        let actual = sha256_hex(&tmp)?;
        if !actual.eq_ignore_ascii_case(expected.trim()) {
            drop(std::fs::remove_file(&tmp));
            return Err(format!(
                "checksum mismatch: expected {expected}, got {actual}"
            ));
        }
    }
    // Same-directory rename: atomic on POSIX and Windows.
    std::fs::rename(&tmp, dest).map_err(|err| {
        drop(std::fs::remove_file(&tmp));
        format!("cannot move the file into place: {err}")
    })?;
    Ok(bytes)
}

/// Hex SHA-256 of a file, read in chunks so a 70 MB database does not
/// have to fit in memory.
fn sha256_hex(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|err| format!("cannot read the downloaded file: {err}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|err| format!("cannot read the downloaded file: {err}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Sibling temporary path, unique per download so overlapping starts never
/// clobber each other. Finalization is `rename`, which requires the same
/// filesystem.
fn tmp_path(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "GeoLite2.mmdb".to_string());
    dest.with_file_name(format!("{name}.{}.tmp", fumox_core::models::new_id()))
}

async fn download_body(url: &str, tmp: &Path, user_agent: &str) -> Result<u64, String> {
    download_body_capped(url, tmp, user_agent, MAX_MMDB_BYTES).await
}

/// [`download_body`] with an explicit size cap, so tests can exercise the
/// cutoff without streaming half a gigabyte.
async fn download_body_capped(
    url: &str,
    tmp: &Path,
    user_agent: &str,
    max_bytes: u64,
) -> Result<u64, String> {
    // reqwest is compiled without a crypto provider and panics when a
    // client is built before one is installed.
    fumox_core::tls::install_crypto_provider();
    // The mirror the operator configured is trusted for its own redirects.
    let mirror_host = reqwest::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase));
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(user_agent.to_string())
        .redirect(redirect_policy(mirror_host.as_deref()))
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
        // `create_new` (O_EXCL): the name carries a random suffix, so a
        // collision is impossible in practice, and a name that does exist
        // (a symlink planted by someone else) fails instead of truncating
        // the file it points at.
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)
            .await
            .map_err(|err| format!("cannot create the temporary file: {err}"))?;
        use tokio::io::AsyncWriteExt;
        let mut total = 0u64;
        // `chunk()` streams the body without pulling in a Stream extension.
        // The running total is checked before the write: a rogue mirror
        // streaming an endless body is cut at MAX_MMDB_BYTES, not bounded
        // only by the download budget.
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| format!("download interrupted: {err}"))?
        {
            total += chunk.len() as u64;
            if total > max_bytes {
                return Err(format!(
                    "download exceeds the {max_bytes} byte cap, not a GeoLite2 database"
                ));
            }
            file.write_all(&chunk)
                .await
                .map_err(|err| format!("cannot write the temporary file: {err}"))?;
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

    /// A body followed by the metadata marker and a `database_type` field,
    /// the shape a real `.mmdb` tail has.
    fn fake_mmdb(body: &[u8], db_type: &str) -> Vec<u8> {
        let mut bytes = body.to_vec();
        bytes.extend_from_slice(METADATA_MARKER);
        bytes.extend_from_slice(b"\x07database_type");
        bytes.extend_from_slice(db_type.as_bytes());
        bytes
    }

    const CITY: &str = "GeoLite2-City";
    const ASN: &str = "GeoLite2-ASN";

    /// A local HTTP server that answers every request with `body`, and the
    /// URL it listens on.
    async fn serve_body(body: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = listener.accept().await {
                // Read the request before answering: a server that replies
                // to a request it has not read yet sends an "early
                // response", and hyper cancels such a connection instead
                // of parsing it.
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            }
        });
        format!("http://{addr}/GeoLite2-City.mmdb")
    }

    /// The temporary files left in `dir`.
    fn tmp_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.ends_with(".tmp"))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn marker_scan_finds_the_metadata_tail() {
        let tail = fake_mmdb(b"proxies", CITY);
        assert!(naive_find(&tail, METADATA_MARKER).is_some());
        assert!(naive_find(b"no marker here", METADATA_MARKER).is_none());
        assert!(naive_find(b"", METADATA_MARKER).is_none());
        // A needle longer than the haystack never matches.
        assert!(naive_find(METADATA_MARKER, b"\xab\xcd\xefMaxMind.com!!").is_none());
        assert!(naive_find(b"ab", b"").is_none());
    }

    #[test]
    fn plausibility_rejects_empty_and_markerless_files() {
        let dir = scratch_dir();
        let path = dir.join("x.mmdb");

        // Absent file.
        assert_eq!(freshness(&path, CITY), Freshness::Absent);

        // Empty file (a broken download).
        std::fs::write(&path, b"").unwrap();
        assert_eq!(freshness(&path, CITY), Freshness::NotADatabase);

        // Markerless content (an HTML error page served with HTTP 200).
        std::fs::write(&path, b"<html>not a database</html>").unwrap();
        assert_eq!(freshness(&path, CITY), Freshness::NotADatabase);

        // A plausible, fresh file stays.
        std::fs::write(&path, fake_mmdb(b"db-body", CITY)).unwrap();
        assert_eq!(freshness(&path, CITY), Freshness::Fresh);

        // Older than a month, refresh.
        let month_ago = SystemTime::now() - Duration::from_secs(31 * 24 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(month_ago)
            .unwrap();
        assert_eq!(freshness(&path, CITY), Freshness::Stale);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A database of another kind (or another provider) sitting in the
    /// slot is kept: the operator put it there on purpose, and replacing
    /// it with the built-in mirror's file would silently drop their
    /// choice. Only a file that is not a database at all is replaced.
    #[test]
    fn a_well_formed_file_of_another_kind_is_kept() {
        let dir = scratch_dir();
        let path = dir.join("GeoLite2-City.mmdb");

        // ASN content sitting in the City slot.
        std::fs::write(&path, fake_mmdb(b"asn-body", ASN)).unwrap();
        assert_eq!(
            freshness(&path, CITY),
            Freshness::Fresh,
            "a database of another kind is kept"
        );
        assert_eq!(freshness(&path, ASN), Freshness::Fresh);

        // The type string before the marker is data-section text, not a
        // declaration, and does not satisfy the check: the file declares
        // ASN, so the City slot keeps it.
        let mut smuggled = b"GeoLite2-City".to_vec();
        smuggled.extend_from_slice(&fake_mmdb(b"body", ASN));
        std::fs::write(&path, smuggled).unwrap();
        assert_eq!(freshness(&path, CITY), Freshness::Fresh);

        // A file without the metadata block is not a database at all (an
        // HTML error page, a truncated download) and is replaced.
        std::fs::write(&path, b"<html>not a database</html>").unwrap();
        assert_eq!(freshness(&path, CITY), Freshness::NotADatabase);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn redirect_targets_are_limited_to_the_mirror_hosts() {
        // The release shortlink and the CDN it redirects to are allowed.
        assert!(host_allowed_for_redirect("github.com", None));
        assert!(host_allowed_for_redirect("GitHub.com", None));
        assert!(host_allowed_for_redirect(
            "release-assets.githubusercontent.com",
            None
        ));
        // Anything else is not.
        assert!(!host_allowed_for_redirect("evil.example", None));
        assert!(!host_allowed_for_redirect("github.com.evil.example", None));
        assert!(!host_allowed_for_redirect("notgithubusercontent.com", None));
        assert!(!host_allowed_for_redirect("", None));
        // The mirror the operator configured is trusted for its own
        // redirects, and only for its own host.
        assert!(host_allowed_for_redirect(
            "mirror.example",
            Some("mirror.example")
        ));
        assert!(!host_allowed_for_redirect(
            "other.example",
            Some("mirror.example")
        ));
    }

    /// The redirect decision is a pure function of the target URL: https
    /// only, and only to a host the download trusts. An https URL of an
    /// arbitrary host is the case the host rule has to catch on its own
    /// (the scheme is right, the host is not).
    #[test]
    fn a_redirect_target_is_judged_by_its_scheme_and_host() {
        let ok = |url: &str| redirect_target_ok(&reqwest::Url::parse(url).unwrap(), None);
        assert!(ok(
            "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"
        ));
        assert!(ok("https://release-assets.githubusercontent.com/x.mmdb"));
        // https, but a host nobody vouched for.
        assert!(!ok("https://evil.example/x.mmdb"));
        // The right host, but off https.
        assert!(!ok("http://github.com/x.mmdb"));
        // A host that merely ends like an allowed one.
        assert!(!ok("https://github.com.evil.example/x.mmdb"));
        // The mirror the operator configured is allowed on its own.
        assert!(redirect_target_ok(
            &reqwest::Url::parse("https://mirror.example/x.mmdb").unwrap(),
            Some("mirror.example")
        ));
    }

    /// The real databases must survive the content check, or every start
    /// would re-download ~78 MB for nothing. Skips itself when the
    /// gitignored `.mmdb` files are absent (CI runs without them).
    ///
    /// Only the content half of `needs_download` is asserted: the
    /// freshness half reads the files' mtime, so a developer's own copies
    /// age out of the 30-day window on their own and used to turn this
    /// test red on untouched machines. Freshness is covered
    /// deterministically (with `set_modified`) by the fresh/stale test
    /// above.
    #[test]
    fn real_workspace_databases_pass_the_content_check() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
        for file in all_files() {
            let name = file.kind.file_name();
            let path = dir.join(name);
            if !path.is_file() {
                eprintln!("skipping: {} absent", path.display());
                continue;
            }
            assert!(verified_mmdb(&path, file.db_type), "{name} rejected");
        }
    }

    #[test]
    fn writable_dir_requires_a_real_writable_directory() {
        let dir = scratch_dir();
        assert!(ensure_writable_dir(&dir).is_ok());

        // Missing directories are created (the default db_dir is relative).
        let nested = dir.join("a/b");
        assert!(ensure_writable_dir(&nested).is_ok());
        assert!(nested.is_dir());

        // A regular file in the place of the directory is not writable, and
        // the error text names what went wrong (the caller's log line).
        let as_file = dir.join("occupied");
        std::fs::write(&as_file, b"x").unwrap();
        let reason = ensure_writable_dir(&as_file).unwrap_err();
        assert!(reason.contains("directory"), "{reason}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tmp_path_is_a_sibling_with_a_random_suffix() {
        let dest = Path::new("/tmp/geo/GeoLite2-City.mmdb");
        let tmp = tmp_path(dest);
        assert_eq!(tmp.parent(), dest.parent());
        let name = tmp.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("GeoLite2-City.mmdb."), "name was: {name}");
        assert!(name.ends_with(".tmp"));
        // Two calls never collide: the suffix is random, not the pid.
        assert_ne!(tmp, tmp_path(dest));
    }

    /// A temporary file of a download that died is removed at the next
    /// start; a fresh one (a download in flight) is left alone.
    #[test]
    fn orphaned_downloads_are_cleaned_up() {
        let dir = scratch_dir();
        let old = dir.join("GeoLite2-City.mmdb.oldid.tmp");
        let fresh = dir.join("GeoLite2-City.mmdb.fresh.tmp");
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&fresh, b"x").unwrap();
        let two_days_ago = SystemTime::now() - Duration::from_secs(2 * 24 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(two_days_ago)
            .unwrap();

        cleanup_orphan_tmp_files(&dir);

        assert!(!old.exists(), "an orphaned download is removed");
        assert!(fresh.exists(), "a download in flight is left alone");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A mirror streaming more than the cap must be cut off with an error
    /// and the destination kept intact.
    /// Exercised with a tiny cap through [`download_body_capped`] so the
    /// test does not actually write half a gigabyte to disk.
    #[tokio::test]
    async fn oversized_download_is_cut_off_at_the_cap() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        const CAP: u64 = 4 * 1024;
        const SERVE: usize = 64 * 1024;
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                // Read the request before answering: a server that replies
                // to a request it has not read yet sends an "early
                // response", and hyper cancels such a connection instead
                // of parsing it (the request is still being written when
                // the answer arrives).
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {SERVE}\r\nconnection: close\r\n\r\n"
                );
                let _ = sock.write_all(head.as_bytes()).await;
                // Keep streaming until the client hangs up on the cap.
                let zeros = vec![0u8; SERVE];
                loop {
                    if sock.write_all(&zeros).await.is_err() {
                        break;
                    }
                }
            }
        });

        let dir = scratch_dir();
        let dest = dir.join("GeoLite2-City.mmdb");
        // A plausible previous database must survive the failed refresh.
        std::fs::write(&dest, fake_mmdb(b"previous", CITY)).unwrap();

        let err = download_body_capped(
            &format!("http://{addr}/GeoLite2-City.mmdb"),
            &tmp_path(&dest),
            "fumox-test",
            CAP,
        )
        .await
        .unwrap_err();
        assert!(err.contains("byte cap"), "{err}");

        // The temp file was cleaned up by the caller contract (checked by
        // download_and_install in production); here only the error and the
        // intact destination matter.
        assert_eq!(std::fs::read(&dest).unwrap(), fake_mmdb(b"previous", CITY));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A download that delivers the expected database installs it and
    /// leaves no temporary file behind.
    #[tokio::test]
    async fn a_valid_download_installs_the_file_and_leaves_no_temporary() {
        let body = fake_mmdb(b"fresh", CITY);
        let url = serve_body(body.clone()).await;
        let dir = scratch_dir();
        let dest = dir.join("GeoLite2-City.mmdb");
        std::fs::write(&dest, fake_mmdb(b"previous", CITY)).unwrap();

        let bytes = download_and_install(&dest, &url, CITY, None, "fumox-test")
            .await
            .unwrap();
        assert_eq!(bytes, body.len() as u64);
        assert_eq!(std::fs::read(&dest).unwrap(), body);
        assert!(
            tmp_files(&dir).is_empty(),
            "temporary files left behind: {:?}",
            tmp_files(&dir)
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A download that delivers the wrong database is refused: the
    /// previous file stays untouched and the temporary file is removed.
    #[tokio::test]
    async fn a_download_of_the_wrong_database_is_refused() {
        let url = serve_body(fake_mmdb(b"asn", ASN)).await;
        let dir = scratch_dir();
        let dest = dir.join("GeoLite2-City.mmdb");
        let previous = fake_mmdb(b"previous", CITY);
        std::fs::write(&dest, &previous).unwrap();

        let err = download_and_install(&dest, &url, CITY, None, "fumox-test")
            .await
            .unwrap_err();
        assert!(err.contains("database_type"), "{err}");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            previous,
            "the previous database stays in place"
        );
        assert!(
            tmp_files(&dir).is_empty(),
            "the temporary file is removed: {:?}",
            tmp_files(&dir)
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A pinned checksum is verified before the install: a download that
    /// does not match it is refused and the previous database stays.
    #[tokio::test]
    async fn a_pinned_checksum_is_verified_before_the_install() {
        let body = fake_mmdb(b"fresh", CITY);
        let url = serve_body(body.clone()).await;
        let dir = scratch_dir();
        let dest = dir.join("GeoLite2-City.mmdb");
        let previous = fake_mmdb(b"previous", CITY);
        std::fs::write(&dest, &previous).unwrap();
        let served = dir.join("served.bin");
        std::fs::write(&served, &body).unwrap();
        let digest = sha256_hex(&served).unwrap();

        // The wrong checksum refuses the install and keeps the old file.
        let err = download_and_install(&dest, &url, CITY, Some(&"0".repeat(64)), "fumox-test")
            .await
            .unwrap_err();
        assert!(err.contains("checksum mismatch"), "{err}");
        assert_eq!(std::fs::read(&dest).unwrap(), previous);

        // The right one installs the download.
        download_and_install(&dest, &url, CITY, Some(&digest), "fumox-test")
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), body);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The unattended download follows the release shortlink, so the
    /// redirect policy is the only thing between a hijacked release and a
    /// foreign file in `db_dir`. A 302 to anywhere outside the mirror
    /// hosts must fail the request instead of being followed.
    #[tokio::test]
    async fn a_redirect_off_the_mirror_hosts_is_refused() {
        // A server that redirects to a second server, which would happily
        // serve a body if it were ever reached.
        let payload_server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let payload_addr = payload_server.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = payload_server.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let body = fake_mmdb(b"served", CITY);
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            }
        });

        let redirector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirector_addr = redirector.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = redirector.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 302 Found\r\nlocation: http://{payload_addr}/x.mmdb\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = sock.write_all(head.as_bytes()).await;
            }
        });

        let dir = scratch_dir();
        let dest = dir.join("GeoLite2-City.mmdb");
        let err = download_body_capped(
            &format!("http://{redirector_addr}/GeoLite2-City.mmdb"),
            &tmp_path(&dest),
            "fumox-test",
            MAX_MMDB_BYTES,
        )
        .await
        .unwrap_err();
        assert!(err.contains("redirect"), "{err}");

        // Nothing was installed.
        assert!(!dest.exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same rule with the scheme on the safe side: a redirect to an
    /// https URL of a host nobody vouched for is refused by the host rule
    /// alone. The target is unresolvable, so the request fails before any
    /// network call — the refusal is the policy's, not the resolver's.
    #[tokio::test]
    async fn a_redirect_to_an_unexpected_https_host_is_refused() {
        let redirector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirector_addr = redirector.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = redirector.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let head = "HTTP/1.1 302 Found\r\nlocation: https://evil.example/x.mmdb\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                let _ = sock.write_all(head.as_bytes()).await;
            }
        });

        let dir = scratch_dir();
        let dest = dir.join("GeoLite2-City.mmdb");
        let err = download_body_capped(
            &format!("http://{redirector_addr}/GeoLite2-City.mmdb"),
            &tmp_path(&dest),
            "fumox-test",
            MAX_MMDB_BYTES,
        )
        .await
        .unwrap_err();
        assert!(err.contains("redirect"), "{err}");
        assert!(!dest.exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
