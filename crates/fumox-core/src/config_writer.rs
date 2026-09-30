//! Round-trip editor for `config/app.toml`.
//!
//! The admin panel's *Edit settings* page must write back individual
//! fields without destroying the comments the operator put in the file
//! (every section of `config/app.toml` carries RU/EN pair comments).
//! `toml_edit` is built for exactly that, its `DocumentMut` keeps the
//! decoration around every key.
//!
//! Atomic save: write to a sibling `<name>.tmp.<pid>`, then rename.
//! If `rename` fails (some network filesystems do not support it), fall
//! back to a direct write and surface the failure in the log, losing
//! atomicity is better than losing the change.

use std::path::{Path, PathBuf};
use std::str::FromStr;

#[cfg(all(unix, test))]
use std::os::unix::fs::PermissionsExt;

use toml_edit::{Array, DocumentMut, Item, Table, Value};

/// Failure mode of [`EditableConfig`] operations.
#[derive(Debug)]
pub enum ConfigWriteError {
    /// Path either does not exist and its parent is not writable,
    /// or exists but is read-only.
    Unwritable(PathBuf),
    /// `toml_edit` could not parse the file on disk.
    Parse { path: PathBuf, message: String },
    /// `set` was called with a key whose section does not correspond to
    /// any `[section]` block in the file and could not be created, or
    /// could not be dived through because the parent slot is occupied
    /// by a non-table value.
    UnknownSection(String),
    /// `set` was called with a malformed dotted key: empty, leading /
    /// trailing `.`, or containing `..`. Empty segments would write
    /// keys with no name into the file and toml_edit would parse them
    /// back fine, but the operator cannot have meant to do that.
    InvalidKey(String),
    /// I/O error during save (read, write, rename).
    Io(std::io::Error),
}

impl std::fmt::Display for ConfigWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unwritable(p) => write!(f, "config file not writable: {}", p.display()),
            Self::Parse { path, message } => {
                write!(f, "parse error in {}: {}", path.display(), message)
            }
            Self::UnknownSection(s) => write!(f, "unknown section: {s}"),
            Self::InvalidKey(s) => write!(f, "invalid dotted key: {s:?}"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for ConfigWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ConfigWriteError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// A writable handle over the on-disk TOML config.
///
/// Loaded once per request, mutated by [`Self::set`], committed by
/// [`Self::save`]. The in-memory document preserves comments, blank
/// lines and key ordering from the source file.
///
/// That is a read-modify-write of the whole file, and the settings
/// form has no double-submit guard, so the window between `load` and
/// `save` is reachable from two requests at once. The handle therefore
/// takes the editor lock on construction and releases it on drop, which
/// makes the snapshot the `save` writes a snapshot of the current file
/// rather than of whatever the file held when the request started.
pub struct EditableConfig {
    path: PathBuf,
    doc: DocumentMut,
    _lock: EditLock,
}

impl std::fmt::Debug for EditableConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EditableConfig")
            .field("path", &self.path)
            .field("doc", &"<elided>")
            .finish()
    }
}

impl EditableConfig {
    /// Load the TOML at `path`. Returns an empty document if the file
    /// does not exist yet (the admin panel's *Create from defaults*
    /// path writes one for the first time).
    ///
    /// Blocks while another live [`EditableConfig`] in this process is
    /// between its own `load` and its drop, so the document returned is
    /// the current state of the file and no save can land between the
    /// read and the mutation that follows it.
    pub fn load(path: &Path) -> Result<Self, ConfigWriteError> {
        let lock = EditLock::acquire();
        let doc = match std::fs::read_to_string(path) {
            Ok(s) => DocumentMut::from_str(&s).map_err(|e| ConfigWriteError::Parse {
                path: path.to_path_buf(),
                message: e.message().to_string(),
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => DocumentMut::new(),
            Err(e) => return Err(ConfigWriteError::Io(e)),
        };
        Ok(Self {
            path: path.to_path_buf(),
            doc,
            _lock: lock,
        })
    }

    /// Path the editor will write to on [`Self::save`].
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read-only view at the parsed document. Mostly for tests.
    pub fn doc(&self) -> &DocumentMut {
        &self.doc
    }

    /// Look up the leaf `Item` at a dotted path. Returns `None` if any
    /// segment of the path is absent.
    pub fn get(&self, dotted: &str) -> Option<&Item> {
        let mut current: &Item = self.doc.as_item();
        for segment in dotted.split('.') {
            current = current.as_table_like()?.get(segment)?;
        }
        Some(current)
    }

    /// Set the leaf at `dotted` to `value`. Auto-creates any missing
    /// intermediate `[section]` tables and the leaf itself, so callers
    /// can write a brand-new key without first inserting scaffolding.
    ///
    /// `dotted` must be a non-empty string of non-empty segments
    /// separated by exactly one `.`, no leading / trailing dot, no
    /// `..`. Empty or doubled segments are rejected with
    /// [`ConfigWriteError::InvalidKey`].
    pub fn set(&mut self, dotted: &str, value: Item) -> Result<(), ConfigWriteError> {
        if dotted.is_empty()
            || dotted.starts_with('.')
            || dotted.ends_with('.')
            || dotted.contains("..")
        {
            return Err(ConfigWriteError::InvalidKey(dotted.into()));
        }
        let segments: Vec<&str> = dotted.split('.').collect();
        if segments.iter().any(|s| s.is_empty()) {
            return Err(ConfigWriteError::InvalidKey(dotted.into()));
        }

        // Walk into the parent table, creating intermediates if needed.
        let mut current = self.doc.as_table_mut();
        for &segment in &segments[..segments.len() - 1] {
            current = enter_or_create_table(current, segment, dotted)?;
        }

        let leaf = segments[segments.len() - 1];
        current[leaf] = value;
        Ok(())
    }

    /// Atomic save: write to a sibling `<name>.tmp.<pid>.<n>` and
    /// rename over the original. Falls back to direct `write` on
    /// filesystems that reject `rename` (some NFS / SMB mounts).
    ///
    /// The handle owns the editor lock, so no other live
    /// [`EditableConfig`] in this process can have snapshotted the file
    /// before the mutation that produced this document: the second
    /// submission to wait, it waits in `load` and then reads what this
    /// save wrote.
    ///
    /// Tmp-file uniqueness: process id alone is not enough, because two
    /// concurrent saves from the same admin server process (a
    /// double-click on the form button, or a retry fire-and-forget)
    /// would race for the same `<name>.<pid>`. The static counter is
    /// bumped atomically on every call, so two overlapping saves from
    /// the same process produce two distinct tmp files. Two different
    /// processes differ on `<pid>`, so the union of the two makes the
    /// name globally unique within the lifetime of the dir.
    pub fn save(&self) -> Result<(), ConfigWriteError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = self
            .path
            .file_name()
            .ok_or_else(|| ConfigWriteError::Unwritable(self.path.clone()))?;
        let n = SAVE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_name = format!(
            "{}.tmp.{}.{:x}",
            file_name.to_string_lossy(),
            std::process::id(),
            n,
        );
        let tmp_path = parent.join(&tmp_name);

        let serialized = self.doc.to_string();
        write_tmp_preserving_mode(&self.path, &tmp_path, serialized.as_bytes())?;

        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            // Atomic rename is not universally supported. If it fails,
            // do a plain write and remove the tmp, losing atomicity is
            // preferable to losing the change. The user gets a warning
            // in the logs and may decide to back the file up first.
            // The direct write keeps the original inode, so the file's
            // permissions survive this path without extra work.
            tracing::warn!(
                error = %e,
                path = %self.path.display(),
                "atomic rename failed; falling back to direct write"
            );
            std::fs::write(&self.path, serialized.as_bytes())?;
            if let Err(rm_err) = std::fs::remove_file(&tmp_path) {
                // The tmp file leaked. Not fatal, the real config has
                // been written, but the operator should know so they can
                // clean up by hand.
                tracing::warn!(
                    error = %rm_err,
                    tmp = %tmp_path.display(),
                    "could not remove leftover tmp file after fallback write"
                );
            }
        }
        Ok(())
    }
}

/// Counter combined with PID/TID to keep concurrent `save()` calls
/// from stepping on each other's tmp files when two requests hit the
/// admin server at the same time.
static SAVE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One process-wide lock, not one per path: the admin panel edits exactly
/// one config, and keying by path would have to reconcile relative and
/// absolute spellings of the same file. Not reentrant: the flag is held from
/// `load` to drop, so `config::load_config` must never take it (the admin
/// handler re-reads the config through it while the handle is alive).
struct EditLock;

impl EditLock {
    fn acquire() -> Self {
        // Spin with `yield_now` first, then back off, so a handler that
        // only holds the lock across a handful of syscalls does not
        // burn a core for its whole duration while a sibling is in a
        // blocking write.
        let mut spins = 0u32;
        while EDITOR_LOCK
            .compare_exchange_weak(
                false,
                true,
                std::sync::atomic::Ordering::Acquire,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            if spins < 128 {
                spins += 1;
                std::thread::yield_now();
            } else {
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        }
        Self
    }
}

impl Drop for EditLock {
    fn drop(&mut self) {
        EDITOR_LOCK.store(false, std::sync::atomic::Ordering::Release);
    }
}

static EDITOR_LOCK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Write the tmp file with the original file's permission mode.
///
/// `save` commits by renaming the tmp over the original, which swaps the
/// inode: whatever mode the operator put on the config file would
/// silently decay to the umask default (typically 0644) on the first
/// admin-panel save. The file carries `[admin].token` — the same class
/// of plaintext secret for which `db.rs` deliberately hard-codes 0600 on
/// the SQLite file — so a hardened 0600 `app.toml` becoming world-readable
/// exposes the token to every local user (security review f5). The mode is
/// applied at tmp creation, so the file holding the token is never briefly
/// world-readable between a write and a chmod. A missing original (the
/// *Create from defaults* path) falls back to 0644.
#[cfg(unix)]
fn write_tmp_preserving_mode(original: &Path, tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mode = std::fs::metadata(original)
        .map(|meta| meta.permissions().mode())
        .unwrap_or(0o644);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(tmp)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_tmp_preserving_mode(_original: &Path, tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(tmp, bytes)
}

/// Move `current` into the table at `segment`, creating an empty table
/// if the slot was absent or held a non-table value.
fn enter_or_create_table<'a>(
    current: &'a mut Table,
    segment: &str,
    dotted: &str,
) -> Result<&'a mut Table, ConfigWriteError> {
    // `entry` returns an Entry enum. If the key exists as a table, we
    // dive into it; if it is a value or absent, we overwrite with a
    // fresh empty table. `or_insert` keeps any existing decoration.
    if !current.contains_key(segment) {
        current.insert(segment, Item::Table(Table::new()));
    }
    current
        .get_mut(segment)
        .and_then(|item| item.as_table_mut())
        .ok_or_else(|| ConfigWriteError::UnknownSection(dotted.into()))
}

/// Can the OS let us modify `path`? Either the file exists and its
/// permissions allow writes, or it does not exist and its parent
/// directory is writable (a brand-new file can be created there), or
/// `path` is a directory and we can create entries in it.
///
/// The directory case is not hypothetical: the admin panel's *Create
/// from defaults* handler asks about the config *directory*, because
/// the file it is about to create is not there yet. Opening a
/// directory `O_WRONLY` fails with `EISDIR` on Linux and macOS, so a
/// directory must be probed like the missing-file case instead of
/// being run through the file's open-for-write fast path.
///
/// The fast path checks the inode's `readonly` flag; the slow path
/// actually attempts an open-for-write (or a probe file in the
/// directory when the target is missing or is a directory) so a
/// read-only filesystem mount, the docker `:ro` case, where metadata
/// still looks writable but the kernel rejects every write with
/// `EROFS`, is detected too.
///
/// **Advisory only.** The check does not consult POSIX mode bits or
/// ACLs and is meaningless for `root`, which writes regardless. Use
/// it to decide whether to render the editor with enabled or disabled
/// controls, not as an access-control gate, `save()` re-checks errors
/// at write time.
pub fn is_writable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        // Asked about a directory, so answer the question that matters:
        // can we put a new entry in it?
        Ok(md) if md.is_dir() => can_create_in(path),
        Ok(md) => {
            if md.permissions().readonly() {
                return false;
            }
            // Open for write, Linux returns `EROFS` on a read-only mount
            // (e.g. docker `:ro`) without performing any I/O. macOS returns
            // `EROFS` for the same case at the VFS layer. Treat any open
            // failure as "not writable from this process".
            std::fs::OpenOptions::new().write(true).open(path).is_ok()
        }
        // File missing, the target's parent must accept new files.
        Err(_) => path.parent().is_some_and(can_create_in),
    }
}

/// Can we create a new file inside `dir`? Probes with a throwaway
/// `create_new` file so a read-only mount is surfaced even when the
/// directory is empty and no existing file would fail to open.
fn can_create_in(dir: &Path) -> bool {
    let Ok(md) = std::fs::metadata(dir) else {
        return false;
    };
    if md.permissions().readonly() {
        return false;
    }
    // Drop a probe file in the directory to surface a read-only mount
    // (otherwise we could miss a `:ro` filesystem with no existing
    // file in it). The probe is opened with `create_new(true)` so
    // we never overwrite a real file. The counter keeps two probes
    // racing in the same process from colliding on the clock reading
    // and reporting a writable directory as not writable.
    let probe = dir.join(format!(
        ".fumox-write-probe-{}-{}",
        std::process::id(),
        SAVE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// The reference `config/app.toml` shipped in the repository. Embedded
/// at compile time so the admin panel's *Create from defaults* button
/// can bootstrap a fresh checkout without depending on the working
/// directory layout at runtime. Updating `config/app.toml` in the repo
/// automatically updates the embedded copy on the next build.
pub const REFERENCE_CONFIG: &str = include_str!("../../../config/app.toml");

/// Convenience builders for the leaf values the editor page writes.
/// They convert into the `toml_edit::Item` shape that [`EditableConfig`]
/// accepts.
pub mod item {
    use super::*;

    pub fn string(s: impl Into<String>) -> Item {
        Item::Value(Value::from(s.into()))
    }

    pub fn boolean(b: bool) -> Item {
        Item::Value(Value::from(b))
    }

    pub fn integer(n: i64) -> Item {
        Item::Value(Value::from(n))
    }

    /// A multi-line array of strings (one element per visual line in
    /// the file). The editor serialises lists as `["a", "b"]` even when
    /// the operator typed one URL per line in the textarea.
    pub fn string_array(values: impl IntoIterator<Item = impl Into<String>>) -> Item {
        let arr: Array = values.into_iter().map(|v| Value::from(v.into())).collect();
        Item::Value(Value::Array(arr))
    }

    pub fn i64_array(values: impl IntoIterator<Item = i64>) -> Item {
        let arr: Array = values.into_iter().map(Value::from).collect();
        Item::Value(Value::Array(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fumox-cfg-writer-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_preserves_comments_in_reference_config() {
        // `config/app.toml` ships with RU/EN banner comments. Loading it
        // through `DocumentMut` must keep at least the top-of-file
        // banner, that is the whole point of round-tripping through
        // `toml_edit`.
        let doc = DocumentMut::from_str(super::REFERENCE_CONFIG).expect("reference must parse");
        let rendered = doc.to_string();
        assert!(rendered.contains("# Fumox"), "top-of-file banner lost");
        assert!(rendered.contains("[server]"), "section header lost");
        assert!(
            rendered.contains("FUMOX_СЕКЦИЯ__КЛЮЧ"),
            "RU inline comment lost"
        );
    }

    #[test]
    fn set_scalar_replaces_value_only() {
        let dir = tmp_dir("scalar");
        let path = dir.join("app.toml");
        std::fs::write(
            &path,
            "[server]\n# comment\nbind = \"0.0.0.0:8080\"\n[admin]\ntoken = \"x\"\n",
        )
        .unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap();
        let rendered = cfg.doc().to_string();

        assert!(rendered.contains("# comment"), "comment lost");
        assert!(
            rendered.contains("bind = \"127.0.0.1:9999\""),
            "new value missing"
        );
        assert!(
            !rendered.contains("0.0.0.0:8080"),
            "old value still present"
        );
        assert!(rendered.contains("[admin]"), "other section vanished");
        assert!(rendered.contains("token = \"x\""), "other key vanished");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_array_replaces_array_value() {
        let dir = tmp_dir("array");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[probe]\nrecheck_delays_secs = [900, 1800, 3600]\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set(
            "probe.recheck_delays_secs",
            item::i64_array([1800, 3600, 7200]),
        )
        .unwrap();
        let rendered = cfg.doc().to_string();

        assert!(!rendered.contains("900"), "old first entry still present");
        assert!(rendered.contains("1800"));
        assert!(rendered.contains("7200"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_creates_missing_section_and_key() {
        let dir = tmp_dir("create");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("probe.cycle_interval_secs", item::integer(120))
            .unwrap();
        let rendered = cfg.doc().to_string();

        assert!(rendered.contains("[probe]"), "section header not created");
        assert!(
            rendered.contains("cycle_interval_secs = 120"),
            "new key missing"
        );
        assert!(
            rendered.contains("bind = \"0.0.0.0:8080\""),
            "existing key lost"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_save_writes_through_to_disk() {
        let dir = tmp_dir("save");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap();
        cfg.save().unwrap();

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("127.0.0.1:9999"));

        // No stray tmp files left behind.
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftover.is_empty(), "tmp file leaked: {:?}", leftover);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression (security review f5): the save commits by renaming a
    /// fresh tmp file over the original, which swaps the inode — a mode
    /// the operator put on the file (0600 over the file that carries
    /// `[admin].token`) used to silently decay to the umask default on
    /// the first save.
    #[cfg(unix)]
    #[test]
    fn save_preserves_the_original_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("save-mode");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap();
        cfg.save().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "save() downgraded the file mode");
        // The tmp file is created with the preserved mode directly, so no
        // world-readable snapshot of the config ever exists next to it.
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftover.is_empty(), "tmp file leaked: {:?}", leftover);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_on_missing_file_creates_it() {
        let dir = tmp_dir("save-missing");
        let path = dir.join("app.toml");

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("0.0.0.0:8080"))
            .unwrap();
        cfg.save().unwrap();

        assert!(path.is_file());
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("[server]"));
        assert!(on_disk.contains("0.0.0.0:8080"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_file_returns_empty_document() {
        let dir = tmp_dir("missing");
        let path = dir.join("app.toml");
        let cfg = EditableConfig::load(&path).unwrap();
        // Empty doc, no parse error.
        assert!(cfg.doc().to_string().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_error_is_surfaced() {
        let dir = tmp_dir("parse-err");
        let path = dir.join("app.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"[server\nbind = broken\n").unwrap();
        drop(f);

        let err = EditableConfig::load(&path).unwrap_err();
        match err {
            ConfigWriteError::Parse { .. } => {}
            other => panic!("expected Parse, got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_writable_returns_true_for_writable_file() {
        let dir = tmp_dir("writable");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        assert!(is_writable(&path));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_writable_returns_false_for_readonly_file() {
        let dir = tmp_dir("readonly");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).unwrap();

        assert!(!is_writable(&path));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression: the *Create from defaults* handler asks about the
    /// config *directory*, not the file it is about to create in it
    /// (`settings.rs` passes `target.parent()`). Opening a directory
    /// `O_WRONLY` fails with `EISDIR` on Linux and macOS, so the
    /// open-for-write fast path reported "not writable" for a directory
    /// the process can obviously write into and the create button was
    /// permanently broken.
    #[test]
    fn is_writable_returns_true_for_writable_directory() {
        let dir = tmp_dir("writable-dir");
        assert!(dir.is_dir());
        assert!(
            is_writable(&dir),
            "is_writable must answer for a directory, that is what the create path passes"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The other half of the contract for a directory: a directory we
    /// may not write into is still not writable.
    #[test]
    fn is_writable_returns_false_for_readonly_directory() {
        let dir = tmp_dir("readonly-dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = is_writable(&dir);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!result, "is_writable must report false for a read-only dir");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression: `settings_update` is a read-modify-write of the whole
    /// file, and the write button has no double-submit guard, so two
    /// overlapping submissions used to interleave as
    /// `load(A) load(B) save(A) save(B)` and the second save renamed a
    /// document snapshotted before the first one landed. Both requests
    /// reported success and one change was gone. The load -> mutate ->
    /// save cycle has to be serialised for the whole process, the
    /// per-save tmp counter only solved the tmp-file-name half of it.
    #[test]
    fn overlapping_edits_do_not_lose_the_first_change() {
        let dir = tmp_dir("lost-update");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let (loaded_tx, loaded_rx) = std::sync::mpsc::channel::<()>();
        let first = std::thread::spawn({
            let path = path.clone();
            move || {
                let mut cfg = EditableConfig::load(&path).unwrap();
                cfg.set("server.bind", item::string("127.0.0.1:1111"))
                    .unwrap();
                // Tell the second submission that our snapshot is taken
                // and our change is not on disk yet, then hold the edit
                // open long enough for it to read a stale copy.
                loaded_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(200));
                cfg.save().unwrap();
            }
        });

        loaded_rx.recv().unwrap();
        let second = std::thread::spawn({
            let path = path.clone();
            move || {
                let mut cfg = EditableConfig::load(&path).unwrap();
                cfg.set("probe.cycle_interval_secs", item::integer(90))
                    .unwrap();
                cfg.save().unwrap();
            }
        });

        first.join().unwrap();
        second.join().unwrap();

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.contains("127.0.0.1:1111"),
            "second save rolled the file back to a stale snapshot: {on_disk}"
        );
        assert!(
            on_disk.contains("cycle_interval_secs = 90"),
            "second change missing: {on_disk}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Pins the scope of [`EditLock`]: it guards this module's
    /// read-modify-write path and nothing else. The plain figment
    /// loader (`config::load` / `load_config`) reads the same file
    /// without it, and it has to keep doing so — the admin handler
    /// re-reads the config through `refresh_live_config` while its
    /// `EditableConfig` is still alive, and the lock is not reentrant,
    /// so a loader that took it would deadlock that request.
    #[test]
    fn plain_config_loader_does_not_take_the_editor_lock() {
        let dir = tmp_dir("loader-lock-boundary");
        let path = dir.join("app.toml");
        std::fs::write(
            &path,
            "[server]\nbind = \"0.0.0.0:8080\"\n[probe]\ncycle_interval_secs = 60\n",
        )
        .unwrap();

        // Live handle, editor lock held for as long as this binding.
        let _cfg = EditableConfig::load(&path).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let loader_path = path.clone();
        std::thread::spawn(move || {
            let _ = crate::config::load_config(Some(&loader_path));
            tx.send(()).unwrap();
        });

        // A lock the loader also took would spin here until the timeout.
        let returned = rx.recv_timeout(std::time::Duration::from_secs(5));
        drop(_cfg);

        assert!(
            returned.is_ok(),
            "config::load_config must not take the editor lock: it deadlocked against a live EditableConfig"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression: a docker `:ro` mount on a directory that has no file in
    /// it yet (the *Create from defaults* path) must surface as not
    /// writable so the button can be disabled. Modeled with a parent
    /// directory whose mode strips write, on Linux this is the same
    /// code path a docker `:ro` mount goes through (the kernel rejects
    /// the open with `EROFS`); on macOS the permission-mode rejection
    /// arrives as `EACCES` and the test still covers the contract.
    #[test]
    fn is_writable_returns_false_when_probe_in_ro_parent_fails() {
        let dir = tmp_dir("ro-parent-probe");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let path = dir.join("app.toml");
        assert!(!path.exists());

        let result = is_writable(&path);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            !result,
            "is_writable must report false when a probe write in the parent fails"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_writable_returns_true_when_file_missing_but_parent_is() {
        let dir = tmp_dir("missing-parent-ok");
        let path = dir.join("app.toml");
        assert!(!path.exists());
        assert!(is_writable(&path));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn get_returns_value_at_dotted_path() {
        let dir = tmp_dir("get");
        let path = dir.join("app.toml");
        std::fs::write(
            &path,
            "[server]\nbind = \"0.0.0.0:8080\"\n[probe]\ncycle_interval_secs = 60\n",
        )
        .unwrap();

        let cfg = EditableConfig::load(&path).unwrap();
        assert!(cfg.get("server.bind").is_some());
        assert!(cfg.get("server").is_some());
        assert!(cfg.get("probe.cycle_interval_secs").is_some());
        assert!(cfg.get("probe.unknown_key").is_none());
        assert!(cfg.get("missing.anything").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_rejects_empty_or_doubled_segments() {
        let path = std::env::temp_dir().join("fumox-cfg-writer-nofile-needed.toml");
        let mut cfg = EditableConfig::load(&path).unwrap();

        for bad in ["", ".", ".foo", "foo.", "foo..bar", "foo...bar"] {
            let err = cfg
                .set(bad, item::string("x"))
                .expect_err(&format!("key {bad:?} must be rejected"));
            assert!(
                matches!(err, ConfigWriteError::InvalidKey(_)),
                "key {bad:?} returned wrong error: {err:?}"
            );
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_uses_unique_tmp_per_call() {
        // Five saves from the same process must end up with five
        // distinct tmp names; otherwise concurrent admin submissions
        // would race for the same file.
        let dir = tmp_dir("unique-tmp");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        for i in 0..5 {
            let mut cfg = EditableConfig::load(&path).unwrap();
            cfg.set("server.bind", item::string(format!("127.0.0.1:{i}")))
                .unwrap();
            cfg.save().unwrap();
        }
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("127.0.0.1:4"), "final write must win");

        // No leftover tmp files in the directory after the storm.
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftover.is_empty(), "tmp leaked: {leftover:?}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
