//! Round-trip editor for `config/app.toml`.
//!
//! The admin panel's *Edit settings* page must write back individual
//! fields without destroying the comments the operator put in the file
//! (every section of `config/app.toml` carries RU/EN pair comments).
//! `toml_edit` is built for exactly that, its `DocumentMut` keeps the
//! decoration around every key.
//!
//! Atomic save: write to a sibling `.<name>.tmp.<pid>.<n>`, then
//! rename. If `rename` fails (some network filesystems do not support
//! it), fall back to a direct write and surface the failure in the log,
//! losing atomicity is better than losing the change. When the direct
//! write fails too, the tmp holding the new content stays on the disk
//! and its path is logged, so neither version of the file is lost.
//!
//! Serialised save: the editor holds an exclusive advisory lock on a
//! sibling lock file for the whole read-modify-write cycle, so two
//! writers cannot interleave. The lock is a file lock rather than a
//! process-wide mutex because the admin panel is not the only writer
//! of this file: an operator edits it by hand, a deployment tool
//! rewrites it.
//!
//! Conflict detection: the file is fingerprinted when it is loaded and
//! again when it is saved. A file that changed in between carries a
//! concurrent modification, and the save is refused rather than
//! overwriting the other change.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use sha2::{Digest, Sha256};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

/// Re-exported so callers of [`EditableConfig::set`] can name the value
/// type without taking a direct `toml_edit` dependency.
pub use toml_edit::Item as ConfigItem;

/// Failure mode of [`EditableConfig`] operations.
///
/// The enum is `#[non_exhaustive]`: new variants and fields may land
/// with any release, match on it with a catch-all arm. Variants
/// compare equal field-by-field; the two failures of
/// [`ConfigWriteError::Io`] are the same error when the path and the
/// [`std::io::ErrorKind`] match, `io::Error` itself has no equality.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigWriteError {
    /// Path either does not exist and its parent is not writable,
    /// or exists but is read-only. Also what the save maps a
    /// permission denial or a read-only mount to: the config is not
    /// writable at all, the panel renders that as its read-only state.
    Unwritable(PathBuf),
    /// `toml_edit` could not parse the file on disk. `line` and
    /// `column` are the 1-based position in the file's text the parser
    /// failed at.
    Parse {
        path: PathBuf,
        message: String,
        line: usize,
        column: usize,
    },
    /// The write collided with an entry that is in the way: the section
    /// on disk holds a value where a table is needed, or the leaf on
    /// disk holds a table where a value is being written. `section` is
    /// the path segment that collided, `key` the dotted key that was
    /// being written.
    SectionConflict { section: String, key: String },
    /// `set` was called with a malformed dotted key: empty, leading /
    /// trailing `.`, or containing `..`. Empty segments would write
    /// keys with no name into the file and toml_edit would parse them
    /// back fine, but the operator cannot have meant to do that.
    InvalidKey(String),
    /// The file changed on disk between the load and the save. The
    /// write is refused: the document the caller holds is a snapshot
    /// of a file that no longer exists, and committing it would drop
    /// the other change.
    Conflict { path: PathBuf },
    /// The assembled document is not a config the binaries would load:
    /// an unknown key, a value of the wrong type, or a pair of values
    /// that fails the cross-field validation. `message` names the
    /// offending key.
    InvalidDocument { path: PathBuf, message: String },
    /// I/O error during save (read, write, rename). `path` is the file
    /// the operation failed on: the config for reads and direct
    /// writes, the temporary file for tmp writes.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for ConfigWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unwritable(p) => write!(f, "config file not writable: {}", p.display()),
            Self::Parse {
                path,
                message,
                line,
                column,
            } => write!(
                f,
                "parse error in {}:{line}:{column}: {message}",
                path.display()
            ),
            Self::SectionConflict { section, key } => write!(
                f,
                "config key `{key}` collides with the existing `{section}` entry"
            ),
            Self::InvalidKey(s) => write!(f, "invalid dotted key: {s:?}"),
            Self::Conflict { path } => write!(
                f,
                "{} changed on disk since it was loaded; reload the page and apply the change again",
                path.display()
            ),
            Self::InvalidDocument { path, message } => write!(
                f,
                "the resulting {} would not load: {message}",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(f, "i/o error on {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl PartialEq for ConfigWriteError {
    fn eq(&self, other: &Self) -> bool {
        use ConfigWriteError as E;
        match (self, other) {
            (E::Unwritable(a), E::Unwritable(b)) => a == b,
            (
                E::Parse {
                    path: a,
                    message: m,
                    line: la,
                    column: ca,
                },
                E::Parse {
                    path: b,
                    message: n,
                    line: lb,
                    column: cb,
                },
            ) => a == b && m == n && la == lb && ca == cb,
            (
                E::SectionConflict { section: a, key: k },
                E::SectionConflict { section: b, key: l },
            ) => a == b && k == l,
            (E::InvalidKey(a), E::InvalidKey(b)) => a == b,
            (E::Conflict { path: a }, E::Conflict { path: b }) => a == b,
            (
                E::InvalidDocument {
                    path: a,
                    message: m,
                },
                E::InvalidDocument {
                    path: b,
                    message: n,
                },
            ) => a == b && m == n,
            // `io::Error` has no equality; the kind at the same path is
            // the meaningful part of the failure.
            (E::Io { path: a, source: s }, E::Io { path: b, source: t }) => {
                a == b && s.kind() == t.kind()
            }
            _ => false,
        }
    }
}

impl Eq for ConfigWriteError {}

/// A writable handle over the on-disk TOML config.
///
/// Loaded once per request, mutated by [`Self::set`], committed by
/// [`Self::save`]. The in-memory document preserves comments, blank
/// lines and key ordering from the source file.
///
/// That is a read-modify-write of the whole file, and the settings
/// form has no double-submit guard, so the window between `load` and
/// `save` is reachable from two requests at once. The handle therefore
/// takes an exclusive lock on the config for its whole lifetime, which
/// makes the snapshot the `save` writes a snapshot of the current file
/// rather than of whatever the file held when the request started.
pub struct EditableConfig {
    path: PathBuf,
    doc: DocumentMut,
    /// Fingerprint of the bytes this document was parsed from. The
    /// save compares it with the file on disk: a file that changed in
    /// between carries a concurrent modification, and the write is
    /// refused instead of dropping the other change.
    fingerprint: String,
    /// The exclusive lock on the config, held from `load` to drop.
    /// `None` when the config directory cannot hold the lock file (a
    /// read-only mount), where the panel cannot write anyway.
    _lock: Option<ConfigLock>,
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
    /// Blocks while another writer holds the lock on this file, so the
    /// document returned is the current state of the file and no save
    /// can land between the read and the mutation that follows it.
    pub fn load(path: &Path) -> Result<Self, ConfigWriteError> {
        let lock = ConfigLock::acquire(path);
        let (text, fingerprint) = match std::fs::read_to_string(path) {
            Ok(s) => {
                let digest = hex_digest(s.as_bytes());
                (s, digest)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), String::new()),
            Err(e) => {
                return Err(ConfigWriteError::Io {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        };
        let doc = DocumentMut::from_str(&text).map_err(|e| {
            // The span points into the text just read; the operator
            // gets a file:line:column they can jump to in an editor.
            let (line, column) = line_col_at(&text, e.span().map(|s| s.start).unwrap_or(0));
            tracing::error!(
                path = %path.display(),
                line,
                column,
                error = e.message(),
                "the config file does not parse"
            );
            ConfigWriteError::Parse {
                path: path.to_path_buf(),
                message: e.message().to_string(),
                line,
                column,
            }
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            doc,
            fingerprint,
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
    ///
    /// The decoration of the value being replaced is carried over: the
    /// trailing comment of a key belongs to the key, not to the value
    /// it holds, and dropping it would silently strip the operator's
    /// notes from the file.
    ///
    /// A leaf that holds a table on disk is not replaced by a value:
    /// the write would drop every key under it. Such a collision is
    /// refused with [`ConfigWriteError::SectionConflict`].
    pub fn set(&mut self, dotted: &str, mut value: Item) -> Result<(), ConfigWriteError> {
        // One pass over the dotted key: any empty segment — the empty
        // key itself, a leading or trailing dot, a doubled one — is
        // rejected. Empty segments would write keys with no name into
        // the file and toml_edit would parse them back fine, but the
        // operator cannot have meant to do that.
        if dotted.split('.').any(str::is_empty) {
            return Err(ConfigWriteError::InvalidKey(dotted.into()));
        }
        let segments: Vec<&str> = dotted.split('.').collect();

        // Walk into the parent table, creating intermediates if needed.
        let mut current = self.doc.as_table_mut();
        for &segment in &segments[..segments.len() - 1] {
            current = enter_or_create_table(current, segment, dotted)?;
        }

        let leaf = segments[segments.len() - 1];
        if current
            .get(leaf)
            .is_some_and(|existing| existing.is_table() && !value.is_table())
        {
            return Err(ConfigWriteError::SectionConflict {
                section: leaf.to_string(),
                key: dotted.to_string(),
            });
        }
        // Carry the old decoration over to the replacement.
        if let Some(old) = current
            .get(leaf)
            .and_then(|item| item.as_value())
            .map(|value| value.decor().clone())
            && let Some(new) = value.as_value_mut()
        {
            *new.decor_mut() = old;
        }
        current[leaf] = value;
        Ok(())
    }

    /// Atomic save: write to a sibling `.<name>.tmp.<pid>.<n>` and
    /// rename over the original. Falls back to direct `write` on
    /// filesystems that reject `rename` (some NFS / SMB mounts); the
    /// atomicity and the durability guarantees hold on the rename path
    /// only, the direct write keeps the original inode.
    ///
    /// The tmp is fsynced before the rename and the parent dir after
    /// it, so a committed save survives a crash. A failed save leaves
    /// no tmp behind — unless the direct-write fallback failed too, in
    /// which case the tmp stays on the disk holding the new content and
    /// its path is logged: the direct write never truncates the
    /// original up front, so neither the previous nor the new version
    /// of the file is lost.
    ///
    /// The document is checked against the config model before anything
    /// is written: a file the binaries refuse to load aborts both of
    /// them at the next start, so a save that would produce one is
    /// refused here, where the operator can still fix it.
    ///
    /// The file is fingerprinted again before the write. A file that
    /// changed since [`Self::load`] carries somebody else's edit, and
    /// the save is refused with [`ConfigWriteError::Conflict`] rather
    /// than overwriting it.
    ///
    /// Tmp-file uniqueness: the name carries the process id and a
    /// counter, so two concurrent saves from the same admin server
    /// process (a double-click on the form button, or a retry
    /// fire-and-forget) cannot race for the same file. The file is
    /// created with `create_new`, so a name that is already taken is
    /// retried with the next counter value instead of overwriting
    /// somebody else's tmp.
    pub fn save(&mut self) -> Result<(), ConfigWriteError> {
        let serialized = self.doc.to_string();

        // The document must be one the binaries can load. The panel
        // writes the file verbatim and the next start of both binaries
        // aborts on anything the config model refuses, so a save that
        // would produce such a file is refused here.
        if let Err(err) = crate::config::parse_document(&serialized) {
            return Err(ConfigWriteError::InvalidDocument {
                path: self.path.clone(),
                message: err.to_string(),
            });
        }

        // The file must not have changed under us: the document in hand
        // is a snapshot of a file that no longer exists, and writing it
        // would drop whatever landed in the meantime.
        if fingerprint(&self.path) != self.fingerprint {
            return Err(ConfigWriteError::Conflict {
                path: self.path.clone(),
            });
        }

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = self
            .path
            .file_name()
            .ok_or_else(|| ConfigWriteError::Unwritable(self.path.clone()))?
            .to_string_lossy()
            .into_owned();

        let tmp_path = self.write_tmp(parent, &file_name, serialized.as_bytes())?;

        // The rename swaps the inode, and the tmp file was created by
        // this process: hand it the owner and the group of the config it
        // replaces, so the save does not silently transfer the file (and
        // the admin token in it) to the server's user.
        if let Err(err) = mirror_owner(&self.path, &tmp_path) {
            tracing::warn!(
                error = %err,
                path = %self.path.display(),
                "could not give the temporary file the original's owner; writing through the original file instead"
            );
            // No rename here: the tmp still carries this process's
            // owner, swapping it in would hand the config to the
            // server's user. The direct write keeps the tmp until it
            // has taken, so a failure loses neither version of the file.
            commit_direct(&self.path, &tmp_path, serialized.as_bytes())?;
            sync_parent_dir(parent);
            self.fingerprint = fingerprint(&self.path);
            return Ok(());
        }

        commit_save(
            &self.path,
            &tmp_path,
            serialized.as_bytes(),
            fs_rename,
            commit_in_place,
        )?;
        sync_parent_dir(parent);
        self.fingerprint = fingerprint(&self.path);
        Ok(())
    }

    /// Write the temporary file and return its path.
    ///
    /// The name carries the writer's pid and a counter, so two writers
    /// never pick the same one. `create_new` turns a collision into an
    /// error rather than a silent overwrite of somebody else's tmp,
    /// and the name is retried with the next counter value.
    fn write_tmp(
        &self,
        parent: &Path,
        file_name: &str,
        bytes: &[u8],
    ) -> Result<PathBuf, ConfigWriteError> {
        for _ in 0..TMP_NAME_ATTEMPTS {
            let n = SAVE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let tmp = parent.join(tmp_name(file_name, std::process::id(), n));
            match write_tmp_preserving_mode(&self.path, &tmp, bytes) {
                Ok(()) => return Ok(tmp),
                // Somebody else holds the name: take the next one. The
                // file on disk is not ours, so it is left alone.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                // A permission denial or a read-only mount is the
                // config directory refusing new files, the panel's
                // read-only answer naming the config; the rest carries
                // the tmp path the write failed on.
                Err(e) => return Err(save_io_error(&self.path, tmp, e)),
            }
        }
        Err(ConfigWriteError::Io {
            path: self.path.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "no free temporary file name next to {}",
                    self.path.display()
                ),
            ),
        })
    }
}

/// Counter combined with the process id to keep concurrent `save()`
/// calls from stepping on each other's tmp files when two requests hit
/// the admin server at the same time.
static SAVE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many tmp names a save tries before it gives up. The name
/// carries the pid and a counter, so a collision means another writer
/// in this very process picked the same counter value, which the
/// atomic bump rules out; the retry is a safety net, not a hot path.
const TMP_NAME_ATTEMPTS: u32 = 8;

/// One process-wide lock, used on the platforms without an advisory
/// file lock. Not reentrant: the guard is held from `load` to drop, so
/// `config::load_config` must never take it (the admin handler
/// re-reads the config through it while the handle is alive).
#[cfg(not(unix))]
static EDITOR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Exclusive advisory lock on the config, held for the whole
/// read-modify-write cycle.
///
/// The lock lives in a sibling file so every process that opens the
/// same config contends for it: the admin panel is not the only writer
/// of this file. The kernel drops the lock when the descriptor is
/// closed, so a crashed writer does not wedge the file.
enum ConfigLock {
    /// Unix: an exclusive `flock` on the sibling lock file. The
    /// descriptor is held for its drop side effect: closing it is what
    /// releases the lock.
    #[cfg(unix)]
    File { _file: std::fs::File },
    /// Other platforms: the process-wide mutex.
    #[cfg(not(unix))]
    Process(std::sync::MutexGuard<'static, ()>),
}

impl ConfigLock {
    /// Take the lock for `path`.
    ///
    /// A config directory that cannot hold the lock file (a read-only
    /// mount, `FUMOX_CONFIG_ACCESS=ro`) yields no lock at all: the
    /// panel cannot write there anyway, and the fingerprint check still
    /// refuses a write that would drop somebody else's change.
    #[cfg(unix)]
    fn acquire(path: &Path) -> Option<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let lock_path = lock_file_path(path);
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).mode(0o600);
        let file = match options.open(&lock_path) {
            Ok(file) => file,
            Err(err) => {
                // The directory may be read-only while the lock file is
                // still there: a read-only descriptor can be locked.
                match std::fs::File::open(&lock_path) {
                    Ok(file) => file,
                    Err(_) => {
                        tracing::warn!(
                            error = %err,
                            path = %lock_path.display(),
                            "config lock unavailable; concurrent saves are not serialised"
                        );
                        return None;
                    }
                }
            }
        };
        // SAFETY: `file` owns a valid descriptor for the lock file.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                error = %err,
                path = %lock_path.display(),
                "config lock unavailable; concurrent saves are not serialised"
            );
            return None;
        }
        Some(Self::File { _file: file })
    }

    #[cfg(not(unix))]
    fn acquire(_path: &Path) -> Option<Self> {
        let guard = EDITOR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some(Self::Process(guard))
    }
}

/// Path of the lock file that guards `path`.
fn lock_file_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "app.toml".to_string());
    parent.join(format!(".{name}.lock"))
}

/// Fingerprint of the bytes at `path`: the hex sha256 of the file, or
/// the empty string when the file does not exist.
///
/// The panel sends the fingerprint of the file it rendered with the
/// form and refuses the submit when the file on disk no longer
/// matches: an operator who edited `app.toml` by hand in the meantime
/// would otherwise lose that edit to the stale form.
pub fn fingerprint(path: &Path) -> String {
    match std::fs::read(path) {
        Ok(bytes) => hex_digest(&bytes),
        Err(_) => String::new(),
    }
}

/// Hex sha256 of `bytes`.
fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The 1-based line and column of a byte offset in `text`, the column
/// counted in characters so a RU banner comment before the error does
/// not shift it. An offset past the text or inside a character is
/// pulled back to the nearest boundary.
fn line_col_at(text: &str, offset: usize) -> (usize, usize) {
    let mut offset = offset.min(text.len());
    while offset > 0 && !text.is_char_boundary(offset) {
        offset -= 1;
    }
    let head = &text[..offset];
    let line = 1 + head.matches('\n').count();
    let column = match head.rfind('\n') {
        Some(nl) => 1 + head[nl + 1..].chars().count(),
        None => 1 + head.chars().count(),
    };
    (line, column)
}

/// Name of the sibling temporary file a save writes through.
///
/// Hidden (a leading dot) so it does not sit in a directory listing
/// next to the real config, and it carries the writer's pid so a stale
/// file can be attributed to a process that is gone.
fn tmp_name(file_name: &str, pid: u32, n: u64) -> String {
    format!(".{file_name}.tmp.{pid}.{n:x}")
}

/// Remove the leftover temporary files of writers that are gone.
///
/// A save that died between creating the tmp and renaming it leaves a
/// copy of the config behind, and the config carries `[admin].token`.
/// The tmp files are named `.<name>.tmp.<pid>.<n>`, so the pid says
/// who wrote it: a pid that is not alive any more cannot be writing.
pub fn cleanup_stale_tmp_files(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = tmp_name_pid(&name) else {
            continue;
        };
        if process_is_alive(pid) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => {
                removed += 1;
                tracing::warn!(
                    path = %entry.path().display(),
                    "removed a leftover temporary config file; it holds [admin].token"
                );
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %entry.path().display(),
                    "could not remove a leftover temporary config file; it holds [admin].token"
                );
            }
        }
    }
    removed
}

/// The pid out of a temporary config file name, when the name is one
/// of ours.
fn tmp_name_pid(name: &str) -> Option<u32> {
    let rest = name.strip_prefix('.')?;
    let (_, tail) = rest.split_once(".tmp.")?;
    let pid = tail.split('.').next()?;
    pid.parse().ok()
}

/// Is the process with this pid still running?
#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only probes for existence, it never signals.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    // The process exists but belongs to another user.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    // Without a way to probe for a live process, a leftover file is
    // kept: removing a file a live writer still needs would break it.
    true
}

/// Write the tmp file with the original file's permission mode.
///
/// `save` commits by renaming the tmp over the original, which swaps the
/// inode: whatever mode the operator put on the config file would
/// silently decay to the umask default (typically 0644) on the first
/// admin-panel save. The file carries `[admin].token`, the same class
/// of plaintext secret for which `db.rs` deliberately hard-codes 0600 on
/// the SQLite file, so a hardened 0600 `app.toml` becoming world-readable
/// exposes the token to every local user (security review f5). The mode is
/// applied at tmp creation, so the file holding the token is never briefly
/// world-readable between a write and a chmod.
///
/// A missing original (the *Create from defaults* path) gets 0600: the
/// file is created from a document that may carry the admin token, so it
/// starts private rather than world-readable.
///
/// The body is fsynced before the handle drops: the save commits by rename,
/// and without the flush a crash could leave a truncated config in place.
///
/// The file is created with `create_new`, so a name that is taken is an
/// error rather than an overwrite of somebody else's tmp. A failure
/// after the creation removes the file again: it is a copy of the
/// config, with the token in it.
#[cfg(unix)]
fn write_tmp_preserving_mode(original: &Path, tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mode = std::fs::metadata(original)
        .map(|meta| meta.permissions().mode())
        .unwrap_or(0o600);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(tmp)?;
    // The kernel masks the creation mode with the process umask, so a
    // 0660 config under the usual 022 umask would come back 0640. The
    // exact bits are set again on the descriptor: `fchmod` is not
    // umasked. The mode is applied before the bytes, so the file
    // holding the token is never briefly more permissive than the
    // original.
    let result = file
        .set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all());
    if result.is_err() {
        drop(file);
        remove_tmp(tmp);
    }
    result
}

#[cfg(not(unix))]
fn write_tmp_preserving_mode(_original: &Path, tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(tmp)?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    if result.is_err() {
        drop(file);
        remove_tmp(tmp);
    }
    result
}

/// Commit the save: rename the committed tmp over the config, or fall
/// back to a direct write when the filesystem rejects the rename.
///
/// `rename` and `commit` are injected so tests can force either half
/// to fail. On success the tmp is gone — renamed away, or removed
/// after the direct write took over. When the fallback fails too, the
/// tmp stays on the disk holding the new content and its path is
/// logged: the original keeps its bytes (the direct write never
/// truncates up front) and the new version is recoverable by hand
/// instead of being lost with the tmp.
fn commit_save<R, C>(
    path: &Path,
    tmp: &Path,
    bytes: &[u8],
    rename: R,
    commit: C,
) -> Result<(), ConfigWriteError>
where
    R: FnOnce(&Path, &Path) -> std::io::Result<()>,
    C: FnOnce(&Path, &[u8]) -> std::io::Result<()>,
{
    if let Err(e) = rename(tmp, path) {
        // Atomic rename is not universally supported. If it fails,
        // do a plain write and remove the tmp, losing atomicity is
        // preferable to losing the change. The user gets a warning
        // in the logs and may decide to back the file up first.
        // The direct write keeps the original inode, so the file's
        // permissions survive this path without extra work.
        tracing::warn!(
            error = %e,
            path = %path.display(),
            "atomic rename failed; falling back to direct write"
        );
        commit_in_place_fallback(path, tmp, bytes, commit)?;
    }
    Ok(())
}

/// The direct write behind both fallback points: rename refused, or
/// the tmp cannot take over the original's ownership. The tmp is only
/// removed after the write has taken — a write that dies half-way
/// leaves the uncommitted copy on the disk, its path logged.
fn commit_in_place_fallback<C>(
    path: &Path,
    tmp: &Path,
    bytes: &[u8],
    commit: C,
) -> Result<(), ConfigWriteError>
where
    C: FnOnce(&Path, &[u8]) -> std::io::Result<()>,
{
    if let Err(e) = commit(path, bytes) {
        tracing::error!(
            error = %e,
            path = %path.display(),
            tmp = %tmp.display(),
            "the direct write failed too; the uncommitted new content stays in the temporary file"
        );
        return Err(save_io_error(path, path.to_path_buf(), e));
    }
    remove_tmp(tmp);
    Ok(())
}

/// The direct write for the ownership-fallback point, which never gets
/// to rename: the tmp still carries this process's owner and swapping
/// it in would hand the config to the server's user.
fn commit_direct(path: &Path, tmp: &Path, bytes: &[u8]) -> Result<(), ConfigWriteError> {
    commit_in_place_fallback(path, tmp, bytes, commit_in_place)
}

/// `std::fs::rename` with concrete argument types: the generic
/// `AsRef<Path>` item does not satisfy a higher-ranked `FnOnce(&Path,
/// &Path)` bound.
fn fs_rename(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

/// Classify a save-time I/O error. A permission denial or a read-only
/// mount means the config is not writable at all, the panel renders
/// that as its read-only state and names the config, not the tmp;
/// every other error stays a raw [`ConfigWriteError::Io`] carrying the
/// file the operation failed on.
fn save_io_error(unwritable: &Path, io_path: PathBuf, source: std::io::Error) -> ConfigWriteError {
    if matches!(
        source.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
    ) {
        ConfigWriteError::Unwritable(unwritable.to_path_buf())
    } else {
        ConfigWriteError::Io {
            path: io_path,
            source,
        }
    }
}

/// Commit the save through the original inode instead of renaming a
/// temporary file over it.
///
/// The write is not atomic: a reader can observe a partially written
/// file. It is the fallback for the case where the temporary file
/// cannot take over the original's ownership, and it keeps the owner
/// and the mode the operator put on the config.
///
/// The file is not truncated up front: the bytes land first and the
/// tail is cut to the written length after them, so a write that dies
/// half-way leaves the old content behind the partial new prefix
/// instead of an empty or truncated file.
fn commit_in_place(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_all()
}

/// Give the temporary file the owner and the group of the config it is
/// about to replace.
///
/// A rename swaps the inode, and the temporary file was created by this
/// process: without this the first admin save silently hands the config
/// (and the token in it) to the server's user.
///
/// The error is reported rather than swallowed: the caller falls back
/// to writing through the original inode, which keeps the ownership at
/// the cost of atomicity.
#[cfg(unix)]
fn mirror_owner(original: &Path, tmp: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let meta = match std::fs::metadata(original) {
        Ok(meta) => meta,
        // Nothing to mirror: the config does not exist yet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let file = std::fs::OpenOptions::new().write(true).open(tmp)?;
    // SAFETY: `file` owns a valid descriptor.
    let rc = unsafe { libc::fchown(file.as_raw_fd(), meta.uid(), meta.gid()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn mirror_owner(_original: &Path, _tmp: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Remove a temporary config file.
///
/// The file carries the same secrets as the config itself, so a failure
/// to remove it is reported: the operator has to delete it by hand.
fn remove_tmp(tmp: &Path) {
    if let Err(err) = std::fs::remove_file(tmp) {
        if err.kind() == std::io::ErrorKind::NotFound {
            return;
        }
        tracing::warn!(
            error = %err,
            tmp = %tmp.display(),
            "could not remove a temporary config file; it holds [admin].token, remove it by hand"
        );
    }
}

/// Best-effort `fsync` of the config's parent dir, so the rename is durable
/// too. Some filesystems refuse directory syncs; the failure is reported
/// rather than ignored, the data itself was already fsynced by
/// [`write_tmp_preserving_mode`] but the rename may not survive a crash.
#[cfg(unix)]
fn sync_parent_dir(dir: &Path) {
    match std::fs::File::open(dir) {
        Ok(d) => {
            if let Err(err) = d.sync_all() {
                tracing::warn!(
                    error = %err,
                    path = %dir.display(),
                    "could not fsync the config directory; the saved config may not survive a crash"
                );
            }
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %dir.display(),
                "could not open the config directory to fsync it"
            );
        }
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_dir: &Path) {}

/// Move `current` into the table at `segment`.
///
/// An absent slot gets an empty table, so the caller can write a key
/// into a section the file does not have yet. A slot that holds a
/// value is left alone: the caller cannot write a key under it, and
/// the write is refused with
/// [`ConfigWriteError::SectionConflict`] naming the segment that
/// collided.
fn enter_or_create_table<'a>(
    current: &'a mut Table,
    segment: &str,
    dotted: &str,
) -> Result<&'a mut Table, ConfigWriteError> {
    if !current.contains_key(segment) {
        current.insert(segment, Item::Table(Table::new()));
    }
    current
        .get_mut(segment)
        .and_then(|item| item.as_table_mut())
        .ok_or_else(|| ConfigWriteError::SectionConflict {
            section: segment.to_string(),
            key: dotted.to_string(),
        })
}

/// The answer of [`is_writable`] to "can the OS let us modify `path`?"
///
/// Every variant but [`Writability::Writable`] names the reason of the
/// refusal, and every refusal is logged at `warn` with the path — the
/// panel disables the editor on a refusal, the log says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Writability {
    /// Writes land: the file opened for write, or the directory took a
    /// probe file.
    Writable,
    /// The file (or the directory that would hold it) carries a
    /// read-only mode bit.
    ReadOnlyMode,
    /// The mode bits look writable but the kernel refused the write:
    /// a read-only filesystem mount, the docker `:ro` case.
    ReadOnlyMount,
    /// The target (or the directory that would hold it) does not exist.
    NotFound,
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
/// `EROFS`, is detected too. A refusal comes back as the
/// [`Writability`] variant naming why, every refusal is logged at
/// `warn` with the path and the cause; the `Err` arm is a probe that
/// failed for another reason, the raw error is the reason.
///
/// **Advisory only.** The check does not consult POSIX mode bits or
/// ACLs and is meaningless for `root`, which writes regardless. Use
/// it to decide whether to render the editor with enabled or disabled
/// controls, not as an access-control gate, `save()` re-checks errors
/// at write time.
pub fn is_writable(path: &Path) -> Result<Writability, std::io::Error> {
    is_writable_with(path, &can_open_for_write, &create_probe_file)
}

/// The injected-probe shape of [`is_writable`]: `open_for_write` is
/// the open-for-write attempt on an existing file, `probe_dir` drops a
/// throwaway file into a directory. Both are swapped in tests to force
/// the slow paths a real filesystem only shows on a read-only mount.
fn is_writable_with(
    path: &Path,
    open_for_write: &dyn Fn(&Path) -> std::io::Result<()>,
    probe_dir: &dyn Fn(&Path) -> std::io::Result<()>,
) -> Result<Writability, std::io::Error> {
    match std::fs::metadata(path) {
        // Asked about a directory, so answer the question that matters:
        // can we put a new entry in it?
        Ok(md) if md.is_dir() => can_create_in_with(path, probe_dir),
        Ok(md) => {
            if md.permissions().readonly() {
                tracing::warn!(
                    path = %path.display(),
                    "config file carries a read-only mode bit"
                );
                return Ok(Writability::ReadOnlyMode);
            }
            // Open for write: Linux returns `EROFS` on a read-only
            // mount (e.g. docker `:ro`) without performing any I/O,
            // macOS at the VFS layer. A refused open is the
            // read-only-mount answer when the kernel says so, any
            // other failure is reported as-is.
            open_for_write(path)
                .map(|()| Writability::Writable)
                .or_else(|e| {
                    if e.kind() == std::io::ErrorKind::ReadOnlyFilesystem {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "config file refused an open for write: read-only filesystem"
                        );
                        Ok(Writability::ReadOnlyMount)
                    } else {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "config file refused an open for write"
                        );
                        Err(e)
                    }
                })
        }
        // File missing, the target's parent must accept new files. A
        // bare relative name ("app.toml") has an empty parent, which is
        // the current directory, not the filesystem root.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            can_create_in_with(dir, probe_dir)
        }
        Err(e) => Err(e),
    }
}

/// The open-for-write probe for an existing file: an actual open, the
/// only way a read-only mount shows itself while the mode bits look
/// writable. Leaks nothing: the handle drops immediately.
fn can_open_for_write(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new().write(true).open(path).map(drop)
}

/// Can we create a new file inside `dir`? Probes with a throwaway
/// `create_new` file so a read-only mount is surfaced even when the
/// directory is empty and no existing file would fail to open.
fn can_create_in_with(
    dir: &Path,
    probe: &dyn Fn(&Path) -> std::io::Result<()>,
) -> Result<Writability, std::io::Error> {
    let md = match std::fs::metadata(dir) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                path = %dir.display(),
                error = %e,
                "config directory does not exist"
            );
            return Ok(Writability::NotFound);
        }
        Err(e) => return Err(e),
    };
    if md.permissions().readonly() {
        tracing::warn!(
            path = %dir.display(),
            "config directory carries a read-only mode bit"
        );
        return Ok(Writability::ReadOnlyMode);
    }
    match probe(dir) {
        Ok(()) => Ok(Writability::Writable),
        // The probe name is taken: somebody else managed to create a
        // file in this directory, which is the very question asked.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(Writability::Writable),
        Err(e) if e.kind() == std::io::ErrorKind::ReadOnlyFilesystem => {
            tracing::warn!(
                path = %dir.display(),
                error = %e,
                "config directory refused a probe write: read-only filesystem"
            );
            Ok(Writability::ReadOnlyMount)
        }
        Err(e) => {
            tracing::warn!(
                path = %dir.display(),
                error = %e,
                "config directory refused a probe write"
            );
            Err(e)
        }
    }
}

/// Counter for probe-file names, separate from the save counter: a
/// probe and a save bump their own sequences, so a probe can never
/// collide with a tmp name.
static PROBE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Drop a throwaway probe file into `dir`, the probe
/// [`can_create_in_with`] runs. The name carries the pid, a random
/// component and the counter: two processes probing the same directory
/// (a restart, a second instance in the same container) pick different
/// names, and two probes in this process cannot race for one either.
fn create_probe_file(dir: &Path) -> std::io::Result<()> {
    let probe = dir.join(format!(
        ".fumox-write-probe-{}-{:x}-{}",
        std::process::id(),
        rand::random::<u32>(),
        PROBE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map(drop)?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Create `path` with `contents` and mode `0600`.
///
/// The config file can carry `[admin].token`, so it must never exist
/// world-readable, not even for the moment between the create and a
/// later chmod. The mode is therefore set at creation time.
///
/// On non-Unix platforms the platform's ACL model governs and the mode
/// is not applied.
pub fn create_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

/// Write `contents` to `path` through the same atomic path a save
/// takes: a temporary file in the same directory, fsynced, then moved
/// into place. The config file can carry `[admin].token`, so it must
/// never exist world-readable, not even for the moment between the
/// create and a later chmod: the mode is set at creation time.
///
/// An existing file is never overwritten. The check runs under the
/// same advisory lock the editor takes, so a create cannot race the
/// *Edit settings* form for the same path.
///
/// On non-Unix platforms the platform's ACL model governs and the mode
/// is not applied.
pub fn create_private_file_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    let _lock = ConfigLock::acquire(path);
    if path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists", path.display()),
        ));
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the config path has no file name",
            )
        })?
        .to_string_lossy()
        .into_owned();

    let mut tmp = None;
    for _ in 0..TMP_NAME_ATTEMPTS {
        let n = SAVE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = parent.join(tmp_name(&file_name, std::process::id(), n));
        match write_tmp_preserving_mode(path, &candidate, contents.as_bytes()) {
            Ok(()) => {
                tmp = Some(candidate);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let Some(tmp) = tmp else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("no free temporary file name next to {}", path.display()),
        ));
    };

    if let Err(err) = std::fs::rename(&tmp, path) {
        remove_tmp(&tmp);
        return Err(err);
    }
    sync_parent_dir(parent);
    Ok(())
}

/// The reference `app.toml` shipped inside the crate
/// (`crates/fumox-core/reference/app.toml`). Embedded at compile time
/// so the admin panel's *Create from defaults* button can bootstrap a
/// fresh checkout without depending on the working directory layout at
/// runtime — and so the crate builds and packages without reaching for
/// a file outside it. `config/app.toml` at the repository root is the
/// deployable example the guides tell operators to copy; keep it in
/// sync with the embedded reference.
pub const REFERENCE_CONFIG: &str = include_str!("../reference/app.toml");

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
    fn a_created_config_is_private_and_never_overwrites() {
        let dir = tmp_dir("create");
        let path = dir.join("app.toml");

        create_private_file_atomic(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[server]\nbind = \"0.0.0.0:8080\"\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "a fresh config carries the admin token and must not be readable by others"
            );
        }

        // A second create must not overwrite what is there: the panel
        // offers the button only for a missing file, and a create that
        // clobbered an existing config would lose the operator's edits.
        let err =
            create_private_file_atomic(&path, "[server]\nbind = \"0.0.0.0:1\"\n").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("0.0.0.0:8080"),
            "the existing config must survive a refused create"
        );

        // No temporary file is left behind next to the config. The
        // advisory lock file is not one: it is the lock, not a leftover.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "app.toml" && !name.ends_with(".lock"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "the create must leave no temporary file behind: {leftovers:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
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

    /// Regression: a failed rename + failed fallback write used to leak the
    /// tmp (a config copy with `[admin].token]`). The save refuses before
    /// it writes anything when the file changed under it, so nothing is
    /// left behind.
    #[test]
    fn a_refused_save_leaves_no_tmp_behind() {
        let dir = tmp_dir("fallback-leak");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        let err = cfg.save().unwrap_err();
        assert!(
            matches!(err, ConfigWriteError::Conflict { .. }),
            "expected a conflict, got {err:?}"
        );

        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftover.is_empty(), "tmp file leaked: {:?}", leftover);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A temporary file that is already taken belongs to somebody else:
    /// the save must neither overwrite it nor delete it.
    #[test]
    fn an_existing_tmp_is_neither_overwritten_nor_removed() {
        let dir = tmp_dir("tmp-taken");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        let tmp = dir.join(".app.toml.tmp.4242.1");
        std::fs::write(&tmp, b"somebody else's tmp").unwrap();

        let err = write_tmp_preserving_mode(&path, &tmp, b"ours").unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists,
            "a taken tmp name must be an error, not an overwrite"
        );
        assert_eq!(
            std::fs::read(&tmp).unwrap(),
            b"somebody else's tmp",
            "the tmp of another writer must be left alone"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The tmp file of a save is hidden and carries the writer's pid, so
    /// a leftover one can be attributed to a process that is gone.
    #[test]
    fn a_leftover_tmp_of_a_dead_writer_is_cleaned_up() {
        let dir = tmp_dir("stale-tmp");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        let stale = dir.join(".app.toml.tmp.999999.1");
        std::fs::write(&stale, b"[admin]\ntoken = \"secret\"\n").unwrap();
        // A tmp of a live writer (this process) stays.
        let live = dir.join(tmp_name("app.toml", std::process::id(), 0));
        std::fs::write(&live, b"[admin]\ntoken = \"secret\"\n").unwrap();

        let removed = cleanup_stale_tmp_files(&dir);
        assert_eq!(removed, 1, "exactly the dead writer's tmp must go");
        assert!(!stale.exists(), "the stale tmp must be gone");
        assert!(live.exists(), "the tmp of a live writer must stay");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression (security review f5): the save commits by renaming a
    /// fresh tmp file over the original, which swaps the inode, a mode
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

    /// A config file created from scratch can carry `[admin].token`, so it
    /// must never be world-readable, not even for the moment between the
    /// create and a later chmod.
    #[cfg(unix)]
    #[test]
    fn save_on_missing_file_creates_it_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("save-missing-mode");
        let path = dir.join("app.toml");

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("0.0.0.0:8080"))
            .unwrap();
        cfg.save().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "a fresh config must not be readable by others"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The *Create from defaults* path writes the reference config through
    /// the same helper, with the same mode.
    #[cfg(unix)]
    #[test]
    fn create_private_file_writes_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("create-private");
        let path = dir.join("app.toml");
        create_private_file(&path, REFERENCE_CONFIG).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(std::fs::read_to_string(&path).unwrap().contains("[server]"));

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
        if let ConfigWriteError::Parse {
            message,
            line,
            column,
            ..
        } = &err
        {
            assert!(!message.is_empty(), "the parser's message must be kept");
            assert!(
                *line >= 1 && *column >= 1,
                "a 1-based position is expected, got {line}:{column}"
            );
        } else {
            panic!("expected Parse, got {err:?}");
        }
        // The Display carries the file:line:column an editor can jump
        // to, plus the parser's own message.
        let text = err.to_string();
        assert!(
            text.contains(&path.display().to_string()) && text.contains("parse error"),
            "the error must name the file and the failure: {text}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The line and the column point at the offending byte of the
    /// original text, counted per line and per character, so the
    /// position is usable in an editor even after RU comments.
    #[test]
    fn parse_error_line_and_column_point_at_the_failure() {
        // Offset 13 is the `s` of `[server`, one character (`[`) stands
        // before it on the line.
        let (line, column) = line_col_at("a = 1\nb = 2\n[server\n", 13);
        assert_eq!((line, column), (3, 2));
        // A RU comment before the failure must not shift the column:
        // offset 29 is the `x` of `b = x`, four characters stand before
        // it on the line, the comment's bytes stay on their own line.
        let (line, column) = line_col_at("# комментарий\nb = x\n", 29);
        assert_eq!((line, column), (2, 5));
        // Offsets past the text or inside a character are pulled back.
        assert_eq!(line_col_at("ab", 100), (1, 3));
        assert_eq!(line_col_at("я", 1), (1, 1), "offset 1 is inside `я`");
    }

    #[test]
    fn is_writable_returns_true_for_writable_file() {
        let dir = tmp_dir("writable");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        assert!(matches!(is_writable(&path), Ok(Writability::Writable)));
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

        assert!(matches!(is_writable(&path), Ok(Writability::ReadOnlyMode)));
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
            matches!(is_writable(&dir), Ok(Writability::Writable)),
            "is_writable must answer for a directory, that is what the create path passes"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The other half of the contract for a directory: a directory we
    /// may not write into is still not writable.
    #[cfg(unix)]
    #[test]
    fn is_writable_returns_false_for_readonly_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("readonly-dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = is_writable(&dir);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            matches!(result, Ok(Writability::ReadOnlyMode)),
            "is_writable must refuse a read-only dir, got {result:?}"
        );
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
    ///
    /// Deterministic, no sleeps: the first submission signals that its
    /// snapshot is taken and holds the handle until the second signals
    /// that it is at its load attempt, so the second always reaches the
    /// locked file while the first still owns it.
    #[test]
    fn overlapping_edits_do_not_lose_the_first_change() {
        let dir = tmp_dir("lost-update");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel::<()>();
        let (loading_tx, loading_rx) = std::sync::mpsc::channel::<()>();
        let first = std::thread::spawn({
            let path = path.clone();
            move || {
                let mut cfg = EditableConfig::load(&path).unwrap();
                cfg.set("server.bind", item::string("127.0.0.1:1111"))
                    .unwrap();
                // Our snapshot is taken and our change is not on disk
                // yet. Hold the edit open until the second submission
                // has reached its load attempt, then commit.
                snapshot_tx.send(()).unwrap();
                loading_rx.recv().unwrap();
                cfg.save().unwrap();
            }
        });

        snapshot_rx.recv().unwrap();
        let second = std::thread::spawn({
            let path = path.clone();
            move || {
                loading_tx.send(()).unwrap();
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

    /// The lock must not make the handle un-sendable: the admin server
    /// holds it across the await points of a request, and a type that
    /// is not `Send` cannot cross one. The advisory lock is held by an
    /// owned descriptor rather than by a `MutexGuard`, which is what
    /// keeps the handle `Send`.
    #[test]
    fn the_editor_handle_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<EditableConfig>();
    }

    /// Pins the scope of the editor lock: it guards this module's
    /// read-modify-write path and nothing else. The plain figment
    /// loader (`config::load` / `load_config`) reads the same file
    /// without it, and it has to keep doing so, the admin handler
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

        // A lock the loader also took would block here until the timeout.
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
    #[cfg(unix)]
    #[test]
    fn is_writable_returns_false_when_probe_in_ro_parent_fails() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("ro-parent-probe");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let path = dir.join("app.toml");
        assert!(!path.exists());

        let result = is_writable(&path);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            !matches!(result, Ok(Writability::Writable)),
            "is_writable must refuse when a probe write in the parent fails, got {result:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_writable_returns_true_when_file_missing_but_parent_is() {
        let dir = tmp_dir("missing-parent-ok");
        let path = dir.join("app.toml");
        assert!(!path.exists());
        assert!(matches!(is_writable(&path), Ok(Writability::Writable)));
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

    /// A document the binaries would refuse at startup must not reach
    /// the disk: the panel writes the file verbatim and both binaries
    /// abort on the next start when the config does not load, so a
    /// green toast for such a file is a lie.
    #[test]
    fn a_save_that_would_not_load_is_refused() {
        let dir = tmp_dir("invalid-doc");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        // A key the config model does not know: the loader refuses it.
        cfg.set("server.bynd", item::string("127.0.0.1:9999"))
            .unwrap();

        let err = cfg.save().unwrap_err();
        match err {
            ConfigWriteError::InvalidDocument { message, .. } => {
                assert!(
                    message.contains("bynd"),
                    "the error must name the offending key: {message}"
                );
            }
            other => panic!("expected an invalid document, got {other:?}"),
        }

        // The file on disk is untouched.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains("bynd"),
            "the refused document must not have been written: {on_disk}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A value of the wrong type is refused the same way: the loader
    /// expects a socket address, not a number.
    #[test]
    fn a_save_with_a_value_of_the_wrong_type_is_refused() {
        let dir = tmp_dir("invalid-type");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::integer(8080)).unwrap();

        let err = cfg.save().unwrap_err();
        assert!(
            matches!(err, ConfigWriteError::InvalidDocument { .. }),
            "expected an invalid document, got {err:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The trailing comment of a key belongs to the key: replacing the
    /// value must not strip the operator's note.
    #[test]
    fn replacing_a_value_keeps_its_trailing_comment() {
        let dir = tmp_dir("decor");
        let path = dir.join("app.toml");
        std::fs::write(
            &path,
            "[server]\nbind = \"0.0.0.0:8080\" # the public listener\n",
        )
        .unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap();
        cfg.save().unwrap();

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.contains("# the public listener"),
            "the trailing comment must survive the write: {on_disk}"
        );
        assert!(on_disk.contains("127.0.0.1:9999"), "value: {on_disk}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A file that changed on disk between the load and the save carries
    /// somebody else's edit. The save must be refused, not overwrite it.
    #[test]
    fn a_file_changed_on_disk_is_not_overwritten() {
        let dir = tmp_dir("conflict");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap();

        // Somebody edits the file while the form is open.
        std::fs::write(
            &path,
            "[server]\nbind = \"0.0.0.0:8080\"\n[probe]\nfail_limit = 7\n",
        )
        .unwrap();

        let err = cfg.save().unwrap_err();
        assert!(
            matches!(err, ConfigWriteError::Conflict { .. }),
            "expected a conflict, got {err:?}"
        );

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.contains("fail_limit = 7"),
            "the other edit must survive: {on_disk}"
        );
        assert!(
            !on_disk.contains("127.0.0.1:9999"),
            "the stale write must not have landed: {on_disk}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The fingerprint of the file is what the form carries: it changes
    /// with the file and is empty for a file that does not exist.
    #[test]
    fn the_fingerprint_follows_the_file() {
        let dir = tmp_dir("fingerprint");
        let path = dir.join("app.toml");

        assert_eq!(fingerprint(&path), "", "a missing file has no fingerprint");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        let first = fingerprint(&path);
        assert!(!first.is_empty());
        assert_eq!(first, fingerprint(&path), "the fingerprint must be stable");

        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:9090\"\n").unwrap();
        assert_ne!(
            first,
            fingerprint(&path),
            "a changed file must have a different fingerprint"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A section that holds a value where the write needs a table is a
    /// collision: the write is refused and the document is untouched.
    #[test]
    fn a_slot_that_holds_a_value_is_refused() {
        let dir = tmp_dir("slot-conflict");
        let path = dir.join("app.toml");
        std::fs::write(&path, "server = 42\n[probe]\nfail_limit = 3\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        let err = cfg
            .set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap_err();
        match err {
            ConfigWriteError::SectionConflict { section, key } => {
                assert_eq!(section, "server");
                assert_eq!(key, "server.bind");
            }
            other => panic!("expected a section conflict, got {other:?}"),
        }
        assert_eq!(
            cfg.doc().to_string(),
            "server = 42\n[probe]\nfail_limit = 3\n",
            "the document must be untouched"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A leaf that holds a table on disk is not replaced by a value: the
    /// write would drop every key under it.
    #[test]
    fn a_table_is_not_replaced_by_a_value() {
        let dir = tmp_dir("table-conflict");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[probe]\nfail_limit = 3\nsample_size = 10\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        let err = cfg.set("probe", item::string("x")).unwrap_err();
        assert!(
            matches!(err, ConfigWriteError::SectionConflict { .. }),
            "expected a section conflict, got {err:?}"
        );
        let rendered = cfg.doc().to_string();
        assert!(
            rendered.contains("fail_limit = 3") && rendered.contains("sample_size = 10"),
            "the table must keep its keys: {rendered}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The rename that commits the save swaps the inode, and the tmp
    /// file was created by this process: the config must not change
    /// hands behind the operator's back.
    #[cfg(unix)]
    #[test]
    fn a_save_keeps_the_owner_and_the_group_of_the_config() {
        use std::os::unix::fs::MetadataExt;

        let dir = tmp_dir("owner");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        let before = std::fs::metadata(&path).unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap();
        cfg.save().unwrap();

        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.uid(), after.uid(), "the owner must not change");
        assert_eq!(before.gid(), after.gid(), "the group must not change");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A rename that always fails with a direct write that succeeds:
    /// the file is updated through the original inode, the tmp is
    /// removed, no error.
    #[test]
    fn a_failing_rename_falls_back_to_the_direct_write() {
        let dir = tmp_dir("rename-fallback");
        let path = dir.join("app.toml");
        let updated = b"[server]\nbind = \"127.0.0.1:9999\"\n";
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        let tmp = dir.join(".app.toml.tmp.1.1");
        std::fs::write(&tmp, updated).unwrap();

        let no_rename = |_: &Path, _: &Path| -> std::io::Result<()> {
            Err(std::io::Error::other("rename unsupported here"))
        };
        commit_save(&path, &tmp, updated, no_rename, commit_in_place).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[server]\nbind = \"127.0.0.1:9999\"\n",
            "the direct write must carry the change"
        );
        assert!(
            !tmp.exists(),
            "the tmp must be removed once the direct write has taken"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The fallback fails too: neither version of the file may be lost.
    /// The direct write never truncates up front, so the original keeps
    /// its bytes, and the tmp holding the new content stays on the disk
    /// with its path logged for recovery by hand.
    #[test]
    fn a_failing_fallback_keeps_the_tmp_and_the_original() {
        let dir = tmp_dir("fallback-fail");
        let path = dir.join("app.toml");
        let original = "[server]\nbind = \"0.0.0.0:8080\"\n";
        std::fs::write(&path, original).unwrap();
        let tmp = dir.join(".app.toml.tmp.1.1");
        let updated = b"[server]\nbind = \"127.0.0.1:9999\"\n";
        std::fs::write(&tmp, updated).unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = std::sync::Arc::clone(&captured);
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::ERROR)
            .with_writer(move || Captured(std::sync::Arc::clone(&writer)))
            .finish();

        let no_rename = |_: &Path, _: &Path| -> std::io::Result<()> {
            Err(std::io::Error::other("rename unsupported here"))
        };
        let no_direct = |_: &Path, _: &[u8]| -> std::io::Result<()> {
            Err(std::io::Error::other("direct write refused"))
        };
        let err = tracing::subscriber::with_default(subscriber, || {
            commit_save(&path, &tmp, updated, no_rename, no_direct).unwrap_err()
        });

        let log = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains(&tmp.display().to_string()),
            "the surviving tmp must be logged with its path: {log}"
        );
        assert!(
            matches!(err, ConfigWriteError::Io { path: ref p, .. } if p == &path),
            "the raw i/o error naming the config is expected, got {err:?}"
        );
        assert_eq!(
            std::fs::read(&tmp).unwrap(),
            updated,
            "the uncommitted new content must stay in the tmp"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original,
            "the original must not be truncated or emptied"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A read-only mount refusal on the direct-write fallback is the
    /// panel's Unwritable answer, and the tmp stays as the recoverable
    /// copy.
    #[test]
    fn a_readonly_mount_on_the_direct_write_is_unwritable() {
        let dir = tmp_dir("erofs-direct");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        let tmp = dir.join(".app.toml.tmp.1.1");
        let updated = b"[server]\nbind = \"127.0.0.1:9999\"\n";
        std::fs::write(&tmp, updated).unwrap();

        let no_rename = |_: &Path, _: &Path| -> std::io::Result<()> {
            Err(std::io::Error::other("rename unsupported here"))
        };
        let erofs = |_: &Path, _: &[u8]| -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem))
        };
        let err = commit_save(&path, &tmp, updated, no_rename, erofs).unwrap_err();

        assert!(
            matches!(err, ConfigWriteError::Unwritable(ref p) if p == &path),
            "a read-only mount must surface as Unwritable, got {err:?}"
        );
        assert!(
            tmp.exists(),
            "the failed fallback keeps the tmp on the disk"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A save whose tmp cannot even be created because the config
    /// directory is read-only is the Unwritable answer, not a raw i/o
    /// error.
    #[cfg(unix)]
    #[test]
    fn a_save_in_an_unwritable_directory_is_unwritable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("unwritable-save");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let err = cfg.save().unwrap_err();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            matches!(err, ConfigWriteError::Unwritable(ref p) if p == &path),
            "expected Unwritable, got {err:?}"
        );
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("0.0.0.0:8080"),
            "the original must survive the refused save"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression: the tmp is created with `.mode(...)`, which the
    /// kernel masks with the process umask — a 0660 config under the
    /// usual 022 umask came back 0640 (the 0600 case the first mode
    /// test covers is immune to that umask). The mode is now set again
    /// on the descriptor, so the saved file carries exactly the
    /// original's bits.
    #[cfg(unix)]
    #[test]
    fn save_preserves_the_exact_mode_bits() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("save-mode-exact");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

        let mut cfg = EditableConfig::load(&path).unwrap();
        cfg.set("server.bind", item::string("127.0.0.1:9999"))
            .unwrap();
        cfg.save().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o660,
            "save() must reproduce the mode bit-for-bit, umask included"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The error type is `#[non_exhaustive]` and comparable: callers
    /// match on it with a catch-all arm, tests assert exact variants,
    /// and io failures compare by the kind at the same path.
    #[test]
    fn the_error_type_is_non_exhaustive_and_comparable() {
        assert_eq!(
            ConfigWriteError::InvalidKey("a..b".into()),
            ConfigWriteError::InvalidKey("a..b".into())
        );
        assert_ne!(
            ConfigWriteError::InvalidKey("a..b".into()),
            ConfigWriteError::InvalidKey("b..c".into())
        );
        let not_found = || ConfigWriteError::Io {
            path: PathBuf::from("x"),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        assert_eq!(not_found(), not_found());
        assert_ne!(
            not_found(),
            ConfigWriteError::Io {
                path: PathBuf::from("y"),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
            "the path is part of the comparison"
        );
    }

    /// I/O errors carry the file they happened on: a read failure
    /// names the config.
    #[cfg(unix)]
    #[test]
    fn io_errors_carry_the_path_they_failed_on() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_dir("io-path");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = EditableConfig::load(&path).unwrap_err();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(
            matches!(err, ConfigWriteError::Io { path: ref p, .. } if p == &path),
            "the read failure must name the config file: {err:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A probe name that is already taken is itself proof the directory
    /// accepts new files: the answer must be writable, not a refusal.
    #[test]
    fn a_taken_probe_name_still_proves_the_directory_writable() {
        let dir = tmp_dir("probe-taken");
        let taken = |_: &Path| -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
        };

        let result = can_create_in_with(&dir, &taken);

        assert!(
            matches!(result, Ok(Writability::Writable)),
            "a taken probe name must count as writable, got {result:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A read-only mount cannot be produced in CI, so the probe is
    /// injected: directory metadata answers fine and the `create_new`
    /// probe fails with the error kind the kernel reports for a
    /// read-only mount — exactly the docker `:ro` case.
    #[test]
    fn a_readonly_mount_surfaces_as_not_writable_despite_good_metadata() {
        let dir = tmp_dir("erofs-probe");
        let erofs = |_: &Path| -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem))
        };

        let result = can_create_in_with(&dir, &erofs);

        assert!(
            matches!(result, Ok(Writability::ReadOnlyMount)),
            "expected the read-only-mount answer, got {result:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The slow open-probe branch: a probe that always fails refuses an
    /// existing file whose mode bits look perfectly writable.
    #[test]
    fn a_failing_open_probe_answers_not_writable_for_a_writable_file() {
        let dir = tmp_dir("open-probe");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let always_fails = |_: &Path| -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem))
        };
        let result = is_writable_with(&path, &always_fails, &create_probe_file);

        assert!(
            matches!(result, Ok(Writability::ReadOnlyMount)),
            "a failing open probe must refuse the writable file, got {result:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every refusal is logged with the path, and where the OS
    /// produced an error, with the error too — the log is where an
    /// operator finds out why the editor was disabled.
    #[test]
    fn a_refusal_is_logged_with_the_path_and_the_cause() {
        let dir = tmp_dir("refusal-log");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = std::sync::Arc::clone(&captured);
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || Captured(std::sync::Arc::clone(&writer)))
            .finish();

        let always_fails = |_: &Path| -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem))
        };
        let result = tracing::subscriber::with_default(subscriber, || {
            is_writable_with(&path, &always_fails, &create_probe_file)
        });

        assert!(matches!(result, Ok(Writability::ReadOnlyMount)));
        let log = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains(&path.display().to_string()),
            "the refusal must be logged with the path: {log}"
        );
        assert!(
            log.contains("read-only filesystem"),
            "the refusal must be logged with the error: {log}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A bare relative name ("app.toml") has an empty parent, which is
    /// the current directory, not the filesystem root: the check must
    /// answer for the CWD.
    #[test]
    fn is_writable_answers_for_a_bare_relative_name() {
        // The test binary's CWD is the crate root, which is writable.
        let result = is_writable(Path::new("app.toml"));
        assert!(
            matches!(result, Ok(Writability::Writable)),
            "a bare relative name in a writable CWD must be writable, got {result:?}"
        );
    }
}
