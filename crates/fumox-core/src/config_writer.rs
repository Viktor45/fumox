//! Round-trip editor for `config/app.toml`.
//!
//! The admin panel's *Edit settings* page must write back individual
//! fields without destroying the comments the operator put in the file
//! (every section of `config/app.toml` carries RU/EN pair comments).
//! `toml_edit` is built for exactly that — its `DocumentMut` keeps the
//! decoration around every key.
//!
//! Atomic save: write to a sibling `<name>.tmp.<pid>`, then rename.
//! If `rename` fails (some network filesystems do not support it), fall
//! back to a direct write and surface the failure in the log — losing
//! atomicity is better than losing the change.

use std::path::{Path, PathBuf};
use std::str::FromStr;

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
    /// any `[section]` block in the file and could not be created.
    UnknownSection(String),
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
pub struct EditableConfig {
    path: PathBuf,
    doc: DocumentMut,
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
    pub fn load(path: &Path) -> Result<Self, ConfigWriteError> {
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
    pub fn set(&mut self, dotted: &str, value: Item) -> Result<(), ConfigWriteError> {
        let segments: Vec<&str> = dotted.split('.').collect();
        if segments.is_empty() {
            return Err(ConfigWriteError::UnknownSection(dotted.into()));
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

    /// Atomic save: write to `<path>.tmp.<pid>` in the same directory
    /// and rename over the original. Falls back to direct `write` on
    /// filesystems that reject `rename` (some NFS / SMB mounts).
    pub fn save(&self) -> Result<(), ConfigWriteError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| ConfigWriteError::Unwritable(self.path.clone()))?;
        let file_name = self
            .path
            .file_name()
            .ok_or_else(|| ConfigWriteError::Unwritable(self.path.clone()))?;
        let tmp_name = format!("{}.tmp.{}", file_name.to_string_lossy(), std::process::id());
        let tmp_path = parent.join(tmp_name);

        let serialized = self.doc.to_string();
        std::fs::write(&tmp_path, serialized.as_bytes())?;

        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            // Atomic rename is not universally supported. If it fails,
            // do a plain write and remove the tmp — losing atomicity is
            // preferable to losing the change. The user gets a warning
            // in the logs and may decide to back the file up first.
            tracing::warn!(
                error = %e,
                path = %self.path.display(),
                "atomic rename failed; falling back to direct write"
            );
            std::fs::write(&self.path, serialized.as_bytes())?;
            let _ = std::fs::remove_file(&tmp_path);
        }
        Ok(())
    }
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
/// directory is writable (a brand-new file can be created there).
pub fn is_writable(path: &Path) -> bool {
    let md = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => {
            return path
                .parent()
                .and_then(|p| std::fs::metadata(p).ok())
                .is_some_and(|m| !m.permissions().readonly());
        }
    };
    !md.permissions().readonly()
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
        // banner — that is the whole point of round-tripping through
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
}
