//! Admin panel internationalization.
//!
//! Message catalogs live in external TOML files — one file per language,
//! file name (without extension) is the language code: `locales/ru.toml`,
//! `locales/en.toml`, … The directory is `[admin].locales_dir` (default
//! `locales/`, relative to the working directory). Dropping a new file into
//! the directory and restarting the server adds a language — no rebuild.
//!
//! The shipped `ru`/`en` catalogs are also compiled into the binary as a
//! fallback, so a bare binary without a locales directory still renders the
//! panel. Files on disk override the embedded copy of the same language.
//!
//! The UI language is stored in the plain `fumox_lang` cookie; the login
//! screen (`?lang=` query parameter) and the topbar switcher
//! (`/admin/set-lang`) set it. The default language is Russian when its
//! catalog is loaded, otherwise the first available one.
//!
//! Templates access messages through `t("key")` and `lang_code()` helpers
//! that the [`impl_i18n`] macro adds to every template struct carrying a
//! `lang: Lang` field. Messages injected from Rust (toasts, validation,
//! badges) are translated with [`Lang::t`] at the call site.

use axum::http::{HeaderMap, header};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

/// Language cookie name. The value is not signed: it only selects UI text.
pub const LANG_COOKIE: &str = "fumox_lang";

/// Language cookie lifetime: one year.
const LANG_MAX_AGE_SECS: u64 = 365 * 24 * 3600;

/// Catalogs compiled into the binary: the fallback when the locales
/// directory is absent or does not contain a given language.
static EMBEDDED_LOCALES: &[(&str, &str)] = &[
    ("en", include_str!("../../../../locales/en.toml")),
    ("ru", include_str!("../../../../locales/ru.toml")),
];

/// Key of the language's native name inside its own catalog; the language
/// switchers display it (falls back to the code when missing).
const LANG_NAME_KEY: &str = "lang.name";

/// Preferred default language when the request carries no valid choice.
const PREFERRED_DEFAULT: &str = "ru";

/// Every message catalog known to the server. Built once at startup from
/// the embedded catalogs plus the `*.toml` files of the locales directory
/// (disk wins over embedded for the same language code).
pub struct Locales {
    catalogs: BTreeMap<String, Arc<HashMap<String, String>>>,
    default_code: String,
    /// `(code, native name)` pairs for the language switchers, sorted by
    /// code.
    choices: Vec<(String, String)>,
}

impl Locales {
    /// Load catalogs: embedded first, then every `<code>.toml` in `dir`.
    /// Unreadable or malformed files are logged and skipped.
    pub fn load(dir: &Path) -> Self {
        let mut catalogs: BTreeMap<String, Arc<HashMap<String, String>>> = BTreeMap::new();
        for (code, text) in EMBEDDED_LOCALES {
            match parse_catalog(text) {
                Ok(messages) => {
                    catalogs.insert((*code).to_string(), Arc::new(messages));
                }
                Err(err) => {
                    tracing::error!(code, error = %err, "embedded locale failed to parse");
                }
            }
        }

        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                        continue;
                    }
                    let Some(code) = path.file_stem().and_then(|stem| stem.to_str()) else {
                        continue;
                    };
                    let code = code.trim().to_ascii_lowercase();
                    if code.is_empty() {
                        continue;
                    }
                    match std::fs::read_to_string(&path)
                        .map_err(|err| err.to_string())
                        .and_then(|text| parse_catalog(&text))
                    {
                        Ok(messages) => {
                            tracing::info!(code = %code, path = %path.display(), "locale loaded");
                            catalogs.insert(code, Arc::new(messages));
                        }
                        Err(err) => {
                            tracing::error!(path = %path.display(), error = %err, "locale file skipped");
                        }
                    }
                }
            }
            Err(_) => {
                tracing::info!(
                    dir = %dir.display(),
                    "locales directory not found, using embedded catalogs"
                );
            }
        }

        Self::from_catalogs(catalogs)
    }

    /// Build the registry from an already-parsed set of catalogs.
    fn from_catalogs(catalogs: BTreeMap<String, Arc<HashMap<String, String>>>) -> Self {
        // Default language: Russian when available, else the first code
        // (BTreeMap keeps the order deterministic).
        let default_code = if catalogs.contains_key(PREFERRED_DEFAULT) {
            PREFERRED_DEFAULT.to_string()
        } else {
            catalogs.keys().next().cloned().unwrap_or_default()
        };
        let choices = catalogs
            .iter()
            .map(|(code, messages)| {
                let name = messages
                    .get(LANG_NAME_KEY)
                    .cloned()
                    .unwrap_or_else(|| code.clone());
                (code.clone(), name)
            })
            .collect();
        Self {
            catalogs,
            default_code,
            choices,
        }
    }

    /// Resolve a language code to a usable [`Lang`]; unknown or empty codes
    /// fall back to the default language.
    pub fn resolve(&self, code: &str) -> Lang {
        let code = code.trim().to_ascii_lowercase();
        if let Some(messages) = self.catalogs.get(&code) {
            return Lang {
                code,
                messages: messages.clone(),
            };
        }
        Lang {
            code: self.default_code.clone(),
            messages: self
                .catalogs
                .get(&self.default_code)
                .cloned()
                .unwrap_or_default(),
        }
    }

    /// The default language.
    pub fn default_lang(&self) -> Lang {
        self.resolve(&self.default_code)
    }

    /// Resolve the UI language from the `fumox_lang` cookie.
    pub fn lang_from_headers(&self, headers: &HeaderMap) -> Lang {
        for cookie_header in headers.get_all(header::COOKIE).iter() {
            let Ok(text) = cookie_header.to_str() else {
                continue;
            };
            for pair in text.split(';') {
                if let Some((name, value)) = pair.trim().split_once('=')
                    && name.trim() == LANG_COOKIE
                {
                    return self.resolve(value.trim());
                }
            }
        }
        self.default_lang()
    }

    /// `(code, native name)` pairs for the language switchers.
    pub fn choices(&self) -> &[(String, String)] {
        &self.choices
    }

    /// Whether a language code is loaded.
    #[cfg(test)]
    pub fn contains(&self, code: &str) -> bool {
        self.catalogs
            .contains_key(&code.trim().to_ascii_lowercase())
    }
}

/// Parse one TOML catalog document: flat `"domain.name" = "text"` pairs.
fn parse_catalog(text: &str) -> Result<HashMap<String, String>, String> {
    let table: toml::Table = toml::from_str(text).map_err(|err| err.to_string())?;
    let mut messages = HashMap::with_capacity(table.len());
    for (key, value) in table {
        match value {
            toml::Value::String(message) => {
                messages.insert(key, message);
            }
            other => {
                return Err(format!("value of key {key:?} is not a string: {other}"));
            }
        }
    }
    Ok(messages)
}

/// The UI language of one request: a code plus the catalog it resolves to.
/// Cloning is cheap (the catalog is shared).
#[derive(Clone)]
pub struct Lang {
    code: String,
    messages: Arc<HashMap<String, String>>,
}

impl Lang {
    /// Language code for the `<html lang>` attribute and cookies.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Translate a message key. Unknown keys render as the key itself, so
    /// a missing translation is visible instead of blank. The result borrows
    /// from the catalog (via `self`) or from `key`, hence the shared
    /// lifetime.
    pub fn t<'a>(&'a self, key: &'a str) -> &'a str {
        self.messages.get(key).map(String::as_str).unwrap_or(key)
    }

    /// Translate a message key and substitute positional arguments `{0}`,
    /// `{1}`… Used for dynamic validation errors produced outside the admin
    /// layer (pipeline, fetcher): they carry a catalog key plus arguments
    /// instead of pre-rendered text. A missing catalog entry renders as the
    /// key itself (like [`Lang::t`]), with the arguments substituted in.
    pub fn t_args(&self, key: &str, args: &[String]) -> String {
        let mut text = self.t(key).to_string();
        for (idx, arg) in args.iter().enumerate() {
            text = text.replace(&format!("{{{idx}}}"), arg);
        }
        text
    }
}

/// `Set-Cookie` header value persisting the language choice.
pub fn lang_cookie(code: &str) -> String {
    format!("{LANG_COOKIE}={code}; Path=/; HttpOnly; SameSite=Lax; Max-Age={LANG_MAX_AGE_SECS}")
}

/// Add the `t()` and `lang_code()` template helpers to a template struct
/// that carries a `lang: Lang` field. The result borrows from the struct,
/// which owns (via `Arc`) the catalog. `allow` silences per-template
/// unused-helper warnings: which helpers a template actually calls is only
/// known to askama.
macro_rules! impl_i18n {
    ($ty:ty) => {
        impl $ty {
            #[allow(dead_code)]
            fn t<'a>(&'a self, key: &'a str) -> &'a str {
                self.lang.t(key)
            }
            #[allow(dead_code)]
            fn lang_code(&self) -> &str {
                self.lang.code()
            }
        }
    };
}
pub(crate) use impl_i18n;

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded catalogs are the migration reference: both languages
    /// must carry exactly the same keys.
    fn embedded_catalogs() -> Vec<(String, HashMap<String, String>)> {
        EMBEDDED_LOCALES
            .iter()
            .map(|(code, text)| {
                (
                    (*code).to_string(),
                    parse_catalog(text).expect("embedded catalog parses"),
                )
            })
            .collect()
    }

    #[test]
    fn embedded_catalogs_parse_and_share_the_same_keys() {
        let catalogs = embedded_catalogs();
        assert!(!catalogs.is_empty());
        let (first_code, first) = &catalogs[0];
        assert!(!first.is_empty(), "catalog {first_code} is empty");
        for (code, catalog) in &catalogs[1..] {
            assert_eq!(
                first.len(),
                catalog.len(),
                "key count differs between {} and {code}",
                first_code
            );
            for key in first.keys() {
                assert!(catalog.contains_key(key), "key {key} missing in {code}");
            }
        }
        // Every language describes itself for the switcher.
        for (code, catalog) in &catalogs {
            assert!(
                catalog.contains_key(LANG_NAME_KEY),
                "lang.name missing in {code}"
            );
        }
    }

    #[test]
    fn parse_rejects_non_string_values() {
        assert!(parse_catalog(r#""a" = 1"#).is_err());
        assert!(parse_catalog(r#"[section]"#).is_err());
        assert!(parse_catalog(r#""a" = "текст""#).is_ok());
    }

    #[test]
    fn resolve_falls_back_to_the_default_language() {
        let locales = Locales::load(Path::new("/nonexistent-locales-dir"));
        assert_eq!(locales.default_lang().code(), "ru");
        assert_eq!(locales.resolve("en").code(), "en");
        assert_eq!(locales.resolve("EN").code(), "en");
        assert_eq!(locales.resolve("fr").code(), "ru");
        assert_eq!(locales.resolve("").code(), "ru");
        // Translation follows the resolved catalog.
        assert_eq!(locales.resolve("en").t("nav.dashboard"), "Dashboard");
        assert_eq!(locales.resolve("fr").t("nav.dashboard"), "Дашборд");
        // Unknown keys echo themselves.
        assert_eq!(locales.resolve("en").t("no.such.key"), "no.such.key");
    }

    #[test]
    fn t_args_substitutes_positional_arguments() {
        let locales = Locales::load(Path::new("/nonexistent-locales-dir"));
        let args = vec!["rename[0]".to_string(), "z".to_string()];
        assert_eq!(
            locales.resolve("ru").t_args("pipeline.unknown_flag", &args),
            "rename[0].flags: неизвестный флаг «z»"
        );
        assert_eq!(
            locales.resolve("en").t_args("pipeline.unknown_flag", &args),
            "rename[0].flags: unknown flag 'z'"
        );
        // A placeholder without its argument stays visible.
        assert_eq!(
            locales
                .resolve("en")
                .t_args("pipeline.bad_regex", &args[..1]),
            "rename[0].match: invalid regex: {1}"
        );
        // Unknown keys echo themselves, arguments still substituted.
        assert_eq!(
            locales.resolve("en").t_args("no.such.key", &args),
            "no.such.key"
        );
    }

    #[test]
    fn disk_files_add_and_override_languages() {
        let dir = std::env::temp_dir().join(format!(
            "fumox-locales-test-{}",
            fumox_core::models::new_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A brand-new language appears without any rebuild.
        std::fs::write(
            dir.join("de.toml"),
            "\"lang.name\" = \"Deutsch\"\n\"nav.dashboard\" = \"Armaturenbrett\"\n",
        )
        .unwrap();
        // A disk copy overrides the embedded catalog of the same code.
        std::fs::write(dir.join("en.toml"), "\"nav.dashboard\" = \"Dashboard!\"\n").unwrap();
        // A malformed file is skipped, not fatal.
        std::fs::write(dir.join("broken.toml"), "\"oops\" = ").unwrap();

        let locales = Locales::load(&dir);
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(locales.contains("de"));
        assert!(locales.contains("ru"));
        assert!(locales.contains("en"));
        assert!(!locales.contains("broken"));
        assert_eq!(locales.resolve("de").t("nav.dashboard"), "Armaturenbrett");
        // The disk file replaced the embedded English catalog entirely…
        assert_eq!(locales.resolve("en").t("nav.dashboard"), "Dashboard!");
        // …so keys it does not define echo themselves.
        assert_eq!(locales.resolve("en").t("nav.logout"), "nav.logout");
        // Switcher labels come from each catalog's lang.name.
        let choices = locales.choices();
        assert!(choices.contains(&("de".to_string(), "Deutsch".to_string())));
        assert!(choices.contains(&("ru".to_string(), "Русский".to_string())));
    }

    #[test]
    fn lang_cookie_reading_and_writing() {
        let locales = Locales::load(Path::new("/nonexistent-locales-dir"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "other=1; fumox_lang=en; third=x".parse().unwrap(),
        );
        assert_eq!(locales.lang_from_headers(&headers).code(), "en");
        assert_eq!(locales.lang_from_headers(&HeaderMap::new()).code(), "ru");

        let cookie = lang_cookie("en");
        assert!(cookie.starts_with("fumox_lang=en;"));
        assert!(cookie.contains("HttpOnly"));
    }

    /// Every key referenced by a template must exist in every embedded
    /// catalog, so a typo surfaces in CI instead of rendering as a raw key.
    #[test]
    fn every_template_key_exists_in_the_catalog() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        let catalogs = embedded_catalogs();
        let mut missing: Vec<String> = Vec::new();
        visit_templates(&dir, &catalogs, &mut missing);
        assert!(
            missing.is_empty(),
            "unknown i18n keys in templates: {missing:?}"
        );
    }

    fn visit_templates(
        dir: &std::path::Path,
        catalogs: &[(String, HashMap<String, String>)],
        missing: &mut Vec<String>,
    ) {
        for entry in std::fs::read_dir(dir).expect("templates dir readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                visit_templates(&path, catalogs, missing);
            } else if path.extension().is_some_and(|ext| ext == "html") {
                let text = std::fs::read_to_string(&path).expect("template readable");
                for captures in TEMPLATE_KEY_RE.captures_iter(&text) {
                    let key = &captures[1];
                    for (code, catalog) in catalogs {
                        if !catalog.contains_key(key) {
                            missing.push(format!("{}: {key} ({code})", path.display()));
                        }
                    }
                }
            }
        }
    }

    static TEMPLATE_KEY_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"t\("([a-z0-9_.]+)"\)"#).expect("valid regex")
    });
}
