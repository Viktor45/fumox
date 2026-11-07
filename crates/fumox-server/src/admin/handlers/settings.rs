//! Settings overview + edit page.
//!
//! The overview (`GET /admin/settings`) is read-only and shows the
//! effective configuration grouped by owning process (server / probe /
//! shared). The edit page (`GET /admin/settings/edit`) is a form that
//! round-trips the on-disk TOML through `toml_edit`, preserving every
//! existing comment. Saving (`POST /admin/settings/update`) writes the
//! file atomically and refreshes the in-memory view, so a save splits
//! into two application cases. Everything the handlers read through
//! [`AdminState::live`] (and its typed accessors — `[probe]`, `[meow]`,
//! `[fetch]`, …) is in force on the next request, no restart needed. A
//! few values are startup-frozen on purpose and need the restart: the
//! listener sockets (`AdminState::server_bind`) and the rate limiters,
//! built once at startup from the config they were given; the full list
//! lives on the `AdminState` fields in `crate::admin`. A *Create from
//! defaults* button on the overview (`POST /admin/settings/create`)
//! bootstraps a missing `config/app.toml` from the embedded reference
//! copy.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use fumox_core::config::{
    AdminConfig, AppConfig, DatabaseConfig, FetchConfig, GeoConfig, IngestConfig, LogConfig,
    LogLevel, MeowConfig, NetworkConfig, ProbeConfig, RateLimit, ResolvedConfigPath,
    RetentionConfig, ServerConfig, bounds,
};
use fumox_core::config_writer::{ConfigItem, ConfigWriteError, EditableConfig, fingerprint, item};
use fumox_core::models::IpFamily;

/// Dotted keys referenced outside the [`SETTINGS`] table — `save_settings`
/// reads the token around the write, `settings_update` and `save_toast`
/// match it against the env locks, `apply_all` compares the backoff pair:
/// one constant each, so a rename cannot leave a string literal behind.
const KEY_ADMIN_TOKEN: &str = "admin.token";
const KEY_MEOW_BACKOFF_MAX: &str = "meow.backoff_max_secs";
const KEY_MEOW_BACKOFF_MIN: &str = "meow.backoff_initial_secs";

/// Read-only config view the *Settings* overview renders: the same
/// field names `templates/settings.html` has always used, populated
/// from [`AdminState::live`] so the page shows the post-save state
/// without a restart and without a frozen-field bridge. `config_path`
/// rides along for the banner and the *Create from defaults* button;
/// `config_writable` so a read-only deployment gets the same red banner
/// on the overview the editor shows (USERGUIDE: "the same banner
/// appears on the overview").
struct SettingsView {
    server: ServerConfig,
    database: DatabaseConfig,
    fetch: FetchConfig,
    ingest: IngestConfig,
    geo_config: GeoConfig,
    network: NetworkConfig,
    admin: AdminConfig,
    probe: ProbeConfig,
    meow: MeowConfig,
    retention: RetentionConfig,
    log: LogConfig,
    config_path: ResolvedConfigPath,
    config_writable: bool,
}

impl SettingsView {
    fn from_state(state: &AdminState) -> Self {
        Self {
            server: state.server(),
            database: state.database(),
            fetch: state.fetch(),
            ingest: state.ingest(),
            geo_config: state.geo_config(),
            network: state.network(),
            admin: state.admin(),
            probe: state.probe(),
            meow: state.meow(),
            retention: state.retention(),
            log: state.log(),
            config_path: state.config_path.clone(),
            config_writable: state.config_writable,
        }
    }

    /// The DNS resolution timeout in force: the dedicated `[network]` key
    /// when it is set, otherwise the `[geo]` one it follows.
    fn network_dns_timeout(&self) -> u64 {
        if self.network.dns_timeout_secs > 0 {
            self.network.dns_timeout_secs
        } else {
            self.geo_config.dns_timeout_secs
        }
    }
}

/// Settings overview template (read-only).
#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    state: SettingsView,
}

impl SettingsTemplate {
    /// The quarantine ladder as one localized sentence.
    fn ladder_sentence(&self) -> String {
        let mut parts = vec![self.lang.t("set.second_chance").to_string()];
        parts.extend(
            self.state
                .probe
                .recheck_delays_secs
                .iter()
                .map(|delay| self.fmt_delay(*delay)),
        );
        parts.push(self.lang.t("set.removal").to_string());
        parts.join(" → ")
    }

    fn fmt_delay(&self, secs: i64) -> String {
        if secs % 3600 == 0 {
            format!("{} {}", secs / 3600, self.lang.t("probe.hours_short"))
        } else if secs % 60 == 0 {
            format!("{} {}", secs / 60, self.lang.t("probe.mins_short"))
        } else {
            format!("{secs} {}", self.lang.t("common.sec"))
        }
    }

    fn fmt_bytes(&self, bytes: &u64) -> String {
        const MIB: u64 = 1024 * 1024;
        const KIB: u64 = 1024;
        if *bytes != 0 && bytes.is_multiple_of(MIB) {
            format!("{} MiB", bytes / MIB)
        } else if *bytes != 0 && bytes.is_multiple_of(KIB) {
            format!("{} KiB", bytes / KIB)
        } else {
            format!("{bytes} {}", self.lang.t("set.bytes"))
        }
    }

    fn rate_limit(&self, rl: &RateLimit) -> String {
        let unit = match rl.window.as_secs() {
            60 => "min".to_string(),
            3600 => "h".to_string(),
            86400 => "day".to_string(),
            other => format!("{other}s"),
        };
        format!("{}/{}", rl.limit, unit)
    }

    /// The path actually written by the editor, `Missing` reads as the
    /// default location for the "would be" message.
    fn editing_path(&self) -> String {
        self.state
            .config_path
            .path_or_default()
            .display()
            .to_string()
    }

    fn has_config_file(&self) -> bool {
        matches!(self.state.config_path, ResolvedConfigPath::Loaded(_))
    }

    /// Whether the editor's target file can be written. Drives the
    /// not-writable banner on the overview, the same one the editor
    /// shows, so a read-only mount (`FUMOX_CONFIG_ACCESS=ro`) never
    /// looks like a normal, editable deployment.
    fn config_writable(&self) -> bool {
        self.state.config_writable
    }

    /// A boolean as the localized on/off word: the overview reads in
    /// the page language, a bare `true`/`false` does not.
    fn bool_label(&self, value: &bool) -> String {
        self.lang
            .t(if *value { "common.on" } else { "common.off" })
            .to_string()
    }
}

impl_i18n!(SettingsTemplate);

pub async fn settings_overview(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    // The overview prints the effective config (every panel under
    // *Settings*), pulled from the figment-merged live view so an edit
    // that landed between two page loads is visible without a restart.
    let template = SettingsTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(&headers),
        lang,
        active: "settings",
        csrf: state.csrf_for(&headers),
        state: SettingsView::from_state(&state),
    };
    render_html(
        template.lang.clone(),
        "settings.html",
        &template,
        StatusCode::OK,
    )
}

// Edit page.

/// Edit-page template: holds the raw form values and the per-field
/// errors so the view can re-render on validation failure.
#[derive(Template)]
#[template(path = "settings_edit.html")]
struct SettingsEditTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    /// The file the editor writes to and whether it can: the two
    /// deployment facts the page renders (the path banner, the disabled
    /// fieldset), split out of the whole `AdminState` — a template has no
    /// business holding the pool, the caches and the rest of the state.
    config_path: ResolvedConfigPath,
    config_writable: bool,
    /// Raw form values keyed by `<section>.<field>`. Booleans carry the
    /// checkbox literals [`parse_bool_literal`] accepts: `on`/`true`/`1`
    /// (checked), `off`/`false`/`0`/empty string (unchecked, the hidden
    /// `value="off"` input) — plus the key absent entirely (the browser
    /// did not post the field at all).
    raw: HashMap<String, String>,
    /// `(field, message)` pairs produced by the validator.
    errors: Vec<(String, String)>,
    /// Top-level banner (no config file, file not writable, …).
    banner: Option<Banner>,
    /// Fingerprint of the file the form was rendered from. The submit
    /// carries it back, and a file that changed in the meantime is
    /// refused instead of being overwritten by the stale form.
    fingerprint: String,
    /// Dotted config paths the environment overrides. A locked field is
    /// rendered read-only and is left out of the write: the env layer
    /// wins over the file, so a value written here would be inert.
    env_locked: Vec<String>,
}

#[derive(Clone)]
enum Banner {
    Unwritable(String),
    /// The config file could not be read. The form falls back to the
    /// running configuration, which is not what the panel writes, so
    /// the operator is told why the values below are not the file's.
    LoadFailed(String, String),
}

impl SettingsEditTemplate {
    fn raw_value<'a>(&'a self, field: &str) -> &'a str {
        self.raw.get(field).map(String::as_str).unwrap_or("")
    }

    fn bool_value(&self, field: &str) -> bool {
        // Same literals the save parser accepts: the failed-save replay
        // must re-render hidden `value="off"` inputs unchecked.
        parse_bool_literal(self.raw_value(field)).unwrap_or(false)
    }

    /// Whether the rendered unit half of a rate-limit pair is one of the
    /// select's own values. A window that is none of the four canonical
    /// ones renders as its exact seconds (`90sec`), and the select must
    /// carry that as an extra option: without it the browser falls back
    /// to the first option and an untouched pair would save as a
    /// different window.
    fn unit_is_canonical(&self, field: &str) -> bool {
        matches!(self.raw_value(field), "" | "sec" | "min" | "hour" | "day")
    }

    /// `min` for a number input, straight from the bounds table. An
    /// unbounded setting renders an empty attribute rather than a
    /// fabricated `0`.
    fn range_min(&self, field: &str) -> String {
        bounds::min_attr(field)
    }

    /// `max` for a number input, empty when the setting has no range
    /// entry (the field is not a bounded number).
    fn range_max(&self, field: &str) -> String {
        bounds::max_attr(field)
    }

    /// The range as the operator reads it, shown under the input. It is
    /// the same value the save handler enforces, so the number in the
    /// hint and the number in the error cannot drift apart.
    fn range_text(&self, field: &str) -> Option<String> {
        bounds::display(field)
    }

    /// Longest recheck ladder the config accepts, in steps. The ladder
    /// is a list, so its bound is a count rather than a range; both
    /// numbers come from the same constants the deserializer enforces.
    fn ladder_steps(&self) -> usize {
        bounds::RECHECK_MAX_STEPS
    }

    /// Longest single recheck delay, in seconds.
    fn ladder_max_delay(&self) -> i64 {
        bounds::RECHECK_MAX_DELAY_SECS
    }

    /// Path the editor would write to. Surfaces in the page subtitle
    /// and in the intro paragraph so the operator sees the file.
    fn editing_path_str(&self) -> String {
        self.config_path.path_or_default().display().to_string()
    }

    fn banner_html(&self) -> Option<String> {
        match self.banner.as_ref()? {
            Banner::Unwritable(path) => Some(
                self.lang
                    .t_named("set.edit_unwritable", &[("path", path.clone())]),
            ),
            Banner::LoadFailed(path, reason) => Some(self.lang.t_named(
                "set.edit_load_failed",
                &[("path", path.clone()), ("reason", reason.clone())],
            )),
        }
    }

    /// `disabled` attribute for the control of `field`.
    ///
    /// A field the environment overrides is disabled on its own: the env
    /// layer wins over the file, so a value written here would never
    /// take effect and the operator would be shown a change that does
    /// not happen. The read-only deployment (the config file is not
    /// writable) is gated in one place instead, by the `<fieldset
    /// disabled>` around the panes.
    fn field_disabled(&self, field: &str) -> &'static str {
        if is_env_locked(field, &self.env_locked) {
            " disabled"
        } else {
            ""
        }
    }

    /// `disabled` attribute for the read-only deployment: the whole
    /// form is wrapped in a `<fieldset disabled>` instead of carrying
    /// the attribute on every control.
    fn panes_disabled(&self) -> &'static str {
        if self.config_writable {
            ""
        } else {
            " disabled"
        }
    }

    /// The fields the environment overrides, listed once above the form.
    /// Without the list the disabled controls look like a bug rather
    /// than a deliberate lock.
    fn env_locked_hint(&self) -> Option<String> {
        if self.env_locked.is_empty() {
            return None;
        }
        Some(self.lang.t_named(
            "set.env_locked_hint",
            &[("fields", self.env_locked.join(", "))],
        ))
    }

    /// The pane that holds the first validation error, if any.
    ///
    /// A refused save re-renders the form, and the error has to be on
    /// screen: the pane that owns the offending field opens, so the
    /// operator reads the message instead of hunting for the tab.
    /// A form-level error (no field) belongs to no pane and is shown
    /// above the form.
    fn error_tab(&self) -> Option<&'static str> {
        self.errors
            .iter()
            .find(|(field, _)| !field.is_empty())
            .map(|(field, _)| settings_tab_of(field))
    }

    /// Whether the tab is the one the page opens on: the pane that
    /// holds the first error, or the first tab when the form is clean.
    fn tab_checked(&self, tab: &str) -> bool {
        match self.error_tab() {
            Some(owner) => owner == tab,
            None => tab == "server",
        }
    }

    /// Whether the pane holds a validation error: the tab carries a
    /// marker, so a tab the operator did not open still says that
    /// something in it is broken.
    fn tab_has_error(&self, tab: &str) -> bool {
        self.errors
            .iter()
            .any(|(field, _)| !field.is_empty() && settings_tab_of(field) == tab)
    }
}

/// The pane that owns a config path.
///
/// The editor groups the fields by the process that reads them, so a
/// validation error has to name the pane the operator has to open. The
/// mapping mirrors the panes of `settings_edit.html`.
fn settings_tab_of(field: &str) -> &'static str {
    let section = field.split('.').next().unwrap_or_default();
    match section {
        "ingest" | "server" | "database" | "geo" | "network" | "admin" => "server",
        "probe" | "meow" | "retention" => "probe",
        _ => "shared",
    }
}

/// Whether the environment overrides `field`.
///
/// The lock is on the config path (`server.rate_limit`), while the form
/// carries the halves of the pair (`server.rate_limit.limit`,
/// `server.rate_limit.unit`), so a lock on a path covers every form
/// field below it.
fn is_env_locked(field: &str, locked: &[String]) -> bool {
    locked
        .iter()
        .any(|path| path == field || field.starts_with(&format!("{path}.")))
}

impl_i18n!(SettingsEditTemplate, errors);

// Editable-settings registry.
//
// One row per setting the panel round-trips. `raw_from_config` (render
// for the form) and `apply_all` (parse the submit into the TOML
// document) both iterate this table, so a new field can no longer be
// added to one side and silently forgotten on the other: the dotted
// key, its render and its parse live in a single entry. The HTML form
// remains the one hand-written list; the tests below pin it to this
// table in both directions.

/// Signature of a per-field parse/write step: read the submitted raw
/// values for `key`, write into the document, append failures to
/// `errors`. Missing keys are skipped (the editor only writes what the
/// operator's browser posted).
type ApplyField =
    fn(&HashMap<String, String>, &str, &mut EditableConfig, &Lang, &mut Vec<(String, String)>);

/// What one editable setting does. Function pointers so the table can
/// live in a `static`.
struct Setting {
    /// Dotted config key, also the form field name and the
    /// error-attribution key. Written exactly once, here.
    key: &'static str,
    /// Render the current value into the edit form's raw map. A
    /// rate-limit row renders the pair `{key}.limit` + `{key}.unit`.
    render: fn(&AppConfig, &str, &mut HashMap<String, String>),
    /// Parse the submitted value and write it into the document.
    apply: ApplyField,
}

/// Exactly the lowercase levels `LogLevel` deserializes: one bad value
/// fails `config::load` and aborts both binaries at the next start.
///
/// The closed sets below come straight from `fumox-core`
/// (`LogLevel::ALL_AS_STR`, `IpFamily::ALL_AS_STR`), the same constants
/// the deserializers accept — the editor cannot drift away from what the
/// loader parses. `TrustedHeader` has no exported set yet, so its
/// vocabulary stays local.
const LOG_LEVELS: &[&str] = LogLevel::ALL_AS_STR;

/// The closed set `IpFamily` deserializes; same contract as
/// [`LOG_LEVELS`], the strings are also what [`IpFamily::as_str`] renders.
const IP_FAMILIES: &[&str] = IpFamily::ALL_AS_STR;

/// The closed set `TrustedHeader` deserializes; the strings are what
/// `TrustedHeader::as_str` renders.
const TRUSTED_HEADERS: &[&str] = &["none", "xff", "forwarded", "both"];

static SETTINGS: &[Setting] = &[
    // --- server ---
    Setting {
        key: "server.bind",
        render: |c, key, raw| {
            raw.insert(key.into(), c.server.bind.to_string());
        },
        apply: |raw, key, cfg, lang, errors| bind(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "server.trust_proxy_ips",
        render: |c, key, raw| {
            raw.insert(key.into(), c.server.trust_proxy_ips.join("\n"));
        },
        apply: |raw, key, cfg, lang, errors| cidr_list(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "server.trust_proxy_header",
        render: |c, key, raw| {
            raw.insert(key.into(), c.server.trust_proxy_header.as_str().into());
        },
        apply: |raw, key, cfg, lang, errors| {
            enum_field(raw, key, cfg, TRUSTED_HEADERS, lang, errors)
        },
    },
    Setting {
        key: "server.allowed_hosts",
        render: |c, key, raw| {
            raw.insert(key.into(), c.server.allowed_hosts.join("\n"));
        },
        apply: |raw, key, cfg, lang, errors| string_list(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "server.rate_limit",
        render: |c, key, raw| rate_into(raw, key, &c.server.rate_limit),
        apply: |raw, key, cfg, lang, errors| rate_limit(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "server.auth_fail_rate_limit",
        render: |c, key, raw| rate_into(raw, key, &c.server.auth_fail_rate_limit),
        apply: |raw, key, cfg, lang, errors| rate_limit(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "server.export_max_rows",
        render: |c, key, raw| {
            raw.insert(key.into(), c.server.export_max_rows.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    // --- database ---
    Setting {
        key: "database.path",
        render: |c, key, raw| {
            raw.insert(key.into(), c.database.path.display().to_string());
        },
        apply: |raw, key, cfg, lang, errors| string_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "database.busy_timeout_ms",
        render: |c, key, raw| {
            raw.insert(key.into(), c.database.busy_timeout_ms.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "database.max_connections",
        render: |c, key, raw| {
            raw.insert(key.into(), c.database.max_connections.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    // --- fetch ---
    Setting {
        key: "fetch.connect_timeout_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.fetch.connect_timeout_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "fetch.read_timeout_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.fetch.read_timeout_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "fetch.max_response_bytes",
        render: |c, key, raw| {
            raw.insert(key.into(), c.fetch.max_response_bytes.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "fetch.max_concurrency",
        render: |c, key, raw| {
            raw.insert(key.into(), c.fetch.max_concurrency.to_string());
        },
        apply: |raw, key, cfg, lang, errors| usize_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "fetch.max_retries",
        render: |c, key, raw| {
            raw.insert(key.into(), c.fetch.max_retries.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "fetch.retry_base_backoff_ms",
        render: |c, key, raw| {
            raw.insert(key.into(), c.fetch.retry_base_backoff_ms.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "fetch.user_agent",
        render: |c, key, raw| {
            raw.insert(key.into(), c.fetch.user_agent.clone());
        },
        apply: |raw, key, cfg, lang, errors| string_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "fetch.ip_family",
        render: |c, key, raw| {
            raw.insert(key.into(), c.fetch.ip_family.as_str().into());
        },
        apply: |raw, key, cfg, lang, errors| enum_field(raw, key, cfg, IP_FAMILIES, lang, errors),
    },
    // --- ingest ---
    Setting {
        key: "ingest.refresh_check_limit",
        render: |c, key, raw| {
            raw.insert(key.into(), c.ingest.refresh_check_limit.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "ingest.drop_gate",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.ingest.drop_gate));
        },
        apply: |raw, key, cfg, lang, errors| bool_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "ingest.removed_as_unknown",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.ingest.removed_as_unknown));
        },
        apply: |raw, key, cfg, lang, errors| bool_field(raw, key, cfg, lang, errors),
    },
    // --- geo ---
    Setting {
        key: "geo.enabled",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.geo.enabled));
        },
        apply: |raw, key, cfg, lang, errors| bool_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "geo.db_dir",
        render: |c, key, raw| {
            raw.insert(key.into(), c.geo.db_dir.display().to_string());
        },
        apply: |raw, key, cfg, lang, errors| string_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "geo.cache_max_entries",
        render: |c, key, raw| {
            raw.insert(key.into(), c.geo.cache_max_entries.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "geo.cache_ttl_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.geo.cache_ttl_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "geo.dns_timeout_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.geo.dns_timeout_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "geo.startup_download_budget_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.geo.startup_download_budget_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "geo.auto_download",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.geo.auto_download));
        },
        apply: |raw, key, cfg, lang, errors| bool_field(raw, key, cfg, lang, errors),
    },
    // --- network ---
    Setting {
        key: "network.dns_timeout_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.network.dns_timeout_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    // --- admin ---
    Setting {
        key: "admin.enabled",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.admin.enabled));
        },
        apply: |raw, key, cfg, lang, errors| bool_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.bind",
        render: |c, key, raw| {
            raw.insert(key.into(), c.admin.bind.to_string());
        },
        apply: |raw, key, cfg, lang, errors| bind(raw, key, cfg, lang, errors),
    },
    Setting {
        key: KEY_ADMIN_TOKEN,
        // The live token must never reach the markup (USERGUIDE: "The
        // admin token is never shown."): the field renders empty and an
        // empty submit keeps the current token (`token_field`). The key
        // still has to be present, `the_registry_covers_every_rendered_key`
        // and the edit form's input both read it.
        render: |_c, key, raw| {
            raw.insert(key.into(), String::new());
        },
        apply: |raw, key, cfg, lang, errors| token_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.session_ttl_hours",
        render: |c, key, raw| {
            raw.insert(key.into(), c.admin.session_ttl_hours.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.allow_private_urls",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.admin.allow_private_urls));
        },
        apply: |raw, key, cfg, lang, errors| bool_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.rate_limit",
        render: |c, key, raw| rate_into(raw, key, &c.admin.rate_limit),
        apply: |raw, key, cfg, lang, errors| rate_limit(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.login_rate_limit",
        render: |c, key, raw| rate_into(raw, key, &c.admin.login_rate_limit),
        apply: |raw, key, cfg, lang, errors| rate_limit(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.secure_cookies",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.admin.secure_cookies));
        },
        apply: |raw, key, cfg, lang, errors| bool_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.locales_dir",
        render: |c, key, raw| {
            raw.insert(key.into(), c.admin.locales_dir.clone());
        },
        apply: |raw, key, cfg, lang, errors| string_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.trust_proxy_ips",
        render: |c, key, raw| {
            raw.insert(key.into(), c.admin.trust_proxy_ips.join("\n"));
        },
        apply: |raw, key, cfg, lang, errors| cidr_list(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.trust_proxy_header",
        render: |c, key, raw| {
            raw.insert(key.into(), c.admin.trust_proxy_header.as_str().into());
        },
        apply: |raw, key, cfg, lang, errors| {
            enum_field(raw, key, cfg, TRUSTED_HEADERS, lang, errors)
        },
    },
    Setting {
        key: "admin.allowed_hosts",
        render: |c, key, raw| {
            raw.insert(key.into(), c.admin.allowed_hosts.join("\n"));
        },
        apply: |raw, key, cfg, lang, errors| string_list(raw, key, cfg, lang, errors),
    },
    // --- probe ---
    Setting {
        key: "probe.fail_limit",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.fail_limit.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.second_chance_min_hours",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.second_chance_min_hours.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.second_chance_spread_hours",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.second_chance_spread_hours.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.recheck_delays_secs",
        render: |c, key, raw| {
            raw.insert(
                key.into(),
                c.probe
                    .recheck_delays_secs
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        },
        apply: |raw, key, cfg, lang, errors| {
            i64_list_field(
                raw,
                key,
                cfg,
                bounds::RECHECK_MAX_STEPS,
                1,
                bounds::RECHECK_MAX_DELAY_SECS,
                lang,
                errors,
            )
        },
    },
    Setting {
        key: "probe.queue_stale_days",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.queue_stale_days.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.retention_interval_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.retention_interval_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.cycle_interval_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.cycle_interval_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.sample_size",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.sample_size.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.allow_private_targets",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.probe.allow_private_targets));
        },
        apply: |raw, key, cfg, lang, errors| bool_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.connect_timeout_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.connect_timeout_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.tls_timeout_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.tls_timeout_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.concurrency",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.concurrency.to_string());
        },
        apply: |raw, key, cfg, lang, errors| usize_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.heartbeat_interval_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.heartbeat_interval_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "probe.backlog_target_drain_minutes",
        render: |c, key, raw| {
            raw.insert(key.into(), c.probe.backlog_target_drain_minutes.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    // --- meow ---
    Setting {
        key: "meow.api_addr",
        render: |c, key, raw| {
            raw.insert(key.into(), c.meow.api_addr.clone());
        },
        apply: |raw, key, cfg, lang, errors| string_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "meow.config_path",
        render: |c, key, raw| {
            raw.insert(key.into(), c.meow.config_path.display().to_string());
        },
        apply: |raw, key, cfg, lang, errors| string_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "meow.test_url",
        render: |c, key, raw| {
            raw.insert(key.into(), c.meow.test_url.join("\n"));
        },
        apply: |raw, key, cfg, lang, errors| url_list(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "meow.timeout_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.meow.timeout_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: KEY_MEOW_BACKOFF_MIN,
        render: |c, key, raw| {
            raw.insert(key.into(), c.meow.backoff_initial_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: KEY_MEOW_BACKOFF_MAX,
        render: |c, key, raw| {
            raw.insert(key.into(), c.meow.backoff_max_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    // `bool_to_raw`, not `to_string()`: the edit page renders checkbox
    // state from the raw map, where empty means unchecked.
    Setting {
        key: "meow.ipv6",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.meow.ipv6));
        },
        apply: |raw, key, cfg, lang, errors| bool_field(raw, key, cfg, lang, errors),
    },
    // --- retention ---
    Setting {
        key: "retention.probe_results_days",
        render: |c, key, raw| {
            raw.insert(key.into(), c.retention.probe_results_days.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "retention.fetch_log_days",
        render: |c, key, raw| {
            raw.insert(key.into(), c.retention.fetch_log_days.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    // 0 = the purge is off; the range table says so and the sweep skips.
    Setting {
        key: "retention.removed_proxies_days",
        render: |c, key, raw| {
            raw.insert(key.into(), c.retention.removed_proxies_days.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u32_field(raw, key, cfg, lang, errors),
    },
    // --- log ---
    Setting {
        key: "log.server",
        render: |c, key, raw| {
            raw.insert(key.into(), c.log.server.as_str().into());
        },
        apply: |raw, key, cfg, lang, errors| enum_field(raw, key, cfg, LOG_LEVELS, lang, errors),
    },
    Setting {
        key: "log.probe",
        render: |c, key, raw| {
            raw.insert(key.into(), c.log.probe.as_str().into());
        },
        apply: |raw, key, cfg, lang, errors| enum_field(raw, key, cfg, LOG_LEVELS, lang, errors),
    },
];

/// Build the edit template's `raw` map from an `AppConfig`, using the
/// canonical render of every registered field. Booleans become `"on"`
/// when true; false is the key present with an empty value, the
/// unchecked render [`SettingsEditTemplate::bool_value`] reads back.
/// Enums become their short name.
///
/// Loaded from the file on every `GET /admin/settings/edit` so the
/// form reflects the just-saved state (the live view is refreshed by
/// `settings_update`). ENV overrides keep their priority because
/// `AppConfig::load` already merges them on top of the file.
fn raw_from_config(c: &AppConfig) -> HashMap<String, String> {
    let mut raw = HashMap::new();
    for setting in SETTINGS {
        (setting.render)(c, setting.key, &mut raw);
    }
    raw
}

fn rate_into(raw: &mut HashMap<String, String>, prefix: &str, rl: &RateLimit) {
    raw.insert(format!("{prefix}.limit"), rl.limit.to_string());
    // The four units the form's select offers. A window that is none of
    // them renders as its exact seconds (`90sec`, the vocabulary the
    // config parser round-trips): rendering it as the bucket it falls
    // into would make the next save rewrite the window (`10/90sec`
    // would save as `10/min`).
    raw.insert(
        format!("{prefix}.unit"),
        match rl.window.as_secs() {
            1 => "sec".to_string(),
            60 => "min".to_string(),
            3600 => "hour".to_string(),
            86_400 => "day".to_string(),
            secs => format!("{secs}sec"),
        },
    );
}

/// The raw-map render of a stored boolean; [`SettingsEditTemplate::bool_value`]
/// reads it back through [`parse_bool_literal`] (`true` → `"on"`, `false` →
/// the key present with an empty value).
fn bool_to_raw(b: bool) -> String {
    if b { "on".to_string() } else { String::new() }
}

/// The values the form shows: what the file on disk says, without the
/// environment layer.
///
/// The panel writes the file, so the operator has to see the file's own
/// values; the environment is layered on top of it (and wins), and the
/// fields it overrides are rendered read-only and left out of the
/// write.
///
/// `Ok(None)` means the file does not exist yet. `Err` names the
/// reason it could not be read.
fn raw_from_file(path: &Path) -> Result<Option<HashMap<String, String>>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.to_string()),
    };
    let config = fumox_core::config::parse_document(&text).map_err(|err| err.to_string())?;
    Ok(Some(raw_from_config(&config)))
}

/// The outcome of the load/validate/save cycle of the settings form.
enum SaveOutcome {
    /// The document was written.
    Saved {
        path: String,
        /// The admin token the document carried before the write.
        previous_token: String,
        /// The admin token the document carries after the write.
        new_token: String,
        /// The dotted key names this submit actually wrote: carried by the
        /// form and not overridden by the environment. Names only — the
        /// values (the admin token first of all) never belong in a log.
        written_keys: Vec<String>,
    },
    /// The submitted values did not validate; nothing was written.
    Invalid(Vec<(String, String)>),
    /// The document the panel would write is one the binaries refuse
    /// to load. Nothing was written.
    InvalidDocument(String),
    /// The document could not be read.
    LoadError(String),
    /// The document could not be written.
    WriteError(String),
    /// The file changed under the form.
    Conflict,
}

/// Load the document, apply the submitted values and write the result
/// back.
///
/// The whole cycle is synchronous file work: it parses the document and
/// holds the config lock for the read-modify-write. It runs on the
/// blocking pool, so a slow disk cannot stall the async runtime.
fn save_settings(
    target: PathBuf,
    raw: HashMap<String, String>,
    lang: Lang,
    env_locked: Vec<String>,
) -> SaveOutcome {
    let mut cfg = match EditableConfig::load(&target) {
        Ok(cfg) => cfg,
        Err(err) => return SaveOutcome::LoadError(err.to_string()),
    };

    let previous_token = cfg
        .get(KEY_ADMIN_TOKEN)
        .and_then(|item| item.as_str())
        .unwrap_or_default()
        .to_string();

    let mut errors: Vec<(String, String)> = Vec::new();
    apply_all(&raw, &mut cfg, &lang, &mut errors, &env_locked);
    if !errors.is_empty() {
        return SaveOutcome::Invalid(errors);
    }

    // What this submit writes, for the audit line the caller emits: the
    // registry keys the form carried and the environment does not
    // override. On the success path below every one of them was applied
    // (a failed application would have produced `Invalid` above, and
    // nothing is written then). Rate-limit rows ride as their
    // `.limit`/`.unit` halves.
    let carried = |key: &str| raw.contains_key(key) || raw.contains_key(&format!("{key}.limit"));
    let written_keys: Vec<String> = SETTINGS
        .iter()
        .filter(|setting| !is_env_locked(setting.key, &env_locked) && carried(setting.key))
        .map(|setting| setting.key.to_string())
        .collect();

    let new_token = cfg
        .get(KEY_ADMIN_TOKEN)
        .and_then(|item| item.as_str())
        .unwrap_or_default()
        .to_string();

    if let Err(err) = cfg.save() {
        return match err {
            ConfigWriteError::Conflict { .. } => SaveOutcome::Conflict,
            // The document the panel would write is one the binaries
            // refuse to load. That is the operator's file, not a
            // server fault, and it has to be shown as such.
            ConfigWriteError::InvalidDocument { .. } => {
                SaveOutcome::InvalidDocument(err.to_string())
            }
            other => SaveOutcome::WriteError(other.to_string()),
        };
    }

    SaveOutcome::Saved {
        path: target.display().to_string(),
        previous_token,
        new_token,
        written_keys,
    }
}

pub async fn settings_edit(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    // The form is the view of the FILE, not of the running
    // configuration: the panel writes the file, so the operator has to
    // see what the file says. The environment is layered on top of it
    // (and wins), and the fields it overrides are rendered read-only
    // and left out of the write.
    let target = state.config_path.path_or_default();
    let (raw, load_error) = match raw_from_file(&target) {
        Ok(Some(raw)) => (raw, None),
        // No file yet: the operator creates it from the defaults.
        Ok(None) => (raw_from_config(&state.live()), None),
        // The file is there but cannot be read: the live view is the
        // only thing left to show, and the operator is told why the
        // values below are not the file's.
        Err(reason) => {
            tracing::warn!(
                error = %reason,
                path = %target.display(),
                "config load for edit page failed, rendering live view"
            );
            (raw_from_config(&state.live()), Some(reason))
        }
    };

    let banner = if !state.config_writable {
        Some(Banner::Unwritable(target.display().to_string()))
    } else {
        load_error.map(|reason| Banner::LoadFailed(target.display().to_string(), reason))
    };
    let template = edit_template(&state, &headers, raw, Vec::new(), banner);
    render_html(
        template.lang.clone(),
        "settings_edit.html",
        &template,
        StatusCode::OK,
    )
}

pub async fn settings_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    if !state.config_writable {
        return settings_edit_unwritable(&state, &headers);
    }

    let lang = state.locales.lang_from_headers(&headers);
    let raw: HashMap<String, String> = form.into_iter().collect();

    // The fields the environment overrides. The env layer wins over the
    // file, so they are left out of the write and rendered read-only.
    let env_locked = fumox_core::config::env_overridden_paths();

    // Optimistic concurrency: the form carries the fingerprint of the
    // file it was rendered from. A file that changed since (a hand edit
    // in a shell, another panel instance, a deployment that rewrote
    // it) is refused instead of being overwritten by a form that never
    // saw the newer content. The operator reloads and re-applies.
    let target = state.config_path.path_or_default();
    if let Some(submitted) = raw.get("cfg_fingerprint").map(String::as_str)
        && !submitted.is_empty()
        && submitted != fingerprint(&target)
    {
        tracing::warn!(
            path = %target.display(),
            "settings save refused: the config file changed since the form was rendered"
        );
        return settings_edit_conflict(&state, &headers);
    }

    // Build a fresh `EditableConfig` so we can fail-and-replay the form
    // before touching disk. The validator only reads `raw` and the
    // language catalog, no side effects. The editor holds the
    // process-wide config lock, so it is confined to this cycle: its
    // guard must not ride across the awaits below.
    //
    // The whole cycle is synchronous file work and runs on the blocking
    // pool, so a slow disk cannot stall the async runtime.
    let outcome = match tokio::task::spawn_blocking({
        let target = target.clone();
        let raw = raw.clone();
        let lang = lang.clone();
        let env_locked = env_locked.clone();
        move || save_settings(target, raw, lang, env_locked)
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            tracing::error!(error = %err, "the settings save task failed");
            return settings_edit_load_error(&state, &headers, raw, err.to_string());
        }
    };

    let (path, previous_token, new_token, written_keys) = match outcome {
        SaveOutcome::Saved {
            path,
            previous_token,
            new_token,
            written_keys,
        } => (path, previous_token, new_token, written_keys),
        SaveOutcome::Invalid(errors) => {
            // Field names only, never the submitted values: the log must
            // explain the refusal without carrying what the operator typed.
            tracing::warn!(
                fields = ?errors.iter().map(|(f, _)| f.as_str()).collect::<Vec<_>>(),
                "settings update rejected"
            );
            // The replayed form never echoes the submitted token back:
            // the refusal would otherwise pin the typed secret into the
            // 422 page. The field comes back empty and the message under
            // it says the token was not applied, so the operator knows
            // it has to be typed again.
            let mut raw = raw;
            raw.insert(KEY_ADMIN_TOKEN.to_string(), String::new());
            let mut errors = errors;
            if !errors.iter().any(|(field, _)| field == KEY_ADMIN_TOKEN) {
                errors.push((
                    KEY_ADMIN_TOKEN.to_string(),
                    lang.t("set.edit_token_not_saved").to_string(),
                ));
            }
            let template = edit_template(&state, &headers, raw, errors, None);
            return render_html(
                template.lang.clone(),
                "settings_edit.html",
                &template,
                StatusCode::UNPROCESSABLE_ENTITY,
            );
        }
        SaveOutcome::InvalidDocument(message) => {
            // The file on disk is one the binaries would refuse, so the
            // panel did not write over it. The operator has to see the
            // reason, otherwise the refusal is a mystery.
            tracing::warn!(
                error = %message,
                path = %target.display(),
                "settings save refused: the resulting config would not load"
            );
            let template =
                edit_template(&state, &headers, raw, vec![(String::new(), message)], None);
            return render_html(
                template.lang.clone(),
                "settings_edit.html",
                &template,
                StatusCode::UNPROCESSABLE_ENTITY,
            );
        }
        SaveOutcome::LoadError(message) => {
            tracing::error!(
                error = %message,
                path = %target.display(),
                "settings update: config load failed"
            );
            return settings_edit_load_error(&state, &headers, raw, message);
        }
        SaveOutcome::WriteError(message) => {
            tracing::error!(error = %message, path = %target.display(), "failed to save settings");
            let template = edit_template(
                &state,
                &headers,
                raw,
                vec![(
                    "".into(),
                    lang.t_args("err.internal", &[format!("save: {message}")]),
                )],
                None,
            );
            return render_html(
                template.lang.clone(),
                "settings_edit.html",
                &template,
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
        SaveOutcome::Conflict => {
            // The file changed between the load and the write: the
            // document in hand is a snapshot of a file that no longer
            // exists. Refuse it like the stale-form case, so the other
            // change survives.
            tracing::warn!(
                path = %target.display(),
                "settings save refused: the config file changed during the save"
            );
            return settings_edit_conflict(&state, &headers);
        }
    };

    // The audit line names the file, the keys the submit wrote (names
    // only, never values) and a non-reversible tag of the session that
    // made it.
    tracing::info!(
        path = %path,
        keys = written_keys.join(","),
        session = %session_tag(&headers),
        "settings saved"
    );

    // A token rotation through this form must also revoke the sessions
    // minted under the old token: the session key is derived from the
    // token at startup and stays frozen (`AdminState::session_key`), so
    // without an epoch bump a stolen cookie keeps authenticating until
    // the next restart.
    //
    // The comparison is between the token of the document before the
    // write and the one after it, so only an actual change counts: an
    // unconditional bump would log out the very session performing an
    // unrelated save. An empty submit is NOT a change: `token_field`
    // reads it as "keep the current token", so treating it as a
    // rotation would log the operator out of every unrelated save (the
    // field renders empty and untouched fields submit empty).
    //
    // A token the environment overrides is not a rotation at all: the
    // file's value is inert, the running server keeps the environment's
    // token, and the sessions that token minted stay valid.
    let token_locked = env_locked.iter().any(|path| path == KEY_ADMIN_TOKEN);
    let token_rotated = !token_locked && !new_token.is_empty() && new_token != previous_token;
    if token_rotated {
        tracing::info!("admin token rotated; all admin sessions revoked");
        if !crate::admin::auth::revoke_all_sessions(&state.pool).await {
            tracing::warn!(
                "the session revocation did not persist; cookies minted under the old token stay valid"
            );
        }
    }

    // Refresh the figment-merged in-memory view so the next request to
    // /admin/settings, and every handler reading the live config,
    // renders the values the operator just wrote, instead of the startup
    // snapshot. ENV overrides are re-applied by `config::load` itself, so
    // `FUMOX_*` env vars keep winning on top of the file.
    if let Err(err) = state.refresh_live_config(Path::new(&path)) {
        tracing::warn!(error = %err, path = %path, "live config refresh skipped");
        return settings_refresh_failed(&lang, &headers, &path, &err);
    }

    // The toast says what actually happened. A save that the
    // environment overrules is not a plain success: the operator has to
    // learn that the value they changed is not the one in force. A
    // token rotation ends every session, the operator's own included,
    // so its toast says so instead of a plain "saved".
    let (toast, level) = save_toast(&lang, &path, &env_locked, token_rotated);
    if headers.get("HX-Request").is_some() {
        return htmx_redirect_with_toast("/admin/settings", &toast, level);
    }
    super::flash_redirect("/admin/settings", &toast, level)
}

/// Assemble the edit template: the fields every render shares (langs,
/// theme, CSRF token, deployment facts, fingerprint, env locks) with the
/// per-render `raw`/`errors`/`banner` passed in. One constructor for the
/// render sites, so a new shared field cannot be added to the struct and
/// forgotten at one of them.
fn edit_template(
    state: &AdminState,
    headers: &HeaderMap,
    raw: HashMap<String, String>,
    errors: Vec<(String, String)>,
    banner: Option<Banner>,
) -> SettingsEditTemplate {
    SettingsEditTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(headers),
        lang: state.locales.lang_from_headers(headers),
        active: "settings",
        csrf: state.csrf_for(headers),
        config_path: state.config_path.clone(),
        config_writable: state.config_writable,
        raw,
        errors,
        banner,
        fingerprint: fingerprint(&state.config_path.path_or_default()),
        env_locked: fumox_core::config::env_overridden_paths(),
    }
}

/// A non-reversible log tag of the session that performed a save: the
/// first bytes of a purpose-derived key over the session cookie value.
/// The cookie itself is a bearer credential and never reaches the log;
/// the tag is enough to correlate a save with the session that made it.
fn session_tag(headers: &HeaderMap) -> String {
    use std::fmt::Write as _;
    let Some(session) = crate::admin::auth::session_cookie_value(headers) else {
        return String::new();
    };
    let derived = crate::admin::auth::derive_key(b"fumox-settings-audit", &session);
    let mut tag = String::with_capacity(16);
    for byte in &derived[..8] {
        let _ = write!(tag, "{byte:02x}");
    }
    tag
}

/// The toast a finished save answers with, and its level.
///
/// A plain success claims that the values the operator just wrote are
/// the ones in force. The environment sits above the file and wins, so
/// a save that touched an overridden setting did not put that value in
/// force — the toast has to say so instead of claiming a success. A
/// token rotation went further than a save: every session was ended,
/// and the operator is told to sign in again.
fn save_toast(
    lang: &Lang,
    path: &str,
    env_locked: &[String],
    token_rotated: bool,
) -> (String, &'static str) {
    if env_locked.iter().any(|locked| locked == KEY_ADMIN_TOKEN) {
        return (
            lang.t_named("set.edit_token_env_override", &[("path", path.to_string())]),
            "error",
        );
    }
    if token_rotated {
        return (
            lang.t_named(
                "set.edit_token_rotated_toast",
                &[("path", path.to_string())],
            ),
            "warning",
        );
    }
    if !env_locked.is_empty() {
        return (
            lang.t_named(
                "set.edit_env_locked_toast",
                &[
                    ("path", path.to_string()),
                    ("fields", env_locked.join(", ")),
                ],
            ),
            "ok",
        );
    }
    (
        lang.t_named("set.edit_saved_toast", &[("path", path.to_string())]),
        "ok",
    )
}

/// The save reached the disk, but the running view could not be
/// refreshed: the file on disk carries the operator's new configuration,
/// the process keeps the old one until the next restart. The operator is
/// told with an error-level toast, because a green "saved" toast would
/// claim the new values are live while the server runs on the old ones.
fn settings_refresh_failed(
    lang: &Lang,
    headers: &HeaderMap,
    path: &str,
    err: &fumox_core::Error,
) -> Response {
    let message = lang.t_named(
        "err.config_not_reloaded",
        &[("path", path.to_string()), ("error", err.to_string())],
    );
    if headers.get("HX-Request").is_some() {
        return htmx_redirect_with_toast("/admin/settings", &message, "error");
    }
    super::flash_redirect("/admin/settings", &message, "error")
}

fn htmx_redirect_with_toast(redirect_to: &str, toast: &str, level: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (
                HeaderName::from_static("hx-redirect"),
                HeaderValue::from_str(redirect_to).expect("static settings path"),
            ),
            (
                HeaderName::from_static("hx-trigger"),
                super::toast_trigger(level, toast),
            ),
        ],
    )
        .into_response()
}

/// The config file changed under the open form, so the submit is
/// refused. The page comes back with the values that are on disk *now*
/// and the current fingerprint, so the operator reviews them and
/// re-applies their change; a stale form carrying the old values would
/// overwrite the change that beat it.
fn settings_edit_conflict(state: &AdminState, headers: &HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(headers);
    let target = state.config_path.path_or_default();
    let raw = match raw_from_file(&target) {
        Ok(Some(raw)) => raw,
        Ok(None) | Err(_) => raw_from_config(&state.live()),
    };
    let template = edit_template(
        state,
        headers,
        raw,
        vec![("".into(), lang.t("err.config_conflict").to_string())],
        None,
    );
    render_html(
        template.lang.clone(),
        "settings_edit.html",
        &template,
        StatusCode::CONFLICT,
    )
}

fn settings_edit_unwritable(state: &AdminState, headers: &HeaderMap) -> Response {
    let template = edit_template(
        state,
        headers,
        raw_from_config(&state.live()),
        Vec::new(),
        Some(Banner::Unwritable(
            state.config_path.path_or_default().display().to_string(),
        )),
    );
    render_html(
        template.lang.clone(),
        "settings_edit.html",
        &template,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
}

/// The submitted form cannot be applied because the target file could not
/// be read (or the save task died). The page comes back with the
/// operator's own form values — not a re-render of the live config, which
/// would silently discard what they typed — and the load-failure banner
/// names the file and the reason it is unreadable.
fn settings_edit_load_error(
    state: &AdminState,
    headers: &HeaderMap,
    raw: HashMap<String, String>,
    message: String,
) -> Response {
    let template = edit_template(
        state,
        headers,
        raw,
        Vec::new(),
        Some(Banner::LoadFailed(
            state.config_path.path_or_default().display().to_string(),
            message,
        )),
    );
    render_html(
        template.lang.clone(),
        "settings_edit.html",
        &template,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

/// Create `config/app.toml` from the embedded reference copy when it is
/// missing. No-op when the file already exists, so a retry from a stale
/// tab is harmless.
pub async fn settings_create(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let target = state.config_path.path_or_default();

    if target.exists() {
        return redirect_after_create(lang.t("set.file_created_noop").to_string());
    }

    if !matches!(
        fumox_core::config_writer::is_writable(target.parent().unwrap_or(Path::new("."))),
        Ok(fumox_core::config_writer::Writability::Writable)
    ) {
        // Back to the overview with the reason as an error toast, like
        // every other answer of this button: the operator clicked on the
        // overview, the answer lands where they are instead of a 422 page
        // that looks like the editor broke.
        let message = lang.t_named(
            "set.edit_unwritable",
            &[("path", target.display().to_string())],
        );
        return super::flash_redirect("/admin/settings", &message, "error");
    }

    // The file is written through the same atomic path a save takes: a
    // temporary file in the same directory, fsynced, then moved into
    // place. A create that dies half-way leaves no half-written config
    // behind for the next start to refuse.
    let created = tokio::task::spawn_blocking({
        let target = target.clone();
        move || {
            fumox_core::config_writer::create_private_file_atomic(
                &target,
                fumox_core::config_writer::REFERENCE_CONFIG,
            )
        }
    })
    .await;

    match created {
        Ok(Ok(())) => {
            tracing::info!(
                path = %target.display(),
                "config file created from reference defaults"
            );
        }
        Ok(Err(err)) => {
            tracing::error!(error = %err, path = %target.display(), "failed to write reference config");
            return settings_create_failed(&state, &headers, err.to_string());
        }
        Err(err) => {
            tracing::error!(error = %err, path = %target.display(), "failed to write reference config");
            return settings_create_failed(&state, &headers, err.to_string());
        }
    }

    // The file was just materialised from the embedded reference copy;
    // pull the freshly-merged view into the in-memory cache so the next
    // GET to /admin/settings/edit (and the *Settings* overview) renders
    // every default rather than the empty startup snapshot.
    if let Err(err) = state.refresh_live_config(&target) {
        tracing::warn!(error = %err, path = %target.display(), "live config refresh after create skipped");
        let message = lang.t_named(
            "err.config_not_reloaded",
            &[
                ("path", target.display().to_string()),
                ("error", err.to_string()),
            ],
        );
        return super::flash_redirect("/admin/settings/edit", &message, "error");
    }
    let path = target.display().to_string();
    let msg = lang.t_named("set.file_created_toast", &[("path", path)]);
    redirect_after_create(msg)
}

fn redirect_after_create(toast: String) -> Response {
    super::flash_redirect("/admin/settings/edit", &toast, "ok")
}

/// The reference copy could not be written. Not a load failure — the
/// load-failure banner would blame the wrong step — so the reason rides
/// as the form-level error instead.
fn settings_create_failed(state: &AdminState, headers: &HeaderMap, message: String) -> Response {
    let lang = state.locales.lang_from_headers(headers);
    let internal = lang.t("err.internal").to_string();
    let template = edit_template(
        state,
        headers,
        raw_from_config(&state.live()),
        vec![("".into(), format!("{internal}: {message}"))],
        None,
    );
    render_html(
        template.lang.clone(),
        "settings_edit.html",
        &template,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

// Validation / application.

/// Walk every registered setting and apply the ones the form carried.
/// Each field is parsed in isolation, errors accumulate without
/// short-circuiting so the operator sees every problem on a single
/// submit.
///
/// A field the environment overrides is left alone: the env layer wins
/// over the file, so a value written here would never take effect and
/// the operator would be shown a change that does not happen.
fn apply_all(
    raw: &HashMap<String, String>,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
    env_locked: &[String],
) {
    for setting in SETTINGS {
        if is_env_locked(setting.key, env_locked) {
            continue;
        }
        (setting.apply)(raw, setting.key, cfg, lang, errors);
    }

    // Cross-field checks the serde model cannot express.
    let max = raw
        .get(KEY_MEOW_BACKOFF_MAX)
        .and_then(|s| s.parse::<u64>().ok());
    let min = raw
        .get(KEY_MEOW_BACKOFF_MIN)
        .and_then(|s| s.parse::<u64>().ok());
    // A locked side of the pair carries the environment's value, not
    // the file's, so the two halves are not comparable here.
    if is_env_locked(KEY_MEOW_BACKOFF_MAX, env_locked)
        || is_env_locked(KEY_MEOW_BACKOFF_MIN, env_locked)
    {
        return;
    }
    if let (Some(min), Some(max)) = (min, max)
        && max < min
    {
        errors.push((
            KEY_MEOW_BACKOFF_MAX.into(),
            lang.t_args(
                "val.in_range",
                &[format!("\u{2265} {min}"), min.to_string()],
            ),
        ));
    }
}

// Field helpers.
// Field helpers.

/// Bounds of the quarantine recheck ladder, copied from
/// `fumox_core::config::de_recheck_delays` (the deserializer both
/// binaries load the file with). The panel writes the file verbatim, so
/// it must refuse exactly what that parser refuses: a value the loader
/// rejects aborts the next start of fumox-server and fumox-probe.
/// Return the value at `field` only when the form actually carried it.
/// Missing fields are skipped silently, the editor only writes the
/// sections the operator touched, preserving every other setting as it
/// is on disk. Required-only-on-write validation lives in the per-field
/// helpers (empty string is an error, no string at all is not).
fn raw_get<'a>(raw: &'a HashMap<String, String>, field: &str) -> Option<&'a str> {
    raw.get(field).map(String::as_str)
}

/// [`EditableConfig::set`] with the failure surfaced in the per-field
/// error list. A swallowed `UnknownSection` (the slot on disk holds a
/// non-table value) used to save the untouched document and report
/// success: the operator saw a green toast for a setting that was not
/// written. The refusal text is the config writer's own (`toml_edit`/io
/// wording), so it is wrapped in a catalog sentence instead of surfacing
/// untranslated on the form.
fn set_field(
    cfg: &mut EditableConfig,
    field: &str,
    value: ConfigItem,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    if let Err(err) = cfg.set(field, value) {
        errors.push((
            field.into(),
            lang.t_args("val.write_failed", &[err.to_string()]),
        ));
    }
}

fn bind(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    match v.parse::<SocketAddr>() {
        Ok(addr) => {
            set_field(cfg, field, item::string(addr.to_string()), lang, errors);
        }
        Err(_) => {
            errors.push((field.into(), lang.t("val.invalid_bind").into()));
        }
    }
}

fn string_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    if v.is_empty() {
        errors.push((field.into(), lang.t("val.required").into()));
        return;
    }
    set_field(cfg, field, item::string(v.to_string()), lang, errors);
}

/// The admin token. An empty submit keeps the current token: the
/// documented contract (USERGUIDE: "sending the empty string keeps the
/// current token … so the panel never silently disables itself"), and
/// it is also what an untouched field submits, because the render never
/// puts the live token into the form (see the `admin.token` render).
/// `string_field` would refuse an empty submit with `val.required`,
/// and a value of `""` written to the file would disable the panel at
/// the next start.
fn token_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    if v.is_empty() {
        // Keep-current: nothing is written, the document keeps the
        // token it loaded from disk.
        return;
    }
    if v == fumox_core::config::PLACEHOLDER_ADMIN_TOKEN {
        // The placeholder is not a credential: writing it would leave the
        // server unable to start on a non-loopback bind, and it would
        // never open a session. Reject it here, where the operator can
        // still fix it.
        errors.push((
            field.to_string(),
            lang.t("val.token_placeholder").to_string(),
        ));
        return;
    }
    set_field(cfg, field, item::string(v.to_string()), lang, errors);
}

/// The error text for a value outside its setting's range. Reads the
/// bound from [`bounds`] by the field name, so a numeric setting cannot
/// be enforced against one range and advertised with another.
fn out_of_range(field: &str, lang: &Lang) -> String {
    let Some(range) = bounds::range_of(field) else {
        // A numeric field with no entry in the table is a wiring bug,
        // not a user error. Say so instead of blaming the input.
        return format!("{field} has no configured range");
    };
    lang.t_args(
        "val.in_range",
        &[range.min.to_string(), range.max.to_string()],
    )
}

/// Whether a number survives the round trip through the TOML document,
/// which stores integers as `i64`. A larger value wraps negative on the
/// write and the saved config fails to load at the next start.
fn fits_document_i64(value: u64) -> bool {
    value <= i64::MAX as u64
}

fn u64_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    let parsed = match v.parse::<u64>() {
        Ok(n) => n,
        Err(_) => {
            errors.push((field.into(), lang.t("val.must_be_u64").into()));
            return;
        }
    };
    if !bounds::range_of(field).is_some_and(|r| r.contains(parsed)) {
        errors.push((field.into(), out_of_range(field, lang)));
        return;
    }
    // `item::integer` stores an `i64`, so a larger `u64` wraps negative
    // on the write and the saved config fails to load at the next start.
    if !fits_document_i64(parsed) {
        errors.push((
            field.into(),
            lang.t_args("val.must_be_at_most", &[i64::MAX.to_string()]),
        ));
        return;
    }
    set_field(cfg, field, item::integer(parsed as i64), lang, errors);
}

fn u32_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    let parsed = match v.parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            errors.push((field.into(), lang.t("val.must_be_u64").into()));
            return;
        }
    };
    if !bounds::range_of(field).is_some_and(|r| r.contains(u64::from(parsed))) {
        errors.push((field.into(), out_of_range(field, lang)));
        return;
    }
    set_field(cfg, field, item::integer(i64::from(parsed)), lang, errors);
}

fn usize_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    let parsed = match v.parse::<usize>() {
        Ok(n) => n,
        Err(_) => {
            errors.push((field.into(), lang.t("val.must_be_u64").into()));
            return;
        }
    };
    if !bounds::range_of(field).is_some_and(|r| r.contains(parsed as u64)) {
        errors.push((field.into(), out_of_range(field, lang)));
        return;
    }
    set_field(cfg, field, item::integer(parsed as i64), lang, errors);
}

/// The literals a settings checkbox can carry. Save and replay
/// (`bool_value`) must accept exactly this set to agree.
fn parse_bool_literal(v: &str) -> Option<bool> {
    match v {
        "" | "off" | "false" | "0" => Some(false),
        "on" | "true" | "1" => Some(true),
        _ => None,
    }
}

fn bool_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    // The key is handled only when the form carried it. A checkbox the
    // browser did not post (a disabled one, a field the operator never
    // reached) must not reset the setting: writing `false` for it would
    // change a value nobody touched. The form posts the hidden
    // `value="off"` pair next to every checkbox, so an unchecked box
    // still arrives as an explicit "off".
    let Some(v) = raw_get(raw, field) else { return };
    let Some(b) = parse_bool_literal(v) else {
        errors.push((field.into(), lang.t_args("val.bad_bool", &[v.to_string()])));
        return;
    };
    set_field(cfg, field, item::boolean(b), lang, errors);
}

/// Accepts exactly one of `choices` and writes it back verbatim: every
/// enum the panel round-trips (`fetch.ip_family`, the `[log]` levels)
/// has an identity render, so the membership check IS the parse. One
/// value outside the set fails `config::load` and aborts both binaries
/// at the next start.
fn enum_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    choices: &[&str],
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    if !choices.contains(&v) {
        let msg = lang.t_args("val.must_be_enum", &[choices.join(", ")]);
        errors.push((field.into(), msg));
        return;
    }
    set_field(cfg, field, item::string(v.to_string()), lang, errors);
}

fn string_list(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let items: Vec<String> = v
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    set_field(cfg, field, item::string_array(items), lang, errors);
}

/// The T2 test URLs. Three rules the canonical loader enforces and the
/// panel must not write past: the list must not be empty, every entry
/// must be an absolute `http(s)` URL, and an entry must not point at a
/// private address while the probe's SSRF guard is on. The panel writes
/// the file verbatim and the next start of both binaries aborts on
/// anything the loader refuses, so an entry refused here would have
/// turned a green toast into a dead server.
fn url_list(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let items: Vec<String> = v
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if items.is_empty() {
        errors.push((field.into(), lang.t("val.empty_list").into()));
        return;
    }
    // The guard lives in the `[probe]` section, which the editor applies
    // before this one, so the flag in hand is the one the operator just
    // saved, not the one on disk.
    let allow_private = cfg
        .get("probe.allow_private_targets")
        .and_then(|item| item.as_bool())
        .unwrap_or(false);
    for entry in &items {
        let parsed = match url::Url::parse(entry) {
            Ok(parsed) => parsed,
            Err(err) => {
                errors.push((
                    field.into(),
                    lang.t_args("val.url_invalid", &[err.to_string()]),
                ));
                return;
            }
        };
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                errors.push((
                    field.into(),
                    lang.t_args("val.url_scheme", &[other.to_string()]),
                ));
                return;
            }
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            errors.push((field.into(), lang.t("val.url_no_host").into()));
            return;
        }
        if allow_private {
            continue;
        }
        let ip = match parsed.host() {
            Some(url::Host::Ipv4(addr)) => std::net::IpAddr::V4(addr),
            Some(url::Host::Ipv6(addr)) => std::net::IpAddr::V6(addr),
            Some(url::Host::Domain(_)) | None => continue,
        };
        if let Err(reason) = fumox_core::ssrf::vet_addr(ip, false) {
            errors.push((
                field.into(),
                lang.t_args("val.url_ssrf", &[reason.to_string()]),
            ));
            return;
        }
    }
    set_field(cfg, field, item::string_array(items), lang, errors);
}

/// The trusted reverse-proxy lists (`server.trust_proxy_ips`,
/// `admin.trust_proxy_ips`), validated with the same parser
/// `crate::admin::parse_trusted_cidrs` applies at startup (and which
/// feeds both per-IP rate limiters and the X-Forwarded-Proto scheme
/// detection). The startup parser logs and DROPS an unparsable entry,
/// fail-closed, so an entry it would drop must be refused here behind
/// a field error, not persisted behind a success toast and silently
/// emptied at the next restart. Bare-IP entries are accepted, `ipnet`
/// reads them as host prefixes, exactly what the field hint advertises.
/// Entries are written back verbatim, so what reloads is what was
/// saved; an empty list stays valid (empty = never honor forwarded
/// headers).
fn cidr_list(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let items: Vec<String> = v
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for entry in &items {
        if crate::admin::parse_trusted_cidr_entry(entry).is_none() {
            errors.push((
                field.into(),
                lang.t_args("val.invalid_cidr", std::slice::from_ref(entry)),
            ));
            return;
        }
    }
    set_field(cfg, field, item::string_array(items), lang, errors);
}

/// One integer per line, bounded the way the canonical loader bounds the
/// field it writes: at most `max_items` entries, each within `min..=max`.
/// The admin panel writes the file verbatim and the next start of both
/// binaries aborts on anything `fumox_core::config` refuses, so a bound
/// the loader does not share would turn a green toast into a dead server.
///
/// An empty list is refused even though the loader accepts one: for the
/// only field using this helper today, the recheck ladder, `[]` means
/// «remove the proxy right after the failed second chance». The field
/// hint says so (`set.ladder_hint` names the `recheck_delays_secs = []`
/// file edit), and silently emptying the textarea behind a success toast
/// would disable the quarantine ladder anyway — the panel refuses it and
/// the operator makes the change in the file directly.
#[allow(clippy::too_many_arguments)]
fn i64_list_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    max_items: usize,
    min: i64,
    max: i64,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let mut parsed = Vec::new();
    let mut had_error = false;
    for line in v.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed.parse::<i64>() {
            Ok(n) => parsed.push(n),
            Err(_) => {
                errors.push((
                    field.into(),
                    lang.t_args("val.must_be_i64_list", &[trimmed.to_string()]),
                ));
                had_error = true;
                break;
            }
        }
    }
    if had_error {
        return;
    }
    if parsed.is_empty() {
        errors.push((field.into(), lang.t("val.empty_list").into()));
        return;
    }
    // The count, not a value, is what failed: `val.in_range` is the
    // scalar range key the other helpers use and would read as a per-value
    // bound that the very same check accepts `max_items` of. The message
    // counts generic entries, not whatever the caller's field calls them.
    if parsed.len() > max_items {
        errors.push((
            field.into(),
            lang.t_args("val.too_many_entries", &[max_items.to_string()]),
        ));
        return;
    }
    for n in &parsed {
        if *n < min || *n > max {
            let msg = lang.t_args("val.in_range", &[min.to_string(), max.to_string()]);
            errors.push((field.into(), msg));
            return;
        }
    }
    set_field(cfg, field, item::i64_array(parsed), lang, errors);
}

/// The stored rate limit as text (`120/min`, or a bare `120`).
///
/// The document keeps the pair in one value while the form edits the
/// two halves separately, so a half that did not come in is read back
/// from here.
fn stored_rate_limit_text(cfg: &EditableConfig, prefix: &str) -> Option<String> {
    let item = cfg.get(prefix)?;
    if let Some(text) = item.as_str() {
        return Some(text.trim().to_string());
    }
    item.as_integer().map(|n| n.to_string())
}

/// The unit half of a stored rate limit, in the vocabulary the form
/// uses (`sec`, `min`, `hour`, `day`).
fn stored_rate_unit(cfg: &EditableConfig, prefix: &str) -> Option<String> {
    let text = stored_rate_limit_text(cfg, prefix)?;
    let (_, unit) = text.split_once('/')?;
    form_unit(unit).map(str::to_string)
}

/// The limit half of a stored rate limit.
fn stored_rate_limit(cfg: &EditableConfig, prefix: &str) -> Option<String> {
    let text = stored_rate_limit_text(cfg, prefix)?;
    let limit = match text.split_once('/') {
        Some((limit, _)) => limit,
        None => text.as_str(),
    };
    Some(limit.trim().to_string())
}

/// The form's unit vocabulary with the canonical TOML spelling each
/// literal is written as: the one table the parse and the write share, so
/// a literal cannot be accepted on one side and mis-spelled on the other.
/// The canonical spellings are exactly what `config::RateLimit` parses
/// back (`10/s`, `10/min`, `10/h`, `10/day`).
const RATE_UNITS: &[(&str, &str)] = &[("sec", "s"), ("min", "min"), ("hour", "h"), ("day", "day")];

/// The form's unit literal for a stored spelling: the reverse of
/// [`RATE_UNITS`], plus the loose spellings a hand-edited file may hold.
fn form_unit(unit: &str) -> Option<&'static str> {
    let normalized = unit.trim().to_ascii_lowercase();
    RATE_UNITS
        .iter()
        .find(|(form, toml)| *form == normalized || *toml == normalized)
        .map(|(form, _)| *form)
        .or(match normalized.as_str() {
            "second" => Some("sec"),
            "m" | "minute" => Some("min"),
            "d" => Some("day"),
            _ => None,
        })
}

fn rate_limit(
    raw: &HashMap<String, String>,
    prefix: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    // Both halves of the pair must be present, leaving one out means
    // the form was incomplete.
    let limit_raw = raw_get(raw, &format!("{prefix}.limit")).map(str::to_string);
    let unit_raw = raw_get(raw, &format!("{prefix}.unit")).map(str::to_string);
    let (limit_raw, unit_raw) = match (limit_raw, unit_raw) {
        (None, None) => return,
        (Some(limit), None) => {
            // The unit half did not come in. The document supplies it,
            // so the limit is still checked against the pair it would
            // form, and the submit is then refused: a form that lost
            // half of a pair is not a form the operator meant to send.
            let stored = stored_rate_unit(cfg, prefix);
            errors.push((
                format!("{prefix}.unit"),
                lang.t("val.pair_incomplete").into(),
            ));
            (Some(limit), stored)
        }
        (None, Some(unit)) => {
            let stored = stored_rate_limit(cfg, prefix);
            errors.push((
                format!("{prefix}.limit"),
                lang.t("val.pair_incomplete").into(),
            ));
            (stored, Some(unit))
        }
        both => both,
    };

    let limit_str = limit_raw.as_deref().unwrap_or_default();
    let unit_str = unit_raw.as_deref().unwrap_or_default();

    let limit: u32 = match limit_str.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            errors.push((format!("{prefix}.limit"), lang.t("val.must_be_u64").into()));
            return;
        }
    };
    // The form has always advertised `min="1" max="1000000"` on this
    // input, but nothing checked it: the browser's number validation is
    // the only thing that ever enforced it, so a hand-crafted POST wrote
    // `0/min` and every public request met the limit. The bound now
    // comes from the same table the form renders, which is the point of
    // having one.
    let field = format!("{prefix}.limit");
    if !bounds::range_of(&field).is_some_and(|r| r.contains(u64::from(limit))) {
        let msg = out_of_range(&field, lang);
        errors.push((field, msg));
        return;
    }
    // The pair the edit page rendered from the current document. A pair
    // submitted back exactly as rendered was not touched by the
    // operator: writing it would re-spell the window in the form's own
    // vocabulary, and a window the four select options cannot express
    // (rendered as its exact seconds, `90sec`) would be silently
    // rewritten into a different one. An unchanged pair leaves the
    // document alone.
    let unchanged = stored_rate_limit_text(cfg, prefix)
        .and_then(|text| text.parse::<RateLimit>().ok())
        .is_some_and(|stored| {
            let mut rendered = HashMap::new();
            rate_into(&mut rendered, prefix, &stored);
            rendered
                .get(&format!("{prefix}.limit"))
                .is_some_and(|v| v.as_str() == limit_str.trim())
                && rendered
                    .get(&format!("{prefix}.unit"))
                    .is_some_and(|v| v.as_str() == unit_str.trim())
        });
    if unchanged {
        return;
    }
    // The form literal maps straight onto the canonical TOML spelling
    // through [`RATE_UNITS`] — no intermediate seconds for the four
    // select options to be re-spelled through. The exact-seconds form
    // (`90sec`) is what the render side emits for a window the four
    // cannot spell; the config parser accepts the same vocabulary.
    let unit = unit_str.trim();
    let toml_unit = match RATE_UNITS.iter().find(|(form, _)| *form == unit) {
        Some((_, toml)) => (*toml).to_string(),
        None => match unit
            .strip_suffix("sec")
            .and_then(|n| n.trim().parse::<u64>().ok())
            .filter(|secs| *secs > 0)
        {
            Some(secs) => format!("{secs}sec"),
            None => {
                errors.push((
                    format!("{prefix}.unit"),
                    lang.t_args("val.must_be_enum", &["sec, min, hour, day".into()]),
                ));
                return;
            }
        },
    };
    // The one helper where the error key and the write path differ: the
    // form and the bounds table know `{prefix}.limit`, but the document
    // stores the whole `limit/unit` string under `{prefix}` itself. Like
    // `set_field`, a rejected write must surface as a per-field error
    // instead of being swallowed behind a success toast.
    if let Err(err) = cfg.set(prefix, item::string(format!("{limit}/{toml_unit}"))) {
        errors.push((field, lang.t_args("val.write_failed", &[err.to_string()])));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_minimal_config(dir: &Path) -> PathBuf {
        let path = dir.join("app.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"[server]\nbind = \"0.0.0.0:8080\"\n[probe]\nfail_limit = 3\n")
            .unwrap();
        path
    }

    fn collect_field<'a>(errors: &'a [(String, String)], field: &str) -> Option<&'a str> {
        errors
            .iter()
            .find(|(f, _)| f == field)
            .map(|(_, m)| m.as_str())
    }

    fn temp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fumox-settings-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_lang() -> Lang {
        // Embedded catalogs load without a directory. Resolve an explicit
        // English code so the per-error assertions read stable text;
        // the Russian copy is exercised by the i18n catalog tests.
        crate::admin::i18n::Locales::load(Path::new("/nonexistent-fumox-locales")).resolve("en")
    }

    #[test]
    fn apply_all_writes_valid_bind_and_int() {
        let dir = temp_dir("happy");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("server.bind".into(), "127.0.0.1:9999".into());
        raw.insert("probe.fail_limit".into(), "5".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        let serialized = cfg.doc().to_string();
        assert!(serialized.contains("bind = \"127.0.0.1:9999\""));
        assert!(serialized.contains("fail_limit = 5"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_flags_invalid_bind() {
        let dir = temp_dir("bad-bind");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("server.bind".into(), "not-a-socket".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert_eq!(
            collect_field(&errors, "server.bind"),
            Some("invalid socket address"),
            "actual: {errors:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_rejects_out_of_range() {
        let dir = temp_dir("range");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        // fail_limit min=1 max=32
        raw.insert("probe.fail_limit".into(), "0".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(
            collect_field(&errors, "probe.fail_limit").is_some(),
            "expected an error for fail_limit=0, got {errors:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_flags_unknown_enum() {
        let dir = temp_dir("enum");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("fetch.ip_family".into(), "ipv9".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(collect_field(&errors, "fetch.ip_family").is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression: `cfg.set` returns `UnknownSection` when the slot on
    /// disk holds a non-table value, and every call site used to discard
    /// that result. The save then wrote the untouched document and the
    /// operator got a success toast for a setting that was never
    /// applied. The failure must surface as a per-field error.
    #[test]
    fn apply_all_surfaces_unsettable_slot_instead_of_swallowing_it() {
        let dir = temp_dir("unsettable");
        let path = dir.join("app.toml");
        // `server` is a scalar where the editor needs a table to dive
        // into for `server.bind`.
        std::fs::write(&path, "server = 42\n[probe]\nfail_limit = 3\n").unwrap();

        let mut raw = HashMap::new();
        raw.insert("server.bind".into(), "127.0.0.1:9999".into());
        raw.insert("probe.fail_limit".into(), "5".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(
            collect_field(&errors, "server.bind").is_some(),
            "a failed set must surface as a field error, got {errors:?}"
        );
        // The failure is per-field: unrelated edits still applied.
        assert!(cfg.doc().to_string().contains("fail_limit = 5"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_ip_family_round_trips_through_parser() {
        // The dropdown values must match IpFamily::from_str, otherwise
        // the admin save writes a value that the canonical parser
        // refuses on the next restart, silently reverting to default.
        use std::str::FromStr;

        let dir = temp_dir("ip-roundtrip");
        let path = write_minimal_config(&dir);

        for family in [IpFamily::Any, IpFamily::Ipv4, IpFamily::Ipv6] {
            let mut raw = HashMap::new();
            raw.insert("fetch.ip_family".into(), family.as_str().into());

            let lang = test_lang();
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);
            assert!(
                errors.is_empty(),
                "save produced errors for {family:?}: {errors:?}"
            );

            let serialized = cfg.doc().to_string();
            let parsed = IpFamily::from_str(family.as_str())
                .expect("IpFamily::as_str must produce a value IpFamily accepts");
            assert_eq!(parsed, family, "round-trip drifted for {family:?}");

            // toml_edit serialises the leaf under its `[fetch]` section
            // header, so the on-disk text contains the bare key
            // (`ip_family = "ipv4"`) rather than the dotted form.
            assert!(
                serialized.contains(&format!("ip_family = \"{}\"", family.as_str())),
                "saved config missing the literal for {family:?}: {serialized}"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_handles_meow_backoff_cross_check() {
        let dir = temp_dir("cross");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("meow.backoff_initial_secs".into(), "60".into());
        raw.insert("meow.backoff_max_secs".into(), "30".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(
            collect_field(&errors, "meow.backoff_max_secs").is_some(),
            "expected cross-field error, got {errors:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A `false` boolean must reach the edit page as an EMPTY raw value,
    /// the unchecked render `bool_value` re-reads via `parse_bool_literal`.
    #[test]
    fn meow_ipv6_raw_value_round_trips_as_a_checkbox() {
        let mut cfg = AppConfig::default();
        cfg.meow.ipv6 = false;
        assert_eq!(
            raw_from_config(&cfg).get("meow.ipv6").map(String::as_str),
            Some(""),
            "false must map to an empty raw value, not the literal"
        );

        cfg.meow.ipv6 = true;
        assert_eq!(
            raw_from_config(&cfg).get("meow.ipv6").map(String::as_str),
            Some("on")
        );
    }

    #[test]
    fn apply_all_parses_bool_checkboxes() {
        let dir = temp_dir("bool");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("ingest.drop_gate".into(), "on".into());
        // `removed_as_unknown` is absent: a checkbox the browser did
        // not post must not reset the setting.

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(errors.is_empty());
        let serialized = cfg.doc().to_string();
        assert!(serialized.contains("drop_gate = true"));
        assert!(
            !serialized.contains("removed_as_unknown"),
            "a checkbox the form did not carry must not be written: {serialized}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rate_into_renders_minutes() {
        let mut raw = HashMap::new();
        let rl = RateLimit {
            limit: 300,
            window: std::time::Duration::from_secs(60),
        };
        rate_into(&mut raw, "server.rate_limit", &rl);
        assert_eq!(raw.get("server.rate_limit.limit").unwrap(), "300");
        assert_eq!(raw.get("server.rate_limit.unit").unwrap(), "min");
    }

    #[test]
    fn rate_limit_field_round_trip() {
        let dir = temp_dir("rate");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("server.rate_limit.limit".into(), "120".into());
        raw.insert("server.rate_limit.unit".into(), "min".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(errors.is_empty());
        let serialized = cfg.doc().to_string();
        assert!(
            serialized.contains("rate_limit = \"120/min\""),
            "got: {serialized}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A window the four form units cannot spell (`10/90sec`) must
    /// survive a save that did not touch the pair. The edit page renders
    /// its exact seconds (`90sec`), and the pair submitted back verbatim
    /// is not rewritten; the old render bucketed 90s into `min`, so
    /// saving any other field silently turned the window into `10/min`.
    #[test]
    fn noncanonical_rate_window_survives_an_untouched_save() {
        let dir = temp_dir("rate-window");
        let path = dir.join("app.toml");
        std::fs::write(
            &path,
            "[server]\nbind = \"0.0.0.0:8080\"\nrate_limit = \"10/90sec\"\n[probe]\nfail_limit = 3\n",
        )
        .unwrap();

        // The edit page renders the exact seconds, not the bucket the
        // window falls into.
        let raw = raw_from_file(&path).unwrap().expect("the file parses");
        assert_eq!(
            raw.get("server.rate_limit.limit").map(String::as_str),
            Some("10")
        );
        assert_eq!(
            raw.get("server.rate_limit.unit").map(String::as_str),
            Some("90sec")
        );

        // Saving a different field with the pair rendered back verbatim
        // keeps the window exactly as the document holds it. Each cycle
        // scopes its `EditableConfig` handle: the editor holds the
        // config lock from `load` to drop, so a second overlapping load
        // would deadlock.
        let lang = test_lang();
        let mut raw = raw;
        raw.insert("probe.fail_limit".into(), "7".into());
        let serialized = {
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);
            assert!(errors.is_empty(), "{errors:?}");
            cfg.save().unwrap();
            cfg.doc().to_string()
        };
        assert!(
            serialized.contains("rate_limit = \"10/90sec\""),
            "an untouched pair must keep its exact window: {serialized}"
        );
        assert!(serialized.contains("fail_limit = 7"), "{serialized}");

        // A pair the operator did change is written as submitted.
        let mut raw = raw_from_file(&path).unwrap().unwrap();
        raw.insert("server.rate_limit.limit".into(), "20".into());
        raw.insert("server.rate_limit.unit".into(), "min".into());
        let serialized = {
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);
            assert!(errors.is_empty(), "{errors:?}");
            cfg.save().unwrap();
            cfg.doc().to_string()
        };
        assert!(
            serialized.contains("rate_limit = \"20/min\""),
            "a changed pair must be written: {serialized}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The recheck ladder is the only integer list the panel writes, and
    /// the canonical loader (`config::de_recheck_delays`) refuses more
    /// than 16 steps and any delay outside 1..=30 days, both binaries
    /// abort on a file the loader rejects. The bounds checked here must
    /// therefore be the loader's: a ladder the panel accepts has to round
    /// trip through `config::load_config`, and one it rejects must never
    /// reach the file. An emptied textarea is the one value the loader
    /// takes and the panel does not, and that asymmetry is deliberate
    /// (see `i64_list_field`).
    #[test]
    fn recheck_ladder_bounds_match_the_canonical_loader() {
        use fumox_core::config::load_config;

        let dir = temp_dir("ladder");
        let path = write_minimal_config(&dir);
        let lang = test_lang();

        // One admin save cycle. `load_config` deliberately does NOT take the
        // `EditLock` that `EditableConfig::load` holds: the plain loader
        // reads the file without it, and has to keep doing so, because the
        // admin handler re-reads through it while the editor handle is still
        // in scope. A loader that took the lock would deadlock the request.
        // See `fumox_core::config_writer::EditLock`.
        let save = |raw: &HashMap<String, String>| -> Vec<(String, String)> {
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(raw, &mut cfg, &lang, &mut errors, &[]);
            if errors.is_empty() {
                cfg.save().unwrap();
            }
            errors
        };
        let ladder = |steps: &[i64]| -> HashMap<String, String> {
            HashMap::from([(
                "probe.recheck_delays_secs".to_string(),
                steps
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )])
        };

        // A ladder the loader accepts must save and reload unchanged.
        let steps: Vec<i64> = (1..=16).collect();
        let errors = save(&ladder(&steps));
        assert!(errors.is_empty(), "16 steps must be accepted: {errors:?}");
        let loaded = load_config(Some(&path)).expect("the saved ladder must load");
        assert_eq!(loaded.probe.recheck_delays_secs, steps);

        // 17 steps: the panel must refuse it, the loader would not. The
        // message must name the count, not borrow the scalar range wording
        // `u64_field` and friends use, «must be between 0 and 16» reads
        // as a per-delay bound and contradicts the 16 steps just accepted.
        // It also must stay generic: `i64_list_field` is parameterised by
        // `max_items` and knows nothing about ladders, so it counts
        // entries, not steps.
        let errors = save(&ladder(&(1..=17).collect::<Vec<i64>>()));
        let message = collect_field(&errors, "probe.recheck_delays_secs")
            .unwrap_or_else(|| panic!("17 steps must be refused with a message, got {errors:?}"));
        assert_ne!(
            message,
            lang.t_args("val.in_range", &["0".to_string(), "16".to_string()]),
            "an over-long ladder must not be reported as a scalar range"
        );
        assert_eq!(
            message, "at most 16 entries",
            "the count message must not borrow this helper's caller's vocabulary"
        );
        assert!(
            load_config(Some(&path)).is_ok(),
            "the refused ladder must not have been written"
        );

        // Per-delay range: 0, a negative and 30 days + 1s are out,
        // 30 days exactly is in.
        for (value, accepted) in [
            ("0", false),
            ("-1", false),
            ("2592001", false),
            ("2592000", true),
        ] {
            let raw = HashMap::from([("probe.recheck_delays_secs".to_string(), value.into())]);
            let errors = save(&raw);
            assert_eq!(
                collect_field(&errors, "probe.recheck_delays_secs").is_some(),
                !accepted,
                "delay {value} accepted={accepted}, errors: {errors:?}"
            );
        }

        // An emptied textarea is refused, not silently written as an empty
        // ladder: `[]` means «remove the proxy right after the failed
        // second chance», the field hint sends the operator to the file
        // for that (`set.ladder_hint`), and the panel must not trade the
        // operator's ladder for it on a stray select-all + delete.
        let errors = save(&ladder(&[]));
        assert_eq!(
            collect_field(&errors, "probe.recheck_delays_secs"),
            Some(lang.t("val.empty_list")),
            "an emptied ladder must be refused: {errors:?}"
        );
        let loaded = load_config(Some(&path)).expect("the last good ladder must still load");
        assert_eq!(
            loaded.probe.recheck_delays_secs,
            vec![2_592_000],
            "the refused empty ladder must not have been written"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every dotted key the registry renders must be parseable back by
    /// the very same registry, and the shipped defaults must validate
    /// cleanly. This is the whole render→parse pairing in one shot: a
    /// field added to one side but not the other, or a default outside
    /// the advertised range, fails here instead of surfacing as a
    /// silently reverted or unsaveable setting.
    #[test]
    fn the_registry_round_trips_the_default_config_with_zero_errors() {
        let dir = temp_dir("registry-roundtrip");
        let path = write_minimal_config(&dir);
        let lang = test_lang();

        let raw = raw_from_config(&AppConfig::default());
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(errors.is_empty(), "defaults must validate: {errors:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The keys `raw_from_config` produces are exactly the registry's:
    /// every registered key is rendered (a rate-limit entry as its
    /// `.limit`/`.unit` pair), and nothing is rendered that the registry
    /// does not own. A key that appears here but nowhere else is exactly
    /// the silent drift this table exists to prevent.
    #[test]
    fn the_registry_covers_every_rendered_key() {
        let raw = raw_from_config(&AppConfig::default());
        let keys: Vec<&str> = SETTINGS.iter().map(|s| s.key).collect();

        for key in &keys {
            let direct = raw.contains_key(*key);
            let rate_pair = raw.contains_key(&format!("{key}.limit"))
                && raw.contains_key(&format!("{key}.unit"));
            assert!(
                direct || rate_pair,
                "registry key {key} is rendered under neither its own name nor a limit/unit pair"
            );
        }
        for rendered in raw.keys() {
            let owned = keys.iter().any(|key| {
                rendered == key
                    || rendered.strip_suffix(".limit") == Some(key)
                    || rendered.strip_suffix(".unit") == Some(key)
            });
            assert!(
                owned,
                "{rendered} is rendered but not owned by any registry entry"
            );
        }
    }

    /// The unit half of every rate-limit pair renders through the
    /// `unit_select` macro, and the form scans below read the template
    /// as text. Expand each call into the attributes the macro renders
    /// for the field (its `name=` and the `error_attrs` call) and drop
    /// the macro definition itself, so the scans see the form the way
    /// the renderer produces it.
    fn expand_unit_select_macro(template: &str) -> String {
        const MACRO_HEAD: &str = "{% macro unit_select(field) %}";
        const MACRO_TAIL: &str = "{% endmacro %}";
        let start = template
            .find(MACRO_HEAD)
            .expect("unit_select macro definition present");
        let tail_at = template[start..]
            .find(MACRO_TAIL)
            .expect("unit_select macro definition closed");
        let without_def = format!(
            "{}{}",
            &template[..start],
            &template[start + tail_at + MACRO_TAIL.len()..]
        );

        let mut expanded = String::with_capacity(without_def.len());
        let mut rest = without_def.as_str();
        while let Some(pos) = rest.find("unit_select(\"") {
            let (head, tail) = rest.split_at(pos);
            expanded.push_str(head);
            let after = &tail["unit_select(\"".len()..];
            let key_end = after
                .find('"')
                .expect("unit_select call carries a quoted field");
            let key = &after[..key_end];
            expanded.push_str(&format!("name=\"{key}\" error_attrs(\"{key}\")"));
            rest = &after[key_end..];
        }
        expanded.push_str(rest);
        expanded
    }

    /// The HTML form is the one hand-written artifact left: this test is
    /// the stitch that keeps it honest. Every input the form posts must
    /// belong to a registry entry, and every entry must be editable
    /// through the form, either under its own `name=` or, for a
    /// rate-limit pair, as `.limit` + `.unit`.
    #[test]
    fn the_form_posts_exactly_the_registered_settings() {
        let template =
            expand_unit_select_macro(include_str!("../../../templates/settings_edit.html"));
        let mut posted: Vec<String> = Vec::new();
        let mut rest = template.as_str();
        while let Some(pos) = rest.find("name=\"") {
            rest = &rest[pos + 6..];
            if let Some(end) = rest.find('"') {
                posted.push(rest[..end].to_string());
                rest = &rest[end..];
            }
        }
        posted
            .retain(|name| name != "_csrf" && name != "settings-tab" && name != "cfg_fingerprint");

        let keys: Vec<&str> = SETTINGS.iter().map(|s| s.key).collect();

        for name in &posted {
            let owned = keys.iter().any(|key| {
                name == key
                    || name.strip_suffix(".limit") == Some(*key)
                    || name.strip_suffix(".unit") == Some(*key)
            });
            assert!(owned, "the form posts {name} but no registry entry owns it");
        }
        for key in &keys {
            let direct = posted.iter().any(|name| name == key);
            let rate_pair =
                posted.contains(&format!("{key}.limit")) && posted.contains(&format!("{key}.unit"));
            assert!(
                direct || rate_pair,
                "registry key {key} has no input in the form; add the field or drop the entry"
            );
        }
    }

    /// Every field the form can carry has a place to show what the
    /// server refused. The registry decides which fields exist, and the
    /// server reports its errors under those field names, so a field
    /// without an error block would swallow the message: the page comes
    /// back with a 422 and nothing on it.
    #[test]
    fn the_form_carries_an_error_block_for_every_field() {
        let raw = raw_from_config(&AppConfig::default());
        let template =
            expand_unit_select_macro(include_str!("../../../templates/settings_edit.html"));

        for key in raw.keys() {
            assert!(
                template.contains(&format!("error_for(\"{key}\")")),
                "the form has no error block for {key}"
            );
            assert!(
                template.contains(&format!("error_attrs(\"{key}\")")),
                "the form does not mark the control of {key} as invalid"
            );
            assert!(
                template.contains(&format!("id=\"err-{key}\"")),
                "the error block of {key} has no id the control can point at"
            );
        }
    }

    /// Regression for the *Edit settings* bug where the page re-rendered
    /// stale `state.config` instead of reading the file the editor just
    /// wrote to. After `EditableConfig::save()`, a subsequent reload
    /// must hand the form the new on-disk values, not the in-memory
    /// snapshot frozen at startup.
    #[test]
    fn raw_from_config_reflects_post_save_file_state() {
        use fumox_core::config::load_config;

        let dir = temp_dir("postsave");
        let path = dir.join("app.toml");

        std::fs::write(
            &path,
            "[ingest]\ndrop_gate = false\n[admin]\nsecure_cookies = true\n",
        )
        .unwrap();

        let cfg = load_config(Some(&path)).expect("initial load must work");
        let raw = raw_from_config(&cfg);
        // `drop_gate = false` in the file → key present with empty value;
        // `bool_value` parses the literals through `parse_bool_literal`,
        // so an empty string (and an absent key) read as unchecked.
        assert_eq!(raw.get("ingest.drop_gate").map(String::as_str), Some(""));
        // `secure_cookies = true` → "on".
        assert_eq!(
            raw.get("admin.secure_cookies").map(String::as_str),
            Some("on")
        );

        // Simulate the admin save: flip the bool values in the file.
        std::fs::write(
            &path,
            "[ingest]\ndrop_gate = true\n[admin]\nsecure_cookies = false\n",
        )
        .unwrap();

        let cfg = load_config(Some(&path)).expect("post-save load must work");
        let raw = raw_from_config(&cfg);
        // The fresh load must see the *new* file values, not the
        // startup snapshot, this is the regression for the bug where
        // the edit page re-rendered stale in-memory state.
        assert_eq!(raw.get("ingest.drop_gate").map(String::as_str), Some("on"));
        assert_eq!(
            raw.get("admin.secure_cookies").map(String::as_str),
            Some("")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every number input in the settings form resolves to a row in
    /// `config::bounds`, and no bound in that table is left unrendered.
    ///
    /// The ranges used to exist twice: as literal `min`/`max` attributes
    /// in the template and as literal arguments at the save site. The two
    /// could disagree and nothing noticed, which is how the rate-limit
    /// inputs ended up advertising a range the server never checked. Now
    /// that both read one table, the only drift left to guard is the
    /// table losing or gaining a key the form does not use, and a key
    /// typed into a field that is not in the table at all.
    #[test]
    fn every_number_input_has_a_bounds_entry() {
        let template = include_str!("../../../templates/settings_edit.html");
        let mut seen = Vec::new();
        for line in template.lines() {
            let Some(rest) = line.split(r#"type="number""#).nth(1) else {
                continue;
            };
            let Some(name) = rest
                .split(r#"name=""#)
                .nth(1)
                .and_then(|s| s.split('"').next())
            else {
                continue;
            };
            seen.push(name.to_string());
        }
        assert!(seen.len() > 25, "template parsing broke: {seen:?}");
        for name in &seen {
            assert!(
                bounds::range_of(name).is_some(),
                "{name} is a number input with no range in config::bounds::RANGES"
            );
        }
        for (key, _) in bounds::RANGES {
            assert!(
                seen.iter().any(|n| n == key),
                "{key} is bounded but no input edits it; drop it or add the field"
            );
        }
    }

    /// The form must not carry its own numbers: a literal `min="1"` is
    /// exactly the duplication this table replaced, and it is the one a
    /// reviewer will not notice is now out of date.
    #[test]
    fn the_template_takes_no_literal_bounds() {
        let template = include_str!("../../../templates/settings_edit.html");
        for line in template.lines() {
            assert!(
                !line.contains(r#"min=""#) || line.contains("self.range_min"),
                "literal min in: {line}"
            );
            assert!(
                !line.contains(r#"max=""#) || line.contains("self.range_max"),
                "literal max in: {line}"
            );
        }
    }

    /// The form has always advertised `min="1" max="1000000"` on the
    /// rate-limit inputs. Before the table existed nothing checked it:
    /// only the browser's own number validation enforced it, so a POST
    /// that skipped the browser wrote `0/min` and locked every public
    /// route behind a zero budget. The bound is now the loader's.
    #[test]
    fn rate_limit_rejects_a_value_outside_the_advertised_range() {
        let dir = temp_dir("rate-range");
        let path = write_minimal_config(&dir);
        let lang = test_lang();

        for (value, expect_error) in [("0", true), ("1000001", true), ("1", false)] {
            let mut raw = HashMap::new();
            raw.insert("server.rate_limit.limit".into(), value.into());
            raw.insert("server.rate_limit.unit".into(), "min".into());
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

            assert_eq!(
                collect_field(&errors, "server.rate_limit.limit").is_some(),
                expect_error,
                "rate_limit.limit = {value}: {errors:?}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every bounded setting says so in words. The number in the hint
    /// is the number the save handler enforces.
    #[test]
    fn a_bounded_setting_renders_its_range() {
        assert_eq!(bounds::max_attr("fetch.max_response_bytes"), "268435456");
        assert_eq!(bounds::min_attr("fetch.max_response_bytes"), "1024");
        assert_eq!(
            bounds::display("fetch.max_response_bytes").as_deref(),
            Some("1024..=268435456")
        );
        assert_eq!(bounds::max_attr("probe.sample_size"), "100000");
        assert_eq!(
            bounds::display("probe.sample_size").as_deref(),
            Some("1..=100000")
        );
        // A key that is not a bounded number has no range to render.
        assert_eq!(bounds::max_attr("server.bind"), "");
        assert_eq!(bounds::display("server.bind"), None);
    }

    /// Regression: the replay rendered every hidden `value="off"` input
    /// as ticked, so resubmitting silently re-enabled settings.
    #[test]
    fn checkbox_replay_reads_the_literals_the_save_parser_accepts() {
        for (literal, checked) in [
            ("on", true),
            ("true", true),
            ("1", true),
            ("off", false),
            ("false", false),
            ("0", false),
            ("", false),
        ] {
            assert_eq!(
                parse_bool_literal(literal),
                Some(checked),
                "literal {literal:?} must parse as {checked}"
            );
        }
        // An unknown literal is refused; an absent entry reads as the
        // empty-string default.
        assert_eq!(parse_bool_literal("maybe"), None);
    }

    /// Every hidden `value="off"` input must be followed by its checkbox
    /// rendered through `bool_value`; anything else re-breaks the replay.
    #[test]
    fn every_hidden_off_pair_renders_through_bool_value() {
        let template = include_str!("../../../templates/settings_edit.html");
        let mut pairs = 0;
        let mut lines = template.lines();
        while let Some(line) = lines.next() {
            if !line.contains(r#"type="hidden""#) || !line.contains(r#"value="off""#) {
                continue;
            }
            pairs += 1;
            let checkbox = lines.next().unwrap_or("");
            assert!(
                checkbox.contains(r#"type="checkbox""#) && checkbox.contains("self.bool_value("),
                "hidden off input must be followed by its bool_value checkbox, got: {checkbox}"
            );
        }
        assert!(pairs >= 8, "template parsing broke: {pairs} pairs");
    }

    /// Regression: the `[log]` dropdowns accepted any string, and a level
    /// the canonical loader refuses aborts both binaries at the next start.
    #[test]
    fn apply_all_rejects_an_unknown_log_level() {
        let dir = temp_dir("log-bad");
        let path = write_minimal_config(&dir);

        for field in ["log.server", "log.probe"] {
            let mut raw = HashMap::new();
            raw.insert(field.into(), "verbose".into());

            let lang = test_lang();
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

            assert!(
                collect_field(&errors, field).is_some(),
                "{field} = verbose must be refused, got {errors:?}"
            );
            assert!(
                !cfg.doc().to_string().contains("verbose"),
                "the refused level must not reach the document"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every dropdown level must save and reload through the canonical
    /// loader; the set is `LogLevel`'s serde render.
    #[test]
    fn log_levels_round_trip_through_the_canonical_loader() {
        use fumox_core::config::{LogLevel, load_config};

        let dir = temp_dir("log-roundtrip");
        let path = write_minimal_config(&dir);
        let lang = test_lang();

        for level in [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ] {
            let mut raw = HashMap::new();
            raw.insert("log.server".into(), level.as_str().into());
            raw.insert("log.probe".into(), level.as_str().into());

            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);
            assert!(errors.is_empty(), "{level:?} must be accepted: {errors:?}");
            cfg.save().unwrap();

            let loaded = load_config(Some(&path)).expect("the saved level must load");
            assert_eq!(loaded.log.server, level);
            assert_eq!(loaded.log.probe, level);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression: a value above `i64::MAX` wrapped negative on the
    /// write, and the saved config failed `config::load`.
    #[test]
    fn u64_field_refuses_a_value_that_does_not_fit_the_document_i64() {
        use fumox_core::config::load_config;

        let dir = temp_dir("i64-fit");
        let path = write_minimal_config(&dir);
        let lang = test_lang();

        for (value, accepted) in [
            ("1024".to_string(), true),
            ("268435456".to_string(), true),
            (i64::MAX.to_string(), false),
            (u64::MAX.to_string(), false),
        ] {
            let mut raw = HashMap::new();
            raw.insert("fetch.max_response_bytes".into(), value.clone());

            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

            assert_eq!(
                collect_field(&errors, "fetch.max_response_bytes").is_some(),
                !accepted,
                "fetch.max_response_bytes = {value}, errors: {errors:?}"
            );
            if accepted {
                cfg.save().unwrap();
                let loaded = load_config(Some(&path)).expect("the saved value must load");
                assert_eq!(loaded.fetch.max_response_bytes.to_string(), value);
            } else {
                assert!(
                    load_config(Some(&path)).is_ok(),
                    "the refused value must not have been written"
                );
            }
        }
        std::fs::remove_dir_all(&dir).ok();

        // The document stores integers as `i64`. A larger value would
        // wrap negative on the write and the saved config would fail to
        // load at the next start.
        assert!(fits_document_i64(i64::MAX as u64));
        assert!(!fits_document_i64(i64::MAX as u64 + 1));
        assert!(!fits_document_i64(u64::MAX));
    }

    /// The trust lists feed `crate::admin::parse_trusted_cidrs`, which
    /// re-parses them at startup and DROPS what it cannot parse (fail
    /// closed, pinned by the `parse_trusted_cidrs` tests in
    /// `admin_tests.rs`). An entry the parser would drop must therefore
    /// be refused here behind a field error: the old `string_list`
    /// behavior persisted e.g. `10.0.0.0/33` behind a success toast and
    /// silently emptied the entry at the next restart, degrading per-IP
    /// rate limiting to peer-IP keying and switching the
    /// X-Forwarded-Proto scheme detection off.
    #[test]
    fn apply_all_rejects_an_unparsable_trust_proxy_cidr() {
        let dir = temp_dir("cidr-bad");
        let path = write_minimal_config(&dir);
        let lang = test_lang();

        for field in ["server.trust_proxy_ips", "admin.trust_proxy_ips"] {
            let mut raw = HashMap::new();
            raw.insert(field.into(), "10.0.0.0/8\n10.0.0.0/33\nnot-a-cidr".into());

            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

            let message = collect_field(&errors, field).unwrap_or_else(|| {
                panic!("unparsable CIDRs in {field} must be refused, got {errors:?}")
            });
            assert!(
                message.contains("10.0.0.0/33"),
                "the error must name the offending entry: {message}"
            );
            assert!(
                !cfg.doc().to_string().contains("10.0.0.0/8"),
                "a refused list must not be written, not even its valid entries"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A trust list the panel accepts must survive save → reload →
    /// `parse_trusted_cidrs` unchanged, bare-IP entries included: that
    /// chain feeds the per-IP rate-limit keys and the https scheme
    /// detection after a restart, and the field hint advertises "one
    /// CIDR or IP per line".
    #[test]
    fn trust_proxy_cidrs_round_trip_through_the_canonical_loader() {
        use fumox_core::config::load_config;

        let dir = temp_dir("cidr-roundtrip");
        let path = write_minimal_config(&dir);
        let lang = test_lang();

        let mut raw = HashMap::new();
        raw.insert(
            "server.trust_proxy_ips".into(),
            "10.0.0.0/8\n192.168.1.1".into(),
        );
        raw.insert("admin.trust_proxy_ips".into(), " 2.2.2.2/32 ".into());

        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);
        assert!(
            errors.is_empty(),
            "valid CIDR lists must be accepted: {errors:?}"
        );
        cfg.save().unwrap();

        let loaded = load_config(Some(&path)).expect("the saved trust lists must load");
        assert_eq!(
            loaded.server.trust_proxy_ips,
            vec!["10.0.0.0/8", "192.168.1.1"]
        );
        assert_eq!(loaded.admin.trust_proxy_ips, vec!["2.2.2.2/32"]);
        assert_eq!(
            crate::admin::parse_trusted_cidrs(&loaded.server.trust_proxy_ips),
            vec![
                "10.0.0.0/8".parse().unwrap(),
                "192.168.1.1/32".parse().unwrap(),
            ]
        );
        assert_eq!(
            crate::admin::parse_trusted_cidrs(&loaded.admin.trust_proxy_ips),
            vec!["2.2.2.2/32".parse().unwrap()]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The admin token must never be rendered into the edit form
    /// (USERGUIDE: "The admin token is never shown."), and an empty
    /// submit must keep the current token (USERGUIDE: "sending the
    /// empty string keeps the current token … so the panel never
    /// silently disables itself") instead of erroring with
    /// `val.required`: a `""` written to the file would disable the
    /// panel at the next start.
    #[test]
    fn the_placeholder_token_is_rejected_by_the_edit_form() {
        use fumox_core::config::load_config;

        let dir = temp_dir("token-placeholder");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[admin]\ntoken = \"live-secret\"\n").unwrap();
        let lang = test_lang();

        let mut raw = HashMap::new();
        raw.insert("admin.token".into(), "change-me".into());
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert_eq!(
            errors.len(),
            1,
            "the placeholder must be refused: {errors:?}"
        );
        assert_eq!(errors[0].0, "admin.token");
        assert!(
            errors[0].1.contains("change-me"),
            "the error must name the placeholder: {}",
            errors[0].1
        );

        // The document keeps the token it had: the placeholder never
        // reaches the file.
        cfg.save().unwrap();
        let loaded = load_config(Some(&path)).expect("the kept token must load");
        assert_eq!(loaded.admin.token, "live-secret");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn admin_token_renders_empty_and_an_empty_submit_keeps_the_current_one() {
        use fumox_core::config::load_config;

        let mut live = AppConfig::default();
        live.admin.token = "live-secret".into();
        let raw = raw_from_config(&live);
        assert_eq!(
            raw.get("admin.token").map(String::as_str),
            Some(""),
            "the render must not carry the live token into the form"
        );

        let dir = temp_dir("token-keep");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[admin]\ntoken = \"live-secret\"\n").unwrap();
        let lang = test_lang();

        // Empty and whitespace-only submits are keep-current: no error,
        // the token on disk survives save → reload.
        for submitted in ["", "   "] {
            let mut raw = HashMap::new();
            raw.insert("admin.token".into(), submitted.into());
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);
            assert!(
                errors.is_empty(),
                "an empty token submit must keep the current token, not error: {errors:?}"
            );
            cfg.save().unwrap();
            let loaded = load_config(Some(&path)).expect("the kept token must load");
            assert_eq!(loaded.admin.token, "live-secret");
        }

        // A non-empty submit still rotates the token.
        let mut raw = HashMap::new();
        raw.insert("admin.token".into(), "  rotated-secret  ".into());
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);
        assert!(errors.is_empty(), "{errors:?}");
        cfg.save().unwrap();
        let loaded = load_config(Some(&path)).expect("the rotated token must load");
        assert_eq!(
            loaded.admin.token, "rotated-secret",
            "the submitted token is trimmed on write"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Count the `disabled` occurrences that sit inside the opening tag
    /// of a form control (`<input|select|button|textarea … >`). A
    /// whole-page substring count also matches the word in prose and in
    /// non-control markup, so the scan is scoped to the tags the
    /// attribute can actually disable.
    fn disabled_control_tags(html: &str) -> usize {
        ["input", "select", "button", "textarea"]
            .iter()
            .map(|tag| {
                let open = format!("<{tag}");
                let mut rest = html;
                let mut count = 0;
                while let Some(pos) = rest.find(&open) {
                    let after = &rest[pos + open.len()..];
                    let Some(end) = after.find('>') else { break };
                    if after[..end]
                        .split_whitespace()
                        .any(|attr| attr == "disabled")
                    {
                        count += 1;
                    }
                    rest = &after[end..];
                }
                count
            })
            .sum()
    }

    /// The edit page as rendered: the live token must not appear
    /// anywhere in the markup (the leak used to be the `value` attribute
    /// of the password input on every GET), and a not-writable config
    /// must disable the form controls (USERGUIDE: "every control is
    /// disabled") on top of the banner the page already showed. The
    /// template is built through the same `edit_template` constructor the
    /// handlers use, so the test renders exactly what a request renders.
    #[tokio::test]
    async fn settings_edit_renders_without_the_token_and_disables_fields_when_unwritable() {
        let admin = AdminConfig {
            token: "live-secret".into(),
            ..AdminConfig::default()
        };
        let (_dir, mut state) =
            crate::admin::test_admin_state(admin, ServerConfig::default()).await;
        let token = state.admin().token;
        assert!(!token.is_empty(), "the fixture needs a non-empty token");
        let headers = HeaderMap::new();

        // Not writable: the panes are wrapped in a disabled fieldset,
        // the submit button is disabled on its own, the token is still
        // absent, and the banner names the file.
        state.config_writable = false;
        let template = edit_template(
            &state,
            &headers,
            raw_from_config(&state.live()),
            Vec::new(),
            Some(Banner::Unwritable("/unwritable/app.toml".into())),
        );
        let html = template.render().unwrap();
        assert!(
            !html.contains(&token),
            "the live admin token must never appear in the edit form markup"
        );
        assert!(
            html.contains("<fieldset class=\"settings-panes\" disabled>"),
            "a read-only config must disable the whole form: {html}"
        );
        assert!(
            html.contains("<button class=\"btn primary\" type=\"submit\" disabled>"),
            "a read-only config must disable the submit button: {html}"
        );
        assert!(
            html.contains("/unwritable/app.toml"),
            "the banner must name the file it cannot write: {html:.400}"
        );
        assert!(
            html.contains("<div class=\"flash error\" role=\"alert\">"),
            "the banner must be announced as an alert: {html:.400}"
        );

        // Writable: nothing disabled, token still absent, no banner.
        state.config_writable = true;
        let template = edit_template(
            &state,
            &headers,
            raw_from_config(&state.live()),
            Vec::new(),
            None,
        );
        let html = template.render().unwrap();
        assert!(
            !html.contains(&token),
            "the live admin token must never appear in the edit form markup"
        );
        assert!(
            !html.contains("/unwritable/app.toml"),
            "a writable config must not show the unwritable banner: {html:.400}"
        );
        assert_eq!(
            disabled_control_tags(&html),
            0,
            "a writable config must leave every control editable (the scan \
             looks for the raw ` disabled` substring inside control opening \
             tags across the whole page)"
        );
    }

    /// USERGUIDE promises that on a not-writable config "the same banner
    /// appears on the overview" (a first-class deployment mode via
    /// `FUMOX_CONFIG_ACCESS=ro`). Render the real overview template for
    /// both states so the promise cannot regress silently again. The view
    /// model comes from the shared [`SettingsView::from_state`] the
    /// handler itself uses, the banner text is compared in the escaped
    /// form askama renders (a path with a markup character must be found
    /// the way the page prints it), and the banner must sit in a
    /// `role="alert"` container, not plain text.
    #[tokio::test]
    async fn settings_overview_shows_the_unwritable_banner() {
        let lang = test_lang();
        for (writable, path) in [
            (false, "/tmp/fumox-overview/app.toml".to_string()),
            // A path with a markup character: the page may only show it
            // escaped (`&` renders as askama's numeric reference).
            (false, "/tmp/a&b/app.toml".to_string()),
            (true, "/tmp/fumox-overview/app.toml".to_string()),
        ] {
            let admin = AdminConfig {
                token: "live-secret".into(),
                ..AdminConfig::default()
            };
            let (_dir, mut state) =
                crate::admin::test_admin_state(admin, ServerConfig::default()).await;
            state.config_path = ResolvedConfigPath::Loaded(PathBuf::from(&path));
            state.config_writable = writable;

            let template = SettingsTemplate {
                lang: lang.clone(),
                langs: Vec::new(),
                theme: theme::from_headers(&HeaderMap::new()),
                active: "settings",
                csrf: String::new(),
                state: SettingsView::from_state(&state),
            };
            let html = template.render().unwrap();
            let banner = lang.t_named("set.edit_unwritable", &[("path", path.clone())]);
            let escaped_banner = crate::admin::askama_html_escape(&banner);
            assert_eq!(
                html.contains(&escaped_banner),
                !writable,
                "writable={writable} path={path}: the not-writable banner must {}appear on the overview",
                if !writable { "" } else { "not " }
            );
            if !writable {
                assert!(
                    html.contains("<div class=\"flash error\" role=\"alert\">"),
                    "the banner must render inside a role=alert container: {html:.400}"
                );
                // The escaped path itself, independent of the catalog
                // wording: `&` reaches the page only as its escaped form.
                let escaped_path = crate::admin::askama_html_escape(&path);
                assert!(
                    html.contains(&escaped_path),
                    "the path must be escaped the way askama escapes it: {html:.400}"
                );
            }
        }
    }

    /// An empty test-URL list leaves the probe without an endpoint, and
    /// the file is written verbatim: the next start of both binaries
    /// would abort on it. The editor refuses it behind a field error
    /// instead of writing an empty array behind a success toast.
    #[test]
    fn apply_all_refuses_an_empty_test_url_list() {
        let dir = temp_dir("empty-test-url");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("meow.test_url".into(), "  \n \n".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert_eq!(
            collect_field(&errors, "meow.test_url"),
            Some("must not be empty"),
            "actual: {errors:?}"
        );
        assert!(
            !cfg.doc().to_string().contains("test_url"),
            "the empty list must not reach the document: {}",
            cfg.doc()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The loader refuses an entry that is not an absolute http(s) URL,
    /// and the panel writes the file verbatim: an entry the loader would
    /// refuse would abort the next start of both binaries.
    #[test]
    fn apply_all_refuses_a_test_url_the_loader_would_reject() {
        for (entry, expected) in [
            (
                "ftp://example.com/generate_204",
                "only http/https URLs are supported, got 'ftp'",
            ),
            (
                "file:///etc/passwd",
                "only http/https URLs are supported, got 'file'",
            ),
            ("not a url", "invalid URL: "),
            ("http://", "invalid URL: "),
        ] {
            let dir = temp_dir("bad-test-url");
            let path = write_minimal_config(&dir);

            let mut raw = HashMap::new();
            raw.insert("meow.test_url".into(), entry.into());

            let lang = test_lang();
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

            let message = collect_field(&errors, "meow.test_url").unwrap_or_default();
            assert!(
                message.starts_with(expected),
                "entry {entry}: unexpected message {message:?}"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// The probe dials the test URL through the tunnel, so a private
    /// address is refused by the same SSRF policy that guards the feed
    /// targets — unless the operator turned that guard off.
    #[test]
    fn apply_all_refuses_a_private_test_url_while_the_probe_guard_is_on() {
        let dir = temp_dir("private-test-url");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert(
            "meow.test_url".into(),
            "http://127.0.0.1/generate_204".into(),
        );

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        let message = collect_field(&errors, "meow.test_url").unwrap_or_default();
        assert!(
            message.starts_with("SSRF protection: "),
            "unexpected message {message:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_accepts_a_private_test_url_when_the_probe_guard_is_off() {
        let dir = temp_dir("private-test-url-off");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("probe.allow_private_targets".into(), "on".into());
        raw.insert(
            "meow.test_url".into(),
            "http://127.0.0.1/generate_204".into(),
        );

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        assert!(
            cfg.doc()
                .to_string()
                .contains("http://127.0.0.1/generate_204"),
            "the entry must reach the document"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_writes_the_test_urls_verbatim() {
        let dir = temp_dir("test-url-write");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert(
            "meow.test_url".into(),
            "http://cp.cloudflare.com/generate_204\nhttps://www.gstatic.com/generate_204".into(),
        );

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        let serialized = cfg.doc().to_string();
        assert!(
            serialized.contains("http://cp.cloudflare.com/generate_204"),
            "{serialized}"
        );
        assert!(
            serialized.contains("https://www.gstatic.com/generate_204"),
            "{serialized}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A save whose live refresh failed must reach the operator: the file
    /// on disk carries the new configuration, the running process keeps
    /// the old one until the next restart. A green "saved" toast would
    /// hide that.
    #[test]
    fn a_failed_live_refresh_is_reported_with_an_error() {
        let lang = test_lang();
        let err = fumox_core::Error::Config("meow.test_url entry 'x' is not a valid URL".into());

        let response =
            settings_refresh_failed(&lang, &HeaderMap::new(), "/etc/fumox/app.toml", &err);

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        // The message rides in a header, the redirect target stays clean.
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .expect("a redirect")
                .to_str()
                .unwrap(),
            "/admin/settings"
        );
        assert_eq!(
            response
                .headers()
                .get(crate::admin::flash::FLASH_LEVEL_HEADER)
                .expect("the toast must carry a level")
                .to_str()
                .unwrap(),
            "error",
            "the toast must be an error"
        );
        let message = percent_encoding::percent_decode_str(
            response
                .headers()
                .get(crate::admin::flash::FLASH_HEADER)
                .expect("the toast must carry a message")
                .to_str()
                .unwrap(),
        )
        .decode_utf8_lossy()
        .to_string();
        assert!(
            message.contains("/etc/fumox/app.toml"),
            "the message must name the file: {message}"
        );
        assert!(
            message.contains("is not a valid URL"),
            "the message must carry the reason: {message}"
        );
    }

    /// A field the environment overrides cannot be changed through the
    /// file: the env layer wins, so a value written here would be inert
    /// and the operator would be shown a change that does not happen.
    #[test]
    fn an_env_locked_field_is_not_written_back() {
        let dir = temp_dir("env-locked");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[ingest]\ndrop_gate = false\n").unwrap();

        let raw = HashMap::from([("ingest.drop_gate".to_string(), "on".to_string())]);
        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(
            &raw,
            &mut cfg,
            &lang,
            &mut errors,
            &["ingest.drop_gate".to_string()],
        );

        assert!(
            errors.is_empty(),
            "a locked field is not an error: {errors:?}"
        );
        assert!(
            cfg.doc().to_string().contains("drop_gate = false"),
            "the locked field must keep the file's value"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The lock is on the config path, while the form carries the
    /// halves of the rate-limit pair. A lock on the path must cover
    /// both halves, or the operator could write the half the
    /// environment does not shadow.
    #[test]
    fn an_env_lock_covers_the_halves_of_a_rate_limit_pair() {
        let locked = vec!["server.rate_limit".to_string()];
        assert!(is_env_locked("server.rate_limit", &locked));
        assert!(is_env_locked("server.rate_limit.limit", &locked));
        assert!(is_env_locked("server.rate_limit.unit", &locked));
        assert!(!is_env_locked("server.auth_fail_rate_limit", &locked));
        assert!(!is_env_locked("ingest.drop_gate", &locked));
    }

    /// A form that lost half of a rate-limit pair is not a form the
    /// operator meant to send: the submit is refused and the file is
    /// left byte-identical.
    #[test]
    fn a_partial_rate_limit_pair_is_refused_and_the_file_stays_untouched() {
        let dir = temp_dir("half-pair");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nrate_limit = \"120/min\"\n").unwrap();
        let before = std::fs::read(&path).unwrap();

        let raw = HashMap::from([("server.rate_limit.limit".to_string(), "60".to_string())]);
        let outcome = save_settings(path.clone(), raw, test_lang(), Vec::new());

        let SaveOutcome::Invalid(errors) = outcome else {
            panic!("a half-filled pair must be refused");
        };
        assert!(
            collect_field(&errors, "server.rate_limit.unit").is_some(),
            "the missing half must carry the error: {errors:?}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a refused save must leave the file byte-identical"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The same, with the other half of the pair missing.
    #[test]
    fn a_partial_rate_limit_pair_without_the_limit_is_refused() {
        let dir = temp_dir("half-pair-unit");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[server]\nrate_limit = \"120/min\"\n").unwrap();
        let before = std::fs::read(&path).unwrap();

        let raw = HashMap::from([("server.rate_limit.unit".to_string(), "min".to_string())]);
        let outcome = save_settings(path.clone(), raw, test_lang(), Vec::new());

        let SaveOutcome::Invalid(errors) = outcome else {
            panic!("a half-filled pair must be refused");
        };
        assert!(
            collect_field(&errors, "server.rate_limit.limit").is_some(),
            "the missing half must carry the error: {errors:?}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a refused save must leave the file byte-identical"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A checkbox the browser did not post must not reset the setting:
    /// writing `false` for it would change a value nobody touched.
    #[test]
    fn a_bool_the_form_did_not_carry_is_not_reset() {
        let dir = temp_dir("bool-absent");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[ingest]\ndrop_gate = true\n").unwrap();

        let raw = HashMap::from([("probe.fail_limit".to_string(), "5".to_string())]);
        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors, &[]);

        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        assert!(
            cfg.doc().to_string().contains("drop_gate = true"),
            "a checkbox that was not posted must keep its value"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The form is the view of the FILE: the panel writes the file, so
    /// the operator has to see what the file says, not what the
    /// environment layered on top of it.
    #[test]
    fn the_form_shows_the_file_and_not_the_environment() {
        let dir = temp_dir("file-view");
        let path = dir.join("app.toml");
        std::fs::write(&path, "[ingest]\ndrop_gate = true\n").unwrap();

        let raw = raw_from_file(&path).unwrap().expect("the file is there");
        assert_eq!(
            raw.get("ingest.drop_gate").map(String::as_str),
            Some("on"),
            "the form must show the file's own value"
        );

        // A missing file is not an error: the operator creates it from
        // the defaults.
        let missing = dir.join("absent.toml");
        assert!(
            raw_from_file(&missing).unwrap().is_none(),
            "a missing file must not be an error"
        );

        // A file that cannot be parsed names the reason.
        let broken = dir.join("broken.toml");
        std::fs::write(&broken, "[ingest\ndrop_gate = true\n").unwrap();
        assert!(
            raw_from_file(&broken).is_err(),
            "a broken file must report the reason"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The audit outcome names the keys the submit wrote, in registry
    /// order, with the environment-locked ones left out: they are not
    /// written, and the log must not claim they were.
    #[test]
    fn the_save_outcome_names_the_written_keys() {
        let dir = temp_dir("audit-keys");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("probe.fail_limit".into(), "5".into());
        raw.insert("server.rate_limit.limit".into(), "120".into());
        raw.insert("server.rate_limit.unit".into(), "min".into());

        let outcome = save_settings(path.clone(), raw, test_lang(), Vec::new());
        let SaveOutcome::Saved { written_keys, .. } = outcome else {
            panic!("the save must succeed");
        };
        assert_eq!(
            written_keys,
            vec!["server.rate_limit", "probe.fail_limit"],
            "registry order, rate-limit pair spelled by its row key"
        );

        // A key the environment overrides is not written: the env layer
        // wins over the file, so naming it would be a lie.
        let raw = HashMap::from([("admin.token".to_string(), "new-token".to_string())]);
        let outcome = save_settings(path, raw, test_lang(), vec![KEY_ADMIN_TOKEN.to_string()]);
        let SaveOutcome::Saved { written_keys, .. } = outcome else {
            panic!("the locked-key save must succeed");
        };
        assert!(
            written_keys.is_empty(),
            "a locked key must not be reported as written: {written_keys:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A token rotation is not a plain save: the toast says that every
    /// session was ended and the operator has to sign in again.
    #[test]
    fn a_token_rotation_answers_with_a_sign_in_again_toast() {
        let lang = test_lang();

        let (message, level) = save_toast(&lang, "/etc/fumox/app.toml", &[], true);
        assert_eq!(level, "warning");
        assert!(
            message.contains("/etc/fumox/app.toml"),
            "the message must name the file: {message}"
        );
        let expected = lang.t_named(
            "set.edit_token_rotated_toast",
            &[("path", "/etc/fumox/app.toml".to_string())],
        );
        assert_eq!(message, expected);
        // The rotation wording is distinct from the plain saved toast.
        assert_ne!(
            message,
            lang.t_named(
                "set.edit_saved_toast",
                &[("path", "/etc/fumox/app.toml".to_string())]
            )
        );
    }

    /// A save the environment overrules must not claim a plain success:
    /// the operator has to learn that the value they changed is not the
    /// one in force.
    #[test]
    fn a_save_the_environment_overrules_is_not_reported_as_a_success() {
        let lang = test_lang();

        let (message, level) = save_toast(&lang, "/etc/fumox/app.toml", &[], false);
        assert_eq!(level, "ok");
        assert!(
            message.contains("/etc/fumox/app.toml"),
            "the message must name the file: {message}"
        );

        let (message, level) = save_toast(
            &lang,
            "/etc/fumox/app.toml",
            &["ingest.drop_gate".to_string()],
            false,
        );
        assert_eq!(level, "ok");
        assert!(
            message.contains("ingest.drop_gate"),
            "the message must name the overridden setting: {message}"
        );

        // The token is the sharpest case: the panel runs under the
        // environment's token whatever the file says, so a green toast
        // would claim a rotation that did not happen.
        let (message, level) = save_toast(
            &lang,
            "/etc/fumox/app.toml",
            &["admin.token".to_string()],
            false,
        );
        assert_eq!(level, "error");
        assert!(
            message.contains("admin.token") || message.contains("FUMOX_ADMIN__TOKEN"),
            "the message must name the token override: {message}"
        );
    }

    /// A field the environment overrides must be rendered read-only,
    /// and the operator must be told why: a disabled control without a
    /// reason reads as a bug.
    #[tokio::test]
    async fn an_env_locked_field_renders_read_only_with_a_reason() {
        let admin = AdminConfig {
            token: "live-secret".into(),
            ..AdminConfig::default()
        };
        let (_dir, mut state) =
            crate::admin::test_admin_state(admin, ServerConfig::default()).await;
        state.config_writable = true;

        let template = SettingsEditTemplate {
            langs: Vec::new(),
            theme: theme::from_headers(&HeaderMap::new()),
            lang: test_lang(),
            active: "settings",
            csrf: String::new(),
            config_path: state.config_path.clone(),
            config_writable: state.config_writable,
            raw: raw_from_config(&state.live()),
            errors: Vec::new(),
            banner: None,
            fingerprint: String::new(),
            env_locked: vec!["ingest.drop_gate".to_string()],
        };
        let html = template.render().unwrap();

        // The control of the locked field carries the attribute, and
        // the hidden mirror next to it does too: a mirror that stayed
        // enabled would post the field and defeat the lock.
        assert!(
            html.contains(r#"<input type="checkbox" name="ingest.drop_gate" value="on" id="ingest-drop" checked disabled>"#),
            "the locked checkbox must be disabled: {html}"
        );
        assert!(
            html.contains(r#"<input type="hidden" name="ingest.drop_gate" value="off" disabled>"#),
            "the hidden mirror of the locked checkbox must be disabled: {html}"
        );
        // A field that is not locked stays editable.
        assert!(
            html.contains(r#"<input type="checkbox" name="ingest.removed_as_unknown" value="on" id="ingest-removed" >"#)
                || html.contains(r#"name="ingest.removed_as_unknown" value="on" id="ingest-removed""#),
            "an unlocked field must stay editable: {html}"
        );
        // The reason is on the page.
        let lang = test_lang();
        let hint = lang.t_named(
            "set.env_locked_hint",
            &[("fields", "ingest.drop_gate".to_string())],
        );
        assert!(
            html.contains(&hint),
            "the page must name the locked field: {html:.400}"
        );
    }
}
