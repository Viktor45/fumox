//! Settings overview + edit page.
//!
//! The overview (`GET /admin/settings`) is read-only and shows the
//! effective configuration grouped by owning process (server / probe /
//! shared). The edit page (`GET /admin/settings/edit`) is a form that
//! round-trips the on-disk TOML through `toml_edit`, preserving every
//! existing comment. Saving (`POST /admin/settings/update`) writes the
//! file atomically and tells the operator to restart both server and
//! probe for the changes to apply. A *Create from defaults* button on
//! the overview (`POST /admin/settings/create`) bootstraps a missing
//! `config/app.toml` from the embedded reference copy.

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
    AdminConfig, AppConfig, DEFAULT_CONFIG_PATH, DatabaseConfig, FetchConfig, GeoConfig,
    IngestConfig, LogConfig, MeowConfig, ProbeConfig, RateLimit, ResolvedConfigPath,
    RetentionConfig, ServerConfig, bounds,
};
use fumox_core::config_writer::{ConfigItem, EditableConfig, item};
use fumox_core::models::IpFamily;

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
            admin: state.admin(),
            probe: state.probe(),
            meow: state.meow(),
            retention: state.retention(),
            log: state.log(),
            config_path: state.config_path.clone(),
            config_writable: state.config_writable,
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
        match &self.state.config_path {
            ResolvedConfigPath::Loaded(p) => p.display().to_string(),
            ResolvedConfigPath::Missing => DEFAULT_CONFIG_PATH.to_string(),
        }
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
    render_html(template.lang.clone(), &template, StatusCode::OK)
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
    state: AdminState,
    /// Raw form values keyed by `<section>.<field>`. Booleans carry the
    /// checkbox literals: `"on"`, `"off"` (hidden input) or absent.
    raw: HashMap<String, String>,
    /// `(field, message)` pairs produced by the validator.
    errors: Vec<(String, String)>,
    /// Top-level banner (no config file, file not writable, …).
    banner: Option<Banner>,
}

#[derive(Clone)]
enum Banner {
    Unwritable(String),
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

    /// `min` for a number input, straight from the bounds table. An
    /// unbounded setting renders an empty attribute rather than a
    /// fabricated `0`.
    fn range_min(&self, field: &str) -> String {
        bounds::min_attr(field)
    }

    /// `max` for a number input, empty when the setting is unbounded.
    fn range_max(&self, field: &str) -> String {
        bounds::max_attr(field)
    }

    /// The range as the operator reads it, shown under the input. It is
    /// the same value the save handler enforces, so the number in the
    /// hint and the number in the error cannot drift apart.
    fn range_text(&self, field: &str) -> Option<String> {
        bounds::display(field, self.lang.t("set.range_open_ended"))
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
        editing_target(&self.state).display().to_string()
    }

    fn banner_html(&self) -> Option<String> {
        let Banner::Unwritable(path) = self.banner.as_ref()?;
        Some(
            self.lang
                .t_named("set.edit_unwritable", &[("path", path.clone())]),
        )
    }

    /// `disabled` attribute carried by every visible control on the
    /// form when the config file is not writable. USERGUIDE promises
    /// "every control is disabled" for a read-only deployment; the save
    /// path refuses the POST anyway (`settings_edit_unwritable`), so
    /// the form must not invite edits it cannot keep. The hidden
    /// `value="off"` inputs and the CSS-only tab radios stay enabled:
    /// they carry no setting (the hidden pair only mirrors its
    /// checkbox) or are navigation, and a disabled radio would freeze
    /// the pane view instead of just the edits.
    fn fields_disabled(&self) -> &'static str {
        if self.state.config_writable {
            ""
        } else {
            " disabled"
        }
    }
}

impl_i18n!(SettingsEditTemplate, errors);

/// Path that the editor writes to, deriving a default when no file was
/// loaded at startup. Used by `settings_create` to know where to drop
/// the embedded reference copy.
fn editing_target(state: &AdminState) -> PathBuf {
    match &state.config_path {
        ResolvedConfigPath::Loaded(p) => p.clone(),
        ResolvedConfigPath::Missing => PathBuf::from(DEFAULT_CONFIG_PATH),
    }
}

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
    /// Dotted config key — also the form field name and the
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
const LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];

/// The closed set `IpFamily` deserializes; same contract as
/// [`LOG_LEVELS`], the strings are also what [`ip_family_str`] renders.
const IP_FAMILIES: &[&str] = &["any", "ipv4", "ipv6"];

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
            raw.insert(key.into(), ip_family_str(c.fetch.ip_family).into());
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
        apply: |raw, key, cfg, _lang, errors| bool_field(raw, key, cfg, errors),
    },
    Setting {
        key: "ingest.removed_as_unknown",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.ingest.removed_as_unknown));
        },
        apply: |raw, key, cfg, _lang, errors| bool_field(raw, key, cfg, errors),
    },
    // --- geo ---
    Setting {
        key: "geo.enabled",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.geo.enabled));
        },
        apply: |raw, key, cfg, _lang, errors| bool_field(raw, key, cfg, errors),
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
        key: "geo.dns_timeout_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.geo.dns_timeout_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    // --- admin ---
    Setting {
        key: "admin.enabled",
        render: |c, key, raw| {
            raw.insert(key.into(), bool_to_raw(c.admin.enabled));
        },
        apply: |raw, key, cfg, _lang, errors| bool_field(raw, key, cfg, errors),
    },
    Setting {
        key: "admin.bind",
        render: |c, key, raw| {
            raw.insert(key.into(), c.admin.bind.to_string());
        },
        apply: |raw, key, cfg, lang, errors| bind(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "admin.token",
        // The live token must never reach the markup (USERGUIDE: "The
        // admin token is never shown."): the field renders empty and an
        // empty submit keeps the current token (`token_field`). The key
        // still has to be present — `the_registry_covers_every_rendered_key`
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
        apply: |raw, key, cfg, _lang, errors| bool_field(raw, key, cfg, errors),
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
        apply: |raw, key, cfg, _lang, errors| bool_field(raw, key, cfg, errors),
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
        apply: |raw, key, cfg, _lang, errors| bool_field(raw, key, cfg, errors),
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
        apply: |raw, key, cfg, lang, errors| string_list(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "meow.timeout_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.meow.timeout_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "meow.backoff_initial_secs",
        render: |c, key, raw| {
            raw.insert(key.into(), c.meow.backoff_initial_secs.to_string());
        },
        apply: |raw, key, cfg, lang, errors| u64_field(raw, key, cfg, lang, errors),
    },
    Setting {
        key: "meow.backoff_max_secs",
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
        apply: |raw, key, cfg, _lang, errors| bool_field(raw, key, cfg, errors),
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
/// when true, absent otherwise; enums become their short name.
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
    raw.insert(
        format!("{prefix}.unit"),
        match rl.window.as_secs() {
            1..=59 => "sec".to_string(),
            60..=3599 => "min".to_string(),
            3600..=86399 => "hour".to_string(),
            _ => "day".to_string(),
        },
    );
}

/// The raw-map render of a stored boolean; [`SettingsEditTemplate::bool_value`] reads it back.
fn bool_to_raw(b: bool) -> String {
    if b { "on".to_string() } else { String::new() }
}

fn ip_family_str(f: IpFamily) -> &'static str {
    match f {
        IpFamily::Any => "any",
        // These strings are the SAME ones `IpFamily::from_str` accepts on
        // startup (crates/fumox-core/src/models.rs). If they ever drift,
        // admin saves silently revert on the next restart because the
        // parser falls back to the default. Keep them locked together ,
        // `apply_all_ip_family_round_trip` in this file proves the pair.
        IpFamily::Ipv4 => "ipv4",
        IpFamily::Ipv6 => "ipv6",
    }
}

pub async fn settings_edit(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);

    // Reload the file on every GET so the form reflects the last save
    // (the in-memory `state.config` is frozen at startup and would lag
    // behind every admin write). ENV overrides still win, `AppConfig::load`
    // merges them on top of the file.
    let target = editing_target(&state);
    let raw = match fumox_core::config::load(Some(&target)) {
        Ok(loaded) => raw_from_config(&loaded.config),
        // The unwritable / load-error fallback: the file on disk is not
        // an option, so the form renders the live in-memory view instead.
        Err(_) => raw_from_config(&state.live()),
    };

    let banner = if !state.config_writable {
        Some(Banner::Unwritable(target.display().to_string()))
    } else {
        None
    };
    let template = SettingsEditTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(&headers),
        lang,
        active: "settings",
        csrf: state.csrf_for(&headers),
        state: state.clone(),
        raw,
        errors: Vec::new(),
        banner,
    };
    render_html(template.lang.clone(), &template, StatusCode::OK)
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

    // Build a fresh `EditableConfig` so we can fail-and-replay the form
    // before touching disk. The validator only reads `raw` and the
    // language catalog, no side effects. The editor holds the
    // process-wide config lock, so it is confined to this block: its
    // guard must not ride across the awaits below.
    let path = {
        let mut cfg = match EditableConfig::load(&editing_target(&state)) {
            Ok(c) => c,
            Err(err) => return settings_edit_load_error(&state, &headers, err.to_string()),
        };

        let mut errors: Vec<(String, String)> = Vec::new();
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        if !errors.is_empty() {
            let template = SettingsEditTemplate {
                langs: state.locales.choices().to_vec(),
                theme: theme::from_headers(&headers),
                lang: lang.clone(),
                active: "settings",
                csrf: state.csrf_for(&headers),
                state: state.clone(),
                raw,
                errors,
                banner: None,
            };
            return render_html(
                template.lang.clone(),
                &template,
                StatusCode::UNPROCESSABLE_ENTITY,
            );
        }

        // Persist atomically. On a backend that rejects `rename` (NFS / SMB),
        // `save()` falls back to a direct write with a tracing warning.
        if let Err(err) = cfg.save() {
            tracing::error!(error = %err, path = %cfg.path().display(), "failed to save settings");
            let template = SettingsEditTemplate {
                langs: state.locales.choices().to_vec(),
                theme: theme::from_headers(&headers),
                lang: lang.clone(),
                active: "settings",
                csrf: state.csrf_for(&headers),
                state: state.clone(),
                raw,
                errors: vec![(
                    "".into(),
                    lang.t_args("err.internal", &[format!("save: {err}")]),
                )],
                banner: None,
            };
            return render_html(
                template.lang.clone(),
                &template,
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }

        cfg.path().display().to_string()
    };

    tracing::info!(path = %path, "settings saved");

    // A token rotation through this form must also revoke the sessions
    // minted under the old token: the session key is derived from the
    // token at startup and stays frozen (`AdminState::session_key`), so
    // without an epoch bump a stolen cookie keeps authenticating until
    // the next restart. The comparison runs before `refresh_live_config`
    // swaps the new token into the live config, and only on an actual
    // change — an unconditional bump would log out the very session
    // performing an unrelated save. An empty submit is NOT a change:
    // `token_field` reads it as "keep the current token", so treating
    // it as a rotation would log the operator out of every unrelated
    // save (the field renders empty and untouched fields submit empty).
    let submitted_token = raw
        .get("admin.token")
        .map(String::as_str)
        .unwrap_or_default()
        .trim();
    if !submitted_token.is_empty() && submitted_token != state.admin().token {
        crate::admin::auth::revoke_all_sessions(&state.pool).await;
    }

    // Refresh the figment-merged in-memory view so the next request to
    // /admin/settings — and every handler reading the live config —
    // renders the values the operator just wrote, instead of the startup
    // snapshot. ENV overrides are re-applied by `config::load` itself, so
    // `FUMOX_*` env vars keep winning on top of the file.
    if let Err(err) = state.refresh_live_config(Path::new(&path)) {
        tracing::warn!(error = %err, path = %path, "live config refresh skipped");
    }

    let toast = lang.t_named("set.edit_saved_toast", &[("path", path)]);
    if headers.get("HX-Request").is_some() {
        return htmx_redirect_with_toast("/admin/settings", &toast);
    }
    super::flash_redirect("/admin/settings", &toast, "ok")
}

fn htmx_redirect_with_toast(redirect_to: &str, toast: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (
                HeaderName::from_static("hx-redirect"),
                HeaderValue::from_str(redirect_to).expect("static settings path"),
            ),
            (
                HeaderName::from_static("hx-trigger"),
                super::toast_trigger("ok", toast),
            ),
        ],
    )
        .into_response()
}

fn settings_edit_unwritable(state: &AdminState, headers: &HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(headers);
    let template = SettingsEditTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(headers),
        lang,
        active: "settings",
        csrf: state.csrf_for(headers),
        state: state.clone(),
        raw: raw_from_config(&state.live()),
        errors: Vec::new(),
        banner: Some(Banner::Unwritable(
            editing_target(state).display().to_string(),
        )),
    };
    render_html(
        template.lang.clone(),
        &template,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
}

fn settings_edit_load_error(state: &AdminState, headers: &HeaderMap, message: String) -> Response {
    let lang = state.locales.lang_from_headers(headers);
    let internal = lang.t("err.internal").to_string();
    let template = SettingsEditTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(headers),
        lang: lang.clone(),
        active: "settings",
        csrf: state.csrf_for(headers),
        state: state.clone(),
        raw: raw_from_config(&state.live()),
        errors: vec![("".into(), format!("{internal}: {message}"))],
        banner: None,
    };
    render_html(
        template.lang.clone(),
        &template,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

/// Create `config/app.toml` from the embedded reference copy when it is
/// missing. No-op when the file already exists, so a retry from a stale
/// tab is harmless.
pub async fn settings_create(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let target = editing_target(&state);

    if target.exists() {
        return redirect_after_create(lang.t("set.file_created_noop").to_string());
    }

    if !fumox_core::config_writer::is_writable(target.parent().unwrap_or(Path::new("."))) {
        return settings_edit_unwritable(&state, &headers);
    }

    if let Err(err) = std::fs::write(&target, fumox_core::config_writer::REFERENCE_CONFIG) {
        tracing::error!(error = %err, path = %target.display(), "failed to write reference config");
        return settings_edit_load_error(&state, &headers, err.to_string());
    }

    // The file was just materialised from the embedded reference copy;
    // pull the freshly-merged view into the in-memory cache so the next
    // GET to /admin/settings/edit (and the *Settings* overview) renders
    // every default rather than the empty startup snapshot.
    if let Err(err) = state.refresh_live_config(&target) {
        tracing::warn!(error = %err, path = %target.display(), "live config refresh after create skipped");
    }

    let path = target.display().to_string();
    let msg = lang.t_named("set.file_created_toast", &[("path", path)]);
    redirect_after_create(msg)
}

fn redirect_after_create(toast: String) -> Response {
    super::flash_redirect("/admin/settings/edit", &toast, "ok")
}

// Validation / application.

/// Walk every registered setting and apply the ones the form carried.
/// Each field is parsed in isolation, errors accumulate without
/// short-circuiting so the operator sees every problem on a single
/// submit.
fn apply_all(
    raw: &HashMap<String, String>,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    for setting in SETTINGS {
        (setting.apply)(raw, setting.key, cfg, lang, errors);
    }

    // Cross-field checks the serde model cannot express.
    let max = raw
        .get("meow.backoff_max_secs")
        .and_then(|s| s.parse::<u64>().ok());
    let min = raw
        .get("meow.backoff_initial_secs")
        .and_then(|s| s.parse::<u64>().ok());
    if let (Some(min), Some(max)) = (min, max)
        && max < min
    {
        errors.push((
            "meow.backoff_max_secs".into(),
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
/// written.
fn set_field(
    cfg: &mut EditableConfig,
    field: &str,
    value: ConfigItem,
    errors: &mut Vec<(String, String)>,
) {
    if let Err(err) = cfg.set(field, value) {
        errors.push((field.into(), err.to_string()));
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
            set_field(cfg, field, item::string(addr.to_string()), errors);
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
    set_field(cfg, field, item::string(v.to_string()), errors);
}

/// The admin token. An empty submit keeps the current token — the
/// documented contract (USERGUIDE: "sending the empty string keeps the
/// current token … so the panel never silently disables itself") — and
/// it is also what an untouched field submits, because the render never
/// puts the live token into the form (see the `admin.token` render).
/// `string_field` would refuse an empty submit with `val.required`,
/// and a value of `""` written to the file would disable the panel at
/// the next start.
fn token_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    _lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    if v.is_empty() {
        // Keep-current: nothing is written, the document keeps the
        // token it loaded from disk.
        return;
    }
    set_field(cfg, field, item::string(v.to_string()), errors);
}

/// The error text for a value outside its setting's range. Reads the
/// bound from [`bounds`] by the field name, so a numeric setting cannot
/// be enforced against one range and advertised with another.
fn out_of_range(field: &str, value: u64, lang: &Lang) -> String {
    let Some(range) = bounds::range_of(field) else {
        // A numeric field with no entry in the table is a wiring bug,
        // not a user error. Say so instead of blaming the input.
        return format!("{field} has no configured range");
    };
    match range.max {
        Some(max) => lang.t_args("val.in_range", &[range.min.to_string(), max.to_string()]),
        None => lang.t_args("val.at_least", &[range.min.to_string(), value.to_string()]),
    }
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
        errors.push((field.into(), out_of_range(field, parsed, lang)));
        return;
    }
    // `item::integer` stores an `i64`, so a larger `u64` wraps negative
    // on the write and the saved config fails to load at the next start.
    if parsed > i64::MAX as u64 {
        errors.push((field.into(), format!("must be at most {}", i64::MAX)));
        return;
    }
    set_field(cfg, field, item::integer(parsed as i64), errors);
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
        errors.push((field.into(), out_of_range(field, u64::from(parsed), lang)));
        return;
    }
    set_field(cfg, field, item::integer(i64::from(parsed)), errors);
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
        errors.push((field.into(), out_of_range(field, parsed as u64, lang)));
        return;
    }
    set_field(cfg, field, item::integer(parsed as i64), errors);
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
    errors: &mut Vec<(String, String)>,
) {
    // Booleans default to `false` when the checkbox was absent, the
    // browser drops unchecked checkboxes from the form submission.
    let v = raw_get(raw, field).unwrap_or("");
    let Some(b) = parse_bool_literal(v) else {
        errors.push((field.into(), format!("unexpected bool literal: {v}")));
        return;
    };
    set_field(cfg, field, item::boolean(b), errors);
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
    set_field(cfg, field, item::string(v.to_string()), errors);
}

fn string_list(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    _lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let items: Vec<String> = v
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    set_field(cfg, field, item::string_array(items), errors);
}

/// The trusted reverse-proxy lists (`server.trust_proxy_ips`,
/// `admin.trust_proxy_ips`), validated with the same parser
/// `crate::admin::parse_trusted_cidrs` applies at startup (and which
/// feeds both per-IP rate limiters and the X-Forwarded-Proto scheme
/// detection). The startup parser logs and DROPS an unparsable entry —
/// fail-closed — so an entry it would drop must be refused here behind
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
    _lang: &Lang,
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
            // No catalog key names a CIDR, and the locales are not this
            // file's to extend, so the sentence is written out here —
            // the same escape `i64_list_field` takes for the ladder
            // length and `bool_field` for an unexpected literal.
            errors.push((field.into(), format!("not a valid CIDR or IP: {entry}")));
            return;
        }
    }
    set_field(cfg, field, item::string_array(items), errors);
}

/// One integer per line, bounded the way the canonical loader bounds the
/// field it writes: at most `max_items` entries, each within `min..=max`.
/// The admin panel writes the file verbatim and the next start of both
/// binaries aborts on anything `fumox_core::config` refuses, so a bound
/// the loader does not share would turn a green toast into a dead server.
///
/// An empty list is refused even though the loader accepts one: for the
/// only field using this helper today, the recheck ladder, `[]` means
/// «remove the proxy right after the failed second chance», and the field
/// hint never says so: silently emptying the textarea would disable the
/// quarantine ladder behind a success toast. An operator who wants that
/// configures the file directly.
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
    // bound that the very same check accepts `max_items` of. No catalog
    // key names a list length, and the locales are not this file's to
    // extend, so the sentence is written out here, the same escape
    // `bool_field` takes for an unexpected literal. It counts generic
    // entries, not whatever the caller's field calls them.
    if parsed.len() > max_items {
        errors.push((field.into(), format!("at most {max_items} entries")));
        return;
    }
    for n in &parsed {
        if *n < min || *n > max {
            let msg = lang.t_args("val.in_range", &[min.to_string(), max.to_string()]);
            errors.push((field.into(), msg));
            return;
        }
    }
    set_field(cfg, field, item::i64_array(parsed), errors);
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
    let Some(limit_str) = raw_get(raw, &format!("{prefix}.limit")) else {
        return;
    };
    let Some(unit_str) = raw_get(raw, &format!("{prefix}.unit")) else {
        return;
    };

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
        let msg = out_of_range(&field, u64::from(limit), lang);
        errors.push((field, msg));
        return;
    }
    let secs = match unit_str {
        "sec" => 1u64,
        "min" => 60,
        "hour" => 3600,
        "day" => 86_400,
        _ => {
            errors.push((
                format!("{prefix}.unit"),
                lang.t_args("val.must_be_enum", &["sec, min, hour, day".into()]),
            ));
            return;
        }
    };
    // The one helper where the error key and the write path differ: the
    // form and the bounds table know `{prefix}.limit`, but the document
    // stores the whole `limit/unit` string under `{prefix}` itself. Like
    // `set_field`, a rejected write must surface as a per-field error
    // instead of being swallowed behind a success toast.
    if let Err(err) = cfg.set(
        prefix,
        item::string(format!("{}/{}", limit, unit_for_secs(secs))),
    ) {
        errors.push((field, err.to_string()));
    }
}

fn unit_for_secs(secs: u64) -> &'static str {
    match secs {
        1 => "s",
        60 => "min",
        3600 => "h",
        86_400 => "day",
        other if other < 60 => "s",
        other if other < 3600 => "min",
        other if other < 86_400 => "h",
        _ => "day",
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
        apply_all(&raw, &mut cfg, &lang, &mut errors);

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
        apply_all(&raw, &mut cfg, &lang, &mut errors);

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
        apply_all(&raw, &mut cfg, &lang, &mut errors);

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
        apply_all(&raw, &mut cfg, &lang, &mut errors);

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
        apply_all(&raw, &mut cfg, &lang, &mut errors);

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
            raw.insert(
                "fetch.ip_family".into(),
                super::ip_family_str(family).into(),
            );

            let lang = test_lang();
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors);
            assert!(
                errors.is_empty(),
                "save produced errors for {family:?}: {errors:?}"
            );

            let serialized = cfg.doc().to_string();
            let parsed = IpFamily::from_str(super::ip_family_str(family))
                .expect("ip_family_str must produce a value IpFamily accepts");
            assert_eq!(parsed, family, "round-trip drifted for {family:?}");

            // toml_edit serialises the leaf under its `[fetch]` section
            // header, so the on-disk text contains the bare key
            // (`ip_family = "ipv4"`) rather than the dotted form.
            assert!(
                serialized.contains(&format!("ip_family = \"{}\"", super::ip_family_str(family))),
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
        apply_all(&raw, &mut cfg, &lang, &mut errors);

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
        // `removed_as_unknown` is absent → false.

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        assert!(errors.is_empty());
        let serialized = cfg.doc().to_string();
        assert!(serialized.contains("drop_gate = true"));
        assert!(serialized.contains("removed_as_unknown = false"));
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
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        assert!(errors.is_empty());
        let serialized = cfg.doc().to_string();
        assert!(
            serialized.contains("rate_limit = \"120/min\""),
            "got: {serialized}"
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
            apply_all(raw, &mut cfg, &lang, &mut errors);
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
        // ladder: the field hint never mentions that `[]` means «remove
        // the proxy right after the failed second chance», and the panel
        // must not trade the operator's ladder for that on a stray
        // select-all + delete.
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

    #[test]
    fn writer_helper_compiles() {
        let s = String::from("ok");
        assert_eq!(s, "ok");
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
        apply_all(&raw, &mut cfg, &lang, &mut errors);

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

    /// The HTML form is the one hand-written artifact left: this test is
    /// the stitch that keeps it honest. Every input the form posts must
    /// belong to a registry entry, and every entry must be editable
    /// through the form, either under its own `name=` or, for a
    /// rate-limit pair, as `.limit` + `.unit`.
    #[test]
    fn the_form_posts_exactly_the_registered_settings() {
        let template = include_str!("../../../templates/settings_edit.html");
        let mut posted: Vec<String> = Vec::new();
        let mut rest = template;
        while let Some(pos) = rest.find("name=\"") {
            rest = &rest[pos + 6..];
            if let Some(end) = rest.find('"') {
                posted.push(rest[..end].to_string());
                rest = &rest[end..];
            }
        }
        posted.retain(|name| name != "_csrf" && name != "settings-tab");

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

    /// Regression for the *Edit settings* bug where the page re-rendered
    /// stale `state.config` instead of reading the file the editor just
    /// wrote to. After `EditableConfig::save()`, a subsequent reload
    /// must hand the form the new on-disk values, not the in-memory
    /// snapshot frozen at startup.
    #[test]
    fn raw_from_config_reflects_post_save_file_state() {
        use fumox_core::config::load_config;

        let dir = std::env::temp_dir().join(format!("fumox-edit-postsave-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.toml");

        std::fs::write(
            &path,
            "[ingest]\ndrop_gate = false\n[admin]\nsecure_cookies = true\n",
        )
        .unwrap();

        let cfg = load_config(Some(&path)).expect("initial load must work");
        let raw = raw_from_config(&cfg);
        // `drop_gate = false` in the file → key present with empty value
        // (template's `bool_value` returns `!v.is_empty()`, so empty ==
        // unchecked).
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
            apply_all(&raw, &mut cfg, &lang, &mut errors);

            assert_eq!(
                collect_field(&errors, "server.rate_limit.limit").is_some(),
                expect_error,
                "rate_limit.limit = {value}: {errors:?}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An unbounded setting says so in words and leaves `max` empty.
    /// Printing `u64::MAX / 2` would be a true number nobody can type,
    /// and printing `0` would be a lie the browser reads as "max zero".
    #[test]
    fn an_unbounded_setting_renders_an_empty_max() {
        assert_eq!(bounds::max_attr("fetch.max_response_bytes"), "");
        assert_eq!(bounds::min_attr("fetch.max_response_bytes"), "1024");
        assert_eq!(
            bounds::display("fetch.max_response_bytes", "and up").as_deref(),
            Some("1024 and up")
        );
        assert_eq!(bounds::max_attr("probe.sample_size"), "100000");
        assert_eq!(
            bounds::display("probe.sample_size", "and up").as_deref(),
            Some("0..=100000")
        );
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
            apply_all(&raw, &mut cfg, &lang, &mut errors);

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
            apply_all(&raw, &mut cfg, &lang, &mut errors);
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
            (i64::MAX.to_string(), true),
            ((i64::MAX as u64 + 1).to_string(), false),
            (u64::MAX.to_string(), false),
        ] {
            let mut raw = HashMap::new();
            raw.insert("fetch.max_response_bytes".into(), value.clone());

            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors);

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
            apply_all(&raw, &mut cfg, &lang, &mut errors);

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
        apply_all(&raw, &mut cfg, &lang, &mut errors);
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
    /// `val.required` — a `""` written to the file would disable the
    /// panel at the next start.
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
            apply_all(&raw, &mut cfg, &lang, &mut errors);
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
        apply_all(&raw, &mut cfg, &lang, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        cfg.save().unwrap();
        let loaded = load_config(Some(&path)).expect("the rotated token must load");
        assert_eq!(
            loaded.admin.token, "rotated-secret",
            "the submitted token is trimmed on write"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The edit page as rendered: the live token must not appear
    /// anywhere in the markup (the leak used to be the `value` attribute
    /// of the password input on every GET), and a not-writable config
    /// must disable the form controls (USERGUIDE: "every control is
    /// disabled") on top of the banner the page already showed.
    #[tokio::test]
    async fn settings_edit_renders_without_the_token_and_disables_fields_when_unwritable() {
        let (_dir, mut state) =
            crate::admin::test_admin_state(AdminConfig::default(), ServerConfig::default()).await;
        let token = state.admin().token;
        assert!(!token.is_empty(), "the fixture needs a non-empty token");

        // Not writable: every control disabled, token still absent.
        state.config_writable = false;
        let template = SettingsEditTemplate {
            langs: Vec::new(),
            theme: theme::from_headers(&HeaderMap::new()),
            lang: test_lang(),
            active: "settings",
            csrf: String::new(),
            state: state.clone(),
            raw: raw_from_config(&state.live()),
            errors: Vec::new(),
            banner: Some(Banner::Unwritable("/unwritable/app.toml".into())),
        };
        let html = template.render().unwrap();
        assert!(
            !html.contains(&token),
            "the live admin token must never appear in the edit form markup"
        );
        let disabled = html.matches(" disabled").count();
        assert!(
            disabled >= 60,
            "every control must be disabled when the config is not writable, got {disabled}"
        );

        // Writable: nothing disabled, token still absent.
        state.config_writable = true;
        let template = SettingsEditTemplate {
            langs: Vec::new(),
            theme: theme::from_headers(&HeaderMap::new()),
            lang: test_lang(),
            active: "settings",
            csrf: String::new(),
            state: state.clone(),
            raw: raw_from_config(&state.live()),
            errors: Vec::new(),
            banner: None,
        };
        let html = template.render().unwrap();
        assert!(
            !html.contains(&token),
            "the live admin token must never appear in the edit form markup"
        );
        assert_eq!(
            html.matches(" disabled").count(),
            0,
            "a writable config must leave every control editable"
        );
    }

    /// USERGUIDE promises that on a not-writable config "the same banner
    /// appears on the overview" (a first-class deployment mode via
    /// `FUMOX_CONFIG_ACCESS=ro`). Render the real overview template for
    /// both states so the promise cannot regress silently again.
    #[test]
    fn settings_overview_shows_the_unwritable_banner() {
        let lang = test_lang();
        let path = "/tmp/fumox-overview/app.toml";
        let banner = lang.t_named("set.edit_unwritable", &[("path", path.to_string())]);

        for (writable, want_banner) in [(false, true), (true, false)] {
            let cfg = AppConfig::default();
            let template = SettingsTemplate {
                lang: lang.clone(),
                langs: Vec::new(),
                theme: theme::from_headers(&HeaderMap::new()),
                active: "settings",
                csrf: String::new(),
                state: SettingsView {
                    server: cfg.server.clone(),
                    database: cfg.database.clone(),
                    fetch: cfg.fetch.clone(),
                    ingest: cfg.ingest.clone(),
                    geo_config: cfg.geo.clone(),
                    admin: cfg.admin.clone(),
                    probe: cfg.probe.clone(),
                    meow: cfg.meow.clone(),
                    retention: cfg.retention.clone(),
                    log: cfg.log.clone(),
                    config_path: ResolvedConfigPath::Loaded(PathBuf::from(path)),
                    config_writable: writable,
                },
            };
            let html = template.render().unwrap();
            assert_eq!(
                html.contains(&banner),
                want_banner,
                "writable={writable}: the not-writable banner must {}appear on the overview",
                if want_banner { "" } else { "not " }
            );
        }
    }
}
